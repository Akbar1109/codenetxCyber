"""
Catch the Intruder — Network Intrusion Detection & Alerting System
Flask + Scapy + Remote SSH log tailing + Gemini enrichment
"""

import os
import re
import time
import uuid
import threading
import subprocess
import requests
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request
from scapy.all import sniff, IP, TCP

# ----------------------------------------------------------------------
# CONFIG — fill these in before running
# ----------------------------------------------------------------------
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.replace("export ", "").strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)

TARGET_IP = os.environ.get("TARGET_IP", "192.168.1.50")      # mini laptop IP
SSH_USER = os.environ.get("SSH_USER", "pi")                   # SSH username on target
AUTH_LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/var/log/auth.log")  # or /var/log/secure

SCAN_THRESHOLD, SCAN_WINDOW = 10, 10     # 10 distinct ports within 10 seconds
BRUTE_THRESHOLD, BRUTE_WINDOW = 5, 30    # 5 failed logins within 30 seconds

api_key = os.environ.get("GEMINI_API_KEY", "").strip()
USE_GEMINI = bool(api_key and api_key != "your_key_here")
if USE_GEMINI:
    print(f"[*] Gemini AI enrichment enabled using active API Key (prefix: {api_key[:6]}...)")
else:
    print("[*] Gemini AI enrichment is disabled (no GEMINI_API_KEY set or placeholder used).")

# ----------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------
app = Flask(__name__, template_folder="templates")

port_scan_window = defaultdict(deque)   # src_ip -> deque[(ts, port)]
auth_fail_window = defaultdict(deque)   # src_ip -> deque[ts]
alerts = []                             # newest appended; served newest-first
traffic_log = deque(maxlen=300)         # rolling feed for the live chart
last_alert_time = {}                    # (kind, src) -> float timestamp
lock = threading.Lock()

MITRE_MAP = {
    "port_scan": "T1046 - Network Service Discovery",
    "brute_force": "T1110 - Brute Force",
    "possible_compromise": "T1078 - Valid Accounts (post-brute-force access)",
}

SEVERITY_MAP = {
    "port_scan": "Medium",
    "brute_force": "High",
    "possible_compromise": "Critical",
}


# ----------------------------------------------------------------------
# GEMINI ENRICHMENT (Resilient Direct REST with model fallbacks)
# ----------------------------------------------------------------------
def enrich_with_gemini(alert):
    if not USE_GEMINI or not api_key:
        return "Gemini disabled — set GEMINI_API_KEY to enable AI analysis."

    prompt = f"""You are an elite SOC incident response analyst reviewing an automated IDS detection alert.

Alert type: {alert['kind']}
Source IP: {alert['src']}
Detail: {alert['detail']}
Preliminary MITRE: {alert['mitre']}
Preliminary Severity: {alert['severity']}

Provide a crisp 3-part incident analysis in under 70 words:
• Explanation: Plain-English explanation of the attack behavior.
• Severity: Confirm or adjust severity rating with reason.
• Action: Immediate containment or investigation response.
Format as three clean bullet points."""

    models = ["gemini-3.6-flash", "gemini-flash-latest", "gemini-2.5-flash-lite"]
    for model_name in models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            resp = requests.post(url, json=payload, timeout=7)
            if resp.status_code == 200:
                data = resp.json()
                cand = data.get("candidates", [])
                if cand:
                    parts = cand[0].get("content", {}).get("parts", [])
                    texts = [p.get("text", "") for p in parts if "text" in p]
                    if texts:
                        return "\n".join(texts).strip()
            elif resp.status_code == 404:
                continue
            else:
                print(f"[!] Gemini {model_name} HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            print(f"[!] Gemini connection error with {model_name}: {e}")
            continue

    return "⚠️ AI analysis currently unavailable (network timeout or API limit). Recommended: Investigate source IP and inspect host auth logs."


def _async_gemini_worker(alert_obj):
    analysis = enrich_with_gemini(alert_obj)
    with lock:
        alert_obj["analysis"] = analysis
        alert_obj["analyzed"] = True


def raise_alert(kind, src, detail):
    now = time.time()
    key = (kind, src)
    
    with lock:
        # De-duplicate / anti-looping: if same alert kind from same source in last 12s, group it
        if key in last_alert_time and (now - last_alert_time[key]) < 12.0:
            for a in alerts:
                if a["kind"] == kind and a["src"] == src:
                    a["count"] = a.get("count", 1) + 1
                    a["timestamp"] = now
                    a["detail"] = f"{detail} (Repeated {a['count']}x)"
                    return
        
        last_alert_time[key] = now
        alert_id = f"{int(now * 1000)}-{str(uuid.uuid4())[:6]}"
        alert = {
            "id": alert_id,
            "kind": kind,
            "src": src,
            "detail": detail,
            "mitre": MITRE_MAP.get(kind, "Unmapped"),
            "severity": SEVERITY_MAP.get(kind, "Low"),
            "timestamp": now,
            "count": 1,
            "analyzed": False,
            "analysis": "⚡ AI SOC Analyst analyzing incident with Gemini..."
        }
        alerts.insert(0, alert)
        if len(alerts) > 100:
            alerts.pop()

    print(f"[ALERT] {kind} from {src} — {detail}")
    # Run AI enrichment in background thread so sniffer & SSH threads never stall
    threading.Thread(target=_async_gemini_worker, args=(alert,), daemon=True).start()


# ----------------------------------------------------------------------
# DETECTOR 1 — PORT SCAN (live packet sniffing on interface)
# ----------------------------------------------------------------------
def handle_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[IP].dst != TARGET_IP:
        return

    with lock:
        traffic_log.append({
            "ts": time.time(),
            "src": pkt[IP].src,
            "dport": pkt[TCP].dport,
        })

    if pkt[TCP].flags != "S":   # only count SYN (connection attempts)
        return

    now = time.time()
    src = pkt[IP].src
    dq = port_scan_window[src]
    dq.append((now, pkt[TCP].dport))
    while dq and now - dq[0][0] > SCAN_WINDOW:
        dq.popleft()

    distinct_ports = len({p for _, p in dq})
    if distinct_ports >= SCAN_THRESHOLD:
        raise_alert("port_scan", src, f"{distinct_ports} distinct ports probed in {SCAN_WINDOW}s")
        dq.clear()  # avoid re-firing until window resets


def start_sniffer():
    print(f"[*] Sniffing traffic destined for {TARGET_IP} ...")
    try:
        sniff(filter=f"host {TARGET_IP}", prn=handle_packet, store=False)
    except Exception as e:
        print(f"[!] Packet sniffing stopped: {e}")
        print("[!] Note: Packet sniffing requires root privileges. Run with: sudo -E ./.venv/bin/python server.py")


# ----------------------------------------------------------------------
# DETECTOR 2 — BRUTE FORCE + POST-COMPROMISE (remote SSH log tail)
# ----------------------------------------------------------------------
IP_RE = re.compile(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def tail_remote_auth_log():
    cmd = ["ssh", f"{SSH_USER}@{TARGET_IP}", "sudo", "tail", "-n", "0", "-f", AUTH_LOG_PATH]
    print(f"[*] Tailing remote auth log: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        print(f"[!] Could not start remote log tail: {e}")
        return

    for line in proc.stdout:
        now = time.time()
        m = IP_RE.search(line)
        src = m.group(1) if m else "unknown"

        if "Failed password" in line or "authentication failure" in line:
            dq = auth_fail_window[src]
            dq.append(now)
            while dq and now - dq[0] > BRUTE_WINDOW:
                dq.popleft()
            if len(dq) >= BRUTE_THRESHOLD:
                raise_alert("brute_force", src, f"{len(dq)} failed logins in {BRUTE_WINDOW}s")
                dq.clear()

        elif "Accepted password" in line or "Accepted publickey" in line:
            prior_fails = len(auth_fail_window.get(src, []))
            if prior_fails >= 3:
                raise_alert("possible_compromise", src,
                             f"login succeeded after {prior_fails} recent failures")
                # Clear to prevent looping on repeated auth events
                auth_fail_window[src].clear()


# ----------------------------------------------------------------------
# ROUTES
# ----------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    with lock:
        return jsonify(alerts[:50])


@app.route("/api/traffic")
def api_traffic():
    with lock:
        return jsonify(list(traffic_log))


@app.route("/api/stats")
def api_stats():
    now = time.time()
    with lock:
        recent_crit = sum(1 for a in alerts if a.get("severity") == "Critical" and (now - a["timestamp"]) < 300)
        recent_high = sum(1 for a in alerts if a.get("severity") == "High" and (now - a["timestamp"]) < 300)
        recent_med = sum(1 for a in alerts if a.get("severity") == "Medium" and (now - a["timestamp"]) < 300)
        
        penalty = (recent_crit * 30) + (recent_high * 15) + (recent_med * 5)
        health_score = max(5, min(100, 100 - penalty))

        if health_score >= 88:
            threat_level = "OPTIMAL"
            threat_color = "#00f0ff"
        elif health_score >= 65:
            threat_level = "ELEVATED"
            threat_color = "#f5d442"
        elif health_score >= 35:
            threat_level = "HIGH ALERT"
            threat_color = "#ff9f43"
        else:
            threat_level = "CRITICAL"
            threat_color = "#ff4d4f"

        recent_pkts = sum(1 for p in traffic_log if (now - p.get("ts", 0)) < 10)
        syn_velocity = round(recent_pkts / 10.0, 1)
        threat_index = min(100, int((syn_velocity * 4) + (recent_high * 18) + (recent_crit * 32)))

        return jsonify({
            "total_alerts": len(alerts),
            "by_kind": {
                k: sum(1 for a in alerts if a["kind"] == k)
                for k in MITRE_MAP
            },
            "packets_seen": len(traffic_log),
            "health_score": health_score,
            "threat_level": threat_level,
            "threat_color": threat_color,
            "syn_velocity": syn_velocity,
            "threat_index": threat_index,
            "recent_alerts_5m": recent_crit + recent_high + recent_med,
            "gemini_active": USE_GEMINI,
            "target_ip": TARGET_IP,
            "ssh_user": SSH_USER
        })


@app.route("/api/test_alert", methods=["POST", "GET"])
def api_test_alert():
    kinds = ["port_scan", "brute_force", "possible_compromise"]
    kind = request.args.get("kind", "port_scan")
    if kind not in kinds:
        kind = "port_scan"

    details = {
        "port_scan": "14 distinct destination ports probed in 10s (SYN probe simulation)",
        "brute_force": "5 failed SSH authentication attempts in 24s for user 'admin'",
        "possible_compromise": "SSH login succeeded for user 'akbar' immediately after 4 failed attempts"
    }
    raise_alert(kind, "192.168.1.188", details[kind])
    return jsonify({"status": "ok", "message": f"Triggered simulated {kind} alert"})


@app.route("/api/clear_alerts", methods=["POST", "GET"])
def api_clear_alerts():
    with lock:
        alerts.clear()
        port_scan_window.clear()
        auth_fail_window.clear()
        last_alert_time.clear()
    return jsonify({"status": "ok", "message": "All alerts cleared"})


# ----------------------------------------------------------------------
# ENTRYPOINT
# ----------------------------------------------------------------------
if __name__ == "__main__":
    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=tail_remote_auth_log, daemon=True).start()
    app.run(host="0.0.0.0", port=8000, debug=False)
