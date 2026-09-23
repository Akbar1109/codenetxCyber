# Catch the Intruder

Live network intrusion detection & alerting system — Flask + Scapy + Gemini enrichment.

## Setup

```bash
pip3 install -r requirements.txt
export GEMINI_API_KEY="your_key_here"          # from aistudio.google.com/app/apikey
export TARGET_IP="192.168.1.50"                 # mini laptop's IP
export SSH_USER="pi"                            # SSH username on mini laptop
export AUTH_LOG_PATH="/var/log/auth.log"        # or /var/log/secure on RHEL-based systems
```

**Before first run**, manually SSH in once to accept the host key:
```bash
ssh $SSH_USER@$TARGET_IP tail -n 5 /var/log/auth.log
```
If this hangs on a "yes/no" prompt, answer it — otherwise the background thread will hang silently.

## Run

```bash
sudo -E python3 server.py
```
`-E` preserves your exported env vars under `sudo` (root is required for packet sniffing).

Then open **http://localhost:8000** for the live dashboard.

## Demo sequence

```bash
nmap -sS <TARGET_IP>                              # triggers port_scan alert
hydra -l root -P wordlist.txt ssh://<TARGET_IP>   # triggers brute_force alert
```
If a brute-force run eventually succeeds (weak test password), the system raises a
`possible_compromise` alert — login success immediately following repeated failures.

---

## How this maps to "Catch the Intruder"

| Problem statement requirement | How it's implemented |
|---|---|
| Port scanning patterns | Sliding-window count of distinct destination ports per source IP (`SCAN_THRESHOLD` / `SCAN_WINDOW`) |
| Repeated connections / brute-force behavior | Sliding-window count of failed SSH auth attempts per source IP, read live from the target's own auth log over SSH — no agent installed on the target |
| Unusual communication / abnormal connection frequency | Live SYN-packet feed visualized as a rolling 30-second traffic chart; same pipeline extends to volumetric/beaconing detection |
| Suspicious traffic patterns | `possible_compromise` correlation: successful login immediately following ≥3 recent failures — links two independent event types into one meaningful incident |
| Generate meaningful alerts | Every alert carries a MITRE ATT&CK technique ID, a severity rating, and an AI-generated (Gemini) plain-English analysis + recommended response — not just a raw log line |
| Team-controlled/simulated network activity only | All testing is against a mini laptop owned and controlled by the team, over a private local network |

### Why the architecture is split across two machines
The mini laptop (Intel Atom N450, 1GB RAM) only runs `sshd` — no detection code runs on it,
since it has no headroom for that. All sniffing, correlation, and AI enrichment run on the
MacBook, which:
1. Sniffs its own outbound traffic to the target (captures port-scan attempts locally, no
   promiscuous mode or special network access needed)
2. SSHes into the target to tail its auth log remotely (captures brute-force attempts without
   installing anything on the target)

This mirrors a lightweight **edge sensor → central analysis** pattern — the same
architectural principle behind distributed IDS/SOC systems, just scoped to what's buildable
and demoable in a 12-hour hackathon window.
