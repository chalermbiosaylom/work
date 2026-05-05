---
description: Fast port discovery (masscan → nmap two-step) — replaces slow nmap -p-
---

# Fast Port Scan Workflow (masscan → nmap)

Use this **instead of** `nmap -p-` for all full-range port discovery.
Masscan finds open ports in ~5 seconds, then nmap does version/script scan only on hits.

## Step 1: Masscan — Find Open Ports Fast

// turbo
```bash
sudo masscan <target_ip> -p 0-65535 --rate=10000 -oG /tmp/mscan.txt 2>/dev/null
```

**Rate guidance:**
- LAN / local CTF: `--rate=10000` (safe, ~5s)
- Remote / internet: `--rate=1000` (polite, ~30s)
- Aggressive CTF lab: `--rate=50000` (~1s, may drop packets)

## Step 2: Extract Open Ports

// turbo
```bash
PORTS=$(grep "open" /tmp/mscan.txt | awk '{print $4}' | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//'); echo "[+] Open ports: $PORTS"
```

## Step 3: nmap Version + Script Scan on Discovered Ports Only

// turbo
```bash
nmap -sV -sC -p "$PORTS" <target_ip>
```

## One-Liner (All 3 Steps Combined)

```bash
PORTS=$(sudo masscan <target_ip> -p 0-65535 --rate=10000 2>/dev/null | grep "open" | awk '{print $4}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//'); echo "[+] Open: $PORTS"; nmap -sV -sC -p "$PORTS" <target_ip>
```

## Alternatives

```bash
# rustscan (auto-pipes to nmap, no root needed)
rustscan -a <target_ip> --range 0-65535 --ulimit 5000 -- -sV -sC

# docker rustscan (if not installed)
docker run -it --rm --network host rustscan/rustscan:latest -a <target_ip> -- -sV -sC

# nmap only (slower fallback — use only if masscan unavailable)
nmap -Pn -p- --min-rate 5000 --max-retries 1 -T4 <target_ip>
```

## Speed Comparison

| Tool | 0-65535 scan time | Notes |
|---|---|---|
| `nmap -p-` default | ~15-20 min | Too slow for CTF |
| `nmap -p- --min-rate 5000` | ~2-3 min | Acceptable fallback |
| **masscan --rate=10000** | **~5 sec** | Standard CTF |
| **rustscan** | **~10-30 sec** | Auto-pipes nmap |

## Reachability Check (specific port only — NOT full scan)

For checking if a **single known port** is open (e.g., after reading challenge prompt):
```bash
nc -zvw 10 <target_ip> <port> || nmap -Pn -p<port> --max-rtt-timeout 10s <target_ip>
```
