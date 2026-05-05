# RTAF COC2026 Match-Day Runbook (One Page)

## 0) Mission Lock (Always)
- Scope: Authorized CTF targets only
- Goal: Ethical pentest for flag capture only
- Rule: New challenge -> `@solve-challenge` first

## 1) One-Click PassCheck (Before exploit)

```bash
bash /home/kali/Desktop/.windsurf/tools/pre_match_passcheck.sh \
  --target <host_or_ip> \
  --port <port> \
  --protocol <service> \
  --scope ctf \
  --stateful <yes|no> \
  --baseline <baseline_file_if_stateful>
```

Pass criteria:
- `scope_ok`
- `target_lock_ok`
- `reachability_ok`
- `timeout_ok`
- `evidence_mode_ok`
- `state_safety_ok` (required for ICS/stateful writes)

If any FAIL -> fix immediately before exploit.

## 2) Routing Contract (Fast)
- Web -> `@ctf-web` | primary `ctf-solve` | backup `burp-mcp` / `pentest-mcp`
- Pwn -> `@ctf-pwn` | primary `pentest-mcp` | backup `ctf-solve` + `ghidramcp`
- Reverse -> `@ctf-reverse` | primary `ghidramcp`
- Crypto -> `@ctf-crypto` | primary `ctf-solve` (Python/Sage)
- Forensics/PCAP -> `@ctf-forensics` | primary `sharkmcp`/`wiremcp`
- ICS/OT -> `@ctf-ics` | primary `ctf-solve` (one-shot read/decode) | escalation `pentest-mcp` (interactive/stateful) + backup `sharkmcp`/`wiremcp`
- OS post-exploit -> `@ctf-os-exploit` | primary `pentest-mcp` + `gtfobins`

Execution discipline:
- Use one primary MCP path at a time
- Switch MCP only when phase changes (e.g., one-shot -> interactive)
- If `pentest-mcp` stalls >20-30s: retry once with fresh session, then pivot back to `ctf-solve`

## 3) Halt / Pivot Protocol

Hard pivot immediately when:
1. Same failure repeats 3 times
2. No measurable progress after 2 cycles
3. Active branch stalls >10s without new signal

On pivot:
- Log reason in one line
- Change vector/category, do not repeat same payload family

## 4) Flag Capture Protocol (Absolute Priority)

Hunt regex:

`/(?:coc2026|flag|ctf|rtaf|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`

When valid flag appears: STOP immediately and output exactly

```text
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line extraction command/chain>
```

## 5) 60-Second Pre-Flight Checklist
- [ ] Challenge scope confirmed (CTF authorized)
- [ ] Target tuple locked (`host/ip/port/protocol`)
- [ ] PassCheck script returns `RESULT=PASSCHECK_OK`
- [ ] Primary skill + MCP selected
- [ ] Timeout bounds enabled
- [ ] Evidence path recorded

## 6) Copy/Paste Quick Commands

```bash
# Baseline triage
file *; ls -lah; cat README* 2>/dev/null

# Reachability (no ping)
nc -zvw 10 <host> <port> || nmap -Pn -p<port> --max-rtt-timeout 10s <host>

# One-shot passcheck
bash /home/kali/Desktop/.windsurf/tools/pre_match_passcheck.sh --target <host> --port <port> --protocol <svc> --scope ctf
```
