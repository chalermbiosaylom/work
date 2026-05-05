# CTF Skill Router - Quick Reference (RTAF COC 2026)

**MANDATORY FIRST STEP:** Always invoke `@solve-challenge` for ANY CTF challenge.

## Skill Mapping (1-Page Cheatsheet)

| Trigger | Invoke Skill | Primary MCP | When to Use |
|---------|--------------|-------------|-------------|
| **New challenge** | `@solve-challenge` | ctf-solve | ALWAYS start here - orchestrator routes to specialized skills |
| Port 502/44818/102/4840/1883/47808 | `@ctf-ics` | ctf-solve (default) + pentest-mcp (interactive) + sharkmcp + ghidramcp | Modbus/ENIP/S7/OPC-UA/MQTT/BACnet |
| HTTP/HTTPS service | `@ctf-web` | ctf-solve | XSS/SQLi/SSTI/SSRF/JWT/file upload |
| Binary + remote service | `@ctf-pwn` | pentest-mcp + ghidramcp | Buffer overflow/ROP/heap/format string |
| Binary analysis only | `@ctf-reverse` | ghidramcp | Decompile/debug/anti-debug/VM/obfuscation |
| RSA/AES/crypto math | `@ctf-crypto` | ctf-solve | Encryption/hashing/signatures/PRNG/lattice |
| .pcap/.pcapng | `@ctf-forensics` | sharkmcp/wiremcp | Network captures (+ ctf-ics for OT traffic) |
| Memory/disk dumps | `@ctf-forensics` | ctf-solve/pentest-mcp | Volatility/TSK/deleted files/registry |
| Steganography | `@ctf-forensics` | ctf-solve | Images/audio/LSB/metadata |
| OSINT/public data | `@ctf-osint` | ctf-solve | Social media/geolocation/DNS/leaks |
| Obfuscated malware | `@ctf-malware` | ghidramcp + pentest-mcp | C2 traffic/PE analysis/deobfuscation |
| Encoding/jail/esoteric | `@ctf-misc` | ctf-solve | Base64/Python jail/RF/SDR/Z3/QR codes |
| Post-exploit/privesc | `@ctf-os-exploit` | pentest-mcp + gtfobins | Shell→root/lateral move/pivoting/AD |
| Trap detection | `@ctf-omni-anti-trap` | N/A | Timeouts/infinite loops/fake flags/rabbit holes |

## Workflows (Slash Commands)

- `/ctf-quick-start` - Fast triage → route → execute
- `/hybrid-mcp-quick-card` - 10-second MCP lane selection + stall fallback (ctf-solve ↔ pentest-mcp)
- `/ics-ot-speedrun` - Modbus/ENIP/S7/MQTT flag hunting (+ Judge Focus Mode: Modbus+ENIP)
- `/modbus-enip-15m-mock-drill` - 15-minute drill + KPI scoring for Modbus(502) and ENIP(44818)
- `/ics-ot-matchday-hardening` - ICS/OT preflight, baseline snapshot, rollback safety workflow
- `/web-exploit-chain` - Web vulns → privesc chaining
- `/pwn-remote-exploit` - Local analysis → remote shell
- `/forensics-pcap-hunt` - PCAP flag extraction

## Flag Capture Protocol

**Hunt Regex:** `/(?:coc2026|flag|RTAF|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`

**On Match → HALT immediately:**
```
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line command>
```

**Auto-decode:** Base64 (`Y29j...`) or Hex (`434f43...`) before validation.

## Anti-Trap Triggers

Invoke `@ctf-omni-anti-trap` when:
- Command hangs >10s
- Same error repeats 3x
- Infinite dump/loop detected
- Brute-force >5 minutes without proof of tractability

## Cross-Category Patterns

- **Web + Crypto:** JWT forgery → `@ctf-web` + `@ctf-crypto`
- **ICS + Forensics:** OT PCAP → `@ctf-ics` + `@ctf-forensics`
- **Pwn + Reverse:** Packed binary → `@ctf-reverse` then `@ctf-pwn`
- **Web + OS:** RCE → shell → `@ctf-web` then `@ctf-os-exploit`

---

**Competition Rule:** Speed > cleverness. Use skills, don't reinvent.
