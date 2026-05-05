# RTAF COC2026 Readiness Audit

Date: 2026-04-20
Scope: `.windsurf/skills`, `.windsurf/workflows`, `global_rules.md`, active MCP inventory

## Executive Status

- Overall readiness: **READY (with minor hardening notes)**
- Competition mode: **Aligned** (skill-first, anti-trap, pivot/timebox, flag-stop protocol)
- Ethics lock: **Aligned** (CTF-only scope explicitly enforced)
- PassCheck gate: **Defined and validated** (global rule updated)

## MCP Server Coverage Check

| Domain | Primary MCP | Backup/Support | Status |
|---|---|---|---|
| Web | `ctf-solve` | `burp-mcp`, `pentest-mcp` | Ready |
| Pwn | `pentest-mcp` (interactive) | `ctf-solve`, `ghidramcp` | Ready |
| Reverse | `ghidramcp` | `ctf-solve` tools | Ready |
| Crypto | `ctf-solve` (Python/Sage) | local offline tools | Ready |
| Forensics/PCAP | `sharkmcp` / `wiremcp` | `ctf-solve`, `pentest-mcp` | Ready |
| ICS/OT | `ctf-solve` (one-shot) | `pentest-mcp` (interactive/stateful), `sharkmcp`/`wiremcp`, `ghidramcp` | Ready |
| OS post-exploit | `pentest-mcp` | `gtfobins`, `ctf-solve` | Ready |
| OSINT | `ctf-solve` + web tooling | - | Ready |
| Malware | `ctf-solve`/`ghidramcp` | forensics pivots | Ready |
| Misc | `ctf-solve` | `pentest-mcp`, cross-skill pivots | Ready |

## Skill-Chain Readiness

### Global Chain (new challenge)
1. `@solve-challenge`
2. 30s triage (`file *`, `ls -lah`, `cat README*`)
3. target-lock + reachability proof
4. route to domain skill + MCP primary
5. apply fail-fast pivot (3 repeats / no measurable progress)
6. stop immediately on validated flag

### Domain Chains (validated)
- Web: `solve-challenge -> ctf-web -> ctf-solve (-> burp/pentest when needed)`
- Pwn: `solve-challenge -> ctf-pwn -> pentest-mcp (+ ghidramcp)`
- ICS: `solve-challenge -> ctf-ics -> ctf-solve (one-shot) -> pentest-mcp when interactive/stateful (+ shark/wire for PCAP)`
- Forensics: `solve-challenge -> ctf-forensics -> shark/wire (+ pentest for heavy runs)`
- Crypto: `solve-challenge -> ctf-crypto -> ctf-solve (Python/Sage gate)`

## Duplicate Memory Consolidation

Consolidated overlapping competition directives into one canonical global memory and one canonical file rule.

Actions completed:
- Created canonical memory: `RTAF COC 2026 Canonical Global Rule (Skill-First + Ethical Scope + PassCheck)`
- Removed overlapping legacy memories that duplicated the same directive
- Updated `~/.codeium/windsurf/memories/global_rules.md` to canonical structure

## PassCheck Security Validation

All required checks are present and enforced in global rule:

- `scope_ok`: CTF-authorized scope only
- `target_lock_ok`: host/ip/port/protocol lock required
- `reachability_ok`: `nc`/`nmap` proof, no ping reliance
- `timeout_ok`: bounded requests required
- `evidence_mode_ok`: evidence-first, no guessed claims
- `state_safety_ok`: read-first + baseline before ICS writes

Result: **PASS**

## Minor Hardening Notes (non-blocking)

1. Keep `burp-mcp` marked as supplemental (already documented in web skill).
2. Ensure long interactive loops always switch from `ctf-solve` to `pentest-mcp`.
3. Maintain strict one-primary-MCP flow to avoid duplicate noisy scans.
4. Re-run benchmark commands pre-match (`solve_web.py`, `solve_pwn.py`, `solve_forensics.py`, `solve_crypto.py`) as final smoke test.

## Final Competition Rule Reminder

This environment is for **CTF ethical hacking and penetration testing to capture flags** within authorized challenge scope only. It is **not** for attacking general systems.
