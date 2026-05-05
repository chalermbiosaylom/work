# Cross-Skill Integration Patches V6 (Anti-Trap Toolkit Executables)
**Date:** Apr 17, 2026
**Scope:** `ctf-omni-anti-trap` (shared across all categories)
**Trigger:** `antitrapwhaitingupdate.txt` - comprehensive anti-trap reference

---

## Objective
Convert the 10-section anti-trap reference into **executable tooling** that any skill can invoke on demand, preventing:
- Zip bombs / OOM
- Tool stalls and runaway processes
- Tarpit network endpoints
- Decoy flag submission
- Packed/encrypted/stego noise traps

---

## Files Created (all executable, all smoke-tested)

### `/home/kali/Desktop/.windsurf/skills/ctf-omni-anti-trap/`

| File | Purpose | Key Thresholds |
|:-----|:--------|:---------------|
| `ANTI_TRAP_TOOLKIT.md` | Executable reference + category cheat sheet | - |
| `ctf_safe_run.sh` | Resource-monitored executor | kill on 95% CPU + >MAX_MEM_MB, stall >15s |
| `archive_inspect.sh` | Pre-extraction gate for archives | reject >100 files or >50x ratio |
| `flag_filter.py` | Decoy flag scorer | penalize `fake/test/noob/...`, reward entropy |
| `adaptive_timeout.sh` | RTT-based timeout calc | `max(10s, 3*rtt + 5s)` |
| `entropy_check.py` | Packer/stego entropy detector | warn >7.5 bits/byte, LSB ratio <0.1 |

### Updated
- `ctf-omni-anti-trap/SKILL.md` - Additional Resources section + Quick Invocations block

---

## Smoke Test Results

```
=== safe_run ===
[SAFE_RUN] cmd=sleep 1 | max_time=3s | max_mem=500MB | stall=15s
[SAFE_RUN] exit=0

=== flag_filter ===
[PASS]  +15  coc2026{R3al_Fl4g_H3r3_2026}
[drop]  -10  coc2026{test_flag_noob}

=== adaptive ===
10

=== entropy ===
[entropy] 5.975 bits/byte (158632 bytes) /bin/ls
```

All helpers return proper exit codes and log traps to `/tmp/ctf_loot.txt`.

---

## Usage Matrix by Skill

| Skill | When to invoke | Helper |
|:------|:---------------|:-------|
| `@ctf-web` | Unknown-size response | `smart_curl` (V5) |
| `@ctf-web` | Rate-limited / tarpit endpoint | `adaptive_timeout.sh` |
| `@ctf-forensics` | Provided archive/zip/7z/tar | `archive_inspect.sh` |
| `@ctf-forensics` | Suspected LSB stego image | `entropy_check.py` |
| `@ctf-reverse` | Unknown binary, possibly packed | `entropy_check.py` |
| `@ctf-pwn` | Running potentially hanging binary | `ctf_safe_run.sh` |
| `@ctf-crypto` | Before attempting factorization | feasibility gate (in toolkit) |
| `@ctf-os-exploit` | Bounded enum/cat | `smart_enum.sh` (V5) |
| **All** | Flag candidates from grep/regex | `flag_filter.py` |
| **All** | Any long-running command | `ctf_safe_run.sh` |

---

## Source Mapping (antitrapwhaitingupdate.txt -> Executable)

| Section in doc | Converted to |
|:---------------|:-------------|
| 1. Process Management & Timeouts | `ctf_safe_run.sh` |
| 2. Resource Exhaustion Defense | `archive_inspect.sh` + toolkit cheats |
| 3. Rabbit Hole Evasion | `entropy_check.py` + toolkit patterns |
| 4. Crypto Trap Detection | toolkit feasibility check |
| 5. Decoy Flag Validation | `flag_filter.py` |
| 6. Steganography Trap Detection | `entropy_check.py` (LSB mode) |
| 7. Logic Bomb Countermeasures | toolkit (faketime/LD_PRELOAD patterns) |
| 8. Supply Chain Defense | toolkit (docker/firejail/safety) |
| 9. Adaptive Network Timeouts | `adaptive_timeout.sh` |
| 10. Emergency Bailout Protocols | `ctf_safe_run.sh` (runaway + stall logic) |

---

## Universal Bailout Rules (Now Enforced via Helpers)

1. Same output 3x -> hard pivot (manual discipline)
2. CPU 95%+ AND mem >MAX_MEM -> `ctf_safe_run.sh` auto-kill
3. Stall >15s with 0% CPU -> `ctf_safe_run.sh` auto-kill
4. Archive >100 files OR >50x ratio -> `archive_inspect.sh` exit 1
5. Binary entropy >7.5 -> `entropy_check.py` exit 1 + warning
6. LSB unique ratio <0.1 -> `entropy_check.py` warns noise trap
7. Flag matches decoy keyword -> `flag_filter.py` drops
8. Network target RTT unknown -> `adaptive_timeout.sh` sets safe default (10s floor)

---

## Integration with Previous Patches

- V1-V5 covered per-skill routing, container trap, shell stabilization, precision strike, context bloat
- **V6 is cross-cutting**: any skill can invoke these helpers without modification
- All helpers log to `/tmp/ctf_loot.txt` (the Persistent Loot System from V4)
- Works in concert with:
  - `smart_curl.sh` (V5) for web responses
  - `smart_enum.sh` (V5) for OS enumeration
  - `PIVOT_AUTOSCAFFOLD.sh` (V4) for tunnel setup
  - `MASTER_PROMPT_PROTOCOL.md` (V4) for behavior guardrails

---

## Recommended Next Steps

1. Add `ANTI_TRAP_TOOLKIT.md` link to each category skill's `Additional Resources`
2. Update `/ctf-quick-start` workflow to reference `archive_inspect.sh` for provided-file challenges
3. Consider `sudo install` of helpers to `/usr/local/bin/` for system-wide access:
   ```bash
   sudo install -m 0755 ctf_safe_run.sh archive_inspect.sh adaptive_timeout.sh /usr/local/bin/
   sudo install -m 0755 flag_filter.py entropy_check.py /usr/local/bin/
   ```

---

**Status:** All six patches (V1-V6) production-ready for RTAF COC 2026.
