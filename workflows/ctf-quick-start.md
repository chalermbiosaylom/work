---
description: Fast CTF challenge triage and routing workflow
---

# CTF Quick Start Workflow

Use this workflow when a new CTF challenge is provided.

## Step 1: Invoke Master Orchestrator
// turbo
```bash
# MANDATORY: Always start with @solve-challenge skill
# Paste full challenge description/files to the skill
```

**Action:** Invoke `@solve-challenge` immediately with challenge context.

## Step 2: Let Skills Route Automatically

The orchestrator will:
1. Run initial triage (`file *`, `ls -lah`, quick flag hunt)
2. Categorize challenge (Web/Pwn/Crypto/Forensics/ICS/etc.)
3. Route to specialized skill (`@ctf-web`, `@ctf-pwn`, etc.)
4. Execute with appropriate MCP tools

**DO NOT intervene unless explicitly asked.**

## Step 2.5: Target Lock (Mandatory)

Before deep exploitation, record and verify:
- `target_host`
- `target_ip`
- `target_port`
- challenge-specific ids (e.g., Unit IDs)

Validation:
```bash
getent hosts <target_host>
nc -zvw 10 <target_ip> <target_port>
```

If hostname does not resolve, ask one clarifying question and pause. Do not silently pivot to another host.

## Step 3: Monitor for Traps

If execution stalls (>10s) or repeats 3x:
- Invoke `@ctf-omni-anti-trap` to detect tarpit/rabbit-hole
- Pivot to alternative vector

If MCP lane choice is unclear (or `pentest-mcp` stalls), consult:
- `/hybrid-mcp-quick-card` for 10-second lane selection and stall fallback rule.

If judges constrain ICS scope to Modbus+ENIP only, handoff to:
- `/ics-ot-speedrun` Step 3.3 "Judge Focus Mode (Modbus + ENIP only)" and freeze non-502/44818 branches.

Timebox rule:
- T+0..2 min: target lock + reachability proof
- T+2..8 min: read-only extraction/recon
- >T+8 min with no measurable progress: force pivot (`🚨 [PIVOT]`)

## Step 3.5: ENIP Hard Fast-Pivot (44818)

Trigger this immediately when all are true:
- `target_port=44818`
- identity succeeds
- tag hunt returns empty (`tags_found=0`)

Execution:
1. Keep target tuple fixed (no host switching).
2. Pivot to crafted ENIP explicit message path:
   - `RegisterSession (0x65)`
   - `SendRRData (0x6F)`
   - probe vendor classes `0x64-0x7F`, `instance=1`, `attr=1..7`
3. If reply contains `INVALID SERVICE CODE`, keep class/path fixed and brute service `0x01-0x7F`.
4. Stop immediately when payload matches flag regex.

Quick command skeleton:
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 - <<'PY'
from pycomm3 import CIPDriver
import re
ip='<target_ip>'
pat=re.compile(r'coc2026|flag|ctf|override|emergency|key',re.I)
with CIPDriver(ip) as plc:
    for cls in range(0x64,0x80):
        for service in range(1,128):
            try:
                r=plc.generic_message(service=service,class_code=cls,instance=1,attribute=1,connected=False,unconnected_send=True,route_path=True)
                v=getattr(r,'value',b'')
                if isinstance(v,bytes):
                    s=''.join(chr(c) if 32<=c<127 else '.' for c in v)
                    if pat.search(s):
                        print(f'cls=0x{cls:02x} svc=0x{service:02x} {s}')
            except Exception:
                pass
PY
```

Deterministic cue:
- `pycomm3 Failed to parse reply` + TCP open = parser mismatch; parse raw ENIP bytes and continue, do not abandon branch.

## Step 4: Flag Capture

Hunt regex (global): `/(?:coc2026|flag|RTAF|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`

When flag appears matching hunt regex:
- Output exactly 3 lines:
  ```
  [FLAG] <raw_flag>
  [CLEAN] <sanitized_flag>
  [METHOD] <1-line command>
  ```
- STOP all execution immediately

---

**Turbo Mode:** Steps marked `// turbo` auto-run without user approval.
