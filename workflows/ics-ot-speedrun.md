---
description: RTAF COC 2026 ICS/OT/SCADA Ultimate Playbook (Modbus/ENIP/S7/OPC-UA/MQTT)
---

# RTAF COC 2026 ICS/OT Ultimate Speedrun & Hardening Workflow

This is the unified, single-source-of-truth workflow for all ICS/OT challenges. It combines speedrun tactics with match-day hardening (state-safety, baseline snapshots, and fallback pivots).

## Step 1: Target Lock & Match-Day Preflight

1. Lock tuple in notes: `target_host`, `target_ip`, `target_port`, `unit_ids/rack/slot`.
2. Validate network routing and tunnels:
```bash
ip a | grep -E 'ligolo|tun|tap'
ip route
```
3. Reachability proof (NO ping):

// turbo
```bash
nc -zvw 10 <target_ip> <port> || nmap -Pn -p<port> --max-rtt-timeout 10s <target_ip>
```

If unreachable → check tunnel (ligolo/sshuttle) or use proxychains. Do not silently switch to another host.

**Emit PassCheck before proceeding:**
```text
[PASSCHECK] scope_ok=true target_lock_ok=true reachability_ok=<true/false> timeout_ok=true evidence_mode_ok=true state_safety_ok=true
```
- If `reachability_ok=false` → STOP. Fix network path first. Do not proceed to Step 1.5.

## Step 1.5: MEMORY RECALL CHECKPOINT (MANDATORY, <30s)

**IRON RULE:** ก่อน invoke skill หรือเขียน script ใดๆ ต้อง match signature กับ Memory Index ก่อน.

1. **Capture identity signature** (run ONE of these based on port):

// turbo
```bash
# ENIP (44818)
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_list_identity.py --ip <target_ip> --json 2>/dev/null | head -20

# Modbus (502) — quick banner/HR scan
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py --ip <target_ip> --unit 1 --json 2>/dev/null | head -20
```

2. **Match against MEMORY INDEX (`MEMORY[82fe22bb]`):**
   - Scan the ICS PLAYBOOKS table for signature match (Vendor ID, Product Name, protocol pattern)
   - If MEMORY INDEX was not auto-injected, state it explicitly and proceed to Step 2

3. **Emit exactly ONE marker:**
```text
[PLAYBOOK_MATCH] memory=<id> signature=<what matched> tool=<primary_tool_from_playbook>
[PLAYBOOK_PARTIAL] partial_hint=<port/vendor only> falling_back_to=skill_default
[PLAYBOOK_NEW] no_match → standard_workflow
```

4. **Decision gate:**
   - `PLAYBOOK_MATCH` → Load playbook memory, use its primary tool FIRST in Step 3
   - `PLAYBOOK_PARTIAL` / `PLAYBOOK_NEW` → Continue standard flow from Step 2
   - **DO NOT write custom `/tmp/*.py` scripts if playbook has a matching tool**

## Step 2: Protocol Identification & Initial Recon

**If `[PLAYBOOK_MATCH]` was emitted in Step 1.5 → skip this step and jump to Step 4 with the playbook tool.**

### Modbus (502): Unknown Unit ID Protocol

If challenge does not provide Unit ID, do this before any write attempt:

// turbo
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_unit_map.py --ip <target_ip> --port <target_port> --probe-units --unit-range 1-247 --top 5 --json
```

If one-shot mapper returns `recommended_unit: null` with `ambiguous_unit_selection`:
- Do not start write phase until ambiguity is cleared.
- Expand ranges (`--hold-count`, `--input-count`) and retry.
- Follow mapper `suggested_commands` in order.

### ENIP (44818): Identity Fingerprint

// turbo
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_list_identity.py --ip <target_ip> --json
```

Look for: `Vendor ID`, `Product Code`, `Product Name` — match against `MEMORY[82fe22bb]` ICS PLAYBOOKS table.

### Multi-port (Unknown Protocol)

// turbo
```bash
nmap -Pn -sV -p 102,502,4840,44818,47808,1883 <target_ip> --max-rtt-timeout 10s
```

## Step 3: Baseline Snapshot (CRITICAL BEFORE WRITES)

Take a full baseline before any FC05/FC06/FC0F/FC10 actions or state-gated sequences. This prevents permanent state contamination (Logic Bombs).

### 3.1 Modbus Snapshot Template
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 - <<'PY'
from pymodbus.client import ModbusTcpClient
import json, time

TARGET_IP = "<target_ip>"
TARGET_PORT = 502
UNIT_IDS = [1] # update this
COIL_START, COIL_COUNT = 0, 64
HR_START, HR_COUNT = 0, 260
IR_START, IR_COUNT = 0, 260
OUT = f"/home/kali/Desktop/baseline_{TARGET_IP.replace('.','_')}.json"

c = ModbusTcpClient(TARGET_IP, port=TARGET_PORT, timeout=1.5)
assert c.connect(), "connect failed"

def read_regs(fn_name, uid, addr, cnt):
    fn = getattr(c, fn_name)
    try: r = fn(addr, cnt, slave=uid)
    except TypeError:
        try: r = fn(addr, cnt, unit=uid)
        except TypeError: r = fn(addr, cnt, device_id=uid)
    return r.registers if (r and not r.isError() and r.registers) else None

def read_coils(uid, addr, cnt):
    try: r = c.read_coils(addr, cnt, slave=uid)
    except TypeError:
        try: r = c.read_coils(addr, cnt, unit=uid)
        except TypeError: r = c.read_coils(addr, cnt, device_id=uid)
    return r.bits[:cnt] if (r and not r.isError() and r.bits) else None

snap = {"ts": time.time(), "target": f"{TARGET_IP}:{TARGET_PORT}", "units": {}}
for uid in UNIT_IDS:
    snap["units"][str(uid)] = {
        "coils": read_coils(uid, COIL_START, COIL_COUNT),
        "holding": read_regs("read_holding_registers", uid, HR_START, HR_COUNT),
        "input": read_regs("read_input_registers", uid, IR_START, IR_COUNT),
    }

with open(OUT, "w") as f: json.dump(snap, f, indent=2)
print(f"baseline saved -> {OUT}")
c.close()
PY
```

## Step 4: Protocol-Specific Flag Hunt (Invoke `@ctf-ics`)

The skill will auto-execute the following lanes:

### Modbus (502)
- **Read-Only Hunt:** Probe unit IDs → Read holding registers → Hunt flags (`modbus_read_find_flags.py`)
- **Write Fuzz:** `modbus_write_find_flags.py` (with `--verify` for silent locks)
- **State-Gated Sequences:** `modbus_sequence_runner.py` / `modbus_blackstart_runner.py`

### ENIP (44818)
- **Identify & Read:** List identity → Read tags (`tiger_enip_exploit.py` / `enip_cpppo_read_find_flags.py`)
- **State-Gated:** `enip_state_machine_runner.py`
- **Hard Fallback:** If `identity=ok` but `tags_found=0`, pivot to CIP Explicit Messages (Vendor-specific Class `0x64-0x7F`).

### S7comm (102) / MQTT (1883) / OPC-UA (4840) / BACnet (47808)
- Use MCP resources + Async scripts.
- **OPC-UA Tip:** Always look for cycle counter nodes before writing.

## Step 5: State Contamination & Auto Rollback

- Keep single TCP session if stateful challenge
- Write one candidate at a time
- Immediately re-read verification ranges after each write (`--verify-each`)
- If broad unrelated drift appears, stop and rollback using the saved baseline.

## Step 6: Timebox, Pivot, and Flag Capture

**Timebox Rule:**
- T+0..2 min: Target lock + reachability
- T+2..8 min: Read-only extraction / Baseline
- >T+8 min with no measurable progress: `🚨 [PIVOT]`
- Same error repeated 3 times: Pivot branch immediately

**Hunt Regex (global):** `/(?:coc2026|flag|RTAF|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`

When flag is found, output exactly:
```text
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line command chain>
```
Stop execution immediately after capture.
