# Path Validation & Environment Variable Handling

## Problem Statement

Hardcoded paths like `$VENV/bin/python tools/modbus/script.py` fail when:
- Agent runs in wrong directory
- Environment variable `$VENV` not expanded by MCP shell
- Result: `Command not found` errors during competition

## Solution: Absolute Path Resolution

### 1. Environment Setup (One-Time Validation)

Before running ANY ICS/OT scripts, validate environment:

```bash
# Check if VENV exists and is valid
if [ ! -d "/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv" ]; then
  echo "ERROR: VENV not found. Creating..."
  python3 -m venv /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/pip install -r /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/requirements.txt
fi

# Set absolute path (no variable expansion needed)
VENV_PYTHON="/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3"
```

### 2. Script Execution (Always Use Absolute Paths)

**WRONG (Variable-dependent):**
```bash
$VENV/bin/python tools/modbus/modbus_read_find_flags.py 10.10.50.100
```

**CORRECT (Absolute path):**
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/modbus_read_find_flags.py \
  10.10.50.100 --probe-units --json
```

### 3. MCP Tool Execution Pattern

When using `pentest-mcp` or `ctf-solve` to run scripts:

```python
# Via MCP: pentest-mcp (create_session + execute)
execute(
  session_id="ics_session",
  command="/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/modbus_read_find_flags.py 10.10.50.100 --json",
  triggers=[{"type": "timeout", "timeout_seconds": 15}]
)
```

### 4. Working Directory Assumption

**NEVER assume current working directory.** Always use absolute paths for:
- Python interpreter: `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3`
- Script files: `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/<script>.py`
- Output files: `/tmp/ctf_output_<timestamp>.json` (not `./output.json`)

### 5. Quick Reference Table

| Component | Absolute Path |
|-----------|---------------|
| Python (VENV) | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3` |
| Modbus Tools | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/modbus_*.py` |
| ENIP Tools | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/enip_*.py` |
| S7 Tools | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/s7_*.py` |
| PCAP Tools | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/pcap_*.py` |
| cipTool | `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/cipTool/cip.py` |

## Integration with Skills

All ICS-related skills (`ctf-ics`, `solve-challenge`) MUST use absolute paths when invoking tools via MCP.

**Example (Updated ctf-ics SKILL.md):**
```bash
# OLD (WRONG)
$VENV/bin/python tools/modbus/modbus_connect_test.py --ip 10.10.50.100

# NEW (CORRECT)
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/modbus_connect_test.py \
  --ip 10.10.50.100 --full-scan --json
```
