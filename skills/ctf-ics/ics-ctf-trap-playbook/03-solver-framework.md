# 03 - Solver Framework

## แนวคิด

Framework นี้ออกแบบมาเพื่อ solve โจทย์ ICS CTF ที่ **ไม่เคยเห็นมาก่อน**
ไม่ว่า AI จะสร้างโจทย์แบบไหน framework จะลองทุกวิธีจนเจอ flag

## Architecture

```
┌─────────────────────────────────────────┐
│           ICS CTF Solver                │
│                                         │
│  ┌──────────┐  ┌──────────┐            │
│  │  Recon   │→│  Detect  │            │
│  │  Module  │  │  Traps   │            │
│  └──────────┘  └────┬─────┘            │
│                      │                  │
│         ┌────────────┼────────────┐     │
│         ▼            ▼            ▼     │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Passive  │ │  Active  │ │ Brute   │ │
│  │ Decode   │ │  State   │ │ Force   │ │
│  │ (read +  │ │ (write + │ │ (timing │ │
│  │  parse)  │ │  read)   │ │  + xor) │ │
│  └──────────┘ └──────────┘ └─────────┘ │
│         │            │            │     │
│         └────────────┼────────────┘     │
│                      ▼                  │
│              ┌──────────────┐           │
│              │ Flag Matcher │           │
│              │ coc2026{...} │           │
│              │ FLAG{...}    │           │
│              └──────────────┘           │
└─────────────────────────────────────────┘
```

## วิธีใช้

```bash
# Install dependencies
pip install pymodbus cpppo pycomm3

# Run full solver
python3 solvers/ics_ctf_solver.py \
    --modbus 172.20.0.20 \
    --enip 172.20.0.30 \
    --flag-format "coc2026"

# Run recon only
python3 solvers/ics_ctf_solver.py \
    --modbus 172.20.0.20 \
    --recon-only

# Run with custom Unit IDs
python3 solvers/ics_ctf_solver.py \
    --modbus 172.20.0.20 \
    --unit-ids 1,42,99,100
```

## ขั้นตอนการทำงาน

### Phase 1: Reconnaissance
- Port scan (502, 44818, 20000, 4840, 47808)
- Unit ID enumeration (priority list)
- Tarpit detection (timing analysis)
- EtherNet/IP List Identity
- Tag enumeration

### Phase 2: Passive Collection
- อ่านทุก register ที่ non-zero (skip tarpit)
- อ่านทุก tag ที่มีค่า
- เก็บ raw data ทั้งหมด

### Phase 3: Decode Attempts
- ลองทุก endianness (ABCD, CDAB, BADC, DCBA)
- ลอง INT array → ASCII
- ลอง SSTRING parse
- ลอง XOR brute-force (0x00-0xFF)
- ลอง Base64 decode
- หา raw byte pattern { }

### Phase 4: Active Interaction
- Coil toggle + read
- Magic value write + side-effect check
- Boolean tag write + string tag read
- Pulse timing (0.05s - 3.0s)

### Phase 5: Flag Extraction
- Match ทุก result กับ flag patterns
- Report ทุก flag ที่เจอ
