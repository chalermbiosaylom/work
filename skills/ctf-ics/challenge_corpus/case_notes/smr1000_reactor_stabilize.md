# SMR-1000 Nuclear Reactor Stabilization (3-Flag Multi-Protocol)

- target ip/host: <TARGET_IP_OR_PATH>
- ports: 502 (Modbus), 44818 (ENIP/CIP), 8080 (HMI)
- protocols: Modbus TCP, EtherNet/IP CIP, HTTP HMI
- tags: state-gated, decode-chain, decoy, multi-protocol, falsified-sensors, mode-lock, physics-sim

## Flag 1: Modbus HR Base64 Decode
- **Location**: HR[100-149]
- **Encoding**: Base64 ASCII packed in BE registers
- **Decoy**: Plain text "flag" in same HR range — real flag was base64 encoded
- **Decode chain**: HR → BE bytes → ASCII → base64 decode
- **Flag**: `SMR{m0dbu5_15_Ly1nG_ch3ck_CIP_truth}`

## Flag 2: CIP Assembly Instance Read
- **Location**: CIP Class 0x04 (Assembly), Instance 0x65, Attribute 0x03
- **Data type**: SHORT_STRING (byte[0]=length, byte[1..]=ASCII)
- **Bonus data**: SAFE condition text in same instance
- **Trap**: pycomm3 fails ("Target did not connected") — must use raw CIP
- **Trap**: Instance 0x66 = honeypot decoy flag `SMR{h0n3yp0t_ch3ck_0th3r_1nst4nc3}`
- **Flag**: `SMR{C1P_4553mb1y_15_7h3_truth}`

## Flag 3: Reactor Stabilization → DI-Gated HR
- **Gate**: DI#4 (FLAG3_UNLOCKED) goes HIGH after SAFE ≥5 consecutive ticks
- **Location**: HR[200-231] populated only when DI#4=1
- **Encoding**: hex(base64(flag)) — double encoded
- **Decode chain**: HR → BE bytes → ASCII hex → hex decode → base64 decode

### Mode Unlock Sequence
1. CIP Instance 0x67 Attr 3 → operator note with mode keys
2. MAINTENANCE: HR[0]=0xC0DE, HR[1]=0xCAFE (FC16 atomic)
3. OPERATIONAL: HR[0]=0xC0DE, HR[1]=0xCAFE, HR[2]=0xBEEF, HR[3]=0xDEAD (FC16 atomic)
4. **FC06 sequential FAILS** — only gets MAINTENANCE mode

### Sensor Falsification
- IR (FC04) pressure: ~157 bar (looks SAFE)
- CIP 0x64 TRUE pressure: ~134 bar (NOT SAFE)
- SAFE condition checks CIP truth, NOT IR/HMI
- CIP 0x64 data: LE uint16 packed [temp*10, pres*10, flux*10, rod_pos, ...]

### Stabilization Settings (Sweet Spot)
- Mode: OPERATIONAL (HR[0..3] = C0DE, CAFE, BEEF, DEAD)
- Rod Position: HR[10] = 82 → TRUE TEMP≈494, TRUE PRES≈169
- Pump 1: Coil[1] = ON
- Pump 2: Coil[2] = ON
- Coil[0] = SCRAM (DO NOT SET!)
- Sustain all writes every tick (1 Hz) for ≥5 ticks

### CIP Instance Map
| Instance | Content | Type |
|----------|---------|------|
| 0x64 | TRUE sensor data | binary LE uint16 |
| 0x65 | Flag 2 + SAFE condition | SHORT_STRING |
| 0x66 | Honeypot decoy | SHORT_STRING |
| 0x67 | Operator note + mode keys | SHORT_STRING |

## Key Traps & Lessons
1. **LOCKED mode** silently accepts but ignores writes — no error returned
2. **Pressure falsification** across IR/HMI vs CIP truth
3. **Coil[0] = SCRAM**, not pump — verify coil function before writing
4. **Honeypot CIP instance** wastes time if you stop at first flag-like hit
5. **FC16 mandatory** for atomic mode key write
6. **Physics settling** takes ~12 ticks per rod position change
7. **hex(base64())** double encoding on flag data

## Final Extraction Command
```python
# After DI#4=1:
hr = mb_read(fc=3, addr=200, count=32)
raw = b''.join([struct.pack('>H', v) for v in hr]).rstrip(b'\x00')
flag = base64.b64decode(bytes.fromhex(raw.decode('ascii'))).decode()
```

## Time to Flag
- Flag 1: ~8 min
- Flag 2: ~15 min
- Flag 3: ~25 min
