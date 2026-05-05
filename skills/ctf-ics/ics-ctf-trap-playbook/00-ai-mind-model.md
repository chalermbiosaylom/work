# 00 - วิเคราะห์ "สมอง" AI เมื่อถูกสั่งสร้างโจทย์ ICS CTF

## Prompt ที่กรรมการจะใช้

เมื่อกรรมการสั่ง AI สร้างโจทย์ prompt จะมีลักษณะประมาณนี้:

```
"สร้างโจทย์ CTF หัวข้อ ICS/OT security ใช้ Modbus TCP และ EtherNet/IP
มี flag format coc2026{...}
สร้าง trap เพื่อป้องกันไม่ให้ AI solver หรือ automation tool แก้ได้ง่าย
ระดับความยาก easy/medium/hard"
```

## AI คิดอย่างไรเมื่อได้รับ Prompt นี้

AI ไม่ได้ "คิด" จริงๆ แต่มัน generate จาก pattern ที่เคยเห็นใน training data
นี่คือ decision tree ภายในของ AI:

```
ได้รับ prompt "สร้างโจทย์ ICS CTF + trap"
│
├─ Step 1: เลือก protocol
│   ├─ Modbus TCP (port 502) ← เลือกเกือบทุกครั้ง
│   ├─ EtherNet/IP (port 44818) ← เลือกบ่อย
│   ├─ DNP3 (port 20000) ← เลือกน้อย
│   ├─ OPC UA (port 4840) ← เลือกบางครั้ง
│   └─ BACnet (port 47808) ← เลือกน้อยมาก
│
├─ Step 2: เลือก trap category
│   ├─ Encoding trap (byte swap, XOR, base64)
│   ├─ Timing trap (pulse, delay window)
│   ├─ State machine trap (write-then-read)
│   ├─ Honeypot/Tarpit (delay decoy)
│   ├─ Exception trap (flag in error response)
│   └─ Parsing trap (array/struct ที่ต้อง manual parse)
│
├─ Step 3: เลือก flag hiding method
│   ├─ ซ่อนใน register/tag ที่ต้อง decode
│   ├─ ซ่อนใน identity/banner
│   ├─ ซ่อนใน error response
│   ├─ ซ่อนหลัง state change
│   └─ ซ่อนใน timing-dependent response
│
└─ Step 4: สร้าง "anti-AI" mechanism
    ├─ Tarpit ที่ register ต้นๆ
    ├─ Rate limiting
    ├─ Timing window ที่แคบ
    ├─ ต้อง multi-step interaction
    └─ Exception ที่ทำให้ automation abort
```

## ข้อจำกัดของ AI ที่เราใช้ประโยชน์ได้

### 1. AI ใช้ library ยอดนิยมเท่านั้น

AI จะเขียน server ด้วย library ที่มันรู้จัก:

| Protocol | Library ที่ AI จะใช้ | ทำไม |
|----------|---------------------|------|
| Modbus | `pymodbus` | มี example มากสุดใน training data |
| EtherNet/IP | `cpppo` | เกือบเป็น library เดียวที่ AI รู้จัก |
| OPC UA | `opcua` / `asyncua` | Python library หลัก |
| DNP3 | `pydnp3` / custom | มี example น้อย AI มักเขียนเอง |

**ประโยชน์**: เรารู้ว่า server ทำงานยังไง เพราะ library behavior คาดเดาได้

### 2. AI ตั้งชื่อที่บอกใบ้เสมอ

AI ไม่สามารถตั้งชื่อที่ไม่มีความหมายได้ มันจะตั้งชื่อที่ "อธิบายตัวเอง":

```python
# AI จะตั้งชื่อแบบนี้ (บอกใบ้หมด)
class TarpitDataBlock:        # บอกว่าเป็น tarpit
class ExceptionTrapHandler:   # บอกว่าเป็น exception trap
FLAG_REGISTER = 100           # บอกว่า flag อยู่ register 100
SECRET_UNIT_ID = 42           # บอกว่า unit ID 42 มีอะไรซ่อน
PULSE_MIN_TIME = 0.2          # บอก timing window
PULSE_MAX_TIME = 1.5          # บอก timing window

# AI ไม่สามารถตั้งชื่อแบบนี้ได้ (เพราะมันต้อง "เข้าใจ" code ตัวเอง)
class Xk9mHandler:            # AI ไม่ทำแบบนี้
_r = 100                      # AI ไม่ทำแบบนี้
```

### 3. AI สร้าง trap ได้ไม่เกิน ~8 แบบ

ไม่ว่าจะถาม AI กี่ครั้ง trap ที่ได้จะวนอยู่ใน pool นี้:

| # | Trap Type | ความถี่ที่ AI สร้าง |
|---|-----------|--------------------|
| 1 | Byte/Endianness swap | ★★★★★ (เกือบทุกครั้ง) |
| 2 | Tarpit/Honeypot delay | ★★★★★ (เกือบทุกครั้ง) |
| 3 | Hidden Unit ID / address | ★★★★☆ |
| 4 | Timing window (pulse) | ★★★★☆ |
| 5 | State machine (write-then-read) | ★★★★☆ |
| 6 | Exception/Error hiding | ★★★☆☆ |
| 7 | Array/Struct parsing | ★★★☆☆ |
| 8 | XOR / simple encryption | ★★☆☆☆ |

**trap อื่นที่ AI แทบไม่เคยสร้าง** (เพราะไม่มีใน training data มากพอ):
- Protocol-level manipulation (แก้ packet structure)
- Cryptographic challenge (ต้องใช้ key จาก physical process)
- Multi-protocol correlation (ต้องรวมข้อมูลจากหลาย protocol)
- Real PLC logic (ladder logic / function block)

### 4. AI วาง flag ตาม pattern ที่คาดเดาได้

```
Modbus register layout ที่ AI สร้าง:

  HR 0-10:    Tarpit zone (decoy, delay)
  HR 11-99:   ว่างเปล่า หรือ dummy data
  HR 100-150: ★ Flag zone 1 (encoded)
  HR 151-199: ว่างเปล่า
  HR 200-250: ★ Flag zone 2 (exception trigger)
  HR 251+:    ว่างเปล่า

Unit IDs ที่ AI ชอบใช้:
  1:   Default (มี flag หรือ tarpit)
  42:  "Hidden" unit (AI ชอบเลข 42)
  99:  Exception trap unit
  100: Alternative hidden unit
  127: บางครั้ง
  255: Broadcast (บางครั้ง)

EtherNet/IP tags ที่ AI ชอบตั้ง:
  Sec_Data, SecretData, Secret, Flag_Data
  Admin_Mode, AdminMode, Admin_Access
  System_Key, SystemKey, Master_Key
  Config, Status, Control, Sensor_1
```

### 5. AI สร้าง flag ที่ "ดูเท่" แต่ predictable

Flag ที่ AI generate จะมี pattern:
```
coc2026{M0dbus_3nd1an_Sw4p}      ← leetspeak + อธิบาย trap
coc2026{T1m1ng_1s_Ev3ryth1ng}    ← leetspeak + hint
coc2026{St4t3_M4ch1n3_Byp4ss}    ← leetspeak + hint
coc2026{3xc3pt10n_H4ndl3r}       ← leetspeak + hint
coc2026{ENIP_R3c0n_M4st3r}       ← leetspeak + protocol name
```

AI ไม่สามารถสร้าง flag ที่ random จริงๆ ได้ เช่น `coc2026{x8Km2pQ9vL}`
เพราะมันจะ "อธิบาย" challenge ใน flag เสมอ
