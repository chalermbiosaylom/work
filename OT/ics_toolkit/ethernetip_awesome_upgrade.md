# 🏴‍☠️ EtherNet/IP & CIP (TCP/44818, UDP/2222) – Ultimate OT CTF Cheat Sheet
**Status:** `[🔥 God-Mode Enabled]` `[🧠 AI-Ready]`

เอกสารสรุปแนวทางการเจาะระบบและการทำ Data Extraction สำหรับเป้าหมายสาย **Rockwell Automation / Allen-Bradley** ในสนามแข่ง ICS/OT CTF

---

## 📡 1. Protocol Intelligence (ข้อมูลเป้าหมาย)
- **Protocol Name:** EtherNet/IP (ENIP)
- **Core Engine:** CIP (Common Industrial Protocol) วิ่งอยู่ข้างใน ENIP อีกที
- **Target Ports:**
  - `44818/tcp` : Explicit Messaging (การส่งคำสั่งอ่าน/เขียน Tag แบบเจาะจง, ListIdentity)
  - `2222/udp`  : Implicit I/O (การส่งข้อมูลเซนเซอร์/วาล์ว แบบสตรีมมิ่งความเร็วสูง)
- **Nmap Scripts:** `enip-info.nse`, `enip-enumerate.nse`
- **Wireshark Dissector:** `enip` และ `cip`

---

## 🎯 2. Flag Hunting Pattern (จุดซ่อน Flag ยอดฮิต)
ผู้สร้างโจทย์มักจะไม่ส่ง Flag มาให้เห็นง่ายๆ ด้วยข้อจำกัดของ CIP Data Types:
1. **The Null-Byte Trap:** ข้อมูลประเภท CIP String มักจะมี `\x00` คั่นระหว่างตัวอักษร ทำให้ Regex ทั่วไปจับไม่ติด ต้องทำ Denull ก่อน
2. **UTF-16LE Encoding:** สาย Rockwell ชอบเข้ารหัสตัวอักษรแบบ 16-bit (เช่น `WSTRING`) 
3. **Identity Spoofing:** เอา Flag ไปซ่อนแทนชื่อ `Product Name`, `Vendor` หรือ `Serial Number` ของตัว PLC
4. **Data Type Casting:** เอาค่า String ไปซ่อนใน Array ของตัวเลข (เช่น ซ่อนใน `REAL[10]` หรือ `DINT`) ทำให้ดึงออกมาแล้วเป็นเลขทศนิยมขยะ ต้องเอามา Byte Swap คืนร่างเป็น ASCII

---

## ⚔️ 3. The Attack Kill Chain (Workflow การเจาะ)

1. **Recon & Identity (เร็วสุด):**
   - ยิงคำสั่ง `ListIdentity` (0x0063) ทันทีที่เจอพอร์ต 44818 เพื่อดูว่า Flag หลุดมากับ Banner ข้อมูลอุปกรณ์หรือไม่
2. **Passive Interception:**
   - หากมีไฟล์ PCAP หรืออยู่ในเครือข่าย ให้ใช้ Sniffer ดักจับ/สกัด Flag ที่เข้ารหัส UTF-16LE หรือ Byte Swap ออกมา
3. **Active Memory Sweep:**
   - หากโจทย์ให้ Path มา (เช่น `@8/1/5`) ให้อ่านโดยตรง 
   - หากไม่ให้มา ให้เปิดโหมด `--auto-sweep` กวาดหา Class 8 (CIP Object ยอดฮิต)
4. **False Data Injection (Triggering):**
   - หากระบบไม่คาย Flag จนกว่าลอจิกบางอย่างจะทำงาน ให้เขียนค่า (Write) ทับตัวแปรเพื่อสับสวิตช์จำลอง และใช้แทคติก `--restore` เพื่อคืนค่าเดิมป้องกันโจทย์พัง

---

## 🛠️ 4. Arsenal & Execution (คลังอาวุธและวิธีใช้)

ทุกสคริปต์รองรับโหมด `--json` เพื่อส่ง Output ให้ AI Agent (Trae IDE) นำไปวิเคราะห์ต่อโดยอัตโนมัติ

### [Phase 1] Discovery & Recon
**สคริปต์:** `ics_toolkit/enip/enip_list_identity.py`
```bash
# ดึงข้อมูล PLC Identity ทั่วไป (ดู Product Name, Serial)
python3 OT-Security-Lab/ics_toolkit/enip/enip_list_identity.py --ip <IP>

# ดึงข้อมูลพร้อมดู Hex Dump ดิบๆ
python3 OT-Security-Lab/ics_toolkit/enip/enip_list_identity.py --ip <IP> --hex

[Phase 2] Tag Sweeping & Extraction
สคริปต์: ics_toolkit/enip/enip_cpppo_read_find_flags.py

Bash
# อ่าน Tag แบบระบุชื่อและ Data Type (เช่น REAL Array)
python3 OT-Security-Lab/ics_toolkit/enip/enip_cpppo_read_find_flags.py --ip <IP> --tag "SecretTag" --type "REAL[10]"

# ปูพรมกวาดแบบไม่รู้ชื่อ Tag (Auto Sweep Class 8)
python3 OT-Security-Lab/ics_toolkit/enip/enip_cpppo_read_find_flags.py --ip <IP> --auto-sweep --sweep-range 1-50 --sweep-attrs 1-10
[Phase 3] Attack & Injection (Write Trigger)
สคริปต์: ics_toolkit/enip/enip_cpppo_write_find_flags.py

Bash
# โจมตีแบบปลอดภัย (เขียนค่าเพื่อ Trigger แล้วคืนค่าเดิมทันที)
python3 OT-Security-Lab/ics_toolkit/enip/enip_cpppo_write_find_flags.py --ip <IP> --tag "Valve_State" --type "BOOL" --write "1" --restore

# อัด Data ลง Array หลายช่องพร้อมกัน
python3 OT-Security-Lab/ics_toolkit/enip/enip_cpppo_write_find_flags.py --ip <IP> --tag "DataBuffer" --type "INT" --write "1337,1338,1339"
[Phase 4] PCAP Forensics
สคริปต์: ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py

Bash
# สกัด Flag จาก PCAP (ค้นหาผ่านพอร์ต 44818 และ 2222 พร้อมแก้ Endianness)
python3 OT-Security-Lab/ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py capture.pcap

# สกัด Flag แบบดึงทุกพอร์ต (เผื่อโจทย์หลอก) + กำหนด Regex ของทีม
python3 OT-Security-Lab/ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py capture.pcap --all-ports --flag-regex "(coc2026|flag)\{[^}]+\}"

🤖 5. Trae IDE (AI Agent) Prompts
คำสั่งสำหรับป้อนให้ AI ช่วยทำ Automation:

1. หาเบาะแสจาก Identity:

"สแกนเป้าหมาย ENIP ให้รัน python3 enip_list_identity.py --ip <IP> --json อ่าน JSON แล้วบอกฉันว่ามี Flag ซ่อนใน product_name หรือ serial_number หรือไม่"

2. สแกนหาหน่วยความจำลับ:

"รัน python3 enip_cpppo_read_find_flags.py --ip <IP> --auto-sweep --sweep-range 1-100 --json หากฟิลด์ flags_found ไม่ว่างเปล่า ให้บอกค่า Flag และ Tag Path ที่เจอมัน"

3. โจมตีและคืนสภาพ:

"โจมตีตัวแปรระบบ ให้รัน python3 enip_cpppo_write_find_flags.py --ip <IP> --tag <TAG> --write <VAL> --restore --json และยืนยันผลจาก restore_status ว่าระบบไม่พัง"