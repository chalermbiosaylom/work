# EtherNet/IP & CIP (TCP 44818) Cheatsheet

เอกสารนี้สรุปแนวทางทำ CTF/ทดสอบระบบด้วย EtherNet/IP (ENIP) และ Common Industrial Protocol (CIP) โดยโฟกัสงานสาย “ดึงข้อมูลจาก PLC” ผ่านพอร์ต `TCP/44818`.

## Quick Start (ใน lab นี้)

- เครื่องมือหลัก (Python): `pycomm3` (ใช้ `CIPDriver`/`LogixDriver`)
- สคริปต์ใน repo:
  - `cipTool/main.py` (CLI เดิม)
  - `cipTool/tiger_enip_exploit.py` (CLI ใหม่สำหรับ CTF)
  - `ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py` (สกัด flag จาก PCAP)

ติดตั้ง dependency ที่จำเป็นสำหรับ `cipTool`:

```bash
python3 -m venv RTAF-CTF-2026/OT-Security-Lab/.venv
RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python -m pip install -r RTAF-CTF-2026/OT-Security-Lab/cipTool/requirements.txt
```

หมายเหตุ: สคริปต์สาย `scapy` มักต้องรันด้วยสิทธิ์สูง (เช่น `sudo`) หาก sniff/อ่าน interface.

ติดตั้ง dependency ที่จำเป็นสำหรับ `ics_toolkit`:

```bash
RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python -m pip install -r RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/requirements.txt
```

## ภาพรวม Protocol (จำเป็นต่อ CTF)

- **ENIP (EtherNet/IP)**: transport layer บน TCP/UDP
  - `TCP/44818` = explicit messaging (request/response)
  - `UDP/2222` = implicit I/O (cyclic) (พบในบางโจทย์/pcap)
- **CIP**: object model แบบ RPC
  - โครงสร้างเป้าหมาย = **SCIA**
    - `Service` (ฟังก์ชัน)
    - `Class` (Object class)
    - `Instance` (object instance)
    - `Attribute` (field)

## Service IDs ที่ใช้บ่อย

- `0x01` = Get_Attribute_All
- `0x0E` = Get_Attribute_Single
- `0x03` = Get_Attribute_List
- `0x10` = Set_Attribute_Single

CTF tip: เริ่มจาก `Get_Attribute_All` บน Identity Object เพื่อ fingerprint รุ่น/ข้อมูล baseline ก่อนยิง class แปลกๆ.

## Object ที่ควรรู้ (สาย Enumeration)

- `Class 0x01` = Identity Object
  - ใช้ดึง Vendor/Product/Revision/Serial/Product Name (พบบ่อยมากในโจทย์)

ข้อสังเกต: บางอุปกรณ์/เฟิร์มแวร์มี vendor-specific class เพิ่มเติม (จุดซ่อน flag ชอบอยู่ตรงนี้)

## CIP Path / Routing (สำคัญมาก)

- Target เดียว (เข้าตรง IP): `192.168.1.10`
- ผ่าน backplane/slot (เช่น Rockwell): `192.168.1.10/1,0` หรือรูปแบบที่โจทย์กำหนด

แนวคิด: ถ้า `cip_path` มี `,` หรือ `/` ให้ถือว่ามี routing (multi-hop/backplane) และต้องใช้ unconnected send/route path ให้ถูกต้อง

## pycomm3 Mapping (จากโค้ด cipTool)

- ส่ง explicit message แบบ SCIA: `CIPDriver.generic_message(service, class_code, instance, attribute, request_data)`
- ใน `cipTool` มี logic ช่วยเลือก flags ตอน routing:
  - ถ้า path มี `,` หรือ `/` → `connected=False`, `unconnected_send=True`, `route_path=True`
  - ดูตัวอย่างใน `cipTool/util.py`

## Workflow แนะนำ (CTF Speedrun)

### 1) Discovery (หา PLC ในวง)

- ใช้ broadcast discovery ของ `pycomm3`:
  - `CIPDriver.discover()`
  - ใน `tiger_enip_exploit.py` มีเมนู `Discovery scan`

### 2) Fingerprint รุ่น/เฟิร์มแวร์

- ยิง Identity Object (`service 0x01 class 0x01 instance 0x01`)
- ใน `tiger_enip_exploit.py` เมนู `Read target model/firmware`

### 3) Tag Enumeration + Flag Hunting

- ใช้ `LogixDriver.get_tag_list()` เพื่อดึงรายการ tags
- อ่านค่าจริงด้วย `LogixDriver.read(tag)` แล้วสแกนหา pattern `coc2026{}`/`flag{}`
- เทคนิคสแกนที่ควรทำ (สคริปต์ `tiger_enip_exploit.py` ทำแล้ว):
  - plaintext
  - hex string ที่ถูกฝังในค่า/ชื่อ
  - UTF-16LE/WSTRING (พบได้ในบางระบบ)

### 4) Custom SCIA (ล้วง object ลับ)

- เมนูยิง custom ใน `tiger_enip_exploit.py` ช่วยให้ใส่ `Service/Class/Instance/Attribute` เอง
- ใช้ลองยิง class/instance แปลกๆ หรือ vendor-specific ที่ซ่อน flag

## ทริค CTF เพิ่มเติม (44818)

- **Controller vs Program tags**: โจทย์ชอบซ่อน flag ใน Program scope (เช่น `Program:MainProgram.FlagStr`) มากกว่าแค่ controller tag
- **ชนิด STRING/WSTRING/UDT/Array**: flag อาจอยู่ใน member ของ UDT หรือ element ของ array → ต้องลองอ่านเป็นรายตัว หรืออ่าน tag ทั้งก้อนแล้ว parse
- **“hex-flag”**: บางโจทย์ฝัง flag เป็น hex ใน string/bytes → ต้อง decode hex แล้วหา `{...}`
- **PCAP-first**: ถ้าโจทย์ให้ไฟล์ `.pcap` มาก่อน ให้สแกนหา flag ใน traffic ก่อน (เร็วกว่า brute)
  - ใช้ `ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py`
- **Key Switch / Mode**: บางโจทย์ให้ข้อมูลเกี่ยวกับ run/program/remote ผ่าน attribute (ขึ้นกับยี่ห้อ/รุ่น)
  - ใน `cipTool` มีตัวอย่างอ่านสถานะผ่าน `service 0x0E class 0x01 instance 0x01 attribute 0x05` (อาจไม่ universal)
- **อย่าพึ่งเขียนค่า**: คำสั่ง `Set_Attribute_*` หรือ write tag อาจทำให้ PLC เปลี่ยน state/ล็อคตัวเอง (หรือทำโจทย์พัง) ควรอ่านอย่างเดียวก่อน

## Sniff/PCAP Flag Extraction

สคริปต์สกัด flag จาก pcap (รองรับ ENIP/TCP 44818 และ CIP/UDP 2222):

```bash
python3 RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/enip_flag_extract_pcap.py capture.pcap
```

## Reference (ใน repo)

- `cipTool/util.py` = ตัวอย่าง `generic_message()` และเงื่อนไข routing
- `cipTool/structs.py` = โครงสร้าง decode identity
- `docs/Writerside/topics/CIP-CTF.md` = ภาพรวม CIP model (SCIA, routing, services)

---

## 🧩 Advanced ENIP/CIP Code Snippets (from ctf-ics SKILL.md)

### CIP Assembly Instance Full Sweep (Lightweight CIP Devices)

```python
import socket, struct

def cip_sweep_assembly(target_ip, port=44818, interface=None):
    """Sweep CIP Assembly Class (0x04) instances 0x01-0xFF"""
    results = {}
    for inst in range(1, 256):
        for attr in [3, 1, 2]:  # attr 3 first (data), then metadata
            try:
                s = socket.socket()
                s.settimeout(5)
                if interface:
                    s.setsockopt(socket.SOL_SOCKET, 25, (interface + '\0').encode())
                s.connect((target_ip, port))
                
                # RegisterSession
                reg = struct.pack('<HH', 1, 0)
                s.send(struct.pack('<HH', 0x0065, len(reg)) + b'\x00'*20 + reg)
                resp = s.recv(1024)
                session = struct.unpack('<I', resp[4:8])[0]
                
                # Get_Attribute_Single on Assembly/inst/attr
                cip = struct.pack('<BB', 0x0E, 3)
                cip += struct.pack('<BB', 0x20, 0x04)
                cip += struct.pack('<BB', 0x24, inst)
                cip += struct.pack('<BB', 0x30, attr)
                cpf = struct.pack('<H', 2) + struct.pack('<HH', 0, 0)
                cpf += struct.pack('<HH', 0x00B2, len(cip)) + cip
                encap = struct.pack('<IH', 0, 10) + cpf
                s.send(struct.pack('<HH', 0x006F, len(encap))
                       + struct.pack('<I', session) + b'\x00'*16 + encap)
                resp = s.recv(4096)
                s.close()
                
                if len(resp) >= 44:
                    cip_r = resp[40:]  # CIP data starts at offset 40
                    if cip_r[2] == 0:  # status OK
                        data = cip_r[4:]
                        results[(inst, attr)] = data
                        # Try SHORT_STRING interpretation
                        if len(data) > 1 and data[0] < len(data):
                            try:
                                text = data[1:1+data[0]].decode('ascii')
                                print(f'  Inst 0x{inst:02x} Attr {attr}: STRING({data[0]}) = "{text}"')
                            except: pass
                        # Try binary sensor data (LE uint16)
                        elif len(data) >= 8:
                            vals = [struct.unpack('<H', data[i:i+2])[0]
                                    for i in range(0, min(len(data), 16), 2)]
                            print(f'  Inst 0x{inst:02x} Attr {attr}: BINARY = {vals}')
            except: pass
    return results
```

### ENIP Crafted Explicit Message Skeleton

```python
import socket, struct

def enip_hdr(cmd, length, session=0, ctx=b'CTX12345'):
    return struct.pack('<HHII8sI', cmd, length, session, 0, ctx, 0)

def cip_req(service, cls, inst, attr):
    path = bytes([0x20, cls, 0x24, inst, 0x30, attr])
    return bytes([service, len(path) // 2]) + path
```

### ENIP Symbol Object Sweep (When Tag List Fails)

```python
from pycomm3 import CIPDriver

with CIPDriver("<target_ip>") as plc:
    for inst in range(1, 256):
        for attr in range(1, 8):
            resp = plc.generic_message(
                service=0x01,
                class_code=0x6B,
                instance=inst,
                attribute=attr,
                connected=True,
                unconnected_send=False,
                route_path=True,
            )
```
