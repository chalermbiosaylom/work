# IT→OT CTF Writeup (Modbus) – Palantir Control (สรุปแนวทาง)

เอกสารนี้เป็น “สรุปแนวทางทำโจทย์” แบบ IT→OT hybrid ที่พบบ่อยใน OT CTF: เริ่มจากเจาะชั้น IT (scan/เว็บ/cred) แล้ว pivot เข้า OT network เพื่อโจมตี PLC ผ่านโปรโตคอลอุตสาหกรรม (เช่น Modbus) และทำ False Data Injection เพื่อดึง flag.

> Use case: โจทย์จำลองสภาพแวดล้อม PLC/HMI/SCADA, เน้นให้ผู้เล่นใช้เทคนิค IT (enumeration, web vuln, brute-force) เพื่อเข้าถึง segment OT และควบคุม PLC.

## ภาพรวม Flow
1. IT Recon: สแกนพอร์ต/บริการ หา entry point
2. IT Initial Access: เจาะเว็บ/บริการเพื่อได้ foothold
3. Pivot: ทำ tunnel ไปยัง OT subnet (SSH forward / SOCKS)
4. OT Recon: ยืนยันพอร์ต OT (`502/tcp`) + หา Unit ID + map address
5. OT Attack: ใช้ Modbus read/write เพื่อเปลี่ยน state หรือทำ False Data Injection
6. Flag Hunt: อ่าน memory ที่ encode เป็น ASCII/byteswap/wordswap หรือดัก traffic แล้ว regex หา `coc2026{...}`

## 1) IT Recon (เร็ว)
```bash
nmap -Pn -sS -sV -p- --min-rate 5000 <target_ip>
```

ถ้าเจอเว็บ:
```bash
curl -i http://<target_ip>/
```

## 2) IT Initial Access (แนวคิด)
โจทย์แนวนี้มักมีอย่างใดอย่างหนึ่ง:
- CGI/endpoint ที่ misconfig (เช่น path traversal/RCE แบบเบาๆ)
- หน้า admin ที่ brute ได้ (ต้อง rate-limit ตัวเอง)
- credential หลุดในไฟล์/backup/config

เมื่อได้ foothold แล้ว ให้หาว่ามี “อีกเครือข่าย” ที่มองเห็น PLC ได้หรือไม่ (route/ifconfig/arp/cache)

## 3) Pivot เข้าชั้น OT
### Local Port Forward ไป PLC:502
```bash
python3 OT-Security-Lab/ics_toolkit/ssh_tunnel_tool.py \
  --ssh-host <jump_host> --ssh-user <user> --ssh-pass '<pass>' \
  local --target-ip <plc_ip> --target-port 502 --local-port 1502
```

จากนั้นให้ยิง Modbus ที่ `127.0.0.1:1502`

### SOCKS สำหรับ scan OT subnet
```bash
python3 OT-Security-Lab/ics_toolkit/ssh_tunnel_tool.py \
  --ssh-host <jump_host> --ssh-user <user> --ssh-pass '<pass>' \
  socks --local-port 1080
```

## 4) OT Recon – Modbus
### 4.1 ยืนยันพอร์ต 502
```bash
nmap -Pn -sV -p 502 <plc_ip>
```

### 4.2 หา Unit ID (สำคัญมาก)
```bash
python3 OT-Security-Lab/ics_toolkit/pymodbus/modbus_connect_test.py --ip <plc_ip> --port 502
```

## 5) OT Attack – Read/Write + False Data Injection
### 5.1 Read-first: สแกนหาธงแบบเร็ว
สคริปต์นี้สแกนครบ `FC01/02/03/04` และลอง decode แบบ BE/ByteSwap/WordSwap
```bash
python3 OT-Security-Lab/ics_toolkit/pymodbus/modbus_read_find_flags.py <plc_ip> \
  --port 502 --unit 1 --all --reg-end 5000 --bit-end 20000 --stop-after 3
```

ถ้าเอกสาร address เป็น 1-based ให้ลอง:
```bash
python3 OT-Security-Lab/ics_toolkit/pymodbus/modbus_read_find_flags.py <plc_ip> \
  --port 502 --unit 1 --all --address-base 1 --reg-end 5000 --bit-end 20000
```

### 5.2 Write เพื่อ trigger (เฉพาะตอนอ่านไม่เจอ)
```bash
python3 OT-Security-Lab/ics_toolkit/pymodbus/modbus_write_find_flags.py <plc_ip> \
  --port 502 --unit 1 --coil-end 50 --reg-end 50 --values '1,1337,0xFFFF'
```

แนวคิด False Data Injection ที่เจอบ่อย:
- ปรับ register ที่ใช้เป็น “sensor input” ให้ค่าดูปกติ เพื่อผ่าน logic
- toggle coil ที่เป็น manual/override/enable แล้วค่อย set register สำคัญ
- เขียนค่าแล้ว “อ่านซ้ำทันที” เพราะบางโจทย์จะ reset อัตโนมัติ

## 6) Traffic/PCAP (เวลาคิดว่าธงวิ่งผ่านเครือข่าย)
### Sniff live
```bash
python3 OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_sniffer.py --iface <iface>
```

### Extract จาก PCAP
```bash
python3 OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_flag_extract_pcap.py capture.pcap
```

## Anti-Trap Checklist (CTF)
- อ่านก่อนเขียน: เก็บ baseline state ของ coils/registers
- จำกัดช่วงสแกน: ถ้าอ่านยาวแล้วได้ `0x0000` ซ้ำ ๆ ให้หยุดและ pivot ไปช่วงอื่น
- ตั้ง timeout สั้น (3–5s) และอ่านแบบ chunk (`HR/IR` ไม่เกิน 125 regs ต่อครั้ง)
- ถ้าเจอข้อความประหลาดคล้าย flag ให้ลอง ByteSwap/WordSwap

## Mapping ไปที่ Toolkit ใน repo นี้
- Modbus read flags: `OT-Security-Lab/ics_toolkit/pymodbus/modbus_read_find_flags.py`
- Modbus write trigger: `OT-Security-Lab/ics_toolkit/pymodbus/modbus_write_find_flags.py`
- Modbus triage unit id: `OT-Security-Lab/ics_toolkit/pymodbus/modbus_connect_test.py`
- Tunnel/pivot: `OT-Security-Lab/ics_toolkit/ssh_tunnel_tool.py`

