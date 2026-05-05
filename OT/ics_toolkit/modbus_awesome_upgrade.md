# Modbus (TCP/502) – CTF/OT Quick Sheet

## Protocol Facts
- Transport: Modbus/TCP over TCP `502`
- Header: MBAP (7 bytes) + PDU
  - Transaction ID (2)
  - Protocol ID (2) = `0x0000`
  - Length (2) = bytes after this field (Unit ID + PDU)
  - Unit ID (1) = slave/unit identifier (สำคัญมากใน CTF)

## Core Function Codes (ที่เจอบ่อย)
- `0x01` Read Coils (C)
- `0x02` Read Discrete Inputs (DI)
- `0x03` Read Holding Registers (HR)
- `0x04` Read Input Registers (IR)
- `0x05` Write Single Coil
- `0x06` Write Single Register
- `0x0F` Write Multiple Coils
- `0x10` Write Multiple Registers

## Addressing Pitfalls (ที่ทำให้พลาดธง)
- Modbus “เลขพื้นที่” แบบ `0xxxx/1xxxx/3xxxx/4xxxx` เป็น convention ในเอกสาร ไม่ใช่ค่าที่ส่งในโปรโตคอล
- ในคำสั่งจริง “address” เป็น 0-based เกือบทั้งหมด
- ถ้าโจทย์ให้ `40001` บ่อยครั้งหมายถึง HR address `0` (ลองทั้ง base 0 และ base 1)

## CTF Flag Hunting Pattern
- Flag มักซ่อนใน:
  - HR/IR เป็น ASCII ที่ถูก pack เป็น 16-bit registers
  - Byte-swap (สลับ byte ใน register) หรือ word-swap (สลับ register เป็นคู่) ทำให้ข้อความอ่านไม่ออก
  - Coils/DI บางโจทย์ encode flag ผ่าน bitstream
- แนวทางเร็ว:
  - หา unit id ก่อน (1–5, 255, หรือ brute 1–247)
  - อ่าน HR/IR chunk ขนาด 125 registers
  - อ่าน Coils/DI chunk ขนาด 2000 bits
  - decode แบบ BE/ByteSwap + WordSwap แล้ว regex หา `coc2026{...}`

## Recon/Enum Checklist
- เปิดพอร์ต/บริการ: `nmap -sV -p 502 <ip>`
- ตรวจ unit id:
  - ใช้สคริปต์ `pymodbus/modbus_connect_test.py`
  - หรือใช้ `pymodbus/modbus_read_find_flags.py --probe-units --unit-range 1-247`

## Safe Write Notes (CTF)
- Modbus ไม่มี auth โดยธรรมชาติ หลายโจทย์ให้ “write เพื่อ trigger”
- เขียนทีละตัวและอ่านค่า state ก่อน/หลังเสมอ (ป้องกันโจทย์วางกับดัก)
- ถ้าอ่านไม่เจอ ให้ลอง:
  - toggle coils ที่เกี่ยวกับ mode/manual/enable
  - set register ค่า `1`, `1337`, `0xFFFF`, แล้วอ่านซ้ำ

## Local Toolkit (ใน repo นี้)
- Read/scan flags: `ics_toolkit/pymodbus/modbus_read_find_flags.py`
- Simple read: `ics_toolkit/pymodbus/modbus_read_holding_registers.py`
- Write trigger: `ics_toolkit/pymodbus/modbus_write_find_flags.py`
- Sniff/PCAP: `ics_toolkit/scapy_scripts/modbus_sniffer.py`, `ics_toolkit/scapy_scripts/modbus_flag_extract_pcap.py`

