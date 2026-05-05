---
description: 15-minute mock drill for Modbus + EtherNet/IP with KPI scoring and fail-fast pivots
---

# Modbus + EtherNet/IP 15-Min Mock Drill (Match Mode)

🚨 **15-MIN JUDGE FOCUS DRILL: MODBUS & ENIP (TIGER-RESET-ACMI)**

Use this drill when judges scope only `502` (Modbus) and `44818` (ENIP/CIP).

คำสั่งเริ่ม Drill:

`@solve-challenge [FOCUS_LOCK] target=<ip:port> protocol=<modbus/enip>`

## 0) Rules (Hard)

- Authorized CTF target only.
- Evidence-first, read-first.
- One active lane at a time.
- If same failure repeats 3 times: pivot path, not scope.

## ⏱️ PHASE 1: Modbus Lane (เป้าหมาย: 7 นาที)

Scenario: เจอพอร์ต `502` แต่โจทย์ไม่บอก Unit ID และซ่อน Flag หลัง Logic Gate (ต้อง Write ก่อนถึงอ่าน Flag ได้)

- [ ] **0:00 - Target Lock & PassCheck**: รัน `nc -zvw 10` (ห้ามใช้ ping)

  ```bash
  nc -zvw 10 <target_ip> 502
  ```

  ```text
  [SCOPE_LOCK] authorized_ctf=true target=<host/ip:port> protocol=modbus source=<prompt/lab-note>
  [FOCUS_LOCK] protocols=modbus,enip ports=502,44818 objective=flag_hunt_with_evidence
  [PASSCHECK] scope_ok=true target_lock_ok=true reachability_ok=true timeout_ok=true evidence_mode_ok=true state_safety_ok=true
  ```

- [ ] **0:30 - Map Unit ID (KPI <= 90s)**: ล็อก Unit ให้ได้ภายใน 1 นาทีครึ่ง

  ```bash
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_unit_map.py --ip <target_ip> --port 502 --probe-units --unit-range 1-247 --top 5 --json
  ```

- [ ] **2:00 - Baseline Snapshot (KPI 100% Compliance)**: อ่าน `Coils/Holding/Input` ก่อน write ทุกครั้ง

  ```bash
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py --ip <target_ip> --port 502 --probe-units --unit-range 1-247 --reg-start 0 --reg-end 400 --json
  ```

- [ ] **3:30 - Trigger Gate & Readback**: ยิง FC05/FC06 ปลดล็อก แล้วอ่านซ้ำเช็ค state drift
  - ห้าม unsafe write ข้าม baseline
  - หาก drift ให้ rollback baseline ก่อน reset

- [ ] **5:00 - Flag Capture**: decode payload และเทสต์ endianness (BE/LE)

- [ ] **7:00 - HALT**: หยุดทันที พร้อมรายงาน:

  ```text
  [FLAG] <raw_flag>
  [CLEAN] <sanitized_flag>
  [METHOD] <1-line extraction command or decode chain>
  ```

## ⏱️ PHASE 2: ENIP Lane (เป้าหมาย: 8 นาที)

Scenario: เจอพอร์ต `44818` ดึง Identity ได้ แต่ Tag List พัง (parser mismatch / empty tags)

- [ ] **0:00 - Target Lock & Identity**: เช็คพอร์ต + รัน identity

  ```bash
  nc -zvw 10 <target_ip> 44818
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_list_identity.py --ip <target_ip> --port 44818 --json
  ```

- [ ] **1:00 - Tag Sweep Fail**: ลอง tag hunt แล้วต้องตรวจให้เห็นอาการตัน (`failed to get attribute list` หรือ `tags_found=0`)

  ```bash
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/tiger_enip_exploit.py --ip <target_ip> --hunt --json
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_cpppo_read_find_flags.py --ip <target_ip> --port 44818 --auto-sweep --sweep-range 1-50 --json
  ```

- [ ] **3:00 - Pivot Decision (KPI <= 3 min)**: ออก pivot ทันทีเมื่อรู้ว่าตัน

  ```text
  [PIVOT] reason=tags_empty count=1 from=enip_primary to=enip_hard_fallback scope_ok=true
  ```

- [ ] **4:00 - Hard Fallback Executed**: สลับ explicit message / crafted packet

  ```bash
  /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/SCADA-OT-CheatSheet-Advanced-ICS-Hacking-Playbook/tools/cip_security_assessment/cip_exploiter.py --timeout 3 --retries 1 recon <target_ip> --json
  ```

  ```bash
  PYTHONPATH=/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/SCADA-OT-CheatSheet-Advanced-ICS-Hacking-Playbook /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/SCADA-OT-CheatSheet-Advanced-ICS-Hacking-Playbook/tools/common/ics_tool_cli.py --dry-run cip --target <target_ip> --operation enumerate_objects
  ```

- [ ] **6:00 - Hex/ASCII Decode**: ประกอบ raw payload, ระวัง junk bytes / odd-length hex

- [ ] **8:00 - HALT**: หยุดทันที พร้อมรายงาน:

  ```text
  [FLAG] <raw_flag>
  [CLEAN] <sanitized_flag>
  [METHOD] <1-line extraction command or decode chain>
  ```

## ✅ สรุปเกณฑ์ผ่าน (Pass/Fail)

- [ ] หา Modbus Unit เจอใน `90 วินาที` ไหม? (`KPI-M1`)
- [ ] มี Baseline Snapshot ก่อน Write ไหม? (`KPI-M2`)
- [ ] ตอน ENIP พัง Pivot ได้ใน `3 นาที` ไหม? (`KPI-E1`)
- [ ] หยุดทันทีเมื่อปริ้นท์ Flag สำเร็จไหม? (`KPI-FLAG`)

สรุปผลรอบซ้อม:

```text
[DRILL_RESULT] m1=<pass/fail> m2=<pass/fail> e1=<pass/fail> flag=<pass/fail> total=<x/4>
```
