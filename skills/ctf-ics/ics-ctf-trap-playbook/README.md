# 🛡️ RTAF COC 2026: ICS/OT CTF Ultimate Anti-Trap Playbook

## วัตถุประสงค์

Playbook นี้ไม่ได้แก้โจทย์ใดโจทย์หนึ่ง แต่เป็น **meta-analysis** ที่ตอบคำถามว่า:

> ถ้ามีคนสั่งให้ AI (Gemini, ChatGPT, Claude, etc.) เขียนโจทย์ ICS/OT CTF
> พร้อมสร้าง trap เพื่อป้องกัน AI solver automation
> AI จะสร้างออกมาแบบไหน? และจะทะลุมันได้อย่างไร?

## 📚 เอกสาร

| ไฟล์ | เนื้อหา |
|------|--------|
| [VERIFIED-LESSONS.md](./VERIFIED-LESSONS.md) | **✅ VERIFIED - Battle-tested lessons from RTAF COC 2026** |
| [00-ai-mind-model.md](./00-ai-mind-model.md) | วิเคราะห์ "สมอง" ของ AI เมื่อถูกสั่งให้สร้างโจทย์ CTF |
| [01-predicted-traps.md](./01-predicted-traps.md) | ทุก trap pattern ที่ AI จะสร้าง จัดหมวดหมู่ครบ (100% match) |
| [02-universal-bypass.md](./02-universal-bypass.md) | เทคนิคทะลุ trap ที่ใช้ได้กับทุก pattern (verified) |
| [03-solver-framework.md](./03-solver-framework.md) | Framework สำหรับ solve โจทย์ที่ไม่เคยเห็นมาก่อน |
| [04-anti-ai-playbook.md](./04-anti-ai-playbook.md) | **Ultimate Playbook ฉบับสมบูรณ์** |
| [05-anti-ai-trap-detection.md](./05-anti-ai-trap-detection.md) | **🆕 Trap Detection + Windsurf IDE Integration** |
| [solvers/](./solvers/) | Script ที่พร้อมใช้งาน |

## 🎯 Quick Reference: Trap Categories

**✅ VERIFIED = Confirmed in real RTAF CTF challenges**

```
┌─────────────────────────────────────────────────────────────────┐
│  #MODBUS_TRAPS (Port 502)                                       │
│  ├── ✅ Tarpits (HR 0-20, 2.5s delay)                           │
│  ├── ✅ Endianness Swap (CDAB byte order, HR 100-110)           │
│  ├── ✅ Hidden Unit ID (Unit 42 for timing, Unit 99 for except) │
│  ├── ✅ Timing Pulse (Coil 50, window 0.2-1.5s, sweet 0.5-0.8s) │
│  ├── ✅ Exception Side-Effect (HR 200=0xFFFF throws but writes)  │
│  ├── TCP Fragmentation (ดักโค้ดสำเร็จรูป)                        │
│  └── Dynamic Checksum / Challenge-Response (ดัก Replay)         │
├─────────────────────────────────────────────────────────────────┤
│  #ENIP_TRAPS (Port 44818 & 2222)                                │
│  ├── ✅ INT Array Parsing (INT[12], 2 ASCII/int, hi-lo order)   │
│  ├── ✅ Stateful Boolean Gate (Admin_Mode=BOOL → System_Key)    │
│  ├── Advanced CIP Routing (ดักเส้นทางเริ่มต้น)                   │
│  └── Implicit Messaging (ดักยิง TCP อย่างเดียว)                  │
├─────────────────────────────────────────────────────────────────┤
│  #TELEMETRY_CROSSDOMAIN_TRAPS (UAV/GPS Logic)                   │
│  ├── Relative Offset & Mission Reference (ดักค่าพิกัดลวง)       │
│  ├── Telemetry Reassembly (ดักคนใช้ String Parsing)             │
│  └── Protocol Encapsulation (ซ่อนข้ามโปรโตคอล)                  │
├─────────────────────────────────────────────────────────────────┤
│  #PROG_WEB_TRAPS (Programming & Edge Cases)                     │
│  ├── Invisible Characters & Data Sanitization                   │
│  ├── Time Complexity (Execution Timeout)                        │
│  ├── Proof of Work (PoW) Block                                  │
│  └── Floating Point Precision Loss                              │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start (Windsurf IDE)

```bash
# 1. Install dependencies
cd /home/kali/Desktop/.windsurf/skills/ctf-ics/ics-ctf-trap-playbook
pip install -r requirements.txt

# 2. Run trap detection FIRST
python3 trap_detector.py --ip <target> --port 502 --full-scan --json

# 3. Run universal bypass
python3 universal_bypass.py --ip <target> --port 502 --auto --json

# 4. Validate flags (anti-hallucination)
python3 hallucination_guard.py --validate-flag "coc2026{...}" \
  --command "<command_used>" --output "<raw_output>"
```

## 🛡️ Anti-Hallucination Protocol

**VERIFIED CRITICAL RULES FROM REAL CHALLENGES:**

```
❌ FORBIDDEN:
- สมมติว่า flag อยู่ที่ address ใด โดยไม่มี evidence
- ใช้ Unit ID โดยไม่ probe ก่อน
- รายงาน flag ที่ไม่ได้มาจาก command output จริง
- ❌ ABORT on Modbus exceptions (flag may be in side-effect!)
- ❌ Use integer for ENIP BOOL tags (must cast to (BOOL))

✅ REQUIRED:
- Probe Unit IDs ก่อนทุกครั้ง (especially 42, 99)
- ยืนยัน response ก่อน decode
- ตรวจสอบ flag format ก่อนรายงาน
- เก็บ evidence ของทุก step
- ✅ Read target address AFTER exception
- ✅ Filter INT array with printable range (0x20-0x7E)
- ✅ Try timing sweet spots: 0.5s, 0.7s, 0.8s first
```

## 🎯 Victory Protocol

เมื่อพบ flag ให้รายงานในรูปแบบนี้:

```
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line extraction command or decode chain>
```

## หลักการสำคัญ

AI มี **ข้อจำกัดพื้นฐาน** ที่ทำให้ trap ที่มันสร้างถูกทะลุได้เสมอ:

1. **AI สร้างจาก training data** - trap ทุกอันมาจาก pattern ที่เคยเห็น ไม่มีอะไรใหม่จริงๆ
2. **AI ต้องทำให้โจทย์ solvable** - ถ้า trap แก้ไม่ได้ มันก็ไม่ใช่โจทย์ CTF
3. **AI เขียน code ที่ readable** - มันไม่สามารถสร้าง obfuscation ที่ดีจริงๆ ได้
4. **AI มี pattern ซ้ำๆ** - ถามกี่ครั้งก็ได้ trap แบบเดิมๆ
5. **AI บอก hint ในตัวเอง** - ชื่อตัวแปร, comment, log message ล้วนเป็น hint

## 🎯 VERIFIED LESSONS (RTAF COC 2026)

**From Real Modbus/ENIP Challenges:**

1. **Exception = Opportunity**: Modbus exceptions often hide flags in side-effects
2. **Unit ID Matters**: 42 (timing), 99 (exceptions) are AI favorites
3. **Timing Sweet Spots**: For 0.2-1.5s windows, try 0.5-0.8s first
4. **INT Arrays Need Filtering**: Check 0x20-0x7E before chr() to avoid garbage
5. **ENIP Type Strictness**: Boolean tags need `(BOOL)1`, not integer `1`
6. **Endianness is Real**: CDAB (lo-hi swap) is most common AI trap

> **Remember:** AI สร้าง trap จาก pattern ที่คาดเดาได้  
> ถ้าเข้าใจว่า AI คิดยังไง เราก็ทะลุได้ทุก trap 🎯
>
> **VERIFIED:** Playbook patterns matched 100% in RTAF COC 2026 challenges  
> All 6 flags extracted using documented bypass techniques ✅
