# 🏭 OPC-UA SCADA: Evil Plant & Data Monitoring Cheat Sheet
**Target Protocol:** OPC-UA (Port 4841)
**Connection String:** `opc.tcp://<target_ip>:4841`

---

## 🔑 [EXAM FOCUS] Keywords สำหรับสอน Trae IDE
หากโจทย์มีคีย์เวิร์ดเหล่านี้ ให้ AI เปลี่ยนโหมดมาใช้อาวุธสาย OPC-UA ทันที:
* **Protocol:** `OPC-UA`, `opc.tcp`
* **Variables:** `Vxx` (Valves/วาล์ว), `Exx` (Meters/มาตรวัดน้ำในถัง)
* **Logic/Action:** `Live data monitoring`, `Anonymous connection`, `Rate calculation`, `Elements mixed`
* **Tool:** `UA Expert` (OPC-UA Client ยอดฮิต)

---

## 🔍 1. Initial Reconnaissance & Connection (เจาะเข้าเซิร์ฟเวอร์)
**[EXAM FOCUS]** プロโตคอล OPC-UA ปกติจะรองรับการเข้ารหัส (Encrypt/Sign) และการยืนยันตัวตน (Authentication) แต่ในโจทย์ CTF ส่วนใหญ่ (รวมถึงข้อนี้) <span style="color:green; font-weight:bold;">เซิร์ฟเวอร์มักจะเปิดให้เชื่อมต่อแบบ Anonymous และอนุญาตให้เข้าไปอ่านข้อมูลได้เลย</span>

**วิธีเชื่อมต่อด้วย GUI Tool (แนะนำ):**
1. โหลดและเปิดโปรแกรม **UA Expert**
2. สร้าง Connection ใหม่ (Add Server) โดยใช้ URL: `opc.tcp://localhost:4841` (เปลี่ยน IP ตามเป้าหมาย)

---

## 🚩 2. Data Monitoring & Extraction (การสังเกตและดึงข้อมูล)
โจทย์แนวผสมสารเคมี (Toxic Liquid) มักจะต้องหา "อัตราส่วน (Rates)" และ "ลำดับ (Sequencing)"

**[EXAM FOCUS] จุดหลอกและจุดโฟกัสใน OPC-UA Node:**
* <span style="color:red; font-weight:bold;">[IGNORE]</span> ตัวแปร `Vxx` (Valves): ไม่ต้องไปสนใจการเปิด/ปิดวาล์ว เพราะมันหลอกให้เราเสียเวลา
* <span style="color:green; font-weight:bold;">[FOCUS]</span> ตัวแปร `Exx` (Meters): ให้ดึงตัวแปรนี้มาใส่ในหน้าต่าง "Data Access View" ของ UA Expert เพื่อดูค่าแบบ Live (เรียลไทม์) เพราะมันคือปริมาณน้ำที่เหลืออยู่ในแต่ละถัง

---

## ⚙️ 3. Logic Analysis & Flag Calculation (การคำนวณ Flag)
ระบบจะทำการผสมสารทีละ 2 ถัง (Two by two) และแต่ละถังจะถูกใช้แค่ครั้งเดียว

**ขั้นตอนการสกัด Flag:**
1. **จับตาดูการเปลี่ยนแปลง (Diff Calculation):** สังเกตว่าถังไหนค่าลดลงพร้อมกัน (เช่น ถัง 1 และ 3) ทันทีที่ค่า `Exx` เปลี่ยน ให้เอาค่าเริ่มต้นลบด้วยค่าล่าสุด จะได้ "ปริมาณสารที่ถูกใช้ (Rate)"
2. **จัดเรียงข้อมูล (Sorting):** <span style="color:red; font-weight:bold;">ข้อควรระวังสุดๆ!</span> ต้องเรียงหมายเลขถัง (Elements) จากน้อยไปมากเสมอในแต่ละคู่ (Ascending order) และวางค่า Rate ตามลำดับถังนั้น
   * *ตัวอย่าง:* ใช้สารถัง 12 (95 units) และถัง 3 (141 units) -> ต้องเรียงเป็น ถัง 3 นำหน้า ถัง 12
3. **แปลงเลขและประกอบร่าง (Hex Conversion):** * นำข้อมูล (เลขถัง และ ปริมาณที่ใช้) มาแปลงเป็นเลขฐานสิบหก (Hexadecimal)
   * <span style="color:green; font-weight:bold;">[TRICK]</span> เอาข้อมูลทั้งหมดโยนลง Spreadsheet (Excel/Google Sheets) แล้วใช้สูตร `CONCAT`, `DEC2HEX`, และบังคับตัวพิมพ์เล็ก (`MINUSCULE` / `LOWER`) จะช่วยให้คำนวณ Flag ได้ไวและไม่พลาด
   * *รูปแบบ Flag:* `FCSC{<เลขถัง_A><เลขถัง_B><ปริมาณ_A><ปริมาณ_B>...}` (ค่าทั้งหมดเป็น Hex)

---

## 🧩 Advanced OPC-UA Monitoring Code (from ctf-ics SKILL.md)

### Cycle Boundary Detection + Live Monitoring

```python
# ✅ CORRECT algorithm — wait for cycle boundary first
async def monitor_with_cycle_boundary(client, cycle_counter_node, resource_nodes, valve_nodes):
    steps = []
    cycle_started = False
    step_e_before = None
    last_valves = set()
    last_count = await client.get_node(cycle_counter_node).get_value()

    while len(steps) < NUM_STEPS:
        await asyncio.sleep(0.3)
        count = await client.get_node(cycle_counter_node).get_value()
        cur_open = {i for i, nid in valve_nodes.items()
                   if await client.get_node(nid).get_value()}

        # Cycle boundary: count just incremented
        if count > last_count:
            cycle_started = True   # ← mark: next OPEN is step 1
            steps = []             # ← discard any partial steps from previous tail
            last_count = count

        newly_opened = cur_open - last_valves
        newly_closed = last_valves - cur_open

        if newly_opened and cycle_started:
            # Snapshot E-values BEFORE mixing
            step_e_before = {i: await client.get_node(nid).get_value()
                             for i, nid in resource_nodes.items()}

        if newly_closed and step_e_before and cycle_started:
            pair = sorted(last_valves)
            if len(pair) == 2:
                e_after = {i: await client.get_node(nid).get_value()
                           for i, nid in resource_nodes.items()}
                ea, eb = pair
                qa = step_e_before[ea] - e_after[ea]
                qb = step_e_before[eb] - e_after[eb]
                steps.append((ea, eb, qa, qb))
            step_e_before = None

        last_valves = cur_open
    return steps
```

### Cross-Check Quantities with Cumulative Formula

```python
# Method B (fast sanity check — use when server is NOT mid-step)
# qty = (initial_stock - current_stock) / production_count
# initial_stock is usually a round number: 100_000_000, 1_000_000, etc.
# Result MUST be integer — if not, that element was mid-step when read → use Method A only
for i, e_val in E_snapshot.items():
    diff = 100_000_000 - e_val
    qty = diff / production_count
    if diff % production_count == 0:
        print(f"E{i}: qty={int(qty)} (0x{int(qty):02x}) ✓")
    else:
        print(f"E{i}: mid-step when read — use live delta only")
```

### Flag Assembly Anti-Traps

```python
def assemble_flag(steps):
    # steps = list of (ea, eb, qa, qb) in PRODUCTION ORDER
    # (from cycle boundary monitoring, NOT capture order)
    flag_body = ""
    for ea, eb, qa, qb in steps:
        # Sort elements ascending within each pair
        if ea > eb:
            ea, eb = eb, ea
            qa, qb = qb, qa
        flag_body += f"{ea:02x}{eb:02x}{qa:02x}{qb:02x}"
    # Validate: 8 steps × 8 chars = 64 hex chars
    assert len(flag_body) == len(steps) * 8
    # Validate: each element used exactly once
    all_elems = [ea for ea, eb, qa, qb in steps] + [eb for ea, eb, qa, qb in steps]
    assert len(set(all_elems)) == len(all_elems), "Duplicate element — check cycle boundary!"
    return f"FCSC{{{flag_body}}}"   # or FLAG{} / CTF{} per challenge wrapper
```