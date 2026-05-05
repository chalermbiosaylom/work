# 01 - ทุก Trap Pattern ที่ AI จะสร้าง

เอกสารนี้ list ทุก trap ที่ AI สามารถ generate ได้เมื่อถูกสั่งให้สร้างโจทย์ ICS CTF
จัดเรียงตามความถี่ที่ AI จะเลือกใช้ พร้อมวิธีทะลุแต่ละอัน

---

## TRAP-01: Byte Order / Endianness Swap

**ความถี่**: ★★★★★ (AI สร้างเกือบทุกครั้ง)

**AI สร้างยังไง**:
AI จะเก็บ flag ใน Modbus holding registers แต่สลับ byte order
แทนที่จะเก็บ `FL` เป็น `0x464C` (big-endian) จะเก็บเป็น `0x4C46` (swapped)

**รูปแบบที่เป็นไปได้ทั้งหมด**:
```
ABCD (Big Endian)     - ปกติ
CDAB (Byte Swap)      - AI ชอบใช้มากสุด
BADC (Word Swap)      - AI ใช้บางครั้ง
DCBA (Little Endian)  - AI ใช้น้อย
```

**วิธีทะลุ**:
```python
def crack_endianness(registers):
    """ลองทุก byte order จนเจอ flag"""
    flag_prefixes = ['coc2026{', 'FLAG{', 'CTF{', 'flag{']
    
    decoders = {
        'ABCD': lambda r: chr((r>>8)&0xFF) + chr(r&0xFF),
        'CDAB': lambda r: chr(r&0xFF) + chr((r>>8)&0xFF),
    }
    
    # เพิ่ม 32-bit decoders ถ้ามี register คู่
    if len(registers) >= 2:
        decoders['BADC'] = None  # ต้อง process ทีละคู่
        decoders['DCBA'] = None
    
    for name, decoder in decoders.items():
        if decoder is None:
            continue
        text = ''.join(decoder(r) for r in registers)
        text = text.replace('\x00', '')
        
        for prefix in flag_prefixes:
            if prefix in text:
                start = text.index(prefix)
                end = text.index('}', start) + 1
                return name, text[start:end]
    
    return None, None
```

---

## TRAP-02: Tarpit / Honeypot Delay

**ความถี่**: ★★★★★

**AI สร้างยังไง**:
AI จะใส่ `time.sleep()` ใน register range ต้นๆ (มักเป็น 0-10 หรือ 0-20)
เพื่อทำให้ brute-force scanner ช้ามาก

**รูปแบบที่เป็นไปได้**:
```python
# Pattern A: Fixed delay
if address in range(0, 10):
    time.sleep(2.5)  # AI ชอบใช้ 2-5 วินาที

# Pattern B: Progressive delay (ยิ่ง scan ยิ่งช้า)
delay = request_count * 0.5
time.sleep(delay)

# Pattern C: Random delay (ทำให้ timing analysis ยาก)
time.sleep(random.uniform(1.0, 5.0))

# Pattern D: Blackhole (ไม่ตอบเลย)
if is_scanning:
    return None  # drop packet
```

**วิธีทะลุ**:
```python
def detect_and_skip_tarpit(client, unit_id=1):
    """ตรวจจับ tarpit แล้วข้ามไป"""
    import time
    
    # วัด baseline response time
    safe_addr = 100  # register สูงๆ มักไม่มี tarpit
    start = time.time()
    client.read_holding_registers(safe_addr, 1, slave=unit_id)
    baseline = time.time() - start
    
    # ทดสอบ register ต้นๆ
    start = time.time()
    client.read_holding_registers(0, 1, slave=unit_id)
    test_time = time.time() - start
    
    if test_time > baseline * 3:  # ช้ากว่า 3 เท่า = tarpit
        print(f"[!] Tarpit detected: {test_time:.1f}s vs baseline {baseline:.3f}s")
        print(f"[*] Strategy: skip low registers, start from 20+")
        return True
    
    return False
```

**กฎสำคัญ**: ไม่ต้อง scan register 0-20 เลย เริ่มจาก 50+ ขึ้นไป
AI ไม่เคยวาง flag ที่ register ต่ำๆ (เพราะมันวาง tarpit ไว้)

---

## TRAP-03: Hidden Unit ID / Hidden Address

**ความถี่**: ★★★★☆

**AI สร้างยังไง**:
AI จะสร้าง Modbus server ที่มีหลาย Unit ID
Unit ID default (1) อาจมี tarpit หรือ decoy
Flag จริงอยู่ใน Unit ID อื่น

**Unit IDs ที่ AI ชอบใช้** (เรียงตามความถี่):
```
42   - AI ชอบมาก (Hitchhiker's Guide reference)
99   - AI ชอบ (ดูเหมือน "special")
100  - AI ใช้บ่อย
127  - AI ใช้บางครั้ง (max signed byte)
200  - AI ใช้บางครั้ง
247  - AI ใช้น้อย (Modbus max)
255  - AI ใช้น้อย (broadcast)
13   - AI ใช้น้อย ("unlucky")
```

**วิธีทะลุ**:
```python
def scan_unit_ids(client):
    """Scan เฉพาะ Unit IDs ที่ AI ชอบใช้"""
    # Priority list: IDs ที่ AI เลือกบ่อยสุดก่อน
    priority_ids = [1, 42, 99, 100, 127, 200, 247, 255, 13, 2, 10, 50]
    
    active = []
    for uid in priority_ids:
        # อ่าน register สูงๆ เพื่อหลีก tarpit
        result = client.read_holding_registers(100, 1, slave=uid)
        if not result.isError():
            active.append(uid)
    
    return active
```

---

## TRAP-04: Timing Window / Pulse Challenge

**ความถี่**: ★★★★☆

**AI สร้างยังไง**:
AI จะสร้าง challenge ที่ต้อง:
1. Write ค่าหนึ่ง
2. รอเวลาที่กำหนด (ไม่เร็วไป ไม่ช้าไป)
3. Write ค่าอีกค่า หรือ Read ผลลัพธ์

**Timing windows ที่ AI มักใช้**:
```
0.2 - 1.5 วินาที   (VERIFIED - Modbus Coil 50 pulse)
0.1 - 1.0 วินาที   (AI ใช้บ่อยสุด)
0.5 - 2.0 วินาที   (AI ใช้บางครั้ง)
1.0 - 3.0 วินาที   (AI ใช้น้อย)
0.05 - 0.5 วินาที  (AI ใช้น้อยมาก, "hard" mode)

VERIFIED SWEET SPOT: 0.5-0.8s for 0.2-1.5s window
```

**วิธีทะลุ**:
```python
def brute_timing(client, write_func, read_func):
    """ลอง timing ทุกช่วงจนเจอ"""
    # ลองจาก sweet spot ของแต่ละ window
    delays = [0.3, 0.5, 0.7, 1.0, 0.1, 1.5, 2.0, 0.05, 2.5, 3.0]
    
    for delay in delays:
        write_func(True)   # start
        time.sleep(delay)
        write_func(False)  # stop
        time.sleep(0.1)    # ให้ server process
        
        result = read_func()
        if result and has_flag(result):
            print(f"[+] Timing cracked: {delay}s")
            return result
    
    return None
```

**เคล็ดลับ**: AI มักตั้ง sweet spot ไว้ที่ ~40-60% ของ window
เช่น window 0.2-1.5s → sweet spot ≈ 0.7-0.8s

---

## TRAP-05: State Machine (Write-Then-Read)

**ความถี่**: ★★★★☆

**AI สร้างยังไง**:
AI จะสร้าง tag/register ที่ต้อง write ค่าเฉพาะก่อน
แล้วค่อย read flag จาก tag/register อื่น

**Pattern ที่ AI ใช้**:
```
Pattern A: Boolean toggle (VERIFIED - ENIP Admin_Mode)
  Write Admin_Mode = 1 → Read System_Key = flag
  CRITICAL: ENIP tags require exact type (BOOL), not integer

Pattern B: Magic value
  Write HR[200] = 0xDEAD → Read HR[201-210] = flag

Pattern C: Sequence
  Write HR[100] = 1 → Write HR[101] = 2 → Write HR[102] = 3 → Read flag

Pattern D: Password
  Write tag "Auth" = "admin" → Read tag "Secret" = flag

Pattern E: Exception Side-Effect (VERIFIED - Modbus HR 200)
  Write HR[200] = 0xFFFF (Unit 99) → Exception thrown BUT flag written to HR 200-210
  CRITICAL: Do NOT abort on exception - read the target address immediately after
```

**วิธีทะลุ**:
```python
def crack_state_machine(client, unit_id):
    """ลอง write patterns ที่ AI ชอบใช้"""
    
    # Pattern A: Boolean toggle ที่ coils
    for coil in [0, 1, 10, 50, 100]:
        client.write_coil(coil, True, slave=unit_id)
        time.sleep(0.3)
        # อ่านทุก register range หา flag
        for addr in [0, 1, 50, 100, 200]:
            result = client.read_holding_registers(addr, 20, slave=unit_id)
            if has_flag_in_registers(result):
                return extract_flag(result)
            result = client.read_input_registers(addr, 20, slave=unit_id)
            if has_flag_in_registers(result):
                return extract_flag(result)
    
    # Pattern B: Magic values
    magic_values = [0xFFFF, 0xDEAD, 0xBEEF, 0x1337, 0x0001, 0x00FF]
    for val in magic_values:
        for addr in [0, 100, 200, 255]:
            try:
                client.write_register(addr, val, slave=unit_id)
            except:
                pass
            # ตรวจ side-effect
            for check in [addr+1, addr+10, 0, 100]:
                result = client.read_holding_registers(check, 20, slave=unit_id)
                if has_flag_in_registers(result):
                    return extract_flag(result)
    
    return None
```

---

## TRAP-06: Exception / Error Hiding

**ความถี่**: ★★★☆☆

**AI สร้างยังไง**:
AI จะสร้าง handler ที่:
1. รับ write ค่าพิเศษ (เช่น 0xFFFF)
2. Return exception/error
3. แต่แอบเขียน flag ลง register อื่นเป็น side-effect

Automation tool มักจะ abort เมื่อเจอ exception ทำให้พลาด flag

**วิธีทะลุ**:
```python
def crack_exception_trap(client, unit_id):
    """Write ค่าพิเศษ แล้วอ่าน side-effect"""
    
    trigger_values = [0xFFFF, 0xDEAD, 0xBEEF, 0x1337, 0xCAFE]
    trigger_addrs = [0, 100, 200, 255]
    
    for addr in trigger_addrs:
        # อ่าน snapshot ก่อน
        before = {}
        for check_addr in range(max(0, addr-10), min(300, addr+30)):
            r = client.read_holding_registers(check_addr, 1, slave=unit_id)
            if not r.isError():
                before[check_addr] = r.registers[0]
        
        for val in trigger_values:
            # Write ค่าพิเศษ (คาดว่าจะ error)
            try:
                result = client.write_register(addr, val, slave=unit_id)
            except:
                pass  # ไม่สนใจ error
            
            # ตรวจ side-effect: register ไหนเปลี่ยน?
            time.sleep(0.1)
            for check_addr in range(max(0, addr-10), min(300, addr+30)):
                r = client.read_holding_registers(check_addr, 1, slave=unit_id)
                if not r.isError():
                    old_val = before.get(check_addr, 0)
                    if r.registers[0] != old_val:
                        print(f"[!] Side-effect: HR {check_addr} changed")
                        # อ่าน range กว้างๆ
                        flag_data = client.read_holding_registers(
                            check_addr, 20, slave=unit_id)
                        if not flag_data.isError():
                            return extract_flag(flag_data)
    
    return None
```

**กฎสำคัญ (VERIFIED)**: เมื่อเจอ Modbus exception อย่า abort
ให้อ่าน registers รอบๆ address ที่ write ไปทันที

**REAL EXAMPLE**:
```python
# Write 0xFFFF to HR 200 (Unit 99) → Exception thrown
client.write_register(200, 0xFFFF, slave=99)  # Will throw exception
# BUT flag is written as side-effect!
time.sleep(0.1)
result = client.read_holding_registers(200, 20, slave=99)  # Contains flag!
```

---

## TRAP-07: Array / Struct Parsing

**ความถี่**: ★★★☆☆

**AI สร้างยังไง**:
AI จะเก็บ flag ใน data type ที่ generic client อ่านไม่ถูก:
- INT[n] array ที่แต่ละ element เก็บ 2 ASCII chars
- SSTRING ที่มี length byte นำหน้า
- REAL (float) ที่ต้องแปลงกลับเป็น bytes
- Custom struct ที่ต้อง unpack เอง

**VERIFIED TRAP - ENIP Sec_Data (INT[12])**:
Flag stored as INT array where each 16-bit int = 2 ASCII chars
Example: `0x464C` = 'FL' (hi-lo) or 'LF' (lo-hi)

**วิธีทะลุ**:
```python
def parse_any_format(raw_values):
    """ลองทุก format จนเจอ flag"""
    results = []
    
    # Format 1: INT array → 2 ASCII chars per element (hi-lo) [VERIFIED]
    text = ''
    for v in raw_values:
        if isinstance(v, int):
            if v < 0: v += 65536
            hi = (v >> 8) & 0xFF
            lo = v & 0xFF
            # CRITICAL: Check printable range before chr()
            if 0x20 <= hi <= 0x7E: text += chr(hi)
            if 0x20 <= lo <= 0x7E: text += chr(lo)
    results.append(('INT-HI-LO', text.replace('\x00', '')))
    
    # Format 2: INT array → 2 ASCII chars per element (lo-hi swapped) [VERIFIED]
    text = ''
    for v in raw_values:
        if isinstance(v, int):
            if v < 0: v += 65536
            hi = (v >> 8) & 0xFF
            lo = v & 0xFF
            # CRITICAL: Swap order
            if 0x20 <= lo <= 0x7E: text += chr(lo)
            if 0x20 <= hi <= 0x7E: text += chr(hi)
    results.append(('INT-LO-HI', text.replace('\x00', '')))
    
    # Format 3: Raw bytes concatenation
    if isinstance(raw_values[0], int):
        raw_bytes = b''
        for v in raw_values:
            if v < 0: v += 65536
            raw_bytes += v.to_bytes(2, 'big')
        results.append(('RAW-BE', raw_bytes.decode('utf-8', errors='replace')))
        raw_bytes = b''
        for v in raw_values:
            if v < 0: v += 65536
            raw_bytes += v.to_bytes(2, 'little')
        results.append(('RAW-LE', raw_bytes.decode('utf-8', errors='replace')))
    
    # Format 4: SSTRING (skip first byte = length)
    if isinstance(raw_values, (bytes, bytearray)):
        length = raw_values[0]
        text = raw_values[1:1+length].decode('utf-8', errors='replace')
        results.append(('SSTRING', text))
    
    # หา flag ในทุก result
    for fmt, text in results:
        if has_flag(text):
            return fmt, text
    
    return None, results
```

---

## TRAP-08: XOR / Simple Encryption

**ความถี่**: ★★☆☆☆

**AI สร้างยังไง**:
AI จะ XOR flag กับ key ง่ายๆ แล้วเก็บใน register
Key มักจะ:
- อยู่ใน register อื่น
- เป็นค่าคงที่ง่ายๆ (0xFF, 0x42, 0x55, 0xAA)
- เป็น Unit ID
- เป็น register address

**วิธีทะลุ**:
```python
def crack_xor(encrypted_bytes):
    """Brute-force XOR key"""
    flag_prefixes = [b'coc2026{', b'FLAG{', b'CTF{', b'flag{']
    
    # Single-byte XOR
    for key in range(256):
        decrypted = bytes(b ^ key for b in encrypted_bytes)
        for prefix in flag_prefixes:
            if prefix in decrypted:
                start = decrypted.index(prefix)
                end = decrypted.index(b'}', start) + 1
                return key, decrypted[start:end].decode()
    
    # Known-plaintext attack: ถ้ารู้ว่า flag เริ่มด้วย coc2026{
    expected = b'coc2026{'
    if len(encrypted_bytes) >= len(expected):
        key_bytes = bytes(e ^ p for e, p in zip(encrypted_bytes, expected))
        # ตรวจว่า key ซ้ำกันไหม (single-byte key)
        if len(set(key_bytes)) == 1:
            key = key_bytes[0]
            decrypted = bytes(b ^ key for b in encrypted_bytes)
            return key, decrypted.decode('utf-8', errors='replace')
    
    return None, None
```

---

## TRAP-09: Rate Limiting / Connection Limiting

**ความถี่**: ★★☆☆☆

**AI สร้างยังไง**:
AI จะนับ requests ต่อวินาที ถ้าเกิน threshold จะ:
- Block IP
- Return garbage data
- เพิ่ม delay
- ตัด connection

**วิธีทะลุ**:
```python
def slow_scan(client, unit_id, delay=1.0):
    """Scan ช้าๆ เพื่อหลีก rate limit"""
    for addr in range(0, 300, 10):
        result = client.read_holding_registers(addr, 10, slave=unit_id)
        if not result.isError():
            non_zero = [(addr+i, v) for i, v in enumerate(result.registers) if v != 0]
            if non_zero:
                print(f"Data at: {non_zero}")
        time.sleep(delay)  # ช้าแต่ชัวร์
```

---

## TRAP-10: Multi-Protocol Correlation

**ความถี่**: ★☆☆☆☆ (AI สร้างน้อยมาก แต่ถ้าสร้างจะยากสุด)

**AI สร้างยังไง**:
Flag ถูกแบ่งเป็นส่วนๆ กระจายอยู่ในหลาย protocol:
- ครึ่งแรกอยู่ใน Modbus register
- ครึ่งหลังอยู่ใน EtherNet/IP tag
- หรือ key อยู่ใน protocol หนึ่ง, encrypted flag อยู่อีก protocol

**วิธีทะลุ**:
```python
def correlate_protocols(modbus_data, enip_data):
    """รวม data จากหลาย protocol"""
    
    # ลอง concatenate
    combined = modbus_data + enip_data
    if has_flag(combined):
        return combined
    
    # ลองสลับ
    combined = enip_data + modbus_data
    if has_flag(combined):
        return combined
    
    # ลอง XOR กัน
    if len(modbus_data) == len(enip_data):
        xored = bytes(a ^ b for a, b in zip(
            modbus_data.encode(), enip_data.encode()))
        if has_flag(xored.decode('utf-8', errors='replace')):
            return xored.decode()
    
    return None
```

---

## สรุป: Trap Priority Matrix

```
เมื่อเจอโจทย์ ICS CTF ที่ AI สร้าง ให้ทำตามลำดับนี้:

1. [RECON]     Scan ports, Unit IDs, tags
2. [SKIP]      ตรวจจับ tarpit → ข้ามไป
3. [READ]      อ่าน registers/tags ที่ non-zero
4. [DECODE]    ลองทุก endianness + encoding
5. [STATE]     ลอง write-then-read patterns
6. [TIMING]    ลอง pulse timing ถ้ามี coils
7. [EXCEPTION] ลอง write ค่าพิเศษ + ตรวจ side-effect
8. [XOR]       ลอง brute-force XOR ถ้ายังไม่เจอ
9. [CORRELATE] รวม data จากหลาย protocol
```
