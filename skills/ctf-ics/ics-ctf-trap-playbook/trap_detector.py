#!/usr/bin/env python3
"""
🛡️ ICS CTF Trap Detector
Detects AI-generated traps before exploitation

Usage:
    python3 trap_detector.py --ip <target> --port 502 --full-scan --json

Integrates with: ctf-ics skill for Windsurf IDE
"""

import argparse
import json
import socket
import struct
import time
import re
import sys
from typing import Dict, List, Tuple, Optional, Any


class TrapDetector:
    """
    Comprehensive trap detection for ICS CTF challenges
    Detects all AI-generated trap patterns
    """
    
    # Tarpit detection
    TARPIT_THRESHOLD = 1.0  # seconds
    AI_TARPIT_ZONES = [(0, 20), (0, 10), (0, 50)]
    
    # AI favorite Unit IDs (ordered by verified frequency)
    # VERIFIED: 42 (Modbus pulse timing), 99 (exception trap)
    AI_FAVORITE_UNITS = [1, 42, 99, 100, 127, 200, 247, 255, 13, 2, 10, 50]
    
    # Decoy patterns
    DECOY_PATTERNS = [
        b'FAKE', b'DECOY', b'NOT_FLAG', b'NOT_THE_FLAG',
        b'WRONG', b'TRY_AGAIN', b'NOPE', b'INVALID',
        b'LOCKED', b'ACCESS_DENIED', b'UNAUTHORIZED',
    ]
    
    # Flag patterns
    FLAG_PATTERNS = [
        rb'coc2026\{[^}]+\}',
        rb'FLAG\{[^}]+\}',
        rb'CTF\{[^}]+\}',
        rb'flag\{[^}]+\}',
        rb'rtaf\{[^}]+\}',
    ]
    
    def __init__(self, host: str, port: int = 502, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results = {
            'traps_detected': [],
            'safe_parameters': {},
            'recommendations': [],
            'active_units': [],
            'scan_summary': {}
        }
    
    def full_scan(self) -> Dict[str, Any]:
        """Run complete trap detection scan"""
        
        print(f"[*] Starting trap detection on {self.host}:{self.port}")
        
        # Phase 1: Connectivity check
        if not self._check_connectivity():
            self.results['error'] = 'Target not reachable'
            return self.results
        
        # Phase 2: Tarpit detection
        self._detect_tarpit()
        
        # Phase 3: Unit ID discovery
        self._discover_units()
        
        # Phase 4: Rate limit detection
        self._detect_rate_limit()
        
        # Phase 5: Exception and Honeypot detection
        self._detect_exception_trap()
        self._detect_honeypot()
        
        # Phase 6: Generate recommendations
        self._generate_recommendations()
        
        return self.results
    
    def _check_connectivity(self) -> bool:
        """Check if target is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result == 0:
                print(f"[+] Target {self.host}:{self.port} is reachable")
                return True
            else:
                print(f"[-] Target {self.host}:{self.port} is not reachable")
                return False
        except Exception as e:
            print(f"[-] Connectivity check failed: {e}")
            return False
    
    def _detect_tarpit(self) -> None:
        """Detect tarpit traps by measuring response times"""
        print("[*] Phase 2: Tarpit detection...")
        
        tarpit_ranges = []
        safe_start = 0
        test_addresses = [0, 5, 10, 15, 20, 30, 50, 100, 150, 200]
        baseline_times = []
        
        for addr in test_addresses:
            elapsed = self._measure_response_time(1, addr)
            
            if elapsed is None:
                continue
            
            if elapsed > self.TARPIT_THRESHOLD:
                tarpit_ranges.append((addr, addr + 20))
                print(f"  [!] TARPIT at address {addr}: {elapsed:.2f}s")
            else:
                baseline_times.append(elapsed)
        
        if tarpit_ranges:
            max_end = max(end for _, end in tarpit_ranges)
            safe_start = max_end + 10
            
            self.results['traps_detected'].append({
                'type': 'tarpit',
                'ranges': tarpit_ranges,
                'severity': 'high'
            })
        
        self.results['safe_parameters']['start_address'] = safe_start
        self.results['safe_parameters']['avg_response_time'] = (
            sum(baseline_times) / len(baseline_times) if baseline_times else 0
        )
        
        print(f"  [*] Safe start address: {safe_start}")
    
    def _discover_units(self) -> None:
        """Discover active Unit IDs"""
        print("[*] Phase 3: Unit ID discovery...")
        
        active_units = []
        safe_addr = self.results['safe_parameters'].get('start_address', 100)
        
        for uid in self.AI_FAVORITE_UNITS:
            response = self._read_register(uid, safe_addr, 1)
            if response is not None:
                active_units.append(uid)
                print(f"  [+] Unit ID {uid} is active")
        
        if not active_units:
            print("  [!] No active units found with AI favorites, trying extended scan")
            for uid in range(1, 248):
                if uid in self.AI_FAVORITE_UNITS:
                    continue
                response = self._read_register(uid, safe_addr, 1)
                if response is not None:
                    active_units.append(uid)
                    print(f"  [+] Unit ID {uid} is active")
                    if len(active_units) >= 5:
                        break
        
        self.results['active_units'] = active_units
        
        # Check for hidden unit trap
        if 1 not in active_units and active_units:
            self.results['traps_detected'].append({
                'type': 'hidden_unit_id',
                'description': 'Default Unit ID 1 is not active',
                'active_units': active_units,
                'severity': 'medium'
            })
    
    def _detect_rate_limit(self) -> None:
        """Detect rate limiting"""
        print("[*] Phase 4: Rate limit detection...")
        
        if not self.results['active_units']:
            return
        
        uid = self.results['active_units'][0]
        safe_addr = self.results['safe_parameters'].get('start_address', 100)
        
        # Send rapid requests
        success_count = 0
        fail_count = 0
        
        for i in range(20):
            response = self._read_register(uid, safe_addr, 1)
            if response is not None:
                success_count += 1
            else:
                fail_count += 1
        
        if fail_count > 5:
            self.results['traps_detected'].append({
                'type': 'rate_limit',
                'success_rate': success_count / 20,
                'severity': 'medium'
            })
            self.results['safe_parameters']['request_delay'] = 0.2
            print(f"  [!] Rate limiting detected: {fail_count}/20 requests failed")
        else:
            print(f"  [+] No rate limiting detected")
    
    def _detect_exception_trap(self) -> None:
        """Detect exception-based traps (VERIFIED: Unit 99, HR 200)"""
        print("[*] Phase 5a: Exception trap detection...")
        
        if not self.results['active_units']:
            return
        
        # Test known exception trap patterns
        exception_tests = [
            (99, 200, 0xFFFF),  # VERIFIED pattern
            (1, 200, 0xFFFF),
            (1, 255, 0xFFFF),
        ]
        
        for uid, addr, val in exception_tests:
            if uid not in self.results['active_units']:
                continue
            
            try:
                # Snapshot before
                before = self._read_register(uid, addr, 20)
                
                # Trigger exception
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))
                request = struct.pack('>HHHBBHH', 1, 0, 6, uid, 0x06, addr, val)
                sock.sendall(request)
                response = sock.recv(256)
                sock.close()
                
                # Check if exception occurred
                if len(response) >= 8 and response[7] & 0x80:
                    # Exception occurred - check for side-effect
                    time.sleep(0.1)
                    after = self._read_register(uid, addr, 20)
                    
                    if before and after and before != after:
                        self.results['traps_detected'].append({
                            'type': 'exception_side_effect',
                            'unit_id': uid,
                            'address': addr,
                            'trigger_value': f'0x{val:04X}',
                            'severity': 'high',
                            'description': 'Exception thrown but registers changed (flag side-effect)'
                        })
                        print(f"  [!] Exception trap at Unit {uid}, HR {addr}")
            except:
                pass
    
    def _detect_honeypot(self) -> None:
        """ตรวจจับ honeypot/decoy data"""
        print("[*] Phase 5b: Honeypot detection...")
        
        if not self.results['active_units']:
            return
        
        decoys_found = []
        
        for uid in self.results['active_units'][:3]:  # Check first 3 units
            safe_addr = self.results['safe_parameters'].get('start_address', 50)
            
            for addr in range(safe_addr, safe_addr + 200, 20):
                registers = self._read_register(uid, addr, 20)
                if registers is None:
                    continue
                
                # Convert to bytes
                data = b''.join(r.to_bytes(2, 'big') for r in registers)
                
                # Check for decoy patterns
                for pattern in self.DECOY_PATTERNS:
                    if pattern in data.upper():
                        decoys_found.append({
                            'unit_id': uid,
                            'address': addr,
                            'pattern': pattern.decode('utf-8', errors='replace')
                        })
                        print(f"  [!] Decoy found at Unit {uid}, Addr {addr}: {pattern}")
        
        if decoys_found:
            self.results['traps_detected'].append({
                'type': 'honeypot',
                'decoys': decoys_found,
                'severity': 'low'
            })
    
    def _generate_recommendations(self) -> None:
        """Generate bypass recommendations based on detected traps"""
        print("[*] Phase 6: Generating recommendations...")
        
        recommendations = []
        
        for trap in self.results['traps_detected']:
            trap_type = trap['type']
            
            if trap_type == 'tarpit':
                safe_start = self.results['safe_parameters'].get('start_address', 50)
                recommendations.append({
                    'trap': 'tarpit',
                    'action': f'Skip addresses 0-{safe_start-10}, start from {safe_start}',
                    'command_flag': f'--start-addr {safe_start}'
                })
            
            elif trap_type == 'hidden_unit_id':
                active = self.results['active_units']
                recommendations.append({
                    'trap': 'hidden_unit_id',
                    'action': f'Use Unit ID {active[0]} instead of default 1',
                    'command_flag': f'--unit {active[0]}'
                })
            
            elif trap_type == 'rate_limit':
                recommendations.append({
                    'trap': 'rate_limit',
                    'action': 'Add 200ms delay between requests',
                    'command_flag': '--delay 0.2'
                })
            
            elif trap_type == 'honeypot':
                recommendations.append({
                    'trap': 'honeypot',
                    'action': 'Filter results with --filter-decoys flag',
                    'command_flag': '--filter-decoys'
                })
        
        # Always recommend trying all encodings
        recommendations.append({
            'trap': 'byte_swap',
            'action': 'Try all endianness variants (ABCD, CDAB, BADC, DCBA)',
            'command_flag': '--try-all-endianness'
        })
        
        self.results['recommendations'] = recommendations
        
        # Generate summary command
        flags = ' '.join(r['command_flag'] for r in recommendations)
        self.results['suggested_command'] = (
            f"python3 modbus_read_find_flags.py --ip {self.host} --port {self.port} {flags} --json"
        )
    
    def _measure_response_time(self, unit_id: int, address: int) -> Optional[float]:
        """Measure response time for single read"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            request = struct.pack('>HHHBBHH', 1, 0, 6, unit_id, 0x03, address, 1)
            
            start = time.time()
            sock.sendall(request)
            response = sock.recv(256)
            elapsed = time.time() - start
            
            sock.close()
            return elapsed
        except:
            return None
    
    def _read_register(self, unit_id: int, address: int, count: int) -> Optional[List[int]]:
        """Read holding registers"""
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
            
            return registers
        except:
            return None
    
    def _recv_all(self, sock: socket.socket, expected: int) -> bytes:
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


def main():
    parser = argparse.ArgumentParser(
        description='🛡️ ICS CTF Trap Detector - Detect AI-generated traps'
    )
    parser.add_argument('--ip', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=502, help='Target port (default: 502)')
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout in seconds')
    parser.add_argument('--full-scan', action='store_true', help='Run full trap detection')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    detector = TrapDetector(args.ip, args.port, args.timeout)
    
    if args.full_scan:
        results = detector.full_scan()
    else:
        results = detector.full_scan()  # Default to full scan
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "="*60)
        print("TRAP DETECTION RESULTS")
        print("="*60)
        
        print(f"\nTraps Detected: {len(results['traps_detected'])}")
        for trap in results['traps_detected']:
            print(f"  - {trap['type'].upper()}: {trap.get('severity', 'unknown')} severity")
        
        print(f"\nActive Unit IDs: {results['active_units']}")
        
        print(f"\nSafe Parameters:")
        for key, value in results['safe_parameters'].items():
            print(f"  - {key}: {value}")
        
        print(f"\nRecommendations:")
        for rec in results['recommendations']:
            print(f"  - [{rec['trap']}] {rec['action']}")
        
        if 'suggested_command' in results:
            print(f"\nSuggested Command:")
            print(f"  {results['suggested_command']}")
        
        print()


if __name__ == '__main__':
    main()
