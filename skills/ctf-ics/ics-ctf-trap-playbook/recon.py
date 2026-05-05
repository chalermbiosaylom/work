#!/usr/bin/env python3
"""
ICS CTF Reconnaissance Script
Use this FIRST before solving challenges.

Detects:
- Active services and ports
- Modbus Unit IDs
- Tarpit traps
- EtherNet/IP identity
- Available tags

Usage:
    python3 recon.py --target 172.20.0.0/24
    python3 recon.py --modbus 172.20.0.20 --enip 172.20.0.30
"""

import argparse
import socket
import struct
import sys
import time


def scan_port(host, port, timeout=2):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_network(subnet_base, ports=[502, 44818, 2222, 80, 443]):
    """Scan a /24 subnet for ICS services"""
    print(f"[*] Scanning {subnet_base}.0/24")
    
    found = []
    for host_id in range(1, 255):
        host = f"{subnet_base}.{host_id}"
        for port in ports:
            if scan_port(host, port, timeout=1):
                service = {
                    502: 'Modbus TCP',
                    44818: 'EtherNet/IP',
                    2222: 'SSH (alt)',
                    22: 'SSH',
                    80: 'HTTP',
                    443: 'HTTPS',
                }.get(port, 'Unknown')
                print(f"  [+] {host}:{port} - {service}")
                found.append((host, port, service))
    
    return found


def recon_modbus(host, port=502):
    """Detailed Modbus reconnaissance"""
    print(f"\n{'='*50}")
    print(f"MODBUS RECON: {host}:{port}")
    print(f"{'='*50}")
    
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        print("[!] pymodbus not installed: pip install pymodbus")
        return
    
    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        print("[!] Connection failed")
        return
    
    # 1. Unit ID Discovery
    print("\n[1] Unit ID Discovery")
    active_units = []
    test_ids = list(range(1, 11)) + [42, 99, 100, 127, 200, 247, 255]
    
    for uid in test_ids:
        try:
            result = client.read_holding_registers(100, 1, slave=uid)
            if not result.isError():
                active_units.append(uid)
                print(f"  [+] Unit ID {uid}: ACTIVE (HR 100 = {result.registers[0]})")
        except:
            pass
    
    if not active_units:
        print("  [!] No active Unit IDs found")
        client.close()
        return
    
    # 2. Tarpit Detection
    print("\n[2] Tarpit Detection")
    for uid in active_units:
        for addr in [1, 5, 10, 50, 100, 200]:
            start = time.time()
            try:
                client.read_holding_registers(addr, 1, slave=uid)
            except:
                pass
            elapsed = time.time() - start
            
            if elapsed > 1.0:
                print(f"  [!] TARPIT: Unit {uid}, HR {addr} ({elapsed:.1f}s)")
            elif elapsed > 0.3:
                print(f"  [?] SLOW: Unit {uid}, HR {addr} ({elapsed:.2f}s)")
    
    # 3. Register Scan (skip tarpit ranges)
    print("\n[3] Non-Zero Register Scan")
    for uid in active_units:
        print(f"  Unit ID {uid}:")
        
        # Holding Registers
        for start_addr in range(20, 300, 20):
            try:
                result = client.read_holding_registers(
                    start_addr, 20, slave=uid)
                if not result.isError():
                    for i, val in enumerate(result.registers):
                        if val != 0:
                            addr = start_addr + i
                            print(f"    HR {addr}: {val} (0x{val:04X})")
            except:
                pass
        
        # Input Registers
        for start_addr in range(0, 100, 20):
            try:
                result = client.read_input_registers(
                    start_addr, 20, slave=uid)
                if not result.isError():
                    for i, val in enumerate(result.registers):
                        if val != 0:
                            addr = start_addr + i
                            print(f"    IR {addr}: {val} (0x{val:04X})")
            except:
                pass
        
        # Coils
        for start_addr in range(0, 100, 20):
            try:
                result = client.read_coils(start_addr, 20, slave=uid)
                if not result.isError():
                    for i, val in enumerate(result.bits[:20]):
                        if val:
                            addr = start_addr + i
                            print(f"    Coil {addr}: ON")
            except:
                pass
    
    # 4. Function Code Support
    print("\n[4] Supported Function Codes")
    uid = active_units[0]
    tests = [
        ('FC01 Read Coils', lambda: client.read_coils(0, 1, slave=uid)),
        ('FC02 Read DI', lambda: client.read_discrete_inputs(0, 1, slave=uid)),
        ('FC03 Read HR', lambda: client.read_holding_registers(100, 1, slave=uid)),
        ('FC04 Read IR', lambda: client.read_input_registers(0, 1, slave=uid)),
        ('FC05 Write Coil', lambda: client.write_coil(0, False, slave=uid)),
        ('FC06 Write HR', lambda: client.write_register(0, 0, slave=uid)),
    ]
    
    for name, func in tests:
        try:
            result = func()
            status = 'Supported' if not result.isError() else 'Error'
            print(f"  {name}: {status}")
        except Exception as e:
            print(f"  {name}: Exception")
    
    client.close()


def recon_enip(host, port=44818):
    """Detailed EtherNet/IP reconnaissance"""
    print(f"\n{'='*50}")
    print(f"ETHERNET/IP RECON: {host}:{port}")
    print(f"{'='*50}")
    
    # 1. List Identity
    print("\n[1] List Identity")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        packet = struct.pack('<HHII8sI',
            0x0063, 0, 0, 0, b'\x00' * 8, 0)
        sock.send(packet)
        
        response = sock.recv(4096)
        sock.close()
        
        if len(response) > 24:
            print(f"  Response length: {len(response)} bytes")
            
            # Try to extract product name
            text = response.decode('utf-8', errors='replace')
            # Search for printable strings
            current = ''
            strings_found = []
            for ch in text:
                if ch.isprintable() and ch != '\x00':
                    current += ch
                else:
                    if len(current) > 3:
                        strings_found.append(current)
                    current = ''
            if current and len(current) > 3:
                strings_found.append(current)
            
            print(f"  Strings found:")
            for s in strings_found:
                flag_marker = " <-- POSSIBLE FLAG" if '{' in s and '}' in s else ""
                print(f"    '{s}'{flag_marker}")
        else:
            print(f"  [!] Short response: {len(response)} bytes")
    
    except Exception as e:
        print(f"  [!] Error: {e}")
    
    # 2. Tag Discovery
    print("\n[2] Tag Discovery")
    try:
        from cpppo.server.enip import client
        
        common_tags = [
            'Sec_Data', 'SecData', 'Secret', 'Flag', 'Data',
            'Admin_Mode', 'AdminMode', 'Admin', 'Mode',
            'System_Key', 'SystemKey', 'Key', 'Password',
            'Config', 'Status', 'Control', 'Output', 'Input',
            'Token', 'Auth', 'Level', 'Sensor', 'Actuator',
        ]
        
        with client.connector(host=host, port=port) as conn:
            for tag in common_tags:
                try:
                    operations = conn.pipeline(
                        operations=client.parse_operations([tag]),
                        timeout=2.0
                    )
                    for idx, dsc, op, rpy, sts, val in operations:
                        if sts is None or sts == 0:
                            print(f"  [+] {tag}: EXISTS (value={val})")
                        else:
                            pass  # Tag doesn't exist
                except:
                    pass
    
    except ImportError:
        print("  [!] cpppo not installed: pip install cpppo")
    except Exception as e:
        print(f"  [!] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='ICS CTF Reconnaissance')
    parser.add_argument('--target', help='Target subnet (e.g., 172.20.0)')
    parser.add_argument('--modbus', help='Modbus server IP')
    parser.add_argument('--enip', help='EtherNet/IP server IP')
    args = parser.parse_args()
    
    print("=" * 60)
    print("ICS CTF RECONNAISSANCE")
    print("=" * 60)
    
    if args.target:
        scan_network(args.target)
    
    if args.modbus:
        recon_modbus(args.modbus)
    
    if args.enip:
        recon_enip(args.enip)
    
    if not any([args.target, args.modbus, args.enip]):
        # Default: scan the lab network
        print("\n[*] No target specified, using defaults")
        recon_modbus('172.20.0.20')
        recon_enip('172.20.0.30')


if __name__ == '__main__':
    main()
