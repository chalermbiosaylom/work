#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS HOLDING REGISTERS INSPECTOR (AI & TRAE IDE READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. รันแบบมนุษย์อ่าน (มีสีสัน, โชว์ Process)
python3 modbus_read_holding_registers.py 127.0.0.1 --addr 0 --count 100

# 2. รันแบบให้ Trae IDE / AI อ่าน (พ่นออกมาเป็น JSON เพียวๆ ไม่มีสี)
python3 modbus_read_holding_registers.py 127.0.0.1 --addr 0 --count 100 --json
===================================================================
"""
import argparse
import struct
import sys
import re
import json
from pymodbus.client import ModbusTcpClient

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m'

def _call_read(client: ModbusTcpClient, unit_id: int, address: int, count: int):
    try:
        return client.read_holding_registers(address=address, count=count, slave=unit_id)
    except TypeError:
        return client.read_holding_registers(address=address, count=count, unit=unit_id)

def _regs_to_ascii(registers, byte_swap: bool) -> str:
    out = bytearray()
    for r in registers:
        b = int(r).to_bytes(2, "big", signed=False)
        if byte_swap:
            b = b[::-1]
        out.extend(b)
    s = out.decode("utf-8", errors="ignore")
    return "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in s)

def extract_interesting_strings(ascii_str):
    matches = re.findall(r'[A-Za-z0-9_{}-]{4,}', ascii_str)
    return [m for m in matches if m]

def main():
    parser = argparse.ArgumentParser(description="Modbus Inspector (AI Ready)")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--port", type=int, default=502, help="Target Port")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    parser.add_argument("--unit", type=int, default=1, help="Unit ID (Slave ID)")
    parser.add_argument("--addr", type=int, required=True, help="Starting Address")
    parser.add_argument("--count", type=int, default=1, help="Number of registers")
    parser.add_argument("--address-base", type=int, choices=[0, 1], default=0)
    parser.add_argument("--json", action="store_true", help="Output in pure JSON format for Trae IDE / AI")
    
    args = parser.parse_args()
    
    addr = int(args.addr)
    if args.address_base == 1 and addr > 0:
        addr -= 1

    # --- โครงสร้าง Data สำหรับส่งให้ AI ---
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "unit_id": args.unit,
        "scan_range": f"{addr} to {addr + args.count - 1}",
        "status": "success",
        "error_msg": "",
        "found_strings": [],
        "analyzed_floats": [],
        "raw_registers": []
    }

    client = ModbusTcpClient(args.ip, port=args.port, timeout=args.timeout)
    if not client.connect():
        if args.json:
            ai_report["status"] = "failed"
            ai_report["error_msg"] = "Connection Refused"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Failed to connect to {args.ip}:{args.port}{W}")
        sys.exit(1)
        
    if not args.json:
        print(f"{C}[*] Commencing Data Extraction for Trae...{W}")
    
    max_chunk = 125
    read_count = args.count
    current_addr = addr
    all_registers = []
    global_found_strings = set()
    
    while read_count > 0:
        chunk = min(read_count, max_chunk)
        if not args.json:
            print(f"{Y}[~] Reading Addr {current_addr:04d} to {current_addr + chunk - 1:04d} ... {W}", end="")
            sys.stdout.flush()
            
        rr = _call_read(client, args.unit, current_addr, chunk)
        
        if rr.isError():
            if not args.json: print(f"{R}ERROR!{W}")
            ai_report["status"] = "partial_success_or_error"
            ai_report["error_msg"] = str(rr)
            break
            
        if not args.json: print(f"{G}SUCCESS{W}")
        
        # สกัด String
        s_be = _regs_to_ascii(rr.registers, byte_swap=False)
        s_le = _regs_to_ascii(rr.registers, byte_swap=True)
        found_strings = set(extract_interesting_strings(s_be) + extract_interesting_strings(s_le))
        global_found_strings.update(found_strings)

        if not args.json and found_strings:
            print(f"    {G}╰─> 🔥 FOUND STRINGS:{W} {found_strings}")

        all_registers.extend(rr.registers)
        current_addr += chunk
        read_count -= chunk

    # อัปเดตข้อมูลลง JSON Report
    ai_report["raw_registers"] = all_registers
    ai_report["found_strings"] = list(global_found_strings)

    # วิเคราะห์ Float32 เพื่อป้อนให้ AI
    if len(all_registers) >= 2:
        for i in range(0, len(all_registers) - 1, 2):
            r1, r2 = all_registers[i], all_registers[i+1]
            pack_be = struct.pack('>HH', r1, r2)
            f_abcd = struct.unpack('>f', pack_be)[0]
            
            # เก็บค่า Float ที่ดูสมเหตุสมผลให้ AI
            if -1e6 < f_abcd < 1e6 and f_abcd != 0.0:
                ai_report["analyzed_floats"].append({
                    "address_pair": f"{addr+i}:{addr+i+1}",
                    "value_abcd": round(f_abcd, 4)
                })

    client.close()

    # ---------------------------------------------------------
    # การแสดงผล: แยกมนุษย์ กับ AI อย่างชัดเจน
    # ---------------------------------------------------------
    if args.json:
        # พ่น JSON เพียวๆ ให้ Trae IDE เอาไปเข้า Context
        print(json.dumps(ai_report, indent=2))
    else:
        # พ่นแบบ UI สีสันให้กัปตันดู
        print(f"\n{C}=================================================={W}")
        print(f"{G}[+] Extraction Complete! Retrieved: {len(all_registers)} regs.{W}")
        if global_found_strings:
            print(f"{Y}[🎯] ALL POTENTIAL STRINGS/FLAGS:{W}")
            for s in global_found_strings:
                print(f"     => {G}{s}{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()