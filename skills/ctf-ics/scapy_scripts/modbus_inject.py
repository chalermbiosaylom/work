#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS RAW PACKET CRAFTER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ยิง Custom Read (FC03)
python3 modbus_raw_crafter.py 192.168.1.100 --fc 3 --addr 0 --val 10

# 2. ยิง Custom Write (FC06)
python3 modbus_raw_crafter.py 192.168.1.100 --fc 6 --addr 5 --val 9999

# 3. ยิง Function Code เถื่อน (เช่น FC 0x43) แบบกำหนด Payload เองเป็น Hex
python3 modbus_raw_crafter.py 192.168.1.100 --raw-hex "000100000006014300000000"

# 4. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON)
python3 modbus_raw_crafter.py 192.168.1.100 --fc 3 --addr 0 --val 10 --json
===================================================================
"""
import argparse
import socket
import struct
import random
import json
import sys

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m'

def build_modbus_pdu(unit_id: int, fc: int, addr: int, val_or_count: int) -> bytes:
    """สร้าง Modbus Payload (MBAP + PDU) แบบ Raw Bytes"""
    transaction_id = random.randint(1, 65535)
    protocol_id = 0
    length = 6 # ขนาดมาตรฐานของ FC03/06 (Unit 1B + FC 1B + Addr 2B + Val 2B)
    
    # Pack data: > (Big-endian), H (2 bytes), B (1 byte)
    header = struct.pack(">HHHBBHH", 
                         transaction_id, 
                         protocol_id, 
                         length, 
                         unit_id, 
                         fc, 
                         addr, 
                         val_or_count)
    return header

def main():
    parser = argparse.ArgumentParser(description="Modbus Raw Packet Crafter (God-Mode)")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--port", type=int, default=502, help="Target Port")
    parser.add_argument("--unit", type=int, default=1, help="Unit ID")
    parser.add_argument("--fc", type=int, help="Function Code (e.g., 3 for Read, 6 for Write)")
    parser.add_argument("--addr", type=int, default=0, help="Register Address")
    parser.add_argument("--val", type=int, default=1, help="Value to write OR Count to read")
    parser.add_argument("--raw-hex", help="Inject absolute raw hex payload (bypasses all rules)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    
    args = parser.parse_args()

    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "status": "success",
        "sent_hex": "",
        "recv_hex": "",
        "recv_ascii": "",
        "error_msg": ""
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ MODBUS RAW PACKET CRAFTER (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")

    # เตรียม Payload
    if args.raw_hex:
        try:
            payload = bytes.fromhex(args.raw_hex)
        except ValueError:
            if args.json: print(json.dumps({"error": "Invalid raw-hex format"}))
            else: print(f"{R}[-] Invalid raw-hex format. Must be like '000100000006010300000001'{W}")
            sys.exit(1)
    elif args.fc is not None:
        payload = build_modbus_pdu(args.unit, args.fc, args.addr, args.val)
    else:
        if args.json: print(json.dumps({"error": "Must specify either --fc or --raw-hex"}))
        else: print(f"{R}[-] You must specify either --fc or --raw-hex{W}")
        sys.exit(1)

    ai_report["sent_hex"] = payload.hex()

    if not args.json:
        print(f"[*] Target       : {args.ip}:{args.port}")
        print(f"[*] Payload Hex  : {Y}{payload.hex()}{W}")
        print(f"[*] Connecting... (TCP 3-Way Handshake)")

    # 🚀 เปิด Socket (ให้ OS ทำ TCP Handshake ให้)
    try:
        with socket.create_connection((args.ip, args.port), timeout=args.timeout) as s:
            if not args.json: print(f"{G}[+] Connected! Injecting payload...{W}")
            
            # ยิง Payload
            s.sendall(payload)
            
            # รอรับผล (อ่านผลลัพธ์ว่า PLC ด่ากลับมา หรือคาย Flag ออกมา)
            response = s.recv(4096)
            
            ai_report["recv_hex"] = response.hex()
            ai_report["recv_ascii"] = response.decode('utf-8', 'ignore')

            if args.json:
                print(json.dumps(ai_report, indent=2))
            else:
                if response:
                    print(f"\n{G}[+] Response Received ({len(response)} bytes):{W}")
                    print(f"    Hex   : {C}{response.hex()}{W}")
                    
                    ascii_safe = "".join(chr(b) if 32 <= b <= 126 else "." for b in response)
                    print(f"    ASCII : {Y}{ascii_safe}{W}")
                else:
                    print(f"\n{R}[-] Connection closed by peer (No response).{W}")

    except Exception as e:
        ai_report["status"] = "error"
        ai_report["error_msg"] = str(e)
        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"\n{R}[-] Network Error: {e}{W}")

if __name__ == "__main__":
    main()