#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ENIP/CIP LIST-IDENTITY RECON & FLAG HUNTER (GOD-MODE) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ยิงคำสั่ง ListIdentity เพื่อดึงชื่อรุ่น PLC และค้นหา Flag
python3 enip_list_identity.py --ip 10.10.10.5

# 2. ดูข้อมูลดิบแบบ Hex Dump (เผื่อคนออกโจทย์ซ่อนลึกเกิน CIP Header)
python3 enip_list_identity.py --ip 10.10.10.5 --hex

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 enip_list_identity.py --ip 10.10.10.5 --json
===================================================================
"""
import argparse
import re
import socket
import struct
import json
import binascii
import sys
from typing import List, Tuple, Dict, Any

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
M = '\033[95m'  # Magenta
W = '\033[0m'   # Reset

CIP_VENDORS = {1: "Rockwell Automation/Allen-Bradley", 2: "Namco", 5: "Schneider Electric", 43: "Omron"}
CIP_DEVICE_TYPES = {12: "Communications Adapter", 14: "PLC (Programmable Logic Controller)", 43: "Generic Device"}

def _compile_flag_regex(pattern: str) -> "re.Pattern[bytes]":
    return re.compile(pattern.encode("utf-8"), re.IGNORECASE)

def _find_flags_bytes(flag_re: "re.Pattern[bytes]", blob: bytes) -> List[str]:
    return [m.group(0).decode("utf-8", errors="ignore") for m in flag_re.finditer(blob)]

def _extract_flag_candidates(flag_re: "re.Pattern[bytes]", payload: bytes) -> List[str]:
    """สุดยอดเครื่องยนต์สกัด Flag ทะลวง Null Byte, UTF-16 และ Hex-ASCII"""
    out: List[str] = []
    
    # 1. Direct Regex Match
    for f in _find_flags_bytes(flag_re, payload):
        if f not in out: out.append(f)
        
    # 2. Denull (remove null bytes)
    if b"\x00" in payload:
        denulled = payload.replace(b"\x00", b"")
        for f in _find_flags_bytes(flag_re, denulled):
            if f not in out: out.append(f)
            
    # 3. UTF-16LE Decoding
    try:
        s16 = payload.decode("utf-16le", errors="ignore")
        for f in _find_flags_bytes(flag_re, s16.encode("utf-8", errors="ignore")):
            if f not in out: out.append(f)
    except Exception:
        pass
        
    # 4. Hex-ASCII Extraction (เผื่อโจทย์ซ่อน Flag เป็น Hex ในช่อง Padding)
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        hex_candidates = re.findall(r'[0-9a-fA-F]{20,}', payload_str)
        for hc in hex_candidates:
            try:
                decoded_hex = binascii.unhexlify(hc)
                for f in _find_flags_bytes(flag_re, decoded_hex):
                    if f not in out: out.append(f)
            except: pass
    except: pass
    
    return out

def _encapsulation_header(command: int, length: int, session: int = 0, status: int = 0, context: bytes = b"\x00" * 8, options: int = 0) -> bytes:
    if len(context) != 8:
        raise ValueError("sender_context must be 8 bytes")
    return struct.pack("<HHII8sI", command, length, session, status, context, options)

def build_list_identity_request(sender_context: bytes = b"\xc1\xde\xbe\xd1\x00\x00\x00\x00") -> bytes:
    # 0x0063 คือคำสั่ง ListIdentity ที่ไม่ต้องใช้ Session ID สมบูรณ์แบบสำหรับ Recon
    return _encapsulation_header(0x0063, 0, context=sender_context)

def _printable_ascii_bytes(payload: bytes) -> str:
    s = payload.decode("latin-1", errors="ignore")
    return "".join(ch if 32 <= ord(ch) <= 126 or ch in "\r\n\t" else "." for ch in s)

def parse_encapsulation_response(data: bytes) -> Tuple[int, int, int, int, bytes]:
    if len(data) < 24:
        raise ValueError("Packet too short to be ENIP Encapsulation")
    command, length, session, status, context, options = struct.unpack("<HHII8sI", data[:24])
    payload = data[24 : 24 + length]
    return command, length, session, status, payload

def parse_cip_identity_item(payload: bytes) -> Dict[str, Any]:
    """[UPGRADE] ชำแหละโครงสร้าง CIP Identity Item ออกมาเป็นชิ้นๆ"""
    info = {}
    try:
        if len(payload) < 2: return info
        item_count = struct.unpack("<H", payload[:2])[0]
        
        # ข้าม Item Count ไปอ่าน Item แรก (ส่วนใหญ่มักมีแค่ 1 Item)
        offset = 2
        for _ in range(item_count):
            if offset + 4 > len(payload): break
            item_type, item_length = struct.unpack("<HH", payload[offset:offset+4])
            offset += 4
            
            # Item Type 0x0C = ListIdentity Response
            if item_type == 0x0C and offset + item_length <= len(payload):
                item_data = payload[offset:offset+item_length]
                if len(item_data) >= 20: # ขนาดขั้นต่ำของ Identity Data
                    info['encap_version'] = struct.unpack("<H", item_data[0:2])[0]
                    # ข้าม Socket Address (16 bytes)
                    vendor_num = struct.unpack("<H", item_data[18:20])[0]
                    info['vendor_id'] = f"{vendor_num} ({CIP_VENDORS.get(vendor_num, 'Unknown Vendor')})"                
                    device_num = struct.unpack("<H", item_data[20:22])[0]
                    info['device_type'] = f"{device_num} ({CIP_DEVICE_TYPES.get(device_num, 'Unknown Device Type')})"
                    info['product_code'] = struct.unpack("<H", item_data[22:24])[0]
                    info['revision'] = f"{item_data[24]}.{item_data[25]}"
                    info['status'] = struct.unpack("<H", item_data[26:28])[0]
                    info['serial_number'] = f"0x{struct.unpack('<I', item_data[28:32])[0]:08X}"
                    
                    name_len = item_data[32]
                    info['product_name'] = item_data[33:33+name_len].decode('utf-8', 'ignore')
            offset += item_length
    except Exception:
        pass
    return info

def main() -> None:
    parser = argparse.ArgumentParser(description="EtherNet/IP discovery: ListIdentity (0x0063) - AI Ready")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=44818, help="Target Port (ENIP TCP: 44818)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    parser.add_argument("--hex", action="store_true", help="Dump raw hex payload")
    
    # 🚀 อัปเกรด Regex เป็น God-Mode ให้ตรงกันทั้งโปรเจกต์
    parser.add_argument("--flag-regex", default=r"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key)[\s_.:-]*\{([a-zA-Z0-9_\-\.\!\?@#$%^&* ]{4,100})\}", help="Regex pattern")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = parser.parse_args()

    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "status": "success",
        "error_msg": "",
        "enip_header": {},
        "device_identity": {},
        "flags_found": []
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ ENIP LIST-IDENTITY RECON (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Targeting ENIP/CIP : {Y}{args.ip}:{args.port}{W}")

    flag_re = _compile_flag_regex(args.flag_regex)
    req = build_list_identity_request()

    try:
        with socket.create_connection((args.ip, args.port), timeout=args.timeout) as s:
            s.sendall(req)
            s.settimeout(args.timeout)
            data = s.recv(4096)
    except socket.timeout:
        if args.json:
            ai_report["status"] = "timeout"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Connection timed out.{W}")
        sys.exit(1)
    except Exception as e:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error connecting to target: {e}{W}")
        sys.exit(1)

    try:
        command, length, session, status, payload = parse_encapsulation_response(data)
        ai_report["enip_header"] = {"command": f"0x{command:04x}", "session": f"0x{session:08x}", "status": f"0x{status:08x}"}
        
        # ชำแหละ Identity Info
        device_info = parse_cip_identity_item(payload)
        ai_report["device_identity"] = device_info

        # ค้นหา Flag ด้วยเครื่องยนต์ใหม่
        found = _extract_flag_candidates(flag_re, payload)
        ai_report["flags_found"] = found

        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"[*] ENIP Command: {Y}0x{command:04x} (ListIdentity){W} | Status: {Y}0x{status:08x}{W}")
            print(f"[*] Payload Length: {length} bytes\n")
            
            if device_info:
                print(f"{M}--- [ CIP IDENTITY ITEM ] ---{W}")
                print(f"  Vendor ID    : {device_info.get('vendor_id', 'N/A')}")
                print(f"  Device Type  : {device_info.get('device_type', 'N/A')}")
                print(f"  Product Code : {device_info.get('product_code', 'N/A')}")
                print(f"  Revision     : v{device_info.get('revision', 'N/A')}")
                print(f"  Serial Number: {C}{device_info.get('serial_number', 'N/A')}{W}")
                print(f"  Product Name : {G}{device_info.get('product_name', 'N/A')}{W}")
                print(f"{M}-----------------------------{W}\n")
            
            if found:
                print(f"{R}🚨 [ALERT] POTENTIAL FLAGS FOUND 🚨{W}")
                for f in found:
                    print(f"  {G}╰─> {f}{W}")
            else:
                print(f"{Y}[-] No flags matching regex found in payload.{W}")

            if args.hex:
                print(f"\n{C}[+] Hex Dump:{W}\n" + payload.hex())
            else:
                print(f"\n{C}[+] ASCII Dump:{W}\n" + _printable_ascii_bytes(payload))

    except Exception as e:
        if args.json:
            ai_report["status"] = "parsing_error"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error parsing response: {e}{W}")

if __name__ == "__main__":
    main()