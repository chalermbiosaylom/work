#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ LIVE IEC-104 FLAG SNIFFER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ดักจับแพ็กเก็ต IEC-104 (พอร์ต 2404) จากทุก Interface
sudo python3 iec104_sniffer.py

# 2. ดักจับผ่าน VPN/Interface เฉพาะ และโจทย์อาจจะซ่อนในพอร์ตอื่น (เช่น 24004)
sudo python3 iec104_sniffer.py --iface tun0 --port 24004

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON-Lines สำหรับ AI)
sudo python3 iec104_sniffer.py --json
===================================================================
"""
import argparse
import re
import sys
import json
import logging
import binascii
from datetime import datetime

# ปิดแจ้งเตือนกวนใจของ Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, TCP, IP, Raw

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
M = '\033[95m'  # Magenta
W = '\033[0m'   # Reset

# 🚀 อัปเกรด Regex เป็นระดับ God-Mode ให้ตรงกันทั้งโปรเจกต์ (ดักจับรูปแบบ Bytes)
FLAG_RE = re.compile(
    rb"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key)[\s_.:-]*\{([a-zA-Z0-9_\-\.\!\?@#$%^&* ]{4,100})\}",
    re.IGNORECASE
)
# 🚀 เพิ่ม Regex สำหรับดักจับกลุ่มเลข Hex ยาวๆ ที่อาจจะเป็น Flag
HEX_REGEX = re.compile(rb"\b[0-9a-fA-F]{20,}\b")

def extract_flags_from_payload(payload: bytes) -> set:
    """เครื่องยนต์ชำแหละ Byte ค้นหา Flag ทะลวง ASDU Endianness และ Hex-ASCII"""
    found = set()
    
    # 1. Direct Search (Raw)
    for match in FLAG_RE.finditer(payload):
        found.add(match.group(0).decode('utf-8', 'ignore'))
        
    # 2. Byte Swapped (16-bit)
    data = bytearray(payload)
    if len(data) % 2 != 0: data.append(0)
    swapped_byte = bytearray(data)
    swapped_byte[0::2], swapped_byte[1::2] = swapped_byte[1::2], swapped_byte[0::2]
    for match in FLAG_RE.finditer(bytes(swapped_byte)):
        found.add(match.group(0).decode('utf-8', 'ignore'))

    # 3. Word Swapped (32-bit CDAB)
    if len(data) >= 4:
        pad_len = (4 - (len(data) % 4)) % 4
        data_word = bytearray(payload) + bytearray([0] * pad_len)
        swapped_word = bytearray(data_word)
        swapped_word[0::4], swapped_word[2::4] = swapped_word[2::4], swapped_word[0::4]
        swapped_word[1::4], swapped_word[3::4] = swapped_word[3::4], swapped_word[1::4]
        for match in FLAG_RE.finditer(bytes(swapped_word)):
            found.add(match.group(0).decode('utf-8', 'ignore'))
            
    # 4. 🚀 Hex-ASCII Extraction (ไม้ตายก้นหีบ สำหรับโปรโตคอลระดับ Network)
    try:
        # แปลง payload เป็น Hex String (เช่น b'\x63\x6f...' -> b'636f...')
        hex_payload = binascii.hexlify(payload)
        
        # ลองสแกนหา Flag ในร่าง Hex String ด้วย (เผื่อตัวอักษรเรียงกันแบบแปลกๆ)
        for match in FLAG_RE.finditer(hex_payload):
            found.add(match.group(0).decode('utf-8', 'ignore'))
            
        # ลองสแกนหา Hex ก้อนยาวๆ แล้วถอดกลับเป็น ASCII
        for token in HEX_REGEX.findall(hex_payload):
            try:
                decoded_hex = binascii.unhexlify(token)
                for match in FLAG_RE.finditer(decoded_hex):
                    found.add(match.group(0).decode('utf-8', 'ignore'))
            except: pass
    except: pass

    return found

def build_packet_handler(is_json: bool, target_port: int):
    """Factory Function สำหรับสร้าง Handler เพื่อส่งออก JSON/Console"""
    def packet_handler(pkt):
        try:
            if TCP in pkt and Raw in pkt:
                # ยืนยันพอร์ตเป้าหมายอีกชั้น (กันเหนียว)
                if pkt[TCP].sport == target_port or pkt[TCP].dport == target_port:
                    payload = bytes(pkt[Raw].load)
                    
                    # ข้ามการตรวจสอบความยาว APCI 6 Bytes ไปเลย เพื่อความรวดเร็วในการล่า Flag
                    flags = extract_flags_from_payload(payload)
                    
                    if flags:
                        src = pkt[IP].src if IP in pkt else "Unknown"
                        dst = pkt[IP].dst if IP in pkt else "Unknown"
                        timestamp = datetime.now().strftime("%H:%M:%S")

                        if is_json:
                            # [โหมด AI] พ่น JSON-Lines
                            report = {
                                "timestamp": timestamp,
                                "protocol": "IEC-104",
                                "source_ip": src,
                                "destination_ip": dst,
                                "flags_found": list(flags)
                            }
                            print(json.dumps(report))
                            sys.stdout.flush() # ดันข้อมูลออกทันทีให้ Trae หยิบไปอ่าน
                        else:
                            # [โหมดมนุษย์] เด้ง Alert เตือนภัย
                            print(f"\n{C}[{timestamp}]{W} {R}⚡ ALERT! FLAG DETECTED IN IEC-104 TRAFFIC ⚡{W}")
                            print(f"  {M}Route: {src} -> {dst}{W}")
                            for f in flags:
                                print(f"  {G}╰─> {f}{W}")
        except Exception:
            pass
            
    return packet_handler

def main():
    parser = argparse.ArgumentParser(description="Live IEC-104 Flag Sniffer (AI Ready)")
    parser.add_argument("--iface", help="Interface to sniff on (e.g., eth0, tun0)")
    parser.add_argument("--port", type=int, default=2404, help="IEC-104 Port (Default: 2404)")
    parser.add_argument("--json", action="store_true", help="Output JSON-Lines for Trae IDE")
    args = parser.parse_args()

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} ⚡ LIVE IEC-104 FLAG SNIFFER (GOD-MODE) ⚡ {W}")
        print(f"{C}=================================================={W}")
        iface_str = args.iface if args.iface else "ALL INTERFACES"
        print(f"[*] Listening on Interface : {Y}{iface_str}{W}")
        print(f"[*] Target Port Filter     : {Y}TCP {args.port}{W}")
        print(f"[*] Waiting for Flags... (Press Ctrl+C to stop)\n")

    handler = build_packet_handler(args.json, args.port)
    bpf_filter = f"tcp port {args.port}"

    try:
        if args.iface:
            sniff(filter=bpf_filter, prn=handler, iface=args.iface, store=0)
        else:
            sniff(filter=bpf_filter, prn=handler, store=0)
            
    except PermissionError:
        if args.json:
            print(json.dumps({"error": "Permission denied. Requires sudo/root."}))
        else:
            print(f"{R}[-] Permission denied. Packet sniffing requires root/sudo privileges!{W}")
            print(f"{Y}[*] Try running with: sudo python3 iec104_sniffer.py{W}")
    except KeyboardInterrupt:
        if not args.json:
            print(f"\n{Y}[*] Sniffer stopped by user. Exiting.{W}")
    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\n{R}[-] Sniffer encountered a fatal error: {e}{W}")

if __name__ == "__main__":
    main()