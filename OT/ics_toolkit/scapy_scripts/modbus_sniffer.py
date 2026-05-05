#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ LIVE MODBUS FLAG SNIFFER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ดักจับแพ็กเก็ต Modbus (พอร์ต 502) จากทุก Interface ในเครื่อง
sudo python3 modbus_sniffer.py

# 2. ระบุ Interface ที่เชื่อมต่อกับเป้าหมาย (เช่น VPN tun0 หรือ eth1)
sudo python3 modbus_sniffer.py --iface tun0

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON-Lines สำหรับ AI)
sudo python3 modbus_sniffer.py --iface tun0 --json
===================================================================
"""
import argparse
import re
import sys
import json
import logging
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

# แก้ไข Regex ให้จับแบบเต็มคำด้วย (?:...)
FLAG_RE = re.compile(rb"(?:coc2026|flag|TIGER)\{[^}\r\n]{1,200}\}", re.IGNORECASE)

def extract_flags_from_payload(payload: bytes) -> set:
    """เครื่องยนต์ชำแหละ Byte เพื่อหา Flag (รองรับ Big/Little/Word Swap)"""
    found = set()
    
    # 1. Direct Search
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

    return found

def build_packet_handler(is_json: bool):
    """สร้างฟังก์ชัน Handler เพื่อดักจับและส่งออกผลลัพธ์ (รองรับโหมด AI)"""
    def packet_handler(pkt):
        try:
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                flags = extract_flags_from_payload(payload)
                
                if flags:
                    src = pkt[IP].src if IP in pkt else "Unknown"
                    dst = pkt[IP].dst if IP in pkt else "Unknown"
                    timestamp = datetime.now().strftime("%H:%M:%S")

                    if is_json:
                        # [โหมด AI] พ่น JSON ออกทีละบรรทัด (Streaming Format)
                        report = {
                            "timestamp": timestamp,
                            "source_ip": src,
                            "destination_ip": dst,
                            "flags_found": list(flags)
                        }
                        print(json.dumps(report))
                        sys.stdout.flush() # บังคับดันข้อมูลออกทันทีให้ AI อ่าน
                    else:
                        # [โหมดมนุษย์] เด้ง Alert สีสันกระแทกตา
                        print(f"\n{C}[{timestamp}]{W} {R}🚨 ALERT! FLAG DETECTED IN LIVE TRAFFIC 🚨{W}")
                        print(f"  {M}Route: {src} -> {dst}{W}")
                        for f in flags:
                            print(f"  {G}╰─> {f}{W}")
        except Exception:
            pass # ถ้าแพ็กเก็ตพัง ให้ข้ามไปเงียบๆ ป้องกันโปรแกรมแคช
            
    return packet_handler

def main():
    parser = argparse.ArgumentParser(description="Live Modbus Flag Sniffer (AI Ready)")
    parser.add_argument("--iface", help="Interface to sniff on (e.g., eth0, tun0)")
    parser.add_argument("--json", action="store_true", help="Output JSON-Lines for Trae IDE")
    args = parser.parse_args()

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 📡 LIVE MODBUS FLAG SNIFFER (GOD-MODE) 📡 {W}")
        print(f"{C}=================================================={W}")
        iface_str = args.iface if args.iface else "ALL INTERFACES"
        print(f"[*] Listening on Interface : {Y}{iface_str}{W}")
        print(f"[*] Target Port Filter     : {Y}TCP 502{W}")
        print(f"[*] Waiting for Flags... (Press Ctrl+C to stop)\n")

    # เรียกใช้ Factory function เพื่อส่งสถานะ JSON เข้าไปใน Scapy Sniffer
    handler = build_packet_handler(args.json)

    try:
        if args.iface:
            sniff(filter="tcp port 502", prn=handler, iface=args.iface, store=0)
        else:
            sniff(filter="tcp port 502", prn=handler, store=0)
            
    except PermissionError:
        # ดักจับ Error หากลืมใช้ Sudo
        if args.json:
            print(json.dumps({"error": "Permission denied. Requires sudo/root."}))
        else:
            print(f"{R}[-] Permission denied. Packet sniffing requires root/sudo privileges!{W}")
            print(f"{Y}[*] Try running with: sudo python3 modbus_sniffer.py{W}")
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