#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS PCAP FLAG EXTRACTOR (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สกัด Flag จากไฟล์ PCAP ทั่วไป (หาเฉพาะพอร์ต 502)
python3 modbus_flag_extract_pcap.py capture.pcap

# 2. สแกนทุกพอร์ตในไฟล์ PCAP (เผื่อโจทย์หลอกใช้พอร์ตอื่นที่ไม่ใช่ 502)
python3 modbus_flag_extract_pcap.py capture.pcap --all-ports

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_flag_extract_pcap.py capture.pcap --json
===================================================================
"""
import argparse
import re
import sys
import json
import logging

# ปิดแจ้งเตือนกวนใจของ Scapy (เช่น IPv6 warning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, TCP, UDP, IP, Raw

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
M = '\033[95m'  # Magenta
W = '\033[0m'   # Reset

# ใช้ (?:...) เพื่อแก้บั๊ก Regex ให้ดึงข้อมูลเต็มๆ ออกมา ไม่ใช่แค่ Prefix
FLAG_RE = re.compile(rb"(?:coc2026|flag|TIGER)\{[^}\r\n]{1,200}\}", re.IGNORECASE)

def extract_flags_from_payload(payload: bytes) -> set:
    """เครื่องยนต์ชำแหละ Byte ค้นหา Flag ในทุกมิติ Endianness"""
    found = set()
    
    # 1. Raw Payload (อ่านตรงๆ)
    for match in FLAG_RE.finditer(payload):
        found.add(match.group(0).decode('utf-8', 'ignore'))
        
    # 2. Byte Swapped (สลับทีละ 16-bit)
    data = bytearray(payload)
    if len(data) % 2 != 0: 
        data.append(0)
    swapped_byte = bytearray(data)
    swapped_byte[0::2], swapped_byte[1::2] = swapped_byte[1::2], swapped_byte[0::2]
    for match in FLAG_RE.finditer(bytes(swapped_byte)):
        found.add(match.group(0).decode('utf-8', 'ignore'))
        
    # 3. Word Swapped (สลับทีละ 32-bit CDAB - เจอแอบบ่อยในตู้ Float ของ PLC)
    if len(data) % 4 == 0 or len(data) > 4:
        pad_len = (4 - (len(data) % 4)) % 4
        data_word = bytearray(payload) + bytearray([0] * pad_len)
        swapped_word = bytearray(data_word)
        # สลับ [0,1,2,3] -> [2,3,0,1]
        swapped_word[0::4], swapped_word[2::4] = swapped_word[2::4], swapped_word[0::4]
        swapped_word[1::4], swapped_word[3::4] = swapped_word[3::4], swapped_word[1::4]
        for match in FLAG_RE.finditer(bytes(swapped_word)):
            found.add(match.group(0).decode('utf-8', 'ignore'))

    return found

def main():
    parser = argparse.ArgumentParser(description="Advanced Modbus PCAP Flag Extractor")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (not just 502)")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = parser.parse_args()

    # โครงสร้าง Report สำหรับป้อน Trae IDE
    ai_report = {
        "pcap_file": args.pcap,
        "status": "success",
        "error_msg": "",
        "total_packets_scanned": 0,
        "flags_found": []
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ MODBUS PCAP FLAG EXTRACTOR (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Reading PCAP: {Y}{args.pcap}{W}")
        print(f"[*] Port Filter : {Y}{'ALL PORTS' if args.all_ports else '502 (Modbus)'}{W}\n")

    global_flags = set()
    packet_count = 0
    
    try:
        # ใช้ PcapReader ช่วยให้อ่านไฟล์ 10GB+ ได้โดยที่คอมไม่ค้าง
        with PcapReader(args.pcap) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                
                if Raw in pkt:
                    # ระบบกรองพอร์ต (Port Filtering)
                    is_modbus_port = False
                    if TCP in pkt and (pkt[TCP].sport == 502 or pkt[TCP].dport == 502):
                        is_modbus_port = True
                    elif UDP in pkt and (pkt[UDP].sport == 502 or pkt[UDP].dport == 502):
                        is_modbus_port = True
                        
                    if not args.all_ports and not is_modbus_port:
                        continue
                        
                    payload = bytes(pkt[Raw].load)
                    extracted = extract_flags_from_payload(payload)
                    
                    if extracted:
                        # ดึง IP มาวิเคราะห์ว่าใครส่ง Flag ให้ใคร
                        src_ip = pkt[IP].src if IP in pkt else "Unknown"
                        dst_ip = pkt[IP].dst if IP in pkt else "Unknown"
                        
                        for f in extracted:
                            if f not in global_flags:
                                global_flags.add(f)
                                ai_report["flags_found"].append({
                                    "flag": f,
                                    "packet_num": packet_count,
                                    "source_ip": src_ip,
                                    "destination_ip": dst_ip
                                })
                                if not args.json:
                                    print(f"  {G}[🎯 FOUND]{W} Pkt #{packet_count} | {M}{src_ip} -> {dst_ip}{W} | Flag: {G}{f}{W}")

    except FileNotFoundError:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = "File not found"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error: PCAP file '{args.pcap}' not found.{W}")
        sys.exit(1)
    except Exception as e:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error reading PCAP: {e}{W}")
        sys.exit(1)

    ai_report["total_packets_scanned"] = packet_count

    # สรุปผล
    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        print(f"\n{C}=================================================={W}")
        print(f"[*] Total Packets Scanned: {packet_count}")
        if not global_flags:
            print(f"{R}[-] No flags found in this PCAP.{W}")
        else:
            print(f"{G}[+] Extracted {len(global_flags)} unique flags!{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()