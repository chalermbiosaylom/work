#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ETHERNET/IP (ENIP/CIP) PCAP FLAG EXTRACTOR (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สกัด Flag จากไฟล์ PCAP ทั่วไป (หาเฉพาะ ENIP TCP:44818, UDP:2222)
python3 enip_flag_extract_pcap.py capture.pcap

# 2. ค้นหาทุกพอร์ต (เผื่อโจทย์ซ่อน ENIP ไว้พอร์ตอื่น) พร้อมเปลี่ยนรูปแบบ Flag
python3 enip_flag_extract_pcap.py capture.pcap --all-ports --flag-regex "secret_[A-Z0-9]+"

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 enip_flag_extract_pcap.py capture.pcap --json
===================================================================
"""
import argparse
import re
import sys
import json
import logging
import binascii
from typing import List

# ปิดแจ้งเตือนกวนใจของ Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, TCP, UDP, IP, Raw

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
M = '\033[95m'  # Magenta
W = '\033[0m'   # Reset

# 🚀 อัปเกรด Regex ให้เป็น God-Mode
FLAG_REGEX_PATTERN = r"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key)[\s_.:-]*\{([a-zA-Z0-9_\-\.\!\?@#$%^&* ]{4,100})\}"
HEX_REGEX = re.compile(rb"\b[0-9a-fA-F]{20,}\b")

def _compile_flag_regex(pattern: str) -> "re.Pattern[bytes]":
    return re.compile(pattern.encode("utf-8"), re.IGNORECASE)

def _find_flags_bytes(flag_re: "re.Pattern[bytes]", blob: bytes) -> List[str]:
    return [m.group(0).decode("utf-8", errors="ignore") for m in flag_re.finditer(blob)]

def _extract_flag_candidates(flag_re: "re.Pattern[bytes]", payload: bytes) -> List[str]:
    """เครื่องยนต์ชำแหละ Byte สำหรับ ENIP/CIP โดยเฉพาะ (ทะลวง Null, UTF-16, Hex)"""
    out: List[str] = []

    # 1. ค้นหาแบบตรงไปตรงมา (Raw UTF-8)
    for f in _find_flags_bytes(flag_re, payload):
        if f not in out: out.append(f)

    # 2. สาย CIP String มักจะมี Null Byte (\x00) คั่นระหว่างตัวอักษร
    if b"\x00" in payload:
        denulled = payload.replace(b"\x00", b"")
        for f in _find_flags_bytes(flag_re, denulled):
            if f not in out: out.append(f)

    # 3. สาย CIP แบบ WSTRING (UTF-16 Little Endian)
    try:
        s16 = payload.decode("utf-16le", errors="ignore")
        for f in _find_flags_bytes(flag_re, s16.encode("utf-8", errors="ignore")):
            if f not in out: out.append(f)
    except Exception:
        pass
        
    # 4. 🚀 Hex-ASCII Extraction (เผื่อโจทย์ซ่อน Flag เป็น Hex ในระดับ Network Layer)
    try:
        hex_payload = binascii.hexlify(payload)
        for f in _find_flags_bytes(flag_re, hex_payload):
            if f not in out: out.append(f)
            
        for token in HEX_REGEX.findall(hex_payload):
            try:
                decoded_hex = binascii.unhexlify(token)
                for f in _find_flags_bytes(flag_re, decoded_hex):
                    if f not in out: out.append(f)
            except: pass
    except: pass

    return out

def main():
    parser = argparse.ArgumentParser(description="Advanced EtherNet/IP (ENIP/CIP) Flag Extractor")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (ignore 44818/2222 filter)")
    parser.add_argument("--flag-regex", default=FLAG_REGEX_PATTERN, help="Custom regex pattern")
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
        print(f"{C} 🏴‍☠️ ENIP/CIP PCAP FLAG EXTRACTOR (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Reading PCAP: {Y}{args.pcap}{W}")
        print(f"[*] Port Filter : {Y}{'ALL PORTS' if args.all_ports else 'TCP:44818, UDP:2222'}{W}")
        print(f"[*] Regex       : {Y}{args.flag_regex}{W}\n")

    flag_re = _compile_flag_regex(args.flag_regex)
    global_flags = set()
    packet_count = 0
    
    try:
        # ใช้ PcapReader ทะลวงขีดจำกัด RAM
        with PcapReader(args.pcap) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                payload = b""
                proto_name = ""

                if Raw in pkt:
                    if TCP in pkt:
                        if args.all_ports or pkt[TCP].sport == 44818 or pkt[TCP].dport == 44818:
                            payload = bytes(pkt[Raw].load)
                            proto_name = "ENIP/TCP"
                    elif UDP in pkt:
                        if args.all_ports or pkt[UDP].sport == 2222 or pkt[UDP].dport == 2222:
                            payload = bytes(pkt[Raw].load)
                            proto_name = "CIP/UDP"
                
                if payload:
                    found = _extract_flag_candidates(flag_re, payload)
                    if found:
                        src_ip = pkt[IP].src if IP in pkt else "Unknown"
                        dst_ip = pkt[IP].dst if IP in pkt else "Unknown"
                        
                        for f in found:
                            # เก็บข้อมูลไม่ให้ซ้ำซ้อนในระดับ Packet เดียวกัน
                            record_key = f"{f}_{src_ip}_{dst_ip}"
                            if record_key not in global_flags:
                                global_flags.add(record_key)
                                
                                ai_report["flags_found"].append({
                                    "flag": f,
                                    "packet_num": packet_count,
                                    "protocol": proto_name,
                                    "source_ip": src_ip,
                                    "destination_ip": dst_ip
                                })
                                
                                if not args.json:
                                    print(f"  {G}[🎯 FOUND]{W} Pkt #{packet_count} | {Y}{proto_name}{W} | {M}{src_ip} -> {dst_ip}{W}")
                                    print(f"      ╰─> {G}{f}{W}")

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
        if not ai_report["flags_found"]:
            print(f"{R}[-] No flags found in this PCAP.{W}")
        else:
            print(f"{G}[+] Extracted {len(ai_report['flags_found'])} flag occurrences!{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()