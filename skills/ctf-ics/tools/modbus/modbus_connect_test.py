#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS TRIAGE & CONNECTION TESTER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. รันแบบมนุษย์ (สแกนแบบเร็ว Unit 1-5, 255)
python3 modbus_connect_test.py --ip 127.0.0.1 --port 502

# 2. โหมดปูพรม (สแกนหา Unit ID ทั้งหมด 1-255 ด้วยความเร็วสูง)
python3 modbus_connect_test.py --ip 10.10.10.5 --full-scan

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_connect_test.py --ip 10.10.10.5 --full-scan --json
===================================================================
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pymodbus.client import ModbusTcpClient

# ANSI Color Codes for CTF
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

# Dictionary แปลภาษา Exception ของ Modbus
MODBUS_EXCEPTIONS = {
    1: "Illegal Function (FC ไม่รองรับ)",
    2: "Illegal Data Address (ไม่มีตู้นี้ในระบบ หรือ Address 0 อ่านไม่ได้)",
    3: "Illegal Data Value (ค่าที่ส่งไปผิดแปลก)",
    4: "Slave Device Failure (อุปกรณ์ปลายทางพัง)"
}

def get_device_info(client: ModbusTcpClient, uid: int) -> dict:
    """ดึงข้อมูลยี่ห้อและรุ่นของเป้าหมายด้วย Function Code 43 (MEI)"""
    info = {"vendor": "Unknown", "product": "Unknown", "version": "Unknown"}
    try:
        try:
            resp = client.read_device_information(read_code=1, object_id=0, slave=uid)
        except TypeError:
            resp = client.read_device_information(read_code=1, object_id=0, unit=uid)

        # 🛡️ Safe check ป้องกัน Error Object
        if resp and not getattr(resp, 'isError', lambda: True)():
            info["vendor"] = resp.information.get(0, b'Unknown').decode('utf-8', 'ignore')
            info["product"] = resp.information.get(1, b'Unknown').decode('utf-8', 'ignore')
            info["version"] = resp.information.get(2, b'Unknown').decode('utf-8', 'ignore')
    except Exception:
        pass
    return info

def check_single_slave(ip: str, port: int, uid: int) -> dict | None:
    """ฟังก์ชันเช็ค Slave ตัวเดียว (สำหรับใช้กับ Threading)"""
    client = ModbusTcpClient(ip, port=port, timeout=1.0) # Timeout สั้นๆ เพื่อความเร็วในการสแกน
    result = None
    try:
        if client.connect():
            try:
                rr = client.read_holding_registers(address=0, count=1, slave=uid)
            except TypeError:
                rr = client.read_holding_registers(address=0, count=1, unit=uid)
            
            if rr is None:
                return None
                
            if not getattr(rr, 'isError', lambda: True)():
                dev_info = get_device_info(client, uid)
                result = {"unit_id": uid, "status": "ACTIVE (Responded to FC03)", "device_info": dev_info}
            elif hasattr(rr, 'exception_code'):
                ex_msg = MODBUS_EXCEPTIONS.get(rr.exception_code, f"Unknown Exception ({rr.exception_code})")
                dev_info = get_device_info(client, uid)
                result = {"unit_id": uid, "status": f"ACTIVE (Returned: {ex_msg})", "device_info": dev_info}
    except Exception:
        pass
    finally:
        client.close()
    return result

def main() -> None:
    # --- 🛠️ ส่วน Argument Parsing ที่หายไป (Restored) ---
    parser = argparse.ArgumentParser(description="Modbus Triage & Connection Tester (AI Ready)")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=502, help="Target Port (default: 502)")
    parser.add_argument("--full-scan", action="store_true", help="Scan all 255 Unit IDs")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = parser.parse_args()

    # เตรียม JSON โครงสร้างสำหรับ AI
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "connection_success": False,
        "scan_type": "Full (1-255)" if args.full_scan else "Quick (1-5, 255)",
        "active_slaves": [],
        "error_msg": ""
    }

    if not args.json:
        print(f"\n{CYAN}=================================================={RESET}")
        print(f"{CYAN} 🏴‍☠️ MODBUS TRIAGE & CONNECTION TESTER (GOD-MODE) 🏴‍☠️ {RESET}")
        print(f"{CYAN}=================================================={RESET}")
        print(f"[*] Target : {YELLOW}{args.ip}:{args.port}{RESET}")

    # ทดสอบการเชื่อมต่อเบื้องต้น (Socket Test)
    test_client = ModbusTcpClient(args.ip, port=args.port, timeout=3.0)
    if test_client.connect():
        ai_report["connection_success"] = True
        if not args.json: print(f"{GREEN}[+] Connection Established Successfully!{RESET}\n")
        test_client.close()
        
        # กำหนดช่วงสแกน
        target_units = list(range(1, 256)) if args.full_scan else [1, 2, 3, 4, 5, 255]
        
        if not args.json: print(f"{CYAN}[*] Initiating {ai_report['scan_type']} Slave ID Scan using Multi-threading...{RESET}")
        
        # ยิง Multi-threading แบบดุดัน
        with ThreadPoolExecutor(max_workers=50) as executor:
            # ใช้ args.ip และ args.port ให้ตรงกับ argparse
            results = executor.map(lambda uid: check_single_slave(args.ip, args.port, uid), target_units)
            
            for res in results:
                if res:
                    ai_report["active_slaves"].append(res)
                    if not args.json:
                        uid = res["unit_id"]
                        status = res["status"]
                        vend = res["device_info"]["vendor"]
                        prod = res["device_info"]["product"]
                        color = GREEN if "Responded" in status else YELLOW
                        
                        print(f"{color}[+] Slave ID {uid:<3} : {status}{RESET}")
                        if vend != "Unknown" or prod != "Unknown":
                            print(f"      {MAGENTA}╰─> Device: {vend} | {prod}{RESET}")
        
        # จบการทำงาน (แสดงผล)
        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"\n{YELLOW}--- [ TRIAGE COMPLETE ] ---{RESET}")
            if ai_report["active_slaves"]:
                target_id = ai_report["active_slaves"][0]["unit_id"]
                active_list = [s["unit_id"] for s in ai_report["active_slaves"]]
                print(f"Target        : {args.ip}:{args.port}")
                print(f"Active Slaves : {active_list}")
                print(f"{GREEN}Next Step     : Use flag hunter script with '--unit {target_id}'{RESET}\n")
            else:
                print(f"{RED}[-] Connected, but NO Slave IDs responded. (Might be a Honeypot or requires specific FC){RESET}\n")
    else:
        # กรณีต่อไม่ติดเลยตั้งแต่ต้น
        if args.json:
            ai_report["error_msg"] = "Connection Refused or Timeout"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{RED}[-] Connection failed. Check IP, Port, or your Tunnel!{RESET}")
            sys.exit(1)

if __name__ == "__main__":
    main()