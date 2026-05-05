#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS TRIAGE & CONNECTION TESTER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. รันแบบมนุษย์ (สแกนแบบเร็ว Unit 1-5, 255)
python3 modbus_connect_test.py --ip 127.0.0.1 --port 1503

# 2. โหมดปูพรม (สแกนหา Unit ID ทั้งหมด 1-255 ด้วยความเร็วสูง)
python3 modbus_connect_test.py --ip 10.10.10.5 --full-scan

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_connect_test.py --ip 10.10.10.5 --full-scan --json
===================================================================
"""
from __future__ import annotations

import argparse
import json
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
    2: "Illegal Data Address (ไม่มีตู้นี้ในระบบ)",
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

        if not resp.isError():
            info["vendor"] = resp.information.get(0, b'Unknown').decode('utf-8', 'ignore')
            info["product"] = resp.information.get(1, b'Unknown').decode('utf-8', 'ignore')
            info["version"] = resp.information.get(2, b'Unknown').decode('utf-8', 'ignore')
    except Exception:
        pass
    return info

def check_single_slave(ip: str, port: int, uid: int) -> dict | None:
    """ฟังก์ชันเช็ค Slave ตัวเดียว (สำหรับใช้กับ Threading)"""
    client = ModbusTcpClient(ip, port=port, timeout=1.0)
    result = None
    try:
        if client.connect():
            try:
                rr = client.read_holding_registers(address=0, count=1, slave=uid)
            except TypeError:
                rr = client.read_holding_registers(address=0, count=1, unit=uid)
            
            if not rr.isError():
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
    p = argparse.ArgumentParser(description="Modbus Triage & Connection Tester (AI Edition)")
    p.add_argument("--ip", dest="ip_address", default="127.0.0.1", help="Target IP")
    p.add_argument("--port", dest="port", type=int, default=502, help="Target Port")
    p.add_argument("--full-scan", action="store_true", help="Scan all Unit IDs (1-255)")
    p.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = p.parse_args()

    ip_address = args.ip_address
    port = args.port

    ai_report = {
        "target": f"{ip_address}:{port}",
        "connection_success": False,
        "active_slaves": []
    }

    if not args.json:
        print(f"\n{CYAN}=================================================={RESET}")
        print(f"{CYAN} 🔌 MODBUS TRIAGE & CONNECTION TESTER {RESET}")
        print(f"{CYAN}=================================================={RESET}")
        print(f"{CYAN}[*] Attempting to connect to {ip_address}:{port}...{RESET}")
    
    # ทดสอบการเชื่อมต่อเบื้องต้น
    test_client = ModbusTcpClient(ip_address, port=port, timeout=3)
    if test_client.connect():
        ai_report["connection_success"] = True
        if not args.json: print(f"{GREEN}[+] Connection Established Successfully!{RESET}\n")
        test_client.close()
        
        # กำหนดช่วงสแกน
        target_units = list(range(1, 256)) if args.full_scan else [1, 2, 3, 4, 5, 255]
        scan_type = "Full (1-255)" if args.full_scan else "Quick (1-5, 255)"
        
        if not args.json: print(f"{CYAN}[*] Initiating {scan_type} Slave ID Scan using Multi-threading...{RESET}")
        
        # ยิง Multi-threading แบบดุดัน
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(lambda uid: check_single_slave(ip_address, port, uid), target_units)
            
            for res in results:
                if res:
                    ai_report["active_slaves"].append(res)
                    if not args.json:
                        uid = res["unit_id"]
                        status = res["status"]
                        vend = res["device_info"]["vendor"]
                        prod = res["device_info"]["product"]
                        color = GREEN if "Responded" in status else YELLOW
                        
                        print(f"{color}[+] Slave ID {uid:3} : {status}{RESET}")
                        if vend != "Unknown":
                            print(f"      {MAGENTA}[i] Device: {vend} | {prod}{RESET}")
        
        # จบการทำงาน
        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"\n{YELLOW}--- [ TRIAGE COMPLETE ] ---{RESET}")
            if ai_report["active_slaves"]:
                target_id = ai_report["active_slaves"][0]["unit_id"]
                active_list = [s["unit_id"] for s in ai_report["active_slaves"]]
                print(f"Target        : {ip_address}:{port}")
                print(f"Active Slaves : {active_list}")
                print(f"{GREEN}Next Step     : Use flag hunter script with '--unit {target_id}'{RESET}\n")
            else:
                print(f"{RED}[-] Connected, but NO Slave IDs responded.{RESET}\n")
    else:
        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            raise SystemExit(f"{RED}[-] Connection failed. Check IP, Port, or your Tunnel!{RESET}")

if __name__ == "__main__":
    main()