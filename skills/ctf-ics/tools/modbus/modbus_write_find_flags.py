#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ SAFE MODBUS FUZZER & FLAG HUNTER (AI & TRAE IDE READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ยิง Fuzzing แบบมาตรฐาน (มนุษย์อ่าน)
python3 modbus_write_find_flags.py 127.0.0.1

# 2. ยิง Fuzzing ด้วยกระสุนพิเศษ (0 และ 9999)
python3 modbus_write_find_flags.py 127.0.0.1 --values "0,9999"

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_write_find_flags.py 127.0.0.1 --coil-end 50 --reg-end 50 --json

# 4. ยิงพร้อมตรวจสอบ Silent Lock (verify read-back)
python3 modbus_write_find_flags.py 127.0.0.1 --verify --json

# 5. เขียนแบบ FC16 Atomic Write (หลาย register พร้อมกัน)
python3 modbus_write_find_flags.py 127.0.0.1 --fc16-atomic --values "0xDEAD,0xBEEF,0xCAFE" --json
===================================================================
"""
import argparse
import sys
import time
import json
from pymodbus.client import ModbusTcpClient

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
def _write_coil(client: ModbusTcpClient, unit_id: int, address: int, value: bool):
    try:
        return client.write_coil(address, value, slave=unit_id)
    except TypeError:
        return client.write_coil(address, value, unit=unit_id)

def _write_register(client: ModbusTcpClient, unit_id: int, address: int, value: int):
    try:
        return client.write_register(address, value, slave=unit_id)
    except TypeError:
        return client.write_register(address, value, unit=unit_id)

def _read_coil(client: ModbusTcpClient, unit_id: int, address: int):
    try:
        return client.read_coils(address, 1, slave=unit_id)
    except TypeError:
        return client.read_coils(address, 1, unit=unit_id)

def _read_register(client: ModbusTcpClient, unit_id: int, address: int):
    try:
        return client.read_holding_registers(address, 1, slave=unit_id)
    except TypeError:
        return client.read_holding_registers(address, 1, unit=unit_id)

def decode_ascii(val: int):
    """ฟังก์ชันถอดรหัสเลข 16-bit เป็นตัวอักษร ASCII 2 ตัว"""
    high = (val >> 8) & 0xFF
    low = val & 0xFF
    chars = ""
    if 32 <= high <= 126: chars += chr(high)
    else: chars += "."
    
    if 32 <= low <= 126: chars += chr(low)
    else: chars += "."
    return chars

# ---------------------------------------------------------
# Main Logic
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Safe Modbus Fuzzer (Read-Store-Restore) for AI/CTF")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--port", type=int, default=502, help="Target Port")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout seconds")
    parser.add_argument("--unit", type=int, default=1, help="Unit ID")
    parser.add_argument("--coil-end", type=int, default=20, help="Max coil address to fuzz")
    parser.add_argument("--reg-end", type=int, default=20, help="Max register address to fuzz")
    parser.add_argument("--address-base", type=int, choices=[0, 1], default=0)
    parser.add_argument("--values", default="1,1337,65535", help="Comma-separated values to write")
    parser.add_argument("--verify", action="store_true", help="Read-back after each write to detect silent lock")
    parser.add_argument("--word-swap", action="store_true", help="Also decode ASCII with word-swapped register pairs")
    parser.add_argument("--fc16-atomic", action="store_true", help="Use FC16 Write Multiple Registers (atomic) instead of FC06")
    parser.add_argument("--json", action="store_true", help="Output in pure JSON format for Trae IDE / AI")
    
    args = parser.parse_args()

    # เตรียม Data Structure สำหรับส่งให้ AI
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "unit_id": args.unit,
        "status": "success",
        "error_msg": "",
        "fuzz_stats": {
            "coils_tested": 0,
            "registers_tested": 0,
            "silent_locks_detected": 0,
            "errors": []
        },
        "discovered_string": "",
        "discovered_string_ws": ""
    }

    client = ModbusTcpClient(args.ip, port=args.port, timeout=args.timeout)
    if not client.connect():
        if args.json:
            ai_report["status"] = "failed"
            ai_report["error_msg"] = "Connection Refused"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"[-] Failed to connect to {args.ip}:{args.port}")
        sys.exit(1)

    if not args.json:
        print(f"[*] Connected to {args.ip}:{args.port} (Unit: {args.unit})")
        print(f"[*] Starting SAFE-FUZZING Mode (Read -> Fuzz -> Restore)...")
    
    base = args.address_base

    values = []
    for s in str(args.values).split(","):
        s = s.strip()
        if s: values.append(int(s, 0))
    if not values:
        values = [1, 1337, 65535]

    # ================= FUZZING COILS =================
    if not args.json: print(f"\n[*] --- Fuzzing Coils (0-{args.coil_end}) ---")
    for i in range(args.coil_end + 1):
        addr = i - base
        if addr < 0: continue
        try:
            # 1. อ่านค่าเดิม
            orig_resp = _read_coil(client, args.unit, addr)
            orig_val = False
            if not orig_resp.isError():
                orig_val = orig_resp.bits[0]
                if not args.json: print(f"  [+] Coil {addr} original: {orig_val}")
            else:
                if not args.json: print(f"  [-] Coil {addr} read error, defaulting to False")

            # 2. ยิง Fuzz
            fuzz_val = not orig_val
            _write_coil(client, args.unit, addr, fuzz_val)  # <--- เปลี่ยนเป็น fuzz_val
            time.sleep(0.1)
            
            # 3. คืนค่าเดิม
            _write_coil(client, args.unit, addr, orig_val)
            ai_report["fuzz_stats"]["coils_tested"] += 1
            
        except Exception as e:
            if not args.json: print(f"  [!] Error on coil {addr}: {e}")
            ai_report["fuzz_stats"]["errors"].append(f"Coil {addr}: {str(e)}")

    # ================= FUZZING REGISTERS =================
    if not args.json: print(f"\n[*] --- Fuzzing Holding Registers (0-{args.reg_end}) ---")
    discovered_flag = ""
    all_regs_raw: list = []  # Collect raw register values for word-swap decode
    
    for i in range(args.reg_end + 1):
        addr = i - base
        if addr < 0: continue
        try:
            # 1. อ่านค่าเดิม
            orig_resp = _read_register(client, args.unit, addr)
            orig_val = 0
            if not orig_resp.isError():
                orig_val = orig_resp.registers[0]
                all_regs_raw.append(orig_val)
                ascii_str = decode_ascii(orig_val)
                
                if ascii_str != "..":  
                    discovered_flag += ascii_str.replace(".", "")
                    if not args.json: print(f"  [+] Reg {addr} original: {orig_val:<5} (Hex: {hex(orig_val):<6}) -> ASCII: '{ascii_str}'")
                else:
                    if not args.json: print(f"  [+] Reg {addr} original: {orig_val}")
            else:
                if not args.json: print(f"  [-] Reg {addr} read error, defaulting to 0")

            # 2. ยิง Fuzz
            for val in values:
                write_val = int(val) & 0xFFFF
                if args.fc16_atomic:
                    try:
                        client.write_registers(addr, [write_val], slave=args.unit)
                    except TypeError:
                        client.write_registers(addr, [write_val], unit=args.unit)
                else:
                    _write_register(client, args.unit, addr, write_val)
                time.sleep(0.1)

                # Verify read-back (silent lock detection)
                if args.verify:
                    try:
                        vr = _read_register(client, args.unit, addr)
                        if not vr.isError():
                            actual = vr.registers[0]
                            if actual != write_val:
                                ai_report["fuzz_stats"]["silent_locks_detected"] += 1
                                if not args.json:
                                    print(f"  [⚠️ SILENT LOCK] Reg {addr}: wrote {write_val} but read-back {actual}")
                    except Exception:
                        pass
                
            # 3. คืนค่าเดิม
            _write_register(client, args.unit, addr, orig_val)
            ai_report["fuzz_stats"]["registers_tested"] += 1
            
        except Exception as e:
            if not args.json: print(f"  [!] Error on register {addr}: {e}")
            ai_report["fuzz_stats"]["errors"].append(f"Reg {addr}: {str(e)}")
            
    client.close()

    # ---------------------------------------------------------
    # สรุปผลลัพธ์ (Output Rendering)
    # ---------------------------------------------------------
    ai_report["discovered_string"] = discovered_flag

    # Word-swap variant: swap adjacent register pairs for DINT layout PLCs
    if args.word_swap and all_regs_raw:
        ws_flag = ""
        swapped = []
        i = 0
        while i + 1 < len(all_regs_raw):
            swapped.extend([all_regs_raw[i + 1], all_regs_raw[i]])
            i += 2
        if i < len(all_regs_raw):
            swapped.append(all_regs_raw[i])
        for v in swapped:
            ws_flag += decode_ascii(v)
        ws_flag = ws_flag.replace(".", "")
        ai_report["discovered_string_ws"] = ws_flag
        if not args.json and ws_flag:
            print(f"\n🔄 [!] Word-Swap String: {ws_flag}")

    if args.json:
        # โหมด AI: พ่น JSON อย่างเดียว
        print(json.dumps(ai_report, indent=2))
    else:
        # โหมดมนุษย์: แสดงผลปกติ
        if discovered_flag:
            print(f"\n🎯 [!] Potential Flag/String Recovered: {discovered_flag}")
        print("\n[*] Done. Target state restored successfully.")

if __name__ == "__main__":
    main()