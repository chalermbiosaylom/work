#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS FLAG HUNTER v2.0 (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สแกนแหกค่าย (หาตู้ทั้งหมด + หา Unit อัตโนมัติด้วย Multi-thread)
python3 modbus_read_find_flags.py 10.10.x.x --probe-units --reg-end 65535 --stop-after 5

# 2. กำหนดเป้าหมาย Unit และรูปแบบตัวอักษรของ Flag แบบเจาะจง
python3 modbus_read_find_flags.py 10.10.x.x --unit 1 --flag-regex "secret_[A-Z0-9]+"

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_read_find_flags.py 10.10.x.x --probe-units --json
===================================================================
"""
import argparse
import re
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Sequence

from pymodbus.client import ModbusTcpClient

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
W = '\033[0m'   # Reset

def _compile_flag_regex(pattern: str) -> "re.Pattern[bytes]":
    return re.compile(pattern.encode("utf-8"), re.IGNORECASE)

def _iter_units(unit: Optional[int], unit_range: Optional[str]) -> List[int]:
    if unit is not None:
        return [unit]
    if not unit_range:
        return [1]
    if "-" not in unit_range:
        return [int(unit_range)]
    start_s, end_s = unit_range.split("-", 1)
    start, end = int(start_s), int(end_s)
    if start <= 0 or end <= 0 or end < start:
        raise ValueError("invalid unit range")
    return list(range(start, end + 1))

def _call_modbus(client: ModbusTcpClient, method: str, unit_id: int, **kwargs):
    fn = getattr(client, method)
    try:
        return fn(slave=unit_id, **kwargs)
    except TypeError:
        return fn(unit=unit_id, **kwargs)

def _regs_to_bytes_variants(registers: Sequence[int]) -> List[bytes]:
    def regs_to_be(regs: Sequence[int]) -> bytes:
        out = bytearray()
        for r in regs: out.extend(int(r).to_bytes(2, "big", signed=False))
        return bytes(out)

    def regs_to_le(regs: Sequence[int]) -> bytes:
        out = bytearray()
        for r in regs: out.extend(int(r).to_bytes(2, "big", signed=False)[::-1])
        return bytes(out)

    def word_swap(regs: Sequence[int]) -> List[int]:
        swapped: List[int] = []
        i = 0
        while i + 1 < len(regs):
            swapped.extend([regs[i + 1], regs[i]])
            i += 2
        if i < len(regs): swapped.append(regs[i])
        return swapped

    regs_list = list(registers)
    swapped = word_swap(regs_list)
    return [regs_to_be(regs_list), regs_to_le(regs_list), regs_to_be(swapped), regs_to_le(swapped)]

def _find_flags(flag_re: "re.Pattern[bytes]", blob: bytes) -> List[str]:
    return [m.group(0).decode("utf-8", errors="ignore") for m in flag_re.finditer(blob)]

def _scan_register_space(client: ModbusTcpClient, unit_id: int, method: str, start: int, end: int, chunk: int, flag_re: "re.Pattern[bytes]", stop_after: int, flags_found: List[str], is_json: bool) -> None:
    addr = start
    overlap = 10  # อ่านเหลื่อม 10 ตู้ เพื่อกัน Flag ขาดรอยต่อ
    while addr < end and len(flags_found) < stop_after:
        count = min(chunk, end - addr)
        try:
            rr = _call_modbus(client, method, unit_id, address=addr, count=count)
        except Exception:
            addr += (count - overlap) if count == chunk else count
            continue
            
        if rr is None or getattr(rr, "isError", lambda: True)():
            addr += (count - overlap) if count == chunk else count
            continue
            
        regs = getattr(rr, "registers", None)
        if not regs:
            addr += (count - overlap) if count == chunk else count
            continue
            
        for blob in _regs_to_bytes_variants(regs):
            for f in _find_flags(flag_re, blob):
                if f not in flags_found:
                    flags_found.append(f)
                    if not is_json:
                        kind = "Holding Reg" if method == "read_holding_registers" else "Input Reg"
                        print(f"  {G}[🎯 FOUND]{W} Unit: {C}{unit_id:02d}{W} | {Y}{kind}{W} | Addr: {C}{addr}{W} -> {G}{f}{W}")
                    if len(flags_found) >= stop_after: return
                    
        addr += (count - overlap) if count == chunk else count

# --- Multi-threaded Probe Function ---
def _probe_single_unit(ip: str, port: int, timeout: float, uid: int) -> Optional[int]:
    tmp_client = ModbusTcpClient(ip, port=port, timeout=timeout)
    try:
        if tmp_client.connect():
            rr = _call_modbus(tmp_client, "read_holding_registers", uid, address=0, count=1)
            if rr and not getattr(rr, "isError", lambda: True)():
                return uid
    except Exception:
        pass
    finally:
        tmp_client.close()
    return None

def main() -> None:
    p = argparse.ArgumentParser(description="Modbus flag hunter (FC01/02/03/04) - AI Ready")
    p.add_argument("ip", help="Target IP")
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--unit", type=int, default=None)
    p.add_argument("--unit-range", default=None, help="e.g. 1-247")
    p.add_argument("--probe-units", action="store_true", help="FAST detect active unit IDs using Threads")
    p.add_argument("--reg-start", type=int, default=0)
    p.add_argument("--reg-end", type=int, default=65535)
    p.add_argument("--chunk-reg", type=int, default=125)
    p.add_argument("--address-base", type=int, choices=[0, 1], default=0)
    p.add_argument("--stop-after", type=int, default=5)
    p.add_argument("--flag-regex", default=r"(coc2026|flag|TIGER)\{[^}\r\n]{1,200}\}")
    p.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = p.parse_args()

    # เตรียม Data สำหรับ AI
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "status": "success",
        "error_msg": "",
        "active_units": [],
        "flags_found": []
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ MODBUS FLAG HUNTER v2.0 (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}\n")
        print(f"[*] Target: {C}{args.ip}:{args.port}{W}")
        print(f"[*] Regex : {Y}{args.flag_regex}{W}")

    try:
        units = _iter_units(args.unit, args.unit_range)
    except ValueError:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = "Invalid --unit-range"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Invalid --unit-range{W}")
        raise SystemExit(2)

    reg_end = max(0, int(args.reg_end))
    start_reg = args.reg_start + (1 if args.address_base == 1 else 0)
    flag_re = _compile_flag_regex(args.flag_regex)

    # ================= PROBE UNITS (MULTI-THREADED) =================
    if args.probe_units and args.unit is None:
        probe = units if args.unit_range else list(range(1, 248)) + [255]
        if not args.json: print(f"[*] Probing {len(probe)} Unit IDs using Multi-threading...")
        active: List[int] = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(lambda uid: _probe_single_unit(args.ip, args.port, args.timeout, uid), probe)
            for res in results:
                if res is not None:
                    active.append(res)
                    if not args.json: print(f"  {G}[+] Unit {res} is ACTIVE!{W}")
                    
        units = sorted(set(active))
        if not units:
            if args.json:
                ai_report["status"] = "no_units_found"
                print(json.dumps(ai_report, indent=2))
            else:
                print(f"{R}[-] No active units found.{W}")
            raise SystemExit(1)
            
    if not args.json: print(f"[*] Commencing Deep Scan on Units: {units}\n")
    ai_report["active_units"] = units

    # ================= DEEP SCAN (MAIN CONNECTION) =================
    client = ModbusTcpClient(args.ip, port=args.port, timeout=args.timeout)
    if not client.connect():
        if args.json:
            ai_report["status"] = "connection_failed"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Connect failed: {args.ip}:{args.port}{W}")
        raise SystemExit(1)

    flags_found: List[str] = []
    for uid in units:
        if len(flags_found) >= args.stop_after: break
        
        # Scan Holding Registers (FC03)
        _scan_register_space(client, uid, "read_holding_registers", start_reg, reg_end, max(1, int(args.chunk_reg)), flag_re, args.stop_after, flags_found, args.json)
        
        # Scan Input Registers (FC04)
        if len(flags_found) < args.stop_after:
            _scan_register_space(client, uid, "read_input_registers", start_reg, reg_end, max(1, int(args.chunk_reg)), flag_re, args.stop_after, flags_found, args.json)

    client.close()

    # ================= OUTPUT RESULTS =================
    ai_report["flags_found"] = flags_found

    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        print(f"\n{C}=================================================={W}")
        if not flags_found:
            print(f"{R}[-] No flags found. Mission Failed.{W}")
        else:
            print(f"{G}[+] Mission Accomplished! Extracted {len(flags_found)} Flags.{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()