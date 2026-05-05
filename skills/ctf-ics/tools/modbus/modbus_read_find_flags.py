#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ MODBUS FLAG HUNTER v2.0 (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สแกนแหกค่าย (หาตู้ทั้งหมด + หา Unit อัตโนมัติด้วย Multi-thread)
python3 modbus_read_find_flags.py --ip 10.10.x.x --probe-units --reg-end 65535 --stop-after 5

# 2. กำหนดเป้าหมาย Unit และรูปแบบตัวอักษรของ Flag แบบเจาะจง
python3 modbus_read_find_flags.py --ip 10.10.x.x --unit 1 --flag-regex "secret_[A-Z0-9]+"

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 modbus_read_find_flags.py --ip 10.10.x.x --probe-units --json

# 4. สแกนเฉพาะ Input Registers (FC04) สำหรับ sensor challenge
python3 modbus_read_find_flags.py --ip 10.10.x.x --unit 1 --fc04-only --json

# 5. สแกนรวม Coils (FC01) ด้วย (หา flag ซ่อนใน bit pattern)
python3 modbus_read_find_flags.py --ip 10.10.x.x --unit 1 --fc01-coils --json
===================================================================
"""
import argparse
import re
import sys
import json
import binascii
import struct
import base64
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
    if start < 0 or end < 0 or end < start or end > 255:
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
    found: List[str] = []
    seen = set()
    
    # 1. Direct regex match on bytes
    for m in flag_re.finditer(blob):
        flag = m.group(0).decode("utf-8", errors="ignore")
        if flag not in seen:
            seen.add(flag)
            found.append(flag)
    
    # 2. ASCII-Hex Detection
    try:
        blob_str = blob.decode('utf-8', errors='ignore')
        hex_candidates = re.findall(r'[0-9a-fA-F]{20,}', blob_str)
        for hc in hex_candidates:
            try:
                decoded_hex = binascii.unhexlify(hc)
                for m in flag_re.finditer(decoded_hex):
                    flag = m.group(0).decode("utf-8", errors="ignore")
                    if flag not in seen:
                        seen.add(flag)
                        found.append(flag)
            except:
                pass
    except:
        pass

    # 3. Base64 → Hex → ASCII decode chain (GridTech HR[200] pattern)
    try:
        blob_str = blob.decode('utf-8', errors='ignore')
        b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', blob_str)
        for bc in b64_candidates:
            try:
                step2 = base64.b64decode(bc + '==')
                step2_str = step2.decode('ascii', errors='strict').strip()
                if re.fullmatch(r'[0-9a-fA-F]+', step2_str) and len(step2_str) % 2 == 0:
                    step3 = bytes.fromhex(step2_str)
                    for m in flag_re.finditer(step3):
                        flag = m.group(0).decode("utf-8", errors="ignore")
                        if flag not in seen:
                            seen.add(flag)
                            found.append(flag)
            except:
                pass
    except:
        pass

    # 4. NEW: Hex → Base64 → ASCII chain (BlackStart vault pattern)
    try:
        blob_str = blob.decode('utf-8', errors='ignore')
        hex_candidates = re.findall(r'[0-9a-fA-F]{20,}', blob_str)
        for hc in hex_candidates:
            if len(hc) % 2 != 0:
                continue
            try:
                step2 = binascii.unhexlify(hc)
                step2_str = step2.decode('ascii', errors='ignore').strip()
                # Check if it's base64-encoded
                if re.fullmatch(r'[A-Za-z0-9+/=]{8,}', step2_str):
                    padded = step2_str + '=' * (-len(step2_str) % 4)
                    step3 = base64.b64decode(padded)
                    for m in flag_re.finditer(step3):
                        flag = m.group(0).decode("utf-8", errors="ignore")
                        if flag not in seen:
                            seen.add(flag)
                            found.append(flag)
            except:
                pass
    except:
        pass

    # 5. Null-byte stripped direct match
    try:
        stripped = blob.replace(b'\x00', b'')
        if stripped != blob:  # only if different
            for m in flag_re.finditer(stripped):
                flag = m.group(0).decode("utf-8", errors="ignore")
                if flag not in seen:
                    seen.add(flag)
                    found.append(flag)
    except:
        pass

    return found

def _scan_coils_for_flags(client: ModbusTcpClient, unit_id: int, start: int, end: int, flag_re: "re.Pattern[bytes]", stop_after: int, flags_found: List[str], is_json: bool) -> None:
    """Scan coils (FC01), pack bits into bytes, and run flag extraction."""
    chunk = 2000  # max coils per request
    addr = start
    all_bits: List[int] = []
    while addr < end and len(flags_found) < stop_after:
        count = min(chunk, end - addr)
        try:
            rr = _call_modbus(client, "read_coils", unit_id, address=addr, count=count)
        except Exception:
            addr += count
            continue
        if rr is None or getattr(rr, "isError", lambda: True)():
            addr += count
            continue
        bits = getattr(rr, "bits", None)
        if not bits:
            addr += count
            continue
        all_bits.extend([1 if b else 0 for b in bits[:count]])
        addr += count

    if not all_bits:
        return

    # Pack bits into bytes (LSB-first, like Modbus coil response)
    blob = bytearray()
    for i in range(0, len(all_bits), 8):
        byte_val = 0
        for bit_idx in range(min(8, len(all_bits) - i)):
            if all_bits[i + bit_idx]:
                byte_val |= (1 << bit_idx)
        blob.append(byte_val)

    for f in _find_flags(flag_re, bytes(blob)):
        if f not in flags_found:
            flags_found.append(f)
            if not is_json:
                print(f"  {G}[🎯 FOUND]{W} Unit: {C}{unit_id:02d}{W} | {Y}Coil bits{W} -> {G}{f}{W}")
            if len(flags_found) >= stop_after:
                return


def _scan_register_space(client: ModbusTcpClient, unit_id: int, method: str, start: int, end: int, chunk: int, flag_re: "re.Pattern[bytes]", stop_after: int, flags_found: List[str], is_json: bool) -> None:
    addr = start
    overlap = 10  # อ่านเหลื่อม 10 ตู้ เพื่อกัน Flag ขาดรอยต่อ
    while addr < end and len(flags_found) < stop_after:
        count = min(chunk, end - addr)
        try:
            rr = _call_modbus(client, method, unit_id, address=addr, count=count)
        except Exception:
            step = max(1, count - overlap) if count == chunk else count
            addr += step
            continue
            
        if rr is None or getattr(rr, "isError", lambda: True)():
            addr += 1
            continue
            
        regs = getattr(rr, "registers", None)
        if not regs:
            addr += 1
            continue
            
        for blob in _regs_to_bytes_variants(regs):
            for f in _find_flags(flag_re, blob):
                if f not in flags_found:
                    flags_found.append(f)
                    if not is_json:
                        kind = "Holding Reg" if method == "read_holding_registers" else "Input Reg"
                        print(f"  {G}[🎯 FOUND]{W} Unit: {C}{unit_id:02d}{W} | {Y}{kind}{W} | Addr: {C}{addr}{W} -> {G}{f}{W}")
                    if len(flags_found) >= stop_after: return
                    
        step = max(1, count - overlap) if count == chunk else count
        addr += step

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
    p.add_argument("--ip", required=True, help="Target IP")
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
    
    # 🚀 อัปเกรด Regex เป็นระดับ God-Mode ให้ครอบคลุมทุกค่าย
    p.add_argument("--flag-regex", default=r"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key)[\s_.:-]*\{([a-zA-Z0-9_\-\.\!\?@#$%^&* ]{4,100})\}")
    p.add_argument("--fc04-only", action="store_true", help="Scan only Input Registers (FC04), skip Holding Registers")
    p.add_argument("--fc01-coils", action="store_true", help="Also scan Coils (FC01) for flag bit patterns")
    p.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    
    args = p.parse_args()

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
        probe = units if args.unit_range else [0] + list(range(1, 248)) + [255]
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
        
        # Scan Coils (FC01) — optional, for flag bit patterns
        if args.fc01_coils and len(flags_found) < args.stop_after:
            _scan_coils_for_flags(client, uid, 0, min(reg_end, 2000), flag_re, args.stop_after, flags_found, args.json)

        # Scan Holding Registers (FC03) — skip if --fc04-only
        if not args.fc04_only and len(flags_found) < args.stop_after:
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