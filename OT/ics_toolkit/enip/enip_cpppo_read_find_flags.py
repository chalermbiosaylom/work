#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ENIP/CIP TAG SWEEPER & FLAG HUNTER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สแกนหา Flag จาก Tag/Path แบบเจาะจง (เช่น Class 8, Instance 1, Attribute 5)
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --tag "@8/1/5"

# 2. ปูพรมสแกนอัตโนมัติ (Auto-Sweep) กวาด Class 8 ตั้งแต่ Instance 1-50
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --auto-sweep --sweep-range 1-50

# 3. ระบุชนิดข้อมูล (Data Type) ที่ต้องการให้แปลความหมาย (เช่น STRING, DINT, REAL)
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --tag "@8/1/5" --type "STRING"

# 4. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --auto-sweep --json
===================================================================
"""
import argparse
import re
import struct
import sys
import json
from typing import Any, Iterable, List, Sequence

try:
    from cpppo.server.enip.get_attribute import proxy_simple
except ImportError:
    print("\033[91m[-] Missing 'cpppo' library.\033[0m")
    print("\033[93m[*] Please install it using: pip install cpppo\033[0m")
    sys.exit(1)

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
W = '\033[0m'   # Reset

def _compile_flag_regex(pattern: str) -> "re.Pattern[bytes]":
    return re.compile(pattern.encode("utf-8"), re.IGNORECASE)

def _find_flags_bytes(flag_re: "re.Pattern[bytes]", blob: bytes) -> List[str]:
    return [m.group(0).decode("utf-8", errors="ignore") for m in flag_re.finditer(blob)]

def _extract_flag_candidates(flag_re: "re.Pattern[bytes]", payload: bytes) -> List[str]:
    out: List[str] = []
    for f in _find_flags_bytes(flag_re, payload):
        if f not in out: out.append(f)

    if b"\x00" in payload:
        denulled = payload.replace(b"\x00", b"")
        for f in _find_flags_bytes(flag_re, denulled):
            if f not in out: out.append(f)

    try:
        s16 = payload.decode("utf-16le", errors="ignore")
        for f in _find_flags_bytes(flag_re, s16.encode("utf-8", errors="ignore")):
            if f not in out: out.append(f)
    except Exception:
        pass

    return out

def _coerce_to_bytes_variants(value: Any) -> List[bytes]:
    """เครื่องยนต์แปลง CIP Data Type เป็น Bytes ทุกรูปแบบเพื่อหา Flag"""
    variants: List[bytes] = []

    if isinstance(value, (bytes, bytearray)):
        variants.append(bytes(value))
        return variants

    if isinstance(value, str):
        variants.append(value.encode("utf-8", errors="ignore"))
        return variants

    if isinstance(value, (int, float)):
        value = [value]

    if isinstance(value, list):
        if value and all(isinstance(b, int) for b in value):
            b = bytes([x & 0xFF for x in value])
            variants.append(b)
            return variants

        raw_f_le = bytearray()
        raw_f_be = bytearray()
        raw_i_le = bytearray()
        raw_i_be = bytearray()

        for x in value:
            if isinstance(x, float):
                try:
                    raw_f_le.extend(struct.pack("<f", x))
                    raw_f_be.extend(struct.pack(">f", x))
                except Exception: continue
            elif isinstance(x, int):
                try:
                    raw_i_le.extend(struct.pack("<I", x & 0xFFFFFFFF))
                    raw_i_be.extend(struct.pack(">I", x & 0xFFFFFFFF))
                except Exception: continue

        if raw_f_le: variants.append(bytes(raw_f_le))
        if raw_f_be: variants.append(bytes(raw_f_be))
        if raw_i_le: variants.append(bytes(raw_i_le))
        if raw_i_be: variants.append(bytes(raw_i_be))

    return variants

def _flatten_results(result: Any) -> List[Any]:
    if result is None: return []
    if isinstance(result, dict): return list(result.values())
    if isinstance(result, list): return result
    return [result]

def main():
    parser = argparse.ArgumentParser(description="Scan EtherNet/IP (ENIP/CIP) tags/paths for flags")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=44818, help="Target Port (default: 44818)")
    parser.add_argument("--tag", help="Specific Tag to read (optional)")
    parser.add_argument("--type", default="REAL[10]", help="Data type to cast (default: REAL[10])")
    parser.add_argument("--auto-sweep", action="store_true", help="Auto-sweep common CIP paths (Class 8)")
    parser.add_argument("--sweep-range", default="1-10", help="Instance range for @8 sweep, e.g. 1-50")
    parser.add_argument("--sweep-attrs", default="1-6", help="Attribute range for @8 sweep, e.g. 1-10")
    parser.add_argument("--max-flags", type=int, default=3, help="Stop after finding N flags")
    parser.add_argument("--flag-regex", default=r"(?:coc2026|flag|TIGER)\{[^}\r\n]{1,200}\}")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")

    args = parser.parse_args()

    # โครงสร้าง JSON สำหรับ AI
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "status": "success",
        "error_msg": "",
        "tags_scanned": 0,
        "flags_found": []
    }

    flag_re = _compile_flag_regex(args.flag_regex)

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ ENIP CIP TAG SWEEPER (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Connecting to {args.ip}:{args.port}...")

    try:
        dev = proxy_simple(args.ip, port=args.port)
    except Exception as e:
        if args.json:
            ai_report["status"] = "connection_failed"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Connection failed: {e}{W}")
        sys.exit(1)

    tags_to_scan = []
    if args.tag:
        tags_to_scan.append(args.tag)
    
    if args.auto_sweep:
        def parse_range(s: str) -> range:
            if "-" not in s:
                v = int(s)
                return range(v, v + 1)
            a, b = s.split("-", 1)
            start, end = int(a), int(b)
            if end < start:
                start, end = end, start
            return range(start, end + 1)

        insts = parse_range(args.sweep_range)
        attrs = parse_range(args.sweep_attrs)
        if not args.json: print(f"[*] Generating Auto-Sweep targets (Class 8)...")
        tags_to_scan.extend([f"@8/{inst}/{attr}" for inst in insts for attr in attrs])

    if not tags_to_scan:
        if args.json:
            ai_report["status"] = "error"
            ai_report["error_msg"] = "No tags specified"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] No tags specified. Use --tag or --auto-sweep.{W}")
        sys.exit(1)

    if not args.json:
        print(f"[*] Scanning {len(tags_to_scan)} tags/paths (Type: {args.type})...\n")
    
    found_flags_dict: List[dict] = []
    found_strings: List[str] = []
    
    for tag in tags_to_scan:
        if len(found_strings) >= args.max_flags: break

        if not args.json:
            # Live Progress Bar ทับบรรทัดเดิม
            print(f"{Y}[~] Probing CIP Path: {tag:<15}{W}", end="\r")
            sys.stdout.flush()

        try:
            res = dev.read([(tag, args.type)])
            for item in _flatten_results(res):
                for blob in _coerce_to_bytes_variants(item):
                    for f in _extract_flag_candidates(flag_re, blob):
                        if f not in found_strings:
                            found_strings.append(f)
                            found_flags_dict.append({"path": tag, "flag": f})
                            
                            if not args.json:
                                # เคลียร์บรรทัดเก่า แล้วปรินต์ BINGO!
                                sys.stdout.write("\033[K") 
                                print(f"{G}[🎯 BINGO!]{W} Path: {C}{tag}{W} -> {G}{f}{W}")
                                
                            if len(found_strings) >= args.max_flags: break
                if len(found_strings) >= args.max_flags: break
        except Exception as e:
            # ซ่อน Error ของ Auto-sweep เพื่อไม่ให้หน้าจอล้น
            if args.tag and not args.json:
                sys.stdout.write("\033[K")
                print(f"{R}[-] Error reading {tag}: {e}{W}")

    # อัปเดตข้อมูลลง AI Report
    ai_report["tags_scanned"] = len(tags_to_scan)
    ai_report["flags_found"] = found_flags_dict

    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        sys.stdout.write("\033[K") # เคลียร์ Progress Bar
        print(f"\n{C}=================================================={W}")
        if not found_strings:
            print(f"{R}[-] Scan complete. No flags found.{W}")
        else:
            print(f"{G}[+] Mission Accomplished! Extracted {len(found_strings)} Flags.{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()