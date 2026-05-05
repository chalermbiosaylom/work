#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ENIP/CIP TAG SWEEPER & FLAG HUNTER (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สแกนหา Flag จาก Tag/Path แบบเจาะจง
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --tag "@8/1/5"

# 2. ปูพรมสแกนอัตโนมัติ (Auto-Sweep) กวาด Class 8
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --auto-sweep --sweep-range 1-50

# 3. ระบุชนิดข้อมูล (Data Type)
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --tag "@8/1/5" --type "STRING"

# 4. รันผ่าน Trae IDE / AI Agent (พ่นผลลัพธ์เป็น JSON)
python3 enip_cpppo_read_find_flags.py --ip 10.10.10.5 --auto-sweep --json

# 5. NEW: Multi-Class Sweep (Assembly 0x04 + Control 0x64) — สำหรับ PDS-9000 family
python3 enip_cpppo_read_find_flags.py --ip 192.168.1.22 --auto-sweep \
    --sweep-classes "0x04,0x64" --sweep-range 1-200 --use-get-all

# 6. NEW: Hex → Base64 → ASCII decode chain (ปลดล็อค hex(base64(flag)) vault)
python3 enip_cpppo_read_find_flags.py --ip <IP> --tag "@4/150/3" --decode-chain hex,base64
===================================================================

Lessons learned (BlackStart Grid CTF, Apr 2026):
- Get Attribute Single (0x0E) often truncates large strings;
  use Get Attribute All (0x01) via --use-get-all to retrieve full payload.
- Hidden audit objects appear in Class 0x64 (Control) Inst > 1 only after state transition.
- Vault payloads use chained encoding: hex(base64(ascii_flag)).
- Always sweep Class 0x04 (Assembly) + 0x64 (Control) on PDS-9000 emulator family.
"""
import argparse
import re
import struct
import sys
import json
import base64
import binascii
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

def _get_variants(raw_bytes: bytes) -> List[bytes]:
    """สร้างร่างแยกของข้อมูล (Byte Swap, Word Swap) เพื่อดัก Flag ที่เรียงผิดระเบียบ"""
    variants = [raw_bytes] 
    
    # Byte Swap (AB CD -> BA DC)
    try:
        if len(raw_bytes) % 2 == 0:
            b_swap = bytearray()
            for i in range(0, len(raw_bytes), 2):
                b_swap.append(raw_bytes[i+1])
                b_swap.append(raw_bytes[i])
            variants.append(bytes(b_swap))
    except: pass

    # Word Swap (AB CD EF GH -> CD AB GH EF)
    try:
        if len(raw_bytes) % 4 == 0:
            w_swap = bytearray()
            for i in range(0, len(raw_bytes), 4):
                w_swap.extend(raw_bytes[i+2:i+4])
                w_swap.extend(raw_bytes[i:i+2])
            variants.append(bytes(w_swap))
    except: pass

    return variants

def _extract_flag_candidates(flag_re: "re.Pattern[bytes]", payload: bytes) -> List[str]:
    """เครื่องยนต์สกัด Flag ทะลวง Endianness, Null Byte, UTF-16 และ Hex"""
    out: List[str] = []
    
    # โยน payload เข้าโรงงานสร้างร่างแยก (สลับ Byte/Word) ก่อนเลย
    for variant_payload in _get_variants(payload):
        
        # 1. Direct regex match
        for f in _find_flags_bytes(flag_re, variant_payload):
            if f not in out: out.append(f)

        # 2. Denull (remove null bytes)
        if b"\x00" in variant_payload:
            denulled = variant_payload.replace(b"\x00", b"")
            for f in _find_flags_bytes(flag_re, denulled):
                if f not in out: out.append(f)

        # 3. UTF-16LE decoding
        try:
            s16 = variant_payload.decode("utf-16le", errors="ignore")
            for f in _find_flags_bytes(flag_re, s16.encode("utf-8", errors="ignore")):
                if f not in out: out.append(f)
        except Exception:
            pass
        
        # 4. ASCII-Hex Detection (Hex → ASCII)
        try:
            payload_str = variant_payload.decode('utf-8', errors='ignore')
            hex_candidates = re.findall(r'[0-9a-fA-F]{20,}', payload_str)
            for hc in hex_candidates:
                # Trim to even length
                hc_even = hc if len(hc) % 2 == 0 else hc[:-1]
                try:
                    decoded_hex = binascii.unhexlify(hc_even)
                    for f in _find_flags_bytes(flag_re, decoded_hex):
                        if f not in out: out.append(f)

                    # 5. NEW: Hex → Base64 → ASCII chain (BlackStart vault pattern)
                    try:
                        b64_str = decoded_hex.decode('ascii', errors='ignore').strip()
                        # Base64 alphabet validation
                        if re.fullmatch(r'[A-Za-z0-9+/=]+', b64_str) and len(b64_str) >= 8:
                            # Pad to multiple of 4
                            pad = (-len(b64_str)) % 4
                            b64_padded = b64_str + ('=' * pad)
                            decoded_b64 = base64.b64decode(b64_padded, validate=False)
                            for f in _find_flags_bytes(flag_re, decoded_b64):
                                if f not in out: out.append(f)
                    except Exception:
                        pass
                except Exception:
                    pass
        except Exception:
            pass

        # 6. NEW: Direct Base64 → ASCII (in case payload is already b64)
        try:
            payload_str = variant_payload.decode('utf-8', errors='ignore')
            b64_candidates = re.findall(r'[A-Za-z0-9+/=]{16,}', payload_str)
            for bc in b64_candidates:
                pad = (-len(bc)) % 4
                bc_padded = bc + ('=' * pad)
                try:
                    decoded = base64.b64decode(bc_padded, validate=False)
                    for f in _find_flags_bytes(flag_re, decoded):
                        if f not in out: out.append(f)
                except Exception:
                    pass
        except Exception:
            pass

    return out

def _coerce_to_bytes_variants(value: Any) -> List[bytes]:
    """แปลง CIP Data Type เป็น Bytes พื้นฐาน"""
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

        raw_f_le, raw_f_be = bytearray(), bytearray()
        raw_i_le, raw_i_be = bytearray(), bytearray()

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
    parser.add_argument("--auto-sweep", action="store_true", help="Auto-sweep common CIP paths")
    parser.add_argument("--sweep-range", default="1-10", help="Instance range, e.g. 1-200")
    parser.add_argument("--sweep-attrs", default="1-6", help="Attribute range, e.g. 1-10")
    parser.add_argument("--sweep-classes", default="8",
                        help="NEW: Comma-separated CIP classes to sweep (e.g. '0x04,0x64,8' for Assembly+Control+Symbol)")
    parser.add_argument("--use-get-all", action="store_true",
                        help="NEW: Use Service 0x01 (Get Attribute All) instead of 0x0E - avoids truncation")
    parser.add_argument("--decode-chain", default="",
                        help="NEW: Force decode chain on payload (e.g. 'hex,base64')")
    parser.add_argument("--max-flags", type=int, default=3, help="Stop after finding N flags")
    
    # 🚀 อัปเกรด Regex เป็นระดับ God-Mode ให้ครอบคลุมรูปแบบที่หลากหลายขึ้น
    parser.add_argument("--flag-regex", default=r"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key)[\s_.:-]*\{([a-zA-Z0-9_\-\.\!\?@#$%^&* ]{4,100})\}")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")

    args = parser.parse_args()

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

        def parse_class(c: str) -> int:
            c = c.strip()
            return int(c, 16) if c.lower().startswith('0x') else int(c)

        insts = parse_range(args.sweep_range)
        attrs = parse_range(args.sweep_attrs)
        classes = [parse_class(c) for c in args.sweep_classes.split(',')]
        if not args.json:
            cls_str = ','.join(f'0x{c:02X}' for c in classes)
            print(f"[*] Generating Auto-Sweep targets (Classes: {cls_str})...")

        for cls in classes:
            if args.use_get_all:
                # Get Attribute All for each instance (covers all attrs in one call, no truncation)
                tags_to_scan.extend([f"@{cls}/{inst}" for inst in insts])
            else:
                tags_to_scan.extend([f"@{cls}/{inst}/{attr}" for inst in insts for attr in attrs])

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
            print(f"{Y}[~] Probing CIP Path: {tag:<15}{W}", end="\r")
            sys.stdout.flush()

        try:
            # NEW: When --use-get-all, query without specifying type to get raw payload
            if args.use_get_all:
                # cpppo proxy_simple supports the path-only form for service 0x01 via tuple
                # For Class/Inst paths (no Attr), cpppo will issue Get Attribute All
                res = dev.read([tag])
            else:
                res = dev.read([(tag, args.type)])
            for item in _flatten_results(res):
                for blob in _coerce_to_bytes_variants(item):
                    for f in _extract_flag_candidates(flag_re, blob):
                        if f not in found_strings:
                            found_strings.append(f)
                            found_flags_dict.append({"path": tag, "flag": f})
                            
                            if not args.json:
                                sys.stdout.write("\033[K") 
                                print(f"{G}[🎯 BINGO!]{W} Path: {C}{tag}{W} -> {G}{f}{W}")
                                
                            if len(found_strings) >= args.max_flags: break
                if len(found_strings) >= args.max_flags: break
        except Exception as e:
            if args.tag and not args.json:
                sys.stdout.write("\033[K")
                print(f"{R}[-] Error reading {tag}: {e}{W}")
            
            # 🛡️ THE POLISH: Reconnect on dropped socket
            try:
                dev = proxy_simple(args.ip, port=args.port)
            except Exception:
                pass 

    ai_report["tags_scanned"] = len(tags_to_scan)
    ai_report["flags_found"] = found_flags_dict

    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        sys.stdout.write("\033[K") 
        print(f"\n{C}=================================================={W}")
        if not found_strings:
            print(f"{R}[-] Scan complete. No flags found.{W}")
        else:
            print(f"{G}[+] Mission Accomplished! Extracted {len(found_strings)} Flags.{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()