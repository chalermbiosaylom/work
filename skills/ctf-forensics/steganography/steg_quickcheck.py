#!/usr/bin/env python3
"""
===================================================================
🖼️ STEGANOGRAPHY QUICK-CHECK (GOD-MODE & AI-READY) 🖼️
===================================================================
# วิธีใช้ (Usage Examples):

# 1. ตรวจสอบไฟล์ภาพเบื้องต้น (รวดเร็ว)
python3 steg_quickcheck.py image.png

# 2. ตรวจสอบแบบเจาะลึก (เปิดใช้งาน Stegoveritas และ Zsteg แบบสแกนทุกมิติ)
python3 steg_quickcheck.py image.png --deep

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON พร้อมสกัด Flag อัตโนมัติ)
python3 steg_quickcheck.py image.png --json
===================================================================
"""
import sys
import subprocess
import os
import argparse
import json
import re
import tempfile
import shutil

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
M = '\033[95m'
W = '\033[0m'

# 🚀 God-Mode Regex (รองรับ Hex 32 ตัว, Leetspeak และรูปแบบต่างๆ)
FLAG_REGEX = re.compile(
    r"(?:coc2026|flag|f1a9|fl4g|tiger|ctf|key)[\s_.:-]*\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b",
    re.IGNORECASE
)

def extract_flags(text: str) -> list:
    """สแกนหา Flag จาก Text Output ทุกชนิด"""
    if not text: return []
    return [m.group(0) for m in FLAG_REGEX.finditer(text)]

def run_command(cmd: list, timeout: int = 15) -> tuple:
    """รันคำสั่งและคืนค่า (Success, Output_String)"""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        output = ""
        if result.stdout: output += result.stdout.decode("utf-8", errors="ignore")
        if result.stderr: output += "\n" + result.stderr.decode("utf-8", errors="ignore")
        return (result.returncode == 0, output)
    except subprocess.TimeoutExpired:
        return (False, f"[!] Timeout exceeded ({timeout}s)")
    except FileNotFoundError:
        return (False, f"[!] Tool '{cmd[0]}' not installed.")
    except Exception as e:
        return (False, f"[!] Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Steganography Quick Check (AI Ready)")
    parser.add_argument("image", help="Path to image file")
    parser.add_argument("--deep", action="store_true", help="Run thorough/slow tools (stegoveritas, zsteg -a)")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = parser.parse_args()

    if not os.path.exists(args.image):
        if args.json: print(json.dumps({"status": "error", "error_msg": "File not found"}))
        else: print(f"{R}[-] File not found: {args.image}{W}")
        sys.exit(1)

    ai_report = {
        "target": args.image,
        "status": "success",
        "flags_found": [],
        "tool_results": {}
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🖼️ STEGANOGRAPHY QUICK-CHECK (GOD-MODE) 🖼️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Target : {Y}{args.image}{W}")
        print(f"[*] Mode   : {'Deep Scan (Slow)' if args.deep else 'Quick Triage (Fast)'}\n")

    global_flags = set()
    temp_dir = tempfile.mkdtemp(prefix="steg_")

    try:
        # 1. File & Magic Bytes
        is_png = False
        success, out = run_command(["file", args.image])
        ai_report["tool_results"]["file"] = out.strip()
        if "PNG image" in out: is_png = True
        
        # 2. Exiftool
        success, out = run_command(["exiftool", args.image])
        flags = extract_flags(out)
        ai_report["tool_results"]["exiftool"] = {"flags": flags, "raw_excerpt": out[:500] + "..." if len(out)>500 else out}
        global_flags.update(flags)

        # 3. Binwalk (ตรวจหาไฟล์ซ่อน/Zip ที่ต่อท้าย)
        success, out = run_command(["binwalk", args.image])
        flags = extract_flags(out)
        ai_report["tool_results"]["binwalk"] = {"flags": flags, "raw": out.strip()}
        global_flags.update(flags)

        # 4. Strings (ASCII & UTF-16LE)
        _, out_ascii = run_command(["strings", "-n", "8", args.image])
        _, out_utf16 = run_command(["strings", "-n", "8", "-el", args.image])
        all_strings = out_ascii + "\n" + out_utf16
        flags = extract_flags(all_strings)
        ai_report["tool_results"]["strings"] = {"flags": flags}
        global_flags.update(flags)

        # 5. Steghide (ลองเจาะแบบไม่มีรหัสผ่าน)
        steghide_out_file = os.path.join(temp_dir, "steghide_out.bin")
        success, out = run_command(["steghide", "extract", "-sf", args.image, "-p", "", "-q", "-xf", steghide_out_file])
        if os.path.exists(steghide_out_file) and os.path.getsize(steghide_out_file) > 0:
            with open(steghide_out_file, "rb") as f:
                extracted_data = f.read().decode("utf-8", errors="ignore")
                flags = extract_flags(extracted_data)
                ai_report["tool_results"]["steghide"] = {"success": True, "flags": flags, "extracted_preview": extracted_data[:200]}
                global_flags.update(flags)
        else:
            ai_report["tool_results"]["steghide"] = {"success": False, "msg": "Requires password or no stego data."}

        # 6. Zsteg (เฉพาะ PNG/BMP)
        if is_png:
            zsteg_cmd = ["zsteg", "-a", args.image] if args.deep else ["zsteg", args.image]
            success, out = run_command(zsteg_cmd, timeout=60 if args.deep else 20)
            flags = extract_flags(out)
            ai_report["tool_results"]["zsteg"] = {"flags": flags, "raw_excerpt": out[:500] + "..." if len(out)>500 else out}
            global_flags.update(flags)

        # 7. Stegoveritas (รันเฉพาะตอนสั่ง --deep เพราะมันช้ามาก)
        if args.deep:
            sv_out_dir = os.path.join(temp_dir, "sv_out")
            success, out = run_command(["stegoveritas", args.image, "-out", sv_out_dir], timeout=120)
            ai_report["tool_results"]["stegoveritas"] = {"success": success, "out_dir": sv_out_dir}

        # สรุปผล
        ai_report["flags_found"] = list(global_flags)

        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            # รายงานให้มนุษย์อ่าน
            print(f"[*] Analysis Complete!")
            print(f"  - File Type : {ai_report['tool_results']['file'].split(':')[1].strip() if ':' in ai_report['tool_results']['file'] else 'Unknown'}")
            print(f"  - Steghide  : {'[+] Extracted data!' if ai_report['tool_results'].get('steghide', {}).get('success') else '[-] No data / Needs password'}")
            if is_png:
                print(f"  - Zsteg     : {'[+] Ran successfully' if 'zsteg' in ai_report['tool_results'] else '[-] Failed'}")
            
            if 'binwalk' in ai_report['tool_results'] and 'Zip archive' in ai_report['tool_results']['binwalk'].get('raw', ''):
                print(f"\n{Y}[!] BINWALK ALERT: Hidden archives detected! Run 'binwalk -e {args.image}' to extract.{W}")

            if global_flags:
                print(f"\n{R}🚨 [BINGO!] FLAGS DETECTED IN IMAGE 🚨{W}")
                for f in global_flags:
                    print(f"  {G}╰─> {f}{W}")
            else:
                print(f"\n{Y}[-] No explicit flags found. Manual visual inspection (Stegsolve) may be required.{W}")

    finally:
        # ทำความสะอาดไฟล์ชั่วคราว
        if not args.deep: # ถ้าสั่ง --deep จะเก็บโฟลเดอร์ sv_out ไว้ให้คนเข้าไปดูรูป
            shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            if not args.json: print(f"\n{M}[i] Deep scan temp files retained at: {temp_dir}{W}")

if __name__ == "__main__":
    main()