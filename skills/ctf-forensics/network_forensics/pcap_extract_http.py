#!/usr/bin/env python3
"""
===================================================================
🌐 PCAP HTTP/DNS EXTRACTOR & FLAG HUNTER (GOD-MODE & AI-READY) 🌐
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สกัด HTTP, ดึงไฟล์ที่ดาวน์โหลด/อัปโหลด, และหา Flag อัตโนมัติ
python3 pcap_extract_http.py capture.pcap

# 2. ระบุโฟลเดอร์ปลายทาง
python3 pcap_extract_http.py capture.pcap --outdir /tmp/pcap_analysis

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 pcap_extract_http.py capture.pcap --json
===================================================================
"""
import sys
import os
import subprocess
import argparse
import json
import re
import shutil

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
M = '\033[95m'
W = '\033[0m'

# 🚀 God-Mode Regex
FLAG_REGEX = re.compile(
    r"(?:coc2026|flag|f1a9|fl4g|tiger|ctf|key)[\s_.:-]*\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b",
    re.IGNORECASE
)

def run_cmd(cmd: list, timeout: int = 60) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.returncode == 0, result.stdout, result.stderr)
    except Exception as e:
        return (False, "", str(e))

def extract_flags_from_file(filepath: str) -> set:
    """สแกนหา Flag ในไฟล์ (อ่านแบบ Binary-safe)"""
    found = set()
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            for match in FLAG_REGEX.finditer(content):
                found.add(match.group(0))
    except Exception:
        pass
    return found

def main():
    parser = argparse.ArgumentParser(description="PCAP HTTP/DNS Extractor & Flag Hunter")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--outdir", default="pcap_extraction", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for Trae IDE")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        if args.json: print(json.dumps({"status": "error", "error_msg": "PCAP file not found"}))
        else: print(f"{R}[-] PCAP file not found: {args.pcap}{W}")
        sys.exit(1)

    ai_report = {
        "pcap_file": args.pcap,
        "status": "success",
        "dns_queries": [],
        "http_requests": [],
        "extracted_files": [],
        "flags_found": []
    }

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🌐 HTTP/DNS PCAP EXTRACTOR (GOD-MODE) 🌐 {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Target : {Y}{args.pcap}{W}")
        print(f"[*] Output : {Y}{args.outdir}{W}\n")

    os.makedirs(args.outdir, exist_ok=True)
    global_flags = set()

    # ---------------------------------------------------------
    # 1. Extract DNS Queries
    # ---------------------------------------------------------
    if not args.json: print(f"[*] Extracting DNS Queries...")
    success, stdout, _ = run_cmd(["tshark", "-r", args.pcap, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"])
    if success and stdout:
        queries = list(set(q.strip() for q in stdout.split("\n") if q.strip()))
        ai_report["dns_queries"] = queries
        
        # ค้นหา Flag ในชื่อ Domain (DNS Exfiltration)
        for q in queries:
            flags = FLAG_REGEX.findall(q)
            global_flags.update(flags)

        dns_file = os.path.join(args.outdir, "dns_queries.txt")
        with open(dns_file, "w") as f: f.write("\n".join(queries))

    # ---------------------------------------------------------
    # 2. Extract HTTP Requests & POST Data
    # ---------------------------------------------------------
    if not args.json: print(f"[*] Extracting HTTP Requests & POST Data...")
    success, stdout, _ = run_cmd([
        "tshark", "-r", args.pcap, "-Y", "http.request", 
        "-T", "fields", 
        "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri", "-e", "http.file_data"
    ])
    if success and stdout:
        reqs = [r.strip() for r in stdout.split("\n") if r.strip()]
        ai_report["http_requests"] = reqs
        
        # สแกนหา Flag ใน URI หรือ POST Data
        flags = FLAG_REGEX.findall(stdout)
        global_flags.update(flags)

        req_file = os.path.join(args.outdir, "http_requests.txt")
        with open(req_file, "w") as f: f.write("\n".join(reqs))

    # ---------------------------------------------------------
    # 3. Export HTTP Objects (ดาวน์โหลดไฟล์ที่ถูกรับ/ส่ง)
    # ---------------------------------------------------------
    http_obj_dir = os.path.join(args.outdir, "http_objects")
    os.makedirs(http_obj_dir, exist_ok=True)
    
    if not args.json: print(f"[*] Exporting HTTP Objects (Files)...")
    success, _, stderr = run_cmd(["tshark", "-r", args.pcap, "--export-objects", f"http,{http_obj_dir}"])
    
    if os.path.exists(http_obj_dir):
        extracted_files = os.listdir(http_obj_dir)
        ai_report["extracted_files"] = extracted_files
        
        # สแกนหา Flag ในทุกไฟล์ที่สกัดออกมาได้!
        for filename in extracted_files:
            filepath = os.path.join(http_obj_dir, filename)
            file_flags = extract_flags_from_file(filepath)
            global_flags.update(file_flags)

    # ---------------------------------------------------------
    # 4. TCPFlow Fallback (ถ้าจำเป็น)
    # ---------------------------------------------------------
    tcpflow_dir = os.path.join(args.outdir, "tcpflow_output")
    os.makedirs(tcpflow_dir, exist_ok=True)
    if not args.json: print(f"[*] Reconstructing Raw TCP Streams (tcpflow)...")
    run_cmd(["tcpflow", "-r", args.pcap, "-o", tcpflow_dir])
    
    # สแกนหา Flag ใน TCP Streams ดิบๆ
    if os.path.exists(tcpflow_dir):
        for filename in os.listdir(tcpflow_dir):
            filepath = os.path.join(tcpflow_dir, filename)
            if os.path.isfile(filepath):
                file_flags = extract_flags_from_file(filepath)
                global_flags.update(file_flags)

    # ---------------------------------------------------------
    # สรุปผล
    # ---------------------------------------------------------
    ai_report["flags_found"] = list(global_flags)

    if args.json:
        print(json.dumps(ai_report, indent=2))
    else:
        print(f"\n{C}=================================================={W}")
        print(f"[*] Output saved to: {Y}{args.outdir}{W}")
        print(f"[*] HTTP Objects Extracted: {len(ai_report['extracted_files'])} files")
        print(f"[*] Unique DNS Queries    : {len(ai_report['dns_queries'])} domains")
        
        if global_flags:
            print(f"\n{R}🚨 [BINGO!] FLAGS DETECTED IN NETWORK TRAFFIC 🚨{W}")
            for f in global_flags:
                print(f"  {G}╰─> {f}{W}")
        else:
            print(f"\n{Y}[-] No explicit flags found in plaintext/HTTP. Try analyzing the extracted files manually.{W}")
        print(f"{C}=================================================={W}")

if __name__ == "__main__":
    main()