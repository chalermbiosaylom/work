#!/usr/bin/env python3
"""
===================================================================
📊 ENTROPY SCANNER (GOD-MODE & AI-READY) 📊
===================================================================
# วิธีใช้ (Usage Examples):

# 1. สแกนไฟล์แบบด่วน (หาค่ารวม และหา Block ที่ซ่อนไฟล์เข้ารหัส)
python3 entropy_scan.py suspicious.bin

# 2. ปรับขนาด Block และตั้ง Threshold (เช่น โชว์เฉพาะจุดที่ Entropy > 7.5)
python3 entropy_scan.py suspicious.bin --block-size 512 --threshold 7.5

# 3. รันผ่าน Trae IDE (พ่นผลลัพธ์เป็น JSON สำหรับ AI)
python3 entropy_scan.py suspicious.bin --json
===================================================================
"""
import sys
import math
import argparse
import json
import os
from collections import Counter

# --- ANSI Colors ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
M = '\033[95m'
W = '\033[0m'

# Magic Bytes ยอดฮิตที่มักจะอยู่ตรงจุดที่ Entropy พุ่งสูง
MAGIC_HINTS = {
    b'PK\x03\x04': 'ZIP Archive',
    b'Rar!\x1a\x07': 'RAR Archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
    b'\x1f\x8b\x08': 'GZIP Archive',
    b'\x89PNG': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'MZ': 'Windows PE Executable',
    b'\x7fELF': 'Linux ELF Executable'
}

def calculate_entropy(data: bytes) -> float:
    """คำนวณ Shannon Entropy (0.0 ถึง 8.0)"""
    if not data:
        return 0.0
    byte_counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def interpret_entropy(entropy: float) -> str:
    """แปลความหมายของค่า Entropy"""
    if entropy < 1.0: return "Very Low (Highly repetitive, padding, sparse data)"
    elif entropy < 3.5: return "Low (Text files, uncompressed bitmaps, structured data)"
    elif entropy < 6.0: return "Medium (Machine code, documents, mixed data)"
    elif entropy < 7.5: return "High (Compressed data, packed code)"
    else: return "Very High (Encrypted, heavily compressed, or true random)"

def get_sparkline(entropies: list, length: int = 50) -> str:
    """สร้างกราฟ ASCII Sparkline เพื่อดูภาพรวมของไฟล์"""
    if not entropies: return ""
    sparks = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█']
    step = max(1, len(entropies) // length)
    sampled = [max(entropies[i:i+step]) for i in range(0, len(entropies), step)]
    
    line = ""
    for e in sampled:
        # Map 0.0 - 8.0 to 0 - 7
        idx = min(7, int((e / 8.0) * 8))
        if e > 7.5: line += f"{R}{sparks[idx]}{W}"
        elif e > 6.0: line += f"{Y}{sparks[idx]}{W}"
        else: line += f"{G}{sparks[idx]}{W}"
    return line

def check_magic(data_block: bytes) -> str:
    """แอบส่อง Magic Bytes ตรงจุดที่ Entropy สไปค์"""
    for magic, name in MAGIC_HINTS.items():
        if data_block.startswith(magic):
            return name
    return ""

def main():
    parser = argparse.ArgumentParser(description="Advanced Block-Level Entropy Scanner")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--block-size", type=int, default=1024, help="Size of chunk to scan (default: 1024)")
    parser.add_argument("--threshold", type=float, default=7.5, help="Flag blocks with entropy >= this value (default: 7.5)")
    parser.add_argument("--json", action="store_true", help="Output pure JSON for AI")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        if args.json: print(json.dumps({"error": "File not found"}))
        else: print(f"{R}[-] File not found: {args.file}{W}")
        sys.exit(1)

    ai_report = {
        "file": args.file,
        "size_bytes": os.path.getsize(args.file),
        "global_entropy": 0.0,
        "high_entropy_blocks": []
    }

    try:
        with open(args.file, "rb") as f:
            full_data = f.read()
            
        if not full_data:
            if args.json: print(json.dumps({"error": "File is empty"}))
            else: print(f"{Y}[!] File is empty.{W}")
            sys.exit(0)

        # 1. Global Entropy
        global_ent = calculate_entropy(full_data)
        ai_report["global_entropy"] = round(global_ent, 4)

        if not args.json:
            print(f"\n{C}=================================================={W}")
            print(f"{C} 📊 ADVANCED ENTROPY SCANNER (GOD-MODE) 📊 {W}")
            print(f"{C}=================================================={W}")
            print(f"[*] Target       : {Y}{args.file}{W}")
            print(f"[*] File Size    : {len(full_data)} bytes")
            print(f"[*] Block Size   : {args.block_size} bytes")
            print(f"[*] Threshold    : >= {args.threshold} bits/byte")
            print(f"\n{M}[ GLOBAL ENTROPY ]{W}")
            print(f"  ╰─> Value  : {Y}{global_ent:.4f}{W} bits/byte")
            print(f"  ╰─> Status : {interpret_entropy(global_ent)}")

        # 2. Block-Level Scanning
        block_entropies = []
        high_blocks = []

        for offset in range(0, len(full_data), args.block_size):
            chunk = full_data[offset:offset+args.block_size]
            ent = calculate_entropy(chunk)
            block_entropies.append(ent)
            
            if ent >= args.threshold:
                hint = check_magic(chunk)
                hex_preview = chunk[:8].hex()
                
                high_blocks.append({
                    "offset": offset,
                    "offset_hex": f"0x{offset:08x}",
                    "entropy": round(ent, 4),
                    "magic_hint": hint,
                    "hex_preview": hex_preview
                })

        ai_report["high_entropy_blocks"] = high_blocks

        # แสดงผลลัพธ์
        if args.json:
            print(json.dumps(ai_report, indent=2))
        else:
            print(f"\n{M}[ ENTROPY MAP ]{W} (Green=Low, Yellow=Med, Red=High)")
            print(f"  [{get_sparkline(block_entropies, 50)}]")
            
            print(f"\n{M}[ BLOCK ANALYSIS ]{W}")
            if high_blocks:
                print(f"{R}🚨 Found {len(high_blocks)} High-Entropy Blocks! (Possible hidden payloads) 🚨{W}")
                for idx, hb in enumerate(high_blocks[:20]): # โชว์แค่ 20 อันแรกกันล้นจอ
                    hint_str = f" | Hint: {G}{hb['magic_hint']}{W}" if hb['magic_hint'] else ""
                    print(f"  ╰─> Offset: {C}{hb['offset_hex']}{W} | Entropy: {R}{hb['entropy']:.2f}{W} | Hex: {hb['hex_preview']}{hint_str}")
                
                if len(high_blocks) > 20:
                    print(f"  ... and {len(high_blocks) - 20} more blocks.")
                
                print(f"\n{Y}[!] Next Action:{W}")
                print(f"    Use 'dd' or 'binwalk' to carve out data starting at the identified offsets.")
                print(f"    Example: dd if={args.file} of=extracted.bin bs=1 skip=$(( {high_blocks[0]['offset']} ))")
            else:
                print(f"{G}[+] No specific high-entropy spikes found (Threshold >= {args.threshold}).{W}")

    except Exception as e:
        if args.json: print(json.dumps({"error": str(e)}))
        else: print(f"{R}[-] Error: {e}{W}")

if __name__ == "__main__":
    main()