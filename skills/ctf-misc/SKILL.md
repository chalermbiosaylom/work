---
name: ctf-misc
description: Miscellaneous CTF challenge techniques. Use for encoding puzzles, RF/SDR signal processing, Python/bash jails, DNS exploitation, unicode steganography, floating-point tricks, QR codes, audio challenges, Z3 constraint solving, Kubernetes RBAC, WASM game patching, esoteric languages, game theory, commitment schemes, combinatorial games, or challenges that don't fit other categories.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [solve_misc.py](solve_misc.py) - Auto route selection (`--input-json`) + benchmark mode (`--benchmark-mode`)
- [MISC_BENCHMARK_CASES.json](MISC_BENCHMARK_CASES.json) - Benchmark set for misc tracks (programming, jail, encodings, signal)
- [challenge_artifacts.misc.template.json](challenge_artifacts.misc.template.json) - Copy-run artifact template for immediate routing
- [MISC_PROGRAMMING_PLAYBOOK.md](MISC_PROGRAMMING_PLAYBOOK.md) - Speed + continuity execution guide for programming/jail style misc
- [encodings.md](encodings.md) - Base64, hex, ROT13, custom alphabets, XOR, Vigenère, substitution, transposition, Bacon cipher, Morse, binary, octal
- [encodings-advanced.md](encodings-advanced.md) - Upstream advanced encoding and transform edge cases
- [bashjails.md](bashjails.md) - Bash restricted shell escape, Python sandbox bypass, eval jail, command filtering, import restrictions, builtins access
- [games-and-vms.md](games-and-vms.md) - Game theory, Nim, commitment schemes, custom VMs, bytecode analysis, esoteric languages
- [games-and-vms-3.md](games-and-vms-3.md) - Upstream games/VM advanced pattern set #3
- [games-and-vms-4.md](games-and-vms-4.md) - Upstream games/VM advanced pattern set #4
- [rf-sdr.md](rf-sdr.md) - RF signal analysis, SDR, GNU Radio, DTMF, FSK, ASK, PSK, spectrum analysis
- [ai-llm-challenges.md](ai-llm-challenges.md) - LLM prompt injection, jailbreaks, token manipulation, model extraction
- [shapesofyou-lessons.md](shapesofyou-lessons.md) - ASCII art encoding anti-patterns (whitespace blindness, detection order, geometric validation)
- [ANTI_PATTERN_ENCODING.md](ANTI_PATTERN_ENCODING.md) - Quick reference card for encoding challenge traps
- [rf-sdr.md](rf-sdr.md) - RF/SDR/IQ signal processing (QAM-16, carrier recovery, timing sync)
- [dns.md](dns.md) - DNS exploitation (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling)
- [ctfd-navigation.md](ctfd-navigation.md) - Upstream CTFd workflow/navigation optimization notes
- [games-and-vms.md](games-and-vms.md) - WASM patching, Roblox place file reversing, PyInstaller, marshal, Python env RCE, Z3, K8s RBAC, floating-point precision exploitation, multi-phase crypto games with HMAC commitment-reveal and GF(256) Nim, custom assembly language sandbox escape via Python MRO chain

## Router & Benchmark (Fast Triage)

```bash
# Route from artifact JSON
python3 solve_misc.py --input-json challenge_artifacts.misc.template.json --json

# Benchmark routing quality
python3 solve_misc.py --benchmark-mode --json

# CI/checklist strict mode
python3 solve_misc.py --benchmark-mode --strict-benchmark --pass-threshold 0.95 --json
```

Core tracks:
- `programming-algorithmic`
- `pyjail`
- `bashjail`
- `encodings`
- `esolang`
- `qr-barcode`
- `audio-video-signal`
- `rf-sdr`
- `dns-exploitation`

## MCP Priority (Programming-focused)

- Default primary: `[MCP: ctf-solve]` for one-shot parsing, quick scripts, deterministic transforms
- Interactive/jail/long loop: switch primary to `[MCP: pentest-mcp]` for persistent session control
- Artifact-heavy media/signal: add `[MCP: ctf-forensics]` as supplemental
- Cross-over to VM/reverse internals: pivot to `[MCP: ctf-reverse]`

Hybrid default policy:
- Start with `ctf-solve` during triage
- Switch to `pentest-mcp` as soon as exploit/interactive phase becomes continuous
- Keep `pentest-mcp` as primary until stateful interaction is finished
- Use `ctf-solve` again only for one-shot final transforms/reporting

Do NOT use all MCPs simultaneously. Use trigger-based routing from artifact evidence.

## Speed + Continuity Rules (Programming/Jail)

1. Parse constraints first, choose complexity budget (`O(n)`, `O(n log n)`, etc.)
2. Use fast I/O template (`sys.stdin.readline`) by default
3. For interactive prompts, keep persistent session and read output in chunks
4. Stress test optimized solver against brute/reference before final answer
5. If exact same error repeats 3 times, pivot approach immediately

Detailed runbook: [MISC_PROGRAMMING_PLAYBOOK.md](MISC_PROGRAMMING_PLAYBOOK.md)

## External Best-Practice Anchors

- CP-Algorithms (algorithm coverage and implementation references)
- KACTL (stress-test + CI confidence model)
- USACO Guide Fast I/O (readline/write performance pattern)

---

## General Tips

- Read all provided files carefully
- Check file metadata, hidden content, encoding
- Power Automate scripts may hide API calls
- Use binary search when guessing multiple answers

## Common Encodings

```bash
# Base64
echo "encoded" | base64 -d

# Base32 (A-Z2-7=)
echo "OBUWG32D..." | base32 -d

# Hex
echo "68656c6c6f" | xxd -r -p

# ROT13
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**Identify by charset:**
- Base64: `A-Za-z0-9+/=`
- Base32: `A-Z2-7=` (no lowercase)
- Hex: `0-9a-fA-F`

See [encodings.md](encodings.md) for Caesar brute force, URL encoding, and full details.

## IEEE-754 Float Encoding (Data Hiding)

**Pattern (Floating):** Numbers are float32 values hiding raw bytes.

**Key insight:** A 32-bit float is just 4 bytes interpreted as a number. Reinterpret as raw bytes -> ASCII.

```python
import struct
floats = [1.234e5, -3.456e-7, ...]  # Whatever the challenge gives
flag = b''
for f in floats:
    flag += struct.pack('>f', f)
print(flag.decode())
```

**Variations:** Double `'>d'`, little-endian `'<f'`, mixed. See [encodings.md](encodings.md) for CyberChef recipe.

## USB Mouse PCAP Reconstruction

**Pattern (Hunt and Peck):** USB HID mouse traffic captures on-screen keyboard typing. Use USB-Mouse-Pcap-Visualizer, extract click coordinates (falling edges), cumsum relative deltas for absolute positions, overlay on OSK image.

## File Type Detection

```bash
file unknown_file
xxd unknown_file | head
binwalk unknown_file
```

## Archive Extraction

```bash
7z x archive.7z           # Universal
tar -xzf archive.tar.gz   # Gzip
tar -xjf archive.tar.bz2  # Bzip2
tar -xJf archive.tar.xz   # XZ
```

### Nested Archive Script
```bash
while f=$(ls *.tar* *.gz *.bz2 *.xz *.zip *.7z 2>/dev/null|head -1) && [ -n "$f" ]; do
    7z x -y "$f" && rm "$f"
done
```

## QR Codes

```bash
zbarimg qrcode.png       # Decode
qrencode -o out.png "data"
```

See [encodings.md](encodings.md) for QR structure, repair techniques, and chunk reassembly.

## Audio Challenges

```bash
sox audio.wav -n spectrogram  # Visual data
qsstv                          # SSTV decoder
```

## RF / SDR / IQ Signal Processing

See [rf-sdr.md](rf-sdr.md) for full details (IQ formats, QAM-16 demod, carrier/timing recovery).

**Quick reference:**
- **cf32**: `np.fromfile(path, dtype=np.complex64)` | **cs16**: int16 reshape(-1,2) | **cu8**: RTL-SDR raw
- Circles in constellation = constant frequency offset; Spirals = drifting frequency + gain instability
- 4-fold ambiguity in DD carrier recovery - try 0/90/180/270 rotation

## pwntools Interaction

```python
from pwn import *

r = remote('host', port)
r.recvuntil(b'prompt: ')
r.sendline(b'answer')
r.interactive()
```

## Python Jail Quick Reference

- **Oracle pattern:** `L()` = length, `Q(i,x)` = compare, `S(guess)` = submit. Linear or binary search.
- **Walrus bypass:** `(abcdef := "new_chars")` reassigns constraint vars
- **Decorator bypass:** `@__import__` + `@func.__class__.__dict__[__name__.__name__].__get__` for no-call, no-quotes escape
- **String join:** `open(''.join(['fl','ag.txt'])).read()` when `+` is blocked

See [pyjails.md](pyjails.md) for full techniques.

## Z3 / Constraint Solving

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
# Add constraints, check sat, extract model
```

See [games-and-vms.md](games-and-vms.md) for YARA rules, type systems as constraints.

## Hash Identification

MD5: `0x67452301` | SHA-256: `0x6a09e667` | MurmurHash64A: `0xC6A4A7935BD1E995`

## SHA-256 Length Extension Attack

MAC = `SHA-256(SECRET || msg)` with known msg/hash -> forge valid MAC via `hlextend`. Vulnerable: SHA-256, MD5, SHA-1. NOT: HMAC, SHA-3.

```python
import hlextend
sha = hlextend.new('sha256')
new_data = sha.extend(b'extension', b'original_message', len_secret, known_hash_hex)
```

## Technique Quick References

<!-- Missing file: - **PyInstaller:** `pyinstxtractor.py packed.exe`. See [games-and-vms.md](games-and-vms.md) for opcode remapping. -->
- **Marshal:** `marshal.load(f)` then `dis.dis(code)`. See [games-and-vms.md](games-and-vms.md).
- **Python env RCE:** `PYTHONWARNINGS=ignore::antigravity.Foo::0` + `BROWSER="cmd"`. See [games-and-vms.md](games-and-vms.md).
- **WASM patching:** `wasm2wat` -> flip minimax -> `wat2wasm`. See [games-and-vms.md](games-and-vms.md).
- **Float precision:** Large multipliers amplify FP errors into exploitable fractions. See [games-and-vms.md](games-and-vms.md).
- **K8s RBAC bypass:** SA token -> impersonate -> hostPath mount -> read secrets. See [games-and-vms.md](games-and-vms.md).

## 3D Printer Video Nozzle Tracking (LACTF 2026)

**Pattern (flag-irl):** Video of 3D printer fabricating nameplate. Flag is the printed text.

**Technique:** Track nozzle X/Y positions from video frames, filter for print moves (top/text layer only), plot 2D histogram to reveal letter shapes:
```python
# 1. Identify text layer frames (e.g., frames 26100-28350)
# 2. Track print head X position (physical X-axis)
# 3. Track bed X position (physical Y-axis from camera angle)
# 4. Filter for moves with extrusion (head moving while printing)
# 5. Plot as 2D scatter/histogram -> letters appear
```

## Discord API Enumeration (0xFun 2026)

Flags hidden in Discord metadata (roles, animated emoji, embeds). Invoke `/ctf-osint` and see [ctf-osint social-media.md](../ctf-osint/social-media.md) for Discord API enumeration technique and code.

---

## SUID Binary Exploitation (0xFun 2026)

```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Cross-reference with GTFObins
# xxd with SUID: xxd flag.txt | xxd -r
# vim with SUID: vim -c ':!cat /flag.txt'
```

**Reference:** https://gtfobins.github.io/

---

## Linux Privilege Escalation Quick Checks

```bash
# GECOS field passwords
cat /etc/passwd  # Check 5th colon-separated field

# ACL permissions
getfacl /path/to/restricted/file

# Sudo permissions
sudo -l
```

---

## Useful One-Liners

```bash
grep -rn "flag{" .
strings file | grep -i flag
python3 -c "print(int('deadbeef', 16))"
```

## Keyboard Shift Cipher

**Pattern (Frenzy):** Characters shifted left/right on QWERTY keyboard layout.

**Identification:** dCode Cipher Identifier suggests "Keyboard Shift Cipher"

**Decoding:** Use [dCode Keyboard Shift Cipher](https://www.dcode.fr/keyboard-shift-cipher) with automatic mode.

## Pigpen / Masonic Cipher

**Pattern (Working For Peanuts):** Geometric symbols representing letters based on grid positions.

**Identification:** Angular/geometric symbols, challenge references "Peanuts" comic (Charlie Brown), "dusty looking crypto"

**Decoding:** Map symbols to Pigpen grid positions, or use online decoder.

## ASCII in Numeric Data Columns

**Pattern (Cooked Books):** CSV/spreadsheet numeric values (48-126) are ASCII character codes.

```python
import csv
with open('data.csv') as f:
    reader = csv.DictReader(f)
    flag = ''.join(chr(int(row['Times Borrowed'])) for row in reader)
print(flag)
```

**CyberChef:** "From Decimal" recipe with line feed delimiter.

## Backdoor Detection in Source Code

**Pattern (Rear Hatch):** Hidden command prefix triggers `system()` call.

**Common patterns:**
- `strncmp(input, "exec:", 5)` -> runs `system(input + 5)`
- Hex-encoded comparison strings: `\x65\x78\x65\x63\x3a` = "exec:"
- Hidden conditions in maintenance/admin functions

## DNS Exploitation Techniques

See [dns.md](dns.md) for full details (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling).

**Quick reference:**
- **ECS spoofing**: `dig @server flag.example.com TXT +subnet=10.13.37.1/24` - try leet-speak IPs (1337)
- **NSEC walking**: Follow NSEC chain to enumerate DNSSEC zones
- **IXFR**: `dig @server domain IXFR=0` when AXFR is blocked
- **DNS rebinding**: Low-TTL alternating resolution to bypass same-origin
- **DNS tunneling**: Data exfiltrated via subdomain queries or TXT responses

## Unicode Steganography

### Variation Selectors Supplement (U+E0100-U+E01EF)
**Patterns (Seen & emoji, Nullcon 2026):** Invisible Variation Selector Supplement characters encode ASCII via codepoint offset.

```python
# Extract hidden data from variation selectors after visible character
data = open('README.md', 'r').read().strip()
hidden = data[1:]  # Skip visible emoji character
flag = ''.join(chr((ord(c) - 0xE0100) + 16) for c in hidden)
```

**Detection:** Characters appear invisible but have non-zero length. Check with `[hex(ord(c)) for c in text]` -- look for codepoints in `0xE0100-0xE01EF` or `0xFE00-0xFE0F` range.

## UTF-16 Endianness Reversal

**Pattern (endians):** Text "turned to Japanese" -- mojibake from UTF-16 endianness mismatch.

```python
# If encoded as UTF-16-LE but decoded as UTF-16-BE:
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')
```

**Identification:** CJK characters, challenge mentions "translation" or "endian". See [encodings.md](encodings.md) for details.

## Cipher Identification Workflow

1. **ROT13** - Challenge mentions "ROT", text looks like garbled English
2. **Base64** - `A-Za-z0-9+/=`, title hints "64"
3. **Base32** - `A-Z2-7=` uppercase only
4. **Atbash** - Title hints (Abash/Atbash), preserves spaces, 1:1 substitution
5. **Pigpen** - Geometric symbols on grid
6. **Keyboard Shift** - Text looks like adjacent keys pressed
7. **Substitution** - Frequency analysis applicable

**Auto-identify:** [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)


---

# [Appended from ctf-arsenal: misc-tools]

# Miscellaneous CTF Tools

## When to Use

Load this skill when:
- Solving programming or algorithm challenges
- Decoding esoteric languages (Brainfuck, Malbolge, etc.)
- Scanning QR codes or barcodes
- Analyzing audio/video files
- Working with unconventional challenge types

## Programming Challenges

### Fast Input Parsing

```python
#!/usr/bin/env python3
"""Template for fast I/O in programming challenges"""
import sys

def fast_input():
    """Read all input at once (faster than input())"""
    return sys.stdin.read().strip().split('\n')

def solve():
    """Main solution"""
    lines = fast_input()
    n = int(lines[0])
    
    for i in range(1, n + 1):
        # Process each line
        data = list(map(int, lines[i].split()))
        result = process(data)
        print(result)

def process(data):
    """Process logic here"""
    return sum(data)

if __name__ == "__main__":
    solve()
```

### Common Algorithms

```python
# Binary Search
def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1

# GCD (Greatest Common Divisor)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# LCM (Least Common Multiple)
def lcm(a, b):
    return abs(a * b) // gcd(a, b)

# Prime Check
def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

# Factorial with memoization
from functools import lru_cache

@lru_cache(maxsize=None)
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
```

## Esoteric Languages

### Brainfuck Interpreter

```python
#!/usr/bin/env python3
"""Brainfuck interpreter"""

def brainfuck(code, input_data=""):
    """Execute Brainfuck code"""
    # Initialize
    tape = [0] * 30000
    ptr = 0
    code_ptr = 0
    output = []
    input_ptr = 0
    
    # Match brackets
    brackets = {}
    stack = []
    for i, cmd in enumerate(code):
        if cmd == '[':
            stack.append(i)
        elif cmd == ']':
            if stack:
                left = stack.pop()
                brackets[left] = i
                brackets[i] = left
    
    # Execute
    while code_ptr < len(code):
        cmd = code[code_ptr]
        
        if cmd == '>':
            ptr += 1
        elif cmd == '<':
            ptr -= 1
        elif cmd == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            output.append(chr(tape[ptr]))
        elif cmd == ',':
            if input_ptr < len(input_data):
                tape[ptr] = ord(input_data[input_ptr])
                input_ptr += 1
        elif cmd == '[':
            if tape[ptr] == 0:
                code_ptr = brackets[code_ptr]
        elif cmd == ']':
            if tape[ptr] != 0:
                code_ptr = brackets[code_ptr]
        
        code_ptr += 1
    
    return ''.join(output)

# Example
code = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
print(brainfuck(code))  # Output: "Hello World!\n"
```

### Common Esoteric Language Patterns

| Language | Detection | Tool |
|----------|-----------|------|
| **Brainfuck** | `+-<>[].,` characters only | `esolang/bf_decode.py` |
| **Malbolge** | Base-85 printable ASCII | Online interpreter |
| **Whitespace** | Only spaces, tabs, newlines | Online interpreter |
| **JSFuck** | `[]()!+` characters only | Browser console |
| **Ook!** | `Ook. Ook? Ook!` | Online interpreter |
| **Piet** | Colorful bitmap image | npiet compiler |

### Online Interpreters

```bash
# Try44 - Multi-language online interpreter
https://tio.run/

# Esoteric.codes
https://esoteric.codes/
```

## QR Codes and Barcodes

### Scan QR Codes

```bash
# Install zbar tools
sudo apt install zbar-tools

# Scan single QR code
zbarimg qrcode.png

# Scan multiple QR codes
zbarimg qr1.png qr2.png qr3.png

# Output to file
zbarimg qrcode.png > output.txt
```

### Scan All QR Codes in Directory

```bash
#!/bin/bash
# Scan all images in directory for QR/barcodes

for file in *.png *.jpg *.jpeg; do
    if [ -f "$file" ]; then
        echo "=== $file ==="
        zbarimg "$file" 2>/dev/null || echo "No code found"
        echo
    fi
done
```

### Generate QR Code

```bash
# Install qrencode
sudo apt install qrencode

# Generate QR code
qrencode -o output.png "Your text here"

# Generate with error correction
qrencode -l H -o output.png "Your text here"
# Levels: L (7%), M (15%), Q (25%), H (30%)
```

### Python QR Code

```python
from PIL import Image
import subprocess

def scan_qr(image_path):
    """Scan QR code from image"""
    result = subprocess.run(
        ['zbarimg', '--quiet', '--raw', image_path],
        capture_output=True, text=True
    )
    return result.stdout.strip()

# Usage
data = scan_qr('qrcode.png')
print(f"QR Code data: {data}")
```

## Audio and Video Analysis

### Audio Spectrogram

```bash
# Generate spectrogram with Sox
sox audio.wav -n spectrogram -o spectrogram.png

# With higher resolution
sox audio.wav -n spectrogram -x 3000 -y 513 -z 120 -w Kaiser -o spectrogram.png

# Extract specific frequency range
sox audio.wav -n spectrogram -o spec.png trim 0 10  # First 10 seconds
```

### Audio Metadata

```bash
# Extract metadata
exiftool audio.mp3
ffprobe audio.mp3

# Extract hidden data from LSB
python3 helpers/audio_lsb.py audio.wav
```

### Video Frame Extraction

```bash
# Extract all frames
ffmpeg -i video.mp4 frames/frame_%04d.png

# Extract every 10th frame
ffmpeg -i video.mp4 -vf "select='not(mod(n\,10))'" -vsync 0 frames/frame_%04d.png

# Extract frame at specific time
ffmpeg -i video.mp4 -ss 00:01:30 -vframes 1 frame.png
```

### DTMF Tone Decoding

```bash
# Install multimon-ng
sudo apt install multimon-ng

# Decode DTMF tones from audio
sox audio.wav -t raw -r 22050 -e signed -b 16 -c 1 - | multimon-ng -t raw -a DTMF /dev/stdin
```

## Encoding and Decoding

### Common Encodings

```python
import base64
import codecs

# Base64
data = base64.b64decode('SGVsbG8gV29ybGQ=')

# Base32
data = base64.b32decode('JBSWY3DPEBLW64TMMQ======')

# Base85
data = base64.b85decode(b'BOu!rD]j7BEbo7')

# Hex
data = bytes.fromhex('48656c6c6f')

# ROT13
data = codecs.decode('Uryyb Jbeyq', 'rot_13')

# URL encoding
from urllib.parse import unquote
data = unquote('Hello%20World')
```

### Multi-Layer Decoding

```python
def auto_decode(data):
    """Try common decodings recursively"""
    import base64
    import binascii
    
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except:
            return data
    
    # Try base64
    try:
        decoded = base64.b64decode(data)
        if decoded != data.encode():
            print("[+] Base64 decoded")
            return auto_decode(decoded)
    except:
        pass
    
    # Try hex
    try:
        decoded = bytes.fromhex(data)
        print("[+] Hex decoded")
        return auto_decode(decoded)
    except:
        pass
    
    return data

# Usage
result = auto_decode("NGE2MTY3N2I2MjYxNzM2NTM2MzQ1Zjc0Njg2OTcyNzQ3OTVmNzQ3Nzc2")
print(result)
```

## Quick Reference

| Challenge Type | Tool | Command |
|----------------|------|---------|
| **Brainfuck** | Python | `python3 esolang/bf_decode.py code.bf` |
| **QR Code** | zbar | `zbarimg qrcode.png` |
| **Barcode** | zbar | `zbarimg barcode.jpg` |
| **Spectrogram** | sox | `sox audio.wav -n spectrogram -o spec.png` |
| **DTMF** | multimon-ng | `multimon-ng -a DTMF audio.wav` |
| **Video frames** | ffmpeg | `ffmpeg -i video.mp4 frames/frame_%04d.png` |
| **Base64** | base64 | `base64 -d <<< "SGVsbG8="` |
| **Hex** | xxd | `xxd -r -p hex.txt output.bin` |

## Bundled Resources

### Programming

- `programming/fast_parse.py` - Fast I/O template for competitive programming
- `programming/algorithms.py` - Common algorithms (GCD, LCM, primes)

### Esoteric Languages

- `esolang/bf_decode.py` - Brainfuck interpreter
<!-- Missing file: - `esolang/malbolge_helper.md` - Malbolge reference -->

### QR and Barcodes

- `qr_barcodes/qr_scan_all.sh` - Batch QR code scanner
<!-- Missing file: - `qr_barcodes/qr_generate.sh` - QR code generator wrapper -->

### Audio and Video

- `audio_video/spectrogram.sh` - Generate audio spectrogram
<!-- Missing file: - `audio_video/extract_frames.sh` - Extract video frames -->
<!-- Missing file: - `audio_video/audio_lsb.py` - Audio LSB steganography -->

## External Tools

```bash
# Esoteric language interpreters
pip install bf  # Brainfuck

# QR/Barcode tools
sudo apt install zbar-tools qrencode

# Audio/Video tools
sudo apt install sox ffmpeg multimon-ng audacity

# Python libraries
pip install qrcode pillow pydub
```

## Keywords

miscellaneous, misc, programming, algorithms, esoteric languages, brainfuck, esolang, QR code, barcode, zbar, audio analysis, spectrogram, DTMF, video analysis, frame extraction, ffmpeg, sox, encoding, decoding, base64, hex, multi-layer decoding, competitive programming

---



