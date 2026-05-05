---
name: ctf-forensics
description: Digital forensics and signal analysis for CTF challenges. Use when analyzing disk images, memory dumps, event logs, network captures, cryptocurrency transactions, steganography, PDF analysis, Windows registry, Volatility, PCAP, Docker images, coredumps, side-channel power traces, DTMF audio spectrograms, packet timing analysis, or recovering deleted files and credentials.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [magic-bytes-reference.md](magic-bytes-reference.md) - **CRITICAL:** Magic bytes / file signature reference for anti-spoofing (Rule 0 enforcement)
- [visual-artifact-checklist.md](visual-artifact-checklist.md) - **CRITICAL:** Visual artifact extraction protocol (OCR, QR decode, archive handling, human handoff for images/PDFs)
- [FORENSICS_BENCHMARK_CASES.json](FORENSICS_BENCHMARK_CASES.json) - Routing benchmark cases for rapid triage quality checks
- [solve_forensics.py](solve_forensics.py) - Auto track router (`--input-json`) and one-shot benchmark (`--benchmark-mode`)
- [3d-printing.md](3d-printing.md) - 3D printing forensics (PrusaSlicer binary G-code, QOIF, heatshrink)
- [windows.md](windows.md) - Windows forensics (registry, SAM, event logs, recycle bin, USN journal, PowerShell history, Defender MPLog, WMI persistence, Amcache)
- [network.md](network.md) - Network forensics (PCAP, SMB3, WordPress, credentials, NTLMv2 cracking, USB HID steno, USB HID mouse/pen drawing recovery, BCD encoding, HTTP file upload exfiltration, packet interval timing encoding)
- [disk-and-memory.md](disk-and-memory.md) - Disk/memory forensics (Volatility, disk mounting/carving, VM/OVA/VMDK, coredumps, deleted partitions, ZFS, VMware snapshots, ransomware analysis, GPT GUID encoding, VMDK sparse parsing)
- [disk-advanced.md](disk-advanced.md) - Advanced disk forensics techniques
- [steganography.md](steganography.md) - Steganography (binary border stego, PDF multi-layer stego, FFT frequency domain, DTMF audio, SSTV+LSB, SVG keyframes, PNG reorder, file overlays, JPEG unused DQT table LSB, custom frequency dual-tone keypad, multi-track audio differential subtraction)
- [stego-advanced-2.md](stego-advanced-2.md) - Upstream advanced stego continuation reference
- [stego-image.md](stego-image.md) - Upstream image-focused steganography reference
- [linux-forensics.md](linux-forensics.md) - Linux/app forensics (log analysis, Docker image forensics, attack chains, browser credentials, Firefox history, TFTP, TLS weak RSA, USB audio, Git directory recovery)
- [signals-and-hardware.md](signals-and-hardware.md) - Hardware signal decoding with decode code (VGA frame parsing, HDMI TMDS symbol decode, DisplayPort 8b/10b + LFSR descrambler), Voyager Golden Record audio, Saleae Logic 2 UART decode, Flipper Zero .sub files, side-channel power analysis (DPA)
- [peripheral-capture.md](peripheral-capture.md) - Upstream peripheral capture and extraction notes

---

## Router & Benchmark (Fast Triage)

```bash
# Auto-select forensics track from artifact JSON
python3 solve_forensics.py --input-json challenge_artifacts.json --json

# If artifact JSON is a list, infer all in one run
python3 solve_forensics.py --input-json FORENSICS_BENCHMARK_CASES.json --json

# One-shot benchmark validation
python3 solve_forensics.py --benchmark-mode --json
```

This helps enforce deterministic triage routing before deep analysis.

---

## Quick Start Commands

```bash
# File analysis (ALWAYS check type first)
file suspicious_file

# Based on file type:
# - Text: cat, grep
# - Image: tesseract (OCR), zbarimg (QR)
# - PDF: pdftotext, exiftool
# - Archive: unzip -l, 7z l (list before extract)
# - Office: unzip -l (DOCX/XLSX are ZIP)

exiftool suspicious_file     # Metadata
binwalk suspicious_file      # Embedded files
strings -n 8 suspicious_file
hexdump -C suspicious_file | head  # Check magic bytes

# Archive handling (if file shows ZIP/RAR/7z)
unzip -l suspicious_file.zip     # List contents
7z l suspicious_file.7z          # List contents
tar -tzf suspicious_file.tar.gz  # List contents

# Disk forensics
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd              # List files
photorec image.dd            # Carve deleted files

# Memory forensics (Volatility 3)
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.filescan
```

See [disk-and-memory.md](disk-and-memory.md) for full Volatility plugin reference, VM forensics, and coredump analysis.

## Log Analysis

```bash
grep -iE "(flag|part|piece|fragment)" server.log     # Flag fragments
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'  # Reconstruct
sort logfile.log | uniq -c | sort -rn | head         # Find anomalies
```

See [linux-forensics.md](linux-forensics.md) for Linux attack chain analysis and Docker image forensics.

## Windows Event Logs (.evtx)

**Key Event IDs:**
- 1001 - Bugcheck/reboot
- 1102 - Audit log cleared
- 4720 - User account created
- 4781 - Account renamed

**RDP Session IDs (TerminalServices-LocalSessionManager):**
- 21 - Session logon succeeded
- 24 - Session disconnected
- 1149 - RDP auth succeeded (RemoteConnectionManager, has source IP)

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

See [windows.md](windows.md) for full event ID tables, registry analysis, SAM parsing, USN journal, and anti-forensics detection.

## When Logs Are Cleared

If attacker cleared event logs, use these alternative sources:
1. **USN Journal ($J)** - File operations timeline (MFT ref, timestamps, reasons)
2. **SAM registry** - Account creation from key last_modified timestamps
3. **PowerShell history** - ConsoleHost_history.txt (USN DATA_EXTEND = command timing)
4. **Defender MPLog** - Separate log with threat detections and ASR events
5. **Prefetch** - Program execution evidence
6. **User profile creation** - First login time (profile dir in USN journal)

See [windows.md](windows.md) for detailed parsing code and anti-forensics detection checklist.

## Steganography

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP analysis
stegsolve                    # Visual analysis
```

- **Binary border stego:** Black/white pixels in 1px image border encode bits clockwise
- **FFT frequency domain:** Image data hidden in 2D FFT magnitude spectrum; try `np.fft.fft2` visualization
- **DTMF audio:** Phone tones encoding data; decode with `multimon-ng -a DTMF`
- **Multi-layer PDF:** Check hidden comments, post-EOF data, XOR with keywords, ROT18 final layer
- **SSTV + LSB:** SSTV signal may be red herring; check 2-bit LSB of audio samples with `stegolsb`
- **SVG keyframes:** Animation `keyTimes`/`values` attributes encode binary/Morse via fill color alternation
- **PNG chunk reorder:** Fix chunk order: IHDR → ancillary → IDAT (in order) → IEND
- **File overlays:** Check after IEND for appended archives with overwritten magic bytes

- **Custom freq DTMF:** Non-standard dual-tone frequencies; generate spectrogram first (`ffmpeg -i audio -lavfi showspectrumpic`), map custom grid to keypad digits, decode variable-length ASCII
- **JPEG DQT LSB:** Unused quantization tables (ID 2, 3) carry LSB-encoded data; access via `Image.open().quantization` and extract bit 0 from each of 64 values
- **Multi-track audio subtraction:** Two nearly-identical audio tracks in MKV/video; `sox -m a0.wav "|sox a1.wav -p vol -1" diff.wav` cancels shared content, flag appears in spectrogram of difference signal (5-12 kHz band)
- **Packet interval timing:** Identical packets with two distinct interval values (e.g., 10ms/100ms) encode binary; filter by interface, compute inter-packet deltas, threshold to bits

See [steganography.md](steganography.md) for full code examples and decoding workflows.

## PDF Analysis

```bash
exiftool document.pdf        # Metadata (often hides flags!)
pdftotext document.pdf -     # Extract text
strings document.pdf | grep -i flag
binwalk document.pdf         # Embedded files
```

**Advanced PDF stego (Nullcon 2026 rdctd):** Six techniques -- invisible text separators, URI annotations with escaped braces, Wiener deconvolution on blurred images, vector rectangle QR codes, compressed object streams (`mutool clean -d`), document metadata fields.

See [steganography.md](steganography.md) for full PDF steganography techniques and code.

## 🚨 MULTIMEDIA, VISUAL & ARCHIVE HANDOFF PROTOCOL

**Trigger:** Whenever a file is extracted/dumped from memory or disk.

---

### Rule 0: TRUE FILE TYPE VERIFICATION (ANTI-SPOOFING) - ⚠️ CRITICAL

**NEVER trust the file extension.** CTF challenges frequently spoof extensions (e.g., hiding a .zip inside a .jpg name).

**MANDATORY FIRST STEP:** You MUST run `file <filename>` on EVERY extracted artifact to read its true Magic Bytes / File Signature.

```bash
# ALWAYS run this FIRST
file <extracted_file>
```

**Data Fallback:** If `file <filename>` returns only "data" (unknown), immediately run:

```bash
# Inspect raw magic bytes
xxd <filename> | head -n 5
# OR
hexdump -C <filename> | head -n 5
```

Then pivot your strategy based on those bytes.

**Common Magic Bytes Reference:**

| Magic Bytes (Hex) | File Type | Extension |
|-------------------|-----------|----------|
| `50 4B 03 04` | ZIP archive | `.zip`, `.docx`, `.xlsx` |
| `89 50 4E 47` | PNG image | `.png` |
| `FF D8 FF` | JPEG image | `.jpg`, `.jpeg` |
| `47 49 46 38` | GIF image | `.gif` |
| `25 50 44 46` | PDF document | `.pdf` |
| `52 49 46 46` | RIFF container | `.wav`, `.avi` |
| `49 44 33` | MP3 audio | `.mp3` |
| `00 00 00 18 66 74 79 70` | MP4 video | `.mp4` |
| `1F 8B 08` | GZIP compressed | `.gz` |
| `52 61 72 21` | RAR archive | `.rar` |
| `37 7A BC AF 27 1C` | 7-Zip archive | `.7z` |

---

### Rule 1: STRICTLY PROHIBITED ACTIONS

**DO NOT route tools based on the file name or extension. ALWAYS route based on the output of Rule 0.**

**DO NOT:**
- ❌ Route tools based on file name/extension (ALWAYS use Rule 0 output)
- ❌ Run `cat` on non-text files (will cause context overflow with gibberish)
- ❌ Attempt to guess visual content or transcribe audio without using dedicated tools
- ❌ Extract archives blindly without listing their contents first

---

### Rule 2: AUTOMATED TRIAGE (AI Phase)

Before asking the human, run rapid automated checks based on file type to see if the flag is easily accessible:

#### 📷 For Images (PNG, JPG, BMP, GIF)

```bash
# Metadata
exiftool <file> | grep -iE "flag|coc2026|secret"

# Steganography
zsteg -a <file> | grep -iE "flag|coc2026"

# QR/Barcode
zbarimg <file>

# OCR (Text in image)
tesseract <file> stdout | grep -iE "flag|coc2026"
```

#### 🎵 For Audio (WAV, MP3, OGG)

```bash
# Metadata
exiftool <file>

# Hidden Files
binwalk -e <file>

# Embedded Strings
strings -n 10 <file> | grep -iE "flag|coc2026"

# Spectrogram analysis (if tools available)
# sox <file> -n spectrogram -o spectrogram.png
```

#### 🎬 For Video (MP4, MKV, AVI)

```bash
# Metadata
exiftool <file>

# Extract frames (if ffmpeg available)
# ffmpeg -i <file> -vf fps=1 frame_%04d.png

# Extract audio track
# ffmpeg -i <file> -vn -acodec copy audio.mp3

# Embedded strings
strings -n 10 <file> | grep -iE "flag|coc2026"
```

#### 📄 For Documents (PDF)

```bash
# Text extraction
pdftotext <file> - | grep -iE "flag|coc2026"

# Metadata
exiftool <file> | grep -iE "flag|coc2026"

# Hidden embedded files
binwalk <file>
```

#### 📦 For Archives (ZIP, 7z, RAR, DOCX, unknown .dat)

```bash
# List contents first
unzip -l <file>      # For ZIP/DOCX
7z l <file>          # For 7z/RAR
tar -tzf <file>      # For TAR.GZ

# Extract safely
mkdir /tmp/ext_$$
unzip <file> -d /tmp/ext_$$ 2>/dev/null || 7z x <file> -o/tmp/ext_$$ -y

# Recursive search
grep -r -iE "coc2026|flag" /tmp/ext_$$

# Cleanup
rm -rf /tmp/ext_$$
```

#### 📝 For Text/ASCII

```bash
# Safe to read directly
cat <file> | grep -iE "coc2026|flag"
```

---

### Rule 3: HUMAN HANDOFF (Critical Pause)

**If the automated triage in Rule 2 does NOT yield the flag for Image, Audio, or Video files, you MUST pause execution for this specific file and alert the user EXACTLY in this format:**

```
[🚨 MEDIA ARTIFACT EXTRACTED]
- Type: <Image/Audio/Video>
- Path: <absolute_path_to_file>
- AI Triage: <Brief result, e.g., "Exiftool clean, no QR detected, zsteg negative, OCR failed">

[👀 HUMAN ACTION REQUIRED]
Please open this file manually.
- If Image: Look for hidden text, color variations, or visual clues.
- If Audio: Check spectrogram (Audacity/Sonic Visualiser) or listen for Morse code/DTMF.
- If Video: Watch for hidden frames or audio tracks.

CRITICAL: Waiting for your input before proceeding with other tasks.
```

**DO NOT:**
- Continue to other files without user confirmation
- Discard the media file
- Assume the flag is not present

**DO:**
- Preserve the file path for user access
- Document all automated checks performed
- Wait for explicit user feedback

---

## Disk / VM / Memory Forensics

```bash
# Disk images
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd && photorec image.dd

# VM images (OVA/VMDK)
tar -xvf machine.ova
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r

# Memory (Volatility 3) - BEHAVIOR-FIRST APPROACH
# Step 1: Find suspicious behavior FIRST
vol3 -f memory.dmp windows.netscan     # Network connections (external IPs, unusual ports)
vol3 -f memory.dmp windows.malfind     # Injected code detection
vol3 -f memory.dmp windows.cmdline     # Command line arguments

# Step 2: Cross-reference to find suspicious PIDs
# Look for: external connections + suspicious commands + code injection

# Step 3: Target specific processes
vol3 -f memory.dmp windows.pslist --pid <suspicious_pid>
vol3 -f memory.dmp windows.memmap --pid <suspicious_pid> --dump
vol -f memory.dmp windows.dumpfiles --pid <suspicious_pid>

# String carving (TARGETED - not full dump)
strings -a -n 6 memdump.bin | grep -E "FLAG|SSH_CLIENT|SESSION_KEY"

# Coredump
gdb -c core.dump  # info registers, x/100x $rsp, find "flag"
```

### 🚨 Volatility 3 Linux Symbol Dependency (Offline Fallback)

**CRITICAL:** Volatility 3 requires Symbol Tables (ISF) for Linux memory analysis.

**Problem:** In isolated/offline networks, Vol3 cannot download symbols automatically.

**Solution:**
```bash
# Attempt Linux analysis
vol3 -f memory.dmp linux.pslist

# If error about symbols/ISF:
# ERROR: Unable to download symbols...

# Fallback 1: Use Volatility 2 (if available)
vol.py -f memory.dmp --profile=LinuxUbuntu1804x64 linux_pslist

# Fallback 2: Targeted string extraction
strings -a -n 8 memory.dmp | grep -E "bash|sh -c|python|flag|coc2026" > commands.txt
strings -a -n 8 memory.dmp | grep -E "/home|/tmp|/var" > paths.txt

# Fallback 3: Manual symbol generation (if kernel version known)
# See: https://github.com/volatilityfoundation/volatility3#symbol-tables
```

**Prevention:** Pre-download common Linux ISF files before competition.

See [disk-and-memory.md](disk-and-memory.md) for full Volatility plugin reference, VM forensics, VMware snapshots, deleted partition recovery, ZFS forensics, and ransomware analysis.

## Windows Password Hashes

```bash
# Extract with impacket, crack with hashcat -m 1000
python -c "from impacket.examples.secretsdump import *; SAMHashes('SAM', LocalOperations('SYSTEM').getBootKey()).dump()"
```

See [windows.md](windows.md) for SAM details and [network.md](network.md) for NTLMv2 cracking from PCAP.

## Bitcoin Tracing

- Use mempool.space API: `https://mempool.space/api/tx/<TXID>`
- **Peel chain:** ALWAYS follow LARGER output; round amounts indicate peels

## Uncommon File Magic Bytes

| Magic | Format | Extension | Notes |
|-------|--------|-----------|-------|
| `OggS` | Ogg container | `.ogg` | Audio/video |
| `RIFF` | RIFF container | `.wav`,`.avi` | Check subformat |
| `%PDF` | PDF | `.pdf` | Check metadata & embedded objects |
| `GCDE` | PrusaSlicer binary G-code | `.g`, `.bgcode` | See 3d-printing.md |

## Common Flag Locations

- PDF metadata fields (Author, Title, Keywords)
- Image EXIF data
- Deleted files (Recycle Bin `$R` files)
- Registry values
- Browser history
- Log file fragments
- Memory strings

## WMI Persistence Analysis

**Pattern (Backchimney):** Malware uses WMI event subscriptions for persistence (MITRE T1546.003).

```bash
python PyWMIPersistenceFinder.py OBJECTS.DATA
```

- Look for FilterToConsumerBindings with CommandLineEventConsumer
- Base64-encoded PowerShell in consumer commands
- Event filters triggered on system events (logon, timer)

See [windows.md](windows.md) for WMI repository analysis details.

## Network Forensics Quick Reference

- **TFTP netascii:** Binary transfers corrupted; fix with `data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')`
- **TLS weak RSA:** Extract cert, factor modulus, generate private key with `rsatool`, add to Wireshark
- **USB audio:** Extract isochronous data with `tshark -e usb.iso.data`, import as raw PCM in Audacity
- **NTLMv2 from PCAP:** Extract server challenge + NTProofStr + blob from NTLMSSP_AUTH, brute-force

See [network.md](network.md) for SMB3 decryption, credential extraction, and [linux-forensics.md](linux-forensics.md) for full TLS/TFTP/USB workflows.

## Browser Forensics

- **Chrome/Edge:** Decrypt `Login Data` SQLite with AES-GCM using DPAPI master key
- **Firefox:** Query `places.sqlite` -- `SELECT url FROM moz_places WHERE url LIKE '%flag%'`

See [linux-forensics.md](linux-forensics.md) for full browser credential decryption code.

## Additional Technique Quick References

- **Docker image forensics:** Config JSON preserves ALL `RUN` commands even after cleanup. `tar xf app.tar` then inspect config blob. See [linux-forensics.md](linux-forensics.md).
- **Linux attack chains:** Check `auth.log`, `.bash_history`, recent binaries, PCAP. See [linux-forensics.md](linux-forensics.md).
- **PowerShell ransomware:** Extract scripts from minidump, find AES key, decrypt SMTP attachment. See [disk-and-memory.md](disk-and-memory.md).
- **Linux ransomware + memory dump:** If Volatility is unreliable, recover AES key via raw-memory candidate scanning and magic-byte validation; re-extract zip cleanly to avoid missing files/false negatives. See [disk-and-memory.md](disk-and-memory.md).
- **Deleted partitions:** `testdisk` or `kpartx -av`. See [disk-and-memory.md](disk-and-memory.md).
- **ZFS forensics:** Reconstruct labels, Fletcher4 checksums, PBKDF2 cracking. See [disk-and-memory.md](disk-and-memory.md).
- **Hardware signals:** VGA/HDMI TMDS/DisplayPort, Voyager audio, Saleae UART decode, Flipper Zero. See [signals-and-hardware.md](signals-and-hardware.md).
- **USB HID mouse drawing:** Render relative HID movements per draw mode as bitmap; separate modes, skip pen lifts, scale 5-8x. See [network.md](network.md).
- **Side-channel power analysis:** Multi-dimensional power traces (positions × guesses × traces × samples). Average across traces, find sample with max variance, select guess with max power at leak point. See [signals-and-hardware.md](signals-and-hardware.md).
- **Packet interval timing:** Binary data encoded as inter-packet delays in PCAP. Two interval values = two bit values. See [network.md](network.md).
- **G-code visualization:** Side projections (XZ/YZ) reveal text. See [3d-printing.md](3d-printing.md).
<!-- Missing file: - **Git directory recovery:** `helpers/gitdumper.sh` for exposed `.git` dirs. See [linux-forensics.md](linux-forensics.md). -->

## HTTP Exfiltration in PCAP

**Quick path:** `tshark --export-objects http,/tmp/objects` extracts uploaded files instantly. Check for multipart POST uploads, unusual User-Agent strings, and exfiltrated files (images with flag text). See [network.md](network.md#http-file-upload-exfiltration-in-pcap-metactf-2026).

## Common Encodings

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**ROT18:** ROT13 on letters + ROT5 on digits. Common final layer in multi-stage forensics. See [linux-forensics.md](linux-forensics.md) for implementation.


---

## 🎯 God-Mode Tools (AI-Ready Scripts)

**CRITICAL:** These enhanced tools include automatic flag detection, JSON output for AI integration, and advanced obfuscation handling.

### Steganography Quick Check

```bash
# Quick triage (fast)
python3 steganography/steg_quickcheck.py image.png

# Deep scan (slow but thorough)
python3 steganography/steg_quickcheck.py image.png --deep

# AI mode (JSON output)
python3 steganography/steg_quickcheck.py image.png --json
```

**Features:**
- Auto flag extraction with God-Mode regex
- Steghide, Zsteg, Binwalk, Exiftool integration
- UTF-16LE string detection
- Stegoveritas deep scan (--deep mode)

### PCAP HTTP/DNS Extractor

```bash
# Extract HTTP objects and hunt flags
python3 network_forensics/pcap_extract_http.py capture.pcap

# Custom output directory
python3 network_forensics/pcap_extract_http.py capture.pcap --outdir /tmp/analysis

# AI mode (JSON output)
python3 network_forensics/pcap_extract_http.py capture.pcap --json
```

**Features:**
- DNS query extraction (detects DNS exfiltration)
- HTTP object export (files downloaded/uploaded)
- TCP stream reconstruction
- Auto flag scanning in all extracted artifacts

### Entropy Scanner

```bash
# Scan for encrypted/compressed regions
python3 helpers/entropy_scan.py suspicious.bin

# Custom block size and threshold
python3 helpers/entropy_scan.py suspicious.bin --block-size 512 --threshold 7.5

# AI mode (JSON output)
python3 helpers/entropy_scan.py suspicious.bin --json
```

**Features:**
- Block-level entropy analysis
- Magic byte detection at high-entropy offsets
- ASCII sparkline visualization
- Automatic file type hints (ZIP, RAR, PNG, PE, ELF)

---

## 🎯 Advanced Flag Hunting & Anti-Obfuscation (God-Mode)

**CRITICAL:** In forensics challenges, flags are rarely in plain text. They are often hex-encoded in memory, Base64-encoded in the registry, or byte-swapped in disk images. Use these pipelines when standard `grep` fails.

### 1. The God-Mode Regex (Global Monitor)

Always use this robust regex pattern to catch flags, hashes, and Leetspeak variations:
```regex
/(?:coc2026|flag|f1a9|fl4g|tiger|ctf|key)[\s_.:-]*\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i
```

### 2. Universal Payload Decoder Pipeline

If you extract suspicious Hex or Base64 from memory dumps (`volatility`), PCAP payloads, or file carving (`binwalk`), pipe it through these decoders:

**Hex Decoding (With Endianness Swapping):**
```bash
HEX_DATA="636f63323032367b..."

# 1. Standard ASCII
echo "$HEX_DATA" | xxd -r -p | grep -iE "coc2026|flag"

# 2. Byte-Swapped (Common in memory dumps & UTF-16)
echo "$HEX_DATA" | sed 's/\(.\)\(.\)/\2\1/g' | xxd -r -p | grep -iE "coc2026|flag"

# 3. Word-Swapped (Common in 32-bit architecture dumps)
echo "$HEX_DATA" | sed 's/\(.\{4\}\)\(.\{4\}\)/\2\1/g' | xxd -r -p | grep -iE "coc2026|flag"
```

**Base64 Decoding (With Sanitization):**
```bash
# Strip noise/newlines, fix padding, and decode
echo "$DIRTY_B64" | tr -dc 'A-Za-z0-9+/=' | base64 -d | grep -iE "coc2026|flag"
```

### 3. Deep String Carving (Memory & Disk Images)

Don't just use standard `strings`. Use these to catch Unicode and encoded flags:
```bash
# Find standard ASCII flags
strings -n 8 memory.dmp | grep -iE "(coc2026|flag|f1a9)"

# Find UTF-16LE flags (Windows Registry & Memory heavily use this)
strings -el memory.dmp | grep -iE "(coc2026|flag|f1a9)"

# Dump ALL hex strings (20+ chars) from a binary and auto-decode them
strings -n 20 suspicious.bin | grep -E "^[a-fA-F0-9]+$" | while read h; do echo "$h" | xxd -r -p; echo ""; done | grep -iE "coc2026|flag"
```

### 🤖 MCP Instruction for Forensics Flag Hunting:

> **ALWAYS** run `strings -el` (Little-Endian) in addition to standard `strings` when analyzing Windows artifacts (SAM, Registry, Memory Dumps). If a 32-character hex string is found, assume it is an MD5/NTLM hash and report it immediately. If a block of text looks like Base64 but fails to decode, apply the `tr -dc 'A-Za-z0-9+/='` sanitization before abandoning it.

---

## Quick Reference

| Task | Tool | Command |
|------|------|---------|
| **File carving** | binwalk | `binwalk -e file.bin` |
| **Strings** | strings | `strings -n 10 file.bin` |
| **Image LSB** | zsteg | `zsteg -a image.png` |
| **JPEG steg** | steghide | `steghide extract -sf image.jpg` |
| **Metadata** | exiftool | `exiftool image.jpg` |
| **PCAP HTTP** | tshark | `tshark -r file.pcap --export-objects http,out/` |
| **TCP stream** | tshark | `tshark -r file.pcap -z follow,tcp,ascii,0` |
| **Spectrogram** | sox | `sox audio.wav -n spectrogram -o spec.png` |
| **Entropy** | custom | `python3 helpers/entropy_scan.py file.bin` |

## Bundled God-Mode Tools

### Steganography

- `steganography/steg_quickcheck.py` - **God-Mode steg detector**
  - Auto flag extraction (God-Mode regex)
  - Steghide, Zsteg, Binwalk, Exiftool integration
  - UTF-16LE detection, Stegoveritas deep scan
  - JSON output for AI

### Network Forensics

- `network_forensics/pcap_extract_http.py` - **God-Mode PCAP extractor**
  - DNS query extraction (DNS exfiltration detection)
  - HTTP object export with flag scanning
  - TCP stream reconstruction
  - JSON output for AI

### Helpers

- `helpers/entropy_scan.py` - **God-Mode entropy scanner**
  - Block-level analysis with magic byte detection
  - ASCII sparkline visualization
  - High-entropy offset identification
  - JSON output for AI

## External Tools

```bash
# Install common forensics tools
sudo apt install binwalk foremost steghide exiftool

# Python tools
pip install pillow numpy scapy

# Specialized tools
# - StegSolve: https://github.com/zardus/ctf-tools (Java-based)
# - Audacity: https://www.audacityteam.org/ (audio analysis)
# - Wireshark: https://www.wireshark.org/ (PCAP GUI analysis)
```

## Keywords

forensics, digital forensics, file carving, binwalk, steganography, steg, LSB, least significant bit, PCAP, packet capture, network forensics, tshark, wireshark, entropy analysis, strings, metadata, exiftool, file signatures, magic bytes, audio steganography, spectrogram, image analysis, data extraction, hidden data

---

## Community Tools DFIR Extended References (Transilience AI)

Triggered consult — read when investigating Windows incidents, AD attacks, or network relay detection.

### DFIR (`ct-dfir/`)
| File | Use When |
|------|----------|
| `ct-dfir/windows-event-analysis.md` | EVTX parsing, Event ID correlation, AD attack chain detection (4624/4768/4769/7036) |
| `ct-dfir/network-forensics.md` | PCAP→NTLM hash extraction, LLMNR/NBT-NS poisoning detection, relay identification |
| `ct-dfir/filesystem-forensics.md` | MFT parsing, Prefetch analysis, VSS artifact recovery, timeline reconstruction |

**Quick Tool Reference (from DFIR skill):**
```bash
pip install python-evtx windowsprefetch analyzeMFT
# Parse EVTX
python3 -c "from evtx import PyEvtxParser; [print(r.xml()) for r in PyEvtxParser('Security.evtx')]"
# Extract NTLMv2 from PCAP
tshark -r capture.pcap -Y 'ntlmssp.auth.username' -T fields -e ntlmssp.auth.username -e ntlmssp.auth.nt
# MFT parse
analyzeMFT.py -f $MFT -o mft_output.csv
```

**Key Event IDs Quick Reference:**
| Event ID | Indicates |
|----------|-----------|
| 4624 | Successful logon |
| 4768 | TGT request (PreAuthType=0 → AS-REP roast) |
| 4769 | TGS request (EncType=0x17 → Kerberoast) |
| 7036 | Service state change (VSS start → NTDS dump) |
| 106/200 | Scheduled task created/executed |



