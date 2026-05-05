# MULTIMEDIA, VISUAL & ARCHIVE EXTRACTION CHECKLIST

## Problem Statement

In CTF forensics challenges, flags are often hidden in **multimedia and non-text formats** that cannot be extracted with simple `cat` or `strings`:
- Screenshots/images in memory dumps
- Audio spectrograms (DTMF, Morse code, SSTV)
- Video frames or audio tracks
- QR codes or barcodes in documents
- Clipboard data with unusual formats
- Compressed archives disguised as `.dat` files

**Current Workflow Failure:**
```bash
# Agent dumps file from memory
vol3 -f memory.dmp windows.dumpfiles --physaddr 0x1f2a3b4c --dump-dir ./output

# Agent tries to read it (WRONG!)
cat ./output/file.0x1f2a3b4c.dat
# Output: �PNG\r\n\x1a\n\x00\x00\x00\rIHDR... (gibberish)
# Context window polluted, AI confused
```

## Solution: MULTIMEDIA, VISUAL & ARCHIVE HANDOFF PROTOCOL

### Rule 0: TRUE FILE TYPE VERIFICATION (ANTI-SPOOFING)

**CRITICAL:** NEVER trust file extensions. Always verify true file type using magic bytes.

```bash
# MANDATORY FIRST STEP
DUMPED_FILE="./output/file.0x1f2a3b4c.dat"

# Step 1: Check true file type (NOT extension)
file "$DUMPED_FILE"
# Example output: PNG image data, 1920 x 1080, 8-bit/color RGB

# Step 2: If output is just "data" (unknown), inspect magic bytes
FILE_TYPE=$(file -b "$DUMPED_FILE")
if [[ "$FILE_TYPE" == *"data"* ]]; then
  echo "[!] Unknown file type - inspecting magic bytes"
  xxd "$DUMPED_FILE" | head -n 5
  # Example output:
  # 00000000: 504b 0304 1400 0000 0800 ...  PK..........
  # ^ This is 50 4B 03 04 = ZIP archive!
fi

echo "[*] True file type: $FILE_TYPE"

# Step 3: Route based on TRUE type (from Rule 0)
case "$FILE_TYPE" in
  *"ASCII text"*|*"UTF-8"*)
    # Text file - safe to cat
    cat "$DUMPED_FILE" | grep -iE "coc2026|flag"
    ;;
    
  *"RIFF"*|*"WAV"*|*"MP3"*|*"Audio"*)
    echo "[*] Audio detected - using metadata/binwalk/strings"
    
    # Metadata
    exiftool "$DUMPED_FILE"
    
    # Hidden files
    binwalk -e "$DUMPED_FILE"
    
    # Embedded strings
    strings -n 10 "$DUMPED_FILE" | grep -iE "coc2026|flag"
    
    # If all fail - human handoff for spectrogram analysis
    if [ $? -ne 0 ]; then
      echo "[🚨 MEDIA ARTIFACT EXTRACTED]"
      echo "- Type: Audio"
      echo "- Path: $DUMPED_FILE"
      echo "- AI Triage: Metadata clean, binwalk negative, no embedded strings"
      echo ""
      echo "[👀 HUMAN ACTION REQUIRED]"
      echo "Please analyze this audio file:"
      echo "  - Check spectrogram (Audacity: Analyze > Plot Spectrum)"
      echo "  - Listen for Morse code or DTMF tones"
      echo "  - Check for SSTV signals"
      echo ""
      echo "CRITICAL: Waiting for your input before proceeding."
    fi
    ;;
    
  *"ISO Media"*|*"MP4"*|*"Matroska"*|*"AVI"*|*"Video"*)
    echo "[*] Video detected - using metadata/strings"
    
    # Metadata
    exiftool "$DUMPED_FILE"
    
    # Embedded strings
    strings -n 10 "$DUMPED_FILE" | grep -iE "coc2026|flag"
    
    # If all fail - human handoff
    if [ $? -ne 0 ]; then
      echo "[🚨 MEDIA ARTIFACT EXTRACTED]"
      echo "- Type: Video"
      echo "- Path: $DUMPED_FILE"
      echo "- AI Triage: Metadata clean, no embedded strings"
      echo ""
      echo "[👀 HUMAN ACTION REQUIRED]"
      echo "Please analyze this video file:"
      echo "  - Watch for hidden frames or text overlays"
      echo "  - Extract and analyze audio track"
      echo "  - Check for steganography in frames"
      echo ""
      echo "CRITICAL: Waiting for your input before proceeding."
    fi
    ;;
    
  *"PNG image"*|*"JPEG image"*|*"GIF image"*|*"BMP image"*)
    echo "[*] Image detected - using OCR/QR decode"
    
    # Metadata
    exiftool "$DUMPED_FILE" | grep -iE "flag|coc2026|secret"
    
    # Steganography
    zsteg -a "$DUMPED_FILE" 2>/dev/null | grep -iE "flag|coc2026"
    
    # QR/Barcode
    zbarimg "$DUMPED_FILE" 2>/dev/null
    
    # OCR (Text in image)
    tesseract "$DUMPED_FILE" stdout 2>/dev/null | grep -iE "flag|coc2026"
    
    # If all fail - human handoff
    if [ $? -ne 0 ]; then
      echo "[🚨 MEDIA ARTIFACT EXTRACTED]"
      echo "- Type: Image"
      echo "- Path: $DUMPED_FILE"
      echo "- AI Triage: Exiftool clean, no QR detected, zsteg negative, OCR failed"
      echo ""
      echo "[👀 HUMAN ACTION REQUIRED]"
      echo "Please open this file manually."
      echo "  - Look for hidden text, color variations, or visual clues"
      echo "  - Check for LSB steganography with stegsolve"
      echo "  - Analyze with different color planes"
      echo ""
      echo "CRITICAL: Waiting for your input before proceeding."
    fi
    ;;
    
  *"PDF document"*)
    echo "[*] PDF detected - extracting text"
    
    # Text extraction
    pdftotext "$DUMPED_FILE" - | grep -iE "coc2026|flag"
    
    # Metadata
    exiftool "$DUMPED_FILE" | grep -iE "coc2026|flag"
    
    # Embedded files
    binwalk "$DUMPED_FILE"
    ;;
    
  *"Zip archive"*|*"7-zip archive"*|*"RAR archive"*)
    echo "[*] Archive detected - listing contents"
    
    # Create temp extraction directory
    EXTRACT_DIR="/tmp/extract_$$"
    mkdir -p "$EXTRACT_DIR"
    
    # Extract based on type
    if [[ "$FILE_TYPE" == *"Zip"* ]]; then
      unzip -l "$DUMPED_FILE"
      unzip -q "$DUMPED_FILE" -d "$EXTRACT_DIR"
    elif [[ "$FILE_TYPE" == *"7-zip"* ]] || [[ "$FILE_TYPE" == *"RAR"* ]]; then
      7z l "$DUMPED_FILE"
      7z x "$DUMPED_FILE" -o"$EXTRACT_DIR" -y
    fi
    
    # Search recursively
    grep -r -iE "coc2026|flag" "$EXTRACT_DIR"
    
    # Cleanup
    rm -rf "$EXTRACT_DIR"
    ;;
    
  *"Microsoft Word"*|*"Microsoft Excel"*|*"Microsoft PowerPoint"*)
    echo "[*] Office document detected (ZIP-based)"
    
    # Office files are ZIP archives
    EXTRACT_DIR="/tmp/office_$$"
    mkdir -p "$EXTRACT_DIR"
    unzip -q "$DUMPED_FILE" -d "$EXTRACT_DIR" 2>/dev/null
    
    # Search in XML files
    grep -r -iE "coc2026|flag" "$EXTRACT_DIR"
    
    # Also try strings (for older formats)
    strings "$DUMPED_FILE" | grep -iE "coc2026|flag"
    
    rm -rf "$EXTRACT_DIR"
    ;;
    
  *"data"*)
    echo "[*] Unknown data type - trying multiple approaches"
    
    # Try as archive first
    unzip -l "$DUMPED_FILE" 2>/dev/null && echo "  -> ZIP archive"
    7z l "$DUMPED_FILE" 2>/dev/null && echo "  -> 7z/RAR archive"
    
    # Try strings
    strings "$DUMPED_FILE" | grep -iE "coc2026|flag"
    
    # Check for magic bytes
    hexdump -C "$DUMPED_FILE" | head -n 5
    ;;
    
  *)
    echo "[*] Unknown file type - using strings"
    strings "$DUMPED_FILE" | grep -iE "coc2026|flag"
    ;;
esac
```

## Tool Installation (Pre-Competition)

```bash
# OCR
sudo apt-get install -y tesseract-ocr tesseract-ocr-eng

# QR/Barcode
sudo apt-get install -y zbar-tools

# Steganography
sudo apt-get install -y steghide zsteg

# PDF tools
sudo apt-get install -y poppler-utils exiftool

# Archive tools
sudo apt-get install -y p7zip-full unzip unrar
```

## Common Scenarios

### Scenario 1: Screenshot in Memory

```bash
# Volatility dumps a PNG screenshot
vol3 -f memory.dmp windows.dumpfiles --physaddr 0xabcd1234 --dump-dir ./output

# Check type
file ./output/file.0xabcd1234.dat
# Output: PNG image data, 1920 x 1080, 8-bit/color RGB

# OCR the screenshot
tesseract ./output/file.0xabcd1234.dat stdout
# Output: "Welcome to the system
#          Your flag is: coc2026{screenshot_flag_found}"
```

### Scenario 2: QR Code in PDF

```bash
# Dump PDF from memory
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0x1234abcd --dump-dir ./output

# Check type
file ./output/file.0x1234abcd.dat
# Output: PDF document, version 1.7

# Extract images from PDF
pdfimages -all ./output/file.0x1234abcd.dat ./output/pdf_images

# Scan for QR codes
for img in ./output/pdf_images*; do
  zbarimg "$img" 2>/dev/null
done
# Output: QR-Code:coc2026{qr_in_pdf_works}
```

### Scenario 3: Compressed Flag in .dat File

```bash
# Dump unknown file
vol3 -f memory.dmp windows.dumpfiles --physaddr 0x5678abcd --dump-dir ./output

# Check type
file ./output/file.0x5678abcd.dat
# Output: Zip archive data, at least v2.0 to extract

# List contents
unzip -l ./output/file.0x5678abcd.dat
# Output:
#   Length      Date    Time    Name
#   ------      ----    ----    ----
#      42   03-30-2026  08:15   flag.txt

# Extract
unzip ./output/file.0x5678abcd.dat -d /tmp/flag_$$
cat /tmp/flag_$$/flag.txt
# Output: coc2026{compressed_in_memory}
```

### Scenario 4: Clipboard Data (Windows)

```bash
# Search for clipboard data in memory
vol3 -f memory.dmp windows.clipboard

# If clipboard contains image data
# Volatility may dump it as raw bitmap
file clipboard_data.bin
# Output: PC bitmap, Windows 3.x format, 800 x 600 x 24

# Convert to viewable format
convert clipboard_data.bin clipboard.png

# OCR
tesseract clipboard.png stdout | grep -iE "coc2026|flag"
```

## Integration with Main Workflow

Add to `@ctf-forensics` skill execution rules:

```markdown
## File Extraction Protocol

After ANY file dump operation (windows.dumpfiles, photorec, binwalk extract):

1. **NEVER use `cat` directly on dumped files**
2. **ALWAYS run `file <dumped_file>` first**
3. **Route to appropriate handler:**
   - Text → `cat` / `grep`
   - Image → `tesseract` / `zbarimg`
   - PDF → `pdftotext` / `exiftool`
   - Archive → `unzip -l` / `7z l` then extract
   - Office → `unzip` (DOCX/XLSX are ZIP)
   - Unknown → `strings` + `hexdump`

4. **If image OCR fails:**
   - DO NOT discard the file
   - Output: `[ACTION REQUIRED] Manual inspection needed: <path>`
   - Pause execution for human review

5. **Archive handling:**
   - List contents BEFORE extraction
   - Extract to temporary directory
   - Search recursively
   - Clean up after
```

## Human Handoff Template

```
🚨 [ACTION REQUIRED] Visual Artifact Detected

File: <absolute_path>
Type: <file_type>
Size: <file_size>

Automated extraction methods attempted:
  ✗ OCR (tesseract): No flag found
  ✗ QR decode (zbarimg): No QR codes detected
  ✗ Steganography (steghide/zsteg): No hidden data

This file may contain a visual flag that requires manual inspection.
Please open the file and check for:
  - Text in images (screenshots, photos)
  - QR codes or barcodes
  - Hidden layers or transparency
  - Unusual visual patterns

Action: Open <absolute_path> in an image viewer and inspect manually.
```

## Key Improvements

1. ✅ **Type-aware extraction** - No more gibberish in context
2. ✅ **OCR/QR automation** - Attempts automated visual extraction
3. ✅ **Archive handling** - Properly extracts compressed flags
4. ✅ **Human handoff** - Escalates when automation fails
5. ✅ **Context protection** - Prevents binary data overflow
