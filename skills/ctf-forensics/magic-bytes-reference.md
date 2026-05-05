# Magic Bytes / File Signature Reference

## Purpose

In CTF forensics challenges, **file extensions are frequently spoofed** to mislead analysis. The ONLY reliable way to determine a file's true type is by reading its **magic bytes** (file signature) at the beginning of the file.

## Critical Rule

**NEVER trust file extensions.** Always run `file <filename>` first, and if it returns "data", inspect the raw hex bytes.

---

## Common Magic Bytes Table

| Magic Bytes (Hex) | ASCII | File Type | Common Extensions | Notes |
|-------------------|-------|-----------|------------------|-------|
| `50 4B 03 04` | `PK..` | ZIP archive | `.zip`, `.jar`, `.docx`, `.xlsx`, `.pptx`, `.apk` | Office files are ZIP-based |
| `50 4B 05 06` | `PK..` | ZIP (empty) | `.zip` | Empty ZIP archive |
| `50 4B 07 08` | `PK..` | ZIP (spanned) | `.zip` | Multi-part ZIP |
| `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` | PNG image | `.png` | Full 8-byte signature |
| `FF D8 FF E0` | `....` | JPEG (JFIF) | `.jpg`, `.jpeg` | JFIF format |
| `FF D8 FF E1` | `....` | JPEG (Exif) | `.jpg`, `.jpeg` | Exif metadata |
| `47 49 46 38 37 61` | `GIF87a` | GIF image | `.gif` | GIF87a format |
| `47 49 46 38 39 61` | `GIF89a` | GIF image | `.gif` | GIF89a format |
| `42 4D` | `BM` | BMP image | `.bmp` | Windows bitmap |
| `25 50 44 46 2D` | `%PDF-` | PDF document | `.pdf` | Portable Document Format |
| `52 49 46 46 ?? ?? ?? ?? 57 41 56 45` | `RIFF....WAVE` | WAV audio | `.wav` | RIFF WAVE format |
| `52 49 46 46 ?? ?? ?? ?? 41 56 49 20` | `RIFF....AVI ` | AVI video | `.avi` | RIFF AVI format |
| `49 44 33` | `ID3` | MP3 audio | `.mp3` | ID3v2 tag |
| `FF FB` | `..` | MP3 audio | `.mp3` | MPEG-1 Layer 3 (no ID3) |
| `4F 67 67 53` | `OggS` | Ogg container | `.ogg`, `.oga`, `.ogv` | Ogg Vorbis/Theora |
| `00 00 00 18 66 74 79 70` | `....ftyp` | MP4 video | `.mp4`, `.m4a`, `.m4v` | ISO Base Media |
| `1A 45 DF A3` | `..ß.` | Matroska video | `.mkv`, `.webm` | Matroska container |
| `1F 8B 08` | `...` | GZIP compressed | `.gz`, `.tar.gz` | GZIP format |
| `42 5A 68` | `BZh` | BZIP2 compressed | `.bz2`, `.tar.bz2` | BZIP2 format |
| `52 61 72 21 1A 07 00` | `Rar!...` | RAR archive | `.rar` | RAR v1.5+ |
| `52 61 72 21 1A 07 01 00` | `Rar!....` | RAR archive | `.rar` | RAR v5.0+ |
| `37 7A BC AF 27 1C` | `7z¼¯'.` | 7-Zip archive | `.7z` | 7-Zip format |
| `FD 37 7A 58 5A 00` | `.7zXZ.` | XZ compressed | `.xz`, `.tar.xz` | XZ Utils |
| `7F 45 4C 46` | `.ELF` | ELF executable | (none) | Linux/Unix binary |
| `4D 5A` | `MZ` | DOS/Windows executable | `.exe`, `.dll`, `.sys` | PE/COFF format |
| `CA FE BA BE` | `ÊÞBA¾` | Java class file | `.class` | Java bytecode |
| `D0 CF 11 E0 A1 B1 1A E1` | `Ðϑàá±.á` | Microsoft Office (old) | `.doc`, `.xls`, `.ppt` | OLE2 Compound File |
| `4D 54 68 64` | `MThd` | MIDI audio | `.mid`, `.midi` | MIDI format |
| `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | `RIFF....WEBP` | WebP image | `.webp` | Google WebP |
| `00 00 01 00` | `....` | ICO image | `.ico` | Windows icon |
| `00 00 02 00` | `....` | CUR cursor | `.cur` | Windows cursor |
| `49 49 2A 00` | `II*.` | TIFF image (little-endian) | `.tif`, `.tiff` | Tagged Image File |
| `4D 4D 00 2A` | `MM.*` | TIFF image (big-endian) | `.tif`, `.tiff` | Tagged Image File |
| `23 21` | `#!` | Script (shebang) | `.sh`, `.py`, `.pl` | Unix script |
| `3C 3F 78 6D 6C` | `<?xml` | XML document | `.xml`, `.svg` | XML format |
| `3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C` | `<!DOCTYPE html` | HTML document | `.html`, `.htm` | HTML5 |
| `7B 5C 72 74 66 31` | `{\rtf1` | RTF document | `.rtf` | Rich Text Format |

---

## Detection Workflow

### Step 1: Use `file` Command

```bash
file <filename>
```

**Example outputs:**
```
image.jpg: PNG image data, 1920 x 1080, 8-bit/color RGB
document.pdf: Zip archive data, at least v2.0 to extract
secret.txt: JPEG image data, JFIF standard 1.01
```

**Analysis:**
- `image.jpg` → TRUE type: PNG (extension is misleading!)
- `document.pdf` → TRUE type: ZIP (PDF extension is fake!)
- `secret.txt` → TRUE type: JPEG (TXT extension is spoofed!)

### Step 2: If `file` Returns "data"

```bash
xxd <filename> | head -n 5
# OR
hexdump -C <filename> | head -n 5
```

**Example output:**
```
00000000: 504b 0304 1400 0000 0800 a58d 5f58 0000  PK.........._X..
00000010: 0000 0000 0000 0000 0000 0900 1c00 666c  ..............fl
00000020: 6167 2e74 7874 5554 0900 03e7 8d5f 58e7  ag.txtUT....._X.
```

**Analysis:**
- First bytes: `50 4B 03 04` = ZIP archive
- Action: Use `unzip -l <filename>` to list contents

### Step 3: Route to Appropriate Handler

Based on TRUE file type (NOT extension):

```bash
TRUE_TYPE=$(file -b <filename>)

case "$TRUE_TYPE" in
  *"PNG image"*)
    # Use image tools (tesseract, zbarimg, zsteg)
    ;;
  *"Zip archive"*)
    # Use archive tools (unzip -l, 7z l)
    ;;
  *"JPEG image"*)
    # Use image tools
    ;;
  *"data"*)
    # Inspect magic bytes manually
    xxd <filename> | head -n 5
    ;;
esac
```

---

## Real CTF Examples

### Example 1: ZIP Disguised as Image

```bash
# Challenge provides: flag.png
file flag.png
# Output: Zip archive data, at least v2.0 to extract

# WRONG approach (trusting extension):
tesseract flag.png stdout  # FAILS - not an image!

# CORRECT approach (using true type):
unzip -l flag.png
# Output:
#   Length      Date    Time    Name
#   ------      ----    ----    ----
#      42   03-30-2026  08:15   secret.txt

unzip flag.png
cat secret.txt
# Output: coc2026{magic_bytes_never_lie}
```

### Example 2: JPEG Disguised as Text

```bash
# Challenge provides: readme.txt
file readme.txt
# Output: JPEG image data, JFIF standard 1.01

# WRONG approach (trusting extension):
cat readme.txt  # Gibberish in terminal

# CORRECT approach (using true type):
tesseract readme.txt stdout
# Output: coc2026{extension_spoofing_detected}
```

### Example 3: Unknown "data" File

```bash
# Challenge provides: mystery.bin
file mystery.bin
# Output: data

# Inspect magic bytes
xxd mystery.bin | head -n 5
# Output:
# 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR

# Analysis: 89 50 4E 47 = PNG image (corrupted header)
# Fix header and process as PNG
```

---

## Integration with MULTIMEDIA Protocol

**Rule 0 (TRUE FILE TYPE VERIFICATION) MUST be executed BEFORE all other rules:**

```bash
# Rule 0: Verify true file type
DUMPED_FILE="./output/file.0xabcd1234.dat"
TRUE_TYPE=$(file -b "$DUMPED_FILE")

if [[ "$TRUE_TYPE" == *"data"* ]]; then
  # Fallback: Inspect magic bytes
  MAGIC_BYTES=$(xxd "$DUMPED_FILE" | head -n 1 | awk '{print $2$3}')
  
  case "$MAGIC_BYTES" in
    "504b0304")
      TRUE_TYPE="Zip archive data"
      ;;
    "89504e47")
      TRUE_TYPE="PNG image data"
      ;;
    "ffd8ff")
      TRUE_TYPE="JPEG image data"
      ;;
    *)
      echo "[!] Unknown magic bytes: $MAGIC_BYTES"
      ;;
  esac
fi

echo "[*] True file type: $TRUE_TYPE"

# Rule 1: Route based on TRUE type (NOT extension)
case "$TRUE_TYPE" in
  *"PNG image"*|*"JPEG image"*|*"GIF image"*)
    # Image handling
    ;;
  *"Zip archive"*)
    # Archive handling
    ;;
  # ... etc
esac
```

---

## Tools for Magic Bytes Inspection

### 1. `file` Command
```bash
file <filename>
file -b <filename>  # Brief output (no filename)
file -i <filename>  # MIME type
```

### 2. `xxd` (Hex Dump)
```bash
xxd <filename> | head -n 5
xxd -l 16 <filename>  # First 16 bytes only
```

### 3. `hexdump`
```bash
hexdump -C <filename> | head -n 5
hexdump -n 16 -C <filename>  # First 16 bytes only
```

### 4. `od` (Octal Dump)
```bash
od -A x -t x1z -v <filename> | head -n 5
```

---

## Key Takeaways

1. ✅ **ALWAYS run `file <filename>` FIRST**
2. ✅ **NEVER trust file extensions**
3. ✅ **If `file` returns "data", inspect magic bytes with `xxd` or `hexdump`**
4. ✅ **Route tools based on TRUE file type, not extension**
5. ✅ **Reference this magic bytes table when analyzing unknown files**

**This is Rule 0 for a reason - it MUST be executed before all other analysis steps.**
