# CTF Challenge Triage — Multi-Category Decision Matrix

## Table of Contents
- [Ambiguous File Type Matrix](#ambiguous-file-type-matrix)
- [Cross-Category Challenge Patterns](#cross-category-challenge-patterns)
- [Confidence Scoring](#confidence-scoring)
- [Quick Recon Commands](#quick-recon-commands)

---

## Ambiguous File Type Matrix

When `file *` and initial inspection are inconclusive, use this matrix:

| File Type | First Check | If Remote Service? | Secondary Category |
|---|---|---|---|
| ELF binary | `checksec`, `strings` for flag | Yes → pwn | No → reverse |
| PE / .exe | `strings`, look for network calls | Yes → pwn (Windows) | No → reverse or malware |
| .py / .sage | Is it a crypto script? → crypto | Does it spawn a server? → pwn/misc | Jail? → misc |
| .pcap / .pcapng | `tshark -r f.pcap -qz io,phs` | Has exploit traffic? → pwn | Encrypted? → crypto+forensics |
| .js | Node server? → web | Browser challenge? → web | Obfuscated logic? → reverse |
| Image (PNG/JPG) | Check LSB with `stegsolve` → forensics | EXIF injection hint? → web | Mathematical pattern? → crypto |
| PDF | Hidden layers → forensics | Form fields with injection? → web | — |
| .wasm | Called from web context? → web | Standalone logic? → reverse | — |
| .apk / .ipa | UI challenge? → reverse | Talks to server? → web+reverse | — |
| No file, URL only | Test all web attacks → web | Source provided? → web | Binary download? → pwn |

---

## Cross-Category Challenge Patterns

### Web + Crypto

**Indicators:**
- JWT manipulation (web delivery, crypto weakness)
- Custom encryption in cookies/tokens
- Padding oracle over HTTP
- Timing attack on authentication

**Approach:** Start with web (enumerate endpoints, auth flow), then apply crypto attacks to tokens/ciphertexts found.

```bash
# Identify crypto in web context:
curl -sv https://target.com/ 2>&1 | grep -iE 'set-cookie|authorization|token'
# Decode token:
echo "TOKEN" | base64 -d | xxd | head  # look for crypto magic bytes
python3 -c "import jwt; print(jwt.decode('TOKEN', options={'verify_signature':False}))"
```

### Web + Reverse

**Indicators:**
- Client-side JavaScript does crypto/validation
- WASM module checks the flag
- Challenge provides a compiled binary + web interface
- XSS payload needs to exploit a binary (XSS-to-binary-pwn bridge)

**Approach:** Extract client-side logic first (browser DevTools, `wasm2wat`), reverse the validation, then craft the web request.

### Pwn + Crypto

**Indicators:**
- Binary implements custom crypto → need to reverse first, then exploit
- Memory leak exposes key material → decrypt captured traffic
- Crypto oracle is exposed via socket

**Approach:** Reverse the crypto protocol, then exploit the binary to leak keys or forge values.

### Pwn + Reverse

**Indicators:**
- Obfuscated/packed binary (UPX, custom packer)
- Anti-debug in binary that also has pwn vulnerability
- Custom VM binary where you must understand bytecode to reach vuln

**Approach:** Unpack/deobfuscate first, then find the vulnerability.

```bash
# Quick packer detection:
upx -t binary           # test for UPX
file binary             # look for 'packed'
strings binary | head -20  # UPX magic or packer strings
upx -d binary -o unpacked  # decompress
```

### Forensics + Crypto

**Indicators:**
- PCAP with encrypted traffic (need to find/derive key)
- Memory dump with encrypted ransomware files
- Disk image with encrypted partition

**Approach:** Use forensics tools to extract key material, then apply crypto attacks.

### Misc + Pwn

**Indicators:**
- Python/bash jail with a binary inside
- Container escape leads to binary exploitation
- Custom VM implemented in Python/JS that has memory corruption bugs

**Approach:** Escape the jail/VM layer first, then apply pwn techniques.

---

## Confidence Scoring

Score each category using Router v2 weights:

```
+3  Definitive indicator (e.g., .pcap file = forensics, socket + ELF = pwn)
+2  Strong hint in description ("buffer overflow", "RSA", "XSS")
+1  Weak hint (binary exists, web URL provided)
+0  No evidence
-1  Contradicting evidence
```

## Route Decision Rule (Router v2 Sync)

- Route immediately when both hold:
  - `top_score >= 4`
  - `(top_score - second_score) >= 2`

- If condition fails:
  - choose one primary route,
  - set one backup route (cross-category),
  - enforce short fail-fast timebox.

### One-Line Handoff Contract (Mandatory)

Output exactly one routing line:

`Routing to /<skill> | primary_mcp=<mcp> | confidence=<n> | backup=/ctf-<skill2>`

### Fail-Fast Pivot Mapping

Pivot immediately when one is true:
- same error repeats 3 times
- no measurable progress in 2 command cycles
- active branch stalls >10s without output

Then invoke backup route using the same one-line handoff format.

**If all categories score ≤ 1:** run full recon battery from SKILL.md before committing.

---

## Quick Recon Commands

```bash
# Universal first pass — run on all challenge files:
file *
strings * | grep -iE '(flag|ctf|key|secret|pass|token|encrypt|decrypt)' | head -30
binwalk -e *                          # extract embedded files
exiftool * 2>/dev/null | grep -v 'ExifTool\|File'  # metadata
xxd file | head -5                    # magic bytes

# Network service:
nc -v target port                     # banner grab
curl -sv http://target:port/          # HTTP recon
openssl s_client -connect target:443  # TLS info

# Determine endianness / arch for binaries:
readelf -h binary 2>/dev/null | grep -E '(Class|Data|Machine)'

# Find flag pattern anywhere:
grep -rniE '(ctf|ictf|flag|htb|picoctf)\{' .
strings * | grep -E '[A-Za-z0-9_]{2,}\{[^}]+\}'
```

See [fallback.md](fallback.md) for what to do when initial categorization fails.
See [SKILL.md](SKILL.md) for the main categorization workflow.