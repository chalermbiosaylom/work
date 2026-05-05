# Solve-Challenge: Flag Hunting Priority Rules

## 🎯 CRITICAL RULE: FLAG HUNT FIRST

**For ALL challenge categories, flag hunting is the PRIMARY objective.**

### 🚨 PARADIGM SHIFT: "HUNT FIRST, ESCALATE LATER"

**MANDATORY WORKFLOW FOR ALL CATEGORIES:**

```
Initial Foothold Achieved (Shell/Access/Exploit Success)
  ↓
🚩 PHASE 1: FLAG HUNT (Current Permissions)
  ├─ Search accessible files/directories
  ├─ Check environment variables
  ├─ Inspect current user's home directory
  ├─ Read application configuration files
  └─ Extract data from databases (if accessible)
  ↓
Flag Found? → HALT IMMEDIATELY
  ↓ NO
🔐 PHASE 2: PRIVILEGE ESCALATION
  ├─ Quick Wins (sudo -l, SUID, capabilities)
  ├─ Automated enumeration (LinPEAS/WinPEAS filtered)
  └─ Exploit identified vector
  ↓
🚩 PHASE 3: FLAG HUNT (Elevated Permissions)
  ├─ Search /root directory
  ├─ Read protected system files
  └─ Access previously denied locations
  ↓
Flag Found? → HALT IMMEDIATELY
  ↓ NO
🔄 PHASE 4: LATERAL MOVEMENT
  ├─ Enumerate other users
  ├─ Check Docker/container escape
  └─ Pivot to other systems
```

**WHY THIS MATTERS:**
- ✅ **40% of CTF challenges** place flags accessible to initial user
- ✅ **Saves 10-20 minutes** by avoiding unnecessary privilege escalation
- ✅ **Prevents token waste** from running full LinPEAS when flag is visible
- ❌ **AI "power addiction"** = rushing to root before checking obvious locations

**CRITICAL RULES:**
1. ✅ **ALWAYS execute PHASE 1 before PHASE 2**
2. ✅ **NEVER run LinPEAS/WinPEAS before basic flag hunt**
3. ✅ **NEVER assume flag requires root access**
4. ❌ **NEVER skip current-user flag hunt**

---

## 📋 Category-Specific Flag Hunt Workflows

### 1. Web Exploitation (`/ctf-web`)
```
Exploit (SQLi/XSS/SSTI/RCE)
  ↓
Get Webshell/Command Execution
  ↓
PHASE 1: FLAG HUNT (Current Permissions) ← START HERE
  ↓
Permission Denied?
  ↓ YES
PHASE 2: PRIVILEGE ESCALATION
  ↓
PHASE 3: FLAG HUNT (Elevated Permissions)
  ↓
Still No Flag?
  ↓
PHASE 4: LATERAL MOVEMENT
```

**Commands:**
```bash
# Phase 1: Quick flag hunt
cat /flag.txt /flag /root/flag.txt /home/*/flag.txt /var/www/html/flag.txt /app/flag.txt 2>/dev/null
find / -name "*flag*" -type f 2>/dev/null | head -20
grep -r "coc2026{" /var/www /home /tmp 2>/dev/null | head -10
env | grep -iE "(flag|coc2026)"

# Phase 2: If permission denied
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null

# Phase 3: After privesc
cat /root/flag.txt /flag.txt
grep -r "coc2026{" / 2>/dev/null | head -5
```

---

### 2. Pwn (`/ctf-pwn`)
```
Reverse binary locally
  ↓
Find vulnerability (buffer overflow/format string/heap)
  ↓
Develop exploit locally (process())
  ↓
Test locally → Confirm primitive works
  ↓
Connect to remote (remote())
  ↓
Send exploit → Extract flag from stdout
```

**Commands:**
```python
from pwn import *

# Phase 1: Local testing
p = process('./challenge')
payload = b'A'*offset + p64(win_addr)
p.sendline(payload)
print(p.recvall())  # Check if exploit works

# Phase 2: Remote flag extraction
r = remote('target.com', 1337)
r.sendline(payload)
flag = r.recvall()  # Flag should be in output
print(flag)
```

---

### 3. Crypto (`/ctf-crypto`)
```
Analyze crypto challenge
  ↓
Identify weakness (weak RSA/padding oracle/etc.)
  ↓
Develop attack script
  ↓
Decrypt/crack → Flag in plaintext output
```

**Commands:**
```python
# Example: RSA attack
from Crypto.Util.number import long_to_bytes
# ... attack logic ...
plaintext = long_to_bytes(decrypted)
print(plaintext)  # Flag should be here
```

---

### 4. Reverse Engineering (`/ctf-reverse`)
```
Decompile binary (Ghidra/radare2)
  ↓
Analyze logic/strings
  ↓
Find flag in:
  - Hardcoded strings
  - Decryption routine output
  - Correct input validation
```

**Commands:**
```bash
# Quick string search
strings binary | grep -iE "(coc2026|flag)"

# Ghidra decompilation
# Look for flag validation logic or decryption functions

# Dynamic analysis
ltrace ./binary
strace ./binary
```

---

### 5. Forensics (`/ctf-forensics`)
```
Analyze artifact (PCAP/disk/memory)
  ↓
Extract files/data
  ↓
Hunt for flag in:
  - Extracted files
  - Network streams
  - Memory dumps
  - Deleted files
```

**Commands:**
```bash
# PCAP
strings file.pcap | grep -iE "coc2026{"
tshark -r file.pcap -Y "http" -T fields -e http.file_data | grep -iE "flag"

# Disk image
strings disk.dd | grep -iE "coc2026{"
foremost -i disk.dd -o output/

# Memory dump
volatility -f memory.dmp --profile=Win7SP1x64 filescan | grep -i flag
```

---

### 6. ICS/OT (`/ctf-ics`) - Custom Tools Integration
```
Scan Modbus/ENIP service
  ↓
Read registers/tags
  ↓
Flag in:
  - Holding registers
  - Coil values
  - Tag data
  - PCAP traffic
```

**Commands (Absolute Paths - Custom Tools):**
```bash
# Modbus flag hunt (ABSOLUTE PATH)
python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/pymodbus/modbus_read_find_flags.py <IP> --probe-units --json
# Output: JSON with register values and flag detection

# ENIP flag hunt (ABSOLUTE PATH)
python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/enip/enip_cpppo_read_find_flags.py --ip <IP> --auto-sweep --json
# Output: JSON with tag data and automatic flag extraction

# S7comm flag hunt (ABSOLUTE PATH)
python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/s7comm/s7_read_find_flags.py --ip <IP> --rack 0 --slot 1 --auto-probe --json
# Output: JSON with DB blocks and flag detection

# MQTT telemetry hunt (ABSOLUTE PATH)
python3 /home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/mqtt/mqtt_subscribe_hunt.py --broker <IP> --topic "#" --timeout 30 --json
# Output: JSON with all MQTT messages and flag detection

# PCAP analysis
strings ics_traffic.pcap | grep -iE "coc2026{|f1a9{|fl4g{"
tshark -r ics_traffic.pcap -Y "modbus || enip || s7comm" -T fields -e data | xxd -r -p | grep -E "coc2026"
```

**WHY ABSOLUTE PATHS:**
- ✅ Prevents AI from guessing wrong command names
- ✅ Ensures correct tool execution
- ✅ Enables `--json` output for easy parsing
- ✅ Integrates with custom automation scripts

---

### 7. OS Exploit (`/ctf-os-exploit`)
```
Get initial foothold (SSH/webshell)
  ↓
PHASE 1: FLAG HUNT (Current User)
  ↓
Permission Denied?
  ↓
PHASE 2: PRIVILEGE ESCALATION
  ↓
PHASE 3: FLAG HUNT (Root)
  ↓
PHASE 4: LATERAL MOVEMENT (if needed)
```

**Commands:**
```bash
# Same as Web exploitation workflow
# See ctf-web/FLAG_HUNT_CHEATSHEET.md
```

---

## 🚨 HALT Protocol (When Flag Found)

**Output EXACTLY 3 lines:**
```
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line command>
```

**Example:**
```
[FLAG] coc2026{example_flag_here}
[CLEAN] coc2026{example_flag_here}
[METHOD] grep -r "coc2026{" /var/www 2>/dev/null
```

**DO NOT:**
- ❌ Add explanations
- ❌ Add summaries
- ❌ Continue searching

---

## 🛡️ Anti-Hallucination Rules (CRITICAL - LLM Weakness)

**PROBLEM:** Large Language Models have a dangerous tendency to "imagine" results instead of reading actual command output.

### NEVER:
- ❌ **Generate fake flags** (e.g., `coc2026{example_flag}` without running commands)
- ❌ **Assume vulnerabilities exist without proof** (must see actual error/output)
- ❌ **Hallucinate command flags** (verify tool syntax before use)
- ❌ **Claim success without verification** ("exploit worked" without seeing shell prompt)
- ❌ **Invent flag content** based on challenge description
- ❌ **Predict flag format** without actual extraction

### ALWAYS:
- ✅ **Run commands and read actual output** (stdout/stderr only)
- ✅ **Verify exploits with `whoami`/`id`** before claiming shell access
- ✅ **Report only flags that appear in stdout/stderr/files** (real data only)
- ✅ **Pivot to alternatives if tools fail** (don't retry same command)
- ✅ **Copy-paste exact flag string** from command output
- ✅ **Show command output** before claiming flag found

**ENFORCEMENT:**
```
IF claiming flag found:
  MUST show actual command output containing flag
  MUST NOT generate placeholder flags
  MUST NOT assume flag content
```

**Example of WRONG behavior:**
```
❌ "I ran the exploit and got the flag: coc2026{pwned}"
   (No command output shown = HALLUCINATION)
```

**Example of CORRECT behavior:**
```
✅ Command: cat /flag.txt
   Output: coc2026{actual_flag_from_file}
   [FLAG] coc2026{actual_flag_from_file}
```

---

## 📊 Flag Hunt Priority Matrix (1-Page Cheatsheet)

**Visual workflow for each category with exact commands:**

| Challenge Type | Priority 1 | Priority 2 | Priority 3 | Tools & Commands |
|----------------|-----------|-----------|-----------|------------------|
| **Web** | Current user files | Environment vars | Database | `find / -name "*flag*" 2>/dev/null`<br>`env \| grep -i flag`<br>`grep -r "coc2026{" /var/www` |
| **Pwn** | Remote stdout | Local test output | Binary strings | `remote().recvall()`<br>`process().recvall()`<br>`strings binary \| grep flag` |
| **Crypto** | Decrypted plaintext | Cracked output | Source code | `long_to_bytes(decrypted)`<br>`print(plaintext)` |
| **Reverse** | Binary strings | Decompiled logic | Runtime output | `strings binary \| grep -E "coc2026\|f1a9"`<br>Ghidra → Search strings<br>`ltrace ./binary` |
| **Forensics** | Extracted files | Network streams | Memory dumps | `strings file.pcap \| grep coc2026`<br>`tshark -r file.pcap -Y http`<br>`volatility filescan` |
| **ICS/OT** | Register values | Tag data | PCAP traffic | `modbus_read_find_flags.py <IP>`<br>`enip_cpppo_read_find_flags.py --ip <IP>`<br>`strings ics.pcap` |
| **OS Exploit** | Current user files | Root files (post-privesc) | Other users | `cat ~/flag.txt /tmp/flag.txt`<br>`find /home -name "*flag*" 2>/dev/null`<br>`grep -r coc2026 /` |

**WORKFLOW SYMBOLS:**
- ↓ = Next step
- ✅ = Success path
- ❌ = Failure path
- 🚩 = Flag hunt phase
- 🔐 = Privilege escalation phase

---

## 🎯 Hunt Regex (Global Monitor - Ultimate Detection)

**This regex catches ALL flag mutations including leetspeak and hash-only flags:**

```regex
/(?:coc2026|flag|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i
```

**Matches:**
- `coc2026{...}` - Standard format
- `flag{...}` - Generic format
- `f1a9{...}` - Leetspeak variant (flag → f1a9)
- `fl4g{...}` - Leetspeak variant (flag → fl4g)
- `{32-char hex}` - MD5 hash in braces
- `32-char hex standalone` - Raw MD5/SHA hash

**WHY THIS IS POWERFUL:**
1. ✅ **Catches leetspeak obfuscation** (f1a9, fl4g)
2. ✅ **Catches hash-only flags** (modern CTF trend)
3. ✅ **Catches bare hashes** (no braces)
4. ✅ **Case-insensitive** (FLAG{} = flag{})

**USAGE:**
```bash
# Apply to all command outputs
grep -rE "(?:coc2026|flag|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b" /path 2>/dev/null

# Apply to decoded data
echo "<base64_data>" | base64 -d | grep -E "coc2026|f1a9|fl4g"

# Apply to hex dumps
xxd file.bin | grep -E "[a-fA-F0-9]{32}"
```

**CRITICAL:** This regex MUST be applied to:
- All file contents
- All command outputs
- All decoded Base64/Hex data
- All network traffic captures
- All memory dumps
- All database query results

---

**Competition Mode:** Execute flag hunt FIRST in every category. HALT on match.
