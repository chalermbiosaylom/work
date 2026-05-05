# 🛡️ CTF Anti-Trap Toolkit (Executable Reference)

Executable companion to `SKILL.md`. Use these helpers when facing:
- Resource exhaustion (zip bombs, binwalk traps, OOM)
- Time-wasting rabbit holes (anti-debug, obfuscation)
- Decoy flags
- Tarpits (adaptive timeouts)
- Long-running scans (safe bailout)

---

## Helper Scripts

### `ctf_safe_run.sh` - Resource-Monitored Executor
Wraps any command with timeout + CPU/memory monitoring and auto-kill.

```bash
# Kill after 60s or if CPU stays at 100% AND memory exceeds 1000MB
bash ctf_safe_run.sh 60 1000 -- nmap -p- target.com
bash ctf_safe_run.sh 30 500  -- ./suspicious_binary
```

### `archive_inspect.sh` - Pre-Extraction Gate
Rejects potential zip/7z/tar bombs before extraction.

```bash
bash archive_inspect.sh suspicious.zip
bash archive_inspect.sh dump.tar.gz
# Flags: >100 files, >50x compression ratio, or nested archives
```

### `flag_filter.py` - Decoy Flag Scorer
Ranks flag candidates, penalizes troll keywords, rewards entropy.

```bash
grep -oE 'coc2026\{[^}]+\}' output.txt | python3 flag_filter.py
# stdin: one flag per line; stdout: sorted with confidence score
```

### `adaptive_timeout.sh` - RTT-Based Timeout
Measures target latency and outputs safe curl/nc timeout value.

```bash
TMO=$(bash adaptive_timeout.sh target.com)
curl --max-time "$TMO" http://target.com/api
```

### `entropy_check.py` - Packer / Stego Entropy
Flags likely-packed binaries or noise-filled stego carriers.

```bash
python3 entropy_check.py ./binary
python3 entropy_check.py ./suspicious.png
# Prints entropy; warns when >7.5 (packed/encrypted)
```

---

## Category Cheat Sheet

### Web / Network (adaptive timeouts, fuzz depth)
```bash
# Adaptive timeout
TMO=$(bash adaptive_timeout.sh target.com); curl --max-time "$TMO" http://target.com

# ffuf with depth + timeout cap
ffuf -w wordlist.txt -u http://target.com/FUZZ -recursion -recursion-depth 2 -timeout 10 -t 20

# gobuster with rate limit
gobuster dir -u http://target.com -w wordlist.txt -t 10 -timeout 10s --no-error
```

### Forensics (archive/binwalk safety)
```bash
# Inspect before extraction
bash archive_inspect.sh file.zip

# Binwalk signature-only first
timeout 30s binwalk file.bin > bw.txt
[ $(grep -cE 'Zlib|LZMA|gzip' bw.txt) -gt 10 ] && echo "SIGNATURE BOMB" && exit 1
binwalk -e file.bin --max-size=100M
```

### Reverse / Pwn (anti-debug bypass)
```bash
# Patch ptrace via LD_PRELOAD
cat > fake_ptrace.c << 'EOF'
#include <sys/types.h>
long ptrace(int r,pid_t p,void*a,void*d){return 0;}
EOF
gcc -shared -fPIC fake_ptrace.c -o fake_ptrace.so
LD_PRELOAD=./fake_ptrace.so gdb ./binary

# GDB catch time-based traps
gdb ./binary -ex 'catch syscall nanosleep' -ex 'catch syscall clock_gettime' -ex run
```

### Crypto (feasibility gate)
```bash
# Abort factoring if >5 minutes estimated
python3 -c "
from Crypto.PublicKey import RSA
k=RSA.import_key(open('pubkey.pem').read())
b=k.n.bit_length(); est=2**(b/3)/1e9
print(f'{b}-bit, est {est:.2e}s')
import sys; sys.exit(1 if est>300 else 0)"
```

### Stego (LSB entropy)
```bash
python3 entropy_check.py suspicious.png
# If LSB unique ratio <0.1 -> noise trap, skip
```

### Logic Bombs (time/env spoofing)
```bash
# faketime wrapper
faketime '2025-01-01 00:00:00' ./binary

# LD_PRELOAD time hook
cat > fake_time.c << 'EOF'
#include <time.h>
time_t time(time_t*t){time_t f=1735689600;if(t)*t=f;return f;}
EOF
gcc -shared -fPIC fake_time.c -o fake_time.so
LD_PRELOAD=./fake_time.so ./binary
```

### Supply Chain (sandbox unknown files)
```bash
# Docker isolation (network-none, read-only)
docker run --rm -it --network none --read-only --tmpfs /tmp -v "$PWD:/work:ro" ubuntu:22.04 bash

# Firejail fallback
firejail --net=none --private --read-only=/work ./binary

# Python deps audit
pip install safety && safety check -r requirements.txt
```

---

## Universal Bailout Rules

1. Same error/output **3 times** → hard pivot (different methodology, not tweaked command)
2. CPU pinned **100%** AND memory **>1GB** → auto-kill via `ctf_safe_run.sh`
3. Network request **>5s** per call in match mode → treat as tarpit, reduce scope
4. Archive **>100 files** OR compression **>50x** → refuse extraction
5. LSB entropy **<0.1** OR binary entropy **>7.5** → likely trap/packed
6. Flag contains `fake|test|try|harder|noob|decoy|haha|nice_try` → decoy, discard
7. RSA est. factor time **>300s** without known weakness → abort, look for structural flaw

---

## Cross-Skill Links
- `@ctf-web` - precision strike + WAF backoff (V4/V5)
- `@ctf-pwn` - anti-debug bypass patterns
- `@ctf-reverse` - entropy / obfuscation detection
- `@ctf-crypto` - feasibility gate before brute force
- `@ctf-forensics` - archive/binwalk safety
- `@ctf-os-exploit` - `smart_enum.sh` for bounded file reads
