# CTF Challenge Fallback Strategies

## Table of Contents
- [When Initial Approach Fails](#when-initial-approach-fails)
- [Fallback Order by Category](#fallback-order-by-category)
- [Escalating Information Gathering](#escalating-information-gathering)
- [Cross-Category Pivots](#cross-category-pivots)
- [Last-Resort Techniques](#last-resort-techniques)

---

## When Initial Approach Fails

**Checklist before pivoting:**

```
1. Did you read ALL provided files? (README, source, config, Dockerfile)
2. Did you connect to the service and explore all endpoints/options?
3. Did you check the challenge description for hidden hints?
4. Did you try the obvious (default creds, common flags, literal strings)?
5. Is there a hint system or discord channel with public hints?
```

**If all above checked — pivot using the table below.**

---

## Fallback Order by Category

### Web Fallback Chain

```
Attempted: SQLi, XSS, SSTI
  -> Fail: Check auth: JWT, session, cookies (ctf-web/auth-jwt.md)
  -> Fail: Check file operations: LFI, path traversal, file upload
  -> Fail: Check modern: prototype pollution, SSRF, XXE
  -> Fail: Check race conditions (ctf-web/race-conditions.md)
  -> Fail: Check HTTP/2 desync, request smuggling (ctf-web/http2-and-race.md)
  -> Fail: Check client-side: XS-Leak, CSRF, postMessage
  -> Fail: Look for CVEs matching the tech stack (ctf-web/cves.md)
  -> Fail: Check Web3/blockchain if any contract code (ctf-web/web3.md)
  -> Fail: Treat as multi-category (see triage.md)
```

```bash
# Tech stack fingerprinting (key for CVE matching):
curl -sv https://target.com/ 2>&1 | grep -iE '(server|x-powered-by|via|x-generator)'
whatweb https://target.com/
```

### Pwn Fallback Chain

```
Attempted: Buffer overflow, ROP chain
  -> Fail: Check format string vulnerability
  -> Fail: Check heap: UAF, double-free, overflow into next chunk
  -> Fail: Check integer issues: overflow, sign confusion, truncation
  -> Fail: Check for info leak first (need libc/heap base)
  -> Fail: Check if seccomp blocks shellcode (use seccomp-tools)
  -> Fail: Check kernel exploitation if driver/module present
  -> Fail: Check race condition (multi-threaded binary)
  -> Fail: Check Windows-specific: SEH, VirtualAlloc ROP
```

```bash
# Quick vuln surface enumeration:
checksec --file=binary
seccomp-tools dump ./binary
strace ./binary 2>&1 | head -50
ltrace ./binary 2>&1 | head -30
```

### Crypto Fallback Chain

```
Attempted: RSA attacks (small e, Wiener, Fermat)
  -> Fail: Check if ECC (look for curve parameters)
  -> Fail: Check AES mode: ECB (penguin), CBC (padding oracle), GCM (nonce reuse)
  -> Fail: Check PRNG: MT19937, LCG, truncated output
  -> Fail: Check protocol: oracle queries available, multi-party
  -> Fail: Check ZKP/post-quantum if exotic math (ctf-crypto/zkp-and-advanced.md)
  -> Fail: Check AES-GCM nonce reuse (ctf-crypto/aes-gcm-attacks.md)
  -> Fail: Check classic/historical ciphers if old-style challenge
```

### Reverse Fallback Chain

```
Attempted: Ghidra static analysis, strings
  -> Fail: Check for packer/obfuscation (UPX, OLLVM, VMProtect)
  -> Fail: Use dynamic analysis: GDB, Frida, strace
  -> Fail: Check for anti-debugging and bypass (ctf-reverse/anti-analysis.md)
  -> Fail: Check language-specific: .NET dnSpy, APK jadx, PyInstaller
  -> Fail: Check for custom VM bytecode (ctf-reverse/patterns-ctf.md)
  -> Fail: Check eBPF program (ctf-reverse/ebpf-analysis.md)
  -> Fail: Check JS engine/LLVM obfuscation (ctf-reverse/js-engine-re.md)
  -> Fail: Use angr symbolic execution
```

```bash
# Detect obfuscation:
upx -t binary                        # UPX test
strings binary | head -5             # packer strings
objdump -d binary | grep -c 'jmp.*rax'  # indirect jumps (CFF)
```

### Forensics Fallback Chain

```
Attempted: Volatility, strings, binwalk
  -> Fail: Check steganography (stegsolve, stegseek, zsteg)
  -> Fail: Check network: decrypt TLS with keylog file, SMB, DNS tunneling
  -> Fail: Check deleted files: photorec, foremost, scalpel
  -> Fail: Check Windows artifacts: registry, event logs, prefetch
  -> Fail: Check file format specifics (ZIP comment, PDF streams, PNG chunks)
  -> Fail: Check audio: spectrogram, DTMF, morse code
```

### Misc Fallback Chain

```
Attempted: Encoding identification, Z3 constraint solving
  -> Fail: Check if it is a jail: Python pyjail or bash jail
  -> Fail: Check AI/LLM challenge (ctf-misc/ai-llm-challenges.md)
  -> Fail: Check RF/SDR signal (ctf-misc/rf-sdr.md)
  -> Fail: Check esoteric language (Brainfuck, Whitespace, Malbolge)
  -> Fail: Check game theory / combinatorial game
  -> Fail: Check Kubernetes RBAC if cloud environment
```

---

## Escalating Information Gathering

When stuck, progressively expand recon:

```bash
# Level 1: File content
strings binary | sort -u | less
exiftool file
binwalk -Me file

# Level 2: Network behavior
strace -e trace=network ./binary
wireshark &; ./binary  # capture traffic
curl -v --proxy http://127.0.0.1:8080 https://target.com/  # Burp proxy

# Level 3: Dynamic execution
gdb -ex 'b main' -ex 'r' -ex 'info functions' binary
frida-trace -i "*" ./binary
qemu-x86_64 -strace ./binary

# Level 4: Source / decompilation
retdec-decompiler binary -o binary.c
ghidra binary  # decompile in Ghidra
python3 -m uncompyle6 code.pyc  # Python bytecode
```

---

## Cross-Category Pivots

If challenge seems unsolvable in current category, consider these pivots:

| Current Category | Pivot To | Trigger |
|---|---|---|
| Web | Crypto | Custom token/cookie with non-standard encoding |
| Web | Reverse | Client-side WASM or obfuscated JS does the check |
| Pwn | Reverse | Binary is packed / anti-debug present |
| Pwn | Crypto | Need to break challenge's auth to reach vuln |
| Reverse | Pwn | Binary has exploitable bug in addition to RE puzzle |
| Crypto | Math | Problem requires number theory / lattice reduction |
| Forensics | Crypto | Encrypted data in artifact needs key recovery |
| Misc | Pwn | Jail escape leads to binary exploitation |

See [triage.md](triage.md) for the full cross-category decision matrix.

---

## Last-Resort Techniques

```bash
# Brute force flag format directly:
python3 -c "
import string, itertools
charset = string.ascii_lowercase + string.digits + '_{}'
# If you know flag length from previous leak:
for c in charset:
    # test each character position
    pass
"

# Check if flag is in the binary itself:
strings binary | grep -E '[a-zA-Z0-9_]{2,}\{[^}]{3,}\}'

# Check git history if source provided:
git log --all --full-history
git stash list
git show HEAD~1  # check previous commits

# Check environment variables:
# (if you have code execution)
import os; print(dict(os.environ))
cat /proc/self/environ | tr '\0' '\n'

# Check common flag locations:
cat /flag /flag.txt /app/flag.txt /home/*/flag* 2>/dev/null
env | grep -i flag
```