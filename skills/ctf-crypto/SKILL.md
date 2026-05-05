---
name: ctf-crypto
description: Cryptography attack techniques for CTF challenges. Use when attacking encryption, hashing, signatures, ZKP, PRNG, or mathematical crypto problems involving RSA, AES, ECC, lattices, LWE, CVP, number theory, Coppersmith, Pollard, Wiener, padding oracle, GCM, key derivation, or stream/block cipher weaknesses.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

## Flag Format (คาดเดา)

- พบบ่อย: `coc2026{...}`
- อื่นๆ ที่เจอได้: `CTF{...}`, `FLAG{...}`, `flag{...}`

## � Competition Crypto Router v2 (10/10 Fast-Path)

Use this section first before deep math.

1. **30s Crypto Triage**
   - Detect class quickly: RSA / ECC / Lattice / Oracle / PRNG / Decode-chain.
   - Extract only minimal artifacts (`n,e,c`, curve params, oracle behavior, sample outputs).

2. **Program-First Rule (Mandatory)**
   - For hard crypto, write a solver program immediately (Python/Sage), do not rely on manual algebra in chat.
   - Solver must emit machine-readable result and candidate flags.

3. **Tool Gate**
   - RSA/basic oracle/PRNG/classic -> Python
   - ECC/Coppersmith/Lattice/LWE/CVP -> Sage (`.sage`) only

4. **Anti-Trap Preflight (Default ON)**
   - Run preflight before execution: context extraction + stage detection + red-herring detection.
   - `solve_crypto.py` does this automatically for `--input-json` unless `--no-preflight` is used.
   - Preflight may enrich missing `n/e/c` from source text when decoys are present.

5. **One-Line Attack Plan Contract**
   - Output exactly one plan line before execution:
   - `AttackPlan: attack=<name> | tool=<python|sage> | solver=<program|one-liner> | confidence=<n>`

6. **Fail-Fast Pivot**
   - Pivot immediately if one condition holds:
     - same failure repeats 3 times,
     - no measurable progress after 2 solve cycles,
     - wrong tool class selected (e.g., lattice in Python).

7. **References for Drill & QA**
   - [CRYPTO_SOLVER_TEMPLATES.md](CRYPTO_SOLVER_TEMPLATES.md)
   - [CRYPTO_ROUTING_EXAMPLES.md](CRYPTO_ROUTING_EXAMPLES.md)
   - [CRYPTO_BENCHMARK_CASES.json](CRYPTO_BENCHMARK_CASES.json)
   - [CRYPTO_BENCHMARK.py](CRYPTO_BENCHMARK.py)
   - [benchmarks/sample_artifacts.json](benchmarks/sample_artifacts.json)
   - [benchmarks/sample_expected_plans.json](benchmarks/sample_expected_plans.json)
   - [helpers/factor_n.py](helpers/factor_n.py) (offline-first factorization chain)
   - [helpers/rtaf_patterns.py](helpers/rtaf_patterns.py) (competition flag/token patterns)
   - [helpers/context_analyzer.py](helpers/context_analyzer.py) (detect real params amid decoys)
   - [helpers/stage_detector.py](helpers/stage_detector.py) (multi-stage gate detector)
   - [helpers/red_herring_detector.py](helpers/red_herring_detector.py) (trap heuristic detector)
   - [helpers/generate_solver.py](helpers/generate_solver.py) (challenge scaffold generator)
   - [solve_crypto.py](solve_crypto.py) (auto Python/Sage scaffold)

## �📏 File Size Awareness (Token Management)

**CRITICAL:** Crypto challenges often include LARGE ciphertext files (10,000+ lines).

**Rules:**
1. **NEVER use `cat` on unknown files** - will overflow context window
2. **Check file size first:** `wc -c <file>` or `ls -lh <file>`
3. **If file > 50KB:** Use `head -n 50` or `tail -n 50` for triage
4. **For large arrays:** Read directly in Python/Sage script, NOT in shell

**Safe Triage Pattern:**
```bash
# Check size first
ls -lh challenge.py output.txt

# If small (<50KB), safe to read
if [ $(wc -c < challenge.py) -lt 51200 ]; then
  cat challenge.py
else
  # Large file - extract only key variables
  grep -E "^(n|e|c|p|q|d) =" challenge.py
  echo "[!] File too large - extracted key variables only"
fi
```

## MCP-First Override (กฎเหล็ก)

- ห้ามมีคำสั่งที่สั่งให้พิมพ์รันผ่าน Terminal Bash/Zsh ด้วยตัวเอง
- ให้ส่งงานรันเครื่องมือ/สคริปต์ผ่าน MCP (เช่น `[MCP:CTF-Solver@5000] run_tool` หรือ `http_request`)

หมายเหตุ: code block ที่เป็น `bash`/`python` ในเอกสาร/ไฟล์ supporting ให้ถือว่าเป็น "payload/ตัวอย่าง" และต้องให้ MCP เป็นคนรัน ไม่ให้พิมพ์รันเองในเครื่อง

## 🚨 No-Internet Assumption (Critical for Competition)

**ASSUME:** CTF competitions run on **isolated networks** with **NO internet access**.

**Rules:**
1. **NEVER rely on external APIs** (FactorDB, online solvers) as primary method
2. **ALWAYS wrap API calls** in `try...except` with 5-second timeout
3. **ALWAYS have local fallback** ready (yafu, msieve, SageMath)
4. **If API fails or times out** → Immediately switch to local tools

**Example Pattern:**
```python
import requests
try:
    response = requests.get(url, timeout=5)
    # Process response
except (requests.Timeout, requests.ConnectionError):
    print("[!] API unreachable - using local fallback")
    # Use local tool instead
```

## Local References (RTAF-CTF-2026)

- MCP-first runbook: [crypto_01_jeopardy.md](file:///home/kali/Desktop/RTAF-CTF-2026/skill/crypto_01_jeopardy.md)
- Benchmark answers (full 12-case): [benchmarks/expected_plans_full.json](benchmarks/expected_plans_full.json)

## Tooling Index (Local)

### crypto-tools (RSA)

- [rsa_common.py](rsa_tool/rsa_common.py)
- [small_e.py](rsa_tool/small_e.py)
- [wiener.py](rsa_tool/wiener.py)
- [common_modulus.py](rsa_tool/common_modulus.py)
- [fermat.py](rsa_tool/fermat.py)

### crypto-tools (Classic)

- [caesar.py](classic/caesar.py)
- [vigenere.py](classic/vigenere.py)
- [xor_single_byte.py](classic/xor_single_byte.py)
- [xor_repeating_key.py](classic/xor_repeating_key.py)
- [frequency_analysis.py](classic/frequency_analysis.py)

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Additional Resources

- [factordb-safe.md](factordb-safe.md) - **CRITICAL:** Offline-first factorization with FactorDB fallback, partial factor handling, yafu/msieve integration
- [classic-ciphers.md](classic-ciphers.md) - Classic ciphers: Vigenere, Atbash, substitution wheels, XOR variants, deterministic OTP, cascade XOR, book cipher
- [modern-ciphers.md](modern-ciphers.md) - Modern cipher attacks: AES (CFB-8, ECB leakage), CBC-MAC/OFB-MAC, padding oracle, S-box collisions, GF(2) elimination, LCG partial output recovery
- [rsa-attacks.md](rsa-attacks.md) - RSA attacks: consecutive primes, multi-prime, restricted-digit, Coppersmith structured primes, Manger oracle, polynomial hash
- [ecc-attacks.md](ecc-attacks.md) - ECC attacks: small subgroup, invalid curve, Smart's attack (anomalous, with Sage code), fault injection, clock group DLP, Pohlig-Hellman
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP/graph 3-coloring, Z3 solver guide, garbled circuits, Shamir SSS, bigram constraint solving, race conditions
- [prng.md](prng.md) - PRNG attacks (MT19937, LCG, GF(2) matrix PRNG, middle-square, deterministic RNG hill climbing, random-mode oracle, time-based seeds, password cracking)
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42, book cipher implementation)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, LLL, Coppersmith, quaternion RSA, monotone inversion, GF(2)[x] CRT, S-box collision code, LWE lattice CVP attack)
- [lattice-and-lwe.md](lattice-and-lwe.md) - Upstream lattice quick triage + HNP/LWE/CVP patterns

---

## Classic Ciphers

- **Caesar:** Frequency analysis or brute force 26 keys
- **Vigenere:** Known plaintext attack with flag format prefix; derive key from `(ct - pt) mod 26`
- **Atbash:** A<->Z substitution; look for "Abashed" hints in challenge name
- **Substitution wheel:** Brute force all rotations of inner/outer alphabet mapping
- **Cascade XOR:** Brute force first byte (256 attempts), rest follows deterministically
- **XOR rotation (power-of-2):** Even/odd bits never mix; only 4 candidate states
- **Weak XOR verification:** Single-byte XOR check has 1/256 pass rate; brute force with enough budget
- **Deterministic OTP:** Known-plaintext XOR to recover keystream; match load-balanced backends

See [classic-ciphers.md](classic-ciphers.md) for full code examples.

## Modern Cipher Attacks

- **AES-ECB:** Block shuffling, byte-at-a-time oracle; image ECB preserves visual patterns
- **AES-CBC:** Bit flipping to change plaintext; padding oracle for decryption without key
- **AES-CFB-8:** Static IV with 8-bit feedback allows state reconstruction after 16 known bytes
- **CBC-MAC/OFB-MAC:** XOR keystream for signature forgery: `new_sig = old_sig XOR block_diff`
- **S-box collisions:** Non-permutation S-box (`len(set(sbox)) < 256`) enables 4,097-query key recovery
- **GF(2) elimination:** Linear hash functions (XOR + rotations) solved via Gaussian elimination over GF(2)
- **Padding oracle:** Byte-by-byte decryption by modifying previous block and testing padding validity

See [modern-ciphers.md](modern-ciphers.md) for full code examples.

---

## 🎯 God-Mode Tools (AI-Ready Scripts)

**CRITICAL:** These enhanced tools include automatic flag detection, JSON output for AI integration, and fast triage capabilities.

### RSA Auto-Hacker (Fast Triage)

**Dependencies:**
```bash
# Install required packages
pip3 install gmpy2 owiener --break-system-packages
# OR (safer - use venv):
python3 -m venv venv && source venv/bin/activate && pip install gmpy2 owiener
```

**Usage:**
```bash
# Quick RSA vulnerability check
python3 helpers/rsa_autohack.py --n <N> --e <E> --c <C>

# AI mode (JSON output)
python3 helpers/rsa_autohack.py --n <N> --e <E> --c <C> --json

# Supports both decimal and hex input
python3 helpers/rsa_autohack.py --n 0x1234... --e 0x10001 --c 0xabcd...

# Example (Small E attack):
python3 helpers/rsa_autohack.py --n 123456789 --e 3 --c 987654321
```

**Features:**
- **Small E Attack** - Direct eth root extraction (e ≤ 100)
- **Wiener's Attack** - Small private exponent d detection
- **Fermat Factorization** - Close primes (|p-q| small)
- **Auto Flag Extraction** - God-Mode regex with automatic decryption
- **Fast Triage** - All attacks complete in < 1 second
- **JSON Output** - AI-ready structured results

**When to Use:**
- First step for ANY RSA challenge
- Before trying RsaCtfTool or manual attacks
- When you need instant vulnerability assessment

**Fallback Chain:**
If `rsa_autohack.py` fails, escalate to:
1. FactorDB (check if N is pre-factored)
2. RsaCtfTool (comprehensive attack suite)
3. Manual Coppersmith/Pollard attacks
4. SageMath for advanced number theory

---

## RSA Attacks

**⚠️ CRITICAL:** For factorization, ALWAYS use offline-first approach. See [factordb-safe.md](factordb-safe.md).

- **Small e with small message:** Take eth root (Python: gmpy2)
- **Common modulus:** Extended GCD attack (Python: gmpy2)
- **Wiener's attack:** Small d (Python: owiener)
- **Fermat factorization:** p and q close together (Python: gmpy2)
- **Pollard's p-1:** Smooth p-1 (Python: sympy or yafu)
- **Hastad's broadcast:** Same message, multiple e=3 encryptions (Python: gmpy2)
- **Consecutive primes:** q = next_prime(p); find first prime below sqrt(N) (Python: sympy)
- **Multi-prime:** Factor N with offline tools; compute phi from all factors (See factordb-safe.md)
- **Restricted-digit primes:** Digit-by-digit factoring from LSB with modular pruning (Python)
- **Coppersmith structured primes:** Partially known prime; `f.small_roots()` in **SageMath ONLY**
- **Manger oracle:** Phase 1 doubling + phase 2 binary search; ~128 queries for 64-bit key (Python)
- **Polynomial hash (trivial root):** `g(0) = 0` for polynomial hash; craft suffix for `msg = 0 (mod P)`, signature = 0 (Python)
- **Polynomial CRT in GF(2)[x]:** Collect ~20 remainders `r = flag mod f`, filter coprime, CRT combine (Python)
- **Affine over composite modulus:** CRT in each prime factor field; Gauss-Jordan per prime (Python)

See [rsa-attacks.md](rsa-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## Elliptic Curve Attacks

**🚨 MANDATORY: Use SageMath for ALL ECC operations. Python's ecdsa/cryptography libs are insufficient.**

- **Small subgroup:** Check curve order for small factors; Pohlig-Hellman + CRT **[SageMath ONLY]**
- **Invalid curve:** Send points on weaker curves if validation missing **[SageMath ONLY]**
- **Singular curves:** Discriminant = 0; DLP maps to additive/multiplicative group **[SageMath ONLY]**
- **Smart's attack:** Anomalous curves (order = p); p-adic lift solves DLP in O(1) **[SageMath ONLY]**
- **Fault injection:** Compare correct vs faulty output; recover key bit-by-bit (Python OK)
- **Clock group (x^2+y^2=1):** Order = p+1 (not p-1!); Pohlig-Hellman when p+1 is smooth **[SageMath ONLY]**
- **Isogenies:** Graph traversal via modular polynomials; pathfinding via LCA **[SageMath ONLY]**

**Execution Pattern:**
```bash
# Create .sage script for ECC
cat > solve_ecc.sage << 'EOF'
F = GF(p)
E = EllipticCurve(F, [a, b])
# ... ECC attack code ...
EOF

# Execute with SageMath (via Docker — sage not in apt)
bash /home/kali/Desktop/.windsurf/skills/ctf-crypto/sage_runner.sh solve_ecc.sage
# OR inline:
# bash sage_runner.sh -c "E = EllipticCurve(GF(p), [a,b]); print(E.order())"
```

See [ecc-attacks.md](ecc-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## Lattice / LWE Attacks

**🚨 MANDATORY: Use SageMath for ALL lattice operations. Python CANNOT handle these attacks.**

- **LWE via CVP (Babai):** Construct lattice from `[q*I | 0; A^T | I]`, use fpylll CVP.babai to find closest vector, project to ternary {-1,0,1}. Watch for endianness mismatches between server description and actual encoding. **[SageMath ONLY]**
- **LLL for approximate GCD:** Short vector in lattice reveals hidden factors **[SageMath ONLY]**
- **Multi-layer challenges:** Geometry → subspace recovery → LWE → AES-GCM decryption chain **[SageMath + Python]**

**Execution Pattern:**
```bash
# Create .sage script (NOT .py)
cat > solve_lwe.sage << 'EOF'
from fpylll import LLL, CVP
# ... lattice construction code ...
EOF

# Execute with SageMath (via Docker — sage not in apt)
bash /home/kali/Desktop/.windsurf/skills/ctf-crypto/sage_runner.sh solve_lwe.sage
```

See [advanced-math.md](advanced-math.md) for full LWE solving code and multi-layer patterns.

## ZKP & Constraint Solving

- **ZKP cheating:** For impossible problems (3-coloring K4), find hash collisions or predict PRNG salts
- **Graph 3-coloring:** `nx.coloring.greedy_color(G, strategy='saturation_largest_first')`
- **Z3 solver:** BitVec for bit-level, Int for arbitrary precision; BPF/SECCOMP filter solving
- **Garbled circuits (free XOR):** XOR three truth table entries to recover global delta
- **Bigram substitution:** OR-Tools CP-SAT with automaton constraint for known plaintext structure
- **Trigram decomposition:** Positions mod n form independent monoalphabetic ciphers
- **Shamir SSS (deterministic coefficients):** One share + seeded RNG = univariate equation in secret
- **Race condition (TOCTOU):** Synchronized concurrent requests bypass `counter < N` checks

See [zkp-and-advanced.md](zkp-and-advanced.md) for full code examples and solver patterns.

## Modern Cipher Attacks (Additional)

- **Affine over composite modulus:** `c = A*x+b (mod M)`, M composite (e.g., 65=5*13). Chosen-plaintext recovery via one-hot vectors, CRT inversion per prime factor. See [modern-ciphers.md](modern-ciphers.md#affine-cipher-over-composite-modulus-nullcon-2026).
- **Custom linear MAC forgery:** XOR-based signature linear in secret blocks. Recover secrets from ~5 known pairs, forge for target. See [modern-ciphers.md](modern-ciphers.md#custom-linear-mac-forgery-nullcon-2026).
- **Manger oracle (RSA threshold):** RSA multiplicative + binary search on `m*s < 2^128`. ~128 queries to recover AES key.

## Common Patterns

- **RSA basics:** `phi = (p-1)*(q-1)`, `d = inverse(e, phi)`, `m = pow(c, d, n)`. See [rsa-attacks.md](rsa-attacks.md) for full examples.
- **XOR:** `from pwn import xor; xor(ct, key)`. See [classic-ciphers.md](classic-ciphers.md) for XOR variants.

## Useful Tools

- **Python:** `pip install pycryptodome z3-solver sympy gmpy2 owiener`
- **SageMath:** `sage script.sage` (MANDATORY for ECC, Coppersmith, lattice attacks)
- **Local Factorization:** `yafu`, `msieve`, `cado-nfs` (offline alternatives to FactorDB)

## 🔧 Tool Selection Protocol

**CRITICAL:** Choose the RIGHT tool for the attack type:

| Attack Type | Tool | Command |
|-------------|------|----------|
| **Lattice (LWE, CVP, LLL)** | SageMath | `sage script.sage` |
| **Coppersmith (partial known)** | SageMath | `sage script.sage` |
| **ECC (Smart's, isogenies)** | SageMath | `sage script.sage` |
| **RSA factorization (offline)** | yafu/msieve | `yafu "factor(N)"` |
| **RSA small e/d** | Python (gmpy2) | `python3 script.py` |
| **Classic ciphers** | Python | `python3 script.py` |
| **Z3 constraints** | Python (z3-solver) | `python3 script.py` |

**⚠️ WARNING:** Using Python for Lattice/Coppersmith/ECC will FAIL. You MUST use SageMath.


---

# [Appended from ctf-arsenal: crypto-tools]

# Cryptography Tools and Techniques

## When to Use

Load this skill when:
- Solving cryptography CTF challenges
- Attacking weak RSA implementations
- Breaking classical ciphers (Caesar, Vigenere, XOR)
- Performing frequency analysis
- Analyzing encrypted data with unknown algorithms

## RSA Attacks

### Small Exponent Attack (e=3)

```python
#!/usr/bin/env python3
"""Attack RSA with small public exponent"""
import gmpy2

def small_e_attack(c, e, n):
    """
    If e is small (typically e=3) and message is short,
    we can take the e-th root directly
    """
    # Try taking e-th root
    for k in range(1000):
        m, exact = gmpy2.iroot(c + k * n, e)
        if exact:
            return int(m)
    return None

# Example
c = 12345678901234567890
e = 3
n = 98765432109876543210
m = small_e_attack(c, e, n)
if m:
    print(f"Message: {bytes.fromhex(hex(m)[2:])}")
```

### Wiener's Attack (Small Private Exponent)

```python
#!/usr/bin/env python3
"""Wiener's attack for small d"""
from fractions import Fraction

def wiener_attack(e, n):
    """
    Attack RSA when d < N^0.25
    Returns private key d if vulnerable
    """
    convergents = continued_fraction(Fraction(e, n))
    
    for k, d in convergents:
        if k == 0:
            continue
        
        phi = (e * d - 1) // k
        # Check if phi is valid
        s = n - phi + 1
        discr = s * s - 4 * n
        
        if discr >= 0:
            t = gmpy2.isqrt(discr)
            if t * t == discr and (s + t) % 2 == 0:
                return d
    return None

def continued_fraction(frac):
    """Generate continued fraction convergents"""
    convergents = []
    n, d = 0, 1
    
    for _ in range(1000):
        a = int(frac)
        convergents.append((n + a * 1, d + a * 1))
        
        frac = frac - a
        if frac == 0:
            break
        frac = 1 / frac
        
    return convergents
```

### Common Modulus Attack

```python
#!/usr/bin/env python3
"""Attack RSA when same message encrypted with different e, same N"""
import gmpy2

def common_modulus_attack(c1, c2, e1, e2, n):
    """
    Given:
    c1 = m^e1 mod n
    c2 = m^e2 mod n
    And gcd(e1, e2) = 1
    Recover m without knowing phi(n)
    """
    # Extended Euclidean algorithm
    gcd, s, t = gmpy2.gcdext(e1, e2)
    
    if gcd != 1:
        raise ValueError("e1 and e2 must be coprime")
    
    # Handle negative exponents
    if s < 0:
        c1 = gmpy2.invert(c1, n)
        s = -s
    if t < 0:
        c2 = gmpy2.invert(c2, n)
        t = -t
    
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return m
```

### Fermat's Factorization (Close Primes)

```python
#!/usr/bin/env python3
"""Fermat factorization when p and q are close"""
import gmpy2

def fermat_factor(n):
    """
    Factor n when p and q are close: |p - q| is small
    Much faster than trial division
    """
    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n
    
    for _ in range(1000000):
        b = gmpy2.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            return int(p), int(q)
        a += 1
        b2 = a * a - n
    
    return None, None

# Example
n = 123456789012345678901234567890
p, q = fermat_factor(n)
if p and q:
    print(f"p = {p}")
    print(f"q = {q}")
```

### RSA Common Template

```python
#!/usr/bin/env python3
"""Standard RSA operations"""
import gmpy2

def rsa_decrypt(c, d, n):
    """Decrypt ciphertext with private key"""
    m = pow(c, d, n)
    return m

def rsa_encrypt(m, e, n):
    """Encrypt message with public key"""
    c = pow(m, e, n)
    return c

def factor_n(p, q):
    """Compute n from primes"""
    return p * q

def compute_phi(p, q):
    """Compute Euler's totient"""
    return (p - 1) * (q - 1)

def compute_d(e, phi):
    """Compute private exponent from public exponent"""
    return int(gmpy2.invert(e, phi))

# Full RSA key recovery from factors
def recover_key_from_factors(p, q, e):
    """Given p, q, e, compute d"""
    n = factor_n(p, q)
    phi = compute_phi(p, q)
    d = compute_d(e, phi)
    return d, n

# Example
p = 1234567890123456789
q = 9876543210987654321
e = 65537

d, n = recover_key_from_factors(p, q, e)
print(f"n = {n}")
print(f"d = {d}")

# Decrypt
c = 12345678901234567890
m = rsa_decrypt(c, d, n)
print(f"Message: {m}")
```

## Classical Ciphers

### Caesar Cipher

```python
#!/usr/bin/env python3
"""Caesar cipher brute force"""

def caesar_decrypt(ciphertext, shift):
    """Decrypt Caesar cipher with given shift"""
    result = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

def caesar_bruteforce(ciphertext):
    """Try all 26 possible shifts"""
    print("Caesar Cipher Bruteforce:")
    for shift in range(26):
        plaintext = caesar_decrypt(ciphertext, shift)
        print(f"Shift {shift:2d}: {plaintext}")

# Example
ciphertext = "Khoor Zruog"
caesar_bruteforce(ciphertext)
```

### Vigenere Cipher

```python
#!/usr/bin/env python3
"""Vigenere cipher attack"""

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenere cipher"""
    result = ""
    key_index = 0
    key = key.upper()
    
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    
    return result

def guess_key_length(ciphertext):
    """Use Index of Coincidence to guess key length"""
    ic_values = []
    for key_len in range(1, 21):
        ic_sum = 0
        for i in range(key_len):
            substring = ciphertext[i::key_len]
            ic_sum += index_of_coincidence(substring)
        ic_values.append((key_len, ic_sum / key_len))
    
    # Sort by IC (higher is better, ~0.065 for English)
    ic_values.sort(key=lambda x: x[1], reverse=True)
    return ic_values[0][0]

def index_of_coincidence(text):
    """Calculate Index of Coincidence"""
    text = ''.join(c.upper() for c in text if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0
    
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic
```

### XOR Cipher

```python
#!/usr/bin/env python3
"""XOR cipher attacks"""

def xor_single_byte(data, key):
    """XOR data with single-byte key"""
    return bytes([b ^ key for b in data])

def xor_bruteforce_single_byte(ciphertext):
    """Bruteforce single-byte XOR key"""
    results = []
    for key in range(256):
        plaintext = xor_single_byte(ciphertext, key)
        score = english_score(plaintext)
        results.append((key, score, plaintext))
    
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:5]  # Top 5 candidates

def english_score(data):
    """Score text based on English letter frequency"""
    try:
        text = data.decode('ascii', errors='ignore').lower()
    except:
        return 0
    
    freq = {
        'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
        'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, ' ': 13.00,
    }
    
    score = sum(freq.get(c, 0) for c in text)
    return score / len(text) if len(text) > 0 else 0

def xor_repeating_key(data, key):
    """XOR data with repeating key"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def find_xor_key_length(ciphertext):
    """Find XOR key length using Hamming distance"""
    distances = []
    
    for keysize in range(2, 41):
        chunks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
        if len(chunks) < 4:
            continue
        
        # Compare first 4 chunks
        dist = 0
        comparisons = 0
        for i in range(3):
            dist += hamming_distance(chunks[i], chunks[i+1])
            comparisons += 1
        
        normalized_dist = dist / comparisons / keysize
        distances.append((keysize, normalized_dist))
    
    distances.sort(key=lambda x: x[1])
    return distances[0][0]

def hamming_distance(b1, b2):
    """Calculate Hamming distance between two byte strings"""
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))
```

## Frequency Analysis

```python
#!/usr/bin/env python3
"""Frequency analysis for ciphertexts"""
from collections import Counter

def frequency_analysis(text):
    """Analyze letter frequency in text"""
    # Clean text
    text = ''.join(c.upper() for c in text if c.isalpha())
    
    # Count frequencies
    freq = Counter(text)
    total = len(text)
    
    # Calculate percentages
    freq_percent = {char: (count / total) * 100 
                    for char, count in freq.items()}
    
    # Sort by frequency
    sorted_freq = sorted(freq_percent.items(), 
                        key=lambda x: x[1], reverse=True)
    
    # English reference frequencies
    english_freq = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
        'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
    }
    
    print("Frequency Analysis:")
    print("-" * 40)
    print("Char | Count | % | English %")
    print("-" * 40)
    for char, percent in sorted_freq[:10]:
        count = freq[char]
        eng = english_freq.get(char, 0)
        print(f"  {char}  | {count:5d} | {percent:5.2f} | {eng:5.2f}")
```

## Quick Reference

| Attack | Condition | Tool |
|--------|-----------|------|
| **Small e** | e=3, short message | `rsa_tool/small_e.py` |
| **Wiener** | d < N^0.25 | `rsa_tool/wiener.py` |
| **Common Modulus** | Same N, diff e | `rsa_tool/common_modulus.py` |
| **Fermat** | \|p-q\| small | `rsa_tool/fermat.py` |
| **Caesar** | Shift cipher | `classic/caesar.py` (bruteforce 26 shifts) |
| **Vigenere** | Repeating key | `classic/vigenere.py` (IC analysis) |
| **XOR Single** | 1-byte key | `classic/xor_single_byte.py` |
| **XOR Repeating** | Multi-byte key | `classic/xor_repeating_key.py` |

## Bundled Resources

### God-Mode Tools

- `helpers/rsa_autohack.py` - **RSA Auto-Hacker (Fast Triage)**
  - Small E, Wiener, Fermat attacks in one tool
  - Auto flag extraction with God-Mode regex
  - JSON output for AI integration
  - < 1 second execution time
- `helpers/factor_n.py` - **Offline-First Factorization Orchestrator**
  - Local-first chain: yafu -> msieve -> FactorDB fallback
  - Safe timeout handling and JSON output
- `helpers/rtaf_patterns.py` - **Competition Pattern Extractor**
  - Unified regex extraction for wrapper-style flags and 32-hex tokens
- `helpers/solve_crypto.py` - **Compatibility Wrapper**
  - Delegates to root `solve_crypto.py` to preserve old helper path calls
- `helpers/generate_solver.py` - **Scaffold Generator**
  - Generates challenge-specific Python/Sage solver templates

### Sage Templates

- `templates/coppersmith.sage` - partial-known prime / small-roots scaffold
- `templates/smart_attack.sage` - anomalous-curve Smart attack scaffold
- `templates/lwe_cvp.sage` - lattice CVP/Babai scaffold
- `templates/pohlig_hellman.sage` - smooth-order ECC DLP scaffold

### Setup Artifacts

- `requirements.txt` - Python dependency baseline
- `sage_requirements.txt` - optional Sage-side package list
- `setup_crypto_tools.sh` - one-command dependency bootstrap

### RSA Tools

- `rsa_tool/rsa_common.py` - Common RSA operations (encrypt/decrypt/factor)
- `rsa_tool/small_e.py` - Small public exponent attack (e=3)
- `rsa_tool/wiener.py` - Wiener's attack for small d
- `rsa_tool/common_modulus.py` - Common modulus attack
- `rsa_tool/fermat.py` - Fermat factorization for close primes

### Classical Ciphers

- `classic/caesar.py` - Caesar cipher bruteforce
- `classic/vigenere.py` - Vigenere cipher with IC analysis
- `classic/xor_single_byte.py` - Single-byte XOR bruteforce
- `classic/xor_repeating_key.py` - Multi-byte XOR key recovery
- `classic/frequency_analysis.py` - Letter frequency analysis tool

## External Tools

```bash
# RsaCtfTool (comprehensive RSA attack suite)
git clone https://github.com/Ganapati/RsaCtfTool.git
python3 RsaCtfTool.py -n <N> -e <E> --private

# CyberChef (web-based encoding/crypto tool)
# https://gchq.github.io/CyberChef/

# FactorDB (check if N is already factored)
# http://factordb.com/
```

## Keywords

cryptography, crypto, RSA, RSA attacks, small exponent, wiener attack, common modulus, fermat factorization, classical cipher, caesar cipher, vigenere cipher, XOR, XOR cipher, frequency analysis, index of coincidence, public key cryptography, modular arithmetic, CTF crypto

---



