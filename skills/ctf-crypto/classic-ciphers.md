# CTF Crypto - Elliptic Curve Attacks

## Table of Contents
- [Small Subgroup Attacks](#small-subgroup-attacks)
- [Invalid Curve Attacks](#invalid-curve-attacks)
- [Singular Curves](#singular-curves)
- [Smart's Attack (Anomalous Curves)](#smarts-attack-anomalous-curves)
- [ECC Fault Injection](#ecc-fault-injection)
- [Clock Group DLP via Pohlig-Hellman (LACTF 2026)](#clock-group-dlp-via-pohlig-hellman-lactf-2026)
- [ECDSA Nonce Reuse (BearCatCTF 2026)](#ecdsa-nonce-reuse-bearcatctf-2026)
- [Ed25519 Torsion Side Channel (BearCatCTF 2026)](#ed25519-torsion-side-channel-bearcatctf-2026)

---

## Small Subgroup Attacks

- Check curve order for small factors
- Pohlig-Hellman: solve DLP in small subgroups, combine with CRT

```python
# SageMath ECC basics
E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]  # generator
order = E.order()
```

---

## Invalid Curve Attacks

If point validation is missing, send points on weaker curves. Craft points with small-order subgroups to leak secret key bits.

---

## Singular Curves

If discriminant delta = 0, curve is singular. DLP becomes easy (maps to additive/multiplicative group).

---

## Smart's Attack (Anomalous Curves)

**When to use:** Curve order equals field characteristic p (anomalous curve). Solves ECDLP in O(1) via p-adic lifting.

**Detection:** `E.order() == p` — always check this first!

**SageMath (automatic):**
```python
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
# Sage's discrete_log handles anomalous curves automatically
secret = G.discrete_log(Q)
```

**Manual p-adic lift (when Sage's auto method fails):**
```python
def smart_attack(p, a, b, G, Q):
    E = EllipticCurve(GF(p), [a, b])
    Qp = pAdicField(p, 2)  # p-adic field with precision 2
    Ep = EllipticCurve(Qp, [a, b])

    # Lift points to p-adics
    Gp = Ep.lift_x(ZZ(G[0]), all=True)  # try both lifts
    Qp_point = Ep.lift_x(ZZ(Q[0]), all=True)

    for gp in Gp:
        for qp in Qp_point:
            try:
                # Multiply by p to get points in kernel of reduction
                pG = p * gp
                pQ = p * qp
                # Extract p-adic logarithm
                x_G = ZZ(pG[0] / pG[1]) / p  # or pG.xy()
                x_Q = ZZ(pQ[0] / pQ[1]) / p
                secret = ZZ(x_Q / x_G) % p
                if E(G) * secret == E(Q):
                    return secret
            except (ZeroDivisionError, ValueError):
                continue
    return None
```

**Multi-layer decryption after key recovery:** Challenge may wrap flag in AES-CBC + DES-CBC or similar — just busywork once the ECC key is recovered. Derive keys with SHA-256 of shared secret.

---

## ECC Fault Injection

**Pattern (Faulty Curves):** Bit flip during ECC computation reveals private key bits.

**Attack:** Compare correct vs faulty ciphertext, recover key bit-by-bit:
```python
# For each key bit position:
# If fault at bit i changes output -> key bit i affects computation
# Binary distinguisher: faulty_output == correct_output -> bit is 0
```

---

## Clock Group DLP via Pohlig-Hellman (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on unit circle group: x^2 + y^2 = 1 (mod p).

**Key facts:**
- Group law: (x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
- **Group order = p + 1** (not p - 1!)
- Isomorphic to GF(p^2)* elements of norm 1

**Group operations:**
```python
def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # identity
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**Recovering hidden prime p:**
```python
# Given points on the curve, p divides (x^2 + y^2 - 1)
from math import gcd
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
# May need to remove small factors
```

**Attack when p+1 is smooth:**
```python
# 1. Recover p from points: gcd(x^2 + y^2 - 1) across known points
# 2. Factor p+1 into small primes
# 3. Pohlig-Hellman: solve DLP in each small subgroup, CRT combine
# 4. Compute shared secret, derive AES key (e.g., via MD5)
```

**Identification:** Challenge mentions "clock", "circle", or gives points satisfying x^2+y^2=1. Always check if p+1 (not p-1) is smooth.

---

## Ed25519 Torsion Side Channel (BearCatCTF 2026)

**Pattern (Curvy Wurvy):** Ed25519 signing oracle derives per-user keys as `user_key = MASTER_KEY * uid mod l` (where `l` is the Ed25519 subgroup order). Goal: recover `MASTER_KEY` from oracle queries.

**The attack exploits Ed25519's cofactor h=8:**
- Full curve order = `8*l`, but scalars are reduced mod `l`
- When `MASTER_KEY * 2^t` wraps around `l`, multiplication produces a torsion component visible as y-coordinate change

**Key extraction via binary decomposition:**
```python
# Query sign(uid=3, 2^t) for t = 0..255
# S_t = (MASTER_KEY * 2^t mod l) * P3
# Check: does doubling S_t match S_{t+1}?

bits = []
for t in range(255):
    S_t = query_sign(3, 2**t)
    S_t1 = query_sign(3, 2**(t+1))
    doubled = point_double(S_t)
    # Wrap occurred if doubled.y != S_{t+1}.y (torsion shift)
    bits.append(0 if doubled.y == S_t1.y else 1)

# Reconstruct: MASTER_KEY ≈ l * (0.bit0 bit1 bit2 ...)_binary
# Try all 8 torsion corrections for exact value
```

**Key insight:** Ed25519's cofactor creates an observable side channel: when scalar multiplication wraps around the subgroup order `l`, the result shifts by a torsion element (one of 8 points). By querying powers of 2 and checking y-coordinate consistency, each bit of the secret scalar is leaked. Libraries like `ecpy` that reduce mod `l` are vulnerable to this when used in multi-user key derivation schemes.

**Detection:** Ed25519 signing oracle with user-controlled UID or multiplier. Key derivation formula `key = master * uid mod l`.

---

## ECDSA Nonce Reuse (BearCatCTF 2026)

**Pattern (Chatroom):** ECDSA signatures on secp256k1 with constant nonce `k`. When two signatures share the same `r` value, the nonce and private key are recoverable.

**Recovery:**
```python
from hashlib import sha256

# Two signatures (r, s1) and (r, s2) with same r → same nonce k
h1 = int(sha256(msg1).hexdigest(), 16)
h2 = int(sha256(msg2).hexdigest(), 16)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n  # private key
```

**Key insight:** Same `r` value across multiple ECDSA signatures means the nonce `k` was reused. This is the same class of bug that compromised the PlayStation 3 signing key. Always check for repeated `r` values in signature datasets.

**Detection:** Multiple ECDSA signatures with identical `r` component. Challenge mentions "nonce", "deterministic signing", or provides a signing oracle.


<!-- APPENDED FROM LATEST UPDATE: ctf-crypto/classic-ciphers.md -->

# CTF Crypto - Classic Ciphers

## Table of Contents
- [Vigenere Cipher](#vigenere-cipher)
- [Atbash Cipher](#atbash-cipher)
- [Substitution Cipher with Rotating Wheel](#substitution-cipher-with-rotating-wheel)
- [Kasiski Examination for Key Length](#kasiski-examination-for-key-length)
- [XOR Variants](#xor-variants)
  - [Multi-Byte XOR Key Recovery via Frequency Analysis](#multi-byte-xor-key-recovery-via-frequency-analysis)
  - [Cascade XOR (First-Byte Brute Force)](#cascade-xor-first-byte-brute-force)
  - [XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)](#xor-with-rotation-power-of-2-bit-isolation-pragyan-2026)
  - [Weak XOR Verification Brute Force (Pragyan 2026)](#weak-xor-verification-brute-force-pragyan-2026)
- [Deterministic OTP with Load-Balanced Backends (Pragyan 2026)](#deterministic-otp-with-load-balanced-backends-pragyan-2026)
- [OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)](#otp-key-reuse--many-time-pad-xor-bypass-ctf-2025)
- [Book Cipher](#book-cipher)
- [Variable-Length Homophonic Substitution (ASIS CTF Finals 2013)](#variable-length-homophonic-substitution-asis-ctf-finals-2013)

---

## Vigenere Cipher

**Known Plaintext Attack (most common in CTFs):**
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def derive_key(ciphertext, plaintext):
    """Derive key from known plaintext (e.g., flag format CCOI26{)"""
    key = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            c_val = ord(c.upper()) - ord('A')
            p_val = ord(p.upper()) - ord('A')
            key.append(chr((c_val - p_val) % 26 + ord('A')))
    return ''.join(key)
```

### Kasiski Examination for Key Length

When no known plaintext is available, determine the Vigenere key length using Kasiski examination: find repeated sequences in the ciphertext and compute the GCD of their distances.

```python
from math import gcd
from functools import reduce
from collections import Counter

def kasiski_examination(ciphertext, min_seq=3):
    """Find repeating sequences and compute likely key lengths."""
    ct = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []

    # Find repeated trigrams and their distances
    for seq_len in range(min_seq, 6):
        seen = {}
        for i in range(len(ct) - seq_len):
            seq = ct[i:i+seq_len]
            if seq in seen:
                for prev_pos in seen[seq]:
                    distances.append(i - prev_pos)
                seen[seq].append(i)
            else:
                seen[seq] = [i]

    # Key length is likely the GCD of distances
    if distances:
        key_len = reduce(gcd, distances)
        print(f"Likely key length: {key_len}")
        print(f"All distances: {sorted(set(distances))}")
        return key_len
    return None

def frequency_attack(ciphertext, key_length):
    """Break Vigenere by frequency analysis on each key-position group."""
    ct = [c.upper() for c in ciphertext if c.isalpha()]
    english_freq = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,
                   0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,
                   0.063,0.091,0.028,0.010,0.023,0.002,0.020,0.001]
    key = []

    for i in range(key_length):
        group = [ct[j] for j in range(i, len(ct), key_length)]
        # Try each shift, score by English letter frequency
        best_shift, best_score = 0, -1
        for shift in range(26):
            decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
            freq = Counter(decrypted)
            score = sum(freq.get(chr(j+65), 0) / len(group) * english_freq[j]
                       for j in range(26))
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('A')))

    return ''.join(key)
```

**Key insight:** Repeated sequences in Vigenere ciphertext occur at distances that are multiples of the key length. The GCD of all such distances reveals the key length, after which each position becomes a simple Caesar cipher solvable by frequency analysis.

**When standard keys don't work:**
1. Key may not repeat - could be as long as message
2. Key derived from challenge theme (character names, phrases)
3. Key may have "padding" - repeated letters (IICCHHAA instead of ICHA)
4. Try guessing plaintext words from theme, derive full key

---

## Atbash Cipher

Simple substitution: A<->Z, B<->Y, C<->X, etc.

```python
def atbash(text):
    return ''.join(
        chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isalpha() else c
        for c in text
    )
```

**Identification:** Challenge name hints ("Abashed" = Atbash), preserves spaces/punctuation, 1-to-1 substitution.

---

## Substitution Cipher with Rotating Wheel

**Pattern (Wheel of Mystery):** Physical cipher wheel with inner/outer alphabets.

**Automated solver:** Use [quipqiup.com](https://quipqiup.com/) for general substitution ciphers — it uses word pattern matching and language entropy to solve without knowing the key.

**Brute force all rotations:**
```python
outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
inner = "QNFUVWLEZYXPTKMR}ABJICOSDHG{"  # Given

for rotation in range(len(outer)):
    rotated = inner[rotation:] + inner[:rotation]
    mapping = {outer[i]: rotated[i] for i in range(len(outer))}
    decrypted = ''.join(mapping.get(c, c) for c in ciphertext)
    if decrypted.startswith("METACTF{"):
        print(decrypted)
```

---

## XOR Variants

### Multi-Byte XOR Key Recovery via Frequency Analysis

**Pattern:** Ciphertext XOR'd with a repeating multi-byte key. Key length unknown.

**Step 1 — Determine key length:** Try each candidate length, split ciphertext into groups by position modulo key length, score each group's byte frequency against English text (space = 0x20 is the most common byte).

**Step 2 — Recover each key byte:** For each position, brute-force all 256 byte values and select the one producing the most English-like decrypted text.

```python
from collections import Counter

def score_english(data):
    """Score how English-like a byte sequence is."""
    freq = Counter(data)
    # Space is the most common character in English text
    return freq.get(ord(' '), 0) + sum(freq.get(c, 0) for c in range(ord('a'), ord('z')+1))

def find_key_length(ciphertext, max_len=40):
    """Test key lengths by scoring single-byte XOR on each column."""
    best_len, best_score = 1, 0
    for kl in range(1, max_len + 1):
        total = 0
        for col in range(kl):
            group = ciphertext[col::kl]
            best_col_score = max(
                score_english(bytes(b ^ k for b in group))
                for k in range(256)
            )
            total += best_col_score
        if total > best_score:
            best_score = total
            best_len = kl
    return best_len

def recover_key(ciphertext, key_length):
    """Recover each key byte via frequency analysis."""
    key = []
    for col in range(key_length):
        group = ciphertext[col::key_length]
        best_k = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in group)))
        key.append(best_k)
    return bytes(key)

ct = open('encrypted.bin', 'rb').read()
kl = find_key_length(ct)
key = recover_key(ct, kl)
print(f"Key ({kl} bytes): {key}")
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

**Key insight:** Multi-byte repeating XOR splits into `key_length` independent single-byte XOR problems. English text frequency (especially space = 0x20) reliably identifies correct key bytes. Works best with ciphertext longer than ~100 bytes.

### Cascade XOR (First-Byte Brute Force)

**Pattern (Shifty XOR):** Each byte XORed with previous ciphertext byte.

```python
# c[i] = p[i] ^ c[i-1] (or similar cascade)
# Brute force first byte, rest follows deterministically
for first_byte in range(256):
    flag = [first_byte]
    for i in range(1, len(ct)):
        flag.append(ct[i] ^ flag[i-1])
    if all(32 <= b < 127 for b in flag):
        print(bytes(flag))
```

### XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)

**Pattern (R0tnoT13):** Given `S XOR ROTR(S, k)` for multiple rotation offsets k, recover S.

**Key insight:** When ALL rotation offsets are powers of 2 (2, 4, 8, 16, 32, 64), even-indexed and odd-indexed bits NEVER mix across any frame. This reduces N-bit recovery to just 2 bits of brute force.

**Algorithm:**
1. Express every bit of S in terms of two unknowns (s_0 for even bits, s_1 for odd bits) using the k=2 frame
2. Only 4 candidate states -> try all, verify against all frames
3. XOR valid state with ciphertext -> plaintext

### Weak XOR Verification Brute Force (Pragyan 2026)

**Pattern (Dor4_Null5):** Verification XORs all comparison bytes into a single byte instead of checking each individually.

**Vulnerability:** Any fixed response has 1/256 probability of passing. With enough interaction budget (e.g., 4919 attempts), brute-force succeeds with ~256 expected attempts.

```python
for attempt in range(3000):
    r.sendlineafter(b"prompt: ", b"00" * 8)  # Fixed zero response
    result = r.recvline()
    if b"successful" in result:
        break
```

---

## Deterministic OTP with Load-Balanced Backends (Pragyan 2026)

**Pattern (DumCows):** Service encrypts data with deterministic keystream that resets per connection. Multiple backends with different keystreams behind a load balancer.

**Attack:**
1. Send known plaintext (e.g., 18 bytes of 'A'), XOR with ciphertext -> recover keystream
2. XOR keystream with target ciphertext -> decrypt secret
3. **Backend matching:** Must connect to same backend for keystream to match. Retry connections until patterns align.

```python
def recover_keystream(known, ciphertext):
    return bytes(k ^ c for k, c in zip(known, ciphertext))

def decrypt(keystream, target_ct):
    return bytes(k ^ c for k, c in zip(keystream, target_ct))
```

**Key insight:** When encryption is deterministic per connection with no nonce/IV, known-plaintext attack is trivial. The challenge is matching backends.

---

## OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)

**Pattern (Once More Unto the Same Wind):** Two ciphertexts encrypted with the same OTP key. Known plaintext for one message enables recovery of the other.

**XOR property:** `C1 XOR C2 = P1 XOR P2` (key cancels). When one plaintext (P1) is known, recover the other: `P2 = C1 XOR C2 XOR P1`.

```python
from pwn import xor

c1 = bytes.fromhex("7713283f5e9979...")
c2 = bytes.fromhex("740b393f4c8b67...")

# If one plaintext is known (or guessable, e.g., padded 'A' chars)
known_plaintext = b"A" * len(c1)
flag = xor(xor(c1, c2), known_plaintext)
print(flag)
```

**When plaintext is unknown — crib dragging:**
```python
def crib_drag(c1, c2, crib, max_pos=None):
    """Slide known word across XOR of two ciphertexts."""
    xored = xor(c1[:min(len(c1), len(c2))], c2[:min(len(c1), len(c2))])
    for pos in range(len(xored) - len(crib)):
        candidate = xor(xored[pos:pos+len(crib)], crib)
        if all(32 <= b < 127 for b in candidate):
            print(f"pos {pos}: {candidate}")
```

**Key insight:** OTP (One-Time Pad) XOR encryption is only secure when the key is truly one-time. Reusing the key on two messages leaks `P1 XOR P2` — exploit with known plaintext or crib dragging.

---

## Book Cipher

**Pattern (Booking Key, Nullcon 2026):** Book cipher with "steps forward" encoding. Brute-force starting position with charset filtering reduces ~56k candidates to 3-4.

See [historical.md](historical.md) for full implementation.

---

## Variable-Length Homophonic Substitution (ASIS CTF Finals 2013)

**Pattern (Rookie Agent):** Ciphertext uses alphanumeric characters grouped in blocks of 5. Single-character frequency analysis shows non-uniform distribution. N-gram analysis reveals repeated multi-character groups mapping to single plaintext characters, with different plaintext characters encoded by groups of different lengths (1-4 characters).

**Analysis workflow:**

1. Collapse whitespace and compute n-gram frequencies (1 through 6):
```python
from collections import Counter

ct = "6di16ovhtmnzslsxqcjo8fkdmtyrbn..."  # cleaned ciphertext
for n in range(1, 7):
    ngrams = [ct[i:i+n] for i in range(len(ct)-n+1)]
    freq = Counter(ngrams).most_common(20)
    print(f"{n}-grams: {freq[:10]}")
```

2. Identify constant-frequency groups — if `8f`, `fk`, and `kd` each appear exactly 36 times, check whether `8fkd` also appears 36 times. If so, it is a single substitution unit:
```python
# Iteratively replace most-frequent fixed groups with single symbols
substitutions = {
    '8fkd': 'E', '4bg9': 'I', 'lsxq': 'A', 'fmrk': 'B',
    '9gle': 'C', 'mtyr': 'D', 'cjo': 'F', 'htm': 'G',
    # ... continue for all identified groups
}
reduced = ct
for pattern, symbol in sorted(substitutions.items(), key=lambda x: -len(x[0])):
    reduced = reduced.replace(pattern, symbol)
```

3. The reduced text is now a monoalphabetic substitution — solve with [quipqiup.com](https://quipqiup.com/) or statistical analysis on English.

4. When some characters remain ambiguous after decryption, brute-force permutations against a known hash of the flag:
```python
from itertools import permutations
from hashlib import sha256

partial_flag = '3c6a1c371b381c943065864b95ae5546'
ambiguous_chars = '12456789x'  # chars with uncertain mapping
known_hash = '9f2a579716af14400c9ba1de8682ca52c17b3ed4235ea17ac12ae78ca24876ef'

for p in permutations(ambiguous_chars):
    mapping = dict(zip(ambiguous_chars, p))
    candidate = ''.join(mapping.get(c, c) for c in partial_flag)
    if sha256(('ASIS_' + candidate).encode()).hexdigest() == known_hash:
        print(f"Flag: ASIS_{candidate}")
        break
```

**Key insight:** Variable-length homophonic substitution hides letter frequencies by mapping common plaintext letters to longer codegroups. The attack reverses this: find n-grams that always appear as a unit (identical frequency for all sub-n-grams), replace them with single symbols, then solve the resulting monoalphabetic substitution. When the flag format provides a hash for verification, brute-force remaining ambiguous character permutations offline.


<!-- APPENDED FROM LATEST UPDATE: ctf-crypto/classic-ciphers.md -->

# CTF Crypto - Classic Ciphers

## Table of Contents
- [Vigenere Cipher](#vigenere-cipher)
- [Atbash Cipher](#atbash-cipher)
- [Substitution Cipher with Rotating Wheel](#substitution-cipher-with-rotating-wheel)
- [Kasiski Examination for Key Length](#kasiski-examination-for-key-length)
- [XOR Variants](#xor-variants)
  - [Multi-Byte XOR Key Recovery via Frequency Analysis](#multi-byte-xor-key-recovery-via-frequency-analysis)
  - [Cascade XOR (First-Byte Brute Force)](#cascade-xor-first-byte-brute-force)
  - [XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)](#xor-with-rotation-power-of-2-bit-isolation-pragyan-2026)
  - [Weak XOR Verification Brute Force (Pragyan 2026)](#weak-xor-verification-brute-force-pragyan-2026)
- [Deterministic OTP with Load-Balanced Backends (Pragyan 2026)](#deterministic-otp-with-load-balanced-backends-pragyan-2026)
- [OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)](#otp-key-reuse--many-time-pad-xor-bypass-ctf-2025)
- [Book Cipher](#book-cipher)
- [Variable-Length Homophonic Substitution (ASIS CTF Finals 2013)](#variable-length-homophonic-substitution-asis-ctf-finals-2013)

---

## Vigenere Cipher

**Known Plaintext Attack (most common in CTFs):**
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def derive_key(ciphertext, plaintext):
    """Derive key from known plaintext (e.g., flag format CCOI26{)"""
    key = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            c_val = ord(c.upper()) - ord('A')
            p_val = ord(p.upper()) - ord('A')
            key.append(chr((c_val - p_val) % 26 + ord('A')))
    return ''.join(key)
```

### Kasiski Examination for Key Length

When no known plaintext is available, determine the Vigenere key length using Kasiski examination: find repeated sequences in the ciphertext and compute the GCD of their distances.

```python
from math import gcd
from functools import reduce
from collections import Counter

def kasiski_examination(ciphertext, min_seq=3):
    """Find repeating sequences and compute likely key lengths."""
    ct = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []

    # Find repeated trigrams and their distances
    for seq_len in range(min_seq, 6):
        seen = {}
        for i in range(len(ct) - seq_len):
            seq = ct[i:i+seq_len]
            if seq in seen:
                for prev_pos in seen[seq]:
                    distances.append(i - prev_pos)
                seen[seq].append(i)
            else:
                seen[seq] = [i]

    # Key length is likely the GCD of distances
    if distances:
        key_len = reduce(gcd, distances)
        print(f"Likely key length: {key_len}")
        print(f"All distances: {sorted(set(distances))}")
        return key_len
    return None

def frequency_attack(ciphertext, key_length):
    """Break Vigenere by frequency analysis on each key-position group."""
    ct = [c.upper() for c in ciphertext if c.isalpha()]
    english_freq = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,
                   0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,
                   0.063,0.091,0.028,0.010,0.023,0.002,0.020,0.001]
    key = []

    for i in range(key_length):
        group = [ct[j] for j in range(i, len(ct), key_length)]
        # Try each shift, score by English letter frequency
        best_shift, best_score = 0, -1
        for shift in range(26):
            decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
            freq = Counter(decrypted)
            score = sum(freq.get(chr(j+65), 0) / len(group) * english_freq[j]
                       for j in range(26))
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('A')))

    return ''.join(key)
```

**Key insight:** Repeated sequences in Vigenere ciphertext occur at distances that are multiples of the key length. The GCD of all such distances reveals the key length, after which each position becomes a simple Caesar cipher solvable by frequency analysis.

**When standard keys don't work:**
1. Key may not repeat - could be as long as message
2. Key derived from challenge theme (character names, phrases)
3. Key may have "padding" - repeated letters (IICCHHAA instead of ICHA)
4. Try guessing plaintext words from theme, derive full key

---

## Atbash Cipher

Simple substitution: A<->Z, B<->Y, C<->X, etc.

```python
def atbash(text):
    return ''.join(
        chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isalpha() else c
        for c in text
    )
```

**Identification:** Challenge name hints ("Abashed" = Atbash), preserves spaces/punctuation, 1-to-1 substitution.

---

## Substitution Cipher with Rotating Wheel

**Pattern (Wheel of Mystery):** Physical cipher wheel with inner/outer alphabets.

**Automated solver:** Use [quipqiup.com](https://quipqiup.com/) for general substitution ciphers — it uses word pattern matching and language entropy to solve without knowing the key.

**Brute force all rotations:**
```python
outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
inner = "QNFUVWLEZYXPTKMR}ABJICOSDHG{"  # Given

for rotation in range(len(outer)):
    rotated = inner[rotation:] + inner[:rotation]
    mapping = {outer[i]: rotated[i] for i in range(len(outer))}
    decrypted = ''.join(mapping.get(c, c) for c in ciphertext)
    if decrypted.startswith("METACTF{"):
        print(decrypted)
```

---

## XOR Variants

### Multi-Byte XOR Key Recovery via Frequency Analysis

**Pattern:** Ciphertext XOR'd with a repeating multi-byte key. Key length unknown.

**Step 1 — Determine key length:** Try each candidate length, split ciphertext into groups by position modulo key length, score each group's byte frequency against English text (space = 0x20 is the most common byte).

**Step 2 — Recover each key byte:** For each position, brute-force all 256 byte values and select the one producing the most English-like decrypted text.

```python
from collections import Counter

def score_english(data):
    """Score how English-like a byte sequence is."""
    freq = Counter(data)
    # Space is the most common character in English text
    return freq.get(ord(' '), 0) + sum(freq.get(c, 0) for c in range(ord('a'), ord('z')+1))

def find_key_length(ciphertext, max_len=40):
    """Test key lengths by scoring single-byte XOR on each column."""
    best_len, best_score = 1, 0
    for kl in range(1, max_len + 1):
        total = 0
        for col in range(kl):
            group = ciphertext[col::kl]
            best_col_score = max(
                score_english(bytes(b ^ k for b in group))
                for k in range(256)
            )
            total += best_col_score
        if total > best_score:
            best_score = total
            best_len = kl
    return best_len

def recover_key(ciphertext, key_length):
    """Recover each key byte via frequency analysis."""
    key = []
    for col in range(key_length):
        group = ciphertext[col::key_length]
        best_k = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in group)))
        key.append(best_k)
    return bytes(key)

ct = open('encrypted.bin', 'rb').read()
kl = find_key_length(ct)
key = recover_key(ct, kl)
print(f"Key ({kl} bytes): {key}")
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

**Key insight:** Multi-byte repeating XOR splits into `key_length` independent single-byte XOR problems. English text frequency (especially space = 0x20) reliably identifies correct key bytes. Works best with ciphertext longer than ~100 bytes.

### Cascade XOR (First-Byte Brute Force)

**Pattern (Shifty XOR):** Each byte XORed with previous ciphertext byte.

```python
# c[i] = p[i] ^ c[i-1] (or similar cascade)
# Brute force first byte, rest follows deterministically
for first_byte in range(256):
    flag = [first_byte]
    for i in range(1, len(ct)):
        flag.append(ct[i] ^ flag[i-1])
    if all(32 <= b < 127 for b in flag):
        print(bytes(flag))
```

### XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)

**Pattern (R0tnoT13):** Given `S XOR ROTR(S, k)` for multiple rotation offsets k, recover S.

**Key insight:** When ALL rotation offsets are powers of 2 (2, 4, 8, 16, 32, 64), even-indexed and odd-indexed bits NEVER mix across any frame. This reduces N-bit recovery to just 2 bits of brute force.

**Algorithm:**
1. Express every bit of S in terms of two unknowns (s_0 for even bits, s_1 for odd bits) using the k=2 frame
2. Only 4 candidate states -> try all, verify against all frames
3. XOR valid state with ciphertext -> plaintext

### Weak XOR Verification Brute Force (Pragyan 2026)

**Pattern (Dor4_Null5):** Verification XORs all comparison bytes into a single byte instead of checking each individually.

**Vulnerability:** Any fixed response has 1/256 probability of passing. With enough interaction budget (e.g., 4919 attempts), brute-force succeeds with ~256 expected attempts.

```python
for attempt in range(3000):
    r.sendlineafter(b"prompt: ", b"00" * 8)  # Fixed zero response
    result = r.recvline()
    if b"successful" in result:
        break
```

---

## Deterministic OTP with Load-Balanced Backends (Pragyan 2026)

**Pattern (DumCows):** Service encrypts data with deterministic keystream that resets per connection. Multiple backends with different keystreams behind a load balancer.

**Attack:**
1. Send known plaintext (e.g., 18 bytes of 'A'), XOR with ciphertext -> recover keystream
2. XOR keystream with target ciphertext -> decrypt secret
3. **Backend matching:** Must connect to same backend for keystream to match. Retry connections until patterns align.

```python
def recover_keystream(known, ciphertext):
    return bytes(k ^ c for k, c in zip(known, ciphertext))

def decrypt(keystream, target_ct):
    return bytes(k ^ c for k, c in zip(keystream, target_ct))
```

**Key insight:** When encryption is deterministic per connection with no nonce/IV, known-plaintext attack is trivial. The challenge is matching backends.

---

## OTP Key Reuse / Many-Time Pad XOR (BYPASS CTF 2025)

**Pattern (Once More Unto the Same Wind):** Two ciphertexts encrypted with the same OTP key. Known plaintext for one message enables recovery of the other.

**XOR property:** `C1 XOR C2 = P1 XOR P2` (key cancels). When one plaintext (P1) is known, recover the other: `P2 = C1 XOR C2 XOR P1`.

```python
from pwn import xor

c1 = bytes.fromhex("7713283f5e9979...")
c2 = bytes.fromhex("740b393f4c8b67...")

# If one plaintext is known (or guessable, e.g., padded 'A' chars)
known_plaintext = b"A" * len(c1)
flag = xor(xor(c1, c2), known_plaintext)
print(flag)
```

**When plaintext is unknown — crib dragging:**
```python
def crib_drag(c1, c2, crib, max_pos=None):
    """Slide known word across XOR of two ciphertexts."""
    xored = xor(c1[:min(len(c1), len(c2))], c2[:min(len(c1), len(c2))])
    for pos in range(len(xored) - len(crib)):
        candidate = xor(xored[pos:pos+len(crib)], crib)
        if all(32 <= b < 127 for b in candidate):
            print(f"pos {pos}: {candidate}")
```

**Key insight:** OTP (One-Time Pad) XOR encryption is only secure when the key is truly one-time. Reusing the key on two messages leaks `P1 XOR P2` — exploit with known plaintext or crib dragging.

---

## Book Cipher

**Pattern (Booking Key, Nullcon 2026):** Book cipher with "steps forward" encoding. Brute-force starting position with charset filtering reduces ~56k candidates to 3-4.

See [historical.md](historical.md) for full implementation.

---

## Variable-Length Homophonic Substitution (ASIS CTF Finals 2013)

**Pattern (Rookie Agent):** Ciphertext uses alphanumeric characters grouped in blocks of 5. Single-character frequency analysis shows non-uniform distribution. N-gram analysis reveals repeated multi-character groups mapping to single plaintext characters, with different plaintext characters encoded by groups of different lengths (1-4 characters).

**Analysis workflow:**

1. Collapse whitespace and compute n-gram frequencies (1 through 6):
```python
from collections import Counter

ct = "6di16ovhtmnzslsxqcjo8fkdmtyrbn..."  # cleaned ciphertext
for n in range(1, 7):
    ngrams = [ct[i:i+n] for i in range(len(ct)-n+1)]
    freq = Counter(ngrams).most_common(20)
    print(f"{n}-grams: {freq[:10]}")
```

2. Identify constant-frequency groups — if `8f`, `fk`, and `kd` each appear exactly 36 times, check whether `8fkd` also appears 36 times. If so, it is a single substitution unit:
```python
# Iteratively replace most-frequent fixed groups with single symbols
substitutions = {
    '8fkd': 'E', '4bg9': 'I', 'lsxq': 'A', 'fmrk': 'B',
    '9gle': 'C', 'mtyr': 'D', 'cjo': 'F', 'htm': 'G',
    # ... continue for all identified groups
}
reduced = ct
for pattern, symbol in sorted(substitutions.items(), key=lambda x: -len(x[0])):
    reduced = reduced.replace(pattern, symbol)
```

3. The reduced text is now a monoalphabetic substitution — solve with [quipqiup.com](https://quipqiup.com/) or statistical analysis on English.

4. When some characters remain ambiguous after decryption, brute-force permutations against a known hash of the flag:
```python
from itertools import permutations
from hashlib import sha256

partial_flag = '3c6a1c371b381c943065864b95ae5546'
ambiguous_chars = '12456789x'  # chars with uncertain mapping
known_hash = '9f2a579716af14400c9ba1de8682ca52c17b3ed4235ea17ac12ae78ca24876ef'

for p in permutations(ambiguous_chars):
    mapping = dict(zip(ambiguous_chars, p))
    candidate = ''.join(mapping.get(c, c) for c in partial_flag)
    if sha256(('ASIS_' + candidate).encode()).hexdigest() == known_hash:
        print(f"Flag: ASIS_{candidate}")
        break
```

**Key insight:** Variable-length homophonic substitution hides letter frequencies by mapping common plaintext letters to longer codegroups. The attack reverses this: find n-grams that always appear as a unit (identical frequency for all sub-n-grams), replace them with single symbols, then solve the resulting monoalphabetic substitution. When the flag format provides a hash for verification, brute-force remaining ambiguous character permutations offline.
