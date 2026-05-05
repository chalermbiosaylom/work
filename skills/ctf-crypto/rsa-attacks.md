# CTF Crypto - ZKP, Solvers & Advanced Techniques

## Table of Contents
- [ZKP Attacks](#zkp-attacks)
- [Graph 3-Coloring](#graph-3-coloring)
- [Z3 SMT Solver Guide](#z3-smt-solver-guide)
- [Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)](#garbled-circuits-free-xor-delta-recovery-lactf-2026)
- [Bigram/Trigram Substitution -> Constraint Solving (LACTF 2026)](#bigramtrigram-substitution---constraint-solving-lactf-2026)
- [Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)](#shamir-secret-sharing-with-deterministic-coefficients-lactf-2026)
- [Race Condition in Crypto-Protected Endpoints (LACTF 2026)](#race-condition-in-crypto-protected-endpoints-lactf-2026)
- [Garbled Circuits: AES Key Recovery via Metadata Leakage (srdnlenCTF 2026)](#garbled-circuits-aes-key-recovery-via-metadata-leakage-srdnlenctf-2026)
- [Post-Quantum Signature Fault Injection: MAYO (srdnlenCTF 2026)](#post-quantum-signature-fault-injection-mayo-srdnlenctf-2026)
- [Lattice-Based Threshold Signature Attack: FROST (srdnlenCTF 2026)](#lattice-based-threshold-signature-attack-frost-srdnlenctf-2026)
- [Groth16 Broken Trusted Setup — delta == gamma (DiceCTF 2026)](#groth16-broken-trusted-setup--delta--gamma-dicectf-2026)
- [Groth16 Proof Replay — Unconstrained Nullifier (DiceCTF 2026)](#groth16-proof-replay--unconstrained-nullifier-dicectf-2026)
- [DV-SNARG Forgery via Verifier Oracle (DiceCTF 2026)](#dv-snarg-forgery-via-verifier-oracle-dicectf-2026)
- [KZG Pairing Oracle for Permutation Recovery (UNbreakable 2026)](#kzg-pairing-oracle-for-permutation-recovery-unbreakable-2026)

---

## ZKP Attacks

- Look for information leakage in proofs
- If proving IMPOSSIBLE problem (e.g., 3-coloring K4), you must cheat
- Find hash collisions to commit to one value but reveal another
- PRNG state recovery: salts generated from seeded PRNG can be predicted
- Small domain brute force: if you know `commit(i) = sha256(salt(i), color(i))` and have salt, brute all colors

---

## Graph 3-Coloring

```python
import networkx as nx
nx.coloring.greedy_color(G, strategy='saturation_largest_first')
```

---

## Z3 SMT Solver Guide

Z3 solves constraint satisfaction - useful when crypto reduces to finding values satisfying conditions.

**Basic usage:**
```python
from z3 import *

# Boolean variables (for bit-level problems)
bits = [Bool(f'b{i}') for i in range(64)]

# Integer/bitvector variables
x = BitVec('x', 32)  # 32-bit bitvector
y = Int('y')         # arbitrary precision int

solver = Solver()
solver.add(x ^ 0xdeadbeef == 0x12345678)
solver.add(y > 100, y < 200)

if solver.check() == sat:
    model = solver.model()
    print(model.eval(x))
```

**BPF/SECCOMP filter solving:**

When challenges use BPF bytecode for flag validation (e.g., custom syscall handlers):

```python
from z3 import *

# Model flag as array of 4-byte chunks (how BPF sees it)
flag = [BitVec(f'f{i}', 32) for i in range(14)]
s = Solver()

# Constraint: printable ASCII
for f in flag:
    for byte in range(4):
        b = (f >> (byte * 8)) & 0xff
        s.add(b >= 0x20, b < 0x7f)

# Extract constraints from BPF dump (seccomp-tools dump ./binary)
mem = [BitVec(f'm{i}', 32) for i in range(16)]

# Example BPF constraint reconstruction
s.add(mem[0] == flag[0])
s.add(mem[1] == mem[0] ^ flag[1])
s.add(mem[4] == mem[0] + mem[1] + mem[2] + mem[3])
s.add(mem[8] == 4127179254)  # From BPF if statement

if s.check() == sat:
    m = s.model()
    flag_bytes = b''
    for f in flag:
        val = m[f].as_long()
        flag_bytes += val.to_bytes(4, 'little')
    print(flag_bytes.decode())
```

**Converting bits to flag:**
```python
from Crypto.Util.number import long_to_bytes

if solver.check() == sat:
    model = solver.model()
    flag_bits = ''.join('1' if model.eval(b) else '0' for b in bits)
    print(long_to_bytes(int(flag_bits, 2)))
```

**When to use Z3:**
- Type system constraints (OCaml GADTs, Haskell types)
- Custom hash/cipher with algebraic structure
- Equation systems over finite fields
- Boolean satisfiability encoded in challenge
- Constraint propagation puzzles

---

## Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)

**Pattern (sisyphus):** Yao's garbled circuit with free XOR optimization. Circuit designed so normal evaluation only reaches one wire label, but the other is needed.

**Free XOR property:** Wire labels satisfy `W_0 XOR W_1 = delta` for global secret delta.

**Attack:** XOR three of four encrypted truth table entries to cancel AES terms:
```python
# Encrypted rows: E_i = AES(key_a_i XOR key_b_i, G_out_f(a,b))
# XOR of three rows where AES inputs differ by delta causes cancellation
# Reveals delta directly, then compute: W_1 = W_0 XOR delta
```

**General lesson:** In garbled circuits, if you can obtain any two labels for the same wire, you recover delta and can compute all labels.

---

## Bigram/Trigram Substitution -> Constraint Solving (LACTF 2026)

**Pattern (lazy-bigrams):** Bigram substitution cipher where plaintext has known structure (NATO phonetic alphabet).

**OR-Tools CP-SAT approach:**
1. Model substitution as injective mapping (IntVar per bigram)
2. Add crib constraints from known flag prefix
3. Add **regular language constraint** (automaton) for valid NATO word sequences
4. Solver finds unique solution

**Pattern (not-so-lazy-trigrams):** "Trigram substitution" that decomposes into three independent monoalphabetic ciphers on positions mod 3.

**Decomposition insight:** If cipher uses `shuffle[pos % n][char]`, each residue class `pos = k (mod n)` is an independent monoalphabetic substitution. Solve each separately with frequency analysis or known-plaintext.

---

## Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)

**Pattern (spreading-secrets):** Coefficients `a_1...a_9` are deterministic functions of secret s (via RNG seeded with s). One share (x_0, y_0) is revealed.

**Vulnerability:** Given one share, the equation `y_0 = s + g(s)*x_0 + g^2(s)*x_0^2 + ... + g^9(s)*x_0^9` is **univariate** in s.

**Root-finding via Frobenius:**
```python
# In GF(p), find roots of h(s) via gcd with x^p - x
# h(s) = s + g(s)*x_0 + ... + g^9(s)*x_0^9 - y_0
# Compute x^p mod h(x) via binary exponentiation with polynomial reduction
# gcd(x^p - x, h(x)) = product of (x - root_i) for all roots
R.<x> = PolynomialRing(GF(p))
h = construct_polynomial(x0, y0)
xp = pow(x, p, h)  # Fast modular exponentiation
g = gcd(xp - x, h)  # Extract linear factors
roots = [-g[0]/g[1]] if g.degree() == 1 else g.roots()
```

**General lesson:** If ALL Shamir coefficients are derived from the secret, a single share creates a univariate equation. This completely breaks the (k,n) threshold scheme.

---

## Race Condition in Crypto-Protected Endpoints (LACTF 2026)

**Pattern (misdirection):** Endpoint has TOCTOU vulnerability: `if counter < 4` check happens before increment, allowing concurrent requests to all pass the check.

**Exploitation:**
1. **Cache-bust signatures:** Modify each request slightly (e.g., prepend zeros to nonce) so server can't use cached verification results
2. **Synchronize requests:** Use multiprocessing with barrier to send ~80 simultaneous requests
3. All pass `counter < 4` check before any increments -> counter jumps past limit

```python
from multiprocessing import Process, Barrier
barrier = Barrier(80)

def make_request(barrier, modified_sig):
    barrier.wait()  # Synchronize all processes
    requests.post(url, json={"sig": modified_sig})

# Launch 80 processes with unique signature modifications
processes = [Process(target=make_request, args=(barrier, modify_sig(i))) for i in range(80)]
```

**Key insight:** TOCTOU in `check-then-act` patterns. Look for read-modify-write without atomicity/locking.

---

## Garbled Circuits: AES Key Recovery via Metadata Leakage (srdnlenCTF 2026)

**Pattern (FHAES):** Service evaluates AES via garbled circuits with a fixed per-connection key. Exploit garbling metadata rather than AES cryptanalysis.

**Attack:**
1. Construct a custom circuit with one attacker-controlled AND gate that leaks the global Free-XOR offset delta
2. Use delta to locally evaluate the key-schedule section (first 1360 AND gates) as the evaluator
3. For each of the first 16 key-schedule S-box calls, brute-force the input byte by re-garbling the S-box chunk and comparing observed AND tables
4. Reconstruct key words from S-box outputs and recover the full 128-bit key through algebraic manipulation of the AES-128 schedule recurrence

```python
def garble_and(A, B, D, and_idx):
    """Reproduce garbling with proper parity handling."""
    r = B & 1
    alpha = A & 1
    beta = B & 1
    # Computes gate0, gate1, z output via hash-based approach
    return gate0, gate1, z

def evaluator_and(A, B, gate0, gate1, and_idx):
    """Evaluate AND gate using hash-based approach."""
    hashA = h_wire(A, and_idx)
    hashB = h_wire(B, and_idx)
    L = hashA if (A & 1) == 0 else (hashA ^ gate0)
    R = hashB if (B & 1) == 0 else (hashB ^ gate1)
    return L ^ R ^ (A * (B & 1))
```

**Key insight:** Garbled circuits that use free XOR optimization with fixed keys across sessions leak key material through the AND gate truth tables. Each S-box has a small enough input space (256 values) to brute-force when you know delta. This extends the LACTF technique from "recovering delta" to "recovering the entire AES key."

---

## Post-Quantum Signature Fault Injection: MAYO (srdnlenCTF 2026)

**Pattern (Faulty Mayo):** One-byte fault injection window in `mayo_sign_signature` before final `s = v + O*x` construction. Controlled bit flips across 64 signature queries recover the secret matrix O row by row.

**Attack:**
1. Reverse binary to map fault offsets to `mayo_sign_signature` instructions
2. For each of 64 rows of secret matrix O, use faulted signatures to extract linear equations over GF(16)
3. Solve 17-variable linear systems over GF(16) for each row using Gaussian elimination
4. Rebuild equivalent signer using recovered O and public seed from compressed public key
5. Forge valid signature for challenge message

**GF(16) Gaussian elimination:**
```python
# Precompute multiplication and inverse tables for GF(16)
# GF(16) = GF(2)[x] / (x^4 + x + 1), elements 0-15
INV = [0] * 16  # multiplicative inverses
MUL = [[0]*16 for _ in range(16)]  # multiplication table

def solve_linear_gf16(equations, nvars=17):
    """Gaussian elimination over GF(16)."""
    A = [x[:] + [y] for x, y in equations]
    m, row = len(A), 0
    for col in range(nvars):
        piv = next((r for r in range(row, m) if A[r][col] != 0), None)
        if piv is None: continue
        A[row], A[piv] = A[piv], A[row]
        invp = INV[A[row][col]]
        A[row] = [MUL[invp][v] for v in A[row]]
        for r in range(m):
            if r != row and A[r][col] != 0:
                f = A[r][col]
                A[r] = [A[r][c] ^ MUL[f][A[row][c]] for c in range(nvars + 1)]
        row += 1
    return [A[i][nvars] for i in range(nvars)]
```

**Key insight:** Post-quantum signature schemes like MAYO can be broken with fault injection if you can cause controlled bit flips during signing. Each fault creates a linear equation over GF(16), and 17+ equations per row suffice to recover the secret. This is analogous to DFA on classical schemes but over extension fields.

---

## Lattice-Based Threshold Signature Attack: FROST (srdnlenCTF 2026)

**Pattern (Threshold):** Preprocessing queue capacity allows collecting many signatures. Fixed challenge construction enables solving 1D noisy linear equations per coefficient.

**Attack:**
1. Exploit queue-depth cap (≤8 active) rather than total-usage cap by alternating menu options
2. Force fixed challenge `c` by choosing commitment `w₀` each query to zero aggregate commitment before high-bit extraction
3. With fixed `c`, each coefficient becomes: `z = λ·u + noise (mod q)`
4. Select multiple signer subsets to obtain different Lagrange coefficient scales (small/mid/huge) for each target signer
5. Solve via interval intersection and maximum-likelihood selection
6. Recover 7 signer shares; combine with own share; reconstruct master secret via Lagrange interpolation

**Interval intersection algorithm:**
```python
from math import ceil, floor

def intersect_intervals(intervals, lam, z, q, B):
    """Refine candidate intervals using one (λ, z) observation with noise bound B."""
    out = []
    for lo, hi in intervals:
        if lam > 0:
            kmin = ceil((lam * lo - z - B) / q)
            kmax = floor((lam * hi - z + B) / q)
            for k in range(kmin, kmax + 1):
                a = (z + q * k - B) / lam
                b = (z + q * k + B) / lam
                lo2, hi2 = max(lo, a), min(hi, b)
                if lo2 <= hi2:
                    out.append((lo2, hi2))
    # Merge overlapping intervals
    out.sort()
    merged = [out[0]] if out else []
    for lo, hi in out[1:]:
        if lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged
```

**Key insight:** Threshold signature schemes can leak individual shares when the challenge value is controlled. By querying with different signer subsets, you get different Lagrange coefficient scales for the same unknown share, allowing iterative interval refinement. With enough observations, the interval converges to a unique value.

---

## Groth16 Broken Trusted Setup — delta == gamma (DiceCTF 2026)

**Pattern (Housing Crisis):** Groth16 verifier has `vk_delta_2 == vk_gamma_2`, which breaks soundness entirely. Proofs are trivially forgeable.

**Forgery:**
```python
from py_ecc.bn128 import G1, G2, multiply, add, neg, pairing
from py_ecc.bn128 import curve_order as q

# When delta == gamma, the pairing equation simplifies:
# e(A, B) = e(alpha, beta) * e(vk_x + C, gamma)
# Set A = vk_alpha1, B = vk_beta2, then:
# e(alpha, beta) * e(vk_x + C, gamma) = e(alpha, beta)
# → e(vk_x + C, gamma) = 1 → C = -vk_x (point negation)

forged_A = vk_alpha1   # alpha point from verification key
forged_B = vk_beta2    # beta point from verification key
forged_C = neg(vk_x)   # negate the public input accumulator

# This proof verifies for ANY public inputs
```

**Detection:** Compare `vk_delta_2` and `vk_gamma_2` in the verifier contract. If equal, the entire Groth16 scheme collapses — any statement can be "proven."

**When to check:** Always inspect Groth16 verification key constants before attempting complex attacks. A broken trusted setup makes everything else unnecessary.

---

## Groth16 Proof Replay — Unconstrained Nullifier (DiceCTF 2026)

**Pattern (Housing Crisis):** DAO governance never tracks used `proposalNullifierHash` values, and the circuit leaves the nullifier unconstrained. A valid proof from the setup transaction can be replayed infinitely.

**Attack:**
1. Find the DAO contract's deployment/setup transaction
2. Extract constructor arguments containing valid Groth16 proof
3. Replay the same proof for every proposal — it always verifies
4. Use proposals to control DAO actions (betting, market creation, resolution)

**Key insight:** ZK circuits that leave inputs unconstrained and systems that don't track nullifiers are vulnerable to replay. Always check: does the verifier contract track proof nullifiers? Does the circuit actually constrain all declared public inputs?

---

## DV-SNARG Forgery via Verifier Oracle (DiceCTF 2026)

**Pattern (Dot):** DV-SNARG (Designated Verifier Succinct Non-interactive ARGument) for an adder circuit. Must produce 20 valid proofs for **wrong** answers.

**Key insight:** DV-SNARGs explicitly lose soundness when the prover has oracle access to the verifier (ePrint 2024/1138). The verifier's secret randomness can be extracted through query patterns.

**DPP (Dot Product Proof) structure:**
```text
q[i] = v[i] + b*(tensor[i] - constraint[i])
where b = fixed constant (e.g., 162817)
      v[i] = random in [-256, 256]
      constraint weights r = random in [-2^40, 2^40]
```

**Forgery via CRS entry cancellation:**
For a wrong answer, only the output constraint (wire N) is violated. Find two CRS entries whose constraint contributions cancel:

1. Wire N is touched by gate G AND the output constraint
2. `pair(input1, input2)` of gate G is touched ONLY by gate G
3. Adding `CRS[wire_N]` and subtracting `CRS[pair]` to the wrong proof cancels `b*r_G` terms
4. The remaining deficit `b*r_output` also cancels
5. Adjust `delta = -v[N] + 2*b*v[input1]*v[input2]` via `delta*G` on h2

**Learning secret v values via oracle:**
```python
# At streak=0, submitting correct answer is "safe" — doesn't reset streak
# Use oracle to learn |v[i]| from unconstrained diagonal pairs:

for guess in range(257):  # v[i] in [-256, 256], |v[i]| in [0, 256]
    # Set pair(i,i) coefficient to guess^2
    # If guess == |v[i]|, specific oracle response differs
    response = oracle_query(guess)
    if response == "hit":
        abs_v_i = guess
        break

# Learn signs from off-diagonal unconstrained pairs (1 query each)
# Learn product sign: v[a]*v[b] sign from pair(a,b)
```

**Performance:** ~364 oracle queries for Phase 1 (~97s), ~300s for 20 forged proofs ≈ 400s total.

**Key insight:** When attacking DV-SNARGs with oracle access, the strategy is: (1) learn a small number of secret values from the verifier's randomness, (2) use algebraic cancellation between CRS entries to forge proofs. Unconstrained pair indices expose pure tensor products of the secret vector.

---

## KZG Pairing Oracle for Permutation Recovery (UNbreakable 2026)

**Pattern (toxicwaste):** KZG commitment scheme publishes shuffled points `{alpha^i * G1}` for i=0..n. The shuffle hides which point corresponds to which exponent. Recover the exponent ordering using bilinear pairings as an oracle, then extract the toxic waste `alpha`.

**Distortion map technique:** On supersingular pairing-friendly curves, a distortion map `psi((x,y)) = (zeta*x, y)` (where `zeta^3 = 1`) enables additive exponent comparisons:

```python
from sage.all import *

# For points P_i = alpha^a_i * G1 and P_j = alpha^a_j * G1:
# e(P_i, psi(P_j)) = e(G1, psi(G1))^(alpha^(a_i + a_j))
# If e(P_i, psi(P_j)) == e(P_k, psi(G1)), then a_i + a_j == a_k

# Step 1: Identify G1 (alpha^0) — the only point where e(P, psi(P)) == e(G1, psi(G1))
g1 = None
base_pairing = None
for P in shuffled_points:
    val = P.weil_pairing(psi(P), order)
    if base_pairing is None:
        base_pairing = val
        g1 = P
    elif val == base_pairing:
        g1 = P
        break

# Step 2: Walk the chain — find alpha*G1 via e(P_?, psi(G1)) comparisons
# Then alpha^2*G1 via e(alpha*G1, psi(alpha*G1)) == e(alpha^2*G1, psi(G1))
# Continue until full ordering recovered

# Step 3: With ordered points, solve A(x) = 0 over GF(q) to get alpha
# Step 4: Forge KZG opening proofs using recovered alpha
```

**Key insight:** Bilinear pairings reveal additive relationships between exponents without solving discrete log. The pairing `e(P_i, psi(P_j))` depends on `alpha^(a_i + a_j)`, so comparing against known pairing values identifies which shuffled point has which exponent. This turns a cryptographic shuffle into a solvable ordering problem.


<!-- APPENDED FROM LATEST UPDATE: ctf-crypto/rsa-attacks.md -->

# CTF Crypto - RSA Attacks

## Table of Contents
- [Small Public Exponent (Cube Root)](#small-public-exponent-cube-root)
- [Common Modulus Attack](#common-modulus-attack)
- [Wiener's Attack (Small Private Exponent)](#wieners-attack-small-private-exponent)
- [Pollard's p-1 Factorization](#pollards-p-1-factorization)
- [Hastad's Broadcast Attack](#hastads-broadcast-attack)
- [RSA with Consecutive Primes (Fermat Factorization)](#rsa-with-consecutive-primes-fermat-factorization)
- [Multi-Prime RSA](#multi-prime-rsa)
- [RSA with Restricted-Digit Primes (LACTF 2026)](#rsa-with-restricted-digit-primes-lactf-2026)
- [Coppersmith for Structured RSA Primes (LACTF 2026)](#coppersmith-for-structured-rsa-primes-lactf-2026)
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)](#mangers-attack-on-rsa-oaep-via-timing-oracle-htb-early-bird)
- [Polynomial Hash with Trivial Root (Pragyan 2026)](#polynomial-hash-with-trivial-root-pragyan-2026)
- [Polynomial CRT in GF(2)[x] (Nullcon 2026)](#polynomial-crt-in-gf2x-nullcon-2026)
- [Affine Cipher over Non-Prime Modulus (Nullcon 2026)](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [RSA p=q Validation Bypass (BearCatCTF 2026)](#rsa-pq-validation-bypass-bearcatctf-2026)
- [RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)](#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [Factoring n from Multiple of phi(n) (BearCatCTF 2026)](#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)](#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [Weak RSA Key Generation via Base Representation (Sharif CTF 2016)](#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [RSA with gcd(e, phi(n)) > 1 (CSAW 2015)](#rsa-with-gcde-phin--1-csaw-2015)
- [Batch GCD for Shared Prime Factoring (BSidesSF 2025)](#batch-gcd-for-shared-prime-factoring-bsidessf-2025)

---

## Small Public Exponent (Cube Root)

**Pattern:** Small `e` (typically 3) with small message. When `m^e < n`, the ciphertext is just `m^e` without modular reduction — take the integer eth root.

```python
import gmpy2

def small_e_attack(c, e):
    """Recover plaintext when m^e < n (no modular wrap)."""
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return int(m)
    return None

# Usage
m = small_e_attack(c, e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**When it fails:** If `m^e > n` (message padded or large), the modular reduction destroys the simple root. In that case, try Hastad's broadcast attack or Coppersmith's short-pad attack.

---

## Common Modulus Attack

**Pattern:** Same message encrypted with same `n` but two different public exponents `e1`, `e2` where `gcd(e1, e2) = 1`. Recover plaintext without factoring `n`.

```python
from math import gcd

def common_modulus_attack(c1, c2, e1, e2, n):
    """Recover plaintext from two encryptions with same n, coprime e1/e2."""
    # Extended GCD: find a, b such that a*e1 + b*e2 = 1
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, a, b = extended_gcd(e1, e2)
    assert g == 1, "e1 and e2 must be coprime"

    # m = c1^a * c2^b mod n
    # Handle negative exponent by using modular inverse
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

**Key insight:** Two encryptions of the same message under the same modulus but different exponents leak the plaintext via Bezout's identity. No factoring required.

---

## Wiener's Attack (Small Private Exponent)

**Pattern:** Private exponent `d` is small (d < N^0.25). The continued fraction expansion of `e/n` reveals `d`.

```python
def wiener_attack(e, n):
    """Recover d when d < N^0.25 using continued fraction expansion of e/n."""
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        convs = []
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        for a in cf:
            h0, h1 = h1, a * h1 + h0
            k0, k1 = k1, a * k1 + k0
            convs.append((h1, k1))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # Check if d is valid: phi = (e*d - 1) / k must be integer
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1, so p+q = n - phi + 1
        s = n - phi + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        from math import isqrt
        t = isqrt(discriminant)
        if t * t == discriminant:
            return d
    return None

# Usage
d = wiener_attack(e, n)
m = pow(c, d, n)
```

**When to use:** Very large `e` (close to `n`) often indicates small `d`. Also try `owiener` Python package: `pip install owiener`.

---

## Pollard's p-1 Factorization

**Pattern:** One prime factor `p` has a smooth `p-1` (all prime factors of `p-1` are small). Compute `a^(B!) mod n`; GCD with `n` reveals `p`.

```python
from math import gcd

def pollard_p1(n, B=100000):
    """Factor n when p-1 is B-smooth for some prime factor p."""
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None

# Usage
result = pollard_p1(n)
if result:
    p, q = result
```

**Key insight:** By Fermat's little theorem, if `p-1` divides `B!`, then `a^(B!) ≡ 1 (mod p)`, so `gcd(a^(B!) - 1, n)` gives `p`. Increase `B` for larger smooth bounds. CTF primes generated with `getStrongPrime()` or similar are resistant.

---

## Hastad's Broadcast Attack

**Pattern:** Same plaintext `m` encrypted with `e` different public keys (all with exponent `e`, typically `e=3`). Use CRT to reconstruct `m^e`, then take the eth root.

```python
from functools import reduce

def hastad_broadcast(ciphertexts, moduli, e):
    """Recover m from e encryptions with the same exponent e."""
    assert len(ciphertexts) >= e and len(moduli) >= e

    # Chinese Remainder Theorem
    def crt(remainders, moduli):
        N = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, m in zip(remainders, moduli):
            Ni = N // m
            Mi = pow(Ni, -1, m)
            result += r * Ni * Mi
        return result % N

    # CRT gives m^e (mod N1*N2*...*Ne)
    # Since m < each Ni, m^e < N1*N2*...*Ne, so no modular reduction occurred
    me = crt(ciphertexts[:e], moduli[:e])

    import gmpy2
    m, exact = gmpy2.iroot(me, e)
    if exact:
        return int(m)
    return None

# Usage (e=3, three encryptions)
m = hastad_broadcast([c1, c2, c3], [n1, n2, n3], e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**Key insight:** CRT reconstructs `m^e` exactly (no modular reduction) because `m < min(n_i)` and therefore `m^e < n_1 * n_2 * ... * n_e`. Taking the integer eth root recovers `m`.

---

## RSA with Consecutive Primes (Fermat Factorization)

**Pattern (Loopy Primes):** q = next_prime(p), making p ~ q ~ sqrt(N). Also known as Fermat factorization — works whenever `|p - q|` is small.

**Factorization:** Find first prime below sqrt(N):
```python
from sympy import nextprime, prevprime, isqrt

root = isqrt(n)
p = prevprime(root + 1)
while n % p != 0:
    p = prevprime(p)
q = n // p
```

**Multi-layer variant:** 1024 nested RSA encryptions, each with consecutive primes of increasing bit size. Decrypt in reverse order.

---

## Multi-Prime RSA

When N is product of many small primes (not just p*q):
```python
# Factor N (easier when many primes)
from sympy import factorint
factors = factorint(n)  # Returns {p1: e1, p2: e2, ...}

# Compute phi using all factors
phi = 1
for p, e in factors.items():
    phi *= (p - 1) * (p ** (e - 1))

d = pow(e, -1, phi)
plaintext = pow(ciphertext, d, n)
```

---

## RSA with Restricted-Digit Primes (LACTF 2026)

**Pattern (six-seven):** RSA primes p, q composed only of digits {6, 7}, ending in 7.

**Digit-by-digit factoring from LSB:**
```python
# At each step k, we know p mod 10^k -> compute q mod 10^k = n * p^{-1} mod 10^k
# Prune: only keep candidates where digit k of both p and q is in {6, 7}
candidates = [(6,), (7,)]  # p ends in 6 or 7
for k in range(1, num_digits):
    new_candidates = []
    for p_digits in candidates:
        for d in [6, 7]:
            p_val = sum(p_digits[i] * 10**i for i in range(len(p_digits))) + d * 10**k
            q_val = (n * pow(p_val, -1, 10**(k+1))) % 10**(k+1)
            q_digit_k = (q_val // 10**k) % 10
            if q_digit_k in {6, 7}:
                new_candidates.append(p_digits + (d,))
    candidates = new_candidates
```

**General lesson:** When prime digits are restricted to a small set, digit-by-digit recovery from LSB with modular arithmetic prunes exponentially. Works for any restricted character set.

---

## Coppersmith for Structured RSA Primes (LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k * x where base is fully known and x is small (x < N^0.25).

**Attack via SageMath:**
```python
# Construct f(x) such that f(x_secret) = 0 (mod p) and thus (mod N)
# p = base + 10^k * x -> x + base * (10^k)^{-1} = 0 (mod p)
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)  # x < N^0.25
```

**When to use:** Whenever part of a prime is known and the unknown part is small enough for Coppersmith bounds (< N^{1/e} for degree-e polynomial, approximately N^0.25 for linear).

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Pattern (TLS, Nullcon 2026):** RSA-encrypted key with threshold oracle. Phase 1: double f until `k*f >= threshold`. Phase 2: binary search. ~128 total queries for 64-bit key.

See [advanced-math.md](advanced-math.md) for full implementation.

---

## Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)

**Pattern:** Flask app implements RSA-OAEP with custom hash (PBKDF2, 2M iterations). Python's short-circuit `or` evaluation creates a timing oracle: if the first byte Y != 0, PBKDF2 is never called (~0.6s). If Y == 0, PBKDF2 runs (~2s).

**Vulnerable code pattern:**
```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return {"ok": False, "error": "decryption error"}
```

**Oracle mapping:** Fast response → Y != 0 (decrypted message >= B). Slow response → Y == 0 (decrypted message < B = 2^(8*(k-1))).

**Calibration for network reliability:**
```python
def calibrate(n, e, k):
    B = pow(2, 8 * (k - 1))
    slow_times, fast_times = [], []
    for i in range(5):
        # Known-slow: encrypt values < B
        enc = pow(B - 1 - i*100, e, n).to_bytes(k, 'big')
        slow_times.append(measure(enc))
        # Known-fast: encrypt values > B
        enc = pow(B + 1 + i*100, e, n).to_bytes(k, 'big')
        fast_times.append(measure(enc))
    FAST_UPPER = max(fast_times) * 1.5
    SLOW_LOWER = min(slow_times) * 0.9
```

**Oracle with retry for ambiguous results:**
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0 (below B)
        elif total < FAST_UPPER:
            return False  # Y != 0 (above B)
        # Ambiguous: retry
```

**Full 3-step Manger's attack (~1024 iterations for 1024-bit RSA):**
```python
# Step 1: Find f1 where f1 * m >= B
f1 = 2
while oracle((pow(f1, e, n) * c) % n):
    f1 *= 2

# Step 2: Find f2 where n <= f2 * m < n + B
f2 = (n + B) // B * f1 // 2
while not oracle((pow(f2, e, n) * c) % n):
    f2 += f1 // 2

# Step 3: Binary search narrowing m to exact value
mmin, mmax = ceil_div(n, f2), floor_div(n + B, f2)
while mmin < mmax:
    f = floor_div(2 * B, mmax - mmin)
    i = floor_div(f * mmin, n)
    f3 = ceil_div(i * n, mmin)
    if oracle((pow(f3, e, n) * c) % n):
        mmax = floor_div(i * n + B, f3)
    else:
        mmin = ceil_div(i * n + B, f3)
m = mmin
```

**Post-recovery OAEP decode:**
```python
from Crypto.Signature.pss import MGF1
maskedSeed = EM[1:hLen+1]
maskedDB = EM[hLen+1:]
seed = bytes(a ^ b for a, b in zip(maskedSeed, MGF1(maskedDB, hLen, HF)))
DB = bytes(a ^ b for a, b in zip(maskedDB, MGF1(seed, k - hLen - 1, HF)))
# DB[:hLen] should match lHash; rest is 0x00...0x01 || message
```

**Key insight:** Python's `or` short-circuits left-to-right. When expensive operations (PBKDF2, bcrypt, argon2) appear in chained conditions, the first condition becomes a timing oracle. RFC 8017 explicitly warns implementations must not let attackers distinguish error conditions — timing differences violate this.

**Detection:** RSA-OAEP with custom hash or slow KDF. Flask/Python backend. `/verify-token` or similar decryption endpoint returning generic errors. Timing differences between responses.

---

## Polynomial Hash with Trivial Root (Pragyan 2026)

**Pattern (!!Cand1esaNdCrypt0!!):** RSA signature scheme using polynomial hash `g(x,a,b) = x(x^2 + ax + b) mod P`.

**Vulnerability:** `g(0) = 0` for all parameters `a,b`. RSA signature of 0 is always 0 (`0^d mod n = 0`).

**Exploitation:** Craft message suffix so `bytes_to_long(prefix || suffix) = 0 (mod P)`:
```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61  # 128-bit prime
# Compute required suffix value mod P
req = (-prefix_val * pow(256, suffix_len, P)) % P
# Brute-force partial bytes until all printable ASCII
while True:
    high = os.urandom(32).translate(printable_table)
    low_val = (req - int.from_bytes(high, 'big') * shift) % P
    low = low_val.to_bytes(16, 'big')
    if all(32 <= b <= 126 for b in low):
        suffix = high + low
        break
# Signature is simply 0
```

**General lesson:** Always check if hash function has trivial inputs (0, 1, -1). Factoring the polynomial often reveals these.

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**Pattern (Going in Circles, Nullcon 2026):** `r = flag mod f` where f is random GF(2) polynomial. Collect ~20 pairs, filter coprime, CRT combine.

See [advanced-math.md](advanced-math.md) for GF(2)[x] polynomial arithmetic and CRT implementation.

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**Pattern (Matrixfun, Nullcon 2026):** `c = A @ p + b (mod m)` with composite m. Chosen-plaintext difference attack. For composite modulus, solve via CRT in each prime factor field separately.

See [advanced-math.md](advanced-math.md) for CRT approach and Gauss-Jordan implementation.

---

## RSA p=q Validation Bypass (BearCatCTF 2026)

**Pattern (Pickme):** Server validates user-submitted RSA key (checks `n`, `e`, `d`, `p*q=n`, `e*d ≡ 1 mod phi`), encrypts the flag, then tries test decryption. If decryption fails, leaks ciphertext in error message.

**Exploit:** Set `p = q`. The server computes `phi = (p-1)*(q-1) = (p-1)^2` (incorrect — real totient of `p^2` is `p*(p-1)`). All validation checks pass, but decryption with the wrong `d` fails, leaking the ciphertext.

```python
from Crypto.Util.number import getPrime, inverse

p = getPrime(512)
q = p  # p = q!
n = p * q  # = p^2
e = 65537
wrong_phi = (p - 1) * (q - 1)  # = (p-1)^2
d = inverse(e, wrong_phi)  # passes server validation

# Server encrypts flag with our key, test decryption fails → leaks ciphertext c
# Decrypt with correct totient:
real_phi = p * (p - 1)
real_d = inverse(e, real_phi)
flag = pow(c, real_d, n)
```

**Key insight:** `phi(p^2) = p*(p-1)`, NOT `(p-1)^2`. When a server validates RSA parameters but uses `(p-1)*(q-1)` without checking `p != q`, setting `p=q` creates a working key that the server will miscompute the private exponent for, causing decryption failure and error-path data leakage.

---

## RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)

**Pattern (Kidd's Crypto):** RSA with `e=3`, modulus composed of many small primes all ≡ 1 (mod 3). Since each `p-1` is divisible by 3, `gcd(e, phi(n)) = 3^k` and the standard modular inverse `d = e^-1 mod phi` doesn't exist.

**Solution:** Compute cube roots per-prime via CRT:
```python
from sympy.ntheory.residues import nthroot_mod
from sympy.ntheory.modular import crt

primes = [p1, p2, ..., p13]  # All ≡ 1 mod 3

# For each prime, find all 3 cube roots of c mod p
roots_per_prime = []
for p in primes:
    roots = nthroot_mod(c % p, 3, p, all_roots=True)
    roots_per_prime.append(roots)

# Try all 3^13 = 1,594,323 combinations
from itertools import product
for combo in product(*roots_per_prime):
    result, mod = crt(primes, list(combo))
    try:
        text = long_to_bytes(result).decode('ascii')
        if text.isprintable():
            print(f"Flag: {text}")
            break
    except:
        continue
```

**Key insight:** When `gcd(e, phi(n)) > 1`, standard RSA decryption fails. Factor `n`, compute eth roots modulo each prime separately (each prime ≡ 1 mod e gives `e` roots), then enumerate all CRT combinations. Feasible when the number of primes is small (3^13 ≈ 1.6M combinations).

---

## Factoring n from Multiple of phi(n) (BearCatCTF 2026)

**Pattern (Twisted Pair):** Given RSA `n` and a leaked pair `(re, rd)` where `re * rd ≡ 1 (mod k*phi(n))`. The value `re*rd - 1` is a multiple of `phi(n)`, enabling probabilistic factoring.

```python
import random
from math import gcd

def factor_from_phi_multiple(n, phi_multiple):
    """Factor n given any multiple of phi(n) using Miller-Rabin variant."""
    # Write phi_multiple = 2^s * d where d is odd
    s, d = 0, phi_multiple
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(100):  # 100 attempts
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            prev = x
            x = pow(x, 2, n)
            if x == n - 1:
                break
            if x == 1:
                # prev is non-trivial square root of 1
                p = gcd(prev - 1, n)
                if 1 < p < n:
                    return p, n // p
        # Check final
        if x != n - 1:
            p = gcd(x - 1, n)
            if 1 < p < n:
                return p, n // p
    return None

phi_mult = re * rd - 1
p, q = factor_from_phi_multiple(n, phi_mult)
```

**Key insight:** Any multiple of `phi(n)` — not just `phi(n)` itself — enables factoring via the Miller-Rabin square root technique. If a server leaks `e*d` for any key pair, or if `re*rd - 1` is given, compute `gcd(a^(m/2) - 1, n)` for random `a` values. Succeeds with probability ≥ 1/2 per attempt.

---

## RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)

**Pattern:** Signing oracle refuses to sign the target message `m` but will sign other values. Unpadded RSA is multiplicatively homomorphic: `S(a) * S(b) mod n == S(a * b) mod n`.

```python
# Factor target message and sign each factor separately
divisor = 2
assert target_msg % divisor == 0
sig_a = sign_oracle(target_msg // divisor)
sig_b = sign_oracle(divisor)
forged_sig = (sig_a * sig_b) % n
```

**Key insight:** Textbook RSA signatures are homomorphic: `m^d mod n` preserves multiplication. If the oracle blacklists `m` but signs its factors, multiply the partial signatures. To find a suitable factorization, try small divisors (2, 3, ...) until `m / divisor` also passes the blacklist check. This is why PKCS#1 padding is essential — padded messages cannot be factored into other valid padded messages.

---

## Weak RSA Key Generation via Base Representation (Sharif CTF 2016)

When RSA primes are generated as `p = kp * B + tp` where B = product_of_small_primes * 2^400 and kp is small (< 2^12):

1. **Compute n mod B^2:** Since n = p*q and both p,q have form k*B + t, expansion gives: `n = kp*kq*B^2 + (kp*tq + kq*tp)*B + tp*tq`
2. **Recover kp*kq:** Brute-force 2^24 possibilities for (kp, kq) where each < 2^12
3. **Solve quadratic:** From known kp*kq and the middle coefficient, recover tp and tq

```python
B = product_of_first_443_primes * (2**400)
B2 = B * B

# n = A*B^2 + C*B + D where A=kp*kq, D=tp*tq
A = n // B2
D = n % B

# Brute-force kp, kq such that kp*kq == A
for kp in range(1, 2**12):
    if A % kp == 0:
        kq = A // kp
        # Solve for tp, tq from remaining equations
```

**Key insight:** Structured prime generation creates a mixed-radix representation of n, allowing efficient factorization by reducing the search space from exponential to polynomial.

---

## RSA with gcd(e, phi(n)) > 1 (CSAW 2015)

When `gcd(e, phi(n)) = g > 1`, standard RSA decryption fails because `d = e^(-1) mod phi(n)` doesn't exist. Instead:

1. Compute `e' = e / g` (reduced exponent)
2. Compute `d' = e'^(-1) mod phi(n)` (now coprime)
3. Compute `m^g = pow(c, d', n)` (partial decryption)
4. Take g-th root: iterate candidate m values where `pow(m, g, n) == m^g`

```python
from sympy import factorint, mod_inverse
from gmpy2 import iroot

g = gcd(e, phi_n)
e_prime = e // g
d_prime = mod_inverse(e_prime, phi_n)
m_g = pow(c, d_prime, n)

# For small g, try integer root first
m, is_exact = iroot(m_g, g)
if is_exact:
    plaintext = int(m)
else:
    # Brute-force: m_g + k*n for small k
    for k in range(10000):
        m, exact = iroot(m_g + k * n, g)
        if exact:
            plaintext = int(m)
            break
```

**Key insight:** Reduce e by the GCD to make decryption possible, then recover the g-th root. Filter candidates by checking plaintext length or ASCII validity.

---

## Batch GCD for Shared Prime Factoring (BSidesSF 2025)

When multiple RSA moduli share a common prime factor (due to faulty hardware RNG, smartcard bugs, or weak seeding):

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """Find shared factors among a list of RSA moduli"""
    # Product tree
    product = reduce(lambda a, b: a * b, moduli)

    factors = {}
    for n in moduli:
        g = gcd(n, product // n)
        if g != 1 and g != n:
            p = g
            q = n // p
            factors[n] = (p, q)
    return factors

# Usage: given list of public keys from smartcards
moduli = [key.n for key in public_keys]
shared = batch_gcd(moduli)
for n, (p, q) in shared.items():
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Private exponent
```

For keys with patterned primes (hardware RNG faults producing primes with fixed bit patterns), combine with Coppersmith's method to recover remaining random bits. See [advanced-math.md](advanced-math.md) for Coppersmith.

**Key insight:** A single shared prime compromises both keys. Batch GCD runs in O(n log n) time via product/remainder trees, making it feasible for thousands of keys. Real-world incidents: Taiwanese citizen smartcards (2013), many IoT device certificates.


<!-- APPENDED FROM LATEST UPDATE: ctf-crypto/rsa-attacks.md -->

# CTF Crypto - RSA Attacks

## Table of Contents
- [Small Public Exponent (Cube Root)](#small-public-exponent-cube-root)
- [Common Modulus Attack](#common-modulus-attack)
- [Wiener's Attack (Small Private Exponent)](#wieners-attack-small-private-exponent)
- [Pollard's p-1 Factorization](#pollards-p-1-factorization)
- [Hastad's Broadcast Attack](#hastads-broadcast-attack)
- [RSA with Consecutive Primes (Fermat Factorization)](#rsa-with-consecutive-primes-fermat-factorization)
- [Multi-Prime RSA](#multi-prime-rsa)
- [RSA with Restricted-Digit Primes (LACTF 2026)](#rsa-with-restricted-digit-primes-lactf-2026)
- [Coppersmith for Structured RSA Primes (LACTF 2026)](#coppersmith-for-structured-rsa-primes-lactf-2026)
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)](#mangers-attack-on-rsa-oaep-via-timing-oracle-htb-early-bird)
- [Polynomial Hash with Trivial Root (Pragyan 2026)](#polynomial-hash-with-trivial-root-pragyan-2026)
- [Polynomial CRT in GF(2)[x] (Nullcon 2026)](#polynomial-crt-in-gf2x-nullcon-2026)
- [Affine Cipher over Non-Prime Modulus (Nullcon 2026)](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [RSA p=q Validation Bypass (BearCatCTF 2026)](#rsa-pq-validation-bypass-bearcatctf-2026)
- [RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)](#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [Factoring n from Multiple of phi(n) (BearCatCTF 2026)](#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)](#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [Weak RSA Key Generation via Base Representation (Sharif CTF 2016)](#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [RSA with gcd(e, phi(n)) > 1 (CSAW 2015)](#rsa-with-gcde-phin--1-csaw-2015)
- [Batch GCD for Shared Prime Factoring (BSidesSF 2025)](#batch-gcd-for-shared-prime-factoring-bsidessf-2025)

---

## Small Public Exponent (Cube Root)

**Pattern:** Small `e` (typically 3) with small message. When `m^e < n`, the ciphertext is just `m^e` without modular reduction — take the integer eth root.

```python
import gmpy2

def small_e_attack(c, e):
    """Recover plaintext when m^e < n (no modular wrap)."""
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return int(m)
    return None

# Usage
m = small_e_attack(c, e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**When it fails:** If `m^e > n` (message padded or large), the modular reduction destroys the simple root. In that case, try Hastad's broadcast attack or Coppersmith's short-pad attack.

---

## Common Modulus Attack

**Pattern:** Same message encrypted with same `n` but two different public exponents `e1`, `e2` where `gcd(e1, e2) = 1`. Recover plaintext without factoring `n`.

```python
from math import gcd

def common_modulus_attack(c1, c2, e1, e2, n):
    """Recover plaintext from two encryptions with same n, coprime e1/e2."""
    # Extended GCD: find a, b such that a*e1 + b*e2 = 1
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, a, b = extended_gcd(e1, e2)
    assert g == 1, "e1 and e2 must be coprime"

    # m = c1^a * c2^b mod n
    # Handle negative exponent by using modular inverse
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

**Key insight:** Two encryptions of the same message under the same modulus but different exponents leak the plaintext via Bezout's identity. No factoring required.

---

## Wiener's Attack (Small Private Exponent)

**Pattern:** Private exponent `d` is small (d < N^0.25). The continued fraction expansion of `e/n` reveals `d`.

```python
def wiener_attack(e, n):
    """Recover d when d < N^0.25 using continued fraction expansion of e/n."""
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        convs = []
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        for a in cf:
            h0, h1 = h1, a * h1 + h0
            k0, k1 = k1, a * k1 + k0
            convs.append((h1, k1))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # Check if d is valid: phi = (e*d - 1) / k must be integer
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1, so p+q = n - phi + 1
        s = n - phi + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        from math import isqrt
        t = isqrt(discriminant)
        if t * t == discriminant:
            return d
    return None

# Usage
d = wiener_attack(e, n)
m = pow(c, d, n)
```

**When to use:** Very large `e` (close to `n`) often indicates small `d`. Also try `owiener` Python package: `pip install owiener`.

---

## Pollard's p-1 Factorization

**Pattern:** One prime factor `p` has a smooth `p-1` (all prime factors of `p-1` are small). Compute `a^(B!) mod n`; GCD with `n` reveals `p`.

```python
from math import gcd

def pollard_p1(n, B=100000):
    """Factor n when p-1 is B-smooth for some prime factor p."""
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None

# Usage
result = pollard_p1(n)
if result:
    p, q = result
```

**Key insight:** By Fermat's little theorem, if `p-1` divides `B!`, then `a^(B!) ≡ 1 (mod p)`, so `gcd(a^(B!) - 1, n)` gives `p`. Increase `B` for larger smooth bounds. CTF primes generated with `getStrongPrime()` or similar are resistant.

---

## Hastad's Broadcast Attack

**Pattern:** Same plaintext `m` encrypted with `e` different public keys (all with exponent `e`, typically `e=3`). Use CRT to reconstruct `m^e`, then take the eth root.

```python
from functools import reduce

def hastad_broadcast(ciphertexts, moduli, e):
    """Recover m from e encryptions with the same exponent e."""
    assert len(ciphertexts) >= e and len(moduli) >= e

    # Chinese Remainder Theorem
    def crt(remainders, moduli):
        N = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, m in zip(remainders, moduli):
            Ni = N // m
            Mi = pow(Ni, -1, m)
            result += r * Ni * Mi
        return result % N

    # CRT gives m^e (mod N1*N2*...*Ne)
    # Since m < each Ni, m^e < N1*N2*...*Ne, so no modular reduction occurred
    me = crt(ciphertexts[:e], moduli[:e])

    import gmpy2
    m, exact = gmpy2.iroot(me, e)
    if exact:
        return int(m)
    return None

# Usage (e=3, three encryptions)
m = hastad_broadcast([c1, c2, c3], [n1, n2, n3], e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**Key insight:** CRT reconstructs `m^e` exactly (no modular reduction) because `m < min(n_i)` and therefore `m^e < n_1 * n_2 * ... * n_e`. Taking the integer eth root recovers `m`.

---

## RSA with Consecutive Primes (Fermat Factorization)

**Pattern (Loopy Primes):** q = next_prime(p), making p ~ q ~ sqrt(N). Also known as Fermat factorization — works whenever `|p - q|` is small.

**Factorization:** Find first prime below sqrt(N):
```python
from sympy import nextprime, prevprime, isqrt

root = isqrt(n)
p = prevprime(root + 1)
while n % p != 0:
    p = prevprime(p)
q = n // p
```

**Multi-layer variant:** 1024 nested RSA encryptions, each with consecutive primes of increasing bit size. Decrypt in reverse order.

---

## Multi-Prime RSA

When N is product of many small primes (not just p*q):
```python
# Factor N (easier when many primes)
from sympy import factorint
factors = factorint(n)  # Returns {p1: e1, p2: e2, ...}

# Compute phi using all factors
phi = 1
for p, e in factors.items():
    phi *= (p - 1) * (p ** (e - 1))

d = pow(e, -1, phi)
plaintext = pow(ciphertext, d, n)
```

---

## RSA with Restricted-Digit Primes (LACTF 2026)

**Pattern (six-seven):** RSA primes p, q composed only of digits {6, 7}, ending in 7.

**Digit-by-digit factoring from LSB:**
```python
# At each step k, we know p mod 10^k -> compute q mod 10^k = n * p^{-1} mod 10^k
# Prune: only keep candidates where digit k of both p and q is in {6, 7}
candidates = [(6,), (7,)]  # p ends in 6 or 7
for k in range(1, num_digits):
    new_candidates = []
    for p_digits in candidates:
        for d in [6, 7]:
            p_val = sum(p_digits[i] * 10**i for i in range(len(p_digits))) + d * 10**k
            q_val = (n * pow(p_val, -1, 10**(k+1))) % 10**(k+1)
            q_digit_k = (q_val // 10**k) % 10
            if q_digit_k in {6, 7}:
                new_candidates.append(p_digits + (d,))
    candidates = new_candidates
```

**General lesson:** When prime digits are restricted to a small set, digit-by-digit recovery from LSB with modular arithmetic prunes exponentially. Works for any restricted character set.

---

## Coppersmith for Structured RSA Primes (LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k * x where base is fully known and x is small (x < N^0.25).

**Attack via SageMath:**
```python
# Construct f(x) such that f(x_secret) = 0 (mod p) and thus (mod N)
# p = base + 10^k * x -> x + base * (10^k)^{-1} = 0 (mod p)
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)  # x < N^0.25
```

**When to use:** Whenever part of a prime is known and the unknown part is small enough for Coppersmith bounds (< N^{1/e} for degree-e polynomial, approximately N^0.25 for linear).

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Pattern (TLS, Nullcon 2026):** RSA-encrypted key with threshold oracle. Phase 1: double f until `k*f >= threshold`. Phase 2: binary search. ~128 total queries for 64-bit key.

See [advanced-math.md](advanced-math.md) for full implementation.

---

## Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)

**Pattern:** Flask app implements RSA-OAEP with custom hash (PBKDF2, 2M iterations). Python's short-circuit `or` evaluation creates a timing oracle: if the first byte Y != 0, PBKDF2 is never called (~0.6s). If Y == 0, PBKDF2 runs (~2s).

**Vulnerable code pattern:**
```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return {"ok": False, "error": "decryption error"}
```

**Oracle mapping:** Fast response → Y != 0 (decrypted message >= B). Slow response → Y == 0 (decrypted message < B = 2^(8*(k-1))).

**Calibration for network reliability:**
```python
def calibrate(n, e, k):
    B = pow(2, 8 * (k - 1))
    slow_times, fast_times = [], []
    for i in range(5):
        # Known-slow: encrypt values < B
        enc = pow(B - 1 - i*100, e, n).to_bytes(k, 'big')
        slow_times.append(measure(enc))
        # Known-fast: encrypt values > B
        enc = pow(B + 1 + i*100, e, n).to_bytes(k, 'big')
        fast_times.append(measure(enc))
    FAST_UPPER = max(fast_times) * 1.5
    SLOW_LOWER = min(slow_times) * 0.9
```

**Oracle with retry for ambiguous results:**
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0 (below B)
        elif total < FAST_UPPER:
            return False  # Y != 0 (above B)
        # Ambiguous: retry
```

**Full 3-step Manger's attack (~1024 iterations for 1024-bit RSA):**
```python
# Step 1: Find f1 where f1 * m >= B
f1 = 2
while oracle((pow(f1, e, n) * c) % n):
    f1 *= 2

# Step 2: Find f2 where n <= f2 * m < n + B
f2 = (n + B) // B * f1 // 2
while not oracle((pow(f2, e, n) * c) % n):
    f2 += f1 // 2

# Step 3: Binary search narrowing m to exact value
mmin, mmax = ceil_div(n, f2), floor_div(n + B, f2)
while mmin < mmax:
    f = floor_div(2 * B, mmax - mmin)
    i = floor_div(f * mmin, n)
    f3 = ceil_div(i * n, mmin)
    if oracle((pow(f3, e, n) * c) % n):
        mmax = floor_div(i * n + B, f3)
    else:
        mmin = ceil_div(i * n + B, f3)
m = mmin
```

**Post-recovery OAEP decode:**
```python
from Crypto.Signature.pss import MGF1
maskedSeed = EM[1:hLen+1]
maskedDB = EM[hLen+1:]
seed = bytes(a ^ b for a, b in zip(maskedSeed, MGF1(maskedDB, hLen, HF)))
DB = bytes(a ^ b for a, b in zip(maskedDB, MGF1(seed, k - hLen - 1, HF)))
# DB[:hLen] should match lHash; rest is 0x00...0x01 || message
```

**Key insight:** Python's `or` short-circuits left-to-right. When expensive operations (PBKDF2, bcrypt, argon2) appear in chained conditions, the first condition becomes a timing oracle. RFC 8017 explicitly warns implementations must not let attackers distinguish error conditions — timing differences violate this.

**Detection:** RSA-OAEP with custom hash or slow KDF. Flask/Python backend. `/verify-token` or similar decryption endpoint returning generic errors. Timing differences between responses.

---

## Polynomial Hash with Trivial Root (Pragyan 2026)

**Pattern (!!Cand1esaNdCrypt0!!):** RSA signature scheme using polynomial hash `g(x,a,b) = x(x^2 + ax + b) mod P`.

**Vulnerability:** `g(0) = 0` for all parameters `a,b`. RSA signature of 0 is always 0 (`0^d mod n = 0`).

**Exploitation:** Craft message suffix so `bytes_to_long(prefix || suffix) = 0 (mod P)`:
```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61  # 128-bit prime
# Compute required suffix value mod P
req = (-prefix_val * pow(256, suffix_len, P)) % P
# Brute-force partial bytes until all printable ASCII
while True:
    high = os.urandom(32).translate(printable_table)
    low_val = (req - int.from_bytes(high, 'big') * shift) % P
    low = low_val.to_bytes(16, 'big')
    if all(32 <= b <= 126 for b in low):
        suffix = high + low
        break
# Signature is simply 0
```

**General lesson:** Always check if hash function has trivial inputs (0, 1, -1). Factoring the polynomial often reveals these.

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**Pattern (Going in Circles, Nullcon 2026):** `r = flag mod f` where f is random GF(2) polynomial. Collect ~20 pairs, filter coprime, CRT combine.

See [advanced-math.md](advanced-math.md) for GF(2)[x] polynomial arithmetic and CRT implementation.

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**Pattern (Matrixfun, Nullcon 2026):** `c = A @ p + b (mod m)` with composite m. Chosen-plaintext difference attack. For composite modulus, solve via CRT in each prime factor field separately.

See [advanced-math.md](advanced-math.md) for CRT approach and Gauss-Jordan implementation.

---

## RSA p=q Validation Bypass (BearCatCTF 2026)

**Pattern (Pickme):** Server validates user-submitted RSA key (checks `n`, `e`, `d`, `p*q=n`, `e*d ≡ 1 mod phi`), encrypts the flag, then tries test decryption. If decryption fails, leaks ciphertext in error message.

**Exploit:** Set `p = q`. The server computes `phi = (p-1)*(q-1) = (p-1)^2` (incorrect — real totient of `p^2` is `p*(p-1)`). All validation checks pass, but decryption with the wrong `d` fails, leaking the ciphertext.

```python
from Crypto.Util.number import getPrime, inverse

p = getPrime(512)
q = p  # p = q!
n = p * q  # = p^2
e = 65537
wrong_phi = (p - 1) * (q - 1)  # = (p-1)^2
d = inverse(e, wrong_phi)  # passes server validation

# Server encrypts flag with our key, test decryption fails → leaks ciphertext c
# Decrypt with correct totient:
real_phi = p * (p - 1)
real_d = inverse(e, real_phi)
flag = pow(c, real_d, n)
```

**Key insight:** `phi(p^2) = p*(p-1)`, NOT `(p-1)^2`. When a server validates RSA parameters but uses `(p-1)*(q-1)` without checking `p != q`, setting `p=q` creates a working key that the server will miscompute the private exponent for, causing decryption failure and error-path data leakage.

---

## RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)

**Pattern (Kidd's Crypto):** RSA with `e=3`, modulus composed of many small primes all ≡ 1 (mod 3). Since each `p-1` is divisible by 3, `gcd(e, phi(n)) = 3^k` and the standard modular inverse `d = e^-1 mod phi` doesn't exist.

**Solution:** Compute cube roots per-prime via CRT:
```python
from sympy.ntheory.residues import nthroot_mod
from sympy.ntheory.modular import crt

primes = [p1, p2, ..., p13]  # All ≡ 1 mod 3

# For each prime, find all 3 cube roots of c mod p
roots_per_prime = []
for p in primes:
    roots = nthroot_mod(c % p, 3, p, all_roots=True)
    roots_per_prime.append(roots)

# Try all 3^13 = 1,594,323 combinations
from itertools import product
for combo in product(*roots_per_prime):
    result, mod = crt(primes, list(combo))
    try:
        text = long_to_bytes(result).decode('ascii')
        if text.isprintable():
            print(f"Flag: {text}")
            break
    except:
        continue
```

**Key insight:** When `gcd(e, phi(n)) > 1`, standard RSA decryption fails. Factor `n`, compute eth roots modulo each prime separately (each prime ≡ 1 mod e gives `e` roots), then enumerate all CRT combinations. Feasible when the number of primes is small (3^13 ≈ 1.6M combinations).

---

## Factoring n from Multiple of phi(n) (BearCatCTF 2026)

**Pattern (Twisted Pair):** Given RSA `n` and a leaked pair `(re, rd)` where `re * rd ≡ 1 (mod k*phi(n))`. The value `re*rd - 1` is a multiple of `phi(n)`, enabling probabilistic factoring.

```python
import random
from math import gcd

def factor_from_phi_multiple(n, phi_multiple):
    """Factor n given any multiple of phi(n) using Miller-Rabin variant."""
    # Write phi_multiple = 2^s * d where d is odd
    s, d = 0, phi_multiple
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(100):  # 100 attempts
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            prev = x
            x = pow(x, 2, n)
            if x == n - 1:
                break
            if x == 1:
                # prev is non-trivial square root of 1
                p = gcd(prev - 1, n)
                if 1 < p < n:
                    return p, n // p
        # Check final
        if x != n - 1:
            p = gcd(x - 1, n)
            if 1 < p < n:
                return p, n // p
    return None

phi_mult = re * rd - 1
p, q = factor_from_phi_multiple(n, phi_mult)
```

**Key insight:** Any multiple of `phi(n)` — not just `phi(n)` itself — enables factoring via the Miller-Rabin square root technique. If a server leaks `e*d` for any key pair, or if `re*rd - 1` is given, compute `gcd(a^(m/2) - 1, n)` for random `a` values. Succeeds with probability ≥ 1/2 per attempt.

---

## RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)

**Pattern:** Signing oracle refuses to sign the target message `m` but will sign other values. Unpadded RSA is multiplicatively homomorphic: `S(a) * S(b) mod n == S(a * b) mod n`.

```python
# Factor target message and sign each factor separately
divisor = 2
assert target_msg % divisor == 0
sig_a = sign_oracle(target_msg // divisor)
sig_b = sign_oracle(divisor)
forged_sig = (sig_a * sig_b) % n
```

**Key insight:** Textbook RSA signatures are homomorphic: `m^d mod n` preserves multiplication. If the oracle blacklists `m` but signs its factors, multiply the partial signatures. To find a suitable factorization, try small divisors (2, 3, ...) until `m / divisor` also passes the blacklist check. This is why PKCS#1 padding is essential — padded messages cannot be factored into other valid padded messages.

---

## Weak RSA Key Generation via Base Representation (Sharif CTF 2016)

When RSA primes are generated as `p = kp * B + tp` where B = product_of_small_primes * 2^400 and kp is small (< 2^12):

1. **Compute n mod B^2:** Since n = p*q and both p,q have form k*B + t, expansion gives: `n = kp*kq*B^2 + (kp*tq + kq*tp)*B + tp*tq`
2. **Recover kp*kq:** Brute-force 2^24 possibilities for (kp, kq) where each < 2^12
3. **Solve quadratic:** From known kp*kq and the middle coefficient, recover tp and tq

```python
B = product_of_first_443_primes * (2**400)
B2 = B * B

# n = A*B^2 + C*B + D where A=kp*kq, D=tp*tq
A = n // B2
D = n % B

# Brute-force kp, kq such that kp*kq == A
for kp in range(1, 2**12):
    if A % kp == 0:
        kq = A // kp
        # Solve for tp, tq from remaining equations
```

**Key insight:** Structured prime generation creates a mixed-radix representation of n, allowing efficient factorization by reducing the search space from exponential to polynomial.

---

## RSA with gcd(e, phi(n)) > 1 (CSAW 2015)

When `gcd(e, phi(n)) = g > 1`, standard RSA decryption fails because `d = e^(-1) mod phi(n)` doesn't exist. Instead:

1. Compute `e' = e / g` (reduced exponent)
2. Compute `d' = e'^(-1) mod phi(n)` (now coprime)
3. Compute `m^g = pow(c, d', n)` (partial decryption)
4. Take g-th root: iterate candidate m values where `pow(m, g, n) == m^g`

```python
from sympy import factorint, mod_inverse
from gmpy2 import iroot

g = gcd(e, phi_n)
e_prime = e // g
d_prime = mod_inverse(e_prime, phi_n)
m_g = pow(c, d_prime, n)

# For small g, try integer root first
m, is_exact = iroot(m_g, g)
if is_exact:
    plaintext = int(m)
else:
    # Brute-force: m_g + k*n for small k
    for k in range(10000):
        m, exact = iroot(m_g + k * n, g)
        if exact:
            plaintext = int(m)
            break
```

**Key insight:** Reduce e by the GCD to make decryption possible, then recover the g-th root. Filter candidates by checking plaintext length or ASCII validity.

---

## Batch GCD for Shared Prime Factoring (BSidesSF 2025)

When multiple RSA moduli share a common prime factor (due to faulty hardware RNG, smartcard bugs, or weak seeding):

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """Find shared factors among a list of RSA moduli"""
    # Product tree
    product = reduce(lambda a, b: a * b, moduli)

    factors = {}
    for n in moduli:
        g = gcd(n, product // n)
        if g != 1 and g != n:
            p = g
            q = n // p
            factors[n] = (p, q)
    return factors

# Usage: given list of public keys from smartcards
moduli = [key.n for key in public_keys]
shared = batch_gcd(moduli)
for n, (p, q) in shared.items():
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Private exponent
```

For keys with patterned primes (hardware RNG faults producing primes with fixed bit patterns), combine with Coppersmith's method to recover remaining random bits. See [advanced-math.md](advanced-math.md) for Coppersmith.

**Key insight:** A single shared prime compromises both keys. Batch GCD runs in O(n log n) time via product/remainder trees, making it feasible for thousands of keys. Real-world incidents: Taiwanese citizen smartcards (2013), many IoT device certificates.
