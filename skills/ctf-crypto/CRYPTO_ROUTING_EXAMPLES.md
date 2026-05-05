# CRYPTO_ROUTING_EXAMPLES (Hard Mode)

Use these one-line drills to enforce fast, correct AttackPlan selection.

## Output Contract (Mandatory)
`AttackPlan: attack=<name> | tool=<python|sage> | solver=<program|one-liner> | confidence=<n>`

---

## 1) RSA e=3 + small plaintext
Evidence:
- `e=3`
- single ciphertext

Line:
`AttackPlan: attack=small-e | tool=python | solver=program | confidence=7`

## 2) RSA suspicious small d
Evidence:
- very large `e`
- classic Wiener hint

Line:
`AttackPlan: attack=wiener | tool=python | solver=program | confidence=7`

## 3) RSA close primes (Fermat)
Evidence:
- hint: `p` and `q` very close

Line:
`AttackPlan: attack=fermat | tool=python | solver=program | confidence=6`

## 4) Coppersmith partial prime bits
Evidence:
- partial known bits of `p`
- structured polynomial relation

Line:
`AttackPlan: attack=coppersmith | tool=sage | solver=program | confidence=6`

## 5) ECC anomalous curve (Smart)
Evidence:
- curve order equals field prime

Line:
`AttackPlan: attack=smart | tool=sage | solver=program | confidence=7`

## 6) LWE/CVP lattice reduction
Evidence:
- matrix `A`, vector `b`, modulus `q`
- CVP/LLL phrasing

Line:
`AttackPlan: attack=lwe-cvp | tool=sage | solver=program | confidence=7`

## 7) CBC padding oracle
Evidence:
- distinguishable padding error response

Line:
`AttackPlan: attack=padding-oracle | tool=python | solver=program | confidence=6`

## 8) Bleichenbacher / PKCS#1 oracle
Evidence:
- RSA PKCS#1 v1.5 validity oracle

Line:
`AttackPlan: attack=bleichenbacher | tool=python | solver=program | confidence=6`

## 9) MT19937 output prediction
Evidence:
- repeated RNG outputs
- need next token prediction

Line:
`AttackPlan: attack=mt-state-recovery | tool=python | solver=program | confidence=7`

## 10) Unknown multilayer decode chain
Evidence:
- base64/hex/reverse fragments
- no direct category hint

Line:
`AttackPlan: attack=decode-chain | tool=python | solver=program | confidence=5`
