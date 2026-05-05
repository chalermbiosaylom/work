#!/usr/bin/env sage
"""Coppersmith template: recover small unknown low bits of p from N."""

# Fill these values
N = 0x0
p_high = 0x0
unknown_bits = 128

R = Zmod(N)
P.<x> = PolynomialRing(R)
f = p_high + x

print("[*] Searching small roots...")
roots = f.small_roots(X=2^unknown_bits, beta=0.5)

if not roots:
    print("[-] No roots found")
    raise SystemExit(1)

x0 = Integer(roots[0])
p = Integer(p_high + x0)
if p <= 1 or N % p != 0:
    print("[-] Invalid factor candidate")
    raise SystemExit(1)

q = Integer(N // p)
print(f"[+] p={p}")
print(f"[+] q={q}")
