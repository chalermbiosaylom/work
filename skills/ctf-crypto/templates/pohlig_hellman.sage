#!/usr/bin/env sage
"""Pohlig-Hellman template for ECC DLP with smooth order."""

# Fill these values
p = 0
a = 0
b = 0
Gx, Gy = 0, 0
Px, Py = 0, 0

F = GF(p)
E = EllipticCurve(F, [a, b])
G = E(Gx, Gy)
P = E(Px, Py)

n = G.order()
fac = factor(n)
print(f"[*] |G| = {n}")
print(f"[*] factor(|G|) = {fac}")

k = G.discrete_log(P)
print(f"[+] k = {k}")
