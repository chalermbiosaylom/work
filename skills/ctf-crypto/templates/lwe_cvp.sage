#!/usr/bin/env sage
"""LWE/CVP template (Babai nearest plane)."""

from fpylll import CVP

# Fill these values
q = 0
A_data = []  # m x n integer matrix
b_data = []  # length m vector

A = Matrix(ZZ, A_data)
b = vector(ZZ, b_data)
m = A.nrows()
n = A.ncols()

if q <= 0 or m == 0 or n == 0:
    print("[-] Fill q, A_data, b_data first")
    raise SystemExit(1)

L = block_matrix([
    [q * identity_matrix(ZZ, n), zero_matrix(ZZ, n, m)],
    [A.transpose(), identity_matrix(ZZ, m)],
])

print("[*] LLL reducing lattice...")
Lred = L.LLL()
target = vector(ZZ, [0] * n + list(b))
closest = CVP.babai(Lred, target)

s_candidate = vector(ZZ, closest[:n])
print(f"[+] s_candidate = {list(s_candidate)}")
