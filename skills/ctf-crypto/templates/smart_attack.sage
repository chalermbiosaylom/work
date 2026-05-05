#!/usr/bin/env sage
"""Smart attack template for anomalous curves (#E(Fp)=p)."""

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

order = E.order()
print(f"[*] Curve order = {order}")
if order != p:
    print("[-] Not anomalous (Smart attack precondition fails)")
    raise SystemExit(1)

k = G.discrete_log(P)
print(f"[+] k = {k}")
