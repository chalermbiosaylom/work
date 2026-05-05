#!/usr/bin/env python3
"""Generate challenge-specific crypto solver scaffold (Python/Sage)."""

from __future__ import annotations

import argparse
from pathlib import Path

PYTHON_RSA_TEMPLATE = """#!/usr/bin/env python3
import json
import gmpy2
from Crypto.Util.number import long_to_bytes

# Challenge: {challenge_name}
# Fill values
n = {n}
e = {e}
c = {c}

def solve() -> dict:
    # TODO: implement attack path
    # 1) small-e
    # 2) wiener
    # 3) fermat/factor_n helper
    return {{
        "status": "todo",
        "attack": "rsa",
        "m": None,
        "flags": [],
    }}

if __name__ == "__main__":
    print(json.dumps(solve(), indent=2, ensure_ascii=False))
"""

SAGE_COPPERSMITH_TEMPLATE = """#!/usr/bin/env sage
import json

# Challenge: {challenge_name}
N = {n}
e = {e}
c = {c}
p_high = {p_high}
unknown_bits = {unknown_bits}

R = Zmod(N)
P.<x> = PolynomialRing(R)
f = p_high + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5)

out = {{"status": "todo", "attack": "coppersmith", "roots": [int(r) for r in roots]}}
print(json.dumps(out, indent=2, ensure_ascii=False))
"""

SAGE_ECC_TEMPLATE = """#!/usr/bin/env sage
import json

# Challenge: {challenge_name}
p = {p}
a = {a}
b = {b}
Gx, Gy = {Gx}, {Gy}
Px, Py = {Px}, {Py}

F = GF(p)
E = EllipticCurve(F, [a, b])
G = E(Gx, Gy)
P = E(Px, Py)

out = {{
    "status": "todo",
    "attack": "ecc",
    "curve_order": int(E.order()),
    "factors": str(factor(E.order())),
}}
print(json.dumps(out, indent=2, ensure_ascii=False))
"""

SAGE_LWE_TEMPLATE = """#!/usr/bin/env sage
import json

# Challenge: {challenge_name}
q = {q}
A_data = {A}
b_data = {b}

A = Matrix(ZZ, A_data)
b = vector(ZZ, b_data)

out = {{
    "status": "todo",
    "attack": "lwe-cvp",
    "rows": int(A.nrows()),
    "cols": int(A.ncols()),
    "q": int(q),
}}
print(json.dumps(out, indent=2, ensure_ascii=False))
"""


TEMPLATES = {
    "rsa": (PYTHON_RSA_TEMPLATE, ".py"),
    "coppersmith": (SAGE_COPPERSMITH_TEMPLATE, ".sage"),
    "ecc": (SAGE_ECC_TEMPLATE, ".sage"),
    "lwe": (SAGE_LWE_TEMPLATE, ".sage"),
}

DEFAULT_PARAMS = {
    "challenge_name": "crypto_challenge",
    "n": "0",
    "e": "65537",
    "c": "0",
    "p_high": "0",
    "unknown_bits": "128",
    "p": "0",
    "a": "0",
    "b": "0",
    "Gx": "0",
    "Gy": "0",
    "Px": "0",
    "Py": "0",
    "q": "0",
    "A": "[]",
    "b": "[]",
}


def parse_kv(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise SystemExit(f"invalid --set value: {item} (expected key=value)")
        k, v = item.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise SystemExit(f"invalid key in --set: {item}")
        out[k] = v
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Generate crypto solver scaffold")
    p.add_argument("--type", required=True, choices=sorted(TEMPLATES.keys()), help="solver type")
    p.add_argument("--output", default="", help="output file path")
    p.add_argument("--set", action="append", default=[], help="template override key=value (repeatable)")
    args = p.parse_args()

    template, ext = TEMPLATES[args.type]
    output_path = Path(args.output) if args.output else Path(f"solve_{args.type}{ext}")

    params = dict(DEFAULT_PARAMS)
    params.update(parse_kv(args.set))

    try:
        content = template.format(**params)
    except KeyError as ex:
        raise SystemExit(f"missing template key: {ex}")

    output_path.write_text(content, encoding="utf-8")
    output_path.chmod(0o755)
    print(f"generated: {output_path}")


if __name__ == "__main__":
    main()
