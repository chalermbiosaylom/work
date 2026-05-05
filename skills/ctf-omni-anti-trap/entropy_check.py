#!/usr/bin/env python3
"""entropy_check - flag likely-packed binaries or noise-filled stego images.

Usage:
    python3 entropy_check.py <file>
    python3 entropy_check.py ./binary
    python3 entropy_check.py ./suspicious.png

Exit code:
    0 if entropy looks normal, 1 if suspicious (packed/encrypted/trap).
"""
from __future__ import annotations
import math
import sys
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def lsb_unique_ratio(path: str) -> float | None:
    try:
        from PIL import Image  # type: ignore
        import numpy as np     # type: ignore
    except Exception:
        return None
    try:
        img = Image.open(path)
        arr = list(img.getdata())
        flat = []
        for px in arr[:1000]:
            if isinstance(px, tuple):
                flat.extend(px)
            else:
                flat.append(px)
        lsb = [p & 1 for p in flat[:1000]]
        if not lsb:
            return None
        return len(set(lsb)) / len(lsb)
    except Exception:
        return None


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: entropy_check.py <file>", file=sys.stderr)
        return 2
    path = sys.argv[1]

    with open(path, "rb") as f:
        data = f.read()

    ent = shannon_entropy(data)
    print(f"[entropy] {ent:.3f} bits/byte ({len(data)} bytes) {path}")

    suspicious = False
    if ent > 7.5:
        print("[WARN] high entropy (>7.5) - likely packed/encrypted or random fill")
        suspicious = True

    if path.lower().endswith((".png", ".bmp", ".jpg", ".jpeg")):
        ratio = lsb_unique_ratio(path)
        if ratio is not None:
            print(f"[lsb_ratio] {ratio:.3f}")
            if ratio < 0.1:
                print("[WARN] LSB unique ratio <0.1 - likely noise trap, not real stego")
                suspicious = True

    return 1 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
