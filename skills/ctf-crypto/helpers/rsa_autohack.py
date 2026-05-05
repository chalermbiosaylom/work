#!/usr/bin/env python3
"""RSA Auto-Hacker (God-Mode triage for common RSA CTF weaknesses)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import gmpy2

try:
    import owiener
except Exception:
    owiener = None


FLAG_WRAPPER_PATTERNS = [
    re.compile(r"(?:coc2026|rtaf|ctf|flag|f1a9|fl4g|tiger|key)\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"\{[a-fA-F0-9]{32}\}"),
]
HASH_TOKEN_PATTERNS = [
    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    re.compile(r"\b[a-fA-F0-9]{40}\b"),
]


def _long_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return int(value).to_bytes((int(value).bit_length() + 7) // 8, "big")


def _preview_text(data: bytes, limit: int = 200) -> str:
    txt = data.decode("utf-8", errors="ignore").replace("\n", " ").replace("\r", " ")
    return txt[:limit]


def _extract_flags(data: bytes, allow_hash_tokens: bool = False) -> List[str]:
    text = data.decode("utf-8", errors="ignore")
    out: List[str] = []
    seen = set()

    for rx in FLAG_WRAPPER_PATTERNS:
        for m in rx.finditer(text):
            token = m.group(0)
            if token not in seen:
                out.append(token)
                seen.add(token)

    if not out and allow_hash_tokens:
        for rx in HASH_TOKEN_PATTERNS:
            for m in rx.finditer(text):
                token = m.group(0)
                if token not in seen:
                    out.append(token)
                    seen.add(token)

    return out


def _small_e_attack(n: int, e: int, c: int, max_k: int) -> Optional[Dict[str, Any]]:
    if e <= 1 or e > 100:
        return None
    for k in range(max_k):
        m, exact = gmpy2.iroot(c + (k * n), e)
        if exact:
            return {"m": int(m), "k_offset": k}
    return None


def _wiener_attack(n: int, e: int, c: int) -> Optional[Dict[str, Any]]:
    if owiener is None:
        return None
    try:
        d = owiener.attack(e, n)
        if not d:
            return None
        m = pow(c, int(d), n)
        return {"m": int(m), "d": int(d)}
    except Exception:
        return None


def _fermat_factor(n: int, max_iterations: int) -> Optional[Tuple[int, int]]:
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n

    for _ in range(max_iterations):
        b = gmpy2.isqrt(b2)
        if b * b == b2:
            p = int(a + b)
            q = int(a - b)
            if p > 1 and q > 1 and p * q == n:
                return p, q
        a += 1
        b2 = a * a - n
    return None


def _fermat_attack(n: int, e: int, c: int, max_iterations: int) -> Optional[Dict[str, Any]]:
    pq = _fermat_factor(n, max_iterations=max_iterations)
    if not pq:
        return None
    p, q = pq
    phi = (p - 1) * (q - 1)
    try:
        d = int(gmpy2.invert(e, phi))
    except Exception:
        return None
    m = pow(c, d, n)
    return {"m": int(m), "p": p, "q": q, "d": d}


def _common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[Dict[str, Any]]:
    g, s, t = gmpy2.gcdext(e1, e2)
    if int(g) != 1:
        return None

    try:
        if s < 0:
            c1 = int(gmpy2.invert(c1, n))
            s = -s
        if t < 0:
            c2 = int(gmpy2.invert(c2, n))
            t = -t
    except Exception:
        return None

    m = (pow(c1, int(s), n) * pow(c2, int(t), n)) % n
    return {"m": int(m), "s": int(s), "t": int(t)}


def _build_success(attack: str, attack_data: Dict[str, Any], allow_hash_tokens: bool) -> Dict[str, Any]:
    m = int(attack_data.get("m", 0))
    plaintext = _long_to_bytes(m)
    flags = _extract_flags(plaintext, allow_hash_tokens=allow_hash_tokens)
    return {
        "status": "success",
        "success": True,
        "attack": attack,
        "flag": flags[0] if flags else None,
        "flags": flags,
        "plaintext_preview": _preview_text(plaintext),
        "details": attack_data,
    }


def run_attacks(args: argparse.Namespace) -> Dict[str, Any]:
    n = int(args.n, 0)
    e = int(args.e, 0)
    c = int(args.c, 0)

    attack_chain = []
    if args.e2 and args.c2:
        e2 = int(args.e2, 0)
        c2 = int(args.c2, 0)
        attack_chain.append(("common_modulus", lambda: _common_modulus_attack(n, e, c, e2, c2)))

    attack_chain.extend(
        [
            ("small_e", lambda: _small_e_attack(n, e, c, max_k=args.max_small_e_k)),
            ("wiener", lambda: _wiener_attack(n, e, c)),
            ("fermat", lambda: _fermat_attack(n, e, c, max_iterations=args.max_fermat_iter)),
        ]
    )

    errors: List[str] = []
    for attack_name, fn in attack_chain:
        try:
            result = fn()
            if result:
                return _build_success(attack_name, result, allow_hash_tokens=args.allow_hash_token)
        except Exception as ex:
            errors.append(f"{attack_name}: {ex}")

    return {
        "status": "failed",
        "success": False,
        "attack": "none",
        "flag": None,
        "flags": [],
        "plaintext_preview": "",
        "details": {},
        "errors": errors,
        "message": "No supported fast attack succeeded",
    }


def main() -> None:
    p = argparse.ArgumentParser(description="RSA Auto-Hacker (fast triage)")
    p.add_argument("--n", required=True, help="RSA modulus (decimal or 0x-hex)")
    p.add_argument("--e", required=True, help="public exponent")
    p.add_argument("--c", required=True, help="ciphertext")
    p.add_argument("--e2", default="", help="second exponent for common modulus")
    p.add_argument("--c2", default="", help="second ciphertext for common modulus")
    p.add_argument("--max-small-e-k", type=int, default=1000)
    p.add_argument("--max-fermat-iter", type=int, default=100000)
    p.add_argument("--allow-hash-token", action="store_true", help="allow raw 32/40-hex token fallback")
    p.add_argument("--json", action="store_true", help="emit JSON output")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    result = run_attacks(args)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    print("=" * 60)
    print("RSA AUTO-HACKER")
    print("=" * 60)
    print(f"status: {result['status']}")
    print(f"attack: {result['attack']}")
    if result.get("flag"):
        print(f"flag: {result['flag']}")
    elif result.get("plaintext_preview"):
        print(f"preview: {result['plaintext_preview']}")
    if args.verbose and result.get("errors"):
        print(f"errors: {result['errors']}")


if __name__ == "__main__":
    main()
