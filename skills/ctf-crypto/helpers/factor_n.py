#!/usr/bin/env python3
"""Offline-first integer factorization helper.

Priority chain:
1) yafu (local)
2) msieve (local)
3) FactorDB (optional online fallback)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Dict, List, Optional

try:
    import requests
except Exception:  # requests is optional
    requests = None


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def _trial_factor(n: int, max_divisor: int = 1_000_000) -> Optional[List[int]]:
    if n < 2:
        return None
    if _is_prime(n):
        return [n]

    rem = n
    factors: List[int] = []

    while rem % 2 == 0:
        factors.append(2)
        rem //= 2

    d = 3
    while d * d <= rem and d <= max_divisor:
        while rem % d == 0:
            factors.append(d)
            rem //= d
        d += 2

    if rem > 1:
        factors.append(rem)

    prod = 1
    for f in factors:
        prod *= f
    if prod == n:
        return factors
    return None


def _parse_factordb(payload: Dict) -> Optional[List[int]]:
    status = payload.get("status", "")
    factors_raw = payload.get("factors", [])
    if status not in {"FF", "CF"} or not isinstance(factors_raw, list):
        return None

    out: List[int] = []
    for item in factors_raw:
        if not isinstance(item, list) or len(item) != 2:
            continue
        base, exp = item
        try:
            b = int(str(base))
            e = int(str(exp))
            out.extend([b] * e)
        except Exception:
            continue

    return out or None


def _parse_yafu(stdout: str) -> Optional[List[int]]:
    factors: List[int] = []
    for line in stdout.splitlines():
        m = re.search(r"\b[PC]\d+\s*=\s*(\d+)", line)
        if not m:
            continue
        if line.strip().startswith("C"):
            return None
        factors.append(int(m.group(1)))
    return factors or None


def _parse_msieve(stdout: str) -> Optional[List[int]]:
    factors: List[int] = []
    for line in stdout.splitlines():
        m = re.search(r"\bp\d+\s*:\s*(\d+)", line.strip(), flags=re.IGNORECASE)
        if m:
            factors.append(int(m.group(1)))
    return factors or None


def _run(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def yafu_factor(n: int, timeout: int) -> Optional[List[int]]:
    try:
        proc = _run(["yafu", f"factor({n})"], timeout=timeout)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    return _parse_yafu(proc.stdout)


def msieve_factor(n: int, timeout: int) -> Optional[List[int]]:
    try:
        proc = _run(["msieve", str(n)], timeout=timeout)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    return _parse_msieve(proc.stdout)


def factordb_factor(n: int, timeout: int) -> Optional[List[int]]:
    if requests is None:
        return None
    try:
        r = requests.get(f"http://factordb.com/api?query={n}", timeout=timeout)
        if r.status_code != 200:
            return None
        return _parse_factordb(r.json())
    except Exception:
        return None


def factor_n(n: int, timeout: int = 60, use_factordb: bool = True) -> Dict:
    trial = _trial_factor(n)
    if trial:
        return {"success": True, "method": "trial", "n": n, "factors": trial}

    factors = yafu_factor(n, timeout=timeout)
    if factors:
        return {"success": True, "method": "yafu", "n": n, "factors": factors}

    factors = msieve_factor(n, timeout=timeout)
    if factors:
        return {"success": True, "method": "msieve", "n": n, "factors": factors}

    if use_factordb:
        factors = factordb_factor(n, timeout=5)
        if factors:
            return {"success": True, "method": "factordb", "n": n, "factors": factors}

    return {
        "success": False,
        "method": "failed",
        "n": n,
        "factors": None,
        "message": "No method succeeded (yafu/msieve/factordb)",
    }


def _verify(n: int, factors: List[int]) -> bool:
    p = 1
    for f in factors:
        p *= int(f)
    return p == n


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline-first factorization helper")
    parser.add_argument("n", help="Integer to factor (decimal or 0x-hex)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout per local method")
    parser.add_argument("--no-factordb", action="store_true", help="Disable FactorDB fallback")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    n = int(args.n, 0)
    result = factor_n(n, timeout=args.timeout, use_factordb=not args.no_factordb)

    if result.get("success") and result.get("factors"):
        result["verified"] = _verify(n, result["factors"])

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    print("=" * 60)
    print("Factorization result")
    print("=" * 60)
    print(f"n bits: {n.bit_length()}")
    print(f"method: {result['method']}")
    if result.get("success"):
        print(f"factors: {result['factors']}")
        print(f"verified: {result.get('verified', False)}")
    else:
        print(result.get("message", "failed"))


if __name__ == "__main__":
    main()
