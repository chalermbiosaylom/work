#!/usr/bin/env python3
"""flag_filter - score flag candidates, demote decoys, rank by confidence.

Usage:
    grep -oE 'coc2026\\{[^}]+\\}' out.txt | python3 flag_filter.py
    python3 flag_filter.py --min-score 3 < candidates.txt

Exit code:
    0 if at least one candidate passed min-score, else 1.
"""
from __future__ import annotations
import argparse
import re
import sys
from typing import List, Tuple

DECOY_KEYWORDS = [
    "fake", "test", "try", "harder", "noob", "wrong",
    "decoy", "haha", "nice_try", "lol", "troll", "gotcha",
    "look_elsewhere", "not_here", "nope",
]

FLAG_RE = re.compile(
    r"(?:coc2026|RTAF|rtaf|flag|ctf|f1a9|fl4g)\{([^}\r\n]{1,200})\}",
    re.IGNORECASE,
)


def score_candidate(full: str, inner: str) -> int:
    score = 0
    low = inner.lower()

    # Penalize decoy keywords
    for kw in DECOY_KEYWORDS:
        if kw in low:
            score -= 10

    if len(inner) == 0:
        return score - 20

    # Reward character entropy
    if len(set(inner)) > len(inner) * 0.5:
        score += 5

    # Reward mixed character classes
    if re.search(r"[a-z]", inner) and re.search(r"[A-Z]", inner):
        score += 3
    if re.search(r"\d", inner):
        score += 2
    if re.search(r"[^A-Za-z0-9]", inner):
        score += 2

    # Reward realistic length
    if len(inner) > 10:
        score += 3
    if len(inner) > 24:
        score += 2

    # Penalize trivial patterns
    if inner.lower() in {"flag", "test", "admin", "password"}:
        score -= 15
    if re.fullmatch(r"(.)\1{3,}", inner):  # aaaa...
        score -= 10

    return score


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-score", type=int, default=0,
                        help="Minimum score to accept (default 0)")
    parser.add_argument("--loot", default="/tmp/ctf_loot.txt",
                        help="Path to append accepted flags")
    args = parser.parse_args()

    raw = sys.stdin.read()
    candidates: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = FLAG_RE.search(line)
        if m:
            candidates.append(m.group(0))
        elif line.startswith(("coc2026{", "flag{", "RTAF{", "rtaf{")):
            candidates.append(line)

    if not candidates:
        print("[filter] no candidates found on stdin", file=sys.stderr)
        return 1

    scored: List[Tuple[int, str]] = []
    for c in candidates:
        m = re.match(r"[^{]+\{([^}]*)\}", c)
        inner = m.group(1) if m else c
        scored.append((score_candidate(c, inner), c))

    scored.sort(reverse=True)

    accepted = []
    for score, flag in scored:
        marker = "PASS" if score >= args.min_score else "drop"
        print(f"[{marker}] {score:+4d}  {flag}")
        if score >= args.min_score:
            accepted.append(flag)

    if accepted:
        try:
            with open(args.loot, "a", encoding="utf-8") as f:
                for fl in accepted:
                    f.write(f"flag_candidate | score_pass | {fl}\n")
        except Exception:
            pass
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
