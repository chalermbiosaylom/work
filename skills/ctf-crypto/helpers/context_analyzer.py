#!/usr/bin/env python3
"""Context analyzer for crypto challenge source text.

Goal: reduce context-confusion traps by extracting and ranking real parameters
instead of trusting first-seen assignments.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Dict, List

NAME_PATTERNS = {
    "n": re.compile(r"\bn\s*=\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE),
    "e": re.compile(r"\be\s*=\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE),
    "c": re.compile(r"\bc\s*=\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE),
}

DECOY_HINTS = ["decoy", "fake", "not real", "dummy", "bait"]


class ContextAnalyzer:
    def __init__(self, source_code: str):
        self.source = source_code or ""

    @staticmethod
    def _parse_int(raw: str) -> int:
        return int(raw.strip(), 0)

    def _score_line(self, line: str) -> int:
        line_low = line.lower()
        score = 10
        for hint in DECOY_HINTS:
            if hint in line_low:
                score -= 6
        if "#" in line_low and "real" in line_low:
            score += 2
        return score

    def extract_candidates(self) -> Dict[str, List[Dict[str, object]]]:
        out: Dict[str, List[Dict[str, object]]] = {"n": [], "e": [], "c": []}
        lines = self.source.splitlines()

        for idx, line in enumerate(lines, start=1):
            for name, rx in NAME_PATTERNS.items():
                for m in rx.finditer(line):
                    raw_value = m.group(1)
                    try:
                        parsed = self._parse_int(raw_value)
                    except Exception:
                        continue
                    out[name].append(
                        {
                            "line": idx,
                            "raw": raw_value,
                            "value": parsed,
                            "score": self._score_line(line),
                            "context": line.strip(),
                        }
                    )
        return out

    def select_best(self, candidates: Dict[str, List[Dict[str, object]]]) -> Dict[str, Dict[str, object]]:
        best: Dict[str, Dict[str, object]] = {}
        for name, items in candidates.items():
            if not items:
                continue
            ranked = sorted(items, key=lambda x: (int(x["score"]), int(x["line"])), reverse=True)
            best[name] = ranked[0]
        return best

    def analyze(self) -> Dict[str, object]:
        candidates = self.extract_candidates()
        best = self.select_best(candidates)
        warnings: List[str] = []

        for key in ("n", "e", "c"):
            if len(candidates.get(key, [])) > 1:
                warnings.append(f"multiple {key} candidates detected; avoid first-value trust")
            if key not in best:
                warnings.append(f"missing {key} candidate")

        return {
            "status": "ok",
            "best": best,
            "candidates": candidates,
            "warnings": warnings,
        }


def main() -> None:
    p = argparse.ArgumentParser(description="Detect likely real n/e/c values from challenge source")
    p.add_argument("file", help="path to source file")
    p.add_argument("--json", action="store_true", help="print JSON output")
    args = p.parse_args()

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    result = ContextAnalyzer(source).analyze()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
