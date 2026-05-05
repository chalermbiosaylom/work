#!/usr/bin/env python3
"""Heuristic detector for common crypto red-herring patterns."""

from __future__ import annotations

import argparse
import json
import re
from typing import Dict, List

RULES = [
    {
        "id": "small_e_with_padding",
        "when": ["e=3", "oaep"],
        "severity": "high",
        "message": "small-e bait likely invalid because OAEP/padding is present",
    },
    {
        "id": "fake_flag_words",
        "when": ["fake flag"],
        "severity": "high",
        "message": "explicit fake-flag wording found; require provenance validation",
    },
    {
        "id": "decoy_parameter",
        "when": ["decoy"],
        "severity": "medium",
        "message": "decoy marker detected near parameters",
    },
    {
        "id": "first_value_trap",
        "when": ["not the real"],
        "severity": "medium",
        "message": "source hints first-seen values are not trustworthy",
    },
]

FLAG_WRAPPER_RX = re.compile(r"(?:coc2026|rtaf|ctf|flag)\{[^}\r\n]{1,200}\}", re.IGNORECASE)


def analyze_text(text: str) -> Dict[str, object]:
    raw = text or ""
    normalized = re.sub(r"\s+", " ", raw.lower()).strip()

    findings: List[Dict[str, str]] = []
    for rule in RULES:
        if all(token in normalized for token in rule["when"]):
            findings.append(
                {
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                }
            )

    candidates = list(dict.fromkeys(FLAG_WRAPPER_RX.findall(raw)))
    needs_strict_validation = len(candidates) > 1 or bool(findings)

    return {
        "status": "ok",
        "findings": findings,
        "candidate_flags": candidates,
        "needs_strict_validation": needs_strict_validation,
        "summary": "red herring risk detected" if findings else "no obvious red-herring pattern",
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Detect likely red-herring patterns in challenge material")
    p.add_argument("file", help="path to input text file")
    p.add_argument("--json", action="store_true", help="print JSON output")
    args = p.parse_args()

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    result = analyze_text(text)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
