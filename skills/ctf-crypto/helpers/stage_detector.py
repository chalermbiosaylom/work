#!/usr/bin/env python3
"""Lightweight detector for multi-stage challenge flow hints."""

from __future__ import annotations

import argparse
import json
import re
from typing import Dict, List

STAGE_RX = re.compile(r"\bstage\s*([0-9]+)?", re.IGNORECASE)
GATE_HINTS = ["captcha", "otp", "token", "verify", "time window", "physical", "gps"]


def detect_stages(text: str) -> Dict[str, object]:
    text = text or ""
    normalized = re.sub(r"\s+", " ", text.lower()).strip()

    stage_mentions = STAGE_RX.findall(normalized)
    explicit_count = len([x for x in stage_mentions if x])
    generic_count = len(stage_mentions)

    gates: List[str] = [h for h in GATE_HINTS if h in normalized]
    estimated = max(explicit_count, 1 if gates else 0, min(4, generic_count))

    recommendations: List[str] = []
    if estimated >= 2:
        recommendations.append("treat as multi-stage; verify completion criteria per stage")
    if "otp" in gates or "time window" in gates:
        recommendations.append("enforce strict timeout and clock-sync checks")
    if "captcha" in gates or "physical" in gates:
        recommendations.append("mark likely human-gated stage and park for later")

    return {
        "status": "ok",
        "estimated_stages": estimated,
        "stage_mentions": generic_count,
        "gate_hints": gates,
        "recommendations": recommendations,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Detect multi-stage trap indicators in challenge text")
    p.add_argument("file", help="path to input text file")
    p.add_argument("--json", action="store_true", help="print JSON output")
    args = p.parse_args()

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()

    result = detect_stages(data)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
