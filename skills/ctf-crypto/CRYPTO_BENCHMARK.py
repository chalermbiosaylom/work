#!/usr/bin/env python3
import argparse
import json
import pathlib
from typing import Dict, List, Tuple

DEFAULT_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-crypto/CRYPTO_BENCHMARK_CASES.json"

def parse_line(line: str) -> Dict[str, str]:
    text = (line or "").strip()
    if not text.startswith("AttackPlan:"):
        return {}

    body = text[len("AttackPlan:") :].strip()
    parts = [p.strip() for p in body.split("|") if p.strip()]
    data: Dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        data[key.strip().lower()] = value.strip()

    attack = data.get("attack", "")
    tool = data.get("tool", "")
    solver = data.get("solver", "")
    confidence = data.get("confidence", "")

    if not attack or tool not in {"python", "sage"} or solver not in {"program", "one-liner"}:
        return {}
    if not confidence.isdigit():
        return {}

    return {
        "attack": attack,
        "tool": tool,
        "solver": solver,
        "confidence": confidence,
    }


def score_case(expected: Dict[str, str], got: Dict[str, str]) -> Tuple[int, List[str]]:
    checks = [
        ("attack", expected["expected_attack"], got.get("attack")),
        ("tool", expected["expected_tool"], got.get("tool")),
        ("solver", expected["expected_solver_type"], got.get("solver")),
    ]

    score = 0
    issues: List[str] = []
    for key, exp, actual in checks:
        if exp == actual:
            score += 1
        else:
            issues.append(f"{key}: expected={exp}, got={actual}")

    conf = got.get("confidence", "")
    if conf.isdigit() and int(conf) >= 4:
        score += 1
    else:
        issues.append("confidence: expected integer >= 4")

    return score, issues


def main() -> None:
    p = argparse.ArgumentParser(description="Benchmark ctf-crypto attack planning quality")
    p.add_argument("--cases", default=DEFAULT_CASES)
    p.add_argument("--answers", required=True, help="JSON mapping case_name -> AttackPlan line")
    p.add_argument("--pass-threshold", type=float, default=0.85)
    args = p.parse_args()

    case_path = pathlib.Path(args.cases)
    ans_path = pathlib.Path(args.answers)

    if not case_path.exists():
        raise SystemExit(f"cases file not found: {case_path}")
    if not ans_path.exists():
        raise SystemExit(f"answers file not found: {ans_path}")

    cases = json.loads(case_path.read_text(encoding="utf-8"))
    answers = json.loads(ans_path.read_text(encoding="utf-8"))

    total = 0
    earned = 0
    rows = []

    for c in cases:
        name = c["name"]
        line = str(answers.get(name, ""))
        got = parse_line(line)
        total += 4

        if not got:
            rows.append({
                "name": name,
                "score": 0,
                "max_score": 4,
                "status": "fail",
                "issues": ["invalid AttackPlan line format"],
            })
            continue

        s, issues = score_case(c, got)
        earned += s
        rows.append({
            "name": name,
            "score": s,
            "max_score": 4,
            "status": "pass" if s == 4 else "partial",
            "issues": issues,
        })

    acc = earned / total if total else 0.0
    out = {
        "summary": {
            "cases": len(cases),
            "earned_points": earned,
            "max_points": total,
            "accuracy": round(acc, 4),
            "pass_threshold": args.pass_threshold,
            "passed": acc >= args.pass_threshold,
        },
        "results": rows,
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
