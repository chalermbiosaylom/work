#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Dict, List, Tuple

DEFAULT_CASES = "/home/kali/Desktop/.windsurf/skills/solve-challenge/ROUTING_BENCHMARK_CASES.json"

LINE_RE = re.compile(
    r"^Routing to (?P<skill>/[\w-]+) \| primary_mcp=(?P<mcp>[\w-]+) \| confidence=(?P<conf>\d+) \| backup=(?P<backup>/[\w-]+)$"
)


def parse_routing_line(line: str) -> Dict[str, str]:
    m = LINE_RE.match(line.strip())
    if not m:
        return {}
    return {
        "skill": m.group("skill"),
        "primary_mcp": m.group("mcp"),
        "confidence": m.group("conf"),
        "backup": m.group("backup"),
    }


def score_case(expected: Dict[str, str], got: Dict[str, str]) -> Tuple[int, List[str]]:
    checks = [
        ("skill", expected.get("expected_skill"), got.get("skill")),
        ("primary_mcp", expected.get("expected_primary_mcp"), got.get("primary_mcp")),
        ("backup", expected.get("expected_backup"), got.get("backup")),
    ]

    passed = 0
    failed = []
    for key, exp, actual in checks:
        if exp == actual:
            passed += 1
        else:
            failed.append(f"{key}: expected={exp}, got={actual}")

    conf = got.get("confidence")
    if conf is not None and conf.isdigit() and int(conf) >= 4:
        passed += 1
    else:
        failed.append("confidence: expected integer >= 4")

    return passed, failed


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark solve-challenge one-line routing quality")
    parser.add_argument("--cases", default=DEFAULT_CASES)
    parser.add_argument("--answers", required=True, help="JSON mapping: case_name -> routing line")
    parser.add_argument("--pass-threshold", type=float, default=0.85)
    args = parser.parse_args()

    case_path = pathlib.Path(args.cases)
    ans_path = pathlib.Path(args.answers)

    if not case_path.exists():
        raise SystemExit(f"cases file not found: {case_path}")
    if not ans_path.exists():
        raise SystemExit(f"answers file not found: {ans_path}")

    cases = json.loads(case_path.read_text(encoding="utf-8"))
    answers = json.loads(ans_path.read_text(encoding="utf-8"))

    total_points = 0
    earned_points = 0
    per_case = []

    for c in cases:
        name = c["name"]
        answer_line = str(answers.get(name, "")).strip()
        got = parse_routing_line(answer_line)

        total_points += 4
        if not got:
            per_case.append({
                "name": name,
                "score": 0,
                "max_score": 4,
                "status": "fail",
                "issues": ["invalid routing line format"],
            })
            continue

        passed, issues = score_case(c, got)
        earned_points += passed
        per_case.append({
            "name": name,
            "score": passed,
            "max_score": 4,
            "status": "pass" if passed == 4 else "partial",
            "issues": issues,
        })

    ratio = (earned_points / total_points) if total_points else 0.0
    summary = {
        "cases": len(cases),
        "earned_points": earned_points,
        "max_points": total_points,
        "accuracy": round(ratio, 4),
        "pass_threshold": args.pass_threshold,
        "passed": ratio >= args.pass_threshold,
    }

    output = {"summary": summary, "results": per_case}
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
