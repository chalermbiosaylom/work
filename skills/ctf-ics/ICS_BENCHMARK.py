#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
from typing import Dict, List, Tuple

DEFAULT_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-ics/ICS_BENCHMARK_CASES.json"


def run_case(case: Dict[str, object], timeout: int) -> Tuple[int, str, str]:
    cmd = str(case.get("command", "")).strip()
    if not cmd:
        return 127, "", "empty command"

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            timeout=timeout,
            executable="/bin/bash",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as ex:
        out = ex.stdout or ""
        err = (ex.stderr or "") + "\nTIMEOUT"
        return 124, out, err


def score_case(case: Dict[str, object], rc: int, out: str, err: str) -> Tuple[int, List[str]]:
    issues: List[str] = []
    score = 0

    expected_rc = int(case.get("expected_exit_code", 0))
    if rc == expected_rc:
        score += 1
    else:
        issues.append(f"exit_code: expected={expected_rc}, got={rc}")

    text = f"{out}\n{err}"
    must = case.get("must_contain", [])
    if not isinstance(must, list):
        must = []

    content_hits = 0
    for token in must:
        token = str(token)
        if token in text:
            content_hits += 1
        else:
            issues.append(f"missing token: {token}")

    if must:
        if content_hits == len(must):
            score += 1
    else:
        score += 1

    return score, issues


def main() -> None:
    p = argparse.ArgumentParser(description="Benchmark ctf-ics readiness commands")
    p.add_argument("--cases", default=DEFAULT_CASES)
    p.add_argument("--pass-threshold", type=float, default=0.85)
    p.add_argument("--timeout", type=int, default=60)
    args = p.parse_args()

    case_path = pathlib.Path(args.cases)
    if not case_path.exists():
        raise SystemExit(f"cases file not found: {case_path}")

    raw = json.loads(case_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("cases must be a JSON list")

    total = 0
    earned = 0
    rows = []

    for case in raw:
        if not isinstance(case, dict):
            continue
        name = str(case.get("name", "unnamed"))
        rc, out, err = run_case(case, timeout=args.timeout)
        s, issues = score_case(case, rc, out, err)

        total += 2
        earned += s
        rows.append(
            {
                "name": name,
                "score": s,
                "max_score": 2,
                "status": "pass" if s == 2 else "partial" if s == 1 else "fail",
                "issues": issues,
                "return_code": rc,
            }
        )

    acc = earned / total if total else 0.0
    result = {
        "summary": {
            "cases": len(rows),
            "earned_points": earned,
            "max_points": total,
            "accuracy": round(acc, 4),
            "pass_threshold": args.pass_threshold,
            "passed": acc >= args.pass_threshold,
        },
        "results": rows,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
