#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Any, Dict, List, Tuple

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-pwn/PWN_BENCHMARK_CASES.json"

TRACK_HINTS: List[Tuple[str, List[str]]] = [
    ("bof-ret2win", ["gets", "ret2win", "win()", "no pie", "no canary", "overflow"]),
    ("ret2libc", ["puts@got", "libc", "system", "/bin/sh", "plt", "got leak"]),
    ("format-string", ["format string", "printf(user_input)", "%p", "%n", "fmtstr"]),
    ("heap-uaf", ["uaf", "use after free", "tcache", "fastbin", "malloc", "free"]),
    ("srop-syscall", ["sigreturn", "srop", "syscall", "rax control", "frame"]),
    ("seccomp-bypass", ["seccomp", "orw", "openat", "sandbox syscall"]),
    ("race-condition", ["pthread", "race", "toctou", "sleep", "usleep"]),
    ("blind-remote-pwn", ["remote only", "blind", "timeout", "no crash output"]),
    ("kernel-pwn", ["kernel", "smep", "smap", "kaslr", "/dev", "ioctl"]),
    ("sandbox-escape", ["sandbox", "restricted", "custom vm", "interpreter", "escape"]),
]

TRACK_PRIMARY_MCP: Dict[str, str] = {
    "bof-ret2win": "ctf-solve",
    "ret2libc": "pentest-mcp",
    "format-string": "ctf-solve",
    "heap-uaf": "pentest-mcp",
    "srop-syscall": "pentest-mcp",
    "seccomp-bypass": "pentest-mcp",
    "race-condition": "pentest-mcp",
    "blind-remote-pwn": "pentest-mcp",
    "kernel-pwn": "pentest-mcp",
    "sandbox-escape": "pentest-mcp",
}

TRACK_SUPPLEMENTAL_MCP: Dict[str, str] = {
    "bof-ret2win": "pentest-mcp",
    "ret2libc": "ctf-solve",
    "format-string": "pentest-mcp",
    "heap-uaf": "ctf-solve",
    "srop-syscall": "ctf-solve",
    "seccomp-bypass": "ctf-solve",
    "race-condition": "ctf-solve",
    "blind-remote-pwn": "ctf-solve",
    "kernel-pwn": "ctf-reverse",
    "sandbox-escape": "ctf-reverse",
}

TRACK_FIRST_ACTION: Dict[str, str] = {
    "bof-ret2win": "run-checksec-and-find-offset",
    "ret2libc": "build-two-stage-leak-chain",
    "format-string": "find-format-offset-and-leak",
    "heap-uaf": "map-heap-primitives-and-target",
    "srop-syscall": "prepare-sigreturn-frame",
    "seccomp-bypass": "design-orw-rop-chain",
    "race-condition": "stabilize-race-harness",
    "blind-remote-pwn": "build-timeout-safe-probe-loop",
    "kernel-pwn": "verify-kernel-primitives",
    "sandbox-escape": "diff-host-vs-sandbox-capabilities",
}


def select_supplemental_mcp(track: str, text: str) -> str:
    # Pwn+OS cross-skill patterns (shell obtained, need privesc)
    if any(k in text for k in ["shell obtained", "privesc", "sudo -l", "suid", "capabilities", "post-exploit"]):
        return "ctf-os-exploit"
    # Default track-specific supplemental
    return TRACK_SUPPLEMENTAL_MCP.get(track, "pentest-mcp")


def select_first_action(track: str, text: str) -> str:
    # Pwn+OS handoff patterns
    if any(k in text for k in ["shell obtained", "privesc", "sudo -l", "suid", "capabilities", "post-exploit"]):
        return "handoff-pwn-os-shell-stabilization"
    # Default track-specific actions
    return TRACK_FIRST_ACTION.get(track, "run-checksec-and-find-offset")


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    return ""


def load_json_file(path: str) -> Any:
    p = pathlib.Path(path).resolve()
    if not p.exists():
        raise SystemExit(f"json file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def infer_track_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str, str, str, int, List[str]]:
    explicit = str(artifact.get("track", "")).strip().lower()
    text = re.sub(r"\s+", " ", _flatten_text(artifact).lower()).strip()

    if explicit:
        return (
            explicit,
            TRACK_PRIMARY_MCP.get(explicit, "ctf-solve"),
            TRACK_SUPPLEMENTAL_MCP.get(explicit, "pentest-mcp"),
            TRACK_FIRST_ACTION.get(explicit, "run-checksec-and-find-offset"),
            9,
            ["track field provided in artifact"],
        )

    if "interactive" in text and any(k in text for k in ["remote", "menu", "heap", "race", "blind"]):
        forced = "blind-remote-pwn"
        return (
            forced,
            TRACK_PRIMARY_MCP[forced],
            TRACK_SUPPLEMENTAL_MCP[forced],
            TRACK_FIRST_ACTION[forced],
            8,
            ["priority rule: continuous interactive pwn loop"],
        )

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}
    for track, hints in TRACK_HINTS:
        for hint in hints:
            if hint in text:
                scores[track] = scores.get(track, 0) + 1
                reasons.setdefault(track, []).append(hint)

    if not scores:
        fallback = "bof-ret2win"
        return (
            fallback,
            TRACK_PRIMARY_MCP[fallback],
            TRACK_SUPPLEMENTAL_MCP[fallback],
            TRACK_FIRST_ACTION[fallback],
            4,
            ["fallback: no strong hints found"],
        )

    best = max(scores, key=lambda x: scores[x])
    conf = min(9, 4 + scores[best])
    matched = reasons.get(best, [])
    return (
        best,
        TRACK_PRIMARY_MCP[best],
        select_supplemental_mcp(best, text),
        select_first_action(best, text),
        conf,
        [f"matched hints: {', '.join(matched)}"],
    )


def build_plan_line(track: str, primary: str, supplemental: str, first_action: str, confidence: int) -> str:
    return (
        "AttackPlan: "
        f"track={track} | "
        f"primary_mcp={primary} | "
        f"supplemental_mcp={supplemental} | "
        "execution_mode=hybrid | "
        f"first_action={first_action} | "
        f"confidence={confidence}"
    )


def infer_many_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts, start=1):
        track, primary, supplemental, action, conf, notes = infer_track_from_artifact(artifact)
        rows.append(
            {
                "index": idx,
                "track": track,
                "execution_mode": "hybrid",
                "primary_mcp": primary,
                "supplemental_mcp": supplemental,
                "first_action": action,
                "confidence": conf,
                "attack_plan": build_plan_line(track, primary, supplemental, action, conf),
                "inference_notes": notes,
            }
        )
    return {"summary": {"artifacts": len(rows), "execution_mode": "hybrid"}, "results": rows}


def benchmark_mode(cases_path: str, pass_threshold: float) -> Dict[str, Any]:
    raw = load_json_file(cases_path)
    if not isinstance(raw, list):
        raise SystemExit("benchmark cases json must be a list")

    rows: List[Dict[str, Any]] = []
    total = 0
    earned = 0

    for case in raw:
        if not isinstance(case, dict):
            continue
        total += 5
        track, primary, supplemental, action, conf, notes = infer_track_from_artifact(case)
        score = 0
        issues: List[str] = []

        if track == str(case.get("expected_track", "")):
            score += 1
        else:
            issues.append(f"track: expected={case.get('expected_track')}, got={track}")

        if primary == str(case.get("expected_primary_mcp", "")):
            score += 1
        else:
            issues.append(f"primary_mcp: expected={case.get('expected_primary_mcp')}, got={primary}")

        if supplemental == str(case.get("expected_supplemental_mcp", "")):
            score += 1
        else:
            issues.append(
                f"supplemental_mcp: expected={case.get('expected_supplemental_mcp')}, got={supplemental}"
            )

        if action == str(case.get("expected_first_action", "")):
            score += 1
        else:
            issues.append(f"first_action: expected={case.get('expected_first_action')}, got={action}")

        if conf >= 4:
            score += 1
        else:
            issues.append("confidence: expected integer >= 4")

        earned += score
        rows.append(
            {
                "name": str(case.get("name", "unnamed_case")),
                "execution_mode": "hybrid",
                "score": score,
                "max_score": 5,
                "status": "pass" if score == 5 else "partial",
                "issues": issues,
                "inference_notes": notes,
                "attack_plan": build_plan_line(track, primary, supplemental, action, conf),
            }
        )

    accuracy = earned / total if total else 0.0
    return {
        "summary": {
            "cases": len(rows),
            "execution_mode": "hybrid",
            "earned_points": earned,
            "max_points": total,
            "accuracy": round(accuracy, 4),
            "pass_threshold": pass_threshold,
            "passed": accuracy >= pass_threshold,
        },
        "results": rows,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="ctf-pwn router with benchmark mode")
    p.add_argument("--track", default="", help="explicit track override")
    p.add_argument("--input-json", default="", help="artifact JSON path")
    p.add_argument("--benchmark-mode", action="store_true", help="run benchmark cases")
    p.add_argument("--strict-benchmark", action="store_true", help="exit code 1 if benchmark is below threshold")
    p.add_argument("--benchmark-cases", default=DEFAULT_BENCHMARK_CASES)
    p.add_argument("--pass-threshold", type=float, default=0.85)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.benchmark_mode:
        out = benchmark_mode(args.benchmark_cases, args.pass_threshold)
        print(json.dumps(out, indent=2, ensure_ascii=False) if args.json else out["summary"])
        if args.strict_benchmark and not out["summary"]["passed"]:
            raise SystemExit(1)
        return

    artifact_data: Dict[str, Any] = {}
    artifact_list: List[Dict[str, Any]] = []

    if args.input_json:
        loaded = load_json_file(args.input_json)
        if isinstance(loaded, dict):
            artifact_data = loaded
        elif isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
            artifact_list = [x for x in loaded if isinstance(x, dict)]
            artifact_data = artifact_list[0]
        else:
            raise SystemExit("input json must be object or non-empty list of objects")

    if not args.track and len(artifact_list) > 1:
        out = infer_many_artifacts(artifact_list)
        if args.json:
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            print(f"artifacts={out['summary']['artifacts']}")
            for row in out["results"]:
                print(f"[{row['index']}] {row['attack_plan']}")
        return

    track = args.track.strip().lower()
    notes: List[str] = []
    conf = 6

    if not track:
        if not artifact_data:
            raise SystemExit("provide --track or --input-json (or use --benchmark-mode)")
        track, primary, supplemental, first_action, conf, notes = infer_track_from_artifact(artifact_data)
    else:
        primary = TRACK_PRIMARY_MCP.get(track, "ctf-solve")
        input_text = re.sub(r"\s+", " ", _flatten_text(artifact_data).lower()).strip() if artifact_data else ""
        supplemental = select_supplemental_mcp(track, input_text)
        first_action = select_first_action(track, input_text)

    result = {
        "track": track,
        "execution_mode": "hybrid",
        "primary_mcp": primary,
        "supplemental_mcp": supplemental,
        "first_action": first_action,
        "attack_plan": build_plan_line(track, primary, supplemental, first_action, conf),
        "inferred": bool(not args.track and artifact_data),
        "inference_notes": notes,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result["attack_plan"])


if __name__ == "__main__":
    main()
