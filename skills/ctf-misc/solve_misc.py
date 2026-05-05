#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Any, Dict, List, Tuple

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-misc/MISC_BENCHMARK_CASES.json"

TRACK_HINTS: List[Tuple[str, List[str]]] = [
    ("programming-algorithmic", ["dp", "dijkstra", "graph", "constraints", "stdin", "algorithm", "time limit"]),
    ("pyjail", ["python jail", "no import", "eval", "blacklist", "restricted python"]),
    ("bashjail", ["rbash", "restricted shell", "bash jail", "histfile", "no slash"]),
    ("encodings", ["base64", "hex", "rot13", "xor", "encoding", "cipher"]),
    ("esolang", ["brainfuck", "whitespace", "malbolge", "esolang"]),
    ("qr-barcode", ["qr", "barcode", "zbar", "chunks", "reassembly"]),
    ("audio-video-signal", ["wav", "spectrogram", "dtmf", "sstv", "audio", "video"]),
    ("rf-sdr", ["iq", "qam", "gnu radio", "complex64", "carrier recovery", "sdr"]),
    ("dns-exploitation", ["dns", "nsec", "ecs", "ixfr", "txt", "rebinding"]),
]

TRACK_PRIMARY_MCP: Dict[str, str] = {
    "programming-algorithmic": "ctf-solve",
    "pyjail": "pentest-mcp",
    "bashjail": "pentest-mcp",
    "encodings": "ctf-solve",
    "esolang": "ctf-solve",
    "qr-barcode": "ctf-solve",
    "audio-video-signal": "ctf-solve",
    "rf-sdr": "ctf-solve",
    "dns-exploitation": "ctf-solve",
}

TRACK_SUPPLEMENTAL_MCP: Dict[str, str] = {
    "programming-algorithmic": "pentest-mcp",
    "pyjail": "ctf-solve",
    "bashjail": "ctf-solve",
    "encodings": "pentest-mcp",
    "esolang": "pentest-mcp",
    "qr-barcode": "ctf-forensics",
    "audio-video-signal": "ctf-forensics",
    "rf-sdr": "ctf-forensics",
    "dns-exploitation": "pentest-mcp",
}

TRACK_FIRST_ACTION: Dict[str, str] = {
    "programming-algorithmic": "classify-complexity-and-select-template",
    "pyjail": "stabilize-interactive-jail-loop",
    "bashjail": "stabilize-interactive-jail-loop",
    "encodings": "build-deterministic-decode-pipeline",
    "esolang": "run-esolang-interpreter-and-extract-output",
    "qr-barcode": "batch-decode-and-order-fragments",
    "audio-video-signal": "generate-spectrogram-and-extract-symbols",
    "rf-sdr": "detect-iq-format-and-run-demod-pipeline",
    "dns-exploitation": "run-deterministic-dns-enumeration",
}


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


def choose_first_action(track: str, text: str) -> str:
    if track == "programming-algorithmic":
        if "interactive" in text or "query" in text:
            return "create-persistent-session-and-fast-io-template"
        return "classify-complexity-and-select-template"
    return TRACK_FIRST_ACTION.get(track, "classify-complexity-and-select-template")


def infer_track_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str, str, str, int, List[str]]:
    explicit = str(artifact.get("track", "")).strip().lower()
    text = re.sub(r"\s+", " ", _flatten_text(artifact).lower()).strip()

    if explicit:
        primary = TRACK_PRIMARY_MCP.get(explicit, "ctf-solve")
        supplemental = TRACK_SUPPLEMENTAL_MCP.get(explicit, "pentest-mcp")
        action = choose_first_action(explicit, text)
        return explicit, primary, supplemental, action, 9, ["track field provided in artifact"]

    if "interactive" in text and any(k in text for k in ["dp", "graph", "algorithm", "constraints"]):
        forced = "programming-algorithmic"
        return (
            forced,
            "pentest-mcp",
            "ctf-solve",
            "create-persistent-session-and-fast-io-template",
            8,
            ["priority rule: interactive algorithmic challenge"],
        )

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}
    for track, hints in TRACK_HINTS:
        for hint in hints:
            if hint in text:
                scores[track] = scores.get(track, 0) + 1
                reasons.setdefault(track, []).append(hint)

    if not scores:
        fallback = "encodings"
        return (
            fallback,
            TRACK_PRIMARY_MCP[fallback],
            TRACK_SUPPLEMENTAL_MCP[fallback],
            choose_first_action(fallback, text),
            4,
            ["fallback: no strong hints found"],
        )

    best = max(scores, key=lambda x: scores[x])
    confidence = min(9, 4 + scores[best])
    return (
        best,
        TRACK_PRIMARY_MCP[best],
        TRACK_SUPPLEMENTAL_MCP[best],
        choose_first_action(best, text),
        confidence,
        [f"matched hints: {', '.join(reasons.get(best, []))}"],
    )


def build_plan_line(track: str, primary: str, supplemental: str, first_action: str, confidence: int) -> str:
    return (
        "AttackPlan: "
        f"track={track} | "
        f"primary_mcp={primary} | "
        f"supplemental_mcp={supplemental} | "
        f"first_action={first_action} | "
        f"confidence={confidence}"
    )


def infer_many(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts, start=1):
        track, primary, supplemental, first_action, confidence, notes = infer_track_from_artifact(artifact)
        rows.append(
            {
                "index": idx,
                "track": track,
                "execution_mode": "hybrid",
                "primary_mcp": primary,
                "supplemental_mcp": supplemental,
                "first_action": first_action,
                "confidence": confidence,
                "attack_plan": build_plan_line(track, primary, supplemental, first_action, confidence),
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
        track, primary, supplemental, first_action, confidence, notes = infer_track_from_artifact(case)
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

        if first_action == str(case.get("expected_first_action", "")):
            score += 1
        else:
            issues.append(
                f"first_action: expected={case.get('expected_first_action')}, got={first_action}"
            )

        if confidence >= 4:
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
                "attack_plan": build_plan_line(track, primary, supplemental, first_action, confidence),
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
    parser = argparse.ArgumentParser(description="ctf-misc router with benchmark mode")
    parser.add_argument("--track", default="", help="explicit track override")
    parser.add_argument("--input-json", default="", help="artifact JSON path")
    parser.add_argument("--benchmark-mode", action="store_true", help="run benchmark cases")
    parser.add_argument("--strict-benchmark", action="store_true", help="exit code 1 if benchmark below threshold")
    parser.add_argument("--benchmark-cases", default=DEFAULT_BENCHMARK_CASES)
    parser.add_argument("--pass-threshold", type=float, default=0.85)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.benchmark_mode:
        out = benchmark_mode(args.benchmark_cases, args.pass_threshold)
        print(json.dumps(out, indent=2, ensure_ascii=False) if args.json else out["summary"])
        if args.strict_benchmark and not out["summary"]["passed"]:
            raise SystemExit(1)
        return

    artifact_data: Dict[str, Any] = {}
    artifacts: List[Dict[str, Any]] = []

    if args.input_json:
        loaded = load_json_file(args.input_json)
        if isinstance(loaded, dict):
            artifact_data = loaded
        elif isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
            artifacts = [x for x in loaded if isinstance(x, dict)]
            artifact_data = artifacts[0]
        else:
            raise SystemExit("input json must be object or non-empty list of objects")

    if not args.track and len(artifacts) > 1:
        out = infer_many(artifacts)
        if args.json:
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            print(f"artifacts={out['summary']['artifacts']}")
            for row in out["results"]:
                print(f"[{row['index']}] {row['attack_plan']}")
        return

    track = args.track.strip().lower()
    notes: List[str] = []
    confidence = 6

    if not track:
        if not artifact_data:
            raise SystemExit("provide --track or --input-json (or use --benchmark-mode)")
        track, primary, supplemental, first_action, confidence, notes = infer_track_from_artifact(artifact_data)
    else:
        primary = TRACK_PRIMARY_MCP.get(track, "ctf-solve")
        supplemental = TRACK_SUPPLEMENTAL_MCP.get(track, "pentest-mcp")
        first_action = choose_first_action(track, _flatten_text(artifact_data).lower())

    result = {
        "track": track,
        "execution_mode": "hybrid",
        "primary_mcp": primary,
        "supplemental_mcp": supplemental,
        "first_action": first_action,
        "attack_plan": build_plan_line(track, primary, supplemental, first_action, confidence),
        "inferred": bool(not args.track and artifact_data),
        "inference_notes": notes,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result["attack_plan"])


if __name__ == "__main__":
    main()
