#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Any, Dict, List, Tuple

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-reverse/REVERSE_BENCHMARK_CASES.json"

TRACK_HINTS: List[Tuple[str, List[str]]] = [
    ("binary-static", ["elf", "pe", "stripped", "objdump", "ghidra", "ida", "radare2"]),
    ("binary-dynamic", ["gdb", "ltrace", "strace", "breakpoint", "memory dump"]),
    ("vm-custom", ["custom vm", "bytecode", "opcode", "interpreter", "virtual machine"]),
    ("obfuscation", ["obfuscated", "packed", "upx", "anti-debug", "anti-analysis"]),
    ("pyc-bytecode", [".pyc", "python bytecode", "marshal", "dis.dis", "opcode remap"]),
    ("wasm", ["wasm", "webassembly", "wasm2c", "wat"]),
    ("apk-mobile", ["apk", "android", "apktool", "jadx", "smali"]),
    ("dotnet", [".net", "dnspy", "ilspy", "c#", "cil"]),
]

TRACK_PRIMARY_MCP: Dict[str, str] = {
    "binary-static": "ghidramcp",
    "binary-dynamic": "ctf-solve",
    "vm-custom": "ctf-solve",
    "obfuscation": "ghidramcp",
    "pyc-bytecode": "ctf-solve",
    "wasm": "ctf-solve",
    "apk-mobile": "ctf-solve",
    "dotnet": "ctf-solve",
}

TRACK_SUPPLEMENTAL_MCP: Dict[str, str] = {
    "binary-static": "ctf-solve",
    "binary-dynamic": "ghidramcp",
    "vm-custom": "ctf-solve",
    "obfuscation": "ctf-solve",
    "pyc-bytecode": "ctf-solve",
    "wasm": "ctf-solve",
    "apk-mobile": "ctf-solve",
    "dotnet": "ctf-solve",
}

TRACK_FIRST_ACTION: Dict[str, str] = {
    "binary-static": "load-in-ghidra-and-analyze",
    "binary-dynamic": "run-with-ltrace-strace",
    "vm-custom": "reverse-opcode-table",
    "obfuscation": "detect-packer-and-unpack",
    "pyc-bytecode": "decompile-with-uncompyle6",
    "wasm": "convert-wasm-to-wat",
    "apk-mobile": "decompile-with-jadx",
    "dotnet": "load-in-dnspy",
}


def select_supplemental_mcp(track: str, text: str) -> str:
    # Reverse+Pwn cross-skill patterns
    if any(k in text for k in ["suid", "setuid", "privilege", "kernel module", "exploit", "rop", "shellcode"]):
        return "ctf-pwn"
    # Reverse+Crypto cross-skill patterns
    if any(k in text for k in ["cipher", "aes", "rsa", "xor key", "encryption", "s-box", "keystream"]):
        return "ctf-crypto"
    # Default track-specific supplemental
    return TRACK_SUPPLEMENTAL_MCP.get(track, "ctf-solve")


def select_first_action(track: str, text: str) -> str:
    # Reverse+Pwn handoff patterns
    if any(k in text for k in ["suid", "setuid", "privilege", "kernel module", "exploit", "rop", "shellcode"]):
        return "handoff-reverse-pwn-exploit-chain"
    # Reverse+Crypto handoff patterns
    if any(k in text for k in ["cipher", "aes", "rsa", "xor key", "encryption", "s-box", "keystream"]):
        return "handoff-reverse-crypto-algorithm-extract"
    # Default track-specific actions
    return TRACK_FIRST_ACTION.get(track, "run-with-ltrace-strace")


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
        primary = TRACK_PRIMARY_MCP.get(explicit, "ctf-solve")
        supplemental = select_supplemental_mcp(explicit, text)
        action = select_first_action(explicit, text)
        return explicit, primary, supplemental, action, 9, ["track field provided in artifact"]

    # Cross-skill priority rules
    if any(k in text for k in ["suid", "setuid", "privilege escalation", "kernel module"]):
        forced = "binary-dynamic"
        return (
            forced,
            TRACK_PRIMARY_MCP[forced],
            "ctf-pwn",
            "handoff-reverse-pwn-exploit-chain",
            8,
            ["priority rule: reverse+pwn cross-skill indicators"],
        )

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}
    for track, hints in TRACK_HINTS:
        for hint in hints:
            if hint in text:
                scores[track] = scores.get(track, 0) + 1
                reasons.setdefault(track, []).append(hint)

    if not scores:
        fallback = "binary-static"
        return (
            fallback,
            TRACK_PRIMARY_MCP[fallback],
            select_supplemental_mcp(fallback, text),
            select_first_action(fallback, text),
            4,
            ["fallback: no strong hints found"],
        )

    best = max(scores, key=lambda x: scores[x])
    conf = min(9, 4 + scores[best])
    return (
        best,
        TRACK_PRIMARY_MCP[best],
        select_supplemental_mcp(best, text),
        select_first_action(best, text),
        conf,
        [f"matched hints: {', '.join(reasons.get(best, []))}"],
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
        track, primary, supplemental, first_action, conf, notes = infer_track_from_artifact(artifact)
        rows.append(
            {
                "index": idx,
                "track": track,
                "execution_mode": "hybrid",
                "primary_mcp": primary,
                "supplemental_mcp": supplemental,
                "first_action": first_action,
                "confidence": conf,
                "attack_plan": build_plan_line(track, primary, supplemental, first_action, conf),
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
    p = argparse.ArgumentParser(description="ctf-reverse router with cross-skill support")
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
        text = re.sub(r"\s+", " ", _flatten_text(artifact_data).lower()).strip() if artifact_data else ""
        supplemental = select_supplemental_mcp(track, text)
        first_action = select_first_action(track, text)

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
