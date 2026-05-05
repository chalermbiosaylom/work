#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Any, Dict, List, Tuple

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-forensics/FORENSICS_BENCHMARK_CASES.json"

TRACK_HINTS: List[Tuple[str, List[str]]] = [
    ("pcap-network", ["pcap", "pcapng", "dns", "http", "tcp", "wireshark", "tshark"]),
    ("memory", ["memory.dmp", "memdump", "volatility", "malfind", "pslist", "dump"]),
    ("disk-image", ["disk.dd", ".dd", ".e01", "partition", "fls", "mactime", "deleted file"]),
    ("steganography", ["steg", "lsb", "zsteg", "steghide", "spectrogram", "hidden image"]),
    ("windows-evtx", ["evtx", "event id", "security log", "rdp", "powershell"]),
    ("document-pdf", ["pdf", "pdftotext", "metadata", "embedded object", "acroform"]),
    ("archive", ["zip", "7z", "rar", "tar", "nested", "extract"]),
]

TRACK_FIRST_TOOL: Dict[str, str] = {
    "pcap-network": "tshark",
    "memory": "volatility3",
    "disk-image": "sleuthkit",
    "steganography": "zsteg",
    "windows-evtx": "evtx_dump",
    "document-pdf": "pdf_triage",
    "archive": "archive_listing",
}


def select_first_tool(track: str, text: str) -> str:
    if track == "steganography":
        if any(k in text for k in ["steghide", ".jpg", ".jpeg", "jpeg", "photo.jpg"]):
            return "steghide"
    return TRACK_FIRST_TOOL.get(track, "triage")


def select_supplemental_mcp(text: str) -> str:
    def has_keyword(keyword: str) -> bool:
        if keyword.isalnum() and len(keyword) <= 3:
            return re.search(rf"\b{re.escape(keyword)}\b", text) is not None
        return keyword in text

    # Check crypto patterns first (more specific)
    if any(has_keyword(k) for k in ["aes", "rsa", "cipher", "encrypted", "key derivation", "gcm", "hmac", "private key"]):
        return "ctf-crypto"
    # Then check ICS patterns
    if any(has_keyword(k) for k in ["modbus", "s7", "enip", "dnp3", "opc ua", "ics", "ot", "plc"]):
        return "ctf-ics"
    return ""


def select_handoff_action(text: str) -> str:
    def has_keyword(keyword: str) -> bool:
        if keyword.isalnum() and len(keyword) <= 3:
            return re.search(rf"\b{re.escape(keyword)}\b", text) is not None
        return keyword in text

    # Check crypto patterns first (more specific)
    if any(has_keyword(k) for k in ["aes", "rsa", "cipher", "encrypted", "key derivation", "gcm", "hmac", "private key"]):
        return "handoff-forensics-crypto-key-recovery"
    # Then check ICS patterns
    if any(has_keyword(k) for k in ["modbus", "s7", "enip", "dnp3", "opc ua", "ics", "ot", "plc"]):
        return "handoff-forensics-ics-protocol-analysis"
    return ""


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


def infer_track_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str, int, List[str]]:
    explicit = str(artifact.get("track", "")).strip().lower()
    if explicit:
        text = re.sub(r"\s+", " ", _flatten_text(artifact).lower()).strip()
        first_tool = select_first_tool(explicit, text)
        return explicit, first_tool, 9, ["track field provided in artifact"]

    tokens_src = _flatten_text(artifact).lower()
    tokens_src = re.sub(r"\s+", " ", tokens_src).strip()

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}

    for track, hints in TRACK_HINTS:
        for hint in hints:
            if hint in tokens_src:
                scores[track] = scores.get(track, 0) + 1
                reasons.setdefault(track, []).append(hint)

    if not scores:
        fallback = "pcap-network"
        return fallback, TRACK_FIRST_TOOL[fallback], 4, ["fallback: no strong hints found"]

    best_track = max(scores, key=lambda k: scores[k])
    score = scores[best_track]
    confidence = min(9, 4 + score)
    matched = reasons.get(best_track, [])
    first_tool = select_first_tool(best_track, tokens_src)
    return best_track, first_tool, confidence, [f"matched hints: {', '.join(matched)}"]


def build_plan_line(track: str, first_tool: str, supplemental_mcp: str, handoff_action: str, confidence: int) -> str:
    return (
        "AttackPlan: "
        f"track={track} | "
        f"first_tool={first_tool} | "
        f"supplemental_mcp={supplemental_mcp or 'none'} | "
        f"handoff_action={handoff_action or 'none'} | "
        "workflow=forensics-rapid | "
        f"confidence={confidence}"
    )


def benchmark_mode(cases_path: str, pass_threshold: float) -> Dict[str, Any]:
    raw = load_json_file(cases_path)
    if not isinstance(raw, list):
        raise SystemExit("benchmark cases json must be a list")

    rows: List[Dict[str, Any]] = []
    total = 0
    earned = 0

    for c in raw:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", "unnamed_case"))
        track, first_tool, conf, notes = infer_track_from_artifact(c)
        text = re.sub(r"\s+", " ", _flatten_text(c).lower()).strip()
        supplemental_mcp = select_supplemental_mcp(text)
        handoff_action = select_handoff_action(text)
        plan_line = build_plan_line(track, first_tool, supplemental_mcp, handoff_action, conf)

        score = 0
        issues: List[str] = []
        total += 5

        exp_track = str(c.get("expected_track", ""))
        exp_first_tool = str(c.get("expected_first_tool", ""))

        if track == exp_track:
            score += 1
        else:
            issues.append(f"track: expected={exp_track}, got={track}")

        if first_tool == exp_first_tool:
            score += 1
        else:
            issues.append(f"first_tool: expected={exp_first_tool}, got={first_tool}")

        exp_supplemental = str(c.get("expected_supplemental_mcp", ""))
        if supplemental_mcp == exp_supplemental:
            score += 1
        else:
            issues.append(f"supplemental_mcp: expected={exp_supplemental}, got={supplemental_mcp}")

        exp_handoff = str(c.get("expected_handoff_action", ""))
        if handoff_action == exp_handoff:
            score += 1
        else:
            issues.append(f"handoff_action: expected={exp_handoff}, got={handoff_action}")

        if conf >= 4:
            score += 1
        else:
            issues.append("confidence: expected integer >= 4")

        earned += score
        rows.append(
            {
                "name": name,
                "score": score,
                "max_score": 5,
                "status": "pass" if score == 5 else "partial",
                "issues": issues,
                "inference_notes": notes,
                "supplemental_mcp": supplemental_mcp,
                "handoff_action": handoff_action,
                "attack_plan": plan_line,
            }
        )

    acc = earned / total if total else 0.0
    return {
        "summary": {
            "cases": len(rows),
            "earned_points": earned,
            "max_points": total,
            "accuracy": round(acc, 4),
            "pass_threshold": pass_threshold,
            "passed": acc >= pass_threshold,
        },
        "results": rows,
    }


def infer_many_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts, start=1):
        track, first_tool, conf, notes = infer_track_from_artifact(artifact)
        text = re.sub(r"\s+", " ", _flatten_text(artifact).lower()).strip()
        supplemental_mcp = select_supplemental_mcp(text)
        handoff_action = select_handoff_action(text)
        rows.append(
            {
                "index": idx,
                "track": track,
                "execution_mode": "hybrid",
                "first_tool": first_tool,
                "supplemental_mcp": supplemental_mcp,
                "handoff_action": handoff_action,
                "confidence": conf,
                "attack_plan": build_plan_line(track, first_tool, supplemental_mcp, handoff_action, conf),
                "inference_notes": notes,
            }
        )
    return {
        "summary": {
            "artifacts": len(rows),
            "execution_mode": "hybrid",
        },
        "results": rows,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Forensics track router with benchmark mode")
    p.add_argument("--track", default="", help="track name, e.g. pcap-network, memory, steganography")
    p.add_argument("--input-json", default="", help="challenge_artifacts.json for auto track inference")
    p.add_argument("--benchmark-mode", action="store_true", help="evaluate routing against benchmark cases")
    p.add_argument("--benchmark-cases", default=DEFAULT_BENCHMARK_CASES, help="benchmark cases JSON path")
    p.add_argument("--pass-threshold", type=float, default=0.85, help="benchmark pass threshold")
    p.add_argument("--json", action="store_true", help="emit JSON output")
    args = p.parse_args()

    if args.benchmark_mode:
        bench = benchmark_mode(args.benchmark_cases, args.pass_threshold)
        if args.json:
            print(json.dumps(bench, indent=2, ensure_ascii=False))
        else:
            s = bench["summary"]
            print(
                f"benchmark: accuracy={s['accuracy']:.4f} "
                f"({s['earned_points']}/{s['max_points']}) passed={s['passed']}"
            )
            for r in bench["results"]:
                print(f"- {r['name']}: {r['score']}/{r['max_score']} [{r['status']}]")
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
            raise SystemExit("input json must be an object or a non-empty list of objects")

    if not args.track and len(artifact_list) > 1:
        multi = infer_many_artifacts(artifact_list)
        if args.json:
            print(json.dumps(multi, indent=2, ensure_ascii=False))
        else:
            print(f"artifacts={multi['summary']['artifacts']}")
            for r in multi["results"]:
                print(f"[{r['index']}] {r['attack_plan']}")
        return

    track = args.track.strip().lower()
    conf = 6
    notes: List[str] = []

    if not track:
        if not artifact_data:
            raise SystemExit("provide --track or --input-json (or use --benchmark-mode)")
        track, _, conf, notes = infer_track_from_artifact(artifact_data)

    text = re.sub(r"\s+", " ", _flatten_text(artifact_data).lower()).strip() if artifact_data else ""
    first_tool = select_first_tool(track, text)
    supplemental_mcp = select_supplemental_mcp(text)
    handoff_action = select_handoff_action(text)
    plan_line = build_plan_line(track, first_tool, supplemental_mcp, handoff_action, conf)

    result = {
        "track": track,
        "execution_mode": "hybrid",
        "first_tool": first_tool,
        "supplemental_mcp": supplemental_mcp,
        "handoff_action": handoff_action,
        "attack_plan": plan_line,
        "inferred": bool(not args.track and artifact_data),
        "inference_notes": notes,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(plan_line)


if __name__ == "__main__":
    main()
