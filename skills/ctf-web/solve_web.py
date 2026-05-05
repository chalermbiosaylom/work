#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from typing import Any, Dict, List, Tuple

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-web/WEB_BENCHMARK_CASES.json"

TRACK_HINTS: List[Tuple[str, List[str]]] = [
    ("jwt-auth", ["jwt", "alg none", "kid", "token", "bearer"]),
    ("sqli", ["sql", "union", "boolean", "time-based", "sqlite", "mysql"]),
    ("upload-rce", ["upload", "multipart", "webshell", "content-type", "extension"]),
    ("ssti", ["{{", "jinja", "template", "mako", "twig", "erb"]),
    ("lfi-traversal", ["../", "traversal", "lfi", "/etc/passwd", "php://filter"]),
    ("xss-client", ["xss", "script", "dom", "onerror", "innerhtml"]),
    ("ssrf", ["ssrf", "url fetch", "169.254.169.254", "internal service"]),
    ("csrf", ["csrf", "state change", "no token", "forged request"]),
    ("graphql", ["graphql", "introspection", "__schema", "query", "mutation"]),
    ("deserialization", ["deserialize", "serialized", "gadget", "pickle", "ysoserial"]),
]

TRACK_PRIMARY_MCP: Dict[str, str] = {
    "jwt-auth": "ctf-solve",
    "sqli": "ctf-solve",
    "upload-rce": "ctf-solve",
    "ssti": "ctf-solve",
    "lfi-traversal": "ctf-solve",
    "xss-client": "ctf-solve",
    "ssrf": "ctf-solve",
    "csrf": "ctf-solve",
    "graphql": "ctf-solve",
    "deserialization": "ctf-solve",
}

TRACK_SUPPLEMENTAL_MCP: Dict[str, str] = {
    "jwt-auth": "burp-mcp",
    "upload-rce": "burp-mcp",
    "xss-client": "burp-mcp",
    "csrf": "burp-mcp",
}

TRACK_FIRST_ACTION: Dict[str, str] = {
    "jwt-auth": "replay-and-tamper-jwt",
    "sqli": "confirm-injection-point",
    "upload-rce": "mutate-upload-request",
    "ssti": "probe-template-engine",
    "lfi-traversal": "test-traversal-variants",
    "xss-client": "verify-context-and-sink",
    "ssrf": "probe-internal-targets",
    "csrf": "capture-and-replay-form",
    "graphql": "enumerate-schema",
    "deserialization": "identify-serializer",
}


def select_supplemental_mcp(track: str, text: str) -> str:
    # Web+Crypto cross-skill patterns
    if any(k in text for k in ["jwt", "jws", "jwe", "signature", "hmac", "rsa token", "aes", "cipher", "decrypt"]):
        return "ctf-crypto"
    # Web+Pwn cross-skill patterns
    if any(k in text for k in ["elf", "stack overflow", "ret2libc", "format string", "heap uaf", "binary exploit", "pwn"]):
        return "ctf-pwn"
    # Web+OS cross-skill patterns
    if any(k in text for k in ["rce", "reverse shell", "webshell", "sudo -l", "privesc", "shell stabilize"]):
        return "ctf-os-exploit"
    # Default burp-mcp for specific tracks
    return TRACK_SUPPLEMENTAL_MCP.get(track, "")


def select_first_action(track: str, text: str) -> str:
    # Web+Crypto handoff patterns
    if any(k in text for k in ["jwt", "jws", "jwe", "signature", "hmac", "rsa token", "aes", "cipher", "decrypt"]):
        return "handoff-web-crypto-token-analysis"
    # Web+Pwn handoff patterns
    if any(k in text for k in ["elf", "stack overflow", "ret2libc", "format string", "heap uaf", "binary exploit", "pwn"]):
        return "handoff-web-pwn-binary-analysis"
    # Web+OS handoff patterns
    if any(k in text for k in ["rce", "reverse shell", "webshell", "sudo -l", "privesc", "shell stabilize"]):
        return "handoff-web-os-shell-stabilization"
    # Default track-specific actions
    return TRACK_FIRST_ACTION.get(track, "recon-and-probe")


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
    text = _flatten_text(artifact).lower()
    text = re.sub(r"\s+", " ", text).strip()
    if explicit:
        mcp = TRACK_PRIMARY_MCP.get(explicit, "ctf-solve")
        supplemental = select_supplemental_mcp(explicit, text)
        action = select_first_action(explicit, text)
        return explicit, mcp, supplemental, action, 9, ["track field provided in artifact"]

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}

    for track, hints in TRACK_HINTS:
        for hint in hints:
            if hint in text:
                scores[track] = scores.get(track, 0) + 1
                reasons.setdefault(track, []).append(hint)

    if not scores:
        fallback = "sqli"
        return fallback, TRACK_PRIMARY_MCP[fallback], select_supplemental_mcp(fallback, text), select_first_action(fallback, text), 4, [
            "fallback: no strong hints found"
        ]

    best = max(scores, key=lambda x: scores[x])
    conf = min(9, 4 + scores[best])
    matched = reasons.get(best, [])
    return best, TRACK_PRIMARY_MCP[best], select_supplemental_mcp(best, text), select_first_action(best, text), conf, [
        f"matched hints: {', '.join(matched)}"
    ]


def build_plan_line(track: str, mcp: str, supplemental_mcp: str, first_action: str, confidence: int) -> str:
    return (
        "AttackPlan: "
        f"track={track} | "
        f"primary_mcp={mcp} | "
        f"supplemental_mcp={supplemental_mcp or 'none'} | "
        "execution_mode=hybrid | "
        f"first_action={first_action} | "
        f"confidence={confidence}"
    )


def infer_many_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts, start=1):
        track, mcp, supplemental, action, conf, notes = infer_track_from_artifact(artifact)
        rows.append(
            {
                "index": idx,
                "track": track,
                "execution_mode": "hybrid",
                "primary_mcp": mcp,
                "supplemental_mcp": supplemental,
                "first_action": action,
                "confidence": conf,
                "attack_plan": build_plan_line(track, mcp, supplemental, action, conf),
                "inference_notes": notes,
            }
        )

    return {
        "summary": {"artifacts": len(rows), "execution_mode": "hybrid"},
        "results": rows,
    }


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
        track, mcp, supplemental, action, conf, notes = infer_track_from_artifact(c)

        score = 0
        issues: List[str] = []
        total += 5

        if track == str(c.get("expected_track", "")):
            score += 1
        else:
            issues.append(f"track: expected={c.get('expected_track')}, got={track}")

        if mcp == str(c.get("expected_primary_mcp", "")):
            score += 1
        else:
            issues.append(
                f"primary_mcp: expected={c.get('expected_primary_mcp')}, got={mcp}"
            )

        exp_supplemental = str(c.get("expected_supplemental_mcp", ""))
        if supplemental == exp_supplemental:
            score += 1
        else:
            issues.append(
                f"supplemental_mcp: expected={exp_supplemental}, got={supplemental}"
            )

        if action == str(c.get("expected_first_action", "")):
            score += 1
        else:
            issues.append(
                f"first_action: expected={c.get('expected_first_action')}, got={action}"
            )

        if conf >= 4:
            score += 1
        else:
            issues.append("confidence: expected integer >= 4")

        earned += score
        rows.append(
            {
                "name": name,
                "execution_mode": "hybrid",
                "score": score,
                "max_score": 5,
                "status": "pass" if score == 5 else "partial",
                "issues": issues,
                "inference_notes": notes,
                "supplemental_mcp": supplemental,
                "attack_plan": build_plan_line(track, mcp, supplemental, action, conf),
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
    p = argparse.ArgumentParser(description="Web track router with Burp MCP-aware benchmark mode")
    p.add_argument("--track", default="", help="explicit track override")
    p.add_argument("--input-json", default="", help="challenge artifact JSON")
    p.add_argument("--benchmark-mode", action="store_true", help="run routing benchmark")
    p.add_argument("--benchmark-cases", default=DEFAULT_BENCHMARK_CASES)
    p.add_argument("--pass-threshold", type=float, default=0.85)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.benchmark_mode:
        out = benchmark_mode(args.benchmark_cases, args.pass_threshold)
        if args.json:
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            s = out["summary"]
            print(
                f"benchmark: accuracy={s['accuracy']:.4f} "
                f"({s['earned_points']}/{s['max_points']}) passed={s['passed']}"
            )
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
        track, mcp, supplemental_mcp, first_action, conf, notes = infer_track_from_artifact(artifact_data)
    else:
        mcp = TRACK_PRIMARY_MCP.get(track, "ctf-solve")
        input_text = re.sub(r"\s+", " ", _flatten_text(artifact_data).lower()).strip() if artifact_data else ""
        supplemental_mcp = select_supplemental_mcp(track, input_text)
        first_action = select_first_action(track, input_text)

    plan = build_plan_line(track, mcp, supplemental_mcp, first_action, conf)
    result = {
        "track": track,
        "execution_mode": "hybrid",
        "primary_mcp": mcp,
        "supplemental_mcp": supplemental_mcp,
        "first_action": first_action,
        "attack_plan": plan,
        "inferred": bool(not args.track and artifact_data),
        "inference_notes": notes,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(plan)


if __name__ == "__main__":
    main()
