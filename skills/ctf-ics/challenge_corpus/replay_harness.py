#!/usr/bin/env python3
"""
Replay Harness for ICS challenge corpus.

- Replays prior win_command cases from corpus_index.md
- Focuses on Modbus and EtherNet/IP (ENIP)
- Measures TTR (Time To Result) per case
- Compares current TTR vs previous run and reports improvement in minutes
"""

import argparse
import json
import pathlib
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

DEFAULT_CORPUS = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/corpus_index.md"
DEFAULT_HISTORY = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_history.json"
DEFAULT_LAST_RUN = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_last_run.json"


def normalize_protocol(proto: str) -> str:
    p = (proto or "").strip().lower()
    alias = {
        "ethernet": "enip",
        "eternet": "enip",
        "ethernetip": "enip",
        "ethernet/ip": "enip",
        "cip": "enip",
    }
    return alias.get(p, p)


def normalize_protocol_set(spec: str) -> List[str]:
    out: List[str] = []
    for token in (spec or "").split(","):
        token = token.strip()
        if not token:
            continue
        p = normalize_protocol(token)
        if p not in out:
            out.append(p)
    return out


def load_corpus_rows(corpus_path: pathlib.Path) -> List[Dict[str, str]]:
    lines = corpus_path.read_text(encoding="utf-8").splitlines()

    header = None
    rows: List[Dict[str, str]] = []
    for line in lines:
        if not line.startswith("|"):
            continue
        if line.startswith("|---"):
            continue

        parts = [x.strip() for x in line.strip().strip("|").split("|")]

        if header is None:
            if parts and parts[0] == "id":
                header = parts
            continue

        if len(parts) != len(header):
            continue

        row = {header[i]: parts[i] for i in range(len(header))}
        rows.append(row)

    return rows


def trim_backticks(s: str) -> str:
    s = s.strip()
    if s.startswith("`") and s.endswith("`"):
        return s[1:-1].strip()
    return s


def load_json(path: pathlib.Path, fallback):
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def save_json(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def should_skip_unresolved(command: str) -> bool:
    return "<target_" in command or "<unit_id>" in command or "<port>" in command


def run_command(command: str, timeout_s: int) -> Tuple[int, str, str, float]:
    start = time.perf_counter()
    proc = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout_s,
        executable="/bin/bash",
    )
    elapsed = time.perf_counter() - start
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def detect_import_error(stdout_text: str, stderr_text: str) -> Tuple[bool, str]:
    combined = f"{stdout_text}\n{stderr_text}".lower()
    markers = [
        "modulenotfounderror",
        "importerror",
        "no module named",
        "import error:",
    ]
    for marker in markers:
        if marker in combined:
            return True, marker
    return False, ""


def main() -> None:
    p = argparse.ArgumentParser(description="Replay harness for Modbus + EtherNet/IP corpus cases")
    p.add_argument("--corpus-index", default=DEFAULT_CORPUS)
    p.add_argument("--protocols", default="modbus,enip", help="comma list: modbus,enip,ethernet,eternet")
    p.add_argument("--timeout", type=int, default=120, help="per-case timeout (seconds)")
    p.add_argument("--max-cases", type=int, default=0, help="0 = all")
    p.add_argument("--include-ids", default="", help="comma-separated case ids")
    p.add_argument("--exclude-ids", default="", help="comma-separated case ids")
    p.add_argument("--history-file", default=DEFAULT_HISTORY)
    p.add_argument("--last-run-file", default=DEFAULT_LAST_RUN)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    corpus_path = pathlib.Path(args.corpus_index)
    history_path = pathlib.Path(args.history_file)
    last_run_path = pathlib.Path(args.last_run_file)

    if not corpus_path.exists():
        raise SystemExit(f"corpus index not found: {corpus_path}")

    wanted_protocols = set(normalize_protocol_set(args.protocols))
    include_ids = {x.strip() for x in args.include_ids.split(",") if x.strip()}
    exclude_ids = {x.strip() for x in args.exclude_ids.split(",") if x.strip()}

    rows = load_corpus_rows(corpus_path)

    selected: List[Dict[str, str]] = []
    skipped: List[Dict[str, str]] = []

    for row in rows:
        case_id = row.get("id", "").strip()
        proto = normalize_protocol(row.get("protocol", ""))
        cmd = trim_backticks(row.get("win_command", ""))

        if wanted_protocols and proto not in wanted_protocols:
            continue
        if include_ids and case_id not in include_ids:
            continue
        if case_id in exclude_ids:
            continue

        if not cmd:
            skipped.append({"id": case_id, "reason": "empty_command"})
            continue
        if should_skip_unresolved(cmd):
            skipped.append({"id": case_id, "reason": "unresolved_placeholder"})
            continue

        entry = {
            "id": case_id,
            "protocol": proto,
            "win_command": cmd,
            "notes_path": trim_backticks(row.get("notes_path", "")),
        }
        selected.append(entry)

    if args.max_cases > 0:
        selected = selected[: args.max_cases]

    history = load_json(history_path, fallback={"last_ttr_sec": {}, "best_ttr_sec": {}, "runs": []})
    last_ttr: Dict[str, float] = history.get("last_ttr_sec", {})
    best_ttr: Dict[str, float] = history.get("best_ttr_sec", {})

    run_at = datetime.now(timezone.utc).isoformat()
    results: List[Dict[str, object]] = []

    for case in selected:
        case_id = case["id"]
        cmd = case["win_command"]

        prev = last_ttr.get(case_id)

        if args.dry_run:
            elapsed = 0.0
            rc = 0
            out = ""
            err = ""
        else:
            try:
                rc, out, err, elapsed = run_command(cmd, timeout_s=args.timeout)
            except subprocess.TimeoutExpired as ex:
                rc = 124
                out = ex.stdout or ""
                err = (ex.stderr or "") + "\nTIMEOUT"
                elapsed = float(args.timeout)

        improve_sec = None
        improve_min = None
        if prev is not None:
            improve_sec = float(prev) - float(elapsed)
            improve_min = round(improve_sec / 60.0, 3)

        import_error_detected, import_error_marker = detect_import_error(out, err)
        success = (rc == 0) and (not import_error_detected)
        failure_reason = ""
        if not success:
            if rc != 0:
                failure_reason = f"return_code_{rc}"
            elif import_error_detected:
                failure_reason = f"import_error:{import_error_marker}"

        result = {
            "id": case_id,
            "protocol": case["protocol"],
            "command": cmd,
            "return_code": rc,
            "success": success,
            "failure_reason": failure_reason,
            "import_error_detected": import_error_detected,
            "ttr_sec": round(elapsed, 3),
            "ttr_min": round(elapsed / 60.0, 3),
            "prev_ttr_sec": prev,
            "improve_sec_vs_prev": improve_sec,
            "improve_min_vs_prev": improve_min,
            "stdout_tail": "\n".join(out.splitlines()[-8:]),
            "stderr_tail": "\n".join(err.splitlines()[-8:]),
            "notes_path": case["notes_path"],
        }
        results.append(result)

        if not args.dry_run:
            last_ttr[case_id] = elapsed
            if case_id not in best_ttr:
                best_ttr[case_id] = elapsed
            else:
                best_ttr[case_id] = min(float(best_ttr[case_id]), elapsed)

    comparable = [r for r in results if r.get("improve_min_vs_prev") is not None]
    total_improve_min = round(sum(float(r["improve_min_vs_prev"]) for r in comparable), 3) if comparable else None

    summary = {
        "run_at_utc": run_at,
        "protocols": sorted(list(wanted_protocols)),
        "selected_cases": len(selected),
        "skipped_cases": skipped,
        "executed_cases": len(results),
        "success_count": sum(1 for r in results if r["success"]),
        "avg_ttr_min": round(sum(float(r["ttr_min"]) for r in results) / len(results), 3) if results else None,
        "total_improve_min_vs_prev": total_improve_min,
        "comparable_cases": len(comparable),
    }

    run_record = {"summary": summary, "results": results}

    if not args.dry_run:
        history["last_ttr_sec"] = last_ttr
        history["best_ttr_sec"] = best_ttr
        history.setdefault("runs", []).append({"run_at_utc": run_at, "summary": summary})
        if len(history["runs"]) > 200:
            history["runs"] = history["runs"][-200:]
        save_json(history_path, history)

    save_json(last_run_path, run_record)

    if args.json:
        print(json.dumps(run_record, indent=2, ensure_ascii=False))
        return

    print("=== ICS Replay Harness ===")
    print(f"Run at: {run_at}")
    print(f"Protocols: {', '.join(summary['protocols'])}")
    print(f"Executed: {summary['executed_cases']} | Success: {summary['success_count']}")
    if summary["avg_ttr_min"] is not None:
        print(f"Avg TTR: {summary['avg_ttr_min']} min")
    if summary["total_improve_min_vs_prev"] is not None:
        print(f"Total improvement vs previous: {summary['total_improve_min_vs_prev']} min")
    print("")

    for r in results:
        speed = r["improve_min_vs_prev"]
        speed_str = "n/a"
        if speed is not None:
            speed_str = f"{speed:+.3f} min"
        print(
            f"- {r['id']} [{r['protocol']}] rc={r['return_code']} "
            f"ttr={r['ttr_min']:.3f} min delta={speed_str}"
        )

    if skipped:
        print("\nSkipped cases:")
        for s in skipped:
            print(f"- {s['id']}: {s['reason']}")

    print(f"\nSaved run report: {last_run_path}")
    print(f"Saved history: {history_path}")


if __name__ == "__main__":
    main()
