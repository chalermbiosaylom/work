#!/usr/bin/env python3
import argparse
import json
import pathlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

DEFAULT_CORPUS = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/corpus_index.md"
DEFAULT_OUTPUT = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/matchday_only_profile.json"
DEFAULT_DIR = "/home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus"

SEMANTIC_WARN_MARKERS = [
    "failed to open a connection",
    "connection refused",
    "unable to read identity",
    "injection_failed",
    '"status": "error"',
    '"status": "timeout"',
]

CONNECTION_FAIL_MARKERS = [
    "connection refused",
    "no route to host",
    "failed to open a connection",
    "timed out",
    "timeout",
]


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


def load_corpus_ids(corpus_path: pathlib.Path) -> List[str]:
    lines = corpus_path.read_text(encoding="utf-8").splitlines()
    header = None
    ids: List[str] = []
    for line in lines:
        if not line.startswith("|") or line.startswith("|---"):
            continue
        parts = [x.strip() for x in line.strip().strip("|").split("|")]
        if header is None:
            if parts and parts[0] == "id":
                header = parts
            continue
        if len(parts) != len(header):
            continue
        row = {header[i]: parts[i] for i in range(len(header))}
        ids.append(row["id"])
    return ids


def list_replay_files(folder: pathlib.Path) -> List[pathlib.Path]:
    out = []
    for p in folder.glob("replay*.json"):
        if p.name == "replay_history.json":
            continue
        try:
            if p.stat().st_size > 0:
                out.append(p)
        except FileNotFoundError:
            continue
    out.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return out


def load_replay(path: pathlib.Path) -> Optional[Dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "results" not in data or not isinstance(data["results"], list):
        return None
    return data


def has_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n in t for n in needles)


def classify_case(result: Dict, max_ttr: float) -> Tuple[bool, bool, Dict[str, object]]:
    stdout_tail = result.get("stdout_tail", "") or ""
    stderr_tail = result.get("stderr_tail", "") or ""
    merged = f"{stdout_tail}\n{stderr_tail}".lower()

    rc = int(result.get("return_code", 1))
    success = bool(result.get("success", False))
    ttr = float(result.get("ttr_sec", 999999))

    semantic_warn = has_any(merged, SEMANTIC_WARN_MARKERS)
    connection_fail = has_any(merged, CONNECTION_FAIL_MARKERS)

    strict_ok = success and rc == 0 and (ttr <= max_ttr) and (not semantic_warn)

    candidate_ok = False
    if strict_ok:
        candidate_ok = True
    elif success and rc == 0 and ttr <= max_ttr:
        candidate_ok = True
    elif rc in (1, 124) and connection_fail:
        candidate_ok = True

    meta = {
        "rc": rc,
        "success": success,
        "ttr_sec": ttr,
        "semantic_clean": not semantic_warn,
        "connection_fail": connection_fail,
    }

    return strict_ok, candidate_ok, meta


def compute_rank_score(
    meta: Dict[str, object],
    max_ttr: float,
    success_weight: float,
    ttr_weight: float,
    semantic_clean_weight: float,
) -> float:
    success = bool(meta.get("success", False))
    ttr = float(meta.get("ttr_sec", 999999.0))
    semantic_clean = bool(meta.get("semantic_clean", False))
    connection_fail = bool(meta.get("connection_fail", False))

    success_component = success_weight if success else 0.0
    ttr_ratio = 0.0
    if max_ttr > 0:
        ttr_ratio = max(0.0, min(1.0, (max_ttr - ttr) / max_ttr))
    ttr_component = ttr_weight * ttr_ratio
    semantic_component = semantic_clean_weight if semantic_clean else 0.0

    # small penalty: cases that only fail by network/service should remain candidates,
    # but rank below clean successes.
    connection_penalty = 5.0 if connection_fail and not success else 0.0

    return round(success_component + ttr_component + semantic_component - connection_penalty, 3)


def build_usage(ids: List[str], timeout: int) -> str:
    include = ",".join(ids)
    return (
        "python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py "
        f"--protocols modbus,enip --include-ids {include} --timeout {timeout} --json"
    )


def sort_ids_by_score(ids: List[str], ranking_meta: Dict[str, Dict[str, object]]) -> List[str]:
    return sorted(
        ids,
        key=lambda cid: (
            ranking_meta.get(cid, {}).get("score", -999999.0),
            -float(ranking_meta.get(cid, {}).get("ttr_sec", 999999.0)),
        ),
        reverse=True,
    )


def interleave_by_protocol(ids: List[str], ranking_meta: Dict[str, Dict[str, object]], top_n: int, balance_mode: str) -> List[str]:
    proto_order = ["modbus", "enip"]
    buckets: Dict[str, List[str]] = {"modbus": [], "enip": []}

    for cid in sort_ids_by_score(ids, ranking_meta):
        proto = str(ranking_meta.get(cid, {}).get("protocol", "")).lower()
        if proto not in buckets:
            buckets[proto] = []
        buckets[proto].append(cid)

    out: List[str] = []
    last_proto = None
    while True:
        progressed = False
        available = [p for p in proto_order if buckets.get(p)]
        if not available:
            break

        candidates: List[Tuple[float, int, str]] = []
        for proto in available:
            head = buckets[proto][0]
            score = float(ranking_meta.get(head, {}).get("score", -999999.0))
            penalty = 0
            if balance_mode == "strict" and last_proto is not None and proto == last_proto and len(available) > 1:
                penalty = 100000
            elif balance_mode == "soft" and last_proto is not None and proto == last_proto and len(available) > 1:
                penalty = 1
            candidates.append((score, -penalty, proto))

        candidates.sort(reverse=True)
        chosen_proto = candidates[0][2]
        out.append(buckets[chosen_proto].pop(0))
        last_proto = chosen_proto
        progressed = True
        if top_n > 0 and len(out) >= top_n:
            return out

        if not progressed:
            break

    # if any non-standard protocol bucket exists, append leftovers by score
    leftovers: List[str] = []
    for proto, vals in buckets.items():
        if proto not in proto_order:
            leftovers.extend(vals)
    leftovers = sort_ids_by_score(leftovers, ranking_meta)
    for cid in leftovers:
        out.append(cid)
        if top_n > 0 and len(out) >= top_n:
            break

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate tiered match-day profile from latest replay report")
    parser.add_argument("--corpus-index", default=DEFAULT_CORPUS)
    parser.add_argument("--replay-dir", default=DEFAULT_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--max-ttr-sec", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--top-service-up", type=int, default=12)
    parser.add_argument("--min-executed-cases", type=int, default=8)
    parser.add_argument("--weight-success", type=float, default=60.0)
    parser.add_argument("--weight-ttr", type=float, default=25.0)
    parser.add_argument("--weight-semantic-clean", type=float, default=15.0)
    parser.add_argument("--min-score", type=float, default=0.0)
    parser.add_argument("--protocol-balance-mode", choices=["off", "soft", "strict"], default="soft")
    args = parser.parse_args()

    corpus_path = pathlib.Path(args.corpus_index)
    replay_dir = pathlib.Path(args.replay_dir)
    output_path = pathlib.Path(args.output)

    if not corpus_path.exists():
        raise SystemExit(f"corpus index not found: {corpus_path}")

    ordered_ids = load_corpus_ids(corpus_path)
    ordered_set = set(ordered_ids)

    replay_files = list_replay_files(replay_dir)
    if not replay_files:
        raise SystemExit(f"no replay json files found in: {replay_dir}")

    valid_reports: List[Tuple[pathlib.Path, Dict]] = []
    for p in replay_files:
        data = load_replay(p)
        if data is not None:
            valid_reports.append((p, data))

    latest_report_path = None
    latest_report = None
    for p, data in valid_reports:
        summary = data.get("summary", {}) if isinstance(data, dict) else {}
        executed = int(summary.get("executed_cases", len(data.get("results", []))))
        if executed >= args.min_executed_cases:
            latest_report_path = p
            latest_report = data
            break

    if latest_report is None and valid_reports:
        latest_report_path, latest_report = valid_reports[0]

    if latest_report is None or latest_report_path is None:
        raise SystemExit("no valid replay report found")

    # Combine latest result per case across reports (newest -> oldest)
    combined_by_case: Dict[str, Dict] = {}
    source_runs_used: List[str] = []
    for p, data in valid_reports:
        used_this_report = False
        for r in data.get("results", []):
            case_id = str(r.get("id", "")).strip()
            if not case_id or case_id in combined_by_case:
                continue
            combined_by_case[case_id] = r
            used_this_report = True
        if used_this_report:
            source_runs_used.append(str(p))

    strict_ids: List[str] = []
    candidate_ids: List[str] = []
    ranking_meta: Dict[str, Dict[str, object]] = {}

    for r in combined_by_case.values():
        case_id = str(r.get("id", "")).strip()
        if not case_id or case_id not in ordered_set:
            continue
        proto = normalize_protocol(str(r.get("protocol", "")))
        if proto not in ("modbus", "enip"):
            continue

        strict_ok, candidate_ok, meta = classify_case(r, max_ttr=args.max_ttr_sec)
        score = compute_rank_score(
            meta=meta,
            max_ttr=args.max_ttr_sec,
            success_weight=args.weight_success,
            ttr_weight=args.weight_ttr,
            semantic_clean_weight=args.weight_semantic_clean,
        )
        ranking_meta[case_id] = {
            "score": score,
            "protocol": proto,
            "rc": meta["rc"],
            "success": meta["success"],
            "ttr_sec": meta["ttr_sec"],
            "semantic_clean": meta["semantic_clean"],
            "connection_fail": meta["connection_fail"],
        }

        if strict_ok and case_id not in strict_ids:
            strict_ids.append(case_id)
        if candidate_ok and case_id not in candidate_ids:
            candidate_ids.append(case_id)

    if not strict_ids:
        # keep profile usable even in unstable environment
        fallback = [x for x in ordered_ids if x in ("modbus_illuminated_pcap", "enip_pcap_flag_forensics_pattern")]
        strict_ids = fallback
        for c in fallback:
            if c not in candidate_ids:
                candidate_ids.append(c)
            if c not in ranking_meta:
                ranking_meta[c] = {
                    "score": 0.0,
                    "protocol": "unknown",
                    "rc": 1,
                    "success": False,
                    "ttr_sec": 999999.0,
                    "semantic_clean": True,
                    "connection_fail": True,
                }

    candidate_ids = [x for x in ordered_ids if x in candidate_ids and ranking_meta.get(x, {}).get("score", -999999.0) >= args.min_score]
    if args.protocol_balance_mode == "off":
        candidate_ids = sort_ids_by_score(candidate_ids, ranking_meta)
    else:
        candidate_ids = interleave_by_protocol(candidate_ids, ranking_meta, top_n=args.top_service_up, balance_mode=args.protocol_balance_mode)
    if args.top_service_up > 0:
        candidate_ids = candidate_ids[: args.top_service_up]

    strict_ids = [x for x in ordered_ids if x in strict_ids]
    strict_ids = sort_ids_by_score(strict_ids, ranking_meta)

    strict_ranked = [{"id": cid, **ranking_meta.get(cid, {})} for cid in strict_ids]
    candidate_ranked = [{"id": cid, **ranking_meta.get(cid, {})} for cid in candidate_ids]

    profile = {
        "description": "Match-day only profile with strict validated-now tier and service-up candidate tier",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "selection_criteria": {
            "protocols": ["modbus", "enip"],
            "prefer_success": True,
            "prefer_ttr_sec_lte": args.max_ttr_sec,
            "strict_semantic_filters": SEMANTIC_WARN_MARKERS,
            "ranking_weights": {
                "success": args.weight_success,
                "ttr": args.weight_ttr,
                "semantic_clean": args.weight_semantic_clean,
            },
            "min_score": args.min_score,
            "protocol_balanced_order": args.protocol_balance_mode != "off",
            "protocol_balance_mode": args.protocol_balance_mode,
        },
        "profile_tiers": {
            "strict_validated_now": {
                "source_run": str(latest_report_path),
                "stable_case_ids": strict_ids,
                "ranked": strict_ranked,
            },
            "service_up_candidates": {
                "source_runs": source_runs_used,
                "candidate_case_ids": candidate_ids,
                "ranked": candidate_ranked,
            },
        },
        "usage": {
            "replay_strict_now": build_usage(strict_ids, timeout=args.timeout),
            "replay_service_up": build_usage(candidate_ids, timeout=args.timeout),
        },
    }

    output_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[OK] latest replay: {latest_report_path}")
    print(f"[OK] merged latest-by-case from {len(source_runs_used)} replay file(s)")
    print(f"[OK] strict_validated_now: {len(strict_ids)} case(s)")
    print(f"[OK] service_up_candidates: {len(candidate_ids)} case(s)")
    if candidate_ids:
        print(f"[OK] top candidate: {candidate_ids[0]} score={ranking_meta[candidate_ids[0]]['score']}")
    print(f"[OK] wrote profile: {output_path}")


if __name__ == "__main__":
    main()
