#!/usr/bin/env python3
"""
Modbus Unit Mapper (AI Ready)
- Discover active Unit IDs
- Build evidence snapshot per unit from FC01/03/04
- Rank units by signal quality (non-zero, printable, keyword hits)
"""

from __future__ import annotations

import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pymodbus.client import ModbusTcpClient


def _iter_units(unit_range: str) -> List[int]:
    if "-" not in unit_range:
        v = int(unit_range)
        return [v]
    s, e = unit_range.split("-", 1)
    start, end = int(s), int(e)
    if start <= 0 or end <= 0 or end < start:
        raise ValueError("invalid --unit-range")
    return list(range(start, end + 1))


def _call(client: ModbusTcpClient, method: str, unit_id: int, **kwargs):
    fn = getattr(client, method)
    try:
        return fn(**kwargs, device_id=unit_id)
    except TypeError:
        try:
            return fn(**kwargs, slave=unit_id)
        except TypeError:
            return fn(**kwargs, unit=unit_id)


def _is_ok(resp: Any) -> bool:
    return bool(resp) and not getattr(resp, "isError", lambda: True)()


def _probe_unit(ip: str, port: int, timeout: float, uid: int) -> Optional[int]:
    c = ModbusTcpClient(ip, port=port, timeout=timeout)
    try:
        if not c.connect():
            return None
        rr = _call(c, "read_holding_registers", uid, address=0, count=1)
        if _is_ok(rr):
            return uid
    except Exception:
        return None
    finally:
        c.close()
    return None


def _regs_to_ascii(registers: Sequence[int]) -> Tuple[str, str]:
    be = bytearray()
    le = bytearray()
    for r in registers:
        hi = (int(r) >> 8) & 0xFF
        lo = int(r) & 0xFF
        be.extend([hi, lo])
        le.extend([lo, hi])
    be_s = "".join(chr(b) if 32 <= b < 127 else "." for b in be)
    le_s = "".join(chr(b) if 32 <= b < 127 else "." for b in le)
    return be_s, le_s


def _score_unit(coils: List[int], holding: List[int], inputs: List[int], keywords_re: re.Pattern[str]) -> Dict[str, Any]:
    all_regs = list(holding) + list(inputs)
    non_zero_regs = sum(1 for v in all_regs if int(v) != 0)
    non_zero_coils = sum(1 for b in coils if int(b) != 0)

    h_be, h_le = _regs_to_ascii(holding)
    i_be, i_le = _regs_to_ascii(inputs)
    merged_text = "\n".join([h_be, h_le, i_be, i_le])

    meaningful_chars = sum(1 for ch in merged_text if ch.isalnum() or ch in "{}_:-")
    meaningful_ratio = (meaningful_chars / max(1, len(merged_text))) if merged_text else 0.0

    token_hits = re.findall(r"[A-Za-z0-9_\-]{4,}", merged_text)
    token_density = len(token_hits)

    keyword_hits = sorted(set(m.group(0).lower() for m in keywords_re.finditer(merged_text)))

    # Weighted score tuned for CTF triage speed
    score = 0
    score += min(non_zero_regs, 100) * 2
    score += min(non_zero_coils, 32)
    score += int(meaningful_ratio * 100)
    score += min(token_density, 20) * 2
    score += len(keyword_hits) * 40

    return {
        "score": score,
        "non_zero_regs": non_zero_regs,
        "non_zero_coils": non_zero_coils,
        "meaningful_ratio": round(meaningful_ratio, 4),
        "token_density": token_density,
        "keyword_hits": keyword_hits,
        "holding_ascii_be": h_be,
        "holding_ascii_le": h_le,
        "input_ascii_be": i_be,
        "input_ascii_le": i_le,
    }


def _read_coils(c: ModbusTcpClient, uid: int, start: int, count: int) -> List[int]:
    try:
        rr = _call(c, "read_coils", uid, address=start, count=count)
        if _is_ok(rr) and getattr(rr, "bits", None) is not None:
            return [1 if b else 0 for b in rr.bits[:count]]
    except Exception:
        pass
    return [0] * count


def _read_regs(c: ModbusTcpClient, method: str, uid: int, start: int, count: int) -> List[int]:
    try:
        rr = _call(c, method, uid, address=start, count=count)
        if _is_ok(rr) and getattr(rr, "registers", None) is not None:
            regs = [int(v) & 0xFFFF for v in rr.registers]
            if len(regs) < count:
                regs.extend([0] * (count - len(regs)))
            return regs[:count]
    except Exception:
        pass
    return [0] * count


def main() -> None:
    p = argparse.ArgumentParser(description="Modbus Unit Mapper (FC01/03/04) - AI Ready")
    p.add_argument("--ip", required=True, help="Target IP")
    p.add_argument("--port", type=int, default=502, help="Target port")
    p.add_argument("--timeout", type=float, default=1.0, help="Socket timeout")
    p.add_argument("--unit-range", default="1-247", help="Unit range, e.g. 1-247")
    p.add_argument("--probe-units", action="store_true", help="Probe active units first")
    p.add_argument("--max-workers", type=int, default=50, help="Thread count for probe")

    p.add_argument("--coil-start", type=int, default=0)
    p.add_argument("--coil-count", type=int, default=32)
    p.add_argument("--hold-start", type=int, default=0)
    p.add_argument("--hold-count", type=int, default=128)
    p.add_argument("--input-start", type=int, default=0)
    p.add_argument("--input-count", type=int, default=128)

    p.add_argument(
        "--keywords",
        default="scram,rod,temp,speed,code,flag,disarm,emergency,override,reactor,centrifuge",
        help="Comma-separated keywords for relevance scoring",
    )
    p.add_argument("--top", type=int, default=5, help="How many top units to include")
    p.add_argument("--json", action="store_true", help="Output pure JSON")
    args = p.parse_args()

    report: Dict[str, Any] = {
        "target": f"{args.ip}:{args.port}",
        "status": "success",
        "error_msg": "",
        "scanned_units": [],
        "unit_rankings": [],
        "recommended_unit": None,
        "next_action": "",
        "suggested_commands": [],
    }

    try:
        units = _iter_units(args.unit_range)
    except ValueError as e:
        report["status"] = "error"
        report["error_msg"] = str(e)
        print(json.dumps(report, indent=2))
        raise SystemExit(2)

    if args.probe_units:
        active: List[int] = []
        with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
            for uid in ex.map(lambda u: _probe_unit(args.ip, args.port, args.timeout, u), units):
                if uid is not None:
                    active.append(uid)
        units = sorted(set(active))

    report["scanned_units"] = units

    if not units:
        report["status"] = "no_units_found"
        report["next_action"] = "verify_target_or_port"
        report["suggested_commands"] = [
            f"nc -zvw 10 {args.ip} {args.port}",
            f"/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_connect_test.py --ip {args.ip} --port {args.port} --full-scan --json",
        ]
        print(json.dumps(report, indent=2))
        raise SystemExit(1)

    keywords = [k.strip().lower() for k in str(args.keywords).split(",") if k.strip()]
    if not keywords:
        keywords = ["flag"]
    keywords_re = re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)

    rankings: List[Dict[str, Any]] = []
    c = ModbusTcpClient(args.ip, port=args.port, timeout=args.timeout)
    if not c.connect():
        report["status"] = "connection_failed"
        report["error_msg"] = "failed to connect"
        report["next_action"] = "check_reachability"
        report["suggested_commands"] = [f"nc -zvw 10 {args.ip} {args.port}"]
        print(json.dumps(report, indent=2))
        raise SystemExit(1)

    try:
        for uid in units:
            coils = _read_coils(c, uid, args.coil_start, args.coil_count)
            holding = _read_regs(c, "read_holding_registers", uid, args.hold_start, args.hold_count)
            inputs = _read_regs(c, "read_input_registers", uid, args.input_start, args.input_count)

            metrics = _score_unit(coils, holding, inputs, keywords_re)
            rankings.append(
                {
                    "unit_id": uid,
                    "score": metrics["score"],
                    "metrics": {
                        "non_zero_regs": metrics["non_zero_regs"],
                        "non_zero_coils": metrics["non_zero_coils"],
                        "meaningful_ratio": metrics["meaningful_ratio"],
                        "token_density": metrics["token_density"],
                        "keyword_hits": metrics["keyword_hits"],
                    },
                    "evidence": {
                        "coils_preview": coils[:32],
                        "holding_preview": holding[:16],
                        "input_preview": inputs[:16],
                        "holding_ascii_be": metrics["holding_ascii_be"][:256],
                        "holding_ascii_le": metrics["holding_ascii_le"][:256],
                        "input_ascii_be": metrics["input_ascii_be"][:256],
                        "input_ascii_le": metrics["input_ascii_le"][:256],
                    },
                }
            )
    finally:
        c.close()

    rankings.sort(key=lambda x: x["score"], reverse=True)
    top_rankings = rankings[: max(1, args.top)]
    report["unit_rankings"] = top_rankings

    if not rankings:
        report["recommended_unit"] = None
    else:
        best_score = rankings[0]["score"]
        tied_best = [r for r in rankings if r["score"] == best_score]
        if best_score <= 0 or len(tied_best) > 1:
            report["recommended_unit"] = None
            report["status"] = "ambiguous_unit_selection"
            report["error_msg"] = "No clear winning Unit ID; expand ranges or add challenge-specific keywords"
            report["next_action"] = "expand_evidence_and_rerank"
            report["suggested_commands"] = [
                f"/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_unit_map.py --ip {args.ip} --port {args.port} --probe-units --unit-range {args.unit_range} --hold-count 256 --input-count 256 --keywords '{args.keywords},alarm,status,hmi' --top {args.top} --json",
                f"/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py --ip {args.ip} --port {args.port} --probe-units --reg-start 0 --reg-end 512 --json",
            ]
        else:
            report["recommended_unit"] = rankings[0]["unit_id"]
            rid = report["recommended_unit"]
            report["next_action"] = "use_recommended_unit_read_first"
            report["suggested_commands"] = [
                f"/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_holding_registers.py {args.ip} --port {args.port} --unit {rid} --addr 0 --count 256 --json",
                f"/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py --ip {args.ip} --port {args.port} --unit {rid} --reg-start 0 --reg-end 512 --json",
            ]

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
