#!/usr/bin/env python3
"""
State-gated Modbus decoder for ICS CTF challenges.

Workflow:
1) Optional trigger gate coil
2) Optional register writes for process transition
3) Optional expectation checks from input registers
4) Layered decode over holding register ranges
5) Optional HR clue follow-up (e.g. ">>HR500")
"""

import argparse
import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from pymodbus.client import ModbusTcpClient

DEFAULT_FLAG_REGEX = r"(?:coc2026|flag|ctf|f1a9|fl4g)\{[^}\r\n]{1,200}\}"
DECOY_MARKERS = ("fake", "not_the_flag", "decoy")
MAX_READ_CHUNK = 120


@dataclass
class DecodeCandidate:
    source: str
    variant: str
    chain: str
    value: str


def parse_assignments(spec: str) -> Dict[int, int]:
    out: Dict[int, int] = {}
    if not spec.strip():
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid assignment '{part}', expected key=value")
        k, v = part.split("=", 1)
        out[int(k.strip(), 0)] = int(v.strip(), 0)
    return out


def parse_ranges(spec: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    if not spec.strip():
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid range '{part}', expected start:count")
        start_s, count_s = part.split(":", 1)
        start, count = int(start_s.strip(), 0), int(count_s.strip(), 0)
        if count <= 0:
            raise ValueError(f"invalid count in range '{part}'")
        out.append((start, count))
    return out


def parse_bool01(v: str) -> bool:
    vv = str(v).strip().lower()
    if vv in {"1", "true", "on", "yes"}:
        return True
    if vv in {"0", "false", "off", "no"}:
        return False
    raise ValueError(f"invalid boolean value '{v}'")


def _call(client: ModbusTcpClient, method: str, unit_id: int, **kwargs):
    fn = getattr(client, method)
    try:
        return fn(slave=unit_id, **kwargs)
    except TypeError:
        return fn(unit=unit_id, **kwargs)


def _read_register_span(client: ModbusTcpClient, unit_id: int, method: str, start: int, count: int) -> List[int]:
    vals: List[int] = []
    cur = start
    left = count
    while left > 0:
        chunk = min(left, MAX_READ_CHUNK)
        rr = _call(client, method, unit_id, address=cur, count=chunk)
        if rr is None or getattr(rr, "isError", lambda: True)():
            break
        regs = getattr(rr, "registers", None)
        if not regs:
            break
        vals.extend(regs)
        cur += chunk
        left -= chunk
    return vals


def _read_coils(client: ModbusTcpClient, unit_id: int, start: int, count: int) -> List[bool]:
    rr = _call(client, "read_coils", unit_id, address=start, count=count)
    if rr is None or getattr(rr, "isError", lambda: True)():
        return []
    return list(getattr(rr, "bits", [])[:count])


def _write_coil(client: ModbusTcpClient, unit_id: int, address: int, value: bool) -> bool:
    rr = _call(client, "write_coil", unit_id, address=address, value=bool(value))
    return rr is not None and not getattr(rr, "isError", lambda: True)()


def _write_register(client: ModbusTcpClient, unit_id: int, address: int, value: int) -> bool:
    rr = _call(client, "write_register", unit_id, address=address, value=(int(value) & 0xFFFF))
    return rr is not None and not getattr(rr, "isError", lambda: True)()


def _regs_to_bytes_variants(registers: Sequence[int]) -> List[Tuple[str, bytes]]:
    def be(regs: Sequence[int]) -> bytes:
        out = bytearray()
        for r in regs:
            out.extend(int(r).to_bytes(2, "big", signed=False))
        return bytes(out)

    def le(regs: Sequence[int]) -> bytes:
        out = bytearray()
        for r in regs:
            out.extend(int(r).to_bytes(2, "big", signed=False)[::-1])
        return bytes(out)

    def word_swap(regs: Sequence[int]) -> List[int]:
        out: List[int] = []
        i = 0
        while i + 1 < len(regs):
            out.extend([regs[i + 1], regs[i]])
            i += 2
        if i < len(regs):
            out.append(regs[i])
        return out

    regs = list(registers)
    ws = word_swap(regs)
    return [
        ("be", be(regs)),
        ("le", le(regs)),
        ("ws_be", be(ws)),
        ("ws_le", le(ws)),
    ]


def _extract_text(blob: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in blob)


def _is_decoy(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in DECOY_MARKERS)


def _decode_candidates(source: str, regs: Sequence[int], flag_re: "re.Pattern[str]") -> Tuple[List[DecodeCandidate], List[DecodeCandidate], List[str]]:
    valid: List[DecodeCandidate] = []
    rejected: List[DecodeCandidate] = []
    clues: List[str] = []

    for variant, blob in _regs_to_bytes_variants(regs):
        text = _extract_text(blob)

        for m in re.finditer(r">>\s*HR(\d{1,5})", text, re.IGNORECASE):
            clues.append(m.group(1))

        for m in flag_re.finditer(text):
            c = DecodeCandidate(source=source, variant=variant, chain="direct_ascii", value=m.group(0))
            (rejected if _is_decoy(c.value) else valid).append(c)

        b64_tokens = set(re.findall(r"[A-Za-z0-9+/=]{12,}", text))
        for token in b64_tokens:
            for t in (token, token[::-1], token[1:], token[:-1]):
                if len(t) < 8:
                    continue
                try:
                    decoded = base64.b64decode(t + "=" * (-len(t) % 4))
                except Exception:
                    continue
                decoded_txt = decoded.decode("utf-8", errors="ignore")
                for m in flag_re.finditer(decoded_txt):
                    c = DecodeCandidate(source=source, variant=variant, chain="ascii->base64", value=m.group(0))
                    (rejected if _is_decoy(c.value) else valid).append(c)

                hex_tokens = set(re.findall(r"[0-9a-fA-F]{16,}", decoded_txt))
                for h in hex_tokens:
                    if len(h) % 2 != 0:
                        continue
                    try:
                        htxt = binascii.unhexlify(h).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    for m in flag_re.finditer(htxt):
                        c = DecodeCandidate(source=source, variant=variant, chain="ascii->base64->hex", value=m.group(0))
                        (rejected if _is_decoy(c.value) else valid).append(c)

        hex_tokens = set(re.findall(r"[0-9a-fA-F]{16,}", text))
        for h in hex_tokens:
            if len(h) % 2 != 0:
                continue
            try:
                htxt = binascii.unhexlify(h).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for m in flag_re.finditer(htxt):
                c = DecodeCandidate(source=source, variant=variant, chain="ascii->hex", value=m.group(0))
                (rejected if _is_decoy(c.value) else valid).append(c)

            try:
                btxt = base64.b64decode(htxt + "=" * (-len(htxt) % 4)).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for m in flag_re.finditer(btxt):
                c = DecodeCandidate(source=source, variant=variant, chain="ascii->hex->base64", value=m.group(0))
                (rejected if _is_decoy(c.value) else valid).append(c)

    return dedup_candidates(valid), dedup_candidates(rejected), sorted(set(clues))


def dedup_candidates(items: List[DecodeCandidate]) -> List[DecodeCandidate]:
    out: List[DecodeCandidate] = []
    seen = set()
    for x in items:
        key = (x.value, x.chain, x.source, x.variant)
        if key in seen:
            continue
        seen.add(key)
        out.append(x)
    return out


def verify_expectations(client: ModbusTcpClient, unit: int, expected_input: Dict[int, int]) -> Dict[str, object]:
    result = {"ok": True, "checks": []}
    if not expected_input:
        return result

    min_addr = min(expected_input)
    max_addr = max(expected_input)
    vals = _read_register_span(client, unit, "read_input_registers", min_addr, max_addr - min_addr + 1)
    if len(vals) < (max_addr - min_addr + 1):
        result["ok"] = False
        result["checks"].append({"error": "failed_to_read_expected_input_range"})
        return result

    for addr in sorted(expected_input):
        got = vals[addr - min_addr]
        exp = expected_input[addr]
        ok = (got == exp)
        if not ok:
            result["ok"] = False
        result["checks"].append({"address": addr, "expected": exp, "got": got, "ok": ok})
    return result


def main() -> None:
    p = argparse.ArgumentParser(description="State-gated Modbus decoder (trigger -> verify -> decode)")
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--unit", type=int, default=1)
    p.add_argument("--trigger-coil", type=int, default=None)
    p.add_argument("--trigger-value", default="1", help="0/1 or true/false")
    p.add_argument("--set-registers", default="", help="comma list: addr=value,addr=value")
    p.add_argument("--expect-input", default="", help="comma list: addr=value")
    p.add_argument("--decode-ranges", default="100:100,200:100,300:100,400:100", help="comma list: start:count")
    p.add_argument("--follow-hr-clue", action="store_true", help="follow clues like >>HR500")
    p.add_argument("--flag-regex", default=DEFAULT_FLAG_REGEX)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    try:
        trigger_value = parse_bool01(args.trigger_value)
        writes = parse_assignments(args.set_registers)
        expected_input = parse_assignments(args.expect_input)
        ranges = parse_ranges(args.decode_ranges)
    except ValueError as e:
        raise SystemExit(str(e))

    flag_re = re.compile(args.flag_regex, re.IGNORECASE)
    report: Dict[str, object] = {
        "target": f"{args.ip}:{args.port}",
        "unit": args.unit,
        "status": "ok",
        "actions": [],
        "baseline": {},
        "expectations": {},
        "valid_candidates": [],
        "rejected_candidates": [],
        "clues": [],
        "final_flags": [],
    }

    client = ModbusTcpClient(args.ip, port=args.port, timeout=args.timeout)
    if not client.connect():
        report["status"] = "connection_failed"
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"[-] Connect failed: {args.ip}:{args.port}")
        raise SystemExit(1)

    try:
        report["baseline"] = {
            "coils_0_15": _read_coils(client, args.unit, 0, 16),
            "input_0_19": _read_register_span(client, args.unit, "read_input_registers", 0, 20),
        }

        if args.trigger_coil is not None:
            ok = _write_coil(client, args.unit, args.trigger_coil, trigger_value)
            report["actions"].append({
                "type": "write_coil",
                "address": args.trigger_coil,
                "value": bool(trigger_value),
                "ok": ok,
            })

        for addr in sorted(writes):
            ok = _write_register(client, args.unit, addr, writes[addr])
            report["actions"].append({
                "type": "write_register",
                "address": addr,
                "value": writes[addr],
                "ok": ok,
            })

        exp_result = verify_expectations(client, args.unit, expected_input)
        report["expectations"] = exp_result

        valid: List[DecodeCandidate] = []
        rejected: List[DecodeCandidate] = []
        clue_regs: List[str] = []

        for start, count in ranges:
            regs = _read_register_span(client, args.unit, "read_holding_registers", start, count)
            if not regs:
                continue
            v, r, clues = _decode_candidates(f"HR[{start}:{start + len(regs) - 1}]", regs, flag_re)
            valid.extend(v)
            rejected.extend(r)
            clue_regs.extend(clues)

        if args.follow_hr_clue:
            for clue in sorted(set(clue_regs)):
                addr = int(clue)
                regs = _read_register_span(client, args.unit, "read_holding_registers", addr, 100)
                if not regs:
                    continue
                v, r, _ = _decode_candidates(f"HR[{addr}:{addr + len(regs) - 1}]", regs, flag_re)
                valid.extend(v)
                rejected.extend(r)

        valid = dedup_candidates(valid)
        rejected = dedup_candidates(rejected)

        report["clues"] = sorted(set(clue_regs))
        report["valid_candidates"] = [x.__dict__ for x in valid]
        report["rejected_candidates"] = [x.__dict__ for x in rejected]
        report["final_flags"] = sorted(set(x.value for x in valid))

    finally:
        client.close()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"[*] Target: {report['target']} (unit {args.unit})")
        print(f"[*] Actions: {len(report['actions'])}")
        print(f"[*] Expectation OK: {report['expectations'].get('ok', True)}")
        if report["clues"]:
            print(f"[*] Clues: {report['clues']}")
        if report["final_flags"]:
            for f in report["final_flags"]:
                print(f"[+] {f}")
        else:
            print("[-] No validated flags found")


if __name__ == "__main__":
    main()
