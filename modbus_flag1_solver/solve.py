import argparse
import base64
import re
import socket
import struct
import sys
from dataclasses import dataclass


BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")
DEFAULT_FLAG_RE = r"(?i)(?:coc2026|flag|ctf|rtaf|f1a9|fl4g)\{[^}\r\n]{1,200}\}"


@dataclass(frozen=True)
class ReadResult:
    addr: int
    count: int
    regs: list[int]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    got = 0
    while got < n:
        b = sock.recv(n - got)
        if not b:
            raise ConnectionError("socket closed")
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def modbus_read_holding_registers(
    host: str,
    port: int,
    unit: int,
    addr: int,
    count: int,
    transaction_id: int,
    timeout_s: float,
) -> ReadResult:
    if not (0 <= unit <= 255):
        raise ValueError("unit must be 0..255")
    if not (0 <= addr <= 0xFFFF):
        raise ValueError("addr must be 0..65535")
    if not (1 <= count <= 125):
        raise ValueError("count must be 1..125")

    pdu = struct.pack(">BHH", 3, addr, count)
    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, 0, len(pdu) + 1, unit)
    req = mbap + pdu

    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        s.sendall(req)

        hdr = _recv_exact(s, 7)
        rx_tid, rx_pid, rx_len, rx_uid = struct.unpack(">HHHB", hdr)
        if rx_tid != (transaction_id & 0xFFFF) or rx_pid != 0 or rx_uid != unit:
            raise ValueError("unexpected mbap header")

        body = _recv_exact(s, rx_len - 1)
        fc = body[0]
        if fc & 0x80:
            if len(body) < 2:
                raise ValueError("short exception response")
            raise RuntimeError(f"modbus exception fc=0x{fc:02x} code=0x{body[1]:02x}")
        if fc != 3:
            raise ValueError(f"unexpected function code: {fc}")
        if len(body) < 2:
            raise ValueError("short response")

        byte_count = body[1]
        data = body[2:]
        if byte_count != len(data):
            raise ValueError("byte_count mismatch")
        if byte_count % 2 != 0:
            raise ValueError("odd byte_count")

        regs = [struct.unpack(">H", data[i : i + 2])[0] for i in range(0, byte_count, 2)]
        return ReadResult(addr=addr, count=len(regs), regs=regs)


def regs_to_bytes_be(regs: list[int]) -> bytes:
    return b"".join(struct.pack(">H", r & 0xFFFF) for r in regs)


def regs_to_bytes_le(regs: list[int]) -> bytes:
    out = bytearray()
    for r in regs:
        out.append(r & 0xFF)
        out.append((r >> 8) & 0xFF)
    return bytes(out)


def bytes_to_printable_ascii(b: bytes) -> str:
    return bytes(x for x in b if 32 <= x <= 126).decode("ascii", errors="ignore")


def iter_base64_candidates(s: str, min_len: int) -> list[str]:
    out: list[str] = []
    for m in BASE64_RE.finditer(s):
        cand = m.group(0)
        if len(cand) >= min_len:
            out.append(cand)
    return out


def try_decode_base64(cand: str) -> list[str]:
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", cand)
    if len(cleaned) < 8:
        return []
    trimmed = cleaned[: len(cleaned) - (len(cleaned) % 4)]
    if len(trimmed) < 8:
        return []

    out: list[str] = []
    for s in {trimmed, trimmed.rstrip("=")}:
        for pad in ["", "=", "==", "==="]:
            t = s + pad
            t = t[: len(t) - (len(t) % 4)]
            if len(t) < 8:
                continue
            try:
                dec = base64.b64decode(t, validate=False)
            except Exception:
                continue
            try:
                text = dec.decode("utf-8")
            except Exception:
                text = dec.decode("latin-1", errors="replace")
            out.append(text)
    return list(dict.fromkeys(out))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=10000)
    ap.add_argument("--count", type=int, default=125)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--min-b64-len", type=int, default=24)
    ap.add_argument("--flag-regex", default=DEFAULT_FLAG_RE)
    args = ap.parse_args()

    if args.start < 0 or args.end < args.start:
        raise SystemExit("invalid start/end")
    if args.count < 1 or args.count > 125:
        raise SystemExit("count must be 1..125")

    flag_re = re.compile(args.flag_regex)

    transaction_id = 1
    window_be = ""
    window_le = ""

    for addr in range(args.start, args.end + 1, args.count):
        count = min(args.count, args.end - addr + 1)

        for attempt in range(2):
            try:
                rr = modbus_read_holding_registers(
                    host=args.host,
                    port=args.port,
                    unit=args.unit,
                    addr=addr,
                    count=count,
                    transaction_id=transaction_id,
                    timeout_s=args.timeout,
                )
                break
            except Exception:
                if attempt == 1:
                    rr = None
                transaction_id += 1
        if rr is None:
            continue

        transaction_id += 1

        be = bytes_to_printable_ascii(regs_to_bytes_be(rr.regs))
        le = bytes_to_printable_ascii(regs_to_bytes_le(rr.regs))

        window_be = (window_be + be)[-8192:]
        window_le = (window_le + le)[-8192:]

        for endian, window in [("BE", window_be), ("LE", window_le)]:
            cands = iter_base64_candidates(window, min_len=args.min_b64_len)
            for c in cands[-50:]:
                for decoded in try_decode_base64(c):
                    m = flag_re.search(decoded)
                    if not m:
                        continue
                    flag = m.group(0)
                    sys.stdout.write(f"[FLAG] {flag}\n")
                    sys.stdout.write(f"[METHOD] python3 solve.py --host {args.host} --port {args.port} --unit {args.unit} --start {args.start} --end {args.end}\n")
                    sys.stdout.write(f"[META] endian={endian} last_addr={addr} window_len={len(window)}\n")
                    return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

