#!/usr/bin/env python3
"""Competition-oriented flag and token pattern helpers."""

from __future__ import annotations

import re
from typing import Iterable, List

PRIMARY_FLAG_PATTERNS = [
    re.compile(r"(?:coc2026|rtaf|ctf|flag)\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"\{[a-fA-F0-9]{32}\}"),
]

RAW_HASH32 = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_candidates(text: str, allow_raw_hash32: bool = False) -> List[str]:
    if not text:
        return []

    out: List[str] = []
    seen = set()

    for rx in PRIMARY_FLAG_PATTERNS:
        for m in rx.finditer(text):
            token = m.group(0)
            if token not in seen:
                seen.add(token)
                out.append(token)

    if allow_raw_hash32:
        for m in RAW_HASH32.finditer(text):
            token = m.group(0)
            if token not in seen:
                seen.add(token)
                out.append(token)

    return out


def extract_from_lines(lines: Iterable[str], allow_raw_hash32: bool = False) -> List[str]:
    merged = "\n".join(lines)
    return extract_candidates(merged, allow_raw_hash32=allow_raw_hash32)


def sanitize_flag(token: str) -> str:
    token = (token or "").strip()
    return token.replace("\n", "").replace("\r", "")
