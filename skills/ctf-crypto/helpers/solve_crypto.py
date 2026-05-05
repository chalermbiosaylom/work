#!/usr/bin/env python3
"""Compatibility wrapper for solve_crypto.py at skill root."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root_solver = Path(__file__).resolve().parents[1] / "solve_crypto.py"
    if not root_solver.exists():
        print(f"solver not found: {root_solver}", file=sys.stderr)
        return 1

    cmd = [sys.executable, str(root_solver), *sys.argv[1:]]
    proc = subprocess.run(cmd)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
