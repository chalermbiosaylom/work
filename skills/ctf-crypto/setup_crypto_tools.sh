#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

python3 -m pip install -r requirements.txt

echo "[+] Python dependencies installed"
echo "[i] For Sage templates, ensure SageMath is installed and install optional packages from sage_requirements.txt as needed"
