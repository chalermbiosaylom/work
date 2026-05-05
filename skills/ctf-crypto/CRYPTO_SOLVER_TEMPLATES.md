# CRYPTO_SOLVER_TEMPLATES (Match-Day)

Use these templates to write reproducible solver programs fast.

## 1) Python Solver Skeleton (General)

```python
#!/usr/bin/env python3
import argparse
import json
import re

FLAG_RE = re.compile(r"(?:coc2026|flag|ctf|rtaf)\{[^}\r\n]{1,200}\}", re.IGNORECASE)

def find_flags(text: str):
    return FLAG_RE.findall(text or "")

def solve(args):
    # TODO: implement challenge-specific logic
    result = {
        "status": "partial",
        "artifacts": {},
        "decoded": [],
        "flags": [],
    }
    return result

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true")
    p.add_argument("--infile", default="")
    args = p.parse_args()

    out = solve(args)
    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(out)

if __name__ == "__main__":
    main()
```

## 2) RSA Attack Pipeline Template

```python
# Order:
# 1) parse N,e,c
# 2) small-e check
# 3) wiener check
# 4) fermat check
# 5) offline factor fallback (yafu/msieve)
# 6) decrypt + decode bytes + regex flag
```

## 3) Oracle Challenge Template (Padding/Bleichenbacher)

```python
# Build oracle(client) wrapper with timeout + retry
# Collect query stats (count, success ratio)
# Store intermediate state every N queries for resume
# Decode plaintext incrementally and flag-scan continuously
```

## 4) ECC/Lattice Template (Sage Mandatory)

```python
# save as solve.sage
# - load params
# - define field/curve or lattice
# - run attack primitive
# - output recovered secret/plaintext
# - emit one-line evidence command
```

## 5) Decode Chain Template (No-Hint)

```python
# candidate -> transforms:
# plain, base64, hex, reverse, utf16le-denull
# score by wrapper-valid + printable ratio + reproducibility
# keep top candidate with source provenance
```

## 6) Competition Output Contract

When flag confirmed, output exactly:

```text
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <single-line command chain>
```
