# Step 2: Replay Harness (TTR Benchmark)

## Goal
Automatically replay prior corpus cases and measure TTR (Time To Result), then compare this run vs previous run in **minutes**.

## Scope
- Protocol focus: `modbus` + `ethernet/enip`
- Data source: `challenge_corpus/corpus_index.md`
- Output:
  - last run report: `replay_last_run.json`
  - rolling history: `replay_history.json`

## Script
- `challenge_corpus/replay_harness.py`

## Quick Start

### 1) Dry-run (safe validation)
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py \
  --protocols modbus,eternet \
  --dry-run \
  --max-cases 10
```

### 2) Real run (Modbus + Ethernet/ENIP)
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py \
  --protocols modbus,ethernet \
  --timeout 120 \
  --json
```

### 3) Protocol-specific run
```bash
# Modbus only
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py --protocols modbus

# Ethernet/ENIP only
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py --protocols enip
```

## Useful Flags
- `--max-cases N` : cap execution size
- `--include-ids a,b,c` : run specific cases
- `--exclude-ids x,y,z` : skip unstable/noisy cases
- `--timeout SEC` : per-case timeout

## TTR Interpretation
- `ttr_min` = current run duration per case
- `improve_min_vs_prev`:
  - positive = faster than previous run
  - negative = slower than previous run
- `total_improve_min_vs_prev` = sum of all comparable case deltas

## Notes
- Harness skips unresolved template commands with placeholders like `<target_ip>`.
- Recommended flow:
  1. run with `--dry-run`
  2. run real replay on stable target
  3. inspect `replay_last_run.json` and trend from `replay_history.json`
