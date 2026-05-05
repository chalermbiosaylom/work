# Step 3: Match-Day Only Profile

## Goal
Run only fast and reliable corpus cases during competition warmup/validation.

## Profile File
- `challenge_corpus/matchday_only_profile.json`

## Inputs Used
- ENIP real replay report:
  - `challenge_corpus/replay_enip_real_run.json`
- Existing Modbus proven/read-focused cases from corpus.

## Current Stable Set
- Tier A: `strict_validated_now`
  - Only cases that passed latest real-run with semantic checks
  - Current IDs: `modbus_illuminated_pcap`, `enip_pcap_flag_forensics_pattern`
- Tier B: `service_up_candidates`
  - Fast candidate set for when lab services are confirmed reachable
  - Includes Modbus + ENIP low-TTR paths that are network/service dependent

## Run Commands
### Tier A (strict now)
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py \
  --protocols modbus,enip \
  --include-ids modbus_illuminated_pcap,enip_pcap_flag_forensics_pattern \
  --timeout 20 --json
```

### Tier B (service up)
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py \
  --protocols modbus,enip \
  --include-ids modbus_chemtech_flag1_register_dump,modbus_chemtech_flag2_maintenance_override,modbus_chemtech_flag3_rgb_formula,modbus_illuminated_pcap,modbus_connect_fullscan_triage,modbus_holding_inspector_chunked,modbus_unit_map_ranking_state_pivot,modbus_state_gated_recovery_pattern,toolkit_enip_tag_sweep_pattern,enip_cpppo_auto_sweep_class8,enip_ics_toolkit_read_sweep,enip_pcap_flag_forensics_pattern \
  --timeout 20 --json
```

## Notes
- Rebuild this profile after each major environment change (service state, dependency updates, network changes).
- Keep unstable entries in corpus, but exclude them from Tier A unless they become stable.

## Auto Regenerate
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/build_matchday_profile.py \
  --replay-dir /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus \
  --output /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/matchday_only_profile.json \
  --max-ttr-sec 2.0 --timeout 20 --top-service-up 12 --min-executed-cases 8
```
