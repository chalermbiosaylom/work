# Step 1: Challenge Corpus (ICS 20-30 Cases)

Current status: `COMPLETED (30 seeded cases)`

## Goal
Create a reusable, searchable practice corpus for ICS/OT CTF that accelerates repeated solve patterns.

Target outcome for Step 1:
- Collect `20-30` ICS challenges.
- Assign category + protocol tags.
- Mark pattern tags: `state-gated`, `decode-chain`, `decoy`.
- Record one reproducible command path per case.

## Scope (Step 1 only)
This step is **catalog + tagging only**.
Do not optimize tools yet (that is next steps).

## Required taxonomy
Use these fields for every challenge row:

- `id`: short unique key (e.g. `modbus_colorplant_01`)
- `source`: HTB / ICS lab / internal / CTF name
- `protocol`: modbus / enip / s7 / opcua / bacnet / pcap
- `category`: recon / state_logic / memory_decode / network_forensics / mixed
- `difficulty`: easy / medium / hard
- `state_gated`: yes/no
- `decode_chain`: none / base64 / hex / base64>hex / hex>xor>base64 / other
- `decoy_present`: yes/no
- `core_pattern`: 1-line pattern summary
- `win_command`: strict 1-line reproducible extraction chain
- `notes_path`: path to notes/writeup file

## Recommended distribution (30-case target)
- Modbus: `10`
- EtherNet/IP: `6`
- S7comm: `4`
- OPC-UA: `3`
- BACnet: `2`
- PCAP/forensics mixed ICS: `5`

## Build steps
1. Create corpus table (markdown or csv).
2. Add first 10 known solved/partially solved cases.
3. Normalize names and tags using taxonomy above.
4. Add remaining cases until at least 20.
5. Prioritize adding cases with `state-gated=yes` and `decoy_present=yes`.
6. Verify every row has `win_command` and `notes_path`.

## Entry template (copy/paste)
```text
id:
source:
protocol:
category:
difficulty:
state_gated:
decode_chain:
decoy_present:
core_pattern:
win_command:
notes_path:
```

## Quick quality gate
A challenge is corpus-ready only if all are true:
- Tags are complete.
- Pattern is explicit and reusable.
- Command chain is reproducible.
- Notes path exists.

## Suggested file layout
- `challenge_corpus/STEP_1_CHALLENGE_CORPUS.md` (this file)
- `challenge_corpus/corpus_index.md` (actual table)
- `challenge_corpus/case_notes/` (per-case writeups)

Seeded outputs from this step:
- `challenge_corpus/corpus_index.md` (30 real entries with tags + win_command + notes_path)
- `challenge_corpus/case_notes/README.md` (writeup structure)
- `challenge_corpus/case_notes/TEMPLATE.md` (copy/paste template)

## Next step pointer
After Step 1 is complete, continue with:
- Step 2: Replay Harness + timing metrics per pattern family (`challenge_corpus/STEP_2_REPLAY_HARNESS.md`)
- Step 2.1: ENIP real-run evidence (`challenge_corpus/replay_enip_real_run.json`)
- Step 3: Match-day stable subset profile (`challenge_corpus/STEP_3_MATCHDAY_PROFILE.md`, `challenge_corpus/matchday_only_profile.json`)
