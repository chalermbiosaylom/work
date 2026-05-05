# ICS Challenge Memory Template (60 seconds)

Use this immediately after recovering a clue/flag so future runs can replay the same success path quickly.

## 1) Target Lock
- Challenge name:
- Protocol/port:
- Target IP:
- Unit ID (if Modbus):
- Address base model (0-based / 1-based):

## 2) State Gate
- Gate type (coil/register/tag):
- Gate address/name:
- Trigger value:
- Pre-state proof:
- Post-state proof:

## 3) Deterministic Action Path
- Read ranges used first:
- Write sequence used (ordered):
- Sensor/verification checks:
- Session rule (single session? yes/no):

## 4) Decode Chain
- Source range(s):
- Chain order (exact):
  - Example: `ascii -> base64 -> hex -> flag`
- Endianness variants tested:
- Successful variant:

## 5) Decoy Guard
- Decoy candidate(s):
- Why rejected (proof):
- Final validated candidate:

## 6) Final Evidence
- Final flag:
- One-line extraction command:
- Reproducibility status (repeatable / unstable):

## 7) Reuse Tags (for memory DB)
- tags: `ics_ot`, `protocol`, `challenge_family`, `state_gated`, `decode_chain`
- key registers/coils/tags:
- pivot trigger if stuck (3-fail bailout):
