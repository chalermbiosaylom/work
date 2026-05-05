# modbus_state_gated_recovery_pattern

## 1) Target lock
- source: ctf-ics skill hardening
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit (if Modbus): 1

## 2) State gate
- gate type/address: coil 99 maintenance gate
- trigger value: true
- pre-state: gate off, hidden ranges not unlocked
- post-state: gate on with unlocked decode ranges

## 3) Action path
- read ranges: decode windows 100/200/300/400
- write sequence: trigger coil -> verify -> decode
- verification signals: gate readback + decoded clues

## 4) Decode chain
- source artifacts: unlocked HR data
- chain order: ascii/hex/base64 variants + clue follow-up
- successful variant: follow `>>HRxxx` clue if present

## 5) Decoy handling
- decoy observed: FAKE/not_the_flag style wrappers
- rejection reason: strict provenance + source register validation

## 6) Final evidence
- flag/result: validated final flags from unlocked chain
- command used: see corpus win_command
- reproducibility: high
