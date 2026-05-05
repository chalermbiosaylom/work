# modbus_unit_map_ranking_state_pivot

## 1) Target lock
- source: ctf-ics tools
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit (if Modbus): probe range 1-20

## 2) State gate
- gate type/address: unit-id selection gate
- trigger value: choose highest-signal unit
- pre-state: unknown/ambiguous unit
- post-state: ranked unit evidence + recommendation

## 3) Action path
- read ranges: FC01/FC03/FC04 previews
- write sequence: none
- verification signals: score ranking and keyword hits

## 4) Decode chain
- source artifacts: register previews and ascii variants
- chain order: be/le decode -> keyword scoring
- successful variant: probe+rank before any write

## 5) Decoy handling
- decoy observed: low-score units with noise
- rejection reason: require top scoring unit with meaningful evidence

## 6) Final evidence
- flag/result: recommended unit + follow-up commands
- command used: see corpus win_command
- reproducibility: high
