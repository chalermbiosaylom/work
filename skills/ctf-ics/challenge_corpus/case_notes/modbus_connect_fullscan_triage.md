# modbus_connect_fullscan_triage

## 1) Target lock
- source: ctf-ics tools
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit (if Modbus): full scan

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: target unknown
- post-state: active slave IDs discovered

## 3) Action path
- read ranges: FC03 addr0 probe per unit
- write sequence: none
- verification signals: active_slaves list

## 4) Decode chain
- source artifacts: probe responses
- chain order: response/error classification
- successful variant: full-scan mode with JSON output

## 5) Decoy handling
- decoy observed: exception responses
- rejection reason: classify as active but non-readable, not as flag

## 6) Final evidence
- flag/result: triage map for next read/hunt steps
- command used: see corpus win_command
- reproducibility: high
