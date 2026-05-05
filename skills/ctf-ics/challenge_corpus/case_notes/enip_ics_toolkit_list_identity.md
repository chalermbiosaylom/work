# enip_ics_toolkit_list_identity

## 1) Target lock
- source: OT-Security-Lab toolkit
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: ENIP endpoint reachable
- post-state: identity item parsed

## 3) Action path
- read ranges: encapsulation header + identity item
- write sequence: none
- verification signals: parsed identity fields

## 4) Decode chain
- source artifacts: identity payload
- chain order: raw -> denull -> utf16 -> regex
- successful variant: parser-assisted identity extraction

## 5) Decoy handling
- decoy observed: non-flag metadata noise
- rejection reason: strict regex and context match

## 6) Final evidence
- flag/result: identity-derived clues/candidates
- command used: see corpus win_command
- reproducibility: medium
