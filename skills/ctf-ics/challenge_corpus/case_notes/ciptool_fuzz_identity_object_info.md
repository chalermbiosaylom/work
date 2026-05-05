# ciptool_fuzz_identity_object_info

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: CIP session open
- post-state: identity object bytes returned

## 3) Action path
- read ranges: CIP identity object attributes
- write sequence: none
- verification signals: byte dump and parsed fields

## 4) Decode chain
- source artifacts: identity bytes
- chain order: bytes -> printable/regex scan
- successful variant: `fuzzing.cipGetInfo()`

## 5) Decoy handling
- decoy observed: serial/version noise
- rejection reason: strict wrapper regex only

## 6) Final evidence
- flag/result: identity metadata and possible clue text
- command used: see corpus win_command
- reproducibility: medium
