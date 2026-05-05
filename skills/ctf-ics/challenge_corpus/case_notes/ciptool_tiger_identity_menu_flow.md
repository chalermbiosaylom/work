# ciptool_tiger_identity_menu_flow

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: target path set
- post-state: identity brief printed

## 3) Action path
- read ranges: identity object fields
- write sequence: none
- verification signals: product/revision/serial output

## 4) Decode chain
- source artifacts: identity strings
- chain order: direct parse -> optional regex
- successful variant: `print_target_brief()` helper

## 5) Decoy handling
- decoy observed: generic metadata
- rejection reason: keep only strict flag wrappers

## 6) Final evidence
- flag/result: identity clues
- command used: see corpus win_command
- reproducibility: medium
