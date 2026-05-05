# ciptool_cli_discovery_workflow

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: local network visibility
- post-state: discovered endpoint list

## 3) Action path
- read ranges: discovery responses only
- write sequence: none
- verification signals: discovered count output

## 4) Decode chain
- source artifacts: discover response metadata
- chain order: direct parse
- successful variant: non-interactive Python entrypoint

## 5) Decoy handling
- decoy observed: empty result set
- rejection reason: treat as valid recon outcome when no devices found

## 6) Final evidence
- flag/result: endpoint inventory
- command used: see corpus win_command
- reproducibility: medium
