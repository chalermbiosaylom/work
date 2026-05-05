# ciptool_tiger_tag_hunt_flow

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: may require target in RUN/unlocked state
- trigger value: challenge-specific
- pre-state: target path reachable
- post-state: tag/value candidate scan completed

## 3) Action path
- read ranges: tag list + optional value readback
- write sequence: none in this flow
- verification signals: candidate hits list from helper

## 4) Decode chain
- source artifacts: tag names and read values
- chain order: plain -> hex decode -> wrapper regex
- successful variant: `list_tags_and_hunt(read_values=True)`

## 5) Decoy handling
- decoy observed: random hex-like tokens
- rejection reason: require valid wrapper and context path

## 6) Final evidence
- flag/result: tag-origin candidates
- command used: see corpus win_command
- reproducibility: medium
