# ciptool_tiger_custom_packet_flow

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: custom CIP service/class/instance path
- trigger value: service `0x01` class `0x01` instance `0x01`
- pre-state: CIP session open
- post-state: raw response captured for decode

## 3) Action path
- read ranges: custom packet response bytes
- write sequence: optional depending on service used
- verification signals: response value / CIP error

## 4) Decode chain
- source artifacts: raw returned bytes
- chain order: bytes -> printable/hex -> regex
- successful variant: direct `send_request()` execution

## 5) Decoy handling
- decoy observed: protocol errors without payload
- rejection reason: only accept regex hits from successful response

## 6) Final evidence
- flag/result: raw-packet derived artifacts
- command used: see corpus win_command
- reproducibility: medium-low (service dependent)
