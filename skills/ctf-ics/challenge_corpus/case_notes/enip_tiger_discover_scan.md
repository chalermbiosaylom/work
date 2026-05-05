# enip_tiger_discover_scan

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP discovery
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: network segment visibility
- post-state: discovered device list

## 3) Action path
- read ranges: discover responses
- write sequence: none
- verification signals: discovered list length

## 4) Decode chain
- source artifacts: discover payloads
- chain order: identity parse -> optional regex scan
- successful variant: discovery before direct tag hunting

## 5) Decoy handling
- decoy observed: empty discover output
- rejection reason: treat as recon result, not failure alone

## 6) Final evidence
- flag/result: target inventory
- command used: see corpus win_command
- reproducibility: medium (network dependent)
