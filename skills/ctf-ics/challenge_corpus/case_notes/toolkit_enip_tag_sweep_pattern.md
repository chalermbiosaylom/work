# toolkit_enip_tag_sweep_pattern

## 1) Target lock
- source: OT-Security-Lab toolkit
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none (read sweep)
- trigger value: n/a
- pre-state: target reachable
- post-state: sweep results collected

## 3) Action path
- read ranges: class8 sweep 1-50 / attrs 1-10
- write sequence: none
- verification signals: tags_scanned and flags_found fields

## 4) Decode chain
- source artifacts: raw sweep response bytes
- chain order: utf16/denull -> regex -> hex fallback
- successful variant: full sweep with JSON output

## 5) Decoy handling
- decoy observed: non-flag tokens and protocol noise
- rejection reason: strict wrapper regex + context provenance

## 6) Final evidence
- flag/result: candidate flags from sweep
- command used: see corpus win_command
- reproducibility: high
