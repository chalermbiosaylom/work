# enip_ics_toolkit_read_sweep

## 1) Target lock
- source: OT-Security-Lab toolkit
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none (read-only)
- trigger value: n/a
- pre-state: session established
- post-state: scanned path result set

## 3) Action path
- read ranges: class8 instance/attribute sweep
- write sequence: none
- verification signals: tags_scanned + hits list

## 4) Decode chain
- source artifacts: raw read outputs
- chain order: bytes -> utf16/denull -> regex
- successful variant: bounded sweep range for speed

## 5) Decoy handling
- decoy observed: random symbols/noise
- rejection reason: keep strict wrapper regex only

## 6) Final evidence
- flag/result: sweep candidates
- command used: see corpus win_command
- reproducibility: high
