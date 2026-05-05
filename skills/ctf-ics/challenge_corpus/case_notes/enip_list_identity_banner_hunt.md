# enip_list_identity_banner_hunt

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none (read-only identity probe)
- trigger value: n/a
- pre-state: TCP/44818 reachable
- post-state: identity payload collected

## 3) Action path
- read ranges: ENIP ListIdentity payload
- write sequence: none
- verification signals: response header + payload fields

## 4) Decode chain
- source artifacts: identity payload bytes
- chain order: raw -> denull -> utf16le -> regex
- successful variant: denull/utf16 paths

## 5) Decoy handling
- decoy observed: possible banner noise
- rejection reason: keep only regex-valid flag wrapper with payload provenance

## 6) Final evidence
- flag/result: identity clues / candidate flags
- command used: see corpus win_command
- reproducibility: medium (depends on target service up)
