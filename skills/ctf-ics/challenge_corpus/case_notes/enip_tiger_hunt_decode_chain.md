# enip_tiger_hunt_decode_chain

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: may require tag/state precondition
- trigger value: challenge-specific
- pre-state: identity/discovery done
- post-state: hunt output with candidate artifacts

## 3) Action path
- read ranges: tag/object hunt paths
- write sequence: optional follow-up outside hunt
- verification signals: JSON candidates + source path

## 4) Decode chain
- source artifacts: tag names/values
- chain order: denull -> utf16 -> hex/base64 fallback
- successful variant: hunt mode with decode pivots

## 5) Decoy handling
- decoy observed: checksum-like hex tokens
- rejection reason: validate with context/provenance

## 6) Final evidence
- flag/result: hunt candidates + final validated flag
- command used: see corpus win_command
- reproducibility: medium
