# enip_tiger_identity_probe

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none
- trigger value: n/a
- pre-state: target reachable
- post-state: identity summary returned

## 3) Action path
- read ranges: identity info (product/revision/serial)
- write sequence: none
- verification signals: JSON identity block

## 4) Decode chain
- source artifacts: identity strings
- chain order: plain text -> optional regex/hex scan
- successful variant: identity mode first before heavy hunt

## 5) Decoy handling
- decoy observed: generic vendor strings
- rejection reason: accept only regex-valid wrappers

## 6) Final evidence
- flag/result: identity clues / candidate flag text
- command used: see corpus win_command
- reproducibility: medium
