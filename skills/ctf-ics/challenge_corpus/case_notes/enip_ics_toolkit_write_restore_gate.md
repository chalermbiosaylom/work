# enip_ics_toolkit_write_restore_gate

## 1) Target lock
- source: OT-Security-Lab toolkit
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: write-trigger tag/path
- trigger value: `1337`
- pre-state: attempted original read
- post-state: write status + optional restore

## 3) Action path
- read ranges: target tag pre-read
- write sequence: trigger write -> restore
- verification signals: injector status/restore_status

## 4) Decode chain
- source artifacts: post-write readable values from follow-up sweep
- chain order: state trigger first then decode pass
- successful variant: explicit type + restore mode

## 5) Decoy handling
- decoy observed: successful write with no meaningful unlock
- rejection reason: require downstream evidence in read phase

## 6) Final evidence
- flag/result: state-unlocked candidate artifacts
- command used: see corpus win_command
- reproducibility: medium
