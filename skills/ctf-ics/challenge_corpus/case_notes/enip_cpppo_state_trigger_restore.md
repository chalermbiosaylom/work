# enip_cpppo_state_trigger_restore

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: CIP tag/path write gate (`@8/1/5`)
- trigger value: `1337`
- pre-state: original value read attempt
- post-state: write + optional restore_status

## 3) Action path
- read ranges: target tag pre-flight read
- write sequence: write trigger -> optional restore
- verification signals: injector JSON status + restore status

## 4) Decode chain
- source artifacts: post-trigger readable fields
- chain order: trigger state first, then run read-hunt chain
- successful variant: write with explicit type

## 5) Decoy handling
- decoy observed: write success without meaningful state change
- rejection reason: require post-trigger evidence from read phase

## 6) Final evidence
- flag/result: state-unlocked candidate artifacts
- command used: see corpus win_command
- reproducibility: medium
