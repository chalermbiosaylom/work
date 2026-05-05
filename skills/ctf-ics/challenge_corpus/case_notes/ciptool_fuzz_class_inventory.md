# ciptool_fuzz_class_inventory

## 1) Target lock
- source: OT-Security-Lab cipTool
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none (enumeration)
- trigger value: n/a
- pre-state: CIP connection established
- post-state: supported class list printed

## 3) Action path
- read ranges: class inventory responses
- write sequence: none
- verification signals: class entries and bytes dump

## 4) Decode chain
- source artifacts: class map and raw bytes
- chain order: raw -> printable scan
- successful variant: `fuzzing.cipListClasses()`

## 5) Decoy handling
- decoy observed: unknown class labels
- rejection reason: not treated as flags without wrapper evidence

## 6) Final evidence
- flag/result: class-surface map for follow-on attacks
- command used: see corpus win_command
- reproducibility: medium
