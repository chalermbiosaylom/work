# modbus_safe_write_fuzzer_restore

## 1) Target lock
- source: ctf-ics tools
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit (if Modbus): 1

## 2) State gate
- gate type/address: coil/register write-trigger space
- trigger value: toggled coils + selected register values
- pre-state: baseline values read
- post-state: original values restored after fuzz

## 3) Action path
- read ranges: coils and holding regs in configured ranges
- write sequence: fuzz value(s) -> restore baseline
- verification signals: fuzz_stats + discovered_string

## 4) Decode chain
- source artifacts: register ASCII pairs during sweep
- chain order: read value -> ascii decode -> aggregate tokens
- successful variant: limited range for speed and safety

## 5) Decoy handling
- decoy observed: non-context strings during fuzz
- rejection reason: only trust reproducible values with provenance

## 6) Final evidence
- flag/result: potential recovered strings and trigger map
- command used: see corpus win_command
- reproducibility: medium-high
