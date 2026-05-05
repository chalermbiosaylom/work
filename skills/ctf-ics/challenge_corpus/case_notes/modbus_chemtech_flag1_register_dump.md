# modbus_chemtech_flag1_register_dump

## 1) Target lock
- source: coc-2026
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit: 1

## 2) State gate
- gate: none required
- trigger value: n/a
- pre/post-state: read-only extraction

## 3) Action path
- read ranges: HR 0-350 (chunked <=125)
- write sequence: none
- verification: repeat read with BE/LE + swap variants

## 4) Decode chain
- source: HR encoded blob
- chain: ascii -> base64 -> regex
- successful variant: BE ascii stream

## 5) Decoy handling
- decoy observed: `CTF{FAKE_this_is_not_the_flag}`
- rejection reason: explicit FAKE marker

## 6) Final evidence
- extraction command: see corpus `win_command`
- reproducibility: repeatable
