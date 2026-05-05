# modbus_holding_inspector_chunked

## 1) Target lock
- source: ctf-ics tools
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit (if Modbus): 1

## 2) State gate
- gate type/address: none (read-only)
- trigger value: n/a
- pre-state: connected
- post-state: chunked register dump + decode views

## 3) Action path
- read ranges: HR chunked (<=125 each request)
- write sequence: none
- verification signals: raw regs + string candidates + float views

## 4) Decode chain
- source artifacts: holding registers
- chain order: ascii be/le -> token extraction -> float endian variants
- successful variant: large count with chunked loop

## 5) Decoy handling
- decoy observed: printable noise tokens
- rejection reason: validate with wrapper/context and repeated evidence

## 6) Final evidence
- flag/result: extracted strings/values for follow-up
- command used: see corpus win_command
- reproducibility: high
