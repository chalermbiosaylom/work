# modbus_chemtech_flag2_maintenance_override

## 1) Target lock
- source: RTAF ICS-ChemTech-PlantC7
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit: 1

## 2) State gate
- gate: Coil 99 (maintenance)
- trigger: write TRUE
- post-state: hidden region becomes readable

## 3) Action path
- read baseline -> trigger coil 99 -> re-read hidden ranges
- verify: coil 99 readback = true

## 4) Decode chain
- chain: ascii/base64 scan on unlocked HR area

## 5) Decoy handling
- reject fake wrapper strings by provenance + marker checks

## 6) Final evidence
- extraction command: see corpus `win_command`
- reproducibility: repeatable with same unit/session
