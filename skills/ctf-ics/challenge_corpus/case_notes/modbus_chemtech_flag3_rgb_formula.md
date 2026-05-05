# modbus_chemtech_flag3_rgb_formula

## 1) Target lock
- source: RTAF ICS-ChemTech-PlantC7
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 502
- unit: 1

## 2) State gate
- gate: Coil 99 = TRUE
- writes: HR32-35 + HR50-52 calibration path
- verify: expected IR checkpoints and clue registers

## 3) Action path
- deterministic flow: trigger -> write -> verify -> decode

## 4) Decode chain
- HR300: ascii-hex -> clue
- HR400: base64 -> hex -> final flag
- optional follow-up by `>>HRxxx` clue

## 5) Decoy handling
- reject `FAKE/not_the_flag` hits even if regex matches

## 6) Final evidence
- extraction command: see corpus `win_command`
- reproducibility: repeatable
