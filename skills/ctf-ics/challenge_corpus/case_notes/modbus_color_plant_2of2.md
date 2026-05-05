# modbus_color_plant_2of2

## 1) Target lock
- source: OT-Security-Lab Color_Plant
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>

## 2) State gate
- gate: mixing state + drain cycle
- trigger: deterministic two-pass recipe

## 3) Action path
- cycle x2: fill RGB to target -> drain M->F -> verify IR7-10

## 4) Decode chain
- process completion may unlock final token/flag path

## 5) Decoy handling
- accept only values matching target state constraints

## 6) Final evidence
- command/script: `solve-color-plant2-2.py`
- reproducibility: repeatable under one persistent TCP session
