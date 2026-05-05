# modbus_color_plant_1of2

## 1) Target lock
- source: OT-Security-Lab Color_Plant
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>
- port: challenge-defined (typically 4502/502)

## 2) State gate
- gate: process valves/coils
- trigger: controlled fill sequence

## 3) Action path
- write flow regs -> open specific coil -> poll IR feedback -> close valve

## 4) Decode chain
- mostly process-state challenge (minimal decode)

## 5) Decoy handling
- verify result via sensor state, not text-only hints

## 6) Final evidence
- command/script: `solve-color-plant1-2.py`
- reproducibility: repeatable with stable session
