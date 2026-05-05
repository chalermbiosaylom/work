# modbus_evil_plant

## 1) Target lock
- source: OT-Security-Lab Evil_Plant
- protocol: Modbus TCP
- target ip/host: <TARGET_IP_OR_PATH>

## 2) State gate
- gate: logic-bomb style writes expected
- trigger: controlled coil/register toggle

## 3) Action path
- read baseline -> minimal write trigger -> re-read for state delta

## 4) Decode chain
- unknown until trigger succeeds; inspect solve notes

## 5) Decoy handling
- validate with before/after state changes, not single string hit

## 6) Final evidence
- reference: `Evil_Plant/solve.md`
