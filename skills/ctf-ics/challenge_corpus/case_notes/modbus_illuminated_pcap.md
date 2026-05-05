# modbus_illuminated_pcap

## 1) Target lock
- source: OT-Security-Lab Illuminated
- protocol: Modbus + PCAP forensics
- target ip/host: <TARGET_IP_OR_PATH>

## 2) State gate
- gate: packet-level event ordering

## 3) Action path
- parse capture -> isolate suspicious frames -> decode payload

## 4) Decode chain
- typical chain: hex/base64 with endian validation

## 5) Decoy handling
- ignore unrelated chatter packets

## 6) Final evidence
- command: `modbus_flag_extract_pcap.py capture.pcap --json`
