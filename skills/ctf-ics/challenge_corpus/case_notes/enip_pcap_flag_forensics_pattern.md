# enip_pcap_flag_forensics_pattern

## 1) Target lock
- source: ctf-ics tools
- protocol: ENIP/CIP over PCAP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818/2222 (+ all-ports fallback)
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: packet-order/state in capture
- trigger value: n/a
- pre-state: valid pcap file
- post-state: extracted candidate occurrences

## 3) Action path
- read ranges: all ENIP/CIP packets in pcap
- write sequence: none
- verification signals: packet count + matched occurrences

## 4) Decode chain
- source artifacts: packet payload bytes
- chain order: raw -> denull -> utf16le -> regex
- successful variant: all-ports scan for non-standard transport

## 5) Decoy handling
- decoy observed: benign text payloads
- rejection reason: strict wrapper regex + packet provenance

## 6) Final evidence
- flag/result: pcap-derived candidates
- command used: see corpus win_command
- reproducibility: high
