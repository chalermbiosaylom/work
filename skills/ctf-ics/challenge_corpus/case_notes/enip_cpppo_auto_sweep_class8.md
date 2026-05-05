# enip_cpppo_auto_sweep_class8

## 1) Target lock
- source: ctf-ics tools
- protocol: EtherNet/IP (CIP)
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818
- unit (if Modbus): n/a

## 2) State gate
- gate type/address: none (read sweep)
- trigger value: n/a
- pre-state: ENIP session available
- post-state: class8 path map collected

## 3) Action path
- read ranges: `@8/<inst>/<attr>` sweep
- write sequence: none
- verification signals: tags_scanned count and payload outputs

## 4) Decode chain
- source artifacts: sweep responses
- chain order: bytes -> utf16/denull -> regex -> hex fallback
- successful variant: class8 auto-sweep with attr range

## 5) Decoy handling
- decoy observed: random tokens / non-flag text
- rejection reason: keep only strict flag regex hits

## 6) Final evidence
- flag/result: candidate tags/flags from sweep
- command used: see corpus win_command
- reproducibility: high
