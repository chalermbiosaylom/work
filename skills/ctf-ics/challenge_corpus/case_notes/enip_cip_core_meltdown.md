# enip_cip_core_meltdown

## 1) Target lock
- source: coc-2026
- protocol: EtherNet/IP CIP
- target ip/host: <TARGET_IP_OR_PATH>
- port: 44818

## 2) State gate
- gate: CIP object/tag visibility by state

## 3) Action path
- identity -> tag/object sweep -> selective write trigger (if needed)

## 4) Decode chain
- UTF-16/null-byte cleanup + base64/hex fallback

## 5) Decoy handling
- treat constant UNKNOWN outputs as pivot signal

## 6) Final evidence
- command: `tiger_enip_exploit.py --hunt --json`
