---
description: PCAP/network forensics flag hunting workflow
---

# Forensics PCAP Hunt Workflow

For `.pcap` or `.pcapng` files

## Step 1: Quick Triage
// turbo
```bash
file <file.pcap>
capinfos <file.pcap>
```

## Step 2: Invoke Forensics Skill

**Action:** Invoke `@ctf-forensics` with PCAP path.

## Step 3: Protocol Detection

Skill will use sharkmcp/wiremcp to:
1. Identify protocols (HTTP/DNS/Modbus/ENIP/S7/MQTT)
2. Extract plaintext credentials
3. Hunt flag patterns in payloads

## Step 4: ICS Traffic Pivot

If industrial protocols detected (Modbus/ENIP/S7/DNP3):
- Invoke `@ctf-ics` for specialized parsing
- Extract register/tag values
- Decode hex/base64 payloads

## Step 5: Advanced Extraction

If standard hunt fails:
// turbo
```bash
# Hex payload decode
tshark -r <file.pcap> -T fields -e tcp.payload | tr -d ':\n' | xxd -r -p | grep -iE 'coc2026\{|flag\{|rtaf\{|f1a9\{|fl4g\{|\{[a-f0-9]{32}\}|\b[a-f0-9]{32}\b'

# TLS decrypt (if keylog provided)
tshark -r <file.pcap> -o tls.keylog_file:<keylog> -Y http -T fields -e http.file_data
```

---

**Tools:** sharkmcp/wiremcp (primary), ctf-ics (OT traffic)
