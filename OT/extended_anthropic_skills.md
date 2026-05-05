# 🔬 Extended ICS/OT Security Reference (Anthropic Skills Integration)

**Purpose:** รวม references และ techniques จาก 28 Skills ใน Anthropic-Cybersecurity-Skills (หมวด OT/ICS Security) เข้ากับ ctf-ics skill โดยใช้ skill เดิมเป็นหลัก

**CTF Context Focus:** เน้น exploitation, flag hunting, และ vulnerability detection มากกว่า defense/monitoring ใน production

---

## กลุ่ม 1: Modbus & SCADA Protocols (9 Skills)

### 1.1 Modbus Protocol Anomaly Detection
**Skill:** `detecting-modbus-protocol-anomalies`
**CTF Application:** ตรวจจับความผิดปกติใน PCAP หรือ live traffic เพื่อหา malicious packets ที่มี flag

**Tools & References:**
- **PCAP Analysis:** `tshark -Y "modbus"` filter + anomaly detection scripts
- **Pattern Matching:** หา function codes ที่ผิดปกติ (เช่น FC16 ใน environment ที่ควรมีแต่ FC03/FC04)
- **Baseline Comparison:** เปรียบเทียบ normal traffic vs attack traffic

**Mapping to ctf-ics tools:**
- `tools/pcap/modbus_flag_extract_pcap.py` - ดึง flag จาก Modbus PCAP
- `tools/pcap/modbus_sniffer.py` - Live Modbus traffic monitoring

### 1.2 Modbus Command Injection Attacks
**Skill:** `detecting-modbus-command-injection-attacks`
**CTF Application:** ตรวจจับ command injection ใน Modbus parameters

**Detection Techniques:**
- **Register Value Analysis:** หา patterns ที่ดูเหมือน shell commands หรือ SQL injection
- **Coil State Sequences:** ตรวจสอบ coil sequences ที่ผิดปกติ (เช่น rapid toggling)
- **Function Code Abuse:** ใช้ FC05/FC06/FC16 ในลักษณะที่น่าสงสัย

**Mapping to ctf-ics tools:**
- `tools/modbus/modbus_write_find_flags.py` - Write operations พร้อม detection
- Pattern C: Noisy PCAP + Malicious FC16 Extraction

### 1.3 SCADA Modbus Traffic Anomaly Monitoring
**Skill:** `monitoring-scada-modbus-traffic-anomalies`
**CTF Application:** Monitor live SCADA traffic เพื่อหา flag หรือ suspicious packets

**Mapping to ctf-ics tools:**
- `scapy_scripts/modbus_sniffer.py` - Live Modbus sniffer
- `tools/pcap/modbus_flag_extract_pcap.py` - PCAP analysis

### 1.4 Modbus TCP Network Encryption
**Skill:** `securing-modbus-tcp-with-network-encryption`
**CTF Application:** เมื่อ challenge ใช้ encrypted Modbus (TLS/DTLS) หรือ obfuscated traffic

**References:**
- OpenSSL-based decryption workflows
- Custom XOR/Base64/Hex decode chains (มีอยู่ใน ctf-ics decode pipeline)

### 1.5 DNP3 Protocol Attack Detection
**Skill:** `detecting-dnp3-protocol-attacks`
**CTF Application:** DNP3 flag hunting และ vulnerability detection

**Mapping to ctf-ics tools:**
- `tools/pcap/dnp3_sniffer.py` - DNP3 flag extraction
- SCADA-OT-CheatSheet fallback: `dnp3_exploitation/`

### 1.6 S7comm Protocol Security Analysis
**Skill:** `performing-s7comm-protocol-security-analysis`
**CTF Application:** S7comm flag hunting และ Siemens PLC exploitation

**Mapping to ctf-ics tools:**
- MCP Tools: `s7_connect`, `s7_list_blocks`, `s7_db_read`, `s7_db_write`
- SCADA-OT-CheatSheet fallback: `s7comm_security_framework/`

### 1.7 EtherNet/IP CIP Protocol Anomaly Detection
**Skill:** `detecting-ethernet-ip-cip-protocol-anomalies`
**CTF Application:** ENIP/CIP anomaly detection ใน PCAP หรือ live traffic

**Mapping to ctf-ics tools:**
- `tools/enip/enip_list_identity.py` - Device fingerprint
- `tools/enip/enip_cpppo_read_find_flags.py` - Tag sweep
- Pattern: ENIP CIP Get_Attribute_Single

### 1.8 PROFINET Protocol Misuse Detection
**Skill:** `detecting-profinet-protocol-misuse`
**CTF Application:** PROFINET-based challenges (rare ใน CTF แต่มีใน advanced ICS CTFs)

**Mapping to ctf-ics tools:**
- PCAP analysis workflows (ใช้ `tools/pcap/` เป็น base)
- SCADA-OT-CheatSheet fallback

### 1.9 OPC-UA Security Violation Detection
**Skill:** `detecting-opc-ua-security-violations`
**CTF Application:** OPC-UA security bypass, certificate manipulation, encryption bypass

**Mapping to ctf-ics tools:**
- MCP Tools: `opcua_enumerate_endpoints`, `opcua_connect`, `opcua_find_writable`
- `opcua_generate_cert` - Self-signed cert generation

---

## กลุ่ม 2: Architecture & มาตรฐาน (IEC 62443 / Purdue Model) (5 Skills)

### 2.1 Purdue Model Network Segmentation
**Skill:** `implementing-purdue-model-network-segmentation`
**CTF Application:** เมื่อ challenge มี multi-tier network architecture (DMZ, Purdue levels)

**Mapping to ctf-ics tools:**
- `/fast-port-scan` workflow - Fast port discovery
- `ctf-os-exploit` skill - Pivoting/tunneling techniques

### 2.2 IEC 62443-3-3 Security Controls
**Skill:** `implementing-iec-62443-3-3-security-controls`
**CTF Application:** Bypass IEC 62443 security controls ใน ICS challenges

**Control Bypass Techniques:**
- Authentication Bypass, Authorization Bypass, Integrity Protection Bypass

### 2.3 Remote Access to OT Environment Security
**Skill:** `securing-remote-access-to-ot-environment`
**CTF Application:** Remote access exploitation (VPN, RDP, SSH) ใน OT environment

**Mapping to ctf-ics tools:**
- `ctf-os-exploit` skill - Remote access exploitation
- Tunnel detection: `ip a | grep -E 'ligolo|tun|tap'`

### 2.4 Industrial DMZ Implementation
**Skill:** `implementing-industrial-dmz-for-ot-security`
**CTF Application:** DMZ bypass, IT/OT boundary exploitation

**Mapping to ctf-ics tools:**
- `ctf-os-exploit` skill - Lateral movement, pivoting

### 2.5 Cyber Risk Assessment for Industrial Systems
**Skill:** `performing-cyber-risk-assessment-for-industrial-systems`
**CTF Application:** Risk-based target prioritization ใน multi-host ICS CTFs

**Mapping to ctf-ics tools:**
- Port scan + service enumeration → protocol-specific exploitation

---

## กลุ่ม 3: Monitoring & Detection (ICS/OT) (6 Skills)

### 3.1 ICS Anomaly Detection
**Skill:** `detecting-anomalies-in-industrial-control-systems`
**CTF Application:** Detect anomalous behavior ใน ICS systems เพื่อหา hidden flags หรือ backdoors

**Mapping to ctf-ics tools:**
- `tools/modbus/modbus_read_find_flags.py` - Register/coil scanning
- Pattern D: Cross-Protocol Truth Validation

### 3.2 Unauthorized PLC Program Change Detection
**Skill:** `detecting-unauthorized-plc-program-changes`
**CTF Application:** Detect modified PLC logic/programs ที่มี flag หรือ backdoor

**Mapping to ctf-ics tools:**
- S7comm: `s7_list_blocks`, `s7_db_read`
- ENIP: CIP Assembly instance scanning

### 3.3 MITM Attacks on ICS Networks
**Skill:** `detecting-man-in-the-middle-attacks-on-ics-networks`
**CTF Application:** MITM detection และ MITM-based flag interception

**Mapping to ctf-ics tools:**
- `mitm_scripts/arp_spoof.py`, `scapy_scripts/modbus_inject.py`, `scapy_scripts/modbus_replay.py`

### 3.4 False Data Injection Attacks in ICS
**Skill:** `detecting-false-data-injection-attacks-in-ics`
**CTF Application:** Detect false data injection และ exploit falsified sensor values

**Mapping to ctf-ics tools:**
- Pattern D: Cross-Protocol Truth Validation
- Pattern F: Process Stabilization with Physics Feedback Loop

### 3.5 BACnet Traffic Analysis for Building Automation
**Skill:** `analyzing-bacnet-traffic-for-building-automation-security`
**CTF Application:** BACnet flag hunting ใน building automation challenges

**Mapping to ctf-ics tools:**
- MCP Tools: `bacnet_connect`, `bacnet_list_objects`, `bacnet_find_writable`

---

## กลุ่ม 4: Defense & Management (Historian / Asset / Patch) (4 Skills)

### 4.1 Industrial Data Historian Security
**Skill:** `securing-industrial-data-historian`
**CTF Application:** Exploit data historian systems (SQL injection, authentication bypass)

**Mapping to ctf-ics tools:**
- `ctf-web` skill - SQL injection, API abuse

### 4.2 OT Patch Management
**Skill:** `implementing-patch-management-for-ot-systems`
**CTF Application:** Exploit unpatched OT systems, version-based attacks

**Mapping to ctf-ics tools:**
- `ctf-pwn` skill - Binary exploitation
- `ctf-web` skill - CVE exploitation

### 4.3 OT Asset Inventory Discovery
**Skill:** `performing-ot-asset-inventory-discovery`
**CTF Application:** Comprehensive asset discovery ใน multi-host ICS CTFs

**Mapping to ctf-ics tools:**
- `/fast-port-scan` workflow - Fast port discovery
- Protocol-specific fingerprinting

### 4.4 Secure Remote Engineering Workstation Controls
**Skill:** `implementing-secure-remote-engineering-workstation-controls`
**CTF Application:** Exploit engineering workstations (PLC programming software, HMI design tools)

**Mapping to ctf-ics tools:**
- `ctf-reverse` skill, `ctf-forensics` skill, `ctf-pwn` skill

---

## กลุ่ม 5: Incident Response & Forensics (5 Skills)

### 5.1 Safe OT Vulnerability Scanning
**Skill:** `performing-ot-vulnerability-scanning-safely`
**CTF Application:** Safe vulnerability scanning บน ICS targets (avoid crashing PLCs)

**Mapping to ctf-ics tools:**
- Anti-Crash Rules, Read-first discipline, `nc -zvw 10` reachability check

### 5.2 SCADA System Threat Modeling
**Skill:** `performing-scada-system-threat-modeling`
**CTF Application:** Threat modeling-based attack path identification

**Mapping to ctf-ics tools:**
- Protocol-specific exploitation paths, Cross-protocol attack vectors (Pattern D)

### 5.3 OT Incident Response Triage
**Skill:** `performing-ot-incident-response-triage`
**CTF Application:** Triage-based exploitation prioritization

**Mapping to ctf-ics tools:**
- Timebox + Pivot Matrix, Execution Priority rules

### 5.4 HMI Exploitation Artifact Analysis
**Skill:** `analyzing-hmi-exploitation-artifacts`
**CTF Application:** Analyze HMI exploitation artifacts (screens, scripts, logs)

**Mapping to ctf-ics tools:**
- `ctf-forensics` skill, `ctf-web` skill, `ctf-reverse` skill

### 5.5 ICS Forensics on PLC Memory Dumps
**Skill:** `performing-ics-forensics-on-plc-memory-dumps`
**CTF Application:** Forensic analysis บน PLC memory dumps

**Mapping to ctf-ics tools:**
- `ctf-forensics` skill, `mcp1_auto_memory_analysis`, `ctf-reverse` skill

---

## Summary: Skill Mapping Matrix

| Anthropic Skill | Primary ctf-ics Tool | Secondary Skills | CTF Use Case |
|----------------|---------------------|------------------|--------------|
| detecting-modbus-protocol-anomalies | `tools/pcap/modbus_flag_extract_pcap.py` | `ctf-forensics` | PCAP flag hunting |
| detecting-modbus-command-injection | `tools/modbus/modbus_write_find_flags.py` | Pattern C | Command injection |
| monitoring-scada-modbus-traffic | `scapy_scripts/modbus_sniffer.py` | `tools/pcap/` | Live traffic monitoring |
| securing-modbus-tcp-encryption | Decode pipeline (Base64/Hex/XOR) | `ctf-crypto` | Encrypted traffic |
| detecting-dnp3-protocol-attacks | `tools/pcap/dnp3_sniffer.py` | `ctf-forensics` | DNP3 flag hunting |
| performing-s7comm-security-analysis | MCP S7comm tools | `ctf-reverse` | S7comm exploitation |
| detecting-ethernet-ip-cip-anomalies | `tools/enip/enip_cpppo_read_find_flags.py` | ENIP CIP pattern | ENIP anomaly detection |
| detecting-profinet-protocol-misuse | PCAP workflows | SCADA-OT-CheatSheet | PROFINET analysis |
| detecting-opc-ua-security-violations | MCP OPC-UA tools | OPC-UA pattern | OPC-UA security bypass |
| implementing-purdue-model-segmentation | `/fast-port-scan` workflow | `ctf-os-exploit` | Network segmentation |
| implementing-iec-62443-3-3-controls | `ctf-os-exploit` | `ctf-web` | IEC 62443 bypass |
| securing-remote-access-ot | `ctf-os-exploit` | Tunnel detection | Remote access |
| implementing-industrial-dmz | `ctf-os-exploit` | `ctf-ics` | DMZ bypass |
| performing-cyber-risk-assessment | Port scan + enumeration | All ICS skills | Target prioritization |
| detecting-ics-anomalies | `tools/modbus/modbus_read_find_flags.py` | Pattern D | Anomaly detection |
| detecting-unauthorized-plc-changes | MCP S7comm/ENIP tools | `ctf-reverse` | PLC program analysis |
| detecting-mitm-ics-networks | `mitm_scripts/arp_spoof.py` | Scapy scripts | MITM attacks |
| detecting-false-data-injection | Pattern D | Pattern F | False data exploitation |
| analyzing-bacnet-traffic-building-automation | MCP BACnet tools | SCADA-OT-CheatSheet | BACnet flag hunting |
| securing-industrial-data-historian | `ctf-web` | `ctf-forensics` | Historian exploitation |
| implementing-ot-patch-management | `ctf-pwn` | `ctf-web` | Unpatched system exploitation |
| performing-ot-asset-inventory | `/fast-port-scan` workflow | Protocol fingerprinting | Asset discovery |
| implementing-secure-remote-eng-workstation | `ctf-reverse` | `ctf-forensics` | Engineering workstation |
| performing-ot-vulnerability-scanning-safely | Anti-Crash Rules | Read-first discipline | Safe scanning |
| performing-scada-threat-modeling | Protocol-specific paths | Cross-protocol patterns | Attack path identification |
| performing-ot-incident-response-triage | Timebox + Pivot Matrix | Execution Priority | Triage-based prioritization |
| analyzing-hmi-exploitation-artifacts | `ctf-forensics` | `ctf-web` | HMI artifact analysis |
| performing-ics-forensics-plc-memory | `ctf-forensics` | `mcp1_auto_memory_analysis` | PLC memory forensics |

---

## Usage Guidelines

**When to use this reference:**
- Challenge มี keywords: "anomaly detection", "MITM", "forensics", "Purdue model", "IEC 62443", "threat modeling"
- Standard protocol tools ไม่พบ flag และต้องการ alternative approaches
- Multi-protocol challenges ที่ต้องการ cross-protocol analysis

**How to use:**
1. Identify relevant skill(s) จาก challenge description
2. Map to primary ctf-ics tool จาก matrix ข้างต้น
3. Use secondary skills ถ้า primary tool ไม่เพียงพอ
4. Maintain evidence-only protocol ตาม ctf-ics rules

**Integration with existing ctf-ics workflow:**
- This reference is **supplementary** - use existing ctf-ics workflow first
- Apply these extended techniques only when standard approaches fail
