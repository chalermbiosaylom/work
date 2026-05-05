---
name: ctf-ics-ultimate
description: >
  Ultimate ICS/SCADA analysis and exploitation toolset for RTAF Cyber Operation Contest 2026.
  Covers Modbus, S7Comm, IEC 104, DNP3, MQTT, and MITM attacks.
  Specialized for Virtual World Attack mode and Flag Hunting (coc2026{}).
  Trigger: When analyzing industrial protocols, PLC, SCADA, or PCAP with OT traffic.
license: MIT
metadata:
  author: ctf-arsenal
  version: "3.1-merged"
  category: ics-scada
---

# 🏭 Ultimate ICS/SCADA Exploitation Skill (RTAF COC 2026)

## When to Use

Load this skill when:

- Analyzing ICS/SCADA traffic or OT PCAPs
- Doing OT recon (Modbus/S7/IEC104/DNP3/BACnet/OPC UA/ENIP/MQTT)
- Performing MITM (Ettercap) for OT protocol observation/injection
- Flag hunting in PLC registers/coils, HMI telemetry, or captured traffic (likely `coc2026{}`)

## ⚡ Fast Execution & Orchestration Rules
เพื่อให้การแข่ง CTF มีประสิทธิภาพสูงสุด ให้ปฏิบัติดังนี้:

1.  **Zero-Yap Policy:** ห้ามอธิบายทฤษฎีการทำงานของ Protocol ยืดยาว ให้โฟกัสที่การวิเคราะห์และเสนอคำสั่งทันที
2.  **Execute First:** เมื่อวิเคราะห์แผนออกแล้ว ให้เรียกใช้ MCP Tools (`ctf-solve` หรือ `hexstrike-ai-community-edition`) เพื่อรันสแกนหรือรันสคริปต์ทันที
3.  **Chain Commands:** พยายามรวมคำสั่ง Bash ไว้ในบรรทัดเดียวเพื่อลด Overhead
4.  **Automatic Decoding:** เมื่อได้ค่าจาก PLC (Modbus/S7) ให้ทำการแปลง Decimal -> Hex -> ASCII และเช็ค Endianness (Byte Swap) เพื่อหา Flag `coc2026{...}` โดยอัตโนมัติ
5.  **Tool Priority:** เลือกใช้ CLI Tools (nmap, tshark) + Python client (pymodbus) ก่อน หากต้องการความซับซ้อนค่อยใช้ Scapy

## Workflow / Methodology (ICS CTF)

| Phase | Goal | What to Collect | Quick Commands (Safe / Read-only) |
|---|---|---|---|
| 1) Recon (IT + OT) | Find entry points and OT surfaces | Target list, port map, protocol candidates | `nmap -sS -p- <target>` · `nmap -Pn -sS -sV -p 502,102,44818,2222,4840,20000,2404,47808,1883 <ot-target>` |
| 2) Pivot readiness | Confirm path into OT subnet | Routes, dual-homed hosts, reachable OT IPs | Identify dual-homed host(s) · Validate routes · Use allowed tunnels/proxies per rules |
| 3) PCAP-first evidence | Capture before you touch anything | PCAP + timestamps + interface name | `tshark -i <iface> -f "tcp port 502 or tcp port 102 or tcp port 44818 or udp port 2222 or tcp port 4840 or tcp port 20000 or tcp port 2404 or udp port 47808 or tcp port 1883" -w ot_capture.pcap` |
| 4) Quick triage | Spot protocol + intent quickly | Top talkers, bursts, write ops | `tshark -r ot_capture.pcap -q -z io,stat,1` · `tshark -r ot_capture.pcap -Y "modbus || s7comm || bacnet || opcua || mqtt" | head` |
| 5) Protocol mapping | Map tags/registers/nodes/DB/IOA | Control-surface table | Enumerate read-only first; extract identifiers from traffic |
| 6) Flag hunt | Find objective evidence | Strings, logs, PCAP artifacts | Extract ASCII quickly; search `coc2026{` and variations |

## 🔍 Initial Recon (Automatic Discovery)

### ICS Port & Protocol Scanning
หากพบ IP เป้าหมายในระบบ OT ให้ใช้คำสั่งนี้เพื่อระบุประเภทของ PLC และ Protocol:

```bash
# สแกนทุกพอร์ตที่เป็นมาตรฐานอุตสาหกรรมในคำสั่งเดียว
nmap -Pn -p 102,502,1883,2404,44818,4840,20000 --script modbus-discover,s7-info,enip-info,bacnet-info <target_ip>
```

| Protocol | Port | Common Tool | Use Case |
|----------|------|-------------|----------|
| **Modbus/TCP** | 502 | `pymodbus` | PLCs, SCADA systems |
| **S7comm** | 102 | `s7scan`, `snap7` | Siemens PLCs |
| **MQTT** | 1883 | `mosquitto_sub` | IoT Messaging, Telemetry |
| **IEC 104** | 2404 | `tshark`, `scapy` | Power grid control |
| **DNP3** | 20000 | `dnp3_sniffer` | Utility SCADA |
| **EtherNet/IP** | 44818 | `nmap` | Rockwell/Allen-Bradley |

## Active Enumeration (Nmap & Metasploit) — RoE-Safe Recon

This section focuses on active fingerprinting and service discovery only. Avoid actions that look like `dos`, `flood`, `bruteforce`, `write`, or `command` unless the challenge explicitly allows it.

### Nmap Baselines + NSE (ICS)

| Goal | Command |
|---|---|
| Fast OT port map | `nmap -Pn -sS -sV -p 502,102,44818,2222,4840,20000,2404,47808,1883 <target>` |
| Modbus identify (read-only) | `nmap -Pn -sV -p 502 --script modbus-discover <target>` |
| Siemens S7 identify (read-only) | `nmap -Pn -sV -p 102 --script s7-info <target>` |
| EtherNet/IP identify (read-only) | `nmap -Pn -sV -p 44818 --script enip-info <target>` |
| BACnet identify (read-only) | `nmap -Pn -sV -sU -p 47808 --script bacnet-info <target>` |
| Multi-subnet sweep (ports only) | `nmap -Pn -sS -p 102,502,44818,4840,47808,2222,20000,2404,1883 --open 192.168.10.0/24 192.168.20.0/24 -oA active_scan` |

### Metasploit (discovery only)

| Task | Command / Module |
|---|---|
| Find safe ICS recon modules | In `msfconsole`: `search type:auxiliary name:modbus` · `search type:auxiliary name:s7` · `search type:auxiliary name:enip` · `search type:auxiliary name:bacnet` |
| Modbus fingerprint | `auxiliary/scanner/scada/modbusdetect` |
| Modbus banner / identify | `auxiliary/scanner/scada/modbus_banner_grabbing` |
| Modbus unit-id discovery | `auxiliary/scanner/scada/modbus_findunitid` |
| BACnet L3 discovery | `auxiliary/scanner/scada/bacnet_l3` |

## 🛠️ Prerequisites & Setup

### Essential Setup (Enable MITM)
```bash
# Enable IP forwarding (REQUIRED for MITM)
sudo sysctl -w net.ipv4.ip_forward=1

# Verify setting
sysctl net.ipv4.ip_forward  # Should return 1
```

### Check Network Interface
```bash
ip link show
# Common: eth0 (Wired), wlan0 (Wireless), tun0 (VPN/Ligolo)
```

## ⚔️ Ettercap MITM Attacks

### Basic ARP Spoofing
```bash
# Text mode (Recommended for CTF)
sudo ettercap -T -i eth0 -M arp:remote /target_ip/ /gateway_ip/
```

### Target Format

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `/192.168.1.100/` | Single target |
| IP range | `/192.168.1.1-30/` | Range of IPs |
| CIDR notation | `/192.168.1.0/24/` | Entire subnet |
| With ports | `/192.168.1.100/80,443/` | Specific ports |
| MAC + IP | `/00:11:22:33:44:55/192.168.1.100/` | MAC and IP |

### ARP Spoofing Modes

```bash
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/
sudo ettercap -T -i eth0 -M arp:oneway /target/ /gateway/
sudo ettercap -T -i eth0 -M arp
```

### Capture Traffic to PCAP
```bash
# Save intercepted traffic for analysis
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -w capture.pcap

# Analyze with Wireshark/Tshark
tshark -r capture.pcap -Y "modbus"
```

### Verify MITM Success

```bash
arp -a
```

### Restore Network After Attack

```bash
sudo arp -d <gateway_ip>
```

### Ettercap Filters (Modbus Blocking)
Filter file: [modbus_block_writes.etter](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/ettercap_filters/modbus_block_writes.etter)

```bash
sudo etterfilter modbus_block_writes.etter -o filter.ef
sudo ettercap -T -i eth0 -F filter.ef -M arp:remote /target/ /gateway/
```

### Ettercap Filter Syntax (Minimal)

```c
if (ip.proto == TCP && tcp.dst == 502) {
    msg("modbus tcp/502\n");
}
```

## Common ICS Protocols and Ports

| Protocol | Port | Use Case |
|---|---:|---|
| Modbus/TCP | 502/tcp | PLC register/coil reads/writes |
| S7comm (ISO-on-TCP) | 102/tcp | Siemens PLC comms |
| IEC 60870-5-104 | 2404/tcp | Power OT telemetry/control |
| DNP3 | 20000/tcp | Utility SCADA |
| BACnet/IP | 47808/udp | BMS/HVAC |
| OPC UA | 4840/tcp | Modern SCADA/IIoT |
| EtherNet/IP (ENIP/CIP) | 44818/tcp, 2222/udp | Allen-Bradley/Rockwell |
| MQTT | 1883/tcp, 8883/tcp | IIoT telemetry/commands |
| CoAP | 5683/udp | Constrained IIoT endpoints |
| WAGO iocheckd (mgmt) | 6626/tcp | PLC management surface |

## Quick Protocol Notes (PCAP-first)

### S7Comm (Siemens S7)

| Item | Value | Notes |
|---|---|---|
| Transport | TCP | Often ISO-on-TCP (COTP) carrying S7Comm |
| Default port | 102/tcp | Siemens PLC comms |
| Common lab params | rack=0, slot=0 | Common defaults in Snap7 tools |

```bash
tshark -r capture.pcap -Y "tcp.port==102 && s7comm" | head
```

### BACnet/IP

| Item | Value | Notes |
|---|---|---|
| Transport | UDP | BVLC + NPDU + APDU |
| Default port | 47808/udp | Common BMS/HVAC |
| High-signal ops | WriteProperty | Treat as control action |

```bash
tshark -r capture.pcap -Y "udp.port==47808 && bacnet" | head
```

### OPC UA

| Item | Value | Notes |
|---|---|---|
| Transport | TCP | `opc.tcp` |
| Default port | 4840/tcp | Endpoint like `opc.tcp://host:4840/...` |
| High-signal ops | Write / Call | Control surface |

```bash
tshark -r capture.pcap -Y "tcp.port==4840 && opcua" | head
```

### EtherNet/IP (ENIP/CIP)

| Item | Value | Notes |
|---|---|---|
| Explicit messaging | 44818/tcp | Session requests/responses |
| Implicit I/O messaging | 2222/udp | Cyclic real-time traffic |
| High-signal ops | Forward Open churn / writes | Often rare in stable OT |

```bash
tshark -r capture.pcap -Y "tcp.port==44818" | head
tshark -r capture.pcap -Y "udp.port==2222" | head
```

## 📡 Protocol Specifics & Exploitation

### 1. Modbus/TCP (Port 502)
**Function Codes:**
*   `0x03` Read Holding Registers (Low Risk)
*   `0x06` Write Single Register (High Risk) - **Use for Control**

**Fast CLI Polling (No-Code):**
```bash
# Read 20 Holding Registers
tshark -r capture.pcap -Y "mbtcp" -T fields -e modbus.data
```

**Pymodbus Read Holding Registers (Works without modpoll):**

Script: [modbus_read_holding_registers.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/pymodbus/modbus_read_holding_registers.py)

```bash
python3 modbus_read_holding_registers.py <target_ip> --unit 1 --addr 1 --count 20
```

**Scapy Sniffer / PCAP Flag Extractor:**

- Live: [modbus_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_sniffer.py)
- PCAP: [modbus_flag_extract_pcap.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_flag_extract_pcap.py)

```bash
python3 modbus_sniffer.py
python3 modbus_flag_extract_pcap.py challenge.pcap
```

### 2. Siemens S7comm (Port 102)
**Fast Recon:**
```bash
nmap -Pn -p 102 --script s7-info <target_ip>
```
**Flag Hunting in Data Blocks:**
```bash
tshark -r capture.pcap -Y "s7comm" -T fields -e s7comm.resp.data
```

### 3. MQTT (Port 1883)
**Real-time Sniffing:**
```bash
# Subscribe to ALL topics
mosquitto_sub -h <target_ip> -p 1883 -t "#" -v

# With Auth
mosquitto_sub -h <target_ip> -u "admin" -P "password" -t "#" -v
```

### 4. IEC 60870-5-104 (Port 2404)
**PCAP Analysis:**
```bash
tshark -r capture.pcap -Y "iec60870_104" -T fields -e iec60870_asdu.typeid
```

**Scapy Sniffer:**

Script: [iec104_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/iec104_sniffer.py)

```bash
python3 iec104_sniffer.py
```

### 5. DNP3 (Port 20000)
**PCAP Analysis:**
```bash
tshark -r capture.pcap -Y "dnp3" -T fields -e dnp3.al.func
```

**Scapy Sniffer:**

Script: [dnp3_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/dnp3_sniffer.py)

```bash
python3 dnp3_sniffer.py
```

## 🚩 Flag Hunting Strategy (coc2026{})

**The Endianness Trap:**
ข้อมูลใน ICS (16-bit registers) มักจะถูกเก็บแบบสลับไบต์ (Little Endian vs Big Endian)
*   หากถอดรหัสแล้วได้ข้อความแปลกๆ เช่น `oc2c02{...}`
*   **Action:** ทำการ Byte Swap ทันที

**Python Quick Decoder:**
```python
import struct
val = 28515 # Decimal from register
print(struct.pack('<H', val).decode('ascii')) # Try <H or >H
print(struct.pack('>H', val).decode('ascii'))
```

## Modbus/TCP vs Modbus RTU over TCP (CTF Trap)

| Feature | Modbus/TCP (502) | Modbus RTU over TCP (4000/8000) |
|---|---|---|
| Header | 7-byte MBAP | No MBAP |
| Unit ID | In MBAP | First byte payload |
| Checksum | TCP handles | CRC-16 at end |

## CODESYS / WAGO (Detection-Oriented)

Reference: [Claroty_CODESYS_CVE.md](file:///home/kali/Desktop/RTAF-CTF-2026/Intel/Claroty_CODESYS_CVE.md)

| Surface | Common indicator | Why it matters |
|---|---|---|
| WAGO management (iocheckd) | tcp/6626 | Often enabled by default; management surface |
| Engineering/HMI stations | New outbound to mgmt ports | Best lateral signal |
| Cloud-managed workflows | PLC ↔ cloud console | Pivot chains may move upward |

## Defensive Forensics (IDS/PCAP)

### Starter Suricata/Snort Templates

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"ICS MODBUS Write Single Coil"; flow:to_server,established; byte_test:1,=,0x05,7; classtype:attempted-admin; sid:4200005; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"ICS MODBUS Write Single Register"; flow:to_server,established; byte_test:1,=,0x06,7; classtype:attempted-admin; sid:4200006; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"ICS MODBUS Write Multiple Coils"; flow:to_server,established; byte_test:1,=,0x0F,7; classtype:attempted-admin; sid:4200015; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"ICS MODBUS Write Multiple Registers"; flow:to_server,established; byte_test:1,=,0x10,7; classtype:attempted-admin; sid:4200016; rev:1;)
```

### Quick PCAP Triage

```bash
tshark -r ot_capture.pcap -q -z io,stat,1
tshark -r ot_capture.pcap -Y "modbus" | head
tshark -r ot_capture.pcap -Y "mqtt" -T fields -e mqtt.topic -e mqtt.msg
```

## Advanced DPI & Mitigations (Cross-Protocol)

| Protocol | High-signal operations | Fast detection idea |
|---|---|---|
| Modbus/TCP | 0x05/0x06/0x0F/0x10 | `tshark -r pcap -Y "modbus && (modbus.func_code==5 || modbus.func_code==6 || modbus.func_code==15 || modbus.func_code==16)"` |
| S7Comm | Write Var / programming-like | Baseline `tcp/102` talkers; alert on new client IP |
| BACnet | WriteProperty | Filter `udp/47808` and search for write services |
| OPC UA | WriteRequest / CallRequest | Filter `opcua` and hunt for write/call |
| ENIP/CIP | new talker to 44818 / connection churn | Alert on new 44818 sessions; spikes in setup traffic |
| MQTT | publish to control topics | Subscribe `#` and diff normal vs new topics |

## IIoT Protocols (MQTT & CoAP)

```bash
tshark -r iot_capture.pcap -Y "mqtt" -T fields -e mqtt.topic -e mqtt.msg
mosquitto_sub -h <target_ip> -p 1883 -t "#" -v
```

```bash
coap-client-openssl -m get coap://<target_ip>/.well-known/core
```

## Traffic Replay (Lab/Challenge)

```bash
sudo tcpreplay -i eth0 original_traffic.pcap
tcprewrite --endpoints=192.168.1.100:10.0.0.50 --infile=original.pcap --outfile=modified.pcap
sudo tcpreplay -i eth0 modified.pcap
```

## Aerospace / Defense OT & Telemetry (Optional)

### ADS-B

| Item | Value |
|---|---|
| Common ports | 1090/tcp, 30003/tcp |

```bash
tshark -r adsb.pcap -q -z io,stat,1
```

### MAVLink

| Item | Value |
|---|---|
| Common port | 14550/udp |

```bash
tshark -r drone.pcap -Y "udp.port==14550" | head
```

## Quick Reference

| Task | Command |
|---|---|
| OT scan | `nmap -Pn -sS -sV -p 102,502,1883,2404,44818,2222,4840,20000,47808 <target>` |
| Capture OT PCAP | `tshark -i <iface> -f "tcp port 502 or tcp port 102 or tcp port 2404 or tcp port 20000 or udp port 47808" -w ot_capture.pcap` |
| Modbus reads (client) | `python3 modbus_read_holding_registers.py <ip> --unit 1 --addr 1 --count 20` |
| Modbus live sniff | `python3 modbus_sniffer.py` |
| Modbus PCAP flag hunt | `python3 modbus_flag_extract_pcap.py <pcap>` |
| MQTT subscribe all | `mosquitto_sub -h <ip> -t "#" -v` |

## 📚 Local References & Tools

### 📖 Cheat Sheets & Playbooks
*   [SCADA OT CheatSheet & Hacking Playbook](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/SCADA-OT-CheatSheet-Advanced-ICS-Hacking-Playbook/README.md)
*   [Modbus CheatSheet](file:///home/kali/Desktop/RTAF-CTF-2026/Arsenal/Intel_Data/ICS_Protocols/Modbus_CheatSheet.md)
*   [S7Comm CheatSheet](file:///home/kali/Desktop/RTAF-CTF-2026/Arsenal/Intel_Data/ICS_Protocols/S7Comm_CheatSheet.md)
*   [IEC104 CheatSheet](file:///home/kali/Desktop/RTAF-CTF-2026/Arsenal/Intel_Data/ICS_Protocols/IEC104_CheatSheet.md)
*   [Ultimate ICS CTF Playbook](file:///home/kali/Desktop/RTAF-CTF-2026/Arsenal/Intel_Data/ICS_Protocols/Ultimate_ICS_CTF_Playbook.md)

### 🧪 Simulators & Labs
*   [PLC and RTU Simulators](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/PLC_and_RTU_Simulator/README.md)
    *   [Modbus Simulator](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/PLC_and_RTU_Simulator/Modbus_PLC_Simulator/)
    *   [S7Comm Simulator](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/PLC_and_RTU_Simulator/S7Comm_RTU_Simulator/)
*   [IT/OT Cyber Security Workshop Materials](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/IT_OT_IoT_Cyber_Security_Workshop/README.md)

### 🧰 Bundled Scripts (Scapy/Ettercap)
*   [ics_toolkit](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/)
    *   [modbus_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_sniffer.py)
    *   [modbus_flag_extract_pcap.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/modbus_flag_extract_pcap.py)
    *   [iec104_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/iec104_sniffer.py)
    *   [dnp3_sniffer.py](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/scapy_scripts/dnp3_sniffer.py)
    *   [modbus_block_writes.etter](file:///home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/ics_toolkit/ettercap_filters/modbus_block_writes.etter)

## Keywords

ICS, SCADA, OT, Modbus, S7Comm, Siemens S7, IEC 104, DNP3, BACnet, OPC UA, EtherNet/IP, ENIP, CIP, MQTT, CoAP, Ettercap, ARP spoofing, MITM, Scapy, PCAP, tshark, DPI, coc2026

---
**Note:** This skill is merged from `skill1.md`, `skill2.md`, and `skill3.md` for the RTAF Cyber Operation Contest 2026.
