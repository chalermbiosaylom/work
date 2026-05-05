# ROUTING_EXAMPLES (Competition Router v2)

Use these examples to train fast routing behavior.

## Format (Mandatory)
`Routing to /<skill> | primary_mcp=<mcp> | confidence=<n> | backup=/ctf-<skill2>`

---

## 1) ICS Modbus Service
Evidence:
- Prompt mentions PLC/coil/register
- Port `502` reachable
- No HTTP service

Output:
`Routing to /ctf-ics | primary_mcp=ctf-solve | confidence=7 | backup=/ctf-forensics`

## 2) ENIP/CIP Challenge
Evidence:
- Prompt mentions EtherNet/IP/CIP
- Port `44818` reachable
- Tag/object language in statement

Output:
`Routing to /ctf-ics | primary_mcp=ctf-solve | confidence=7 | backup=/ctf-reverse`

## 3) PCAP with Industrial Traffic
Evidence:
- File is `.pcapng`
- Modbus/ENIP protocol hints in capture
- No direct exploit binary

Output:
`Routing to /ctf-forensics | primary_mcp=sharkmcp | confidence=6 | backup=/ctf-ics`

## 4) Web App + JWT Token
Evidence:
- HTTP endpoint present
- JWT/cookie auth in response
- Token tampering hinted

Output:
`Routing to /ctf-web | primary_mcp=ctf-solve | confidence=6 | backup=/ctf-crypto`

## 5) ELF + Remote nc Service
Evidence:
- ELF binary in files
- nc prompt on remote port
- Crash behavior on long input

Output:
`Routing to /ctf-pwn | primary_mcp=pentest-mcp | confidence=7 | backup=/ctf-reverse`

## 6) Obfuscated JS + WASM
Evidence:
- `.js` + `.wasm` artifacts
- Client-side validation path
- No direct binary crash context

Output:
`Routing to /ctf-reverse | primary_mcp=ghidramcp | confidence=5 | backup=/ctf-web`

## 7) RSA Numbers Challenge
Evidence:
- Prompt: RSA/modulus/exponent
- `.txt` with large integers
- No service interaction needed initially

Output:
`Routing to /ctf-crypto | primary_mcp=ctf-solve | confidence=7 | backup=/ctf-misc`

## 8) Memory Dump Investigation
Evidence:
- `.raw`/`.mem` file
- Process/network artifact language
- Volatility path implied

Output:
`Routing to /ctf-forensics | primary_mcp=pentest-mcp | confidence=7 | backup=/ctf-malware`

## 9) Restricted Shell Puzzle
Evidence:
- Netcat interactive restricted eval shell
- Input filtering / jail hints
- No explicit memory corruption

Output:
`Routing to /ctf-misc | primary_mcp=ctf-solve | confidence=6 | backup=/ctf-pwn`

## 10) Low-Priv Access Given (Post-Exploitation)
Evidence:
- SSH/WinRM credentials provided
- Goal implies privesc/pivot/lateral
- Not initial foothold discovery

Output:
`Routing to /ctf-os-exploit | primary_mcp=pentest-mcp | confidence=7 | backup=/ctf-web`

---

## Pivot Reminder
Trigger backup route when one condition is true:
- same error repeats 3 times
- no measurable progress in 2 command cycles
- active branch stalls >10s without output
