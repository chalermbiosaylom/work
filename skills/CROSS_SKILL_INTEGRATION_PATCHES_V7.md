# Cross-Skill Integration Patches V7 (Port Discovery + XSS Filter Bypass)
**Date:** Apr 17, 2026
**Trigger:** Real-world miss on Meme Generator challenge (port 4000 missed by hardcoded scan list)

---

## Lessons from Live Run

### Miss #1: Hardcoded Port List
- Scanned: `80,443,1337,3000,5000,8000,8080,8888,9000,9001,9090,31337,8001,8002`
- Target had: `4000/tcp open` (bot service) -> **not in list**
- Only recovered because user corrected
- Root cause: `-Pn -sT -T4 -p-` takes <15s on LAN - no reason to restrict

### Miss #2: Ignored Description Signals
Challenge said: *"The bot accessible via the service... through netcat... use http://meme-generator/"*

Signal breakdown (all ignored):
- "bot" -> expect 2+ services (web + headless browser)
- "netcat" -> non-HTTP custom port expected
- "meme-generator" hostname -> internal docker network
- "localStorage in bot" -> XSS challenge, not injection

### Miss #3: CSS vs Server Uppercase Confusion
- First glance: text came back `ALERT(1)` -> thought server uppercased
- Reality: CSS `text-transform: uppercase` applied visual only, but server ALSO uppercased
- Had to verify by grepping raw HTML bytes vs stylesheet

---

## Patches Applied

### Patch A: Port Discovery Discipline (ctf-web/SKILL.md)
New section: "Port Discovery Discipline (Anti-Tunnel-Vision)"

Three rules:
1. Read description signals first (`"bot"`, `"netcat"`, `"visits"` -> multi-service)
2. Default to **masscan → nmap two-step** on LAN (`masscan -p 0-65535 --rate=10000` → `nmap -sV -sC -p <hits>`)
3. Hardcoded lists require explicit justification

### Patch B: XSS Filter Bypass Quick Patterns (ctf-web/SKILL.md)
Added patterns directly proven in this challenge:
- Server-uppercase bypass via HTML numeric entities in attribute values
- `<script>` stripped -> event handler vectors
- Bot `console.log` exfil (no external callback needed)

### Patch C: Anti-Trap additions
- Do not use hardcoded port lists when description mentions multiple services
- Do not confuse CSS `text-transform` with server-side uppercase filter

---

## New Rule of Thumb

Before any exploit work:

```text
[CHECK] description_signals -> expected_service_count
[CHECK] masscan -p 0-65535 --rate=10000 → nmap -sV -sC -p <hits>  (LAN) or nmap --top-ports 1000 (internet/remote)
[CHECK] raw HTML bytes vs CSS transforms before declaring a filter
```

---

## Token Cost of the Miss
- Extra recon round after correction: ~1,500 tokens
- Would-be rabbit hole (trying to exfil from web only): avoided
- User correction saved ~5,000-10,000 tokens

---

## Files Changed
- `ctf-web/SKILL.md` - added Port Discovery Discipline + XSS Filter Bypass sections
- `CROSS_SKILL_INTEGRATION_PATCHES_V7.md` (this file)
