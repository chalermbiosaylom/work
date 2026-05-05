# Burp MCP Playbook (Community Edition)

Practical playbook for using Burp Suite + Burp MCP during web CTF speedruns.

## 1) Session Boot (60s)

- Confirm Burp proxy listener is up (`127.0.0.1:8080`)
- Intercept off (avoid blocking automated probes)
- Browser proxy enabled for target scope
- Add target host to scope and enable history filtering

## 2) Request Capture Priority

Capture these first because they unlock most chains:

1. Login/auth requests (`/login`, `/api/auth`, `/oauth/*`)
2. State-changing endpoints (`POST/PUT/PATCH/DELETE`)
3. File upload endpoints (`multipart/form-data`)
4. Tokenized endpoints (JWT/session cookies/CSRF tokens)
5. URL fetchers and webhook endpoints (SSRF candidates)

## 3) Smart Mutation Loop (Replay → Diff → Decide)

For every candidate request:

1. Replay baseline request
2. Mutate one variable at a time
3. Diff response body length/status/header/timing
4. Keep only mutations with deterministic delta
5. Escalate to exploit payload only after delta confirmed

## 4) Vulnerability-Specific Burp MCP Actions

## JWT/Auth

- Clone authenticated request
- Replace cookie/bearer token with tampered JWT
- Toggle `alg` to `none` and strip signature
- Mutate `sub`, `role`, `admin`, `kid`
- Compare authorization delta (`403 -> 200`)

## Upload RCE

- Replay multipart request
- Mutate filename and extension order (`.php.jpg`, `.phtml`)
- Mutate `Content-Type` mismatch (`image/jpeg` + script payload)
- Attempt polyglot upload and probe returned path

## CSRF

- Replay state-changing request without token
- Replay with stale token and cross-session token
- Check `Origin`/`Referer` enforcement
- Build forged PoC request if weak validation observed

## XSS

- Replay reflected parameter with context probes
- Test HTML/attribute/JS contexts separately
- Verify sink rendering and script execution path

## 5) High-Signal Diff Keys

Use these as decision points:

- `status_code` transitions (`401/403 -> 200`)
- `content_length` deltas after single mutation
- auth-sensitive strings (`admin`, `internal`, `debug`, `token`)
- timing deltas for blind injections

## 6) CTF Timebox Policy

- 3 failed mutation cycles on same vector -> pivot track
- If JWT auth fails fast -> switch to upload/LFI/SSTI
- If no app-layer delta -> enumerate hidden endpoints/roles

## 7) Pairing with Local Helpers

- JWT flows: `python3 jwt_tamper.py <token>`
- Upload flows: `python3 upload_tester.py <url> <field>`
- LFI flows: `python3 lfi_tester.py <url> <param>`
- SSTI flows: `python3 ssti_tester.py <url> <param>`

## 8) Flag-First Filter

Use this regex while inspecting responses/history:

`/(?:coc2026|flag|ctf|rtaf|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i`
