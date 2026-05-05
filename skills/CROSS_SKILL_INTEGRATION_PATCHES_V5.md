# Cross-Skill Integration Patches V5 (Context-Aware Response Handling)
**Date:** Apr 17, 2026
**Scope:** `ctf-web`, `web-exploit-chain`

---

## Objective
Close three token-killing failure modes observed in live runs:
1. **Context Bloat** - dumping 20KB+ JSON (`/api/debug`, `__builtins__`, etc.) into prompt history on every tool call
2. **Tunnel Vision** - fixating on `?fn=` LFI chain while the same file is often served directly
3. **Error Loop** - retrying mutated versions of the same payload after `HTTP 500`/`UnicodeError`, burning tokens until quota dies

---

## Patch 7: `smart_curl` Wrapper (Anti-Context-Bloat)

### New file
- `/home/kali/Desktop/.windsurf/skills/ctf-web/smart_curl.sh`

### Behavior
- Prints full body if <= `SMART_CURL_MAX` chars (default `2000`)
- Otherwise:
  - JSON -> `jq 'keys'` preview only (50 keys max)
  - Text -> head 20 / tail 10 lines
- Always pre-scans body for flags via regex and appends hits to `/tmp/ctf_loot.txt`
- Never blocks agent flow with pagers or interactive prompts

### Optional system-wide install
```bash
sudo install -m 0755 /home/kali/Desktop/.windsurf/skills/ctf-web/smart_curl.sh /usr/local/bin/smart_curl
smart_curl -sS http://example.com/api/debug
```

### Smoke test (done)
```
$ bash smart_curl.sh
Usage: smart_curl <url> [curl args...]
```

---

## Patch 8: Context-Aware Response Handling (Web SKILL.md)

### Location
- `/home/kali/Desktop/.windsurf/skills/ctf-web/SKILL.md`

### New rules
1. `smart_curl` preferred over `curl` for unknown-size responses
2. JSON drill-down via `jq 'keys'` -> `jq '.<key>'` -> `jq '.<key> | keys'`
3. Text narrowing via `grep -Eni 'flag|secret|token|file|path|version|error'`
4. Never re-request full payload after truncation; always refine
5. File-Leak Pivot: if JSON leaks a server file path, try direct `GET /<basename>` BEFORE crafting LFI

### Anti-Trap additions
- Do not load untrimmed response bodies
- Do not retry payloads that triggered `5xx` or `UnicodeError`

---

## Patch 9: Stop & Think Rule (Error-Loop Breaker)

### Location
- `/home/kali/Desktop/.windsurf/skills/ctf-web/SKILL.md`
- `/home/kali/Desktop/.windsurf/workflows/web-exploit-chain.md`

### Hard rules
- `HTTP 500` twice on same vector -> STOP, switch vector
- Error text contains `UnicodeError` / `IDNA` / `decode` / `bad encoding` -> current path format incompatible, pivot class
- Same payload family fails 2x -> force class pivot (`lfi` -> `ssrf`, `ssti` -> `rce`, ...)

### Required log format
```text
[STOP] vector=<class> | payload=<payload> | error=<error>
[REASON] <why current approach cannot succeed>
[NEXT] <alternative vector or endpoint to try>
```

---

## Operational Outcome

Before V5:
- `/api/debug` response (23KB+) pushed into every subsequent prompt
- Cached tokens balloon to 97k+, quota dies mid-exploit
- Agent tunnels into `?fn=` LFI chain, misses direct `/server.py` fetch

After V5:
- `smart_curl` drops bloat to ~500 chars preview, keeps flag hits intact
- `jq 'keys'` + targeted drill-down replaces raw dumps
- File-Leak Pivot forces direct-fetch attempt before path-traversal guesswork
- Stop & Think breaks 500/UnicodeError loops into logged vector pivots

---

## Files changed
- **New:** `/home/kali/Desktop/.windsurf/skills/ctf-web/smart_curl.sh`
- **New:** `/home/kali/Desktop/.windsurf/skills/CROSS_SKILL_INTEGRATION_PATCHES_V5.md`
- **Updated:** `/home/kali/Desktop/.windsurf/skills/ctf-web/SKILL.md`
- **Updated:** `/home/kali/Desktop/.windsurf/workflows/web-exploit-chain.md`
