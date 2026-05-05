#!/usr/bin/env bash
# smart_curl - Context-safe curl wrapper for AI agents
# Prevents Context Bloat by auto-trimming large responses and suggesting precision queries.
#
# Install:
#   sudo install -m 0755 /home/kali/Desktop/.windsurf/skills/ctf-web/smart_curl.sh /usr/local/bin/smart_curl
#
# Usage:
#   smart_curl <url> [curl args...]
#   smart_curl -X POST http://... -d 'a=1'
#
# Environment overrides:
#   SMART_CURL_MAX=2000         # max chars of raw body to show before trimming
#   SMART_CURL_JSON_KEYS=1      # when JSON & trimmed, emit jq 'keys' preview
#   SMART_CURL_LOOT=/tmp/ctf_loot.txt   # auto-log interesting findings

set -u

MAX="${SMART_CURL_MAX:-2000}"
JSON_KEYS="${SMART_CURL_JSON_KEYS:-1}"
LOOT="${SMART_CURL_LOOT:-/tmp/ctf_loot.txt}"

if [[ $# -lt 1 ]]; then
  echo "Usage: smart_curl <url> [curl args...]" >&2
  exit 1
fi

# Always silent+show errors and include status info (but keep headers off stdout of body)
OUTPUT="$(curl -sS "$@" 2>&1)"
RC=$?
LENGTH=${#OUTPUT}

is_json() {
  command -v jq >/dev/null 2>&1 || return 1
  printf '%s' "$1" | jq -e . >/dev/null 2>&1
}

# Fast flag hunt (never drop a flag regardless of size)
FLAG_REGEX='(coc2026|RTAF|flag|f1a9|fl4g)\{[^}]+\}|\b[a-fA-F0-9]{32}\b'
FLAG_HIT="$(printf '%s' "$OUTPUT" | grep -Eo "$FLAG_REGEX" | head -3 || true)"
if [[ -n "$FLAG_HIT" ]]; then
  echo "[FLAG_HIT]"
  printf '%s\n' "$FLAG_HIT"
  {
    echo "$(date -Is) | type=flag_hit | url=$* | data=$FLAG_HIT"
  } >> "$LOOT" 2>/dev/null || true
fi

if (( LENGTH <= MAX )); then
  printf '%s\n' "$OUTPUT"
  exit $RC
fi

echo "WARNING: Response too large (${LENGTH} chars). Showing structure only."

if [[ "$JSON_KEYS" == "1" ]] && is_json "$OUTPUT"; then
  echo "[TYPE] json"
  echo "[KEYS]"
  printf '%s' "$OUTPUT" | jq -r 'if type=="object" then keys
                                 elif type=="array" then ["array(length=\(length))"]
                                 else [type] end
                                 | .[]' 2>/dev/null | head -50
  echo "[HINT] Drill down with: curl ... | jq '.<key>'   (or jq '.<key> | keys')"
else
  echo "[TYPE] text"
  echo "[PREVIEW_HEAD]"
  printf '%s\n' "$OUTPUT" | head -n 20
  echo "..."
  echo "[PREVIEW_TAIL]"
  printf '%s\n' "$OUTPUT" | tail -n 10
  echo "[HINT] Narrow with: curl ... | grep -Ei 'flag|secret|error|file|path|debug'"
fi

echo "... [TRUNCATED] ... Use grep/jq to refine; do NOT re-request full payload."
exit $RC
