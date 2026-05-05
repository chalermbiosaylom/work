#!/usr/bin/env bash
set -u

PASS=0
FAIL=0

TARGET_HOST="${PASSCHECK_TARGET:-}"
TARGET_PORT="${PASSCHECK_PORT:-}"
PROTOCOL="${PASSCHECK_PROTOCOL:-}"
SCOPE="${PASSCHECK_SCOPE:-ctf}"
STATEFUL="${PASSCHECK_STATEFUL:-no}"
BASELINE_PATH="${PASSCHECK_BASELINE:-}"
NET_TIMEOUT="${PASSCHECK_TIMEOUT:-15}"
EVIDENCE_ROOT="${PASSCHECK_EVIDENCE_ROOT:-/tmp/rtaf_passcheck}"

print_usage() {
  cat <<'EOF'
RTAF COC2026 Pre-Match PassCheck (one-shot)

Usage:
  bash .windsurf/tools/pre_match_passcheck.sh \
    --target <host_or_ip> --port <port> --protocol <name> --scope ctf [options]

Required:
  --target <host_or_ip>      Challenge target host/ip
  --port <port>              Target port
  --protocol <name>          Protocol/service (http, modbus, enip, s7, pwn, etc.)
  --scope ctf                Must be 'ctf'

Optional:
  --stateful yes|no          Enable state safety check (default: no)
  --baseline <path>          Baseline file path for stateful services
  --timeout <seconds>        Network timeout bounds (default: 15)
  --evidence-root <path>     Evidence folder root (default: /tmp/rtaf_passcheck)
  -h, --help                 Show this help

Environment fallback:
  PASSCHECK_TARGET, PASSCHECK_PORT, PASSCHECK_PROTOCOL, PASSCHECK_SCOPE,
  PASSCHECK_STATEFUL, PASSCHECK_BASELINE, PASSCHECK_TIMEOUT, PASSCHECK_EVIDENCE_ROOT
EOF
}

log_check() {
  local name="$1"
  local status="$2"
  local detail="$3"
  if [[ "$status" == "PASS" ]]; then
    PASS=$((PASS + 1))
    printf '[PASS] %-16s | %s\n' "$name" "$detail"
  else
    FAIL=$((FAIL + 1))
    printf '[FAIL] %-16s | %s\n' "$name" "$detail"
  fi
}

is_private_target() {
  local t="$1"
  [[ "$t" == "localhost" ]] && return 0
  [[ "$t" =~ ^127\. ]] && return 0
  [[ "$t" =~ ^10\. ]] && return 0
  [[ "$t" =~ ^192\.168\. ]] && return 0
  [[ "$t" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

run_reachability() {
  local host="$1"
  local port="$2"
  local timeout_s="$3"

  if command -v nc >/dev/null 2>&1; then
    timeout "$timeout_s" nc -zvw 10 "$host" "$port" >/tmp/passcheck_nc.out 2>&1
    return $?
  fi

  if command -v nmap >/dev/null 2>&1; then
    timeout "$timeout_s" nmap -Pn -p"$port" --max-rtt-timeout 10s "$host" >/tmp/passcheck_nmap.out 2>&1
    grep -qiE "${port}/tcp\s+open|${port}/udp\s+open" /tmp/passcheck_nmap.out
    return $?
  fi

  return 127
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_HOST="${2:-}"
      shift 2
      ;;
    --port)
      TARGET_PORT="${2:-}"
      shift 2
      ;;
    --protocol)
      PROTOCOL="${2:-}"
      shift 2
      ;;
    --scope)
      SCOPE="${2:-}"
      shift 2
      ;;
    --stateful)
      STATEFUL="${2:-}"
      shift 2
      ;;
    --baseline)
      BASELINE_PATH="${2:-}"
      shift 2
      ;;
    --timeout)
      NET_TIMEOUT="${2:-}"
      shift 2
      ;;
    --evidence-root)
      EVIDENCE_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1"
      print_usage
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET_HOST" || -z "$TARGET_PORT" || -z "$PROTOCOL" ]]; then
  echo "[ERROR] Missing required arguments"
  print_usage
  exit 2
fi

if ! [[ "$TARGET_PORT" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] --port must be numeric"
  exit 2
fi

if ! [[ "$NET_TIMEOUT" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] --timeout must be numeric"
  exit 2
fi

RUN_TS="$(date +%Y%m%d_%H%M%S)"
SAFE_TARGET="${TARGET_HOST//[^a-zA-Z0-9_.-]/_}"
EVIDENCE_DIR="$EVIDENCE_ROOT/${SAFE_TARGET}_${TARGET_PORT}_${RUN_TS}"
mkdir -p "$EVIDENCE_DIR"

printf '== RTAF COC2026 PassCheck ==\n'
printf 'Target: %s:%s | protocol=%s | scope=%s | stateful=%s\n' "$TARGET_HOST" "$TARGET_PORT" "$PROTOCOL" "$SCOPE" "$STATEFUL"
printf 'Evidence dir: %s\n\n' "$EVIDENCE_DIR"

# 1) scope_ok
if [[ "$SCOPE" != "ctf" ]]; then
  log_check "scope_ok" "FAIL" "scope must be 'ctf'"
elif is_private_target "$TARGET_HOST"; then
  log_check "scope_ok" "PASS" "target appears lab/private (or localhost)"
else
  log_check "scope_ok" "PASS" "scope explicitly set to ctf (public/non-private target allowed)"
fi

# 2) target_lock_ok
if [[ -n "$TARGET_HOST" && -n "$TARGET_PORT" && -n "$PROTOCOL" ]]; then
  {
    echo "target_host=$TARGET_HOST"
    echo "target_port=$TARGET_PORT"
    echo "protocol=$PROTOCOL"
    echo "scope=$SCOPE"
  } >"$EVIDENCE_DIR/target_lock.txt"
  log_check "target_lock_ok" "PASS" "target tuple locked in evidence"
else
  log_check "target_lock_ok" "FAIL" "target tuple incomplete"
fi

# 3) reachability_ok
run_reachability "$TARGET_HOST" "$TARGET_PORT" "$NET_TIMEOUT"
RC=$?
if [[ $RC -eq 0 ]]; then
  if [[ -f /tmp/passcheck_nc.out ]]; then
    cp /tmp/passcheck_nc.out "$EVIDENCE_DIR/reachability.txt" 2>/dev/null
  elif [[ -f /tmp/passcheck_nmap.out ]]; then
    cp /tmp/passcheck_nmap.out "$EVIDENCE_DIR/reachability.txt" 2>/dev/null
  fi
  log_check "reachability_ok" "PASS" "port reachability confirmed"
elif [[ $RC -eq 127 ]]; then
  log_check "reachability_ok" "FAIL" "missing both nc and nmap"
else
  [[ -f /tmp/passcheck_nc.out ]] && cp /tmp/passcheck_nc.out "$EVIDENCE_DIR/reachability.txt" 2>/dev/null
  [[ -f /tmp/passcheck_nmap.out ]] && cp /tmp/passcheck_nmap.out "$EVIDENCE_DIR/reachability.txt" 2>/dev/null
  log_check "reachability_ok" "FAIL" "target not reachable at ${TARGET_HOST}:${TARGET_PORT}"
fi

# 4) timeout_ok
if (( NET_TIMEOUT >= 5 && NET_TIMEOUT <= 30 )); then
  log_check "timeout_ok" "PASS" "timeout=${NET_TIMEOUT}s (bounded)"
else
  log_check "timeout_ok" "FAIL" "timeout=${NET_TIMEOUT}s (must be 5..30s)"
fi

# 5) evidence_mode_ok
if [[ -d "$EVIDENCE_DIR" && -w "$EVIDENCE_DIR" ]]; then
  {
    echo "run_ts=$RUN_TS"
    echo "checklist=passcheck"
    echo "host=$TARGET_HOST"
    echo "port=$TARGET_PORT"
    echo "protocol=$PROTOCOL"
  } >"$EVIDENCE_DIR/evidence.log"
  log_check "evidence_mode_ok" "PASS" "evidence logging initialized"
else
  log_check "evidence_mode_ok" "FAIL" "cannot create/write evidence directory"
fi

# 6) state_safety_ok
if [[ "$STATEFUL" == "yes" ]]; then
  if [[ -n "$BASELINE_PATH" && -f "$BASELINE_PATH" ]]; then
    cp "$BASELINE_PATH" "$EVIDENCE_DIR/state_baseline.ref" 2>/dev/null || true
    log_check "state_safety_ok" "PASS" "stateful mode baseline file exists"
  else
    cat >"$EVIDENCE_DIR/baseline_required.txt" <<EOF
stateful=yes but no valid baseline provided.
Provide --baseline <path_to_baseline_snapshot> before write actions.
EOF
    log_check "state_safety_ok" "FAIL" "stateful target requires --baseline file"
  fi
else
  log_check "state_safety_ok" "PASS" "non-stateful mode"
fi

printf '\n== Summary ==\n'
printf 'PASS=%d | FAIL=%d\n' "$PASS" "$FAIL"

if (( FAIL == 0 )); then
  echo "RESULT=PASSCHECK_OK"
  exit 0
fi

echo "RESULT=PASSCHECK_FAIL"
exit 1
