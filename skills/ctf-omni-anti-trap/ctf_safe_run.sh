#!/usr/bin/env bash
# ctf_safe_run - resource-monitored command executor
# Kills command if:
#   - Total runtime exceeds MAX_TIME
#   - CPU stays at 100% AND memory exceeds MAX_MEM_MB (runaway)
#   - Output hasn't changed for STALL_SECS (stall detection)
#
# Usage:
#   ctf_safe_run.sh <max_time_sec> <max_mem_mb> -- <command...>
#
# Example:
#   ctf_safe_run.sh 60 1000 -- nmap -p- target.com

set -u

if [[ $# -lt 4 || "$3" != "--" ]]; then
  echo "Usage: $0 <max_time_sec> <max_mem_mb> -- <command...>" >&2
  exit 1
fi

MAX_TIME="$1"; shift
MAX_MEM="$1"; shift
shift  # consume --

STALL_SECS="${STALL_SECS:-15}"
LOOT="${SMART_LOOT:-/tmp/ctf_loot.txt}"

echo "[SAFE_RUN] cmd=$* | max_time=${MAX_TIME}s | max_mem=${MAX_MEM}MB | stall=${STALL_SECS}s"

# Launch with overall timeout wrapper
timeout --kill-after=3s "${MAX_TIME}s" "$@" &
pid=$!

# Monitor loop
last_cpu=""
stall_start=$(date +%s)
killed=0

while kill -0 "$pid" 2>/dev/null; do
  sleep 2
  # Check resources
  read -r cpu mem <<< "$(ps -p "$pid" -o %cpu=,rss= 2>/dev/null | awk '{printf "%d %d", $1, $2/1024}')" || break
  if [[ -z "${cpu:-}" ]]; then break; fi

  # Runaway check
  if (( cpu >= 95 )) && (( mem > MAX_MEM )); then
    echo "[SAFE_RUN][KILL] runaway: cpu=${cpu}% mem=${mem}MB > ${MAX_MEM}MB"
    kill -9 "$pid" 2>/dev/null
    killed=1
    echo "$(date -Is) | type=trap | reason=runaway | cmd=$* | cpu=${cpu} | mem=${mem}" >> "$LOOT" 2>/dev/null || true
    break
  fi

  # Stall check (CPU unchanged for STALL_SECS means hung)
  now=$(date +%s)
  if [[ "$cpu" == "$last_cpu" ]]; then
    if (( now - stall_start > STALL_SECS )) && (( cpu == 0 )); then
      echo "[SAFE_RUN][KILL] stalled: cpu=0% for >${STALL_SECS}s"
      kill -9 "$pid" 2>/dev/null
      killed=1
      echo "$(date -Is) | type=trap | reason=stalled | cmd=$*" >> "$LOOT" 2>/dev/null || true
      break
    fi
  else
    stall_start=$now
    last_cpu="$cpu"
  fi
done

wait "$pid" 2>/dev/null
rc=$?
if (( killed == 1 )); then rc=137; fi
echo "[SAFE_RUN] exit=${rc}"
exit "$rc"
