#!/usr/bin/env bash
# adaptive_timeout - measure RTT and print a safe timeout value (seconds).
#
# Usage:
#   adaptive_timeout.sh <host>
#   TMO=$(adaptive_timeout.sh target.com); curl --max-time "$TMO" http://target.com

set -u
HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "Usage: $0 <host>" >&2
  exit 1
fi

RTT_MS="$(ping -c 5 -W 2 "$HOST" 2>/dev/null | awk -F/ '/rtt|round-trip/{print $5; exit}')"

if [[ -z "${RTT_MS:-}" ]]; then
  echo "15"
  exit 0
fi

# timeout = max(10, ceil(3 * rtt_ms / 1000) + 5)
TMO="$(awk -v r="$RTT_MS" 'BEGIN{t=int((3*r/1000)+5); if(t<10)t=10; print t}')"
echo "$TMO"
