#!/usr/bin/env bash
# archive_inspect - pre-extraction safety gate for zip/7z/tar/tar.gz
# Flags archives that are likely zip bombs or nested compression traps.
#
# Usage:
#   archive_inspect.sh <file> [--max-files N] [--max-ratio R]
#
# Defaults:
#   MAX_FILES=100  (reject if > N files inside)
#   MAX_RATIO=50   (reject if uncompressed/compressed > R)

set -u

FILE="${1:-}"
MAX_FILES="${MAX_FILES:-100}"
MAX_RATIO="${MAX_RATIO:-50}"

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "Usage: $0 <archive> [--max-files N] [--max-ratio R]" >&2
  exit 1
fi

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-files) MAX_FILES="$2"; shift 2 ;;
    --max-ratio) MAX_RATIO="$2"; shift 2 ;;
    *) shift ;;
  esac
done

TYPE="$(file -b "$FILE" | tr '[:upper:]' '[:lower:]')"
COMPRESSED_SIZE="$(stat -c '%s' "$FILE")"

inspect_zip() {
  local count uncompressed
  count=$(unzip -l "$FILE" 2>/dev/null | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/' | wc -l)
  uncompressed=$(unzip -l "$FILE" 2>/dev/null | awk '/^[[:space:]]*---/{p=1;next} p{s+=$1} END{print s+0}')
  echo "[zip] files=$count uncompressed=${uncompressed}B compressed=${COMPRESSED_SIZE}B"
  echo "$count $uncompressed"
}

inspect_7z() {
  local count uncompressed
  count=$(timeout 10s 7z l "$FILE" 2>/dev/null | awk '/^[0-9]{4}-/{c++} END{print c+0}')
  uncompressed=$(timeout 10s 7z l "$FILE" 2>/dev/null | awk '/^[0-9]{4}-/{s+=$4} END{print s+0}')
  echo "[7z] files=$count uncompressed=${uncompressed}B compressed=${COMPRESSED_SIZE}B"
  echo "$count $uncompressed"
}

inspect_tar() {
  local count uncompressed
  if [[ "$TYPE" == *gzip* ]]; then
    count=$(timeout 10s tar -tzf "$FILE" 2>/dev/null | wc -l)
    uncompressed=$(timeout 10s gzip -l "$FILE" 2>/dev/null | awk 'NR==2{print $2}')
  else
    count=$(timeout 10s tar -tf "$FILE" 2>/dev/null | wc -l)
    uncompressed=$(timeout 10s tar -tvf "$FILE" 2>/dev/null | awk '{s+=$3} END{print s+0}')
  fi
  echo "[tar] files=$count uncompressed=${uncompressed:-0}B compressed=${COMPRESSED_SIZE}B"
  echo "${count} ${uncompressed:-0}"
}

METRICS=""
case "$TYPE" in
  *zip*)                METRICS="$(inspect_zip | tail -1)" ;;
  *7-zip*|*7z*)         METRICS="$(inspect_7z | tail -1)" ;;
  *tar*|*gzip*|*bzip*)  METRICS="$(inspect_tar | tail -1)" ;;
  *) echo "[WARN] unknown archive type: $TYPE"; exit 2 ;;
esac

read -r count uncompressed <<< "$METRICS"
count="${count:-0}"; uncompressed="${uncompressed:-0}"

verdict=0
reason=""

if (( count > MAX_FILES )); then
  verdict=1; reason="too many entries: ${count} > ${MAX_FILES}"
fi

if (( COMPRESSED_SIZE > 0 )) && (( uncompressed > 0 )); then
  ratio=$(( uncompressed / COMPRESSED_SIZE ))
  if (( ratio > MAX_RATIO )); then
    verdict=1
    reason="${reason:+$reason; }compression ratio ${ratio}x > ${MAX_RATIO}x"
  fi
fi

if (( verdict == 1 )); then
  echo "[TRAP] $reason"
  echo "$(date -Is) | type=trap | reason=archive_bomb | file=$FILE | detail=$reason" >> /tmp/ctf_loot.txt 2>/dev/null || true
  exit 1
fi

echo "[OK] archive looks safe (files=$count, uncompressed=${uncompressed}B)"
exit 0
