#!/bin/bash
# BYET keepalive: solve AES JS challenge (static key/iv, per-IP gate) then hit k.shtml SSI ensure.
# Exit 0 on confirmed ensure run; non-zero otherwise (GA email on failure).
set -u
URL="http://btpp04.byethost33.com/ssi/k.shtml"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

page=$(curl -sm 20 -A "$UA" "${URL}?v=${RANDOM}" || true)

if ! printf '%s' "$page" | grep -q 'aes.js'; then
  # No challenge (session already clear or SSI direct output)
  if printf '%s' "$page" | grep -q 'DONE'; then echo "OK-DIRECT"; exit 0; fi
  echo "FAIL-NO-PAGE"; printf '%s' "$page" | head -c 150; exit 1
fi

A=$(printf '%s' "$page" | grep -oE 'toNumbers\("[0-9a-f]{32}"\)' | sed -n '1p' | grep -oE '[0-9a-f]{32}')
B=$(printf '%s' "$page" | grep -oE 'toNumbers\("[0-9a-f]{32}"\)' | sed -n '2p' | grep -oE '[0-9a-f]{32}')
C=$(printf '%s' "$page" | grep -oE 'toNumbers\("[0-9a-f]{32}"\)' | sed -n '3p' | grep -oE '[0-9a-f]{32}')
[ ${#A} -eq 32 ] && [ ${#B} -eq 32 ] && [ ${#C} -eq 32 ] || { echo "FAIL-TRIAD"; exit 1; }

TOK=$(printf '%s' "$C" | xxd -r -p | openssl enc -aes-128-cbc -d -nopad -K "$A" -iv "$B" 2>/dev/null | xxd -p | tr -d '\n' | head -c 32)
[ ${#TOK} -eq 32 ] || { echo "FAIL-DECRYPT"; exit 1; }

page2=$(curl -sm 30 -A "$UA" --cookie "__test=$TOK" "${URL}?i=1" || true)
if printf '%s' "$page2" | grep -q 'DONE'; then echo "OK-SOLVED"; exit 0; fi
echo "FAIL-SECOND"; printf '%s' "$page2" | head -c 150; exit 1
