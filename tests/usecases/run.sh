#!/usr/bin/env bash
# Runs every use-case acceptance test and prints a matrix.
# Exit 1 on any FAIL. PENDING is reported, never counted as success.
cd "$(dirname "$0")"
tp=0; tf=0; tpend=0; rc=0
for f in uc*.sh; do
  out=$(bash "$f" 2>&1); echo "$out"
  [ $? -ne 0 ] && rc=1
  line=$(echo "$out" | tail -1)
  p=$(echo "$line" | grep -oE '[0-9]+ passed'  | grep -oE '[0-9]+'); tp=$((tp+${p:-0}))
  f2=$(echo "$line" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+'); tf=$((tf+${f2:-0}))
  pd=$(echo "$line" | grep -oE '[0-9]+ pending'| grep -oE '[0-9]+'); tpend=$((tpend+${pd:-0}))
done
printf '\n══════════════════════════════════════════════════════\n'
printf 'use-case acceptance: %d passed, %d failed, %d pending\n' "$tp" "$tf" "$tpend"
[ "$tf" -gt 0 ] && rc=1
[ "$tpend" -gt 0 ] && printf 'PENDING is not success — these gate M0→M2.\n'
exit $rc
