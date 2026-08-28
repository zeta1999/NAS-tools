#!/usr/bin/env bash
# Runs every fuzz target for a bounded time. Exit non-zero if any crashes.
#
#   ./fuzz/run.sh            # 60 s per target — the routine sweep
#   SECS=900 ./fuzz/run.sh   # 15 min per target — before a milestone
#   ./fuzz/run.sh unpad      # one target
#
# Needs nightly (libFuzzer) and cargo-fuzz. Deliberately NOT part of ci.sh:
# a time-boxed fuzz run is not a pass/fail gate, and wiring one into CI trades a
# real signal for a flaky one. Run it before closing a milestone.
set -uo pipefail
cd "$(dirname "$0")"
SECS="${SECS:-60}"
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(decode_fields addr_from_hex unpad manifest_decode dir_manifest_decode aead_open
           slot_record_decode witness_decode lease_decode wrap_decode wire_decode)
fi

fail=0
for t in "${TARGETS[@]}"; do
  printf '\033[1m── %s (%s s) ──\033[0m\n' "$t" "$SECS"
  out=$(cargo +nightly fuzz run "$t" -- -max_total_time="$SECS" -rss_limit_mb=2048 2>&1)
  if echo "$out" | grep -qE "ERROR: libFuzzer|panicked at"; then
    echo "$out" | tail -25
    printf '\033[31m  CRASH — artifact under fuzz/artifacts/%s/\033[0m\n' "$t"
    fail=1
  else
    runs=$(echo "$out" | grep -oE "Done [0-9]+ runs" | grep -oE "[0-9]+")
    cov=$(echo "$out" | grep -oE "cov: [0-9]+" | tail -1)
    printf '  ok — %s runs, %s\n' "${runs:-?}" "${cov:-no coverage line}"
  fi
done

printf '\n'
[ $fail -eq 0 ] && echo "fuzz: PASS" || echo "fuzz: FAIL"
exit $fail
