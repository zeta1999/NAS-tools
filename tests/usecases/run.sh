#!/usr/bin/env bash
# Runs every use-case acceptance test and prints a matrix.
#
# Exit 1 on any FAIL. PENDING is reported, never counted as success.
# NAS_MILESTONE (default M0) bounds which assertions actually execute.
cd "$(dirname "$0")"

# A private NAS_HOME per run. Without this the suite would either scribble in
# the user's real namespace directory or fail on the second run, since
# `ns create` refuses to overwrite an existing namespace.
if [ -z "${NAS_HOME:-}" ]; then
  NAS_HOME=$(mktemp -d "${TMPDIR:-/tmp}/nas-acceptance.XXXXXX")
  export NAS_HOME
  trap 'rm -rf "$NAS_HOME"' EXIT
fi

# The fixture is generated, not committed: it is 1.3 MB of pseudo-random bytes
# that compress to nothing and would bloat every clone.
[ -d fixtures/tree ] || ./fixtures/make.sh >/dev/null

tp=0; tf=0; tpend=0; rc=0
for f in uc*.sh; do
  out=$(bash "$f" 2>&1); status=$?      # capture the SCRIPT's status, not echo's
  echo "$out"
  [ $status -ne 0 ] && rc=1
  line=$(echo "$out" | tail -1)
  if ! echo "$line" | grep -q 'passed,'; then
    printf '\033[31m  !! %s produced no summary (died early?) — treating as FAIL\033[0m\n' "$f"
    rc=1; continue
  fi
  p=$(echo "$line"  | grep -oE '[0-9]+ passed'  | grep -oE '[0-9]+'); tp=$((tp+${p:-0}))
  f2=$(echo "$line" | grep -oE '[0-9]+ failed'  | grep -oE '[0-9]+'); tf=$((tf+${f2:-0}))
  pd=$(echo "$line" | grep -oE '[0-9]+ pending' | grep -oE '[0-9]+'); tpend=$((tpend+${pd:-0}))
done
printf '\n══════════════════════════════════════════════════════\n'
printf 'use-case acceptance (≤%s): %d passed, %d failed, %d pending\n' \
  "${NAS_MILESTONE:-M0}" "$tp" "$tf" "$tpend"
[ "$tf" -gt 0 ] && rc=1
[ "$tpend" -gt 0 ] && printf 'PENDING is not success.\n'
exit $rc
