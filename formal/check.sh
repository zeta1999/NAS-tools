#!/usr/bin/env bash
# Formal verification gate. Exit non-zero on any failure.
#
# Three classes of check, and the third is the one people forget:
#   1. Lean proofs compile, with no `sorry`.
#   2. TLA+ invariants hold.
#   3. TLA+ SANITY checks FAIL. A model that passes because nothing happens
#      proves nothing; these must produce counterexamples or the green run
#      above is meaningless.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
say() { printf '%-46s %s\n' "$1" "$2"; }

echo "── Lean ──────────────────────────────────────────────────────────"
if grep -rn "sorry" lean --include='*.lean' | grep -v '^\s*--'; then
  say "no-sorry gate" "FAIL — admitted proofs found"; fail=1
else
  say "no-sorry gate" "ok"
fi
for f in lean/NasVerify/*.lean; do
  if lean "$f" 2>&1 | grep -qE "error|sorry"; then say "$f" "FAIL"; fail=1
  else say "$f" "verified"; fi
done

echo "── TLA+ ──────────────────────────────────────────────────────────"
JAR=tlaplus/tla2tools.jar
if [ ! -f "$JAR" ]; then
  echo "fetching tla2tools.jar…"
  curl -sSL -o "$JAR" https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar || {
    say "tla2tools.jar" "FAIL — could not fetch"; exit 1; }
fi
pushd tlaplus >/dev/null
run() { java -Xmx2g -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 4 -nowarning -config "$1" SlotConsistency 2>&1; }

CFG=MC_small.cfg; BOUND="MaxSeq=2"
if [ "${DEEP:-0}" = "1" ]; then CFG=MC_full.cfg; BOUND="MaxSeq=3, deep"; fi
out=$(run $CFG)
if echo "$out" | grep -q "No error has been found"; then
  n=$(echo "$out" | grep -oE "[0-9]+ distinct states" | head -1)
  say "SlotConsistency invariants ($BOUND)" "ok — $n"
else
  say "SlotConsistency invariants ($BOUND)" "FAIL"; echo "$out" | tail -20; fail=1
fi

for inv in NeverForks NeverAlarms ForkAlwaysDetected; do
  out=$(run "MC_$inv.cfg")
  if echo "$out" | grep -q "Invariant $inv is violated"; then
    say "sanity: $inv" "violated as required"
  else
    say "sanity: $inv" "FAIL — model is VACUOUS"; fail=1
  fi
done
popd >/dev/null

echo "──────────────────────────────────────────────────────────────────"
[ $fail -eq 0 ] && echo "formal: PASS" || echo "formal: FAIL"
exit $fail
