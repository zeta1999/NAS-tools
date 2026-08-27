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
# Backticked prose is stripped first, so documentation may name `sorry` and
# `sorryAx` without tripping the gate. This is belt-and-braces anyway: the
# axiom check below is strictly stronger, since an admitted proof shows up as
# `sorryAx` in `#print axioms` whether or not the token appears in the source.
if grep -rn "sorry" lean --include='*.lean' | sed 's/`[^`]*`//g' \
     | grep -v '^[^:]*:[0-9]*: *--' | grep -E '\bsorry'; then
  say "no-sorry gate" "FAIL — admitted proofs found"; fail=1
else
  say "no-sorry gate" "ok"
fi
# Allowed axioms. Anything else -- above all `sorryAx`, which an `axiom`
# declaration or a `native_decide` would introduce without the token `sorry`
# ever appearing -- fails the gate.
ALLOWED='propext|Classical.choice|Quot.sound'
for f in lean/NasVerify/*.lean; do
  out=$(lean "$f" 2>&1)
  if echo "$out" | grep -qE "error|sorry"; then
    say "$f" "FAIL"; echo "$out" | head -20; fail=1; continue
  fi
  # Every `#print axioms` line must list only allowed axioms.
  bad=$(echo "$out" | grep "depends on axioms" \
        | sed -E 's/.*\[(.*)\].*/\1/' | tr ',' '\n' | tr -d ' ' \
        | grep -vE "^($ALLOWED)$" | sort -u)
  n=$(echo "$out" | grep -c "depends on axioms")
  if [ -n "$bad" ]; then
    say "$f" "FAIL — unexpected axioms: $(echo $bad | tr '\n' ' ')"; fail=1
  elif [ "$n" -eq 0 ]; then
    say "$f" "FAIL — no #print axioms assertions"; fail=1
  else
    say "$f" "verified ($n theorems, axioms clean)"
  fi
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
