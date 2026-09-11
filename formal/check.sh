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
#
# The `#print axioms` commands are GENERATED here, not read from the file.
#
# The previous version parsed whatever `#print axioms` lines the source
# happened to contain, which meant it only ever checked theorems that
# *volunteered* their axioms. A review planted this in Padding.lean:
#
#     axiom paddingIsAlwaysFree : ∀ (L x : List Nat), (padLadder L x).isSome
#     theorem sneaky (L x : List Nat) : (padLadder L x).isSome :=
#       paddingIsAlwaysFree L x
#
# with no `#print axioms sneaky` -- and the gate reported "axioms clean".
# The demonstration in MANUAL-TESTING §1d only ever worked because the planted
# cheat happened to print its own axioms. A gate you can opt out of is not a
# gate, so the list of names now comes from the declarations themselves.
ALLOWED='propext|Classical.choice|Quot.sound'
for f in lean/NasVerify/*.lean; do
  ns=$(grep -m1 '^namespace ' "$f" | awk '{print $2}')
  names=$(grep -oE '^ *(theorem|lemma) +[A-Za-z_][A-Za-z0-9_'"'"']*' "$f" \
          | awk '{print $NF}' | sort -u)
  if [ -z "$names" ]; then
    say "$f" "FAIL — no theorems found"; fail=1; continue
  fi
  probe=$(mktemp "${TMPDIR:-/tmp}/nas-axioms-XXXXXX.lean")
  cp "$f" "$probe"
  for n in $names; do
    if [ -n "$ns" ]; then echo "#print axioms $ns.$n" >> "$probe"
    else echo "#print axioms $n" >> "$probe"; fi
  done
  out=$(lean "$probe" 2>&1)
  rm -f "$probe"

  if echo "$out" | grep -qE "^.*error|declaration uses 'sorry'"; then
    say "$f" "FAIL"; echo "$out" | head -20; fail=1; continue
  fi
  bad=$(echo "$out" | grep "depends on axioms" \
        | sed -E 's/.*\[(.*)\].*/\1/' | tr ',' '\n' | tr -d ' ' \
        | grep -vE "^($ALLOWED)$" | sort -u)
  declared=$(echo "$names" | wc -w | tr -d ' ')
  printed=$(echo "$out" | grep -c "depends on axioms\|does not depend on any axioms")
  if [ -n "$bad" ]; then
    say "$f" "FAIL — unexpected axioms: $(echo $bad | tr '\n' ' ')"; fail=1
  elif [ "$printed" -lt "$declared" ]; then
    say "$f" "FAIL — $printed of $declared theorems reported axioms"; fail=1
  else
    say "$f" "verified ($declared theorems, axioms enumerated)"
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
# $2 is the module, defaulting to SlotConsistency so every existing call site
# reads as it did before LeaseGC arrived.
run() { java -Xmx2g -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 4 -nowarning -config "$1" "${2:-SlotConsistency}" 2>&1; }

# ForkAt ranges over every admissible divergence point, 1..MaxSeq: ForkAt=1 is
# a fork at genesis (branches share no prefix at all — see SlotConsistency.tla
# IsAncestor), ForkAt=MaxSeq is the latest possible fork (maximal shared
# prefix). Both ends are meaningful, not degenerate, so both are gated.
if [ "${DEEP:-0}" = "1" ]; then
  MAXSEQ=3
  FORK_CFGS="1:MC_full_fork1.cfg 2:MC_full.cfg 3:MC_full_fork3.cfg"
else
  MAXSEQ=2
  FORK_CFGS="1:MC_small_fork1.cfg 2:MC_small.cfg"
fi

for entry in $FORK_CFGS; do
  forkat=${entry%%:*}
  cfg=${entry#*:}
  label="SlotConsistency invariants (MaxSeq=$MAXSEQ, ForkAt=$forkat)"
  out=$(run "$cfg")
  if echo "$out" | grep -q "No error has been found"; then
    # Last match, not first: TLC prints a progress line per minute before the
    # final total, and formats large counts with thousands separators.
    n=$(echo "$out" | grep -oE "[0-9][0-9,]* distinct states" | tail -1)
    say "$label" "ok — $n"
  else
    say "$label" "FAIL"; echo "$out" | tail -60; fail=1
  fi
done

for inv in NeverForks NeverAlarms ForkAlwaysDetected; do
  for entry in "1:MC_${inv}_fork1.cfg" "2:MC_${inv}.cfg"; do
    forkat=${entry%%:*}
    cfg=${entry#*:}
    label="sanity: $inv (MaxSeq=2, ForkAt=$forkat)"
    out=$(run "$cfg")
    if echo "$out" | grep -q "Invariant $inv is violated"; then
      say "$label" "violated as required"
    else
      say "$label" "FAIL — model is VACUOUS"; fail=1
    fi
  done
done

# ── LeaseGC (SPECS §6) ────────────────────────────────────────────────────
# The write/sweep race, the notice window, and the retention floor. Much
# smaller than SlotConsistency, so CI affords two windowings and DEEP widens
# the windows rather than adding a third blob — a third blob does not finish
# inside ten minutes and buys nothing the second does not.
#
# `grace-expiry-notice` in the label is the CONSTANTS triple, and varying it is
# this model's equivalent of varying ForkAt above:
#   1-1-1  the tightest, and the windowing the must-FAIL checks below use;
#          cheapest, but with grace = notice it cannot tell §6.2's window
#          apart from §6.3's;
#   1-2-3  all three distinct, which is the windowing in which revision 6's
#          "these were one field" defect is visible at all;
#   2-2-1  a grace window more than one tick wide (DEEP only).
if [ "${DEEP:-0}" = "1" ]; then
  GC_CFGS="1-1-1:MC_LeaseGC_small.cfg 1-2-3:MC_LeaseGC_full.cfg 2-2-1:MC_LeaseGC_grace2.cfg"
else
  GC_CFGS="1-1-1:MC_LeaseGC_small.cfg 1-2-3:MC_LeaseGC_full.cfg"
fi

for entry in $GC_CFGS; do
  windows=${entry%%:*}
  cfg=${entry#*:}
  label="LeaseGC invariants (grace-expiry-notice $windows)"
  out=$(run "$cfg" LeaseGC)
  if echo "$out" | grep -q "No error has been found"; then
    # Same extraction as the SlotConsistency loop above, for the same reason:
    # last match, because the progress lines carry the same phrase.
    n=$(echo "$out" | grep -oE "[0-9][0-9,]* distinct states" | tail -1)
    say "$label" "ok — $n"
  else
    say "$label" "FAIL"; echo "$out" | tail -60; fail=1
  fi
done

# Non-vacuity for the CI bound, plus one negative control. EveryUploadGetsGrace
# holds in every windowing gated above; its cfg here sets TouchOnDedup = FALSE
# — the `BlobStore::put` that returned early without moving the mtime, which is
# what LeaseGC.tla was written against and found — and must then fail. Green
# above without red here would say nothing about the touch. See LeaseGC.tla.
for inv in NeverSweeps GraceIsRedundant NoticeIsRedundant \
           RenewalNeverRestores EveryUploadGetsGrace; do
  label="sanity: $inv (LeaseGC)"
  out=$(run "MC_LeaseGC_$inv.cfg" LeaseGC)
  if echo "$out" | grep -q "Invariant $inv is violated"; then
    say "$label" "violated as required"
  else
    say "$label" "FAIL — model is VACUOUS"; fail=1
  fi
done

# ── DeleteQuorum (SPECS §16.2) ────────────────────────────────────────────
# Self-contained: its own runner, its own configs, nothing shared above.
#
# The deletion loop rests on three checks — the request-hash binding plus the
# collapse of approvers by key id (`DeleteExecution::verify`, `decide`), the
# offline authority (`Authority`), and the approver device's own clock
# (`Approver::may_sign`). Each one is REMOVED in a sanity configuration below,
# so a green run is attributable to the check rather than to the shape of the
# protocol. Three further sanity checks establish that the model reaches its
# interesting states at all: deletions execute, a full escalated quorum of
# distinct authority members is reachable on one request, and there are states
# in which a member holds the request but has not yet matured — the window in
# which back-dating would pay, and without which NoEarlyApproval is vacuous.
run_dq() { java -Xmx4g -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
             -workers 4 -nowarning -config "$1" DeleteQuorum 2>&1; }

if [ "${DEEP:-0}" = "1" ]; then
  DQ_CFGS="small:MC_DeleteQuorum_small.cfg deep:MC_DeleteQuorum.cfg"
else
  DQ_CFGS="small:MC_DeleteQuorum_small.cfg"
fi

for entry in $DQ_CFGS; do
  size=${entry%%:*}
  cfg=${entry#*:}
  case $size in
    small) label="DeleteQuorum invariants (3-slot bundles)" ;;
    deep)  label="DeleteQuorum invariants (4-slot bundles)" ;;
  esac
  out=$(run_dq "$cfg")
  if echo "$out" | grep -q "No error has been found"; then
    # Last match, not first: TLC repeats the phrase on its per-minute progress
    # line, and only the final summary carries the total.
    n=$(echo "$out" | grep -oE "[0-9][0-9,]* distinct states" | tail -1)
    say "$label" "ok — $n"
  else
    say "$label" "FAIL"; echo "$out" | tail -60; fail=1
  fi
done

for entry in NeverExecutes:NeverExecutes \
             NeverReachesQuorum:NeverReachesQuorum \
             NeverPending:NeverPending \
             replay:NoReplayCountsTwice \
             minted:NoExecutionWithoutQuorum \
             backdate:NoEarlyExecution; do
  cfgname=${entry%%:*}
  inv=${entry#*:}
  label="sanity: DeleteQuorum $cfgname"
  out=$(run_dq "MC_DeleteQuorum_${cfgname}.cfg")
  if echo "$out" | grep -q "Invariant $inv is violated"; then
    say "$label" "violated as required ($inv)"
  else
    say "$label" "FAIL — model is VACUOUS"; fail=1
  fi
done
popd >/dev/null

echo "──────────────────────────────────────────────────────────────────"
[ $fail -eq 0 ] && echo "formal: PASS" || echo "formal: FAIL"
exit $fail
