# Formal verification for NAS-tools

Mirrors the layout of `../../seal-dao-public/formal/`.

## Status, stated honestly

Run `./check.sh` — it fetches `tla2tools.jar` if absent and gates everything.

| Artefact | Tool | State |
|---|---|---|
| `lean/NasVerify/Transcript.lean` | Lean 4.28 | **VERIFIED** — 3 theorems, 0 admitted, axioms clean |
| `lean/NasVerify/Padding.lean` | Lean 4.28 | **VERIFIED** — 10 theorems, 0 admitted, axioms clean. Models the *ladder* (closing the gap where `Nat` truncation hid a `usize` underflow) and the reader's strict check (closing the class-selection covert channel the M0 review found) |
| `tlaplus/SlotConsistency.tla` | TLA+ / TLC | **MODEL-CHECKED** — but note it constrains §5, which is **M2** code; it is assurance about the design, not about anything shipped in M0. — MaxSeq=2: 38,709 distinct states, depth 20 (<1 s, the CI gate). MaxSeq=3: **4,699,837 distinct states from 60.1 M generated, depth 30, 46 s** (the deep gate). 4 invariants + 1 action property hold at both bounds. |
| sanity checks | TLA+ / TLC | **3 required counterexamples found** — the model is not vacuous |

### What the model check actually caught

Revision 1 of `SlotConsistency.tla` was written, honestly labelled unchecked, and
then **failed TLC in 7 states**. Three defects, each of which would have shipped
as a client bug:

1. **Evidence was evaluated only on arrival.** A witness relayed to a client that
   had not yet pinned anything was dropped by a `pinSeq[c] > 0` guard and never
   reconsidered — so a fork could cross between two clients and raise no alarm.
   This is the interesting one, because it is not a modelling slip: "handle the
   event, then forget it" is exactly what an implementation does by default.
   The fix is structural — `known` accumulates every version a client learns of
   and `Alarm` is a *derived predicate* over that set, so evidence is
   re-evaluated on every transition and can never be consumed-and-lost.
2. **`anchor` was initialised to 0 and never assigned**, making the
   freshness-anchor branch dead code and `AnchorFloor` vacuously true.
3. **Compatibility was branch equality**, so divergence at *different* sequence
   numbers was invisible. Replaced with a real ancestry relation over a shared
   prefix.

### Why the sanity checks matter as much as the invariants

A green model check proves nothing if the model cannot reach an interesting
state. Three properties are therefore asserted **expecting failure**, and
`check.sh` fails the build if any of them starts passing:

| Check | Must fail because |
|---|---|
| `NeverForks` | forks must be reachable, or `ForkDetected` is trivially true |
| `NeverAlarms` | alarms must be reachable, or detection is never exercised |
| `ForkAlwaysDetected` | **SPECS §5.4 claims detection, explicitly not prevention.** TLC finds a 6-state trace where a peer withholds every witness and two clients stay forked with nobody alarmed. If this ever *passed*, we would have accidentally claimed a guarantee this architecture cannot deliver. |

That last row is the one worth internalising: the counterexample is not a
failure, it is **positive evidence that the specification says what the prose
says it says**.

A specification nobody ran is a design document with angle brackets.

### The `sorry` trap

`../../simple-network/proofs/lean4/` currently contains:

```lean
theorem eventual_consistency : True := by sorry
```

This is doubly empty: the statement is `True`, which says nothing, and the proof
is `sorry`, which proves nothing. It reads like verification from the outside and
carries none. **CI must reject `sorry`, and any deliberately admitted lemma must
be listed here as admitted.** We would rather have three real theorems than
thirty admitted ones.

## What goes where, and why

Different tools answer different questions. Picking the wrong one wastes weeks.

### TLA+ — concurrency and adversarial interleaving

Use when the bug would be *an ordering*, not a calculation. TLC explores every
interleaving, including the ones nobody thought to test.

- **`SlotConsistency.tla`** *(written)* — a malicious peer that replays old
  versions, refuses to enforce CAS, and withholds witnesses. Establishes that an
  honest client never silently regresses, that a capability's freshness anchor
  protects a *fresh* client with no pin of its own, and that a fork is detected
  once a witness crosses. Deliberately does **not** claim fork prevention: a peer
  that withholds forever must remain an admissible behaviour of the model.
- **`LeaseGC.tla`** *(planned)* — the write/sweep race. Question: is there any
  interleaving where a blob is uploaded, referenced by a published manifest, and
  still swept? The young-blob grace period (SPECS §6.2) exists to prevent it, and
  a grace period is exactly the kind of thing that is *almost* long enough.
- **`DeleteQuorum.tla`** *(planned)* — the deletion authorisation loop (SPECS
  §17). Questions: can data be deleted with fewer than m approvals? Can an
  approval for one request be replayed against a different one? Can the
  cooling-off clock be bypassed by re-submitting?

### Lean 4 — pure properties that are theorems, not protocols

Use when the property is about data and functions, holds for all inputs, and has
no notion of time or concurrency.

- **`Transcript.lean`** *(verified)* — the length-prefixed encoding is injective,
  so a signature over a transcript commits to exactly one reading of its field
  boundaries. This is the formal counterpart of the `transcript_encoding_is_unambiguous`
  test in `simple-network`, and the property the whole transcript-binding fix
  rests on. Also proves padding is reversible **unconditionally** — a wrong size
  class can leak more length information than intended, but can never make a
  chunk unrecoverable.
- *(planned)* Merkle proof soundness for lease checkpoints and slot skip-chains:
  verification succeeding implies membership.

### Property tests — implementation behaviour

`proptest` in the Rust crates. Round-trips (chunk → pad → encrypt → decrypt →
unpad → unchunk), dedup invariants, manifest encode/decode. Cheaper than a proof
and catches the same class of bug at the implementation level, where the proof
does not reach.

### Fuzzing — untrusted input

`cargo-fuzz` over every parser that consumes bytes from a peer: manifests, slot
records, lease deltas, wire messages. This is the highest value per hour of
anything in this directory, because it is the exact surface a malicious peer
attacks, and it needs no specification at all.

## What we deliberately do NOT formalise

- **The cryptographic primitives.** ML-KEM, ML-DSA, XChaCha20-Poly1305 and BLAKE3
  are used as vetted implementations. Proving them here would be theatre.
- **The system end-to-end.** Nobody finishes that, and the half-finished version
  is worse than nothing because of what it implies.
- **Anything a property test covers better.** A round-trip is a `proptest`, not a
  theorem.

## Running

```sh
# Lean — works today
cd lean && lean NasVerify/Transcript.lean

# TLA+ — needs tla2tools.jar (not vendored; fetch from the tlaplus releases)
java -cp tla2tools.jar tlc2.TLC -config MC_SlotConsistency.cfg MC_SlotConsistency
```
