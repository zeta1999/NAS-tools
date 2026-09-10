# Formal verification for NAS-tools

Mirrors the layout of `../../seal-dao-public/formal/`.

## Status, stated honestly

Run `./check.sh` — it fetches `tla2tools.jar` if absent and gates everything.
The default gate is SlotConsistency at MaxSeq=2 plus LeaseGC at its tightest
windowing, and takes about a minute end to end; `DEEP=1 ./check.sh` is MaxSeq=3
and two wider LeaseGC windowings, and takes ~13 minutes on a laptop, almost all
of it in SlotConsistency's ForkAt=1 run.

| Artefact | Tool | State |
|---|---|---|
| `lean/NasVerify/Transcript.lean` | Lean 4.28 | **VERIFIED** — 3 theorems, 0 admitted, axioms clean |
| `lean/NasVerify/Padding.lean` | Lean 4.28 | **VERIFIED** — 11 theorems, 0 admitted, axioms clean. Models the *ladder* (closing the gap where `Nat` truncation hid a `usize` underflow) and the reader's strict check (closing the class-selection covert channel the M0 review found) |
| `tlaplus/SlotConsistency.tla` | TLA+ / TLC | **MODEL-CHECKED**, revision 3 — but note it constrains §5, which is **M2** code; it is assurance about the design, not about anything shipped in M0. `ForkAt` (the sequence number at which branch "b" diverges) is varied over every admissible point, `1..MaxSeq`, not fixed at one value — see [Varying `ForkAt`](#varying-forkat) below. CI gate, MaxSeq=2: ForkAt=1 337,817 distinct states, depth 25 (~3 s); ForkAt=2 38,709 distinct states, depth 20 (~1 s). Deep gate (`DEEP=1`), MaxSeq=3: ForkAt=1 38,366,601 distinct states from 570.7 M generated, depth 35; ForkAt=2 4,699,837 distinct states from 60.1 M generated, depth 30; ForkAt=3 443,429 distinct states, depth 25. **5** invariants + 1 action property hold at every (MaxSeq, ForkAt) pair. Revision 3 changed what is *derived* from the state, not the state space, so every count above is unchanged from revision 2 — measured, not assumed. |
| sanity checks | TLA+ / TLC | **3 required counterexamples found, at both ForkAt=1 and ForkAt=2** — the model is not vacuous at either end of the admissible range |
| `tlaplus/LeaseGC.tla` | TLA+ / TLC | **MODEL-CHECKED** — the write/sweep race of SPECS §6, transcribed from `crates/nas-lease/src/sweep.rs`, which is M0 code that ships. 7 invariants hold at every windowing gated. CI gate: grace-expiry-notice 1-1-1 — 242,988 distinct states from 2,578,505 generated, depth 23 (~13 s); 1-2-3 — 652,268 distinct from 6,914,841 generated, depth 30 (~26 s). Deep gate (`DEEP=1`) adds 2-2-1 — 1,345,944 distinct from 15,186,524 generated, depth 25 (~50 s). The state counts are exact; the times were measured on a laptop running three other TLC jobs and are therefore upper bounds. It also **found a real gap** between §6.2 and the code — see [What `LeaseGC.tla` found](#what-leasegctla-covers-and-what-it-found) |
| LeaseGC sanity checks | TLA+ / TLC | **5 required counterexamples found** at the CI bound — `NeverSweeps`, `GraceIsRedundant`, `NoticeIsRedundant`, `RenewalNeverRestores`, `EveryUploadGetsGrace`. The last is the finding, not a formality |

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

### The defect revision 3 caught, which is defect 1 in a mirror

The fix for defect 3 gave the client `Compatible` — a *global* ancestry
relation that answers for any two versions using branch structure nobody ever
sent it. Defect 1 was evidence lost; this was evidence **assumed**, and it is
the harder one to notice, because the model goes green either way. What it
meant in practice: TLC was checking a detection rule `nas-slots` could not run,
and `client.rs` said so in its own header rather than pretending otherwise.

The fix has two halves, and they match the Rust one for one:

- a witness records its version **and that version's predecessor** — one edge
  of the chain (`Pred`), which is `record_hash` plus the observed record's own
  `prev` in `crates/nas-slots/src/witness.rs`;
- detection is `KnownIncompatible`, which walks back only along edges in
  `known[c]` (`Named`). A missing link is a **gap**: the walk stops and raises
  nothing.

`ForkDetected` carries the hypothesis in its antecedent — `Linked(known[c1], …)`
— so it now says *incompatible evidence raises once the linking witnesses are
known*, which is what the design delivers and no more. `NoFalseAlarm` is the
fifth invariant and states the other direction: evidence that is genuinely all
on one history never raises. That is the property the Rust module defends in
its tests, and the one a "detect more" change would quietly break.

`Compatible` survives as the yardstick the invariants are stated against. It is
never something a client evaluates.

### Varying `ForkAt`

`ForkAt` is a CONSTANT: the sequence number at which branch "b" first diverges
from "a". Earlier revisions fixed it at 2 in every config, so the model never
explored forks originating anywhere else. It is now varied over the full
admissible range, `1..MaxSeq`, at both bounds:

- **CI gate** (`./check.sh`, MaxSeq=2): `MC_small_fork1.cfg` (ForkAt=1) and
  `MC_small.cfg` (ForkAt=2).
- **Deep gate** (`DEEP=1 ./check.sh`, MaxSeq=3): `MC_full_fork1.cfg` (ForkAt=1),
  `MC_full.cfg` (ForkAt=2), and `MC_full_fork3.cfg` (ForkAt=3).

Both ends of the range turned out to be meaningful, not degenerate, once
worked out from `Versions` and `IsAncestor`:

- **`ForkAt=1`** is a fork **at genesis**. `Versions` becomes
  `v[2] = "a" \/ v[1] >= 1`, which is every `(seq, branch)` pair — branch "b"
  exists at every sequence number, not just from the fork point on. And in
  `IsAncestor`, the shared-prefix clause `v1[2] = "a" /\ v2[2] = "b" /\
  v1[1] < ForkAt` can never fire, because no `v1[1] \in 1..MaxSeq` is `< 1`.
  So "a" and "b" share **no** common ancestor at all: this is two chains that
  diverge as early as they possibly can, immediately after the first
  `Publish`. `PeerForks`'s `\E s \in ForkAt..MaxSeq` is non-empty (`1..MaxSeq`),
  and TLC reaches it — the model handles this case correctly, and it is the
  structurally distinct regime where the "shared prefix" the model's own
  comments describe is, for once, empty.
- **`ForkAt=MaxSeq`** is the latest possible fork: `\E s \in ForkAt..MaxSeq`
  narrows to the single point `{MaxSeq}`, and the shared prefix is maximal
  (everything below `MaxSeq` is common ancestry). Checked at MaxSeq=3 as
  `MC_full_fork3.cfg`; not checked separately at MaxSeq=2 because there
  `ForkAt=2` (the pre-existing default) already *is* `MaxSeq`.

The sanity (must-FAIL) checks are cheap at MaxSeq=2 (under a few seconds each),
so they now also run at both ForkAt=1 and ForkAt=2: `MC_NeverForks_fork1.cfg`,
`MC_NeverAlarms_fork1.cfg`, `MC_ForkAlwaysDetected_fork1.cfg` alongside the
existing `MC_NeverForks.cfg`, `MC_NeverAlarms.cfg`, `MC_ForkAlwaysDetected.cfg`.
All six must produce a counterexample, or the corresponding bound is vacuous.

### What `LeaseGC.tla` covers, and what it found

`LeaseGC.tla` is the write/sweep race of SPECS §6: a client uploads a blob and
takes the lease that protects it in two separate round trips, the sweeper is
synchronised with neither, and §6.2's young-blob grace is what is supposed to
close the window between them. Unlike `SlotConsistency.tla` the peer here is
**honest** — a peer that wants your data gone deletes it, which §16's preamble
says in as many words and §5.4 argues at length — so what is checked is that
the policy an honest peer computes never contradicts the protection §6
promises.

The sweep predicate is transcribed from `plan_sweep` in
`crates/nas-lease/src/sweep.rs` rather than from the prose, guard for guard and
in the same order, and the module header carries the correspondence table with
a "Faithful?" column, in the style of `crates/nas-slots/src/client.rs`.

**Modelled:** the upload/take-lease race; lease lapse and the post-expiry
notice window; renewal as a side effect of sync (a take is a union that stamps
`last_seen`, so a take of nothing renews); warn-before-sweep; the retention
floor and the authenticated `forget` that is the only thing allowed to lift it.

Seven invariants hold at every windowing gated — `TypeOK`,
`LiveLeaseNeverSwept`, `GraceProtectsTheYoung`, `NoticeProtectsTheAbsent`,
`FloorNeedsForget`, `RenewalRestoresProtection`, `WarnedBeforeSwept` — and five
checks are asserted **expecting failure**:

| Check | Must fail because |
|---|---|
| `NeverSweeps` | the sweeper must be able to delete something at all |
| `GraceIsRedundant` | the race state must be reachable: a blob present, its lease not yet recorded, and nothing but §6.2's grace between it and the sweeper |
| `NoticeIsRedundant` | a blob kept alive by nothing but a lapsed lease must be reachable, or `NoticeProtectsTheAbsent` is about a state that never occurs |
| `RenewalNeverRestores` | a lapsed holder must be able to become active again by syncing, or `RenewalRestoresProtection` quantifies over nothing |
| `EveryUploadGetsGrace` | **the finding** — §6.2's grace is keyed to the blob file's mtime, which a deduplicated upload does not move. See below |

**Deliberately abstracted**, and therefore not claimed:

- §6.1's delta chains, checkpoints and Merkle roots. Each holder's replayed set
  is taken as given; `set.rs::replay` earns that, and its integrity is a
  signature question, not an ordering one.
- §6.4 quotas — `max_leased_bytes` is reported, never enforced by deleting, so
  it has no data-loss path.
- Blob sizes, epochs, holder authentication, and lease release (§16.2's
  explicit act, which belongs to `DeleteQuorum.tla`).
- Clocks are monotone saturating *ages*, one per blob and per holder, each
  saturating at the largest threshold it is compared against. That is what
  makes the state space finite with no artificial time horizon, and it is also
  why the backwards-clock defence (`Timestamp::saturating_since`, and the
  `a_backwards_clock_does_not_expire_everything` test) is **not** exercised
  here.
- `Peer::sweep` plans and deletes inside one call, so the model's `Sweep`
  applies the whole plan in one step. A plan computed and acted on later — the
  `dry_run` path a human looks at — is not modelled.

**The finding.** `EveryUploadGetsGrace` is asserted expecting failure, and the
counterexample is a real gap between §6.2 and the code rather than a modelling
formality. §6.2 says "any blob uploaded within `grace_period` is **immune from
sweep regardless of leases**". The implementation keys that immunity to the
blob file's mtime (`Peer::inventory` reads `fs::metadata(..).modified()` as
`uploaded_at`), and `BlobStore::put` returns early **without touching the file**
when the address is already present. So an upload that deduplicates gets no
grace at all: the clock it is measured against never restarted. Under
convergent encryption (§3.2) a second client uploading identical ciphertext
takes exactly that path, and so does one client retrying after a crash — which
is the very case §6.2 names. TLC reaches it in five states: upload, tick past
the grace, upload the same address again, sweep; the blob goes while the client
is still inside the window it was promised, and the `take_lease` that was about
to follow fails with `NoSuchBlob`. The model keeps two clocks per blob for
this: `age` (the peer's mtime, what the code enforces) and `offered` (when a
client last handed the bytes over, what §6.2 is written about).

Two further places where code and spec disagree are recorded in the module
header and modelled as the code has it: there is no authenticated `forget`
path at all (`publish_retention` refuses *every* shrink, so the model's
`Forget` is more permissive than the peer), and a stale doc comment at
`crates/nas-cli/src/roaming.rs:232-234` says `expiry + grace` where §6.3 and
that function's own code both say `expiry + notice`.

Varying the `grace-expiry-notice` triple is this model's equivalent of varying
`ForkAt` above. `MC_LeaseGC_small.cfg` (1-1-1) is the tightest and cheapest,
and the windowing the five must-FAIL checks use; with grace = notice it cannot
tell §6.2's window apart from §6.3's, so `MC_LeaseGC_full.cfg` (1-2-3) gives
all three distinct values — the windowing in which revision 6's "these were one
field" defect would be visible at all — and both run in CI.
`MC_LeaseGC_grace2.cfg` (2-2-1), where the grace window is more than a single
tick wide, runs under `DEEP=1`.

### Why the sanity checks matter as much as the invariants

A green model check proves nothing if the model cannot reach an interesting
state. Three properties are therefore asserted **expecting failure**, and
`check.sh` fails the build if any of them starts passing:

| Check | Must fail because |
|---|---|
| `NeverForks` | forks must be reachable, or `ForkDetected` is trivially true |
| `NeverAlarms` | alarms must be reachable, or detection is never exercised |
| `ForkAlwaysDetected` | **SPECS §5.4 claims detection, explicitly not prevention.** TLC finds a short trace where a peer withholds every witness and two clients stay forked with nobody alarmed. If this ever *passed*, we would have accidentally claimed a guarantee this architecture cannot deliver. Revision 3 gives the peer a second and more realistic way to win it: relay *some* witnesses, but not the ones that link two heads — detection then stalls at a gap rather than at silence. |

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
- **`LeaseGC.tla`** *(written)* — the write/sweep race. Question: is there any
  interleaving where a blob is uploaded, referenced by a published manifest, and
  still swept? The young-blob grace period (SPECS §6.2) exists to prevent it, and
  a grace period is exactly the kind of thing that is *almost* long enough.
  **It is**, for a first upload: nothing protected by a live lease, by the
  grace, by the notice window or by the retention floor is ever swept, at every
  windowing gated. For a *deduplicated* upload it is not, because the grace is
  measured from the blob file's mtime and `BlobStore::put` does not touch a file
  it already has. See [What `LeaseGC.tla` covers, and what it
  found](#what-leasegctla-covers-and-what-it-found).
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
java -cp tla2tools.jar tlc2.TLC -config MC_LeaseGC_small.cfg LeaseGC
```
