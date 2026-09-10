# Formal verification for NAS-tools

Mirrors the layout of `../../seal-dao-public/formal/`.

## Status, stated honestly

Run `./check.sh` — it fetches `tla2tools.jar` if absent and gates everything.
The default gate is MaxSeq=2 and takes seconds; `DEEP=1 ./check.sh` is MaxSeq=3
and takes ~11 minutes on a laptop, almost all of it in the ForkAt=1 run.
`DeleteQuorum` adds ~25 s to the default gate and its own ~11 minutes to
`DEEP=1`; its sanity checks are all under a second, since each one is looking
for a counterexample it finds in single-digit steps.

| Artefact | Tool | State |
|---|---|---|
| `lean/NasVerify/Transcript.lean` | Lean 4.28 | **VERIFIED** — 3 theorems, 0 admitted, axioms clean |
| `lean/NasVerify/Padding.lean` | Lean 4.28 | **VERIFIED** — 11 theorems, 0 admitted, axioms clean. Models the *ladder* (closing the gap where `Nat` truncation hid a `usize` underflow) and the reader's strict check (closing the class-selection covert channel the M0 review found) |
| `tlaplus/SlotConsistency.tla` | TLA+ / TLC | **MODEL-CHECKED** — but note it constrains §5, which is **M2** code; it is assurance about the design, not about anything shipped in M0. `ForkAt` (the sequence number at which branch "b" diverges) is varied over every admissible point, `1..MaxSeq`, not fixed at one value — see [Varying `ForkAt`](#varying-forkat) below. CI gate, MaxSeq=2: ForkAt=1 337,817 distinct states, depth 25 (~3 s); ForkAt=2 38,709 distinct states, depth 20 (~1 s). Deep gate (`DEEP=1`), MaxSeq=3: ForkAt=1 38,366,601 distinct states from 570.7 M generated, depth 35 (~10 min); ForkAt=2 4,699,837 distinct states from 60.1 M generated, depth 30 (~1 min); ForkAt=3 443,429 distinct states, depth 25 (~7 s). 4 invariants + 1 action property hold at every (MaxSeq, ForkAt) pair. |
| sanity checks | TLA+ / TLC | **3 required counterexamples found, at both ForkAt=1 and ForkAt=2** — the model is not vacuous at either end of the admissible range |
| `tlaplus/DeleteQuorum.tla` | TLA+ / TLC | **MODEL-CHECKED** — the §16.2 deletion loop against a hostile executor that assembles the `DeleteExecution` bundle itself, out of every approval record that exists, in any multiplicity: replay and re-targeting are behaviours of the model, not things it assumes away. Constrains `crates/nas-delete` (`decide`, `DeleteExecution::verify`, `Approver::may_sign`), which is **M2** code. 6 invariants + 1 step property. CI gate (3 authority members, 1 minted key, 2 requests, cooling-off 2, bundles of 3): 1,326,144 distinct states from 7,889,266 generated, depth 22 (~24 s). Deep gate (`DEEP=1`, bundles of 4 — room to pad a full quorum with a replayed record): **the same 1,326,144 distinct states** from 12,793,312 generated, depth 22 (11 min 31 s). See [DeleteQuorum](#deletequorum-the-deletion-approval-loop-specs-162) |
| DeleteQuorum sanity checks | TLA+ / TLC | **6 required counterexamples found** — three reachability, and three *negative controls* that switch off one defence apiece (the request-hash binding, the offline authority, the approver's own clock) and must then break the invariant that defence carries |

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

### DeleteQuorum: the deletion approval loop (SPECS §16.2)

`tlaplus/DeleteQuorum.tla` models the four steps of §16.2 — `DeleteRequest`,
cooling-off, m × `DeleteApproval` from distinct holders, `DeleteExecution` — as
`crates/nas-delete` implements them (`decide`, `DeleteExecution::verify`,
`Approver::may_sign`), with the peer's append-only trail from
`crates/nas-peer/src/peer.rs`. It also carries §16.2's two policy dials: quorum
by blast radius (`QuorumSmall`/`QuorumWide`, i.e. `QuorumPolicy::base`) and the
rolling escalation that makes decomposition expensive.

#### What the adversary may do

Everything short of forging an ML-DSA signature.

- **The executor is hostile and assembles the bundle itself.** `Bundles` is a
  *sequence* over every approval record that exists, so the same record may
  occupy two slots (**replay**) and a record signed over request `r1` may sit
  in a bundle for `r2` (**re-targeting**). Nothing filters the bundle before
  the verifier sees it; the verifier's own two checks are all that stand there.
- **The relay back-dates.** §16.1 puts the approving key on an offline device,
  so approvals are signed there and carried by whatever machine has a
  connection — and that machine may assert any `first_seen` it likes, `0`
  included. `Approve` ignores the assertion and reads `seen[m][r]`, the
  device's own stamp. This mirrors the Rust exactly: `Approver::approve` takes
  `first_seen` from the device, never from the record it is judging.
- **The laptop mints keys.** `Outsiders` are freshly generated keypairs whose
  approvals are genuine, valid and pairwise distinct — they are simply not in
  the authority. This is the defect STATUS.md records: `decide` once counted
  *distinct approvers* and stopped there, which is a headcount, not a quorum.
- **The executor may fire at any tick,** tick 0 included. The early-execution
  bypass is not forbidden by the model; the action is simply never enabled
  until the approvals it needs exist, which is the entire claim.

#### Six invariants, and three of them are negative-controlled

| Invariant | Says |
|---|---|
| `TypeOK` | — |
| `NoExecutionWithoutQuorum` | an executed request had, in the trail, at least as many distinct *authority* members signing *it* as the policy owed at that tick — base quorum, or the rolling escalation if the window had tripped |
| `NoReplayCountsTwice` | the count the verifier actually used never exceeds the number of distinct authority members who signed that very request |
| `NoEarlyApproval` | no authority approval exists that its own device could not have signed: the cooling-off had elapsed against that device's own stamp |
| `NoEarlyExecution` | at the tick a deletion executed, a full quorum had *each* been sitting on the request for at least the cooling-off, by their own clocks |
| `TrailComplete` / `TrailMonotonic` | an executed deletion still has its request record and its authorising approvals, and no transition ever shortens the trail, restamps an execution, or rewrites a device's arrival stamp |

`NoReplayCountsTwice` is the one that needed care. It is checked against a
recorded value (`countedAt`), not inferred: `Execute` writes down the number
the verifier arrived at, so an inflated count is *visible to an invariant*
rather than something the model would have to assume away. Modelling the
bundle as a set instead would have made replay impossible by construction —
which is assuming the property, not checking it.

#### The three defences are switches, and each is turned off in a sanity config

This is what makes the green run attributable. The invariants above are not
true of the protocol's shape; they are true *because of* three checks, and
`check.sh` proves it by removing them one at a time and requiring TLC to break
the corresponding invariant.

| Config | Switch | Must violate | Counterexample TLC finds |
|---|---|---|---|
| `MC_DeleteQuorum_replay.cfg` | `StrictApprovalCheck = FALSE` | `NoReplayCountsTwice` | 7 states: one genuine approval `<<r1, m1>>` exists, the executor presents it twice, and the execution records a count of **2** against **1** real signer |
| `MC_DeleteQuorum_minted.cfg` | `StrictAuthority = FALSE` | `NoExecutionWithoutQuorum` | 4 states: at tick 0 a minted key `x1` signs, and the deletion executes on **zero** authority approvals — §16.1's claim failing in four steps |
| `MC_DeleteQuorum_backdate.cfg` | `EnforceCoolOff = FALSE` | `NoEarlyExecution` | 5 states: the back-dated `first_seen` is believed, a quorum lands at tick 0, and the deletion executes with the cooling-off untouched |

Three further sanity checks establish that the model reaches its interesting
states at all: `NeverExecutes` (deletions do execute), `NeverReachesQuorum` (a
full *escalated* quorum of three distinct authority members is reachable on one
request), and `NeverPending` (there are states where a member has the request
in hand and has not yet matured — the window in which back-dating would pay; if
it were empty, `NoEarlyApproval` would be vacuous).

#### State counts

| Config | Distinct states | Generated | Depth | Wall |
|---|---|---|---|---|
| `MC_DeleteQuorum_small.cfg` (CI gate) | 1,326,144 | 7,889,266 | 22 | ~24 s |
| `MC_DeleteQuorum.cfg` (`DEEP=1`) | 1,326,144 | 12,793,312 | 22 | 11 min 31 s |

**Those two numbers being identical is the result, not a copy-paste.** The deep
gate differs from the CI gate in exactly one constant: `MaxSlots` 3 → 4, a
bundle with room for a full escalated quorum of three *plus a fourth record*.
It generates 4.9 M more states trying that padding and reaches **not one
reachable state** the three-slot gate did not. Padding a legitimate quorum with
a replayed or re-targeted approval buys the executor nothing, measured rather
than argued.

Deepening the clock or the authority instead was tried and does not fit a
gate: `Roster = 4` (MaxTime 3) reached 10,100,242 distinct states at depth 16
with the queue still growing after ten minutes, and `MaxTime = 4` (Roster 3)
reached 4,445,440 at depth 17. No invariant was violated in either, but neither
completed, so neither is claimed here.

#### What this model deliberately does NOT claim

That the *protocol* enforces the cooling-off. SPECS §16.2 is explicit —
"cooling-off is enforced by the approver devices, against their own local
clocks… nothing in the protocol can enforce it" — because there is no trusted
time source anywhere in this design. So `NoEarlyExecution` is a statement about
a quorum of **honest approver devices**. `MC_DeleteQuorum_backdate.cfg` is what
it looks like when one of them is not, and the counterexample it produces is
the honest statement of the limit, in the same spirit as `ForkAlwaysDetected`
above.

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
- **`DeleteQuorum.tla`** *(written)* — the deletion authorisation loop (SPECS
  §16.2, not §17: this bullet named the wrong section before the model was
  built). It answers the three questions it was written to ask — data cannot
  be deleted with fewer than m approvals from the offline authority, an
  approval for one request cannot be replayed or re-targeted into another, and
  no re-submission reaches the executor before a quorum of approver devices
  have each let their own cooling-off elapse. What it deliberately does not
  claim is that the *protocol* enforces cooling-off; see
  [DeleteQuorum](#deletequorum-the-deletion-approval-loop-specs-162) below.

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
