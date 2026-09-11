-------------------------------- MODULE LeaseGC --------------------------------
(***************************************************************************)
(* Garbage collection by lease for a NAS-tools peer (SPECS.md §6).         *)
(*                                                                         *)
(* The question the TODO asked: is there an interleaving in which a client *)
(* uploads a blob and the sweeper takes it away before the lease that      *)
(* protects it has been recorded? Upload and take-lease are two separate   *)
(* round trips (`Peer::put_blob` then `Peer::take_lease`), and the sweeper *)
(* is synchronised with neither. §6.2's young-blob grace exists to close   *)
(* exactly that window, and a grace period is the kind of thing that is    *)
(* almost long enough.                                                     *)
(*                                                                         *)
(* THE PEER IS HONEST HERE. Unlike SlotConsistency, this model does not    *)
(* explore a malicious peer: a peer that wants your data gone deletes it,  *)
(* and no lease protocol prevents that — §16's preamble says so in as many *)
(* words, and §5.4 is where detection-not-prevention is argued.            *)
(* What is checked is that the policy an *honest* peer computes never      *)
(* contradicts the protection §6 promises — that the bug is not in the     *)
(* ordering.                                                               *)
(*                                                                         *)
(* WHAT TLC FOUND. One real gap: `EveryUploadGetsGrace` failed.            *)
(* §6.2 says "any blob uploaded within `grace_period` is immune from sweep *)
(* regardless of leases". The implementation keys that immunity to the     *)
(* blob file's mtime (`Peer::inventory` reads `metadata(..).modified()`    *)
(* as `uploaded_at`), and `BlobStore::put` returned early without touching *)
(* the file when the address was already present. So a client that uploads *)
(* content the peer already holds — a case convergent encryption (§3.2)    *)
(* makes routine, and the exact case where the client is about to take a   *)
(* lease it does not yet hold — got no grace at all. TLC reached it in     *)
(* five states. CLOSED: `put` and `prove` now touch the file, and the      *)
(* `TouchOnDedup` constant keeps the old behaviour checkable as a negative *)
(* control. See `EveryUploadGetsGrace` at the foot of this file.           *)
(*                                                                         *)
(* Correspondence with the Rust. `crates/nas-lease/src/sweep.rs` is the    *)
(* only code in the system that deletes a user's data; every row below was *)
(* transcribed from it rather than from the prose, and where the two       *)
(* disagree the disagreement is recorded rather than resolved.             *)
(*                                                                         *)
(* | Model | Rust | Faithful? |                                            *)
(* |---|---|---|                                                           *)
(* | `Upload(b)` | `Peer::put_blob` -> `BlobStore::put`, and `Peer::prove` *)
(*   for the client that skips its upload (§4.5) | yes — `age` (the peer's *)
(*   mtime) and `offered` (when a client last handed the bytes over) are   *)
(*   two clocks, and `TouchOnDedup` is whether the code moves both |       *)
(* | `TakeLease(h,S)` | `Peer::take_lease` | partly — the union and the    *)
(*   `last_seen := now` stamp are exact; `S \subseteq stored` stands for   *)
(*   `PeerError::NoSuchBlob`; the §6.4 quota refusal is not modelled |     *)
(* | `Tick` | the caller's `now` vs `Timestamp::saturating_since` | partly *)
(*   — monotone only, so the backwards-clock defence is NOT exercised here *)
(*   (`a_backwards_clock_does_not_expire_everything` covers it in Rust) |  *)
(* | `Retain(b)` | `Peer::extend_retention` | yes |                        *)
(* | `Forget(b)` | *nothing* | **no** — see the discrepancy note below |   *)
(* | `Active(h)`, `Expiring(h)` | `Holder::status` | yes, `<=` at both     *)
(*   bounds |                                                              *)
(* | `MaySweep(b)` | the guard cascade in `plan_sweep` | yes, same order   *)
(*   and the same strict `<` on grace |                                    *)
(* | `Sweep` | `Peer::sweep` | yes — the whole plan in one step, because   *)
(*   that call plans and deletes without releasing anything between, and   *)
(*   it leaves `self.leases` untouched, as this does |                     *)
(* | `Warned(h)` | `SweepPlan::warnings` | yes — built from a separate     *)
(*   predicate here, as it is a separate loop there |                      *)
(* | `LiveLeaseNeverSwept` | `Keep::Leased` | yes |                        *)
(* | `GraceProtectsTheYoung` | `Keep::YoungBlob` | yes |                   *)
(* | `NoticeProtectsTheAbsent` | `Keep::LeasedByExpiring` | yes |          *)
(* | `FloorNeedsForget` | `Keep::RetentionFloor` | yes |                   *)
(* | `RenewalRestoresProtection` | `take_lease` stamps `last_seen` | yes | *)
(* | `WarnedBeforeSwept` | `SweepPlan::warnings` vs `SweepPlan::delete` |  *)
(*   yes |                                                                 *)
(* | `EveryUploadGetsGrace` (must FAIL) | `BlobStore::put`'s early return  *)
(*   vs §6.2's "any blob uploaded within grace_period" | this is the gap | *)
(*                                                                         *)
(* ONE PLACE WHERE CODE AND SPEC DISAGREE, modelled as the code is:        *)
(*                                                                         *)
(*   §6.3: "a per-repo `retention_floor` is never swept without an         *)
(*   authenticated `forget`", and §16.3's table routes a shrink through    *)
(*   the offline delete authority. `Peer::publish_retention` implements    *)
(*   no such path: it refuses EVERY shrink (`RetentionShrink`) and the     *)
(*   only way an address leaves the floor is a peer running                *)
(*   `--hostile ignore-retention`. `Forget(b)` here is therefore MORE      *)
(*   permissive than the code — the code is the safer of the two, but the  *)
(*   authenticated path §6.3 names does not exist yet.                     *)
(*                                                                         *)
(*   (A second disagreement this header used to record — a doc comment in  *)
(*   `crates/nas-cli/src/roaming.rs` saying `expiry + grace` where §6.3    *)
(*   and the function's own code say `expiry + notice` — has been          *)
(*   corrected. The `expiry + grace` further down that file, at the probe, *)
(*   is deliberate: it sits precisely where the conflation bug would       *)
(*   sweep.)                                                               *)
(*                                                                         *)
(* DELIBERATELY ABSTRACTED — these are not checked and may not be claimed: *)
(*   - §6.1's delta chains, checkpoints and Merkle roots. The model takes  *)
(*     each holder's replayed set as given; `set.rs::replay` is what earns *)
(*     that, and its integrity is a different question (a signature one,   *)
(*     not an ordering one).                                               *)
(*   - §6.4 quotas. `max_leased_bytes` is reported, never enforced by      *)
(*     deleting, so it has no data-loss path to model.                     *)
(*   - Blob sizes, epochs, and holder identity/authentication.             *)
(*   - Plan/execute atomicity: `Peer::sweep` plans and deletes inside one  *)
(*     call, so `Sweep` applies the whole plan in one step, as it does.    *)
(*   - Lease release (§16.2's explicit act). §6.3 is explicit that sync    *)
(*     never releases, and the deletion loop is `DeleteQuorum.tla`'s job.  *)
(*                                                                         *)
(* HOW MUCH THIS PROVES, stated before anyone quotes the green run.        *)
(* `Sweep` is enabled by `MaySweep`, which is the code; the four           *)
(* protections it records against — `LiveLease`, `Young`,                  *)
(* `ProtectedByNotice`, `Floored` — are written from SPECS.md, and         *)
(* the invariants say the two never disagree on a reachable state. Where   *)
(* the two expressions coincide, as they mostly do, the invariant is a     *)
(* transcription check rather than a discovery: it catches the day someone *)
(* edits one of them. The part that is NOT structural is the interleaving: *)
(* upload, take-lease, sync and sweep in every order, at every age — and   *)
(* that is where `EveryUploadGetsGrace` found something, by holding two    *)
(* clocks (`age` and `offered`) that the code conflates into one. The      *)
(* must-FAIL checks are what keep the rest from being vacuous: without     *)
(* `GraceIsRedundant` failing, "nothing young is ever swept" could be true *)
(* only because nothing is ever young.                                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Blobs,    \* content addresses the peer may hold
    Holders,  \* lease-holding devices (§6.1's `holder_pk`)
    Grace,    \* §6.2 young-blob immunity      — 24 h in `GcPolicy::default`
    Expiry,   \* §6.3 lease expiry             — 90 days
    Notice,   \* §6.3 post-expiry notice window — 30 days
    TouchOnDedup  \* does an upload of bytes the peer already holds move the
                  \* peer's mtime? TRUE is `BlobStore::put` and `prove` as they
                  \* now are; FALSE is the code `EveryUploadGetsGrace` was found
                  \* against, kept as a negative control (foot of this file)

ASSUME /\ Grace  \in Nat /\ Grace  >= 1
       /\ Expiry \in Nat /\ Expiry >= 1
       /\ Notice \in Nat /\ Notice >= 1
       /\ TouchOnDedup \in BOOLEAN

\* The instant a lease stops protecting: §6.3's "must not sweep until
\* `expiry + notice`", which is `Holder::status`'s second bound.
Lapse == Expiry + Notice

\* TIME IS ABSTRACT AND SATURATING. There is no wall clock and no horizon
\* constant. Every clock is an *age* that saturates at the largest threshold it
\* is ever compared against, which is what makes the state space finite without
\* an artificial bound on how long the system may run:
\*   - a blob's age is only ever compared with `Grace` (`plan_sweep` uses it for
\*     nothing else), so it saturates there;
\*   - a holder's idle time is compared with `Expiry` and with `Lapse`, so it
\*     saturates one past `Lapse` — far enough to be distinguishably expired.
\* This mirrors `Timestamp::saturating_since` only in that neither ever goes
\* negative; the backwards-clock case is NOT modelled (see the header).
Cap == Lapse + 1
Bump(n, cap) == IF n < cap THEN n + 1 ELSE cap

Reasons == {"live", "young", "notice", "floor", "offered"}

VARIABLES
    stored,    \* addresses the peer holds now
    age,       \* blob -> since the peer's file was written (its mtime)
    offered,   \* blob -> since a client last handed the peer these bytes
    leases,    \* holder -> the set the peer has recorded for it
    idle,      \* holder -> since it last published a lease record (last_seen)
    floor,     \* the retention set (§16.3)
    swept,     \* every address a sweep has deleted, ever
    lapsed,    \* holders whose idle time has ever passed `Expiry`
    violated   \* reason -> addresses swept while that protection was in force.
               \* A history variable: the sweep is enabled by `MaySweep`, and
               \* these record the SEPARATELY stated protections of §6.2/§6.3.
               \* An invariant below asserts each stays empty, so a green run
               \* says the two never disagreed on any reachable state.

vars == <<stored, age, offered, leases, idle, floor, swept, lapsed, violated>>

---------------------------------------------------------------------------
(* The policy, transcribed from `plan_sweep` and `Holder::status`. *)

\* `Holder::status`: idle <= expiry is Active, idle <= expiry + notice is
\* Expiring (past expiry, still protecting, and warned), anything more Expired.
Active(h)   == idle[h] <= Expiry
Expiring(h) == idle[h] > Expiry /\ idle[h] <= Lapse

Floored(b) == b \in floor
Young(b)   == age[b] < Grace          \* strict, as in `plan_sweep`

LiveLease(b)   == \E h \in Holders : b \in leases[h] /\ Active(h)
LapsedLease(b) == \E h \in Holders : b \in leases[h] /\ Expiring(h)

\* §6.3 stated as prose rather than as a status: no holder that leases `b` may
\* still be inside `expiry + notice`.
ProtectedByNotice(b) == \E h \in Holders : b \in leases[h] /\ idle[h] <= Lapse

\* The guard cascade of `plan_sweep`, in its order. A blob is deleted only when
\* every one of the four keep-reasons declines it.
MaySweep(b) == /\ ~Floored(b)
               /\ ~Young(b)
               /\ ~LiveLease(b)
               /\ ~LapsedLease(b)

Doomed == {b \in stored : MaySweep(b)}

\* `SweepPlan::warnings`: everything a holder leases that survived the floor,
\* the grace and every *active* lease -- whether it is kept as
\* `LeasedByExpiring` or deleted. Written from the predicates rather than from
\* `Doomed`, because in the Rust it is a separate loop that could disagree.
Warned(h) == {b \in stored : /\ b \in leases[h]
                             /\ ~Floored(b) /\ ~Young(b) /\ ~LiveLease(b)}

---------------------------------------------------------------------------

TypeOK ==
    /\ stored   \subseteq Blobs
    /\ age      \in [Blobs -> 0..Grace]
    /\ offered  \in [Blobs -> 0..Grace]
    /\ leases   \in [Holders -> SUBSET Blobs]
    /\ idle     \in [Holders -> 0..Cap]
    /\ floor    \subseteq Blobs
    /\ swept    \subseteq Blobs
    /\ lapsed   \subseteq Holders
    /\ violated \in [Reasons -> SUBSET Blobs]

Init ==
    /\ stored   = {}
    /\ age      = [b \in Blobs |-> 0]
    /\ offered  = [b \in Blobs |-> 0]
    /\ leases   = [h \in Holders |-> {}]
    /\ idle     = [h \in Holders |-> 0]
    /\ floor    = {}
    /\ swept    = {}
    /\ lapsed   = {}
    /\ violated = [live |-> {}, young |-> {}, notice |-> {}, floor |-> {},
                   offered |-> {}]

(* Time passes. Every clock ages together and none of them is anybody's
   authority: the peer compares its own `now` against its own records. *)
Tick ==
    /\ age'     = [b \in Blobs  |-> Bump(age[b], Grace)]
    /\ offered' = [b \in Blobs  |-> Bump(offered[b], Grace)]
    /\ idle'    = [h \in Holders |-> Bump(idle[h], Cap)]
    /\ lapsed'  = lapsed \cup {h \in Holders : idle'[h] > Expiry}
    /\ UNCHANGED <<stored, leases, floor, swept, violated>>

(* A client hands the peer a blob. THE LEASE IS NOT TAKEN HERE: `TakeLease` is
   a separate round trip, and every interleaving between the two is
   admissible. That gap is the race this model exists for. There is no
   client-side "intends to keep it" variable: the peer cannot see intent, no
   invariant here reads it, and `offered` already carries the only fact that
   matters -- that a client handed these bytes over just now.

   `offered` moves every time, because a client did just hand over the bytes;
   §6.2 is written about `offered`. `age` is the file's mtime, which is what
   the code enforces §6.2 on. With `TouchOnDedup` it moves every time too:
   `BlobStore::put` now touches the file it already holds, and `prove` touches
   on an answered proof-of-possession, which is how a client that skips its
   upload (§4.5) "offers" the bytes -- `Upload(b)` with `b \in stored` stands
   for both paths. With `~TouchOnDedup` it moves only on a first upload, which
   is the code this model was written against, and the two clocks disagree.

   `put` does rewrite -- and so does move the mtime -- when the copy it
   already holds fails to verify. This models only the intact case, which is
   the usual one and the pessimistic one. *)
Upload(b) ==
    /\ ~(b \in stored /\ offered[b] = 0)   \* skip no-ops
    /\ stored'  = stored \cup {b}
    /\ offered' = [offered EXCEPT ![b] = 0]
    /\ age'     = IF b \in stored /\ ~TouchOnDedup
                     THEN age
                     ELSE [age EXCEPT ![b] = 0]
    /\ UNCHANGED <<leases, idle, floor, swept, lapsed, violated>>

(* §6.3: "renewal is a side effect of sync. On every sync a client takes a
   lease on everything it holds. A take is a union that stamps the holder's
   last-seen, so a take with no addresses renews without changing the set."
   `S = {}` is that renewal; `S` is any subset because a holder may lease an
   address it never wrote (which is why §6.4 has quotas at all). Sync never
   releases, so this is the only way `leases` moves. *)
TakeLease(h, S) ==
    /\ S \subseteq stored          \* `PeerError::NoSuchBlob` otherwise
    /\ leases' = [leases EXCEPT ![h] = @ \cup S]
    /\ idle'   = [idle EXCEPT ![h] = 0]
    /\ UNCHANGED <<stored, age, offered, floor, swept, lapsed, violated>>

(* Extending the retention set with the everyday write key (§16.3). *)
Retain(b) ==
    /\ b \notin floor
    /\ floor' = floor \cup {b}
    /\ UNCHANGED <<stored, age, offered, leases, idle, swept, lapsed,
                   violated>>

(* The authenticated `forget` of §6.3 -- the only thing that may take an
   address out of the floor. Modelled as an atomic authorised act; the quorum
   and cooling-off that authorise it are §16.2's, and `DeleteQuorum.tla`'s.
   NOTE: no such path exists in the peer today. See the header. *)
Forget(b) ==
    /\ b \in floor
    /\ floor' = floor \ {b}
    /\ UNCHANGED <<stored, age, offered, leases, idle, swept, lapsed,
                   violated>>

(* The sweep. `Peer::sweep` plans with `plan_sweep` and deletes the whole plan
   in the same call, so this is one step. Lease sets are NOT pruned of deleted
   addresses -- the Rust does not touch `self.leases` either.

   The `violated` update is the whole assurance argument: the action is
   ENABLED by `MaySweep` (the code), and records what it did against the
   protections stated from the specification (`ProtectedByNotice`, `Young`,
   `LiveLease`, `Floored`, and `offered`). Where those two ever disagree, an
   invariant below fails. *)
Sweep ==
    /\ Doomed # {}
    /\ stored' = stored \ Doomed
    /\ swept'  = swept \cup Doomed
    /\ violated' =
         [ live    |-> violated["live"]    \cup {b \in Doomed : LiveLease(b)},
           young   |-> violated["young"]   \cup {b \in Doomed : Young(b)},
           notice  |-> violated["notice"]  \cup {b \in Doomed :
                                                    ProtectedByNotice(b)},
           floor   |-> violated["floor"]   \cup {b \in Doomed : Floored(b)},
           offered |-> violated["offered"] \cup {b \in Doomed :
                                                    offered[b] < Grace} ]
    /\ UNCHANGED <<age, offered, leases, idle, floor, lapsed>>

Next == \/ Tick
        \/ \E b \in Blobs : Upload(b)
        \/ \E h \in Holders, S \in SUBSET Blobs : TakeLease(h, S)
        \/ \E b \in Blobs : Retain(b)
        \/ \E b \in Blobs : Forget(b)
        \/ Sweep

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Invariants *)

\* Nothing held by a live lease is ever swept (§6.3, `Keep::Leased`).
LiveLeaseNeverSwept == violated["live"] = {}

\* Nothing younger than `grace` by the peer's own clock is ever swept: the
\* upload race of §6.2, "immune from sweep regardless of leases".
GraceProtectsTheYoung == violated["young"] = {}

\* Nothing whose lease lapsed less than `notice` ago is swept -- the laptop
\* closed for weeks (§6.3, `Keep::LeasedByExpiring`).
NoticeProtectsTheAbsent == violated["notice"] = {}

\* A retention-floor blob is never swept. Once `Forget` has removed it from the
\* floor it is ordinary again, which is what "without an authenticated
\* `forget`" means (§6.3, `Keep::RetentionFloor`).
FloorNeedsForget == violated["floor"] = {}

\* A renewal inside the notice window restores FULL protection: a holder that
\* has been past expiry and has since synced protects its whole set again, not
\* some residue of it. The bug shape this excludes is an expiry measured from
\* when the lease was first taken rather than from `last_seen`.
\* `RenewalNeverRestores` below establishes that lapse-then-renew is reachable,
\* so this is not quantifying over an empty set.
RenewalRestoresProtection ==
    \A h \in Holders :
        (h \in lapsed /\ Active(h)) => \A b \in leases[h] : b \notin Doomed

\* Warn before sweep (§6.3): nothing is deleted that its holders were not told
\* about. `Warned` and `Doomed` are separate predicates here because they are
\* separate loops in `plan_sweep`.
WarnedBeforeSwept ==
    \A b \in Doomed : \A h \in Holders : b \in leases[h] => b \in Warned(h)

---------------------------------------------------------------------------
(* SANITY CHECKS -- these are EXPECTED TO FAIL.                            *)
(*                                                                         *)
(* Every invariant above is of the form "this bad thing never happened". A  *)
(* model in which nothing happens satisfies all of them. Each check below   *)
(* must produce a counterexample; `check.sh` fails the build with "model is *)
(* VACUOUS" if any of them starts passing.                                  *)

\* Expect violation: the sweeper must be able to delete something at all.
NeverSweeps == swept = {}

\* Expect violation, and this is the state the TODO named: a blob is present,
\* its lease has not been recorded, the sweeper is running, and the ONLY thing
\* standing between them is §6.2's grace. If this ever passed, the grace period
\* would be dead weight and `GraceProtectsTheYoung` would hold for the wrong
\* reason.
GraceIsRedundant ==
    \A b \in stored :
        ~( /\ Young(b)
           /\ ~Floored(b) /\ ~LiveLease(b) /\ ~LapsedLease(b) )

\* Expect violation: likewise for the notice window. A blob kept alive by
\* nothing but a lapsed lease must be reachable, or `NoticeProtectsTheAbsent`
\* is about a state that never occurs.
NoticeIsRedundant ==
    \A b \in stored :
        ~( /\ LapsedLease(b)
           /\ ~Floored(b) /\ ~Young(b) /\ ~LiveLease(b) )

\* Expect violation: a holder that has lapsed must be able to become active
\* again by syncing. This is what makes `RenewalRestoresProtection` mean
\* something -- without it that invariant quantifies over nothing.
RenewalNeverRestores == \A h \in Holders : h \in lapsed => ~Active(h)

\* THE FINDING, now closed in the code and kept here as a negative control.
\*
\* §6.2: "Any blob uploaded within `grace_period` is immune from sweep
\* regardless of leases. This closes revision 1's race where a blob written
\* mid-epoch had no lease yet, and the case where a client crashes between
\* upload and lease publication."
\*
\* The code enforces that on the blob file's mtime (`Peer::inventory` ->
\* `uploaded_at`). When this model was written, `BlobStore::put` returned early
\* without touching the file when the address was already present, so an
\* upload that DEDUPLICATED got no grace: the clock it was measured against
\* never restarted. Under convergent encryption (§3.2) two clients producing
\* identical ciphertext hit exactly this path, and so did one client
\* re-uploading after a crash.
\*
\* TLC's counterexample was five states: upload; tick past the grace; upload
\* the same address again -- deduplicated, so the peer's mtime did not move
\* while `offered` restarted; sweep. The blob went while it was still inside
\* the window §6.2 promises it, and the `take_lease` about to follow would
\* have failed with `NoSuchBlob`.
\*
\* CLOSED: `BlobStore::put` touches the file it already holds, and
\* `BlobStore::prove` touches on an answered proof-of-possession -- the moment
\* a client that skips its upload (§4.5) commits to the peer's copy. With
\* `TouchOnDedup = TRUE` (every gated windowing) this invariant HOLDS. With
\* `TouchOnDedup = FALSE` (`MC_LeaseGC_EveryUploadGetsGrace.cfg`) it must fail
\* in those same five states: the negative control that keeps the finding
\* reproducible, and shows the green run is attributable to the touch.
EveryUploadGetsGrace == violated["offered"] = {}

===============================================================================
