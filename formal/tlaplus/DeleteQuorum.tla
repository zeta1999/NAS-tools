----------------------------- MODULE DeleteQuorum -----------------------------
(***************************************************************************)
(* The deletion approval loop (SPECS.md §16.2), as `crates/nas-delete`      *)
(* implements it: `DeleteRequest` → cooling-off → m × `DeleteApproval` from *)
(* distinct holders of the offline authority → `DeleteExecution`.           *)
(*                                                                         *)
(* THE ADVERSARY. Everything except an ML-DSA forgery is permitted:         *)
(*                                                                         *)
(*   - The EXECUTOR is hostile. It assembles the `DeleteExecution` bundle   *)
(*     itself, out of every approval record that has ever existed, in any   *)
(*     multiplicity. `Bundles` is literally that: a *sequence* over         *)
(*     `approvals`, so the same record may occupy two slots (REPLAY) and a  *)
(*     record signed over request r1 may sit in a bundle for r2            *)
(*     (RE-TARGETING). It may fire at any tick it likes, including tick 0   *)
(*     (the EARLY-EXECUTION bypass) — the action is simply not enabled      *)
(*     until the approvals it needs exist.                                  *)
(*   - The RELAY back-dates. §16.2 lets any machine carry an approval to an *)
(*     approver's device, and that machine may assert whatever `first_seen` *)
(*     it likes. `Approve` ignores the assertion and consults `seen[m][r]`, *)
(*     which is the device's OWN record — mirroring the Rust, where         *)
(*     `Approver::approve` takes `first_seen` from the device and not from  *)
(*     the record it is judging.                                            *)
(*   - The LAPTOP MINTS KEYS. `Outsiders` are freshly generated keypairs.   *)
(*     Their approvals are genuine, valid, and pairwise distinct — they are *)
(*     simply not in the authority. This is the defect STATUS.md records:   *)
(*     `decide` once counted *distinct approvers* and stopped there, which  *)
(*     is a headcount rather than a quorum.                                 *)
(*                                                                         *)
(* THE THREE DEFENCES ARE SWITCHES, and each one is turned off in a sanity  *)
(* configuration that MUST produce a counterexample. That is what makes the *)
(* green run mean something: the invariants below are not true of the       *)
(* protocol's shape, they are true *because of* these three checks, and     *)
(* `check.sh` proves it by removing them one at a time.                     *)
(*                                                                         *)
(*   StrictApprovalCheck  `DeleteExecution::verify` refuses any approval    *)
(*                        whose `request_hash` is not this request's, and   *)
(*                        `decide` collapses approvers into a `BTreeSet` by *)
(*                        key id. FALSE models the naive rule: count the    *)
(*                        records handed over. Replay and re-targeting both *)
(*                        land the moment it is off.                        *)
(*   StrictAuthority      `decide` refuses an approval from outside         *)
(*                        `Authority` (SPECS §16.1). FALSE is the headcount *)
(*                        bug, and a minted quorum walks straight through.  *)
(*   EnforceCoolOff       `Approver::may_sign` against the device's own     *)
(*                        clock. FALSE lets the back-dated `first_seen`     *)
(*                        through.                                          *)
(*                                                                         *)
(* WHAT THIS MODEL DOES NOT CLAIM. Cooling-off is a convention enforced by  *)
(* approver devices, not by the protocol (SPECS §16.2, "Whose clock gates   *)
(* the cooling-off"): there is no trusted time source anywhere in this      *)
(* design. So `NoEarlyExecution` is a statement about a quorum of HONEST    *)
(* approver devices — it says the executor cannot get there early, not that *)
(* a subverted approver device could not sign early. `EnforceCoolOff =      *)
(* FALSE` is exactly that subverted device, and the counterexample TLC      *)
(* produces for it is the honest statement of the limit.                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Roster,              \* the offline deletion authority (SPECS §16.1)
    Outsiders,           \* keypairs a compromised laptop mints: valid, distinct, not authority
    Requests,            \* delete requests that may be opened
    SmallScope,          \* requests whose blast radius is one object (SPECS §16.2)
    QuorumSmall,         \* approvals owed by an object-scoped request
    QuorumWide,          \* approvals owed by a namespace-scoped request
    EscalateTo,          \* approvals owed once the rolling window trips
    RollingLimit,        \* executions inside the window before escalation
    CoolOff,             \* cooling-off, in ticks (SPECS §16.2 step 2)
    MaxTime,             \* bound on the clock; keeps the state space finite
    MaxSlots,            \* how many approval records the executor may present
    StrictApprovalCheck, \* bind the request hash, and count distinct approver ids
    StrictAuthority,     \* only the offline authority's approvals count
    EnforceCoolOff       \* the approver device refuses to sign early

Signers == Roster \cup Outsiders

\* Sentinels, kept numeric so the arithmetic below stays in Naturals. Both sit
\* one tick above the clock's ceiling, so they can never be mistaken for a time.
NotSeen == MaxTime + 1
NotExec == MaxTime + 1

Max(a, b) == IF a > b THEN a ELSE b

\* "One approver to remove a file; three to remove a tree" (SPECS §16.2), i.e.
\* `QuorumPolicy::base`.
BaseQuorum(r) == IF r \in SmallScope THEN QuorumSmall ELSE QuorumWide

VARIABLES
    clock,       \* a tick counter; the approver devices' shared notion of elapsed time
    opened,      \* requests published as `DeleteRequest` (step 1)
    seen,        \* approver -> request -> the tick THIS DEVICE first saw it, by its own clock
    approvals,   \* every `DeleteApproval` record that exists, from anyone, for anything
    executedAt,  \* request -> the tick its `DeleteExecution` was accepted
    countedAt    \* request -> the count the verifier actually used when it accepted

vars == <<clock, opened, seen, approvals, executedAt, countedAt>>

\* The approvals the *authority* genuinely signed for this request. Ground
\* truth: replaying a record does not add to it, and neither does a record
\* signed over some other request, nor one from a minted key.
GenuineSigners(r) == {m \in Roster : <<r, m>> \in approvals}

\* Executions strictly before t. `Execute` admits at most one per tick, so at
\* the moment of execution this is exactly the rolling window's count, and it
\* still is when an invariant recomputes it later. Every tick in this model is
\* inside the 30-day window, so the window's *width* is abstracted away and
\* only its count matters.
ExecutedBefore(t) ==
    Cardinality({q \in Requests : executedAt[q] # NotExec /\ executedAt[q] < t})

\* `decide`'s requirement: the scope's own quorum, raised to `escalate_to` once
\* the rolling threshold is passed. Volume, not the label on the request.
RequiredAt(r, t) ==
    IF ExecutedBefore(t) >= RollingLimit
      THEN Max(BaseQuorum(r), EscalateTo)
      ELSE BaseQuorum(r)

TypeOK ==
    /\ clock      \in 0..MaxTime
    /\ opened     \subseteq Requests
    /\ seen       \in [Roster -> [Requests -> 0..NotSeen]]
    /\ approvals  \subseteq (Requests \X Signers)
    /\ executedAt \in [Requests -> 0..NotExec]
    /\ countedAt  \in [Requests -> 0..MaxSlots]

Init ==
    /\ clock      = 0
    /\ opened     = {}
    /\ seen       = [m \in Roster |-> [r \in Requests |-> NotSeen]]
    /\ approvals  = {}
    /\ executedAt = [r \in Requests |-> NotExec]
    /\ countedAt  = [r \in Requests |-> 0]

---------------------------------------------------------------------------
(* Actions *)

Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED <<opened, seen, approvals, executedAt, countedAt>>

(* Step 1: a signed statement of intent. Deletes nothing. *)
OpenRequest(r) ==
    /\ r \notin opened
    /\ opened' = opened \cup {r}
    /\ UNCHANGED <<clock, seen, approvals, executedAt, countedAt>>

(* An approver device learns of a request, and stamps the arrival against its
   OWN clock. Nothing else may write this. *)
Learn(m, r) ==
    /\ r \in opened
    /\ seen[m][r] = NotSeen
    /\ seen' = [seen EXCEPT ![m][r] = clock]
    /\ UNCHANGED <<clock, opened, approvals, executedAt, countedAt>>

Matured(m, r) == seen[m][r] # NotSeen /\ clock >= seen[m][r] + CoolOff

(* Step 3, and the back-dating adversary. The relay carrying the request may
   assert any `first_seen` it likes -- 0, the strongest possible back-date --
   and it makes no difference: the guard reads `seen[m][r]`, the device's own
   stamp. That asymmetry is the whole of `Approver::approve`. *)
Approve(m, r) ==
    /\ r \in opened
    /\ seen[m][r] # NotSeen
    /\ (EnforceCoolOff => Matured(m, r))
    /\ <<r, m>> \notin approvals
    /\ approvals' = approvals \cup {<<r, m>>}
    /\ UNCHANGED <<clock, opened, seen, executedAt, countedAt>>

(* The invented-approver attack, run for real. A minted key signs a valid,
   distinct approval; no cooling-off applies, because the device is the
   attacker's own. *)
MintApproval(o, r) ==
    /\ r \in opened
    /\ <<r, o>> \notin approvals
    /\ approvals' = approvals \cup {<<r, o>>}
    /\ UNCHANGED <<clock, opened, seen, executedAt, countedAt>>

(* Every bundle a hostile executor could assemble: a sequence, not a set, so a
   record may appear twice (replay), and drawn from ALL approvals, so a record
   bound to another request may appear (re-targeting). *)
Bundles == UNION { [1..n -> approvals] : n \in 1..MaxSlots }

BindsAll(b, r)     == \A i \in DOMAIN b : b[i][1] = r
AuthorityOnly(b)   == \A i \in DOMAIN b : b[i][2] \in Roster
ApproverIds(b)     == { b[i][2] : i \in DOMAIN b }

(* What the verifier counts. Strict is the shipped rule: the bundle has already
   been forced to bind this request, and the approvers collapse into a set by
   key id, so a record presented twice is one holder. Non-strict counts the
   records that were handed over, which is what "count the approvals" means if
   nobody wrote the two checks. *)
Counted(b) ==
    IF StrictApprovalCheck THEN Cardinality(ApproverIds(b))
                           ELSE Cardinality(DOMAIN b)

(* Step 4. Published only on quorum; leases are dropped after this, never
   before. Records the count it used, so an inflated one is visible to an
   invariant rather than having to be inferred. *)
Execute(r, b) ==
    /\ r \in opened
    /\ executedAt[r] = NotExec
    \* At most one execution per tick. An abstraction, and a free one: it costs
    \* no behaviour that matters and makes the rolling window's "executions
    \* strictly before this one" exact rather than approximate.
    /\ \A q \in Requests : executedAt[q] # clock
    /\ (StrictApprovalCheck => BindsAll(b, r))
    /\ (StrictAuthority => AuthorityOnly(b))
    /\ Counted(b) >= RequiredAt(r, clock)
    /\ executedAt' = [executedAt EXCEPT ![r] = clock]
    /\ countedAt'  = [countedAt  EXCEPT ![r] = Counted(b)]
    /\ UNCHANGED <<clock, opened, seen, approvals>>

Next == \/ Tick
        \/ \E r \in Requests : OpenRequest(r)
        \/ \E m \in Roster, r \in Requests : Learn(m, r)
        \/ \E m \in Roster, r \in Requests : Approve(m, r)
        \/ \E o \in Outsiders, r \in Requests : MintApproval(o, r)
        \/ \E r \in Requests, b \in Bundles : Execute(r, b)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Invariants *)

\* THE QUORUM PROPERTY. Whatever the executor presented, a request that
\* executed had, in the trail, at least as many DISTINCT AUTHORITY MEMBERS
\* genuinely signing IT as the policy owed at that moment -- scope quorum, or
\* the rolling escalation if the window had tripped.
NoExecutionWithoutQuorum ==
    \A r \in Requests :
        executedAt[r] # NotExec =>
            Cardinality(GenuineSigners(r)) >= RequiredAt(r, executedAt[r])

\* THE REPLAY PROPERTY. The count the verifier actually used never exceeds the
\* number of distinct authority members who signed this very request. A record
\* presented twice, or an approval lifted from another request, cannot push it
\* above that ceiling. This is the invariant that fails the instant
\* `StrictApprovalCheck` is off.
NoReplayCountsTwice ==
    \A r \in Requests :
        executedAt[r] # NotExec =>
            countedAt[r] <= Cardinality(GenuineSigners(r))

\* No approval from the authority exists that its device could not have signed:
\* the cooling-off had elapsed against that device's own stamp. `Approver::
\* may_sign`, stated as an invariant over every reachable state.
NoEarlyApproval ==
    \A r \in Requests, m \in Roster :
        <<r, m>> \in approvals =>
            (seen[m][r] # NotSeen /\ clock >= seen[m][r] + CoolOff)

\* THE COOLING-OFF PROPERTY. At the tick a deletion executed, a full quorum of
\* authority members had each already been sitting on that request for at least
\* CoolOff, by their own clocks. A full quorum arriving early is not enough --
\* there is no early.
NoEarlyExecution ==
    \A r \in Requests :
        executedAt[r] # NotExec =>
            Cardinality({m \in Roster :
                            /\ <<r, m>> \in approvals
                            /\ seen[m][r] # NotSeen
                            /\ executedAt[r] >= seen[m][r] + CoolOff})
                >= RequiredAt(r, executedAt[r])

\* THE TRAIL (SPECS §16.2: "all of it append-only, so the audit trail cannot be
\* edited either"). An executed deletion still has its request record and the
\* approvals that authorised it. Nothing is deleted by deleting.
TrailComplete ==
    \A r \in Requests :
        executedAt[r] # NotExec =>
            /\ r \in opened
            /\ Cardinality(GenuineSigners(r)) >= RequiredAt(r, executedAt[r])

\* The same thing as a step property: no transition ever shortens the trail,
\* restamps an execution, or rewrites a device's arrival stamp. `publish_delete_
\* request` returns `TrailImmutable` rather than replacing a record; this is
\* that rule for every record in the loop at once.
TrailMonotonic ==
    [][ /\ clock' >= clock
        /\ opened \subseteq opened'
        /\ approvals \subseteq approvals'
        /\ \A r \in Requests :
              executedAt[r] # NotExec => /\ executedAt'[r] = executedAt[r]
                                         /\ countedAt'[r]  = countedAt[r]
        /\ \A m \in Roster, r \in Requests :
              seen[m][r] # NotSeen => seen'[m][r] = seen[m][r] ]_vars

---------------------------------------------------------------------------
(* SANITY CHECKS -- these are EXPECTED TO FAIL.                            *)
(*                                                                         *)
(* Two of them prove the model reaches the interesting states at all. The   *)
(* other three run in configurations with one defence switched off, and     *)
(* prove that the invariants above are carried by that defence rather than  *)
(* by the shape of the protocol. `check.sh` fails the build if any of the   *)
(* five stops producing a counterexample.                                   *)

\* Expect violation: a deletion must be able to execute, or every invariant
\* above is a statement about the empty set.
NeverExecutes == \A r \in Requests : executedAt[r] = NotExec

\* Expect violation: the LARGEST quorum the policy can demand -- the escalated
\* one -- must be reachable on a single request, or NoExecutionWithoutQuorum
\* holds because approvals never accumulate that far and the rolling window's
\* requirement is never actually met by anybody.
NeverReachesQuorum ==
    \A r \in Requests :
        Cardinality(GenuineSigners(r)) < Max(QuorumWide, EscalateTo)

\* Expect violation: there must be states in which an authority member has been
\* asked but has not yet matured. That window is where back-dating would pay,
\* and if it were empty `NoEarlyApproval` would be vacuous.
NeverPending ==
    \A m \in Roster, r \in Requests :
        seen[m][r] # NotSeen => clock >= seen[m][r] + CoolOff

===============================================================================
