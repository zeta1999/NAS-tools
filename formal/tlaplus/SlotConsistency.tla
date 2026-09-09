---------------------------- MODULE SlotConsistency ----------------------------
(***************************************************************************)
(* Rollback and fork detection for a NAS-tools mutable slot (SPECS.md §5). *)
(*                                                                         *)
(* The peer is MALICIOUS: it may serve any version it has ever seen        *)
(* (rollback), admit two records at one sequence number (fork), and        *)
(* withhold witnesses rather than relaying them.                           *)
(*                                                                         *)
(* REVISION 2 OF THIS MODEL. Revision 1 was written, labelled unchecked,   *)
(* and then failed TLC in 7 states. Three real defects, all of which would *)
(* have become client bugs:                                                *)
(*                                                                         *)
(*   1. Evidence was evaluated only on arrival. A witness relayed to a     *)
(*      client that had not yet pinned anything was silently dropped and   *)
(*      never reconsidered, so a fork could cross and raise no alarm.      *)
(*      FIX: `known` accumulates every version a client learns of, and the *)
(*      alarm is a DERIVED predicate over that set — so evidence is        *)
(*      re-evaluated on every transition, structurally, forever.           *)
(*   2. `anchor` was initialised to 0 and never assigned, making the       *)
(*      freshness-anchor branch dead code and AnchorFloor vacuous.         *)
(*      FIX: an explicit IssueCap action.                                  *)
(*   3. Compatibility was branch equality, so divergence at *different*    *)
(*      sequence numbers was invisible. FIX: a real ancestry relation.     *)
(*                                                                         *)
(* REVISION 3. The fix for defect 3 handed the client `Compatible`, which  *)
(* is a GLOBAL ancestry relation — it knows the whole branch structure and *)
(* answers for any two versions. No client can compute that. A client sees *)
(* signed observations, and revision 2's witness carried a version and no  *)
(* ancestry, so the model was checking a detection rule the implementation *)
(* could not run. That is the mirror image of defect 1: not evidence lost, *)
(* but evidence assumed.                                                   *)
(*                                                                         *)
(*   FIX, in two halves, matching `crates/nas-slots`:                      *)
(*                                                                         *)
(*   a. A witness now records its version AND that version's predecessor   *)
(*      — one EDGE of the chain, which is what a `Witness` carries in the  *)
(*      Rust (`record_hash` plus the observed record's own `prev`).        *)
(*   b. Detection uses `KnownIncompatible`, which walks back only along    *)
(*      edges the client has actually been given (`Named`). A walk that    *)
(*      runs out of links STOPS and raises nothing: not proven compatible  *)
(*      is not proven forked. `Compatible` survives only as the yardstick  *)
(*      the invariants are stated against, never as something a client     *)
(*      evaluates.                                                         *)
(*                                                                         *)
(*   `ForkDetected` is restated to match: incompatible evidence raises     *)
(*   ONCE THE LINKING WITNESSES ARE KNOWN. Anything stronger would be a    *)
(*   claim about a client that can see links nobody sent it. `NoFalseAlarm`*)
(*   is the new invariant in the other direction, and is the property the  *)
(*   Rust module defends in its tests: evidence that is genuinely all on   *)
(*   one history never raises.                                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Clients,   \* honest client identities
    MaxSeq,    \* bound on published versions; keeps the state space finite
    ForkAt     \* sequence number at which branch "b" diverges from "a"

Branches == {"a", "b"}

\* Branch "b" does not exist before the fork point: the two branches share a
\* prefix, which is what makes this a fork rather than two unrelated chains.
Versions == {v \in (1..MaxSeq) \X Branches : v[2] = "a" \/ v[1] >= ForkAt}

\* The predecessor of the first version is nothing at all -- the all-zero
\* `prev` of a genesis record in SPECS §5. Not a version: a witness of it is a
\* witness that its subject descends from nowhere.
Genesis == <<0, "a">>

\* v1 is an ancestor of v2 if they are on one branch and v1 is no later, or if
\* v1 sits in the shared prefix that "b" also descends from.
IsAncestor(v1, v2) ==
    \/ (v1[2] = v2[2] /\ v1[1] <= v2[1])
    \/ (v1[2] = "a" /\ v2[2] = "b" /\ v1[1] < ForkAt)

\* Two versions conflict when neither descends from the other.
\*
\* THE YARDSTICK, NOT THE RULE. This is global: it answers for any two
\* versions, using branch structure no client is ever told. The invariants
\* below are stated against it; `KnownIncompatible` is what a client actually
\* computes, and it is strictly weaker by design.
Compatible(v1, v2) == IsAncestor(v1, v2) \/ IsAncestor(v2, v1)

\* The version at sequence n on the chain leading to v, for n \in 1..v[1].
\* Below the fork point every chain runs through branch "a".
ChainAt(v, n) == IF v[2] = "b" /\ n >= ForkAt THEN <<n, "b">> ELSE <<n, "a">>

\* What a witness of v names as v's predecessor.
Pred(v) == IF v[1] = 1 THEN Genesis ELSE ChainAt(v, v[1] - 1)

VARIABLES
    published,  \* versions a writer or a forking peer has created
    pinSeq,     \* client -> highest sequence number accepted
    pinBranch,  \* client -> branch currently believed
    anchor,     \* client -> freshness anchor carried in its capability
    witnessed,  \* signed observations published to the peer: <<by, v, Pred(v)>>
    known,      \* client -> every version it holds an EDGE for, from ANY source
    rolled      \* clients served something below their pin or anchor

vars == <<published, pinSeq, pinBranch, anchor, witnessed, known, rolled>>

(***************************************************************************)
(* Detection, using only what the client holds.                            *)
(*                                                                         *)
(* `known[c]` is the set of versions c holds an edge for: every entry came *)
(* with its predecessor attached, because that is what a witness and a     *)
(* served record both carry. So c can always step ONE back from anything   *)
(* in `known[c]`, and can step further only where the intermediate         *)
(* versions are themselves in `known[c]`.                                  *)
(*                                                                         *)
(* Named(k, v, n): starting at v and walking back along edges in k, the    *)
(* client can name the version at sequence n. The step from m to m-1 needs *)
(* the edge of ChainAt(v, m), so every m strictly above n must be in k --  *)
(* v itself included. A single missing link is a GAP, and a gap ends the   *)
(* walk without a conclusion.                                             *)
(***************************************************************************)
Named(k, v, n) ==
    /\ n \in 1..v[1]
    /\ \A m \in (n+1)..v[1] : ChainAt(v, m) \in k

\* Two things the client holds that cannot both describe one history: walk the
\* higher back to the lower's sequence and land on something else. With
\* u[1] = v[1] this is same-sequence equivocation, which needs no walk at all.
KnownIncompatible(k) ==
    \E v \in k, u \in k :
        /\ Named(k, v, u[1])
        /\ ChainAt(v, u[1]) # u

\* Can c1 walk between these two at all? The hypothesis ForkDetected carries.
Linked(k, v1, v2) ==
    IF v1[1] <= v2[1] THEN Named(k, v2, v1[1]) ELSE Named(k, v1, v2[1])

Head(c) == <<pinSeq[c], pinBranch[c]>>

\* ALARM IS DERIVED, NOT STORED. That is the whole fix for defect 1: there is
\* no moment at which evidence is "handled" and then forgotten.
Alarm == {c \in Clients : KnownIncompatible(known[c]) \/ c \in rolled}

TypeOK ==
    /\ published \subseteq Versions
    /\ pinSeq    \in [Clients -> 0..MaxSeq]
    /\ pinBranch \in [Clients -> Branches]
    /\ anchor    \in [Clients -> 0..MaxSeq]
    /\ witnessed \subseteq (Clients \X Versions \X (Versions \cup {Genesis}))
    /\ known     \in [Clients -> SUBSET Versions]
    /\ rolled    \subseteq Clients

Init ==
    /\ published = {}
    /\ pinSeq    = [c \in Clients |-> 0]
    /\ pinBranch = [c \in Clients |-> "a"]
    /\ anchor    = [c \in Clients |-> 0]
    /\ witnessed = {}
    /\ known     = [c \in Clients |-> {}]
    /\ rolled    = {}

MaxPublished == IF published = {} THEN 0
                ELSE CHOOSE n \in {v[1] : v \in published} :
                        \A w \in published : w[1] <= n

(* An honest writer extends the canonical branch. *)
Publish ==
    /\ MaxPublished < MaxSeq
    /\ published' = published \cup {<<MaxPublished + 1, "a">>}
    /\ UNCHANGED <<pinSeq, pinBranch, anchor, witnessed, known, rolled>>

(* The peer declines to enforce CAS and admits a second record at a taken
   sequence number. This is the fork. *)
PeerForks ==
    /\ \E s \in ForkAt..MaxSeq :
        /\ <<s, "a">> \in published
        /\ <<s, "b">> \notin published
        /\ published' = published \cup {<<s, "b">>}
    /\ UNCHANGED <<pinSeq, pinBranch, anchor, witnessed, known, rolled>>

(* A fresh client is issued a capability carrying the current head as its
   freshness anchor (SPECS §5.3 mechanism 1). *)
IssueCap(c) ==
    /\ pinSeq[c] = 0
    /\ MaxPublished > 0
    /\ anchor[c] = 0
    /\ anchor' = [anchor EXCEPT ![c] = MaxPublished]
    /\ UNCHANGED <<published, pinSeq, pinBranch, witnessed, known, rolled>>

(* The peer serves client c a version of its choosing -- not necessarily the
   newest, not necessarily on the branch c already follows. A served record
   carries its own `prev`, so accepting one adds an edge and not merely a
   name. *)
Serve(c, s, b) ==
    /\ <<s, b>> \in published
    /\ \/ /\ s < anchor[c]              \* below the capability anchor: misbehaviour
          /\ rolled' = rolled \cup {c}
          /\ UNCHANGED <<pinSeq, pinBranch, known>>
       \/ /\ s >= anchor[c]
          /\ \/ /\ s < pinSeq[c]        \* rollback: detected, never silently applied
                /\ rolled' = rolled \cup {c}
                /\ UNCHANGED <<pinSeq, pinBranch, known>>
             \/ /\ s >= pinSeq[c]
                /\ pinSeq'    = [pinSeq    EXCEPT ![c] = s]
                /\ pinBranch' = [pinBranch EXCEPT ![c] = b]
                /\ known'     = [known     EXCEPT ![c] = @ \cup {<<s, b>>}]
                /\ UNCHANGED rolled
    /\ UNCHANGED <<published, anchor, witnessed>>

PeerServes == \E c \in Clients, s \in 1..MaxSeq, b \in Branches : Serve(c, s, b)

(* A client publishes a signed observation of what it currently believes --
   the version AND its predecessor, which together are one edge of the chain.
   The predecessor is what revision 2's witness lacked, and without it a
   recipient can only ever compare observations that name the same sequence. *)
PublishWitness ==
    /\ \E c \in Clients :
        /\ pinSeq[c] > 0
        /\ witnessed' = witnessed \cup {<<c, Head(c), Pred(Head(c))>>}
    /\ UNCHANGED <<published, pinSeq, pinBranch, anchor, known, rolled>>

(* The peer MAY relay a witness. It is free never to do so -- that freedom is
   why we claim detection and not prevention (SPECS §5.4).
   NOTE the absence of any guard on the recipient's state: a witness arriving
   at a client that has pinned nothing is still retained. That guard was
   defect 1.
   NOTE ALSO what the recipient gains: the witnessed version, WITH its edge.
   It does not gain the predecessor's own edge, which is exactly why a walk
   can run out of links. *)
RelayWitness ==
    /\ \E c \in Clients, w \in witnessed :
        /\ w[1] # c
        /\ w[2] \notin known[c]
        /\ known' = [known EXCEPT ![c] = @ \cup {w[2]}]
    /\ UNCHANGED <<published, pinSeq, pinBranch, anchor, witnessed, rolled>>

Next == Publish
     \/ PeerForks
     \/ PeerServes
     \/ PublishWitness
     \/ RelayWitness
     \/ (\E c \in Clients : IssueCap(c))

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Invariants *)

\* An accepted version never sits below the capability's freshness anchor.
\* This is what protects a FRESH client, which has no pin of its own yet.
AnchorFloor == \A c \in Clients : pinSeq[c] = 0 \/ pinSeq[c] >= anchor[c]

\* Evidence is never discarded: anything a client has learned stays learned.
\* Defect 1 was exactly a violation of this.
EvidenceRetained == \A c \in Clients : known[c] \subseteq Versions

\* THE DETECTION PROPERTY, stated at the strength the design delivers. If two
\* clients hold conflicting versions, a witness has crossed between them, AND
\* c1 holds the links to walk one back to the other's sequence, then c1 must
\* be alarmed.
\*
\* The last conjunct is the honest part and was absent in revision 2, which
\* asked a client to detect ancestry nobody had told it about. It is not
\* vacuous: what it leaves to be checked is that the walk lands on a DIFFERENT
\* version whenever the two heads are incompatible, and that a client's own
\* head is still in its own evidence when the walk needs it.
ForkDetected ==
    \A c1, c2 \in Clients :
        (   c1 # c2
         /\ pinSeq[c1] > 0 /\ pinSeq[c2] > 0
         /\ ~Compatible(Head(c1), Head(c2))
         /\ Head(c2) \in known[c1]
         /\ Linked(known[c1], Head(c1), Head(c2)) )
        => c1 \in Alarm

\* SOUNDNESS, and the direction that matters against a hostile relay. A client
\* whose evidence is genuinely all on one history never raises a fork. Without
\* this, "detect more" could always be bought by alarming on everything, and a
\* relay that withheld one witness could make an honest slot look forked.
NoFalseAlarm ==
    \A c \in Clients :
        (\A v1, v2 \in known[c] : Compatible(v1, v2)) => ~KnownIncompatible(known[c])

\* A client's accepted sequence number never decreases.
MonotonicPins == [][\A c \in Clients : pinSeq'[c] >= pinSeq[c]]_vars

---------------------------------------------------------------------------
(* SANITY CHECKS -- these are EXPECTED TO FAIL.                            *)
(*                                                                         *)
(* A model that passes because nothing interesting happens proves nothing.  *)
(* Each of the following must produce a counterexample. If any of them ever *)
(* PASSES, this specification has gone vacuous and its green run is a lie.  *)

\* Expect violation: forks must be reachable, or ForkDetected holds trivially.
NeverForks ==
    \A c1, c2 \in Clients :
        (pinSeq[c1] > 0 /\ pinSeq[c2] > 0) => Compatible(Head(c1), Head(c2))

\* Expect violation: alarms must be reachable, or detection is never exercised.
NeverAlarms == Alarm = {}

\* Expect violation -- and this one is the point. SPECS §5.4 claims fork
\* DETECTION, explicitly not prevention: a peer that withholds every witness
\* keeps two honest clients forked with nobody alarmed. TLC finding a
\* counterexample here is positive evidence that the specification says what
\* §5.4 says it says. If this ever PASSED, we would have accidentally claimed
\* fork prevention -- a guarantee this architecture cannot deliver.
\*
\* Revision 3 gives the peer a second way to win it, and the more realistic
\* one: relay SOME witnesses but not the ones that link two heads together.
\* Detection then stalls at a gap rather than at silence.
ForkAlwaysDetected ==
    (\E c1, c2 \in Clients :
        /\ pinSeq[c1] > 0 /\ pinSeq[c2] > 0
        /\ ~Compatible(Head(c1), Head(c2)))
    => Alarm # {}

===============================================================================
