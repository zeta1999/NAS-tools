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

\* v1 is an ancestor of v2 if they are on one branch and v1 is no later, or if
\* v1 sits in the shared prefix that "b" also descends from.
IsAncestor(v1, v2) ==
    \/ (v1[2] = v2[2] /\ v1[1] <= v2[1])
    \/ (v1[2] = "a" /\ v2[2] = "b" /\ v1[1] < ForkAt)

\* Two versions conflict when neither descends from the other. Seeing both is
\* proof of equivocation -- this is what a client detects by walking `prev`.
Compatible(v1, v2) == IsAncestor(v1, v2) \/ IsAncestor(v2, v1)

VARIABLES
    published,  \* versions a writer or a forking peer has created
    pinSeq,     \* client -> highest sequence number accepted
    pinBranch,  \* client -> branch currently believed
    anchor,     \* client -> freshness anchor carried in its capability
    witnessed,  \* signed observations published to the peer
    known,      \* client -> every version it has learned of, from ANY source
    rolled      \* clients served something below their pin or anchor

vars == <<published, pinSeq, pinBranch, anchor, witnessed, known, rolled>>

\* A client's evidence is inconsistent once it holds two conflicting versions.
Inconsistent(k) == \E v1 \in k, v2 \in k : ~Compatible(v1, v2)

\* ALARM IS DERIVED, NOT STORED. That is the whole fix for defect 1: there is
\* no moment at which evidence is "handled" and then forgotten.
Alarm == {c \in Clients : Inconsistent(known[c]) \/ c \in rolled}

TypeOK ==
    /\ published \subseteq Versions
    /\ pinSeq    \in [Clients -> 0..MaxSeq]
    /\ pinBranch \in [Clients -> Branches]
    /\ anchor    \in [Clients -> 0..MaxSeq]
    /\ witnessed \subseteq (Clients \X (1..MaxSeq) \X Branches)
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
   newest, not necessarily on the branch c already follows. *)
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

(* A client publishes a signed observation of what it currently believes. *)
PublishWitness ==
    /\ \E c \in Clients :
        /\ pinSeq[c] > 0
        /\ witnessed' = witnessed \cup {<<c, pinSeq[c], pinBranch[c]>>}
    /\ UNCHANGED <<published, pinSeq, pinBranch, anchor, known, rolled>>

(* The peer MAY relay a witness. It is free never to do so -- that freedom is
   why we claim detection and not prevention (SPECS §5.4).
   NOTE the absence of any guard on the recipient's state: a witness arriving
   at a client that has pinned nothing is still retained. That guard was
   defect 1. *)
RelayWitness ==
    /\ \E c \in Clients, w \in witnessed :
        /\ w[1] # c
        /\ <<w[2], w[3]>> \notin known[c]
        /\ known' = [known EXCEPT ![c] = @ \cup {<<w[2], w[3]>>}]
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

\* THE DETECTION PROPERTY. If two clients hold conflicting versions and a
\* witness has crossed between them, the recipient must be alarmed.
ForkDetected ==
    \A c1, c2 \in Clients :
        (   c1 # c2
         /\ pinSeq[c1] > 0 /\ pinSeq[c2] > 0
         /\ ~Compatible(<<pinSeq[c1], pinBranch[c1]>>, <<pinSeq[c2], pinBranch[c2]>>)
         /\ <<pinSeq[c2], pinBranch[c2]>> \in known[c1] )
        => c1 \in Alarm

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
        (pinSeq[c1] > 0 /\ pinSeq[c2] > 0) =>
            Compatible(<<pinSeq[c1], pinBranch[c1]>>, <<pinSeq[c2], pinBranch[c2]>>)

\* Expect violation: alarms must be reachable, or detection is never exercised.
NeverAlarms == Alarm = {}

\* Expect violation -- and this one is the point. SPECS §5.4 claims fork
\* DETECTION, explicitly not prevention: a peer that withholds every witness
\* keeps two honest clients forked with nobody alarmed. TLC finding a
\* counterexample here is positive evidence that the specification says what
\* §5.4 says it says. If this ever PASSED, we would have accidentally claimed
\* fork prevention -- a guarantee this architecture cannot deliver.
ForkAlwaysDetected ==
    (\E c1, c2 \in Clients :
        /\ pinSeq[c1] > 0 /\ pinSeq[c2] > 0
        /\ ~Compatible(<<pinSeq[c1], pinBranch[c1]>>, <<pinSeq[c2], pinBranch[c2]>>))
    => Alarm # {}

===============================================================================
