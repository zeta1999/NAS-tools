//! The client's accept decision (SPECS §5.3, §5.5).
//!
//! This is the Rust counterpart of `formal/tlaplus/SlotConsistency.tla`, and
//! the three properties the model checks are the three this module must hold:
//!
//! | TLA+ invariant | Here | Faithful? |
//! |---|---|---|
//! | `AnchorFloor` — a pin never falls below the cap's anchor | [`Reject::BelowAnchor`] | yes |
//! | `MonotonicPins` — pins only move forward | [`Reject::Rollback`] | yes |
//! | `ForkDetected` — incompatible evidence raises once the linking witnesses are known | [`SlotClient::forked`] | yes, under exactly that hypothesis |
//!
//! # What "once the linking witnesses are known" means, precisely
//!
//! A [`Witness`] now carries one **edge of the chain**: the observed record's
//! [`record_hash`](SlotRecord::record_hash) and that record's own `prev`. So a
//! client holding witnesses holds a partial edge relation `record_hash →
//! (seq, prev)`, and [`forked`](Self::forked) raises when two admitted
//! witnesses cannot both describe one history:
//!
//! * **same sequence, different record** — two observations at one `seq`
//!   naming different records. No walk needed; this is all v1 could express.
//! * **different sequences, and the walk links them** — for `w1` at `s1` below
//!   `w2` at `s2`, step back from `w2` along edges the client *actually holds*.
//!   If the walk arrives at `s1` on a record other than `w1`'s, the two
//!   histories differ at `s1`.
//!
//! The hypothesis is the whole of the honesty here. A walk that reaches a hash
//! the client holds no edge for **stops, and raises nothing** — "not proven
//! compatible" is not "proven forked", and a client that guessed would be a
//! client a hostile relay could make cry wolf by withholding one witness. So
//! this is not `Compatible` from the model, which is a *global* ancestry
//! relation available to an omniscient observer; it is `Compatible` restricted
//! to the links this client has been given, and the model now says the same
//! (`Named` / `KnownIncompatible` in `SlotConsistency.tla`, whose `ForkDetected`
//! carries the same hypothesis in its antecedent).
//!
//! Neither half is complete on its own, and neither is claimed to be. SPECS
//! §5.4 promises detection that **converges** as witnesses propagate, not
//! detection on first sight, and a peer that withholds forever defeats both.
//!
//! The walk is bounded by [`MAX_WALK_STEPS`]. It has to be: a client will run
//! it over whatever a relay hands it, and edges relayed at consecutive
//! sequences with a huge gap between the two ends would otherwise be an
//! invitation to iterate for a very long time.
//!
//! # Witnesses must be rostered before they are believed
//!
//! [`Witness::verify`](crate::Witness::verify) checks a signature against the
//! key the witness carries itself, so that a proof stays checkable by a third
//! party. That makes a *bare* proof forgeable: `Role::Witness` identities are
//! derivable by anyone, so a hostile peer can mint two keypairs and produce a
//! verifying `ForkProof` against an honest slot — a permanent false alarm, and
//! a publishable slander.
//!
//! So this module keeps a roster of observers it will believe, and
//! [`observe_witness`] admits nothing outside it. Relaying and re-verifying a
//! proof needs no roster; **acting** on one does.
//!
//! It also bounds what it keeps. Evidence is append-only by design (see below),
//! which without a bound is a peer's invitation to relay witnesses until the
//! client runs out of memory. At most [`MAX_HASHES_PER_SEQ`] distinct hashes are
//! retained per sequence — two already prove a fork, so a third adds nothing —
//! and at most [`MAX_WITNESSES`] witnesses, which is also what bounds the edge
//! relation an ancestry walk runs over.
//!
//! # A record has two names, and they must not share a set
//!
//! `BLAKE3(sig)` ([`sig_hash`](SlotRecord::sig_hash), what a capability's
//! [`Anchor`] carries) and `BLAKE3(domain ‖ body ‖ sig)`
//! ([`record_hash`](SlotRecord::record_hash), what a `prev` and a witness
//! carry) are different bytes for the same record. Putting both into one
//! per-sequence set would make every honest record look like two, and every
//! slot would alarm. So there are two sets per sequence, each append-only and
//! each bounded: the anchor and the public [`observe`] feed the `sig_hash`
//! one, witnesses feed the `record_hash` one, and an offered record — which
//! carries its own bytes — feeds both.
//!
//! # Evidence is re-derived, never latched
//!
//! The first revision of the TLA+ model evaluated evidence only as it arrived
//! and failed its own invariant in seven states: a guard dropped witnesses that
//! came in before the client had a pin, and they were never reconsidered. The
//! fix there was to accumulate *every* observation and make the alarm a derived
//! predicate over the accumulated set. This module does the same — [`observe`]
//! only ever adds, and [`fork_proof`] recomputes. Nothing here decides once and
//! remembers the answer.
//!
//! [`observe`]: SlotClient::observe

use crate::chain::{verify_chain, ChainError};
use crate::id::{SlotId, WriterId};
use crate::record::{Regime, SlotRecord};
use crate::roster::Roster;
use crate::witness::{ForkProof, Witness};
use std::collections::{BTreeMap, BTreeSet};

/// Distinct hashes retained per sequence, in each of the two hash domains.
///
/// Two at one sequence already constitute a fork; a third proves nothing more
/// and would let a peer grow this map without limit.
pub const MAX_HASHES_PER_SEQ: usize = 2;

/// Retained witnesses, from which a publishable proof is built.
pub const MAX_WITNESSES: usize = 64;

/// The longest ancestry walk [`SlotClient::forked`] will run between two
/// witnesses at different sequences.
///
/// The walk needs a distinct known edge per step and edges come only from
/// retained witnesses, so it could not exceed [`MAX_WITNESSES`] steps anyway;
/// this states the bound rather than leaving it as a consequence of two other
/// numbers. A pair further apart than this is left **unproven** — no alarm,
/// which is the safe direction — rather than walked on the chance that a
/// hostile relay stocked every sequence in between.
pub const MAX_WALK_STEPS: usize = MAX_WITNESSES;

// A proof carries the link it walked, so the two bounds have to agree or a
// client could derive an alarm it cannot publish.
const _: () = assert!(MAX_WALK_STEPS <= crate::witness::MAX_LINK);

/// Add one hash at one sequence, never past [`MAX_HASHES_PER_SEQ`].
fn add_bounded(m: &mut BTreeMap<u64, BTreeSet<[u8; 32]>>, seq: u64, hash: [u8; 32]) {
    let set = m.entry(seq).or_default();
    if set.len() < MAX_HASHES_PER_SEQ || set.contains(&hash) {
        set.insert(hash);
    }
}

/// Step `high` back along the edges in `edges` until the record at `target` is
/// named. Returns the witnesses stepped through (at `high.seq - 1 … target + 1`,
/// in that order) and the `record_hash` the walk arrives at.
///
/// `None` — "not proven" — when a step's hash has no known edge, when an edge
/// sits at a sequence the walk did not expect, or when the two are further
/// apart than [`MAX_WALK_STEPS`]. Every one of those is a refusal to conclude,
/// never a conclusion: see [`SlotClient::witness_conflict`].
fn walk_to<'a>(
    edges: &BTreeMap<[u8; 32], &'a Witness>,
    high: &'a Witness,
    target: u64,
) -> Option<(Vec<&'a Witness>, [u8; 32])> {
    if target >= high.seq || high.seq - target > MAX_WALK_STEPS as u64 {
        return None;
    }
    let mut link = Vec::new();
    // `hash` is the record at `seq`, as named by the step above it. The first
    // step is free: `high` signed its own `prev`.
    let mut hash = high.prev;
    let mut seq = high.seq - 1;
    while seq > target {
        let w = *edges.get(&hash)?;
        if w.seq != seq {
            // A witness signing a record_hash at a sequence the chain does not
            // put it at. Refused rather than followed: the walk's arithmetic is
            // what makes "arrived at `target`" mean anything.
            return None;
        }
        link.push(w);
        hash = w.prev;
        seq -= 1;
    }
    Some((link, hash))
}

/// The freshness anchor a capability carries (SPECS §5.3.1).
///
/// Every cap records the `(seq, sig_hash)` current when it was issued, so a
/// *fresh* client — a new device, a restored laptop — can never be served
/// anything older. Revision 1 had no anchor, so a client with no pin accepted
/// any validly signed historical record: a rollback that looked identical to a
/// first sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub sig_hash: [u8; 32],
}

/// What a client has accepted so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    pub seq: u64,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// Older than the anchor in the capability. A rollback against a client
    /// that has no history of its own to compare against.
    BelowAnchor { offered: u64, anchor: u64 },
    /// At the anchor's sequence but not the anchor's record: the peer is
    /// serving a different history than the one the cap was issued against.
    AnchorMismatch { seq: u64 },
    /// Older than what this client already accepted.
    Rollback { offered: u64, pinned: u64 },
    /// The chain did not verify.
    Chain(ChainError),
    /// Offered for a different slot.
    WrongSlot,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BelowAnchor { offered, anchor } => {
                write!(
                    f,
                    "offered seq {offered} is below the cap anchor at {anchor}"
                )
            }
            Self::AnchorMismatch { seq } => {
                write!(
                    f,
                    "seq {seq} does not match the record the cap was anchored to"
                )
            }
            Self::Rollback { offered, pinned } => {
                write!(f, "offered seq {offered} is behind the pinned seq {pinned}")
            }
            Self::Chain(e) => write!(f, "{e}"),
            Self::WrongSlot => write!(f, "offered history is for a different slot"),
        }
    }
}
impl std::error::Error for Reject {}

/// The outcome of being offered a new head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Verified end to end and pinned.
    Accepted { pin: Pin },
    /// Accepted on the anchor plus the head signature alone, because the peer
    /// no longer retains enough history to walk (SPECS §5.5).
    ///
    /// **A warning, never a silent success.** Losing the chain has to be
    /// visible or retain-N quietly becomes "trust the peer".
    Degraded { pin: Pin, reason: &'static str },
    /// Refused.
    Rejected(Reject),
    /// Evidence of a fork. Publishable on its own.
    Alarm(Box<ForkProof>),
}

/// One client's view of one slot.
#[derive(Debug, Clone)]
pub struct SlotClient {
    slot_id: SlotId,
    regime: Regime,
    anchor: Anchor,
    pin: Option<Pin>,
    /// Every `(seq, sig_hash)` ever learned of: the cap anchor, and every
    /// record offered. Append-only — see the module docs on why evidence is
    /// never dropped.
    evidence: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// Every `(seq, record_hash)` ever learned of: every record offered, and
    /// every admitted witness. A second map rather than more entries in the
    /// first, because the two hashes name the same record with different bytes
    /// — see the module docs.
    record_evidence: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// Witnesses kept so a derived alarm can be turned into a publishable
    /// proof, and so an ancestry walk has edges to follow.
    witnesses: Vec<Witness>,
    /// Observers this client will believe. Empty means believe none — the safe
    /// default, since an unrostered witness is one anybody could have minted.
    witness_roster: Roster,
}

impl SlotClient {
    /// A client bootstrapped from a capability.
    pub fn new(slot_id: SlotId, regime: Regime, anchor: Anchor) -> Self {
        let mut evidence = BTreeMap::new();
        evidence.insert(anchor.seq, BTreeSet::from([anchor.sig_hash]));
        Self {
            slot_id,
            regime,
            anchor,
            pin: None,
            evidence,
            record_evidence: BTreeMap::new(),
            witnesses: Vec::new(),
            witness_roster: Roster::new(),
        }
    }

    /// Add an observer whose witnesses this client will act on.
    ///
    /// A client with an empty roster believes no witness at all — the safe
    /// default, since an unrostered witness is one anybody could have minted.
    pub fn trust_witness(&mut self, verifying_key: &[u8]) -> Result<(), crate::RosterError> {
        self.witness_roster.add(verifying_key).map(|_| ())
    }

    pub fn trusted_witnesses(&self) -> usize {
        self.witness_roster.len()
    }

    pub fn slot_id(&self) -> SlotId {
        self.slot_id
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    pub fn pin(&self) -> Option<Pin> {
        self.pin
    }

    /// Record an observation by the record's `sig_hash`. Only ever adds, and
    /// never past the bound.
    ///
    /// The bound is not a compromise of the append-only design: two hashes at
    /// one sequence already prove a fork, so refusing a third loses nothing and
    /// removes a peer's ability to grow this map at will.
    pub fn observe(&mut self, seq: u64, sig_hash: [u8; 32]) {
        add_bounded(&mut self.evidence, seq, sig_hash);
    }

    /// Record an observation by the record's `record_hash`.
    ///
    /// The other of the two names a record has. Kept apart from [`observe`]'s
    /// map on purpose — see the module docs.
    fn observe_record_hash(&mut self, seq: u64, record_hash: [u8; 32]) {
        add_bounded(&mut self.record_evidence, seq, record_hash);
    }

    /// Take in a witness relayed by the peer.
    ///
    /// Three gates, and the roster is the one that was missing. A valid
    /// signature proves only that *somebody* signed; since anyone can derive a
    /// `Role::Witness` identity, a peer that could get an unrostered witness
    /// admitted could manufacture a fork alarm against an honest slot — making
    /// the alarm worthless in the other direction.
    pub fn observe_witness(&mut self, w: &Witness) -> bool {
        if w.slot_id != self.slot_id {
            return false;
        }
        if !self
            .witness_roster
            .contains(&WriterId::of_key(&w.witness_pk))
        {
            return false;
        }
        // `verify` also enforces the genesis rule, so a witness claiming an
        // empty predecessor anywhere but seq 0 never enters the edge relation.
        if w.verify().is_err() {
            return false;
        }
        self.observe_record_hash(w.seq, w.record_hash);
        if self.witnesses.len() < MAX_WITNESSES {
            self.witnesses.push(w.clone());
        }
        true
    }

    /// How many distinct `sig_hash` values are retained at `seq`. For tests and
    /// diagnostics; bounded by [`MAX_HASHES_PER_SEQ`].
    pub fn evidence_at(&self, seq: u64) -> usize {
        self.evidence.get(&seq).map(|s| s.len()).unwrap_or(0)
    }

    /// How many distinct `record_hash` values are retained at `seq`.
    pub fn record_evidence_at(&self, seq: u64) -> usize {
        self.record_evidence.get(&seq).map(|s| s.len()).unwrap_or(0)
    }

    /// Is there evidence of a fork, and at which sequence? Derived, never
    /// cached — nothing here decides once and remembers the answer.
    ///
    /// Three sources, and the lowest sequence any of them names wins, because
    /// that is where the histories actually part:
    ///
    /// 1. two `sig_hash` values at one sequence (the anchor, and offers);
    /// 2. two `record_hash` values at one sequence (offers, and witnesses);
    /// 3. two witnesses at *different* sequences that the client holds enough
    ///    edges to link — see [`witness_conflict`](Self::witness_conflict).
    pub fn forked(&self) -> Option<u64> {
        let by_hash = |m: &BTreeMap<u64, BTreeSet<[u8; 32]>>| {
            m.iter().find(|(_, hs)| hs.len() > 1).map(|(seq, _)| *seq)
        };
        [
            by_hash(&self.evidence),
            by_hash(&self.record_evidence),
            self.witness_conflict().map(|(seq, _, _, _)| seq),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The edge relation this client holds: `record_hash → (seq, prev)`, one
    /// entry per admitted witness.
    ///
    /// Re-derived on every call rather than maintained alongside `witnesses`,
    /// for the same reason [`forked`](Self::forked) is derived: a cache is a
    /// place for evidence to be consumed and lost, which is exactly the defect
    /// the TLA+ model caught in its first revision.
    ///
    /// Two witnesses naming one `record_hash` with different `(seq, prev)`
    /// would need a BLAKE3 collision *or* a signer lying about a record it did
    /// not observe; the first is out of scope and the second is what the
    /// roster is for. Whichever arrives first wins, and a walk that follows a
    /// liar's edge is a liar's problem — the roster decided to believe it.
    fn edges(&self) -> BTreeMap<[u8; 32], &Witness> {
        let mut m = BTreeMap::new();
        for w in &self.witnesses {
            m.entry(w.record_hash).or_insert(w);
        }
        m
    }

    /// Two admitted witnesses at different sequences that cannot both describe
    /// one history, with the link that shows it.
    ///
    /// Returns `(seq, low, high, link)`: the sequence at which the two
    /// histories differ, the witness sitting there, the higher witness, and the
    /// witnesses stepping the higher one down — exactly the shape
    /// [`ForkProof::try_linked`] wants.
    ///
    /// **Soundness before completeness.** A walk that reaches a hash this
    /// client holds no edge for stops and reports nothing: not proven
    /// compatible is not proven forked. So withholding one witness downgrades
    /// this to silence, never to a false alarm.
    fn witness_conflict(&self) -> Option<(u64, &Witness, &Witness, Vec<Witness>)> {
        let edges = self.edges();
        let mut best: Option<(u64, &Witness, &Witness, Vec<&Witness>)> = None;
        for high in &self.witnesses {
            for low in &self.witnesses {
                if low.seq >= high.seq {
                    continue;
                }
                // The lowest sequence wins — that is where the histories part
                // — and among those the nearest `high`, which is the shortest
                // walk and so the smallest proof.
                if best
                    .as_ref()
                    .is_some_and(|(s, _, h, _)| (low.seq, high.seq) >= (*s, h.seq))
                {
                    continue;
                }
                if let Some((link, reached)) = walk_to(&edges, high, low.seq) {
                    // The walk names a record at `low.seq`. If it is the one
                    // `low` named, these two are on one history: no alarm.
                    if reached != low.record_hash {
                        best = Some((low.seq, low, high, link));
                    }
                }
            }
        }
        best.map(|(seq, low, high, link)| (seq, low, high, link.into_iter().cloned().collect()))
    }

    /// A publishable proof, if the witnesses this client holds contain one.
    ///
    /// [`forked`] can be true without this returning a proof: a client can know
    /// it was served two histories without holding the *signed* observations to
    /// show anyone. That is a real distinction and not a gap to paper over —
    /// SPECS §5.4 is explicit that detection converges only once witnesses
    /// propagate. Reporting "forked, but I cannot yet prove it" honestly is
    /// better than inventing a proof.
    ///
    /// Same-sequence conflicts are looked for first: they cost two signature
    /// checks and produce the smallest proof. A linked proof carries every
    /// witness the walk stepped through, because the recipient re-walks rather
    /// than believes.
    ///
    /// # Every proof this can derive today has an empty link, and that is a fact
    ///
    /// Worth stating rather than leaving to be rediscovered. Every edge comes
    /// from a witness, and a witness states the sequence it sits at, so a walk
    /// that arrives at sequence `s` must have stepped through a witness at
    /// `s + 1` — and *that* witness paired with the one at `s` is already a
    /// one-step conflict. `witness_conflict` prefers the nearest `high`, so it
    /// finds that shorter form first and `link` comes back empty.
    ///
    /// The general walk is implemented anyway, and is not decoration: it is the
    /// rule, stated at the width the model states it (`Named` in
    /// `SlotConsistency.tla`); [`ForkProof::verify`] must re-check a linked
    /// proof whoever built it; and the bound and the gap rule are what make
    /// either form sound. `a_derived_proof_is_the_shortest_one` pins the
    /// reduction so it stays a fact and not an assumption.
    ///
    /// [`forked`]: Self::forked
    pub fn fork_proof(&self) -> Option<ForkProof> {
        for (i, a) in self.witnesses.iter().enumerate() {
            for b in &self.witnesses[i + 1..] {
                if let Some(p) = ForkProof::try_new(a, b) {
                    return Some(p);
                }
            }
        }
        let (_, low, high, link) = self.witness_conflict()?;
        ForkProof::try_linked(low, high, link)
    }

    /// Offer a verified chain reaching a new head.
    ///
    /// `records` must be contiguous and reach from the client's pin (or from
    /// the anchor, for a fresh client) to the head.
    pub fn offer(&mut self, records: &[SlotRecord], roster: &Roster) -> Verdict {
        let Some(head) = records.last() else {
            return Verdict::Rejected(Reject::Chain(ChainError::Empty));
        };
        if head.slot_id != self.slot_id {
            return Verdict::Rejected(Reject::WrongSlot);
        }

        // Evidence first: an offer that is about to be rejected is still
        // evidence of what the peer is willing to serve, and dropping it is
        // exactly the mistake the TLA+ model caught.
        // Both names, because a record carries its own bytes: the `sig_hash`
        // the anchor speaks in, and the `record_hash` a witness speaks in.
        for r in records {
            self.observe(r.seq, r.sig_hash());
            self.observe_record_hash(r.seq, r.record_hash());
        }
        if let Some(p) = self.fork_proof() {
            return Verdict::Alarm(Box::new(p));
        }

        if head.seq < self.anchor.seq {
            return Verdict::Rejected(Reject::BelowAnchor {
                offered: head.seq,
                anchor: self.anchor.seq,
            });
        }
        if let Some(pin) = self.pin {
            if head.seq < pin.seq {
                return Verdict::Rejected(Reject::Rollback {
                    offered: head.seq,
                    pinned: pin.seq,
                });
            }
        }

        let expect_prev = self.pin.map(|p| p.record_hash);
        let walk = match verify_chain(records, self.slot_id, roster, expect_prev) {
            Ok(w) => w,
            Err(e) => return Verdict::Rejected(Reject::Chain(e)),
        };
        if walk.regime != self.regime {
            return Verdict::Rejected(Reject::Chain(ChainError::RegimeChanged {
                seq: walk.first_seq,
                from: self.regime,
                to: walk.regime,
            }));
        }

        // The anchor pins one specific record, not merely a height. A peer that
        // forked at or before the anchor would otherwise satisfy the floor with
        // a different history of the same length.
        if let Some(r) = records.iter().find(|r| r.seq == self.anchor.seq) {
            if r.sig_hash() != self.anchor.sig_hash {
                return Verdict::Rejected(Reject::AnchorMismatch {
                    seq: self.anchor.seq,
                });
            }
        }

        let pin = Pin {
            seq: walk.head_seq,
            record_hash: walk.head_hash,
        };
        self.pin = Some(pin);
        Verdict::Accepted { pin }
    }

    /// Accept a head that cannot be chain-walked, because the peer no longer
    /// retains the history between here and there (SPECS §5.5).
    ///
    /// Verified against the anchor and the head's own signature only. Always
    /// [`Verdict::Degraded`] on success — a caller cannot mistake this for a
    /// full verification, because it is a different variant rather than a flag
    /// on the same one.
    pub fn offer_head_only(&mut self, head: &SlotRecord, roster: &Roster) -> Verdict {
        if head.slot_id != self.slot_id {
            return Verdict::Rejected(Reject::WrongSlot);
        }
        self.observe(head.seq, head.sig_hash());
        self.observe_record_hash(head.seq, head.record_hash());
        if let Some(p) = self.fork_proof() {
            return Verdict::Alarm(Box::new(p));
        }
        if head.seq < self.anchor.seq {
            return Verdict::Rejected(Reject::BelowAnchor {
                offered: head.seq,
                anchor: self.anchor.seq,
            });
        }
        if head.seq == self.anchor.seq && head.sig_hash() != self.anchor.sig_hash {
            return Verdict::Rejected(Reject::AnchorMismatch { seq: head.seq });
        }
        if let Some(pin) = self.pin {
            if head.seq < pin.seq {
                return Verdict::Rejected(Reject::Rollback {
                    offered: head.seq,
                    pinned: pin.seq,
                });
            }
        }
        let Some(vk) = roster.get(&head.writer_id) else {
            return Verdict::Rejected(Reject::Chain(ChainError::UnknownWriter {
                seq: head.seq,
                writer: head.writer_id,
            }));
        };
        if let Err(e) = head.verify(vk) {
            return Verdict::Rejected(Reject::Chain(ChainError::Record {
                seq: head.seq,
                source: e,
            }));
        }
        if head.regime != self.regime {
            return Verdict::Rejected(Reject::Chain(ChainError::RegimeChanged {
                seq: head.seq,
                from: self.regime,
                to: head.regime,
            }));
        }

        let pin = Pin {
            seq: head.seq,
            record_hash: head.record_hash(),
        };
        self.pin = Some(pin);
        Verdict::Degraded {
            pin,
            reason: "peer no longer retains history back to the pin; \
                     verified on cap anchor and head signature only",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_core::Addr;
    use nas_crypto::{Identity, Role};

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    fn witness_ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Witness).unwrap()
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"bucket")
    }

    fn chain_of(id: &Identity, n: u64, tag: &str) -> Vec<SlotRecord> {
        let mut out: Vec<SlotRecord> = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = SlotRecord::sign(
                id,
                slot(),
                seq,
                Addr::of_ciphertext(format!("{tag}-{seq}").as_bytes()),
                [1u8; crate::ROOT_NONCE_LEN],
                prev,
                Regime::CasMerge,
            )
            .unwrap();
            prev = r.record_hash();
            out.push(r);
        }
        out
    }

    /// A witness of `seq` naming record `h`, descending from `p`.
    fn wit(id: &Identity, seq: u64, h: u8, p: u8) -> Witness {
        Witness::sign(id, slot(), seq, [h; 32], [p; 32], 0).unwrap()
    }

    fn roster_of(id: &Identity) -> Roster {
        let mut r = Roster::new();
        r.add(id.verifying_key()).unwrap();
        r
    }

    fn fresh(c: &[SlotRecord]) -> SlotClient {
        SlotClient::new(
            slot(),
            Regime::CasMerge,
            Anchor {
                seq: c[0].seq,
                sig_hash: c[0].sig_hash(),
            },
        )
    }

    #[test]
    fn a_valid_chain_is_accepted_and_pinned() {
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        match cl.offer(&c, &roster_of(&id)) {
            Verdict::Accepted { pin } => assert_eq!(pin.seq, 3),
            other => panic!("{other:?}"),
        }
        assert_eq!(cl.pin().unwrap().seq, 3);
    }

    #[test]
    fn anchor_floor_blocks_a_rollback_against_a_fresh_client() {
        // Revision 1's bootstrapping hole: a client with no pin accepted any
        // validly signed historical record, so a rollback and a first sync
        // were indistinguishable.
        let id = ident(1);
        let c = chain_of(&id, 6, "a");
        let mut cl = SlotClient::new(
            slot(),
            Regime::CasMerge,
            Anchor {
                seq: 4,
                sig_hash: c[4].sig_hash(),
            },
        );
        // The peer offers a genuinely signed, genuinely chained older history.
        match cl.offer(&c[..3], &roster_of(&id)) {
            Verdict::Rejected(Reject::BelowAnchor {
                offered: 2,
                anchor: 4,
            }) => {}
            other => panic!("rollback accepted: {other:?}"),
        }
        assert!(cl.pin().is_none(), "a rejected offer must not move the pin");
    }

    #[test]
    fn the_anchor_pins_a_record_not_merely_a_height() {
        // A fork at or before the anchor would otherwise clear the floor with
        // a different history of the same length.
        let (a, b) = (ident(1), ident(2));
        let mut roster = Roster::new();
        roster.add(a.verifying_key()).unwrap();
        roster.add(b.verifying_key()).unwrap();

        let honest = chain_of(&a, 4, "honest");
        let forged = chain_of(&b, 4, "forged");
        let mut cl = SlotClient::new(
            slot(),
            Regime::CasMerge,
            Anchor {
                seq: 1,
                sig_hash: honest[1].sig_hash(),
            },
        );
        match cl.offer(&forged, &roster) {
            Verdict::Rejected(Reject::AnchorMismatch { seq: 1 }) => {}
            // Two histories at seq 1 is also evidence of a fork; either
            // response is correct, silence is not.
            Verdict::Alarm(_) => {}
            other => panic!("forged history accepted: {other:?}"),
        }
    }

    #[test]
    fn pins_only_move_forward() {
        let id = ident(1);
        let c = chain_of(&id, 6, "a");
        let rost = roster_of(&id);
        let mut cl = fresh(&c);
        assert!(matches!(cl.offer(&c[..5], &rost), Verdict::Accepted { .. }));
        let before = cl.pin().unwrap();

        // The peer now offers the shorter prefix it served earlier.
        match cl.offer(&c[..3], &rost) {
            Verdict::Rejected(Reject::Rollback {
                offered: 2,
                pinned: 4,
            }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(cl.pin().unwrap(), before, "a rejected offer moved the pin");
    }

    #[test]
    fn a_continuation_from_the_pin_is_accepted() {
        let id = ident(1);
        let c = chain_of(&id, 8, "a");
        let rost = roster_of(&id);
        let mut cl = fresh(&c);
        assert!(matches!(cl.offer(&c[..4], &rost), Verdict::Accepted { .. }));
        match cl.offer(&c[4..], &rost) {
            Verdict::Accepted { pin } => assert_eq!(pin.seq, 7),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_suffix_that_does_not_continue_the_pin_is_refused() {
        let id = ident(1);
        let a = chain_of(&id, 8, "a");
        let b = chain_of(&id, 8, "b"); // a different history, same writer
        let rost = roster_of(&id);
        let mut cl = fresh(&a);
        assert!(matches!(cl.offer(&a[..4], &rost), Verdict::Accepted { .. }));
        // Offering b's later half: signed, chained internally, wrong history.
        match cl.offer(&b[4..], &rost) {
            Verdict::Rejected(Reject::Chain(ChainError::BrokenLink { seq: 4 })) => {}
            Verdict::Alarm(_) => {}
            other => panic!("cross-history splice accepted: {other:?}"),
        }
    }

    #[test]
    fn conflicting_witnesses_raise_an_alarm_with_a_proof() {
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);

        let (ia, ib) = (witness_ident(10), witness_ident(11));
        cl.trust_witness(ia.verifying_key()).unwrap();
        cl.trust_witness(ib.verifying_key()).unwrap();
        let wa = wit(&ia, 2, 0x01, 0xC0);
        let wb = wit(&ib, 2, 0x02, 0xC0);
        assert!(cl.observe_witness(&wa));
        assert!(cl.observe_witness(&wb));

        assert_eq!(cl.forked(), Some(2));
        let p = cl
            .fork_proof()
            .expect("two conflicting witnesses are a proof");
        assert!(p.verify());
        assert!(p.link.is_empty(), "same-sequence proofs need no walk");
        assert!(matches!(cl.offer(&c, &roster_of(&id)), Verdict::Alarm(_)));
    }

    #[test]
    fn a_witness_arriving_before_any_pin_is_still_remembered() {
        // The exact defect the first TLA+ revision had: a guard dropped
        // witnesses that arrived before the client had a pin, and they were
        // never reconsidered. Evidence must accumulate unconditionally.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        assert!(cl.pin().is_none());

        let (ia, ib) = (witness_ident(10), witness_ident(11));
        cl.trust_witness(ia.verifying_key()).unwrap();
        cl.trust_witness(ib.verifying_key()).unwrap();
        let wa = wit(&ia, 3, 0x01, 0xC0);
        let wb = wit(&ib, 3, 0x02, 0xC0);
        cl.observe_witness(&wa);
        cl.observe_witness(&wb);
        assert_eq!(
            cl.forked(),
            Some(3),
            "evidence dropped before the first pin"
        );
    }

    #[test]
    fn an_unsigned_witness_cannot_manufacture_an_alarm() {
        // The peer relays witnesses. If it could inject one, it could raise a
        // false alarm against an honest slot -- which would make the alarm
        // worthless in the other direction.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let ia = witness_ident(10);
        cl.trust_witness(ia.verifying_key()).unwrap();
        let good = wit(&ia, 2, 0x01, 0xC0);
        let mut forged = good.clone();
        forged.record_hash = [0x02; 32];
        assert!(cl.observe_witness(&good));
        assert!(!cl.observe_witness(&forged), "unsigned witness accepted");
        assert_eq!(cl.forked(), None);
    }

    #[test]
    fn a_peer_cannot_alarm_a_client_with_witness_keys_of_its_own() {
        // The attack the old suite missed entirely. `Role::Witness` identities
        // are derivable by anyone, so a valid signature proves only that
        // SOMEBODY signed. Without a roster this was a permanent false alarm on
        // any slot -- and a publishable slander against an honest writer.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let honest = witness_ident(10);
        cl.trust_witness(honest.verifying_key()).unwrap();

        let evil_a = Identity::derive(&[0xE1; 32], Role::Witness).unwrap();
        let evil_b = Identity::derive(&[0xE2; 32], Role::Witness).unwrap();
        let wa = wit(&evil_a, 2, 0x01, 0xC0);
        let wb = wit(&evil_b, 2, 0x02, 0xC0);

        // Both are perfectly valid signatures, and both are refused.
        assert!(wa.verify().is_ok() && wb.verify().is_ok());
        assert!(!cl.observe_witness(&wa), "unrostered witness admitted");
        assert!(!cl.observe_witness(&wb), "unrostered witness admitted");
        assert_eq!(cl.forked(), None, "a peer manufactured a fork alarm");
        assert!(cl.fork_proof().is_none());
    }

    #[test]
    fn evidence_is_bounded_so_a_peer_cannot_exhaust_memory() {
        // Append-only evidence with no bound is an invitation to relay
        // witnesses until the client dies. Two hashes at one seq already prove
        // a fork, so the third onwards adds nothing.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        for i in 0..1000u32 {
            cl.observe(7, {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&i.to_le_bytes());
                h
            });
        }
        assert_eq!(cl.evidence_at(7), MAX_HASHES_PER_SEQ);
        assert_eq!(cl.forked(), Some(7), "the fork is still detected");
    }

    #[test]
    fn a_witness_for_another_slot_is_ignored() {
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let w = Witness::sign(
            &witness_ident(10),
            SlotId::new(b"ns", b"other"),
            2,
            [1u8; 32],
            [0xC0; 32],
            0,
        )
        .unwrap();
        assert!(!cl.observe_witness(&w));
        assert_eq!(cl.forked(), None);
    }

    #[test]
    fn a_fork_at_disjoint_sequences_is_detected_once_the_links_are_known() {
        // What used to be `a_fork_at_disjoint_sequences_is_not_detected`, and
        // was the documented gap: in a real fork each device witnesses its own
        // head, so the two live branches sit at different sequence numbers.
        // A v1 Witness carried no ancestry, so nothing here could see it.
        //
        // Now a witness carries the edge below the record it names, and the
        // client walks branch b back to branch a's sequence and compares there.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let (ia, ib) = (witness_ident(10), witness_ident(11));
        cl.trust_witness(ia.verifying_key()).unwrap();
        cl.trust_witness(ib.verifying_key()).unwrap();

        // Branch a is at seq 5 (record 0xA5). Branch b runs 0xB5 → 0xB6 → 0xB7
        // and its foot at seq 5 is 0xB5, not 0xA5. Genuinely forked.
        let low = wit(&ia, 5, 0xA5, 0xA4);
        let six = wit(&ib, 6, 0xB6, 0xB5);
        let seven = wit(&ib, 7, 0xB7, 0xB6);
        for w in [&low, &six, &seven] {
            assert!(cl.observe_witness(w), "witness not admitted");
        }

        assert_eq!(cl.forked(), Some(5), "the walk did not reach seq 5");
        let p = cl.fork_proof().expect("the link is a publishable proof");
        assert!(p.verify(), "the proof does not re-walk");
        assert_eq!(p.seq, 5);
        assert_eq!(p.a, low);
        // The shortest form: `six` sits one above `low` and its `prev` already
        // names a record `low` disagrees with, so `seven` is not needed to
        // show it. See `a_derived_proof_is_the_shortest_one`.
        assert_eq!(p.b, six);
        assert!(p.link.is_empty());
    }

    #[test]
    fn a_derived_proof_is_the_shortest_one() {
        // Pins the reduction the module docs name: every edge comes from a
        // witness that states its own sequence, so a walk arriving at seq `s`
        // stepped through a witness at `s + 1`, and that pair is already a
        // one-step proof. A derived proof therefore never carries a link --
        // however many steps apart the two branches' heads are.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let ia = witness_ident(10);
        cl.trust_witness(ia.verifying_key()).unwrap();

        // Branch a at seq 2; branch b runs seq 3..9, every step witnessed.
        assert!(cl.observe_witness(&wit(&ia, 2, 0xA2, 0xA1)));
        for s in 3..=9u64 {
            assert!(cl.observe_witness(&wit(&ia, s, 0xB0 + s as u8, 0xB0 + (s - 1) as u8)));
        }
        let p = cl
            .fork_proof()
            .expect("seven linked steps and still a proof");
        assert!(p.verify());
        assert_eq!(p.seq, 2);
        assert_eq!(p.b.seq, 3, "a longer proof than necessary was built");
        assert!(p.link.is_empty());
    }

    #[test]
    fn a_gap_in_the_walk_raises_nothing() {
        // Soundness, and the property a hostile relay would attack if it were
        // missing: withhold the witness at seq 6 and the walk from seq 7 runs
        // out of edges before it reaches seq 5. "Not proven compatible" is not
        // "proven forked", so this must be silence -- not an alarm, and not a
        // guess.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let (ia, ib) = (witness_ident(10), witness_ident(11));
        cl.trust_witness(ia.verifying_key()).unwrap();
        cl.trust_witness(ib.verifying_key()).unwrap();

        assert!(cl.observe_witness(&wit(&ia, 5, 0xA5, 0xA4)));
        assert!(cl.observe_witness(&wit(&ib, 7, 0xB7, 0xB6))); // 6 withheld

        assert_eq!(
            cl.forked(),
            None,
            "a fork alarm was manufactured from a gap"
        );
        assert!(cl.fork_proof().is_none());
    }

    #[test]
    fn a_chain_that_links_across_sequences_is_not_a_fork() {
        // The other half of soundness, and the ordinary case: two devices on
        // ONE history at different heads. The walk reaches seq 5 and finds
        // exactly the record the low witness named. Crying fork here would
        // make the alarm worthless.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let (ia, ib) = (witness_ident(10), witness_ident(11));
        cl.trust_witness(ia.verifying_key()).unwrap();
        cl.trust_witness(ib.verifying_key()).unwrap();

        // 0xA5 → 0xA6 → 0xA7, and the foot of the walk is 0xA5.
        for w in [
            wit(&ia, 5, 0xA5, 0xA4),
            wit(&ib, 6, 0xA6, 0xA5),
            wit(&ib, 7, 0xA7, 0xA6),
        ] {
            assert!(cl.observe_witness(&w));
        }
        assert_eq!(cl.forked(), None, "one history read as two");
        assert!(cl.fork_proof().is_none());
    }

    #[test]
    fn a_witness_of_seq_zero_with_a_non_zero_prev_is_refused() {
        // The genesis rule, mirroring `SlotRecord`'s. A witness that could
        // claim an empty predecessor anywhere -- or a non-empty one at genesis
        // -- could stop somebody's walk on a hash of its own choosing.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        let ia = witness_ident(10);
        cl.trust_witness(ia.verifying_key()).unwrap();

        // It cannot even be signed...
        assert!(Witness::sign(&ia, slot(), 0, [0xA0; 32], [0x01; 32], 0).is_err());
        // ...and a hand-built one is refused at the door.
        let mut forged = Witness::sign(&ia, slot(), 0, [0xA0; 32], [0u8; 32], 0).unwrap();
        forged.prev = [0x01; 32];
        assert!(!cl.observe_witness(&forged), "genesis rule not enforced");
        assert_eq!(cl.forked(), None);
    }

    #[test]
    fn a_span_past_the_bound_is_refused_rather_than_walked() {
        // A relay controls both ends of the gap it hands over, so the walk
        // needs a stated maximum. Tested on `walk_to` directly and not through
        // `forked`, because MAX_WITNESSES already caps what one client can
        // assemble at exactly MAX_WALK_STEPS edges: going through the client
        // would test retention, not this bound. The bound has to hold on its
        // own -- it is what keeps a derived link inside `MAX_LINK`, and what
        // would still refuse if the retention cap were ever raised.
        let ia = witness_ident(10);
        let n = MAX_WALK_STEPS as u64 + 1;
        // A perfect chain: seq s names record `s`, descending from `s - 1`.
        let chain: Vec<Witness> = (1..=n + 1)
            .map(|s| wit(&ia, s, (s + 0x80) as u8, (s + 0x7F) as u8))
            .collect();
        let edges: BTreeMap<[u8; 32], &Witness> =
            chain.iter().map(|w| (w.record_hash, w)).collect();
        let high = chain.last().unwrap();

        // Exactly at the bound the walk runs; one further and it refuses,
        // with every edge present either way.
        assert!(
            walk_to(&edges, high, high.seq - MAX_WALK_STEPS as u64).is_some(),
            "the bound refused a span it should walk"
        );
        assert!(
            walk_to(&edges, high, high.seq - MAX_WALK_STEPS as u64 - 1).is_none(),
            "a span past the bound was walked"
        );
        // And an absurd span -- what a relay would actually hand over -- costs
        // one comparison, not 2^63 iterations.
        assert!(walk_to(&edges, high, 0).is_none());
    }

    #[test]
    fn a_fork_below_the_served_head_is_detected_by_the_offer_alone() {
        // The other route to the same answer, and what `nas peer sync` relies
        // on: ONE witness is enough when the peer's own history covers the
        // sequence it names. Every record offered is evidence at its own
        // sequence, so a witness citing a different record below the served
        // head collides with the chain right there -- no walk, and no second
        // witness to link to.
        let id = ident(1);
        let c = chain_of(&id, 6, "a");
        let mut cl = fresh(&c);
        let ia = witness_ident(10);
        cl.trust_witness(ia.verifying_key()).unwrap();
        // Another device witnessed seq 3 on a branch this chain does not hold.
        let wa = wit(&ia, 3, 0xA1, 0xA0);
        assert!(cl.observe_witness(&wa));
        assert_eq!(cl.forked(), None, "one observation alone is not a fork");

        let v = cl.offer(&c, &roster_of(&id));
        assert!(
            !matches!(v, Verdict::Alarm(_)),
            "one witness is not a publishable proof, so no Alarm: {v:?}"
        );
        // ...but the evidence is there, and a caller that consults `forked`
        // -- as the CLI does before believing a head -- sees it.
        assert_eq!(cl.forked(), Some(3));
        assert!(cl.fork_proof().is_none());
    }

    #[test]
    fn forked_can_be_true_without_a_publishable_proof() {
        // An honest distinction rather than a gap: the client was served two
        // histories but holds only one signed observation, so it knows and
        // cannot yet show anyone. SPECS §5.4 says detection converges once
        // witnesses propagate, not immediately.
        let id = ident(1);
        let c = chain_of(&id, 4, "a");
        let mut cl = fresh(&c);
        cl.observe(2, [0xAA; 32]);
        cl.observe(2, [0xBB; 32]);
        assert_eq!(cl.forked(), Some(2));
        assert!(cl.fork_proof().is_none());
    }

    #[test]
    fn degraded_acceptance_is_a_distinct_verdict() {
        // SPECS §5.5: losing the chain must be visible. A bool flag on
        // Accepted would be ignorable; a separate variant is not.
        let id = ident(1);
        let c = chain_of(&id, 12, "a");
        let rost = roster_of(&id);
        let mut cl = fresh(&c);
        assert!(matches!(cl.offer(&c[..2], &rost), Verdict::Accepted { .. }));

        match cl.offer_head_only(&c[11], &rost) {
            Verdict::Degraded { pin, reason } => {
                assert_eq!(pin.seq, 11);
                assert!(reason.contains("anchor"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn degraded_acceptance_still_enforces_the_anchor_and_the_pin() {
        // The fallback must not be a way around the two floors.
        let id = ident(1);
        let c = chain_of(&id, 8, "a");
        let rost = roster_of(&id);
        let mut cl = SlotClient::new(
            slot(),
            Regime::CasMerge,
            Anchor {
                seq: 4,
                sig_hash: c[4].sig_hash(),
            },
        );
        assert!(matches!(
            cl.offer_head_only(&c[2], &rost),
            Verdict::Rejected(Reject::BelowAnchor { .. })
        ));
        assert!(matches!(
            cl.offer_head_only(&c[6], &rost),
            Verdict::Degraded { .. }
        ));
        assert!(matches!(
            cl.offer_head_only(&c[5], &rost),
            Verdict::Rejected(Reject::Rollback { .. })
        ));
    }

    #[test]
    fn a_rejected_offer_is_still_recorded_as_evidence() {
        // A peer's willingness to serve something is evidence even when the
        // client refuses it. Dropping it is how the first TLA+ revision lost
        // the fork it was meant to detect.
        let id = ident(1);
        let c = chain_of(&id, 6, "a");
        let mut cl = SlotClient::new(
            slot(),
            Regime::CasMerge,
            Anchor {
                seq: 4,
                sig_hash: c[4].sig_hash(),
            },
        );
        assert!(matches!(
            cl.offer(&c[..3], &roster_of(&id)),
            Verdict::Rejected(Reject::BelowAnchor { .. })
        ));
        // seq 0..2 are now known even though nothing was accepted.
        cl.observe(2, [0xFF; 32]);
        assert_eq!(cl.forked(), Some(2), "the rejected offer was not retained");
    }

    #[test]
    fn an_unrostered_writer_is_refused() {
        let (a, b) = (ident(1), ident(2));
        let c = chain_of(&b, 3, "a");
        let mut cl = fresh(&c);
        assert!(matches!(
            cl.offer(&c, &roster_of(&a)),
            Verdict::Rejected(Reject::Chain(ChainError::UnknownWriter { .. }))
        ));
    }

    #[test]
    fn another_slots_history_is_refused() {
        let id = ident(1);
        let c = chain_of(&id, 3, "a");
        let mut cl = SlotClient::new(
            SlotId::new(b"ns", b"different"),
            Regime::CasMerge,
            Anchor {
                seq: 0,
                sig_hash: [0u8; 32],
            },
        );
        assert_eq!(
            cl.offer(&c, &roster_of(&id)),
            Verdict::Rejected(Reject::WrongSlot)
        );
    }
}
