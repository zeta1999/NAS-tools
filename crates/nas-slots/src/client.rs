//! The client's accept decision (SPECS §5.3, §5.5).
//!
//! This is the Rust counterpart of `formal/tlaplus/SlotConsistency.tla`, and
//! the three properties the model checks are the three this module must hold:
//!
//! | TLA+ invariant | Here |
//! |---|---|
//! | `AnchorFloor` — a pin never falls below the cap's anchor | [`Reject::BelowAnchor`] |
//! | `MonotonicPins` — pins only move forward | [`Reject::Rollback`] |
//! | `ForkDetected` — incompatible evidence always raises | [`SlotClient::fork_proof`] |
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
use crate::id::SlotId;
use crate::record::{Regime, SlotRecord};
use crate::roster::Roster;
use crate::witness::{ForkProof, Witness};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Every `(seq, sig_hash)` ever learned of, from any source. Append-only:
    /// see the module docs on why evidence is never dropped.
    evidence: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// Witnesses kept so a derived alarm can be turned into a publishable proof.
    witnesses: Vec<Witness>,
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
            witnesses: Vec::new(),
        }
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

    /// Record an observation. Only ever adds.
    pub fn observe(&mut self, seq: u64, sig_hash: [u8; 32]) {
        self.evidence.entry(seq).or_default().insert(sig_hash);
    }

    /// Take in a witness relayed by the peer.
    ///
    /// Unverified witnesses are dropped rather than stored: a peer that could
    /// inject an unsigned "observation" could manufacture a fork alarm against
    /// an honest slot, which would make the alarm worthless in the other
    /// direction.
    pub fn observe_witness(&mut self, w: &Witness) -> bool {
        if w.slot_id != self.slot_id || w.verify().is_err() {
            return false;
        }
        self.observe(w.seq, w.sig_hash);
        self.witnesses.push(w.clone());
        true
    }

    /// Is there evidence of a fork? Derived, never cached.
    pub fn forked(&self) -> Option<u64> {
        self.evidence
            .iter()
            .find(|(_, hs)| hs.len() > 1)
            .map(|(seq, _)| *seq)
    }

    /// A publishable proof, if two *witnesses* conflict.
    ///
    /// [`forked`] can be true without this returning a proof: a client can know
    /// it was served two histories without holding two signed observations to
    /// show anyone. That is a real distinction and not a gap to paper over —
    /// SPECS §5.4 is explicit that detection converges only once witnesses
    /// propagate. Reporting "forked, but I cannot yet prove it" honestly is
    /// better than inventing a proof.
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
        None
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
        for r in records {
            self.observe(r.seq, r.sig_hash());
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

        let wa = Witness::sign(&witness_ident(10), slot(), 2, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&witness_ident(11), slot(), 2, [0x02; 32], 0).unwrap();
        assert!(cl.observe_witness(&wa));
        assert!(cl.observe_witness(&wb));

        assert_eq!(cl.forked(), Some(2));
        let p = cl
            .fork_proof()
            .expect("two conflicting witnesses are a proof");
        assert!(p.verify());
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

        let wa = Witness::sign(&witness_ident(10), slot(), 3, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&witness_ident(11), slot(), 3, [0x02; 32], 0).unwrap();
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
        let good = Witness::sign(&witness_ident(10), slot(), 2, [0x01; 32], 0).unwrap();
        let mut forged = good.clone();
        forged.sig_hash = [0x02; 32];
        assert!(cl.observe_witness(&good));
        assert!(!cl.observe_witness(&forged), "unsigned witness accepted");
        assert_eq!(cl.forked(), None);
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
            0,
        )
        .unwrap();
        assert!(!cl.observe_witness(&w));
        assert_eq!(cl.forked(), None);
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
