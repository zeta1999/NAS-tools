//! Witness records (SPECS §5.3).
//!
//! Revision 2 of the spec said "clients gossip", which quietly assumed clients
//! meet. They do not: the target user is a laptop moving between home, office
//! and cafés. So a client publishes a **signed observation** and the untrusted
//! peer relays it.
//!
//! The peer can withhold or delay a witness. It cannot forge one **from a key
//! it does not hold** — and that qualifier is load-bearing.
//!
//! # What a witness names, and why it carries `prev`
//!
//! ```text
//! Witness { witness_pk, slot_id, seq, record_hash, prev, logical_time, sig }
//! sig context "nas-tools/sig/witness/v2"
//! ```
//!
//! `record_hash` is [`SlotRecord::record_hash`](crate::SlotRecord::record_hash)
//! — `BLAKE3(domain ‖ body ‖ sig)`, which is exactly what the successor's
//! `prev` must equal — and `prev` is the observed record's own `prev`. Together
//! they are **one edge of the chain**, signed.
//!
//! v1 carried `BLAKE3(sig)` and no `prev`, so two witnesses could only ever be
//! compared when they named the same sequence: a witness said *what* was seen
//! and never *what it descended from*. Two branches at different heads — which
//! is what a real fork looks like, because each device witnesses its own head —
//! were invisible to anyone holding only witnesses.
//!
//! With the edge, a holder of enough witnesses can walk one head back to the
//! other's sequence and compare there. That is what [`SlotClient::forked`] does
//! and what [`ForkProof::verify`] re-does for a third party. The signing
//! context is bumped to `v2` and the record grew a field, so a v1 witness is
//! **refused** ([`WitnessError::LegacyV1`]) rather than guessed at: v1 carried
//! no ancestry, and there is nothing to upgrade it to.
//!
//! [`SlotClient::forked`]: crate::SlotClient::forked
//!
//! # What a bare `ForkProof` does and does not establish
//!
//! [`Witness::verify`] checks the signature against the key the witness carries
//! *itself*, with no roster. That is deliberate: a proof has to be checkable by
//! a third party who holds neither side's roster, or it is not publishable.
//!
//! The cost is that a bare proof establishes only **"signatures over
//! conflicting heads exist"** — not "legitimate observers equivocated".
//! `Role::Witness` identities are derivable by anyone, so a hostile peer can
//! mint two keypairs and manufacture a proof against a perfectly honest slot.
//! Carrying `prev` does not change that: a linked proof is a chain of
//! signatures, and a peer holding all of the keys can sign any chain it likes.
//!
//! An earlier version of this documentation said flatly that the peer "cannot
//! forge one", and a test named `a_forged_witness_cannot_manufacture_a_proof`
//! appeared to confirm it. That test only defeated the *naive* attack — editing
//! a real witness without re-signing. It never tried generating fresh keys,
//! which succeeds. The claim was a false generalisation from a test that did
//! not cover the attack.
//!
//! So: relay and verify proofs freely, but **act** on one only after checking
//! every witness in it against a roster of known observers. That is
//! [`SlotClient`](crate::SlotClient)'s job, and it now requires it.
//!
//! # Why a witness carries the whole verifying key
//!
//! Slot records carry a 32-byte [`WriterId`](crate::WriterId) because the
//! roster maps it back. A fork proof has no such luxury — it must be verifiable
//! by someone who holds neither party's roster, or it is not publishable. So a
//! witness pays the full 1952 bytes and is self-contained.

use crate::id::SlotId;
use nas_core::{decode_fields, encode_fields, DecodeError};
use nas_crypto::{
    key_id, verify, Identity, SigContext, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

/// Fields on the wire. v1 had six; the seventh is `prev`.
const WITNESS_FIELDS: usize = 7;

/// The longest chain of linking witnesses a [`ForkProof`] may carry, and so the
/// longest ancestry walk anyone will run over one.
///
/// A bound, not a tuning knob. A proof is re-walked by whoever receives it, and
/// a relay that could hand over an arbitrarily long link could make every
/// recipient verify an arbitrary number of ML-DSA signatures. It is also the
/// most a client could ever assemble: `SlotClient` retains at most
/// [`MAX_WITNESSES`](crate::MAX_WITNESSES) witnesses, so a longer link cannot
/// be derived from what one client holds.
pub const MAX_LINK: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum WitnessError {
    Decode(DecodeError),
    Sign(SignError),
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    /// A v1 witness: six fields, `BLAKE3(sig)` and no `prev`.
    ///
    /// Refused with a version error rather than decoded, because there is
    /// nothing to upgrade it to — v1 carried no ancestry at all, and inventing
    /// a `prev` for it would put an unsigned claim inside a signed structure.
    LegacyV1,
    /// `seq` 0 must have an all-zero `prev`, and no other sequence may.
    ///
    /// Mirrors `SlotRecord`'s genesis rule, because a witness names a record
    /// and must not be able to name one the record format forbids: a "genesis"
    /// witness at an arbitrary sequence would terminate an ancestry walk early
    /// with an attacker-chosen hash.
    GenesisMismatch {
        seq: u64,
        prev_is_zero: bool,
    },
    BadSignature,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "witness encoding: {e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::LegacyV1 => write!(
                f,
                "witness is format v1 (no `prev` link); this build speaks v2 only"
            ),
            Self::GenesisMismatch { seq, prev_is_zero } => write!(
                f,
                "witness of seq {seq} with {} prev: only seq 0 may have an empty predecessor",
                if *prev_is_zero {
                    "an all-zero"
                } else {
                    "a non-zero"
                }
            ),
            Self::BadSignature => write!(f, "witness signature does not verify"),
        }
    }
}
impl std::error::Error for WitnessError {}
impl From<DecodeError> for WitnessError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// A signed observation of a slot head, and of the edge below it.
#[derive(Clone, PartialEq, Eq)]
pub struct Witness {
    /// The full verifying key — see the module docs on why not an id.
    pub witness_pk: Vec<u8>,
    pub slot_id: SlotId,
    pub seq: u64,
    /// `BLAKE3(domain ‖ body ‖ sig)` of the record observed at that sequence —
    /// its [`record_hash`](crate::SlotRecord::record_hash), which is exactly
    /// what the successor's `prev` must equal.
    pub record_hash: [u8; 32],
    /// The observed record's own `prev`. All-zero at `seq` 0 and nowhere else.
    pub prev: [u8; 32],
    /// The observer's own counter. **Not a trusted clock** — it orders one
    /// witness's own observations and nothing more (SPECS §5.3 has no trusted
    /// time anywhere).
    pub logical_time: u64,
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Witness")
            .field("by", &hex6(&key_id(&self.witness_pk)))
            .field("slot", &self.slot_id)
            .field("seq", &self.seq)
            .field("record_hash", &hex6(&self.record_hash))
            .field("prev", &hex6(&self.prev))
            .finish()
    }
}

fn hex6(b: &[u8]) -> String {
    b.iter()
        .take(6)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

fn body(
    slot_id: &SlotId,
    seq: u64,
    record_hash: &[u8; 32],
    prev: &[u8; 32],
    logical_time: u64,
) -> Vec<u8> {
    encode_fields(&[
        slot_id.as_bytes(),
        &seq.to_le_bytes(),
        record_hash,
        prev,
        &logical_time.to_le_bytes(),
    ])
    .expect("fixed-width witness body always encodes")
}

/// Exactly a witness of the genesis record has an all-zero `prev`.
fn check_genesis(seq: u64, prev: &[u8; 32]) -> Result<(), WitnessError> {
    let zero = prev.iter().all(|&b| b == 0);
    if (seq == 0) != zero {
        return Err(WitnessError::GenesisMismatch {
            seq,
            prev_is_zero: zero,
        });
    }
    Ok(())
}

impl Witness {
    pub fn sign(
        identity: &Identity,
        slot_id: SlotId,
        seq: u64,
        record_hash: [u8; 32],
        prev: [u8; 32],
        logical_time: u64,
    ) -> Result<Self, WitnessError> {
        check_genesis(seq, &prev)?;
        let b = body(&slot_id, seq, &record_hash, &prev, logical_time);
        let sig = identity
            .sign(SigContext::Witness, &b)
            .map_err(WitnessError::Sign)?;
        Ok(Self {
            witness_pk: identity.verifying_key().to_vec(),
            slot_id,
            seq,
            record_hash,
            prev,
            logical_time,
            sig,
        })
    }

    /// Sign an observation of a record the observer actually holds.
    ///
    /// The shorthand every honest caller should reach for: a witness names one
    /// edge of the chain, and assembling that edge by hand from a record that
    /// is right there is how the two halves come to disagree.
    pub fn of_record(
        identity: &Identity,
        record: &crate::SlotRecord,
        logical_time: u64,
    ) -> Result<Self, WitnessError> {
        Self::sign(
            identity,
            record.slot_id,
            record.seq,
            record.record_hash(),
            record.prev,
            logical_time,
        )
    }

    /// Verify against the key the witness carries.
    ///
    /// Self-contained by design: no roster, no prior knowledge of the observer.
    /// That is what makes a pair of these publishable as a proof.
    pub fn verify(&self) -> Result<(), WitnessError> {
        check_genesis(self.seq, &self.prev)?;
        let b = body(
            &self.slot_id,
            self.seq,
            &self.record_hash,
            &self.prev,
            self.logical_time,
        );
        verify(&self.witness_pk, SigContext::Witness, &b, &self.sig)
            .map_err(|_| WitnessError::BadSignature)
    }

    pub fn witness_id(&self) -> [u8; 32] {
        key_id(&self.witness_pk)
    }

    pub fn encode(&self) -> Result<Vec<u8>, WitnessError> {
        Ok(encode_fields(&[
            &self.witness_pk,
            self.slot_id.as_bytes(),
            &self.seq.to_le_bytes(),
            &self.record_hash,
            &self.prev,
            &self.logical_time.to_le_bytes(),
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        let f = decode_fields(bytes)?;
        if f.len() != WITNESS_FIELDS {
            // Six fields is a v1 witness, and worth saying so: "wrong field
            // count" reads as corruption, and this is a peer speaking the old
            // format (TODO.md :44 — v0 peers are refused, not guessed at).
            if f.len() == 6 {
                return Err(WitnessError::LegacyV1);
            }
            return Err(WitnessError::FieldCount {
                want: WITNESS_FIELDS,
                got: f.len(),
            });
        }
        if f[0].len() != VERIFYING_KEY_LEN {
            return Err(WitnessError::BadWidth {
                field: "witness_pk",
                want: VERIFYING_KEY_LEN,
                got: f[0].len(),
            });
        }
        if f[6].len() != SIGNATURE_LEN {
            return Err(WitnessError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[6].len(),
            });
        }
        let seq = u64::from_le_bytes(fixed::<8>("seq", f[2])?);
        let prev = fixed::<32>("prev", f[4])?;
        check_genesis(seq, &prev)?;
        Ok(Self {
            witness_pk: f[0].to_vec(),
            slot_id: SlotId::from_bytes(fixed::<32>("slot_id", f[1])?),
            seq,
            record_hash: fixed::<32>("record_hash", f[3])?,
            prev,
            logical_time: u64::from_le_bytes(fixed::<8>("logical_time", f[5])?),
            sig: f[6].to_vec(),
        })
    }
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], WitnessError> {
    b.try_into().map_err(|_| WitnessError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

/// Witnesses that cannot all describe one history.
///
/// This is evidence, not an accusation: it says the slot forked, not who forked
/// it. Either the peer served two histories or a writer signed two records at
/// one sequence, and a third party holding only this can confirm the first fact
/// without being able to distinguish the second.
///
/// Two shapes, and `seq` means the same thing in both — **the sequence at which
/// the two histories differ**:
///
/// * *same-sequence*: `a` and `b` both sit at `seq` and name different records.
///   `link` is empty. This is the whole of what v1 could express.
/// * *linked*: `a` sits at `seq`, `b` above it, and `link` carries the
///   witnesses that walk `b` back down to `seq`, where it lands on a record
///   other than `a`'s. Every witness in the link is re-verified by
///   [`verify`](Self::verify), so a recipient re-walks rather than believes.
///
/// A linked proof is not small: each witness is self-contained (5401 B), so a
/// proof spanning `n` sequences carries `n + 1` of them. [`MAX_LINK`] bounds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProof {
    pub slot_id: SlotId,
    /// The sequence at which the two histories differ. `a` sits here.
    pub seq: u64,
    pub a: Witness,
    pub b: Witness,
    /// For a linked proof, the witnesses stepping `b` down to `seq`, in
    /// descending sequence order: `b.seq - 1`, `b.seq - 2`, …, `seq + 1`.
    /// Empty for a same-sequence proof.
    pub link: Vec<Witness>,
}

impl ForkProof {
    /// Build a same-sequence proof if these two witnesses genuinely conflict.
    ///
    /// Returns `None` when they agree, describe different slots or sequences,
    /// or either fails to verify. **The verification is not the caller's job to
    /// remember**: a "proof" made of unverified witnesses would be forgeable by
    /// the peer that relayed them, which is precisely what the design says a
    /// peer cannot do.
    pub fn try_new(a: &Witness, b: &Witness) -> Option<Self> {
        if a.slot_id != b.slot_id || a.seq != b.seq || a.record_hash == b.record_hash {
            return None;
        }
        a.verify().ok()?;
        b.verify().ok()?;
        Some(Self {
            slot_id: a.slot_id,
            seq: a.seq,
            a: a.clone(),
            b: b.clone(),
            link: Vec::new(),
        })
    }

    /// Build a proof that `b`, walked back along `link`, reaches `a`'s sequence
    /// on a different record.
    ///
    /// `link` must be exactly the witnesses at `b.seq - 1 … a.seq + 1`, in that
    /// order. Anything else is refused rather than repaired: the constructor
    /// holds itself to [`verify`](Self::verify) before returning, because a
    /// proof a recipient cannot re-walk is not a proof.
    pub fn try_linked(a: &Witness, b: &Witness, link: Vec<Witness>) -> Option<Self> {
        if a.slot_id != b.slot_id || a.seq >= b.seq {
            return None;
        }
        let p = Self {
            slot_id: a.slot_id,
            seq: a.seq,
            a: a.clone(),
            b: b.clone(),
            link,
        };
        p.verify().then_some(p)
    }

    /// Re-check a proof received from someone else.
    ///
    /// For a linked proof this re-walks the chain: every step's witness must
    /// verify, name this slot, sit at the sequence the walk expects, and carry
    /// the `record_hash` that the step above it named as its `prev`. Nothing is
    /// taken on the sender's word, and the walk is bounded by [`MAX_LINK`].
    pub fn verify(&self) -> bool {
        if self.a.slot_id != self.slot_id || self.b.slot_id != self.slot_id {
            return false;
        }
        if self.a.seq != self.seq || self.a.verify().is_err() || self.b.verify().is_err() {
            return false;
        }
        // Which shape this is comes from the two sequences, never from whether
        // `link` happens to be empty: `b` one above `a` is a linked proof with
        // nothing to step through, and reading that as a same-sequence proof
        // would reject the commonest linked proof there is.
        if self.b.seq == self.seq {
            return self.link.is_empty() && self.a.record_hash != self.b.record_hash;
        }
        if self.b.seq < self.seq || self.link.len() > MAX_LINK {
            return false;
        }
        // The walk. `hash` is what the record at `seq` must be, as named by the
        // step above it; `seq` counts down to the sequence `a` sits at.
        let mut hash = self.b.prev;
        let mut seq = self.b.seq - 1;
        for w in &self.link {
            if seq == self.seq {
                return false; // a link longer than the gap it claims to span
            }
            if w.slot_id != self.slot_id
                || w.seq != seq
                || w.record_hash != hash
                || w.verify().is_err()
            {
                return false;
            }
            hash = w.prev;
            seq -= 1;
        }
        seq == self.seq && hash != self.a.record_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::Role;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Witness).unwrap()
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"doc")
    }

    /// A witness of `seq` naming record `h`, descending from `p`.
    fn w(id: &Identity, seq: u64, h: u8, p: u8) -> Witness {
        Witness::sign(id, slot(), seq, [h; 32], [p; 32], 0).unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let x = Witness::sign(&ident(1), slot(), 7, [0xAA; 32], [0x99; 32], 3).unwrap();
        x.verify().unwrap();
        let back = Witness::decode(&x.encode().unwrap()).unwrap();
        assert_eq!(back, x);
        back.verify().unwrap();
    }

    #[test]
    fn a_witness_verifies_without_a_roster() {
        // The property that makes a fork proof publishable to a third party.
        let x = w(&ident(9), 1, 1, 0xF0);
        assert!(x.verify().is_ok());
    }

    #[test]
    fn a_witness_of_the_genesis_record_has_an_empty_prev_and_no_other_may() {
        // Mirrors `SlotRecord`'s own genesis rule. Without it a witness could
        // claim genesis at any sequence, terminating somebody's ancestry walk
        // early on a hash of its choosing.
        let id = ident(1);
        Witness::sign(&id, slot(), 0, [1; 32], [0; 32], 0).expect("genesis takes a zero prev");
        assert_eq!(
            Witness::sign(&id, slot(), 0, [1; 32], [0xAB; 32], 0),
            Err(WitnessError::GenesisMismatch {
                seq: 0,
                prev_is_zero: false
            })
        );
        assert_eq!(
            Witness::sign(&id, slot(), 4, [1; 32], [0; 32], 0),
            Err(WitnessError::GenesisMismatch {
                seq: 4,
                prev_is_zero: true
            })
        );
    }

    #[test]
    fn a_genesis_violation_is_refused_at_decode_and_at_verify() {
        // The constructor is not the only door: a witness arrives from a peer
        // as bytes, and a hand-built struct skips `sign` entirely.
        let good = w(&ident(1), 4, 0x11, 0x22);
        let mut bad = good.clone();
        bad.prev = [0; 32];
        assert!(matches!(
            bad.verify(),
            Err(WitnessError::GenesisMismatch { seq: 4, .. })
        ));
        let bytes = bad.encode().unwrap();
        assert!(matches!(
            Witness::decode(&bytes),
            Err(WitnessError::GenesisMismatch { seq: 4, .. })
        ));
    }

    #[test]
    fn every_field_is_signed() {
        let base = Witness::sign(&ident(1), slot(), 7, [0xAA; 32], [0x99; 32], 3).unwrap();
        for mutate in [0, 1, 2, 3, 4] {
            let mut x = base.clone();
            match mutate {
                0 => x.seq = 8,
                1 => x.record_hash = [0xBB; 32],
                2 => x.logical_time = 4,
                3 => x.prev = [0x98; 32],
                _ => x.slot_id = SlotId::new(b"ns", b"other"),
            }
            assert_eq!(
                x.verify(),
                Err(WitnessError::BadSignature),
                "mutation {mutate}"
            );
        }
    }

    #[test]
    fn a_v1_witness_is_refused_with_a_version_error() {
        // Six fields, `BLAKE3(sig)`, no `prev`. Not decodable as v2 and not
        // upgradable: it never carried ancestry to upgrade.
        let v1 = encode_fields(&[
            ident(1).verifying_key(),
            slot().as_bytes(),
            &7u64.to_le_bytes(),
            &[0xAA; 32],
            &3u64.to_le_bytes(),
            &[0u8; SIGNATURE_LEN],
        ])
        .unwrap();
        assert_eq!(Witness::decode(&v1), Err(WitnessError::LegacyV1));
    }

    #[test]
    fn conflicting_witnesses_make_a_proof() {
        let (a, b) = (ident(1), ident(2));
        let wa = w(&a, 5, 0x01, 0xC0);
        let wb = w(&b, 5, 0x02, 0xC0);
        let p = ForkProof::try_new(&wa, &wb).expect("this is a fork");
        assert!(p.verify());
        assert_eq!(p.seq, 5);
        assert!(p.link.is_empty());
    }

    #[test]
    fn agreeing_witnesses_are_not_a_fork() {
        // The failure mode that would make the alarm worthless: crying fork
        // whenever two devices both report the same head.
        let (a, b) = (ident(1), ident(2));
        let wa = w(&a, 5, 0x01, 0xC0);
        let wb = Witness::sign(&b, slot(), 5, [0x01; 32], [0xC0; 32], 99).unwrap();
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn different_sequences_are_not_a_bare_fork() {
        // Two devices at different points in one history is the normal case.
        // Saying so needs the link (below); the bare pair proves nothing.
        let (a, b) = (ident(1), ident(2));
        let wa = w(&a, 5, 0x01, 0xC0);
        let wb = w(&b, 6, 0x02, 0x01);
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn different_slots_are_not_a_fork() {
        let (a, b) = (ident(1), ident(2));
        let wa = w(&a, 5, 0x01, 0xC0);
        let wb = Witness::sign(
            &b,
            SlotId::new(b"ns", b"other"),
            5,
            [0x02; 32],
            [0xC0; 32],
            0,
        )
        .unwrap();
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn a_linked_proof_re_walks_to_the_sequence_it_names() {
        // Branch "a" at seq 3 is hash 0xA3. Branch "b" runs 0xB3 → 0xB4 → 0xB5
        // and its foot names 0xB2, not 0xA3, at seq 3.
        let (o1, o2, o3) = (ident(1), ident(2), ident(3));
        let low = w(&o1, 3, 0xA3, 0xA2);
        let mid = w(&o2, 4, 0xB4, 0xB3);
        let high = w(&o3, 5, 0xB5, 0xB4);
        let p = ForkProof::try_linked(&low, &high, vec![mid.clone()])
            .expect("the walk lands on 0xB3, not 0xA3");
        assert_eq!(p.seq, 3);
        assert_eq!(p.link, vec![mid]);
        assert!(p.verify());
    }

    #[test]
    fn a_linked_proof_over_a_chain_that_agrees_is_no_proof() {
        // The soundness case: the same walk, but the foot names exactly the
        // record the low witness named. One history, two devices on it.
        let (o1, o2, o3) = (ident(1), ident(2), ident(3));
        let low = w(&o1, 3, 0xA3, 0xA2);
        let mid = w(&o2, 4, 0xB4, 0xA3);
        let high = w(&o3, 5, 0xB5, 0xB4);
        assert!(ForkProof::try_linked(&low, &high, vec![mid]).is_none());
    }

    #[test]
    fn a_link_with_a_hole_is_no_proof() {
        // A missing step is exactly what a hostile relay produces by dropping
        // one witness. The recipient must refuse, not interpolate.
        let (o1, o3) = (ident(1), ident(3));
        let low = w(&o1, 3, 0xA3, 0xA2);
        let high = w(&o3, 5, 0xB5, 0xB4);
        assert!(ForkProof::try_linked(&low, &high, vec![]).is_none());
    }

    #[test]
    fn a_link_that_does_not_hash_link_is_no_proof() {
        // Every step must be named by the step above it. Otherwise a relay
        // could splice two unrelated observations into a "walk".
        let (o1, o2, o3) = (ident(1), ident(2), ident(3));
        let low = w(&o1, 3, 0xA3, 0xA2);
        let spliced = w(&o2, 4, 0x77, 0xB3); // high names 0xB4, not 0x77
        let high = w(&o3, 5, 0xB5, 0xB4);
        assert!(ForkProof::try_linked(&low, &high, vec![spliced]).is_none());
    }

    #[test]
    fn a_link_longer_than_the_bound_is_refused() {
        let (o1, o2) = (ident(1), ident(2));
        let low = w(&o1, 1, 0xA0, 0x0F);
        let high = w(&o2, MAX_LINK as u64 + 3, 0xB1, 0xB2);
        let link: Vec<Witness> = (0..=MAX_LINK).map(|i| w(&o2, i as u64 + 2, 1, 2)).collect();
        assert!(link.len() > MAX_LINK);
        assert!(ForkProof::try_linked(&low, &high, link).is_none());
    }

    #[test]
    fn a_tampered_link_step_fails_re_verification() {
        let (o1, o2, o3) = (ident(1), ident(2), ident(3));
        let low = w(&o1, 3, 0xA3, 0xA2);
        let mid = w(&o2, 4, 0xB4, 0xB3);
        let high = w(&o3, 5, 0xB5, 0xB4);
        let mut p = ForkProof::try_linked(&low, &high, vec![mid]).unwrap();
        p.link[0].prev = [0xA3; 32]; // "the walk agrees after all"
        assert!(!p.verify(), "an unsigned edit to the link was believed");
    }

    #[test]
    fn editing_a_real_witness_without_re_signing_is_caught() {
        // The naive attack -- and the ONLY one this test used to cover, while
        // being named as though it covered forgery in general.
        let a = ident(1);
        let wa = w(&a, 5, 0x01, 0xC0);
        let mut forged = wa.clone();
        forged.record_hash = [0x02; 32]; // a "conflicting" observation
        assert!(
            ForkProof::try_new(&wa, &forged).is_none(),
            "unsigned conflict accepted"
        );
    }

    #[test]
    fn a_peer_can_manufacture_a_bare_proof_with_keys_of_its_own() {
        // The attack the old test missed. `Role::Witness` identities are
        // derivable by anyone, so a hostile peer mints two keypairs and gets a
        // verifying ForkProof against a perfectly honest slot.
        //
        // Asserted POSITIVELY so the limitation is a fact of the suite rather
        // than a claim in a comment: a bare proof establishes "two signatures
        // over conflicting heads exist", not "two legitimate observers
        // equivocated". SlotClient is what refuses to act on one, by roster.
        // Carrying `prev` changes nothing here -- see the linked case below.
        let evil_a = Identity::derive(&[0xE1; 32], Role::Witness).unwrap();
        let evil_b = Identity::derive(&[0xE2; 32], Role::Witness).unwrap();
        let wa = w(&evil_a, 5, 0x01, 0xC0);
        let wb = w(&evil_b, 5, 0x02, 0xC0);

        let proof = ForkProof::try_new(&wa, &wb)
            .expect("a bare proof shows only that two signatures exist");
        assert!(proof.verify());
    }

    #[test]
    fn a_peer_can_manufacture_a_linked_proof_too() {
        // Stated positively for the same reason. A linked proof is a chain of
        // signatures; a peer holding every key can sign any chain it likes.
        // The link buys detection under partial knowledge, NOT authenticity --
        // that is still the roster's job, in SlotClient.
        let e1 = Identity::derive(&[0xE1; 32], Role::Witness).unwrap();
        let e2 = Identity::derive(&[0xE2; 32], Role::Witness).unwrap();
        let low = w(&e1, 3, 0xA3, 0xA2);
        let mid = w(&e2, 4, 0xB4, 0xB3);
        let high = w(&e1, 5, 0xB5, 0xB4);
        let p = ForkProof::try_linked(&low, &high, vec![mid]).expect("signatures, not honesty");
        assert!(p.verify());
    }

    #[test]
    fn a_proof_with_a_tampered_member_fails_re_verification() {
        let (a, b) = (ident(1), ident(2));
        let wa = w(&a, 5, 0x01, 0xC0);
        let wb = w(&b, 5, 0x02, 0xC0);
        let mut p = ForkProof::try_new(&wa, &wb).unwrap();
        p.b.seq = 6;
        assert!(!p.verify());
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 8, 100, 2000, 5400] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = Witness::decode(&junk);
        }
    }

    #[test]
    fn witness_size() {
        let x = w(&ident(1), 1, 0, 1);
        let n = x.encode().unwrap().len();
        // 1952 pk + 32 slot + 8 seq + 32 record_hash + 32 prev + 8 time
        // + 3309 sig + 7 x 4 B length prefixes.
        assert_eq!(n, 5401, "witness wire size changed");
        // A same-sequence proof is two witnesses. A proof whose two ends sit
        // s sequences apart carries the s - 1 steps between them as well, so
        // s + 1 witnesses in all.
        println!(
            "Witness: {n} B — self-contained, so a same-sequence fork proof costs \
             {} B, and one spanning s sequences (s + 1) x {n} B, capped at {} B \
             by MAX_LINK",
            2 * n,
            (MAX_LINK + 2) * n
        );
    }
}
