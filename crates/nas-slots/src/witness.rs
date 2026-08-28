//! Witness records (SPECS §5.3).
//!
//! Revision 2 of the spec said "clients gossip", which quietly assumed clients
//! meet. They do not: the target user is a laptop moving between home, office
//! and cafés. So a client publishes a **signed observation** and the untrusted
//! peer relays it.
//!
//! The peer can withhold or delay a witness. It **cannot forge one**, and that
//! asymmetry is the whole mechanism: two witnesses citing incompatible
//! `(seq, sig_hash)` for one slot are a self-contained, publishable *proof* of
//! a fork rather than a heuristic.
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
    BadSignature,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "witness encoding: {e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
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

/// A signed observation of a slot head.
#[derive(Clone, PartialEq, Eq)]
pub struct Witness {
    /// The full verifying key — see the module docs on why not an id.
    pub witness_pk: Vec<u8>,
    pub slot_id: SlotId,
    pub seq: u64,
    /// `BLAKE3(record.sig)` of the record observed at that sequence.
    pub sig_hash: [u8; 32],
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
            .field("sig_hash", &hex6(&self.sig_hash))
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

fn body(slot_id: &SlotId, seq: u64, sig_hash: &[u8; 32], logical_time: u64) -> Vec<u8> {
    encode_fields(&[
        slot_id.as_bytes(),
        &seq.to_le_bytes(),
        sig_hash,
        &logical_time.to_le_bytes(),
    ])
    .expect("fixed-width witness body always encodes")
}

impl Witness {
    pub fn sign(
        identity: &Identity,
        slot_id: SlotId,
        seq: u64,
        sig_hash: [u8; 32],
        logical_time: u64,
    ) -> Result<Self, WitnessError> {
        let b = body(&slot_id, seq, &sig_hash, logical_time);
        let sig = identity
            .sign(SigContext::Witness, &b)
            .map_err(WitnessError::Sign)?;
        Ok(Self {
            witness_pk: identity.verifying_key().to_vec(),
            slot_id,
            seq,
            sig_hash,
            logical_time,
            sig,
        })
    }

    /// Verify against the key the witness carries.
    ///
    /// Self-contained by design: no roster, no prior knowledge of the observer.
    /// That is what makes a pair of these publishable as a proof.
    pub fn verify(&self) -> Result<(), WitnessError> {
        let b = body(&self.slot_id, self.seq, &self.sig_hash, self.logical_time);
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
            &self.sig_hash,
            &self.logical_time.to_le_bytes(),
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        let f = decode_fields(bytes)?;
        if f.len() != 6 {
            return Err(WitnessError::FieldCount {
                want: 6,
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
        if f[5].len() != SIGNATURE_LEN {
            return Err(WitnessError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[5].len(),
            });
        }
        Ok(Self {
            witness_pk: f[0].to_vec(),
            slot_id: SlotId::from_bytes(fixed::<32>("slot_id", f[1])?),
            seq: u64::from_le_bytes(fixed::<8>("seq", f[2])?),
            sig_hash: fixed::<32>("sig_hash", f[3])?,
            logical_time: u64::from_le_bytes(fixed::<8>("logical_time", f[4])?),
            sig: f[5].to_vec(),
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

/// Two verified witnesses that cannot both describe one history.
///
/// This is evidence, not an accusation: it says the slot forked, not who forked
/// it. Either the peer served two histories or a writer signed two records at
/// one sequence, and a third party holding only this pair can confirm the first
/// fact without being able to distinguish the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProof {
    pub slot_id: SlotId,
    pub seq: u64,
    pub a: Witness,
    pub b: Witness,
}

impl ForkProof {
    /// Build a proof if these two witnesses genuinely conflict.
    ///
    /// Returns `None` when they agree, describe different slots or sequences,
    /// or either fails to verify. **The verification is not the caller's job to
    /// remember**: a "proof" made of unverified witnesses would be forgeable by
    /// the peer that relayed them, which is precisely what the design says a
    /// peer cannot do.
    pub fn try_new(a: &Witness, b: &Witness) -> Option<Self> {
        if a.slot_id != b.slot_id || a.seq != b.seq || a.sig_hash == b.sig_hash {
            return None;
        }
        a.verify().ok()?;
        b.verify().ok()?;
        Some(Self {
            slot_id: a.slot_id,
            seq: a.seq,
            a: a.clone(),
            b: b.clone(),
        })
    }

    /// Re-check a proof received from someone else.
    pub fn verify(&self) -> bool {
        self.a.slot_id == self.slot_id
            && self.b.slot_id == self.slot_id
            && self.a.seq == self.seq
            && self.b.seq == self.seq
            && self.a.sig_hash != self.b.sig_hash
            && self.a.verify().is_ok()
            && self.b.verify().is_ok()
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

    #[test]
    fn sign_verify_round_trip() {
        let w = Witness::sign(&ident(1), slot(), 7, [0xAA; 32], 3).unwrap();
        w.verify().unwrap();
        let back = Witness::decode(&w.encode().unwrap()).unwrap();
        assert_eq!(back, w);
        back.verify().unwrap();
    }

    #[test]
    fn a_witness_verifies_without_a_roster() {
        // The property that makes a fork proof publishable to a third party.
        let w = Witness::sign(&ident(9), slot(), 1, [1u8; 32], 0).unwrap();
        assert!(w.verify().is_ok());
    }

    #[test]
    fn every_field_is_signed() {
        let base = Witness::sign(&ident(1), slot(), 7, [0xAA; 32], 3).unwrap();
        for mutate in [0, 1, 2, 3] {
            let mut w = base.clone();
            match mutate {
                0 => w.seq = 8,
                1 => w.sig_hash = [0xBB; 32],
                2 => w.logical_time = 4,
                _ => w.slot_id = SlotId::new(b"ns", b"other"),
            }
            assert_eq!(
                w.verify(),
                Err(WitnessError::BadSignature),
                "mutation {mutate}"
            );
        }
    }

    #[test]
    fn conflicting_witnesses_make_a_proof() {
        let (a, b) = (ident(1), ident(2));
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&b, slot(), 5, [0x02; 32], 0).unwrap();
        let p = ForkProof::try_new(&wa, &wb).expect("this is a fork");
        assert!(p.verify());
        assert_eq!(p.seq, 5);
    }

    #[test]
    fn agreeing_witnesses_are_not_a_fork() {
        // The failure mode that would make the alarm worthless: crying fork
        // whenever two devices both report the same head.
        let (a, b) = (ident(1), ident(2));
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&b, slot(), 5, [0x01; 32], 99).unwrap();
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn different_sequences_are_not_a_fork() {
        // Two devices at different points in one history is the normal case,
        // not evidence of anything.
        let (a, b) = (ident(1), ident(2));
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&b, slot(), 6, [0x02; 32], 0).unwrap();
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn different_slots_are_not_a_fork() {
        let (a, b) = (ident(1), ident(2));
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&b, SlotId::new(b"ns", b"other"), 5, [0x02; 32], 0).unwrap();
        assert!(ForkProof::try_new(&wa, &wb).is_none());
    }

    #[test]
    fn a_forged_witness_cannot_manufacture_a_proof() {
        // The peer relays witnesses and could try to invent a conflict. It
        // holds no witness key, so the signature check stops it -- and
        // try_new performs that check itself rather than trusting the caller.
        let a = ident(1);
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let mut forged = wa.clone();
        forged.sig_hash = [0x02; 32]; // a "conflicting" observation
        assert!(
            ForkProof::try_new(&wa, &forged).is_none(),
            "unsigned conflict accepted"
        );
    }

    #[test]
    fn a_proof_with_a_tampered_member_fails_re_verification() {
        let (a, b) = (ident(1), ident(2));
        let wa = Witness::sign(&a, slot(), 5, [0x01; 32], 0).unwrap();
        let wb = Witness::sign(&b, slot(), 5, [0x02; 32], 0).unwrap();
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
        let w = Witness::sign(&ident(1), slot(), 1, [0u8; 32], 0).unwrap();
        let n = w.encode().unwrap().len();
        // 1952 pk + 32 slot + 8 seq + 32 sig_hash + 8 time + 3309 sig
        // + 6 x 4 B length prefixes.
        assert_eq!(n, 5365, "witness wire size changed");
        println!(
            "Witness: {n} B — self-contained, so a fork proof costs {} B",
            2 * n
        );
    }
}
