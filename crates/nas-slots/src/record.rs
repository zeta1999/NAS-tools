//! Slot records — the signed, chained head of every mutable pointer (SPECS §5).
//!
//! ```text
//! SlotRecord { slot_id, seq, root, root_nonce, writer_id, prev, regime, sig }
//! sig = ML-DSA-65.sign(sk_slot, "nas-tools/sig/slot/v1" ‖ canonical(…))
//! ```
//!
//! # What `prev` commits to
//!
//! `prev` is the hash of the whole predecessor **including its signature**, not
//! of its body. Hashing only the body would let two records with identical
//! contents but different signatures share a `prev`, so a chain walk would
//! confirm a history that is not the one the peer actually served. The chain
//! has to commit to the bytes a client can be handed.
//!
//! # Size, measured rather than assumed
//!
//! See [`tests::record_sizes`]. The signature dominates at 3309 bytes, which is
//! the constraint behind SPECS §3.8's "sign roots and deltas, never leaves" —
//! a per-file signature scheme would cost more in signatures than in data for
//! any file under about 3 KB.

use crate::id::{SlotId, WriterId};
use nas_core::{decode_fields, encode_fields, Addr, DecodeError, ADDR_LEN};
use nas_crypto::{verify, Identity, SigContext, SignError, SIGNATURE_LEN};

/// Bytes of the per-version root nonce (SPECS §3.1: random 24 B).
pub const ROOT_NONCE_LEN: usize = 24;

/// Domain string for the record hash, so a record hash can never equal a hash
/// computed over some other structure that happens to share bytes.
const RECORD_HASH_DOMAIN: &[u8] = b"nas-tools/slot-record-hash/v1";

/// Which consistency regime a slot runs under (SPECS §5.1, §5.2).
///
/// Declared at slot creation and immutable. Revision 1 of the spec had one
/// regime for both faces and it was wrong for both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Regime {
    /// Exactly one device may write. Divergence is a genuine alarm, never a
    /// merge — correct for git refs, where a silent merge would be wrong.
    SingleWriter = 0,
    /// Compare-and-swap on `seq`, then re-read and re-merge on rejection.
    /// **A rejected CAS is a normal retry, not a fork alarm** (SPECS §5.2).
    CasMerge = 1,
}

impl Regime {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::SingleWriter),
            1 => Some(Self::CasMerge),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    Decode(DecodeError),
    Sign(SignError),
    /// A field arrived at the wrong width.
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    BadRegime {
        value: u8,
    },
    /// `seq` 0 must have an all-zero `prev`, and no other record may.
    ///
    /// Without this a writer could publish a "genesis" record at any sequence
    /// number, cutting the chain and defeating the walk in SPECS §5.3.
    GenesisMismatch {
        seq: u64,
        prev_is_zero: bool,
    },
    /// The signature does not verify under the writer's key.
    BadSignature,
    /// The record's `writer_id` is not the id of the key offered to verify it.
    WriterMismatch,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "slot record encoding: {e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "{field} is {got} B, want {want} B")
            }
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::BadRegime { value } => write!(f, "unknown regime {value}"),
            Self::GenesisMismatch { seq, prev_is_zero } => write!(
                f,
                "seq {seq} with {} prev: only seq 0 may have an empty predecessor",
                if *prev_is_zero {
                    "an all-zero"
                } else {
                    "a non-zero"
                }
            ),
            Self::BadSignature => write!(f, "slot record signature does not verify"),
            Self::WriterMismatch => write!(f, "record writer_id does not match the offered key"),
        }
    }
}
impl std::error::Error for RecordError {}
impl From<DecodeError> for RecordError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<SignError> for RecordError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

/// A signed slot version.
#[derive(Clone, PartialEq, Eq)]
pub struct SlotRecord {
    pub slot_id: SlotId,
    pub seq: u64,
    /// Address of the root manifest this version points at.
    pub root: Addr,
    /// The random nonce the root manifest was sealed with (SPECS §3.1).
    pub root_nonce: [u8; ROOT_NONCE_LEN],
    pub writer_id: WriterId,
    /// Hash of the predecessor record, all zero at `seq == 0`.
    pub prev: [u8; 32],
    pub regime: Regime,
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for SlotRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotRecord")
            .field("slot", &self.slot_id)
            .field("seq", &self.seq)
            .field("root", &self.root)
            .field("writer", &self.writer_id)
            .field("regime", &self.regime)
            .finish()
    }
}

/// The bytes that are signed. Everything but the signature itself.
fn body(
    slot_id: &SlotId,
    seq: u64,
    root: &Addr,
    root_nonce: &[u8; ROOT_NONCE_LEN],
    writer_id: &WriterId,
    prev: &[u8; 32],
    regime: Regime,
) -> Result<Vec<u8>, DecodeError> {
    encode_fields(&[
        slot_id.as_bytes(),
        &seq.to_le_bytes(),
        root.as_bytes(),
        root_nonce,
        writer_id.as_bytes(),
        prev,
        &[regime as u8],
    ])
}

impl SlotRecord {
    /// Build and sign a record.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &Identity,
        slot_id: SlotId,
        seq: u64,
        root: Addr,
        root_nonce: [u8; ROOT_NONCE_LEN],
        prev: [u8; 32],
        regime: Regime,
    ) -> Result<Self, RecordError> {
        let writer_id = WriterId::of_key(identity.verifying_key());
        check_genesis(seq, &prev)?;
        let b = body(&slot_id, seq, &root, &root_nonce, &writer_id, &prev, regime)?;
        let sig = identity.sign(SigContext::Slot, &b)?;
        Ok(Self {
            slot_id,
            seq,
            root,
            root_nonce,
            writer_id,
            prev,
            regime,
            sig,
        })
    }

    /// Verify the signature against a verifying key.
    ///
    /// Also checks that the key is the one the record names. Without that a
    /// record could be verified against *any* key whose signature happened to
    /// be presented with it, and `writer_id` would be decorative.
    pub fn verify(&self, verifying_key: &[u8]) -> Result<(), RecordError> {
        if WriterId::of_key(verifying_key) != self.writer_id {
            return Err(RecordError::WriterMismatch);
        }
        check_genesis(self.seq, &self.prev)?;
        let b = body(
            &self.slot_id,
            self.seq,
            &self.root,
            &self.root_nonce,
            &self.writer_id,
            &self.prev,
            self.regime,
        )?;
        verify(verifying_key, SigContext::Slot, &b, &self.sig)
            .map_err(|_| RecordError::BadSignature)
    }

    /// `BLAKE3(domain ‖ body ‖ sig)` — what the successor's `prev` must equal.
    pub fn record_hash(&self) -> [u8; 32] {
        let b = body(
            &self.slot_id,
            self.seq,
            &self.root,
            &self.root_nonce,
            &self.writer_id,
            &self.prev,
            self.regime,
        )
        .expect("a constructed record always encodes");
        let mut h = blake3::Hasher::new();
        h.update(RECORD_HASH_DOMAIN);
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(&b);
        h.update(&self.sig);
        *h.finalize().as_bytes()
    }

    /// `BLAKE3(sig)` — the short form carried by caps and witnesses (SPECS §5.3).
    pub fn sig_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.sig).as_bytes()
    }

    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        Ok(encode_fields(&[
            self.slot_id.as_bytes(),
            &self.seq.to_le_bytes(),
            self.root.as_bytes(),
            &self.root_nonce,
            self.writer_id.as_bytes(),
            &self.prev,
            &[self.regime as u8],
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let f = decode_fields(bytes)?;
        if f.len() != 8 {
            return Err(RecordError::FieldCount {
                want: 8,
                got: f.len(),
            });
        }
        let slot_id = SlotId::from_bytes(fixed::<32>("slot_id", f[0])?);
        let seq = u64::from_le_bytes(fixed::<8>("seq", f[1])?);
        let root = Addr::from_bytes(fixed::<ADDR_LEN>("root", f[2])?);
        let root_nonce = fixed::<ROOT_NONCE_LEN>("root_nonce", f[3])?;
        let writer_id = WriterId::from_bytes(fixed::<32>("writer_id", f[4])?);
        let prev = fixed::<32>("prev", f[5])?;
        let regime_byte = fixed::<1>("regime", f[6])?[0];
        let regime =
            Regime::from_u8(regime_byte).ok_or(RecordError::BadRegime { value: regime_byte })?;
        // A signature of the wrong length is rejected here rather than at
        // verification, so a malformed record never reaches the backend.
        if f[7].len() != SIGNATURE_LEN {
            return Err(RecordError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[7].len(),
            });
        }
        check_genesis(seq, &prev)?;
        Ok(Self {
            slot_id,
            seq,
            root,
            root_nonce,
            writer_id,
            prev,
            regime,
            sig: f[7].to_vec(),
        })
    }
}

/// Exactly the genesis record has an all-zero `prev`.
fn check_genesis(seq: u64, prev: &[u8; 32]) -> Result<(), RecordError> {
    let zero = prev.iter().all(|&b| b == 0);
    if (seq == 0) != zero {
        return Err(RecordError::GenesisMismatch {
            seq,
            prev_is_zero: zero,
        });
    }
    Ok(())
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], RecordError> {
    b.try_into().map_err(|_| RecordError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::Role;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    fn slot() -> SlotId {
        SlotId::new(b"namespace-pk", b"refs/heads/main")
    }

    fn genesis(id: &Identity) -> SlotRecord {
        SlotRecord::sign(
            id,
            slot(),
            0,
            Addr::of_ciphertext(b"root-0"),
            [1u8; ROOT_NONCE_LEN],
            [0u8; 32],
            Regime::CasMerge,
        )
        .unwrap()
    }

    #[test]
    fn sign_then_verify() {
        let id = ident(1);
        let r = genesis(&id);
        r.verify(id.verifying_key()).unwrap();
    }

    #[test]
    fn a_record_does_not_verify_under_another_writers_key() {
        let (a, b) = (ident(1), ident(2));
        let r = genesis(&a);
        // writer_id names a's key, so b's key is refused before any crypto.
        assert_eq!(
            r.verify(b.verifying_key()),
            Err(RecordError::WriterMismatch)
        );
    }

    #[test]
    fn a_forged_writer_id_does_not_help() {
        // Rewriting writer_id to name b makes the signature stop verifying,
        // because writer_id is inside the signed body.
        let (a, b) = (ident(1), ident(2));
        let mut r = genesis(&a);
        r.writer_id = WriterId::of_key(b.verifying_key());
        assert_eq!(r.verify(b.verifying_key()), Err(RecordError::BadSignature));
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let id = ident(1);
        let base = genesis(&id);
        let vk = id.verifying_key();

        let mut r = base.clone();
        r.seq = 1;
        r.prev = [9u8; 32]; // keep the genesis rule satisfied
        assert_eq!(
            r.verify(vk),
            Err(RecordError::BadSignature),
            "seq not covered"
        );

        let mut r = base.clone();
        r.root = Addr::of_ciphertext(b"a different root");
        assert_eq!(
            r.verify(vk),
            Err(RecordError::BadSignature),
            "root not covered"
        );

        let mut r = base.clone();
        r.root_nonce = [2u8; ROOT_NONCE_LEN];
        assert_eq!(
            r.verify(vk),
            Err(RecordError::BadSignature),
            "root_nonce not covered"
        );

        let mut r = base.clone();
        r.regime = Regime::SingleWriter;
        assert_eq!(
            r.verify(vk),
            Err(RecordError::BadSignature),
            "regime not covered"
        );

        let mut r = base.clone();
        r.slot_id = SlotId::new(b"other", b"slot");
        assert_eq!(
            r.verify(vk),
            Err(RecordError::BadSignature),
            "slot_id not covered"
        );
    }

    #[test]
    fn only_seq_zero_may_be_genesis() {
        // Otherwise a writer publishes a fresh "genesis" at any seq, cutting
        // the chain and defeating the walk of SPECS §5.3.
        let id = ident(1);
        assert!(matches!(
            SlotRecord::sign(
                &id,
                slot(),
                7,
                Addr::of_ciphertext(b"r"),
                [0u8; ROOT_NONCE_LEN],
                [0u8; 32],
                Regime::CasMerge
            ),
            Err(RecordError::GenesisMismatch { .. })
        ));
        assert!(matches!(
            SlotRecord::sign(
                &id,
                slot(),
                0,
                Addr::of_ciphertext(b"r"),
                [0u8; ROOT_NONCE_LEN],
                [3u8; 32],
                Regime::CasMerge
            ),
            Err(RecordError::GenesisMismatch { .. })
        ));
    }

    #[test]
    fn record_hash_covers_the_signature() {
        // Two records with the same body but different signatures must hash
        // differently, or a chain walk confirms a history the peer did not
        // serve. ML-DSA signing is deterministic, so the difference is forced
        // by hand here.
        let id = ident(1);
        let a = genesis(&id);
        let mut b = a.clone();
        b.sig[0] ^= 0xFF;
        assert_ne!(a.record_hash(), b.record_hash());
    }

    #[test]
    fn encode_decode_round_trips() {
        let id = ident(1);
        let r = genesis(&id);
        let back = SlotRecord::decode(&r.encode().unwrap()).unwrap();
        assert_eq!(back, r);
        back.verify(id.verifying_key()).unwrap();
    }

    #[test]
    fn a_wrong_length_signature_is_refused_at_decode() {
        let id = ident(1);
        let r = genesis(&id);
        let mut f = encode_fields(&[
            r.slot_id.as_bytes(),
            &r.seq.to_le_bytes(),
            r.root.as_bytes(),
            &r.root_nonce,
            r.writer_id.as_bytes(),
            &r.prev,
            &[r.regime as u8],
            &[0u8; 10],
        ])
        .unwrap();
        assert!(matches!(
            SlotRecord::decode(&f),
            Err(RecordError::BadWidth { field: "sig", .. })
        ));
        f.clear();
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 8, 40, 300, 4000] {
            let mut junk = vec![0u8; n];
            for (i, b) in junk.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let _ = SlotRecord::decode(&junk);
        }
    }

    #[test]
    fn record_sizes() {
        // PLAN step 6: measure ML-DSA record sizes while the structs are being
        // designed, not "at M1" generically. 3309 B of signature is the
        // constraint behind SPECS §3.8.
        let id = ident(1);
        let r = genesis(&id);
        let wire = r.encode().unwrap();
        let sig = r.sig.len();
        let overhead = wire.len() - sig;

        assert_eq!(sig, 3309, "ML-DSA-65 signature size");
        // Pinned exactly, not bounded loosely: this is a wire format, and a
        // change in it should show up as a failing test rather than as a
        // slightly different number nobody notices.
        //   32 slot_id + 8 seq + 32 root + 24 nonce + 32 writer + 32 prev
        //   + 1 regime + 3309 sig = 3470, plus 8 x 4 B length prefixes = 3502.
        assert_eq!(wire.len(), 3502, "SlotRecord wire size changed");
        assert_eq!(overhead, 193);

        // The number that shaped SPECS §3.8: a record conveys one 32-byte root
        // address and costs 3502 bytes to do it. Signing per file, let alone
        // per chunk, would cost more in signatures than in data for anything
        // smaller than ~3 KB -- which is most files.
        println!(
            "SlotRecord: {} B wire = {sig} B signature + {overhead} B header; \
             the signature is {:.0}x the 32 B payload it authenticates",
            wire.len(),
            sig as f64 / 32.0
        );
    }
}
