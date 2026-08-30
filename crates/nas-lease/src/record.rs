//! Lease deltas and checkpoints (SPECS §6.1).
//!
//! ```text
//! LeaseDelta      { holder_pk, epoch, seq, add: [addr], remove: [addr], prev, sig }
//! LeaseCheckpoint { holder_pk, epoch, root = merkle(sorted full set), count, prev, sig }
//! ```
//!
//! # Why deltas at all
//!
//! Revision 1 of the spec had one Merkle root over the full set, replaced
//! wholesale each epoch. That compressed the *signature* and nothing else: the
//! full address set still shipped every renewal, so a holder of 10 M chunks
//! pushed ~320 MB per epoch. Deltas ship the change; a checkpoint every N
//! deltas lets the peer compact and lets a cold client resync.
//!
//! **One signature per delta, never per address** (SPECS §3.8). At 3309 bytes
//! a signature is larger than a hundred addresses.
//!
//! # `holder_pk`, not a holder id
//!
//! Slot records carry a 32-byte writer id because a roster maps it back, and a
//! witness carries the full key because a fork proof must be verifiable by a
//! stranger. A lease sits between: only the paired peer verifies it, and
//! pairing already established the key, so an id would do and would save 1952
//! bytes per record.
//!
//! It carries the full key anyway, because SPECS §6.1 says so and because a
//! self-contained record survives a peer that has lost or rebuilt its pairing
//! table — which is exactly the situation in which being unable to verify what
//! you are holding is worst. Deltas batch to epoch boundaries (§6.5), so the
//! redundancy is bounded by epochs rather than by writes.

use crate::merkle;
use nas_core::{decode_fields, encode_fields, Addr, DecodeError, ADDR_LEN};
use nas_crypto::{
    key_id, verify, Identity, SigContext, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

/// Domain string for a record's chain hash.
const CHAIN_DOMAIN: &[u8] = b"nas-tools/lease-chain/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
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
    /// An address list whose length is not a multiple of 32.
    RaggedAddrs {
        bytes: usize,
    },
    /// `seq` 0 must have an all-zero `prev`, and nothing else may.
    GenesisMismatch {
        seq: u64,
    },
    BadSignature,
    /// An address list that is not sorted and de-duplicated.
    ///
    /// The canonical-form rule again: the writer emits sorted unique lists, so
    /// anything else is a covert channel and a second spelling of one delta.
    NonCanonical {
        field: &'static str,
    },
    /// A checkpoint whose `count` disagrees with the set it claims to cover.
    CountMismatch {
        declared: u64,
        actual: u64,
    },
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "lease encoding: {e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::RaggedAddrs { bytes } => {
                write!(
                    f,
                    "address list of {bytes} B is not a multiple of {ADDR_LEN}"
                )
            }
            Self::GenesisMismatch { seq } => {
                write!(f, "seq {seq}: only seq 0 may have an empty predecessor")
            }
            Self::BadSignature => write!(f, "lease signature does not verify"),
            Self::NonCanonical { field } => {
                write!(f, "{field} is not sorted and de-duplicated")
            }
            Self::CountMismatch { declared, actual } => {
                write!(
                    f,
                    "checkpoint declares {declared} entries, root covers {actual}"
                )
            }
        }
    }
}
impl std::error::Error for LeaseError {}
impl From<DecodeError> for LeaseError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<SignError> for LeaseError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

fn pack(addrs: &[Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addrs.len() * ADDR_LEN);
    for a in addrs {
        out.extend_from_slice(a.as_bytes());
    }
    out
}

fn unpack(field: &'static str, b: &[u8]) -> Result<Vec<Addr>, LeaseError> {
    if !b.len().is_multiple_of(ADDR_LEN) {
        return Err(LeaseError::RaggedAddrs { bytes: b.len() });
    }
    let mut out = Vec::with_capacity(b.len() / ADDR_LEN);
    for c in b.chunks_exact(ADDR_LEN) {
        let mut a = [0u8; ADDR_LEN];
        a.copy_from_slice(c);
        out.push(Addr::from_bytes(a));
    }
    check_canonical(field, &out)?;
    Ok(out)
}

/// Sorted, strictly ascending, no duplicates.
fn check_canonical(field: &'static str, addrs: &[Addr]) -> Result<(), LeaseError> {
    for w in addrs.windows(2) {
        if w[0].as_bytes() >= w[1].as_bytes() {
            return Err(LeaseError::NonCanonical { field });
        }
    }
    Ok(())
}

/// Put a list into the one form the encoder emits.
pub fn canonicalise(addrs: &[Addr]) -> Vec<Addr> {
    let mut v: Vec<[u8; ADDR_LEN]> = addrs.iter().map(|a| *a.as_bytes()).collect();
    v.sort_unstable();
    v.dedup();
    v.into_iter().map(Addr::from_bytes).collect()
}

fn check_genesis(seq: u64, prev: &[u8; 32]) -> Result<(), LeaseError> {
    let zero = prev.iter().all(|&b| b == 0);
    if (seq == 0) != zero {
        return Err(LeaseError::GenesisMismatch { seq });
    }
    Ok(())
}

/// An incremental change to a holder's leased set.
#[derive(Clone, PartialEq, Eq)]
pub struct LeaseDelta {
    pub holder_pk: Vec<u8>,
    pub epoch: u64,
    pub seq: u64,
    pub add: Vec<Addr>,
    pub remove: Vec<Addr>,
    pub prev: [u8; 32],
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for LeaseDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseDelta")
            .field("holder", &hex6(&key_id(&self.holder_pk)))
            .field("epoch", &self.epoch)
            .field("seq", &self.seq)
            .field("add", &self.add.len())
            .field("remove", &self.remove.len())
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

fn delta_body(epoch: u64, seq: u64, add: &[Addr], remove: &[Addr], prev: &[u8; 32]) -> Vec<u8> {
    encode_fields(&[
        &epoch.to_le_bytes(),
        &seq.to_le_bytes(),
        &pack(add),
        &pack(remove),
        prev,
    ])
    .expect("lease delta body always encodes")
}

impl LeaseDelta {
    /// Build and sign a delta. Address lists are canonicalised for the caller —
    /// a delta that differed only in list order would be a second spelling of
    /// the same statement.
    pub fn sign(
        identity: &Identity,
        epoch: u64,
        seq: u64,
        add: &[Addr],
        remove: &[Addr],
        prev: [u8; 32],
    ) -> Result<Self, LeaseError> {
        check_genesis(seq, &prev)?;
        let add = canonicalise(add);
        let remove = canonicalise(remove);
        let b = delta_body(epoch, seq, &add, &remove, &prev);
        let sig = identity.sign(SigContext::Lease, &b)?;
        Ok(Self {
            holder_pk: identity.verifying_key().to_vec(),
            epoch,
            seq,
            add,
            remove,
            prev,
            sig,
        })
    }

    pub fn verify(&self) -> Result<(), LeaseError> {
        check_genesis(self.seq, &self.prev)?;
        check_canonical("add", &self.add)?;
        check_canonical("remove", &self.remove)?;
        let b = delta_body(self.epoch, self.seq, &self.add, &self.remove, &self.prev);
        verify(&self.holder_pk, SigContext::Lease, &b, &self.sig)
            .map_err(|_| LeaseError::BadSignature)
    }

    pub fn holder_id(&self) -> [u8; 32] {
        key_id(&self.holder_pk)
    }

    pub fn chain_hash(&self) -> [u8; 32] {
        chain_hash(&self.encode_body_and_sig())
    }

    fn encode_body_and_sig(&self) -> Vec<u8> {
        let mut v = delta_body(self.epoch, self.seq, &self.add, &self.remove, &self.prev);
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn encode(&self) -> Result<Vec<u8>, LeaseError> {
        Ok(encode_fields(&[
            &self.holder_pk,
            &self.epoch.to_le_bytes(),
            &self.seq.to_le_bytes(),
            &pack(&self.add),
            &pack(&self.remove),
            &self.prev,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LeaseError> {
        let f = decode_fields(bytes)?;
        if f.len() != 7 {
            return Err(LeaseError::FieldCount {
                want: 7,
                got: f.len(),
            });
        }
        check_len("holder_pk", f[0], VERIFYING_KEY_LEN)?;
        check_len("sig", f[6], SIGNATURE_LEN)?;
        let seq = u64::from_le_bytes(fixed::<8>("seq", f[2])?);
        let prev = fixed::<32>("prev", f[5])?;
        check_genesis(seq, &prev)?;
        Ok(Self {
            holder_pk: f[0].to_vec(),
            epoch: u64::from_le_bytes(fixed::<8>("epoch", f[1])?),
            seq,
            add: unpack("add", f[3])?,
            remove: unpack("remove", f[4])?,
            prev,
            sig: f[6].to_vec(),
        })
    }
}

/// A signed statement of the holder's whole set, so the peer can compact and a
/// cold client can resync.
#[derive(Clone, PartialEq, Eq)]
pub struct LeaseCheckpoint {
    pub holder_pk: Vec<u8>,
    pub epoch: u64,
    pub seq: u64,
    pub root: [u8; 32],
    pub count: u64,
    pub prev: [u8; 32],
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for LeaseCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseCheckpoint")
            .field("holder", &hex6(&key_id(&self.holder_pk)))
            .field("epoch", &self.epoch)
            .field("seq", &self.seq)
            .field("count", &self.count)
            .finish()
    }
}

fn cp_body(epoch: u64, seq: u64, root: &[u8; 32], count: u64, prev: &[u8; 32]) -> Vec<u8> {
    encode_fields(&[
        &epoch.to_le_bytes(),
        &seq.to_le_bytes(),
        root,
        &count.to_le_bytes(),
        prev,
    ])
    .expect("lease checkpoint body always encodes")
}

impl LeaseCheckpoint {
    /// Build and sign a checkpoint over `full_set`.
    ///
    /// The root and the count are both derived here rather than taken from the
    /// caller, so they cannot disagree with each other or with the set.
    pub fn sign(
        identity: &Identity,
        epoch: u64,
        seq: u64,
        full_set: &[Addr],
        prev: [u8; 32],
    ) -> Result<Self, LeaseError> {
        check_genesis(seq, &prev)?;
        let set = canonicalise(full_set);
        let root = merkle::root(&set);
        let count = set.len() as u64;
        let b = cp_body(epoch, seq, &root, count, &prev);
        let sig = identity.sign(SigContext::LeaseCheckpoint, &b)?;
        Ok(Self {
            holder_pk: identity.verifying_key().to_vec(),
            epoch,
            seq,
            root,
            count,
            prev,
            sig,
        })
    }

    pub fn verify(&self) -> Result<(), LeaseError> {
        check_genesis(self.seq, &self.prev)?;
        let b = cp_body(self.epoch, self.seq, &self.root, self.count, &self.prev);
        verify(&self.holder_pk, SigContext::LeaseCheckpoint, &b, &self.sig)
            .map_err(|_| LeaseError::BadSignature)
    }

    /// Check this checkpoint against a set the verifier holds.
    pub fn covers(&self, full_set: &[Addr]) -> Result<(), LeaseError> {
        let set = canonicalise(full_set);
        if set.len() as u64 != self.count {
            return Err(LeaseError::CountMismatch {
                declared: self.count,
                actual: set.len() as u64,
            });
        }
        if merkle::root(&set) != self.root {
            return Err(LeaseError::BadSignature);
        }
        Ok(())
    }

    pub fn holder_id(&self) -> [u8; 32] {
        key_id(&self.holder_pk)
    }

    pub fn chain_hash(&self) -> [u8; 32] {
        let mut v = cp_body(self.epoch, self.seq, &self.root, self.count, &self.prev);
        v.extend_from_slice(&self.sig);
        chain_hash(&v)
    }

    pub fn encode(&self) -> Result<Vec<u8>, LeaseError> {
        Ok(encode_fields(&[
            &self.holder_pk,
            &self.epoch.to_le_bytes(),
            &self.seq.to_le_bytes(),
            &self.root,
            &self.count.to_le_bytes(),
            &self.prev,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LeaseError> {
        let f = decode_fields(bytes)?;
        if f.len() != 7 {
            return Err(LeaseError::FieldCount {
                want: 7,
                got: f.len(),
            });
        }
        check_len("holder_pk", f[0], VERIFYING_KEY_LEN)?;
        check_len("sig", f[6], SIGNATURE_LEN)?;
        let seq = u64::from_le_bytes(fixed::<8>("seq", f[2])?);
        let prev = fixed::<32>("prev", f[5])?;
        check_genesis(seq, &prev)?;
        Ok(Self {
            holder_pk: f[0].to_vec(),
            epoch: u64::from_le_bytes(fixed::<8>("epoch", f[1])?),
            seq,
            root: fixed::<32>("root", f[3])?,
            count: u64::from_le_bytes(fixed::<8>("count", f[4])?),
            prev,
            sig: f[6].to_vec(),
        })
    }
}

fn chain_hash(body_and_sig: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CHAIN_DOMAIN);
    h.update(&(body_and_sig.len() as u64).to_le_bytes());
    h.update(body_and_sig);
    *h.finalize().as_bytes()
}

fn check_len(field: &'static str, b: &[u8], want: usize) -> Result<(), LeaseError> {
    if b.len() != want {
        return Err(LeaseError::BadWidth {
            field,
            want,
            got: b.len(),
        });
    }
    Ok(())
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], LeaseError> {
    b.try_into().map_err(|_| LeaseError::BadWidth {
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
        Identity::derive(&[seed; 32], Role::Lease).unwrap()
    }

    fn addr(n: u8) -> Addr {
        Addr::of_ciphertext(&[n])
    }

    fn addrs(range: std::ops::Range<u8>) -> Vec<Addr> {
        range.map(addr).collect()
    }

    #[test]
    fn delta_sign_verify_round_trip() {
        let id = ident(1);
        let d = LeaseDelta::sign(&id, 1, 0, &addrs(0..5), &[], [0u8; 32]).unwrap();
        d.verify().unwrap();
        let back = LeaseDelta::decode(&d.encode().unwrap()).unwrap();
        assert_eq!(back, d);
        back.verify().unwrap();
    }

    #[test]
    fn address_lists_are_canonicalised_on_signing() {
        // A delta that differed only in list order would be a second spelling
        // of one statement, and the decoder refuses to accept it.
        let id = ident(1);
        let mut unsorted = addrs(0..6);
        unsorted.reverse();
        unsorted.push(unsorted[0]);
        let d = LeaseDelta::sign(&id, 1, 0, &unsorted, &[], [0u8; 32]).unwrap();
        assert_eq!(d.add, canonicalise(&unsorted));
        d.verify().unwrap();
        LeaseDelta::decode(&d.encode().unwrap()).unwrap();
    }

    #[test]
    fn an_unsorted_address_list_is_refused_at_decode() {
        let id = ident(1);
        let d = LeaseDelta::sign(&id, 1, 0, &addrs(0..4), &[], [0u8; 32]).unwrap();
        let mut swapped = d.add.clone();
        swapped.swap(0, 1);
        let framed = encode_fields(&[
            &d.holder_pk,
            &d.epoch.to_le_bytes(),
            &d.seq.to_le_bytes(),
            &pack(&swapped),
            &pack(&d.remove),
            &d.prev,
            &d.sig,
        ])
        .unwrap();
        assert_eq!(
            LeaseDelta::decode(&framed),
            Err(LeaseError::NonCanonical { field: "add" })
        );
    }

    #[test]
    fn a_non_canonical_remove_list_is_refused_too() {
        // Both lists, not just the first one checked.
        let id = ident(1);
        let d = LeaseDelta::sign(&id, 1, 0, &[], &addrs(0..4), [0u8; 32]).unwrap();
        let mut swapped = d.remove.clone();
        swapped.swap(0, 1);
        let framed = encode_fields(&[
            &d.holder_pk,
            &d.epoch.to_le_bytes(),
            &d.seq.to_le_bytes(),
            &pack(&d.add),
            &pack(&swapped),
            &d.prev,
            &d.sig,
        ])
        .unwrap();
        assert_eq!(
            LeaseDelta::decode(&framed),
            Err(LeaseError::NonCanonical { field: "remove" })
        );
    }

    #[test]
    fn a_ragged_address_list_is_refused() {
        assert_eq!(
            unpack("add", &[0u8; 33]),
            Err(LeaseError::RaggedAddrs { bytes: 33 })
        );
    }

    #[test]
    fn every_delta_field_is_signed() {
        let id = ident(1);
        let base = LeaseDelta::sign(&id, 1, 1, &addrs(0..3), &addrs(5..7), [9u8; 32]).unwrap();
        base.verify().unwrap();
        for m in 0..5 {
            let mut d = base.clone();
            match m {
                0 => d.epoch = 2,
                1 => d.seq = 2,
                // Canonicalised, so the mutation exercises the SIGNATURE
                // rather than tripping the sorted-list check first.
                2 => d.add = canonicalise(&addrs(0..4)),
                3 => d.remove = canonicalise(&addrs(5..8)),
                _ => d.prev = [8u8; 32],
            }
            assert_eq!(d.verify(), Err(LeaseError::BadSignature), "mutation {m}");
        }
    }

    #[test]
    fn only_seq_zero_may_be_genesis() {
        let id = ident(1);
        assert!(matches!(
            LeaseDelta::sign(&id, 1, 3, &[], &[], [0u8; 32]),
            Err(LeaseError::GenesisMismatch { seq: 3 })
        ));
        assert!(matches!(
            LeaseDelta::sign(&id, 1, 0, &[], &[], [1u8; 32]),
            Err(LeaseError::GenesisMismatch { seq: 0 })
        ));
    }

    #[test]
    fn checkpoint_sign_verify_and_cover() {
        let id = ident(1);
        let set = addrs(0..20);
        let c = LeaseCheckpoint::sign(&id, 2, 0, &set, [0u8; 32]).unwrap();
        c.verify().unwrap();
        c.covers(&set).unwrap();
        assert_eq!(c.count, 20);

        let back = LeaseCheckpoint::decode(&c.encode().unwrap()).unwrap();
        assert_eq!(back, c);
        back.covers(&set).unwrap();
    }

    #[test]
    fn a_checkpoint_does_not_cover_a_different_set() {
        let id = ident(1);
        let c = LeaseCheckpoint::sign(&id, 2, 0, &addrs(0..20), [0u8; 32]).unwrap();
        assert!(matches!(
            c.covers(&addrs(0..21)),
            Err(LeaseError::CountMismatch {
                declared: 20,
                actual: 21
            })
        ));
        // Same size, different contents: the count matches and the root does not.
        let mut other = addrs(0..19);
        other.push(addr(99));
        assert_eq!(c.covers(&other), Err(LeaseError::BadSignature));
    }

    #[test]
    fn the_checkpoint_root_and_count_cannot_disagree() {
        // Both derived at signing rather than accepted from the caller, so a
        // checkpoint claiming a count its root does not cover is unbuildable.
        let id = ident(1);
        let set = addrs(0..7);
        let c = LeaseCheckpoint::sign(&id, 1, 0, &set, [0u8; 32]).unwrap();
        assert_eq!(c.count as usize, canonicalise(&set).len());
        assert_eq!(c.root, merkle::root(&set));
    }

    #[test]
    fn a_delta_and_a_checkpoint_do_not_share_a_signature() {
        // Distinct SigContexts: a checkpoint signature presented as a delta
        // signature must not verify (SPECS §3.1).
        let id = ident(1);
        let d = LeaseDelta::sign(&id, 1, 0, &addrs(0..3), &[], [0u8; 32]).unwrap();
        let mut c = LeaseCheckpoint::sign(&id, 1, 0, &addrs(0..3), [0u8; 32]).unwrap();
        c.sig = d.sig.clone();
        assert_eq!(c.verify(), Err(LeaseError::BadSignature));
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 8, 100, 2000, 5400] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = LeaseDelta::decode(&junk);
            let _ = LeaseCheckpoint::decode(&junk);
        }
    }

    #[test]
    fn record_sizes() {
        // SPECS §3.8: one signature per delta, never per address. This is the
        // measurement that says how much a delta actually costs.
        let id = ident(1);
        let empty = LeaseDelta::sign(&id, 1, 0, &[], &[], [0u8; 32]).unwrap();
        let base = empty.encode().unwrap().len();
        // 1952 pk + 8 epoch + 8 seq + 0 add + 0 remove + 32 prev + 3309 sig
        // = 5309, plus 7 x 4 B length prefixes = 5337.
        assert_eq!(base, 5337, "empty LeaseDelta wire size changed");

        let d100 = LeaseDelta::sign(&id, 1, 0, &addrs(0..100), &[], [0u8; 32]).unwrap();
        let with100 = d100.encode().unwrap().len();
        assert_eq!(with100 - base, 100 * ADDR_LEN);

        let cp = LeaseCheckpoint::sign(&id, 1, 0, &addrs(0..100), [0u8; 32]).unwrap();
        let cpn = cp.encode().unwrap().len();
        assert_eq!(cpn, 5377, "LeaseCheckpoint wire size changed");

        println!(
            "LeaseDelta: {base} B fixed + 32 B/addr ({with100} B for 100). \
             Signing each address instead would cost {} B — {:.0}x.",
            100 * (SIGNATURE_LEN + ADDR_LEN),
            (100 * (SIGNATURE_LEN + ADDR_LEN)) as f64 / with100 as f64
        );
        println!("LeaseCheckpoint: {cpn} B regardless of set size (a {cpn}-byte statement about 100 addresses, or about 10 million).");
    }
}
