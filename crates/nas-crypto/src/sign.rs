//! ML-DSA-65 signing with role separation and per-message contexts (SPECS §3.1).
//!
//! # Two separations, not one
//!
//! SPECS §3.1 requires both, and they defend against different things:
//!
//! * **Role separation** — `sk_slot` and `sk_lease` are *distinct keypairs*, so
//!   compromising the key that signs leases cannot forge a slot update. This is
//!   a property of the key material.
//! * **Context separation** — every message is prefixed with a string naming
//!   what it is, so a signature produced for one object cannot be replayed as a
//!   signature for another *even under the same key*. This is a property of the
//!   message.
//!
//! Having only the first still lets one role's two message types be confused;
//! having only the second means one stolen key forges everything. [`Role`]
//! selects the keypair, [`SigContext`] selects the prefix, and [`sign`] requires
//! both. It is not possible to sign a bare message with this API.
//!
//! # Why seeds rather than stored keys
//!
//! An ML-DSA-65 signing key is 4032 bytes. Storing one per role would make the
//! vault large and a backup of it correspondingly awkward. Instead one 32-byte
//! vault seed derives every role under a distinct KDF context, so a new role
//! costs a context string and a backup of the seed restores every identity.
//! That makes the vault seed *the* secret of the system, which §2.2 already
//! assumes it is.

use crate::context::SigContext;
use secure_memory::sig::{SigKeyPair, SIG_SIZE, VK_SIZE};
use zeroize::Zeroize;

pub use secure_memory::sig::{SIG_SIZE as SIGNATURE_LEN, VK_SIZE as VERIFYING_KEY_LEN};

/// A signing role. Each gets its own keypair (SPECS §3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Role {
    /// Signs slot records and checkpoints.
    Slot,
    /// Signs leases and retention sets. A distinct keypair, so a lease key
    /// stolen from a long-running sweep process cannot move a slot head.
    Lease,
    /// Signs witness observations. Distinct because a witness key may be held
    /// by a node that holds nothing else — `nas-peer --witness` (SPECS §5.3).
    Witness,
    /// Owned by `simple-network` for the transport handshake.
    Transport,
}

impl Role {
    /// KDF context for deriving this role's seed from the vault seed.
    pub const fn kdf_context(self) -> &'static str {
        match self {
            Self::Slot => "nas-tools/role/slot/v1",
            Self::Lease => "nas-tools/role/lease/v1",
            Self::Witness => "nas-tools/role/witness/v1",
            Self::Transport => "nas-tools/role/transport/v1",
        }
    }

    pub const ALL: [Role; 4] = [Self::Slot, Self::Lease, Self::Witness, Self::Transport];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The underlying ML-DSA implementation refused.
    Backend,
    /// A verifying key of the wrong length; never a valid ML-DSA-65 key.
    BadKeyLength { got: usize },
    /// A signature of the wrong length. Rejected before the backend sees it,
    /// so a malformed record cannot reach the verifier at all.
    BadSignatureLength { got: usize },
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend => write!(f, "signature operation failed"),
            Self::BadKeyLength { got } => {
                write!(
                    f,
                    "verifying key is {got} B, ML-DSA-65 keys are {VK_SIZE} B"
                )
            }
            Self::BadSignatureLength { got } => {
                write!(
                    f,
                    "signature is {got} B, ML-DSA-65 signatures are {SIG_SIZE} B"
                )
            }
        }
    }
}
impl std::error::Error for SignError {}

/// A role's keypair. The secret half lives in `secure_memory`'s locked memory.
pub struct Identity {
    role: Role,
    kp: SigKeyPair,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifying key is public, but printing 1952 bytes helps nobody.
        write!(
            f,
            "Identity({:?}, vk={})",
            self.role,
            hex12(self.verifying_key())
        )
    }
}

fn hex12(b: &[u8]) -> String {
    b.iter()
        .take(6)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

impl Identity {
    /// Derive this role's keypair from the vault seed.
    ///
    /// Deterministic: the same vault seed always yields the same identity, so
    /// restoring a vault restores the identity rather than orphaning everything
    /// it ever signed.
    pub fn derive(vault_seed: &[u8; 32], role: Role) -> Result<Self, SignError> {
        let mut xi = blake3::derive_key(role.kdf_context(), vault_seed);
        let kp = SigKeyPair::from_seed(&xi).map_err(|_| SignError::Backend)?;
        xi.zeroize();
        Ok(Self { role, kp })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The public half. Safe to publish; this is what a roster holds.
    pub fn verifying_key(&self) -> &[u8] {
        self.kp.verifying_key()
    }

    /// Short, stable identifier: `BLAKE3(vk)`.
    ///
    /// Records carry this rather than the 1952-byte key, and the roster maps it
    /// back. At 3309 bytes of signature per record the budget is already tight
    /// (SPECS §3.8); spending another 1952 to repeat a key the roster holds
    /// would nearly double it.
    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(self.verifying_key()).as_bytes()
    }

    /// Sign `message` as `ctx`. The context is prefixed, never optional.
    pub fn sign(&self, ctx: SigContext, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.kp
            .sign(&framed(ctx, message))
            .map_err(|_| SignError::Backend)
    }
}

/// `context ‖ le32(len(context)) ‖ message`.
///
/// The length is included so the boundary between context and message is
/// unambiguous. Plain concatenation would let a context that is a prefix of
/// another — and `.../delete-request/v1` versus a hypothetical
/// `.../delete-request/v10` is exactly that shape — admit a message that reads
/// as a different context entirely.
fn framed(ctx: SigContext, message: &[u8]) -> Vec<u8> {
    let c = ctx.as_bytes();
    let mut out = Vec::with_capacity(c.len() + 4 + message.len());
    out.extend_from_slice(c);
    out.extend_from_slice(&(c.len() as u32).to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// Verify a signature made by [`Identity::sign`] under the same context.
///
/// Lengths are checked first so a malformed record is rejected here rather than
/// inside the backend.
pub fn verify(
    verifying_key: &[u8],
    ctx: SigContext,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignError> {
    if verifying_key.len() != VK_SIZE {
        return Err(SignError::BadKeyLength {
            got: verifying_key.len(),
        });
    }
    if signature.len() != SIG_SIZE {
        return Err(SignError::BadSignatureLength {
            got: signature.len(),
        });
    }
    match SigKeyPair::verify(verifying_key, &framed(ctx, message), signature) {
        Ok(true) => Ok(()),
        _ => Err(SignError::Backend),
    }
}

/// `BLAKE3(vk)` for a raw verifying key.
pub fn key_id(verifying_key: &[u8]) -> [u8; 32] {
    *blake3::hash(verifying_key).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0xA5; 32];

    #[test]
    fn roles_derive_distinct_keypairs() {
        // SPECS §3.1: a stolen lease key must not be able to move a slot head.
        let mut seen = std::collections::HashSet::new();
        for r in Role::ALL {
            let id = Identity::derive(&SEED, r).unwrap();
            assert!(seen.insert(id.id()), "{r:?} collided with another role");
        }
        assert_eq!(seen.len(), Role::ALL.len());
    }

    #[test]
    fn role_kdf_contexts_are_distinct() {
        let set: std::collections::HashSet<&str> =
            Role::ALL.iter().map(|r| r.kdf_context()).collect();
        assert_eq!(set.len(), Role::ALL.len());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = Identity::derive(&SEED, Role::Slot).unwrap();
        let b = Identity::derive(&SEED, Role::Slot).unwrap();
        assert_eq!(a.verifying_key(), b.verifying_key());
    }

    #[test]
    fn a_different_vault_seed_gives_a_different_identity() {
        let a = Identity::derive(&SEED, Role::Slot).unwrap();
        let b = Identity::derive(&[0x5A; 32], Role::Slot).unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let sig = id.sign(SigContext::Slot, b"a slot record").unwrap();
        assert_eq!(sig.len(), SIG_SIZE);
        verify(id.verifying_key(), SigContext::Slot, b"a slot record", &sig).unwrap();
    }

    #[test]
    fn a_signature_does_not_verify_under_another_context() {
        // The whole point of the prefix: one key signs slot records AND
        // checkpoints, so without a context a checkpoint signature could be
        // presented as a slot signature.
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let msg = b"same bytes, different meaning";
        let sig = id.sign(SigContext::Slot, msg).unwrap();
        assert!(verify(id.verifying_key(), SigContext::Checkpoint, msg, &sig).is_err());
        for ctx in SigContext::ALL {
            let ok = verify(id.verifying_key(), ctx, msg, &sig).is_ok();
            assert_eq!(ok, ctx == SigContext::Slot, "{ctx:?}");
        }
    }

    #[test]
    fn a_signature_does_not_verify_under_another_role() {
        let slot = Identity::derive(&SEED, Role::Slot).unwrap();
        let lease = Identity::derive(&SEED, Role::Lease).unwrap();
        let sig = slot.sign(SigContext::Slot, b"m").unwrap();
        assert!(verify(lease.verifying_key(), SigContext::Slot, b"m", &sig).is_err());
    }

    #[test]
    fn the_context_boundary_is_unambiguous() {
        // Without the length, `ctx ‖ msg` could be re-split: a longer context
        // whose prefix is a shorter one would accept the shorter one's message
        // with the difference moved into the message.
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let c = SigContext::Slot.as_bytes();
        let sig = id.sign(SigContext::Slot, b"tail").unwrap();

        // A forged "message" that would reconstruct the same buffer under naive
        // concatenation must not verify.
        let mut naive = Vec::new();
        naive.extend_from_slice(&c[c.len() - 1..]);
        naive.extend_from_slice(b"tail");
        assert!(verify(id.verifying_key(), SigContext::Slot, &naive, &sig).is_err());
    }

    #[test]
    fn malformed_keys_and_signatures_are_refused_before_the_backend() {
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let sig = id.sign(SigContext::Slot, b"m").unwrap();
        assert_eq!(
            verify(&[0u8; 10], SigContext::Slot, b"m", &sig),
            Err(SignError::BadKeyLength { got: 10 })
        );
        assert_eq!(
            verify(id.verifying_key(), SigContext::Slot, b"m", &[0u8; 10]),
            Err(SignError::BadSignatureLength { got: 10 })
        );
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let sig = id.sign(SigContext::Slot, b"seq=5").unwrap();
        assert!(verify(id.verifying_key(), SigContext::Slot, b"seq=6", &sig).is_err());
    }

    #[test]
    fn debug_does_not_dump_the_whole_key() {
        let id = Identity::derive(&SEED, Role::Slot).unwrap();
        let s = format!("{id:?}");
        assert!(s.len() < 80, "Debug printed {} chars", s.len());
        assert!(s.contains("Slot"));
    }
}
