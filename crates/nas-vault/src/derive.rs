//! What the DEK unwraps into (SPECS §2.2.2).
//!
//! ```text
//! root_secret  = derive_key("nas-tools/ns/root/v1",        DEK)
//! CS_ns        = derive_key("nas-tools/ns/convergence/v1", DEK)
//! sk_slot_seed = derive_key("nas-tools/ns/slot/v1",        DEK)
//! ```
//!
//! Revision 4 of the spec never said what the DEK unwrapped into, and §3 had no
//! single "namespace key" it could have meant. Everything derives from the DEK.
//!
//! # The convergence secret is per-namespace, not tenant-wide
//!
//! `CS_ns` rather than the tenant's `CS`. Otherwise a passphrase namespace
//! would need a vault secret in order to write, and "recoverable from memory
//! alone" would be false — which is the entire point of the mode.
//!
//! The price is real and worth stating: **a passphrase namespace deduplicates
//! only within itself.** Two passphrase namespaces holding the same photo store
//! it twice, and neither shares a chunk with the tenant's `e2ee` data.

use nas_crypto::{context, ConvergenceSecret, DirSecret, Identity, Role, SignError, KEY_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Everything a namespace needs, derived from one 32-byte DEK.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NamespaceSecrets {
    root_secret: [u8; KEY_LEN],
    convergence: [u8; KEY_LEN],
    slot_seed: [u8; KEY_LEN],
}

impl std::fmt::Debug for NamespaceSecrets {
    /// Never renders key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NamespaceSecrets(<redacted>)")
    }
}

impl NamespaceSecrets {
    /// Derive the three secrets. Deterministic: the same DEK always yields the
    /// same namespace, which is what makes "recoverable from memory" true.
    pub fn from_dek(dek: &[u8; KEY_LEN]) -> Self {
        Self {
            root_secret: blake3::derive_key(context::NS_ROOT, dek),
            convergence: blake3::derive_key(context::NS_CONVERGENCE, dek),
            slot_seed: blake3::derive_key(context::NS_SLOT, dek),
        }
    }

    /// The root of the per-directory key chain (SPECS §3.1, §15.3).
    pub fn dir_root(&self) -> DirSecret {
        DirSecret::root(&self.root_secret)
    }

    /// This namespace's convergence secret. See the module docs on why it is
    /// per-namespace.
    pub fn convergence_secret(&self) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(self.convergence)
    }

    /// The identity that signs this namespace's slot records and wrap records.
    pub fn slot_identity(&self) -> Result<Identity, SignError> {
        Identity::derive(&self.slot_seed, Role::Slot)
    }

    /// The identity that signs this namespace's leases.
    pub fn lease_identity(&self) -> Result<Identity, SignError> {
        Identity::derive(&self.slot_seed, Role::Lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK: [u8; 32] = [0x11; 32];

    #[test]
    fn derivation_is_deterministic() {
        // "Recoverable from memory alone" is exactly this property.
        assert_eq!(
            NamespaceSecrets::from_dek(&DEK),
            NamespaceSecrets::from_dek(&DEK)
        );
    }

    #[test]
    fn a_different_dek_gives_an_unrelated_namespace() {
        let a = NamespaceSecrets::from_dek(&DEK);
        let b = NamespaceSecrets::from_dek(&[0x22; 32]);
        assert_ne!(a, b);
        assert_ne!(
            a.slot_identity().unwrap().verifying_key(),
            b.slot_identity().unwrap().verifying_key()
        );
    }

    #[test]
    fn the_three_secrets_are_distinct() {
        // If two derivations collided, the convergence secret would also be a
        // signing seed, and knowing what deduplicates would let you sign.
        let s = NamespaceSecrets::from_dek(&DEK);
        assert_ne!(s.root_secret, s.convergence);
        assert_ne!(s.convergence, s.slot_seed);
        assert_ne!(s.root_secret, s.slot_seed);
    }

    #[test]
    fn slot_and_lease_identities_differ() {
        // SPECS §3.1's role separation survives the namespace derivation: both
        // come from one seed and must still be distinct keypairs.
        let s = NamespaceSecrets::from_dek(&DEK);
        assert_ne!(
            s.slot_identity().unwrap().verifying_key(),
            s.lease_identity().unwrap().verifying_key()
        );
    }

    #[test]
    fn two_passphrase_namespaces_do_not_share_chunks() {
        // The stated price of per-namespace convergence: the same plaintext in
        // two passphrase namespaces is stored twice. Asserted so the trade-off
        // is a fact of the test suite and not only of the documentation.
        use nas_core::Addr;
        use nas_crypto::seal_chunk;

        let a = NamespaceSecrets::from_dek(&DEK);
        let b = NamespaceSecrets::from_dek(&[0x22; 32]);
        let plaintext = b"the same family photo in two namespaces";

        let (ca, _) = seal_chunk(&a.convergence_secret(), plaintext, b"").unwrap();
        let (cb, _) = seal_chunk(&b.convergence_secret(), plaintext, b"").unwrap();
        assert_ne!(Addr::of_ciphertext(&ca), Addr::of_ciphertext(&cb));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let s = NamespaceSecrets::from_dek(&DEK);
        let out = format!("{s:?}");
        assert!(out.contains("redacted"));
        assert!(out.len() < 40, "{out}");
    }
}
