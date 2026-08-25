//! The key schedule (SPECS §3.1) — the only place in the workspace where a
//! nonce is chosen.
//!
//! # The rule this module exists to enforce
//!
//! > A deterministic nonce is permitted **only** when the key is content-derived,
//! > because such a key cannot encrypt two different plaintexts. Every
//! > non-convergent key uses a fresh random nonce.
//!
//! Revision 1 of the specification stated that rule for chunk keys and then
//! introduced a fixed root key with no nonce policy beside a remark that "a zero
//! nonce would also be sound". It was one implementer inference away from
//! keystream reuse on the object anchoring an entire namespace.
//!
//! Prose could not prevent that, so the type system does: [`Key`] has **no
//! public constructor that accepts a nonce policy**. The policy is set by the
//! derivation function that produces the key, and [`seal`] reads it from there.
//! A caller cannot pick a nonce, correctly or otherwise.

use crate::context;
use secure_memory::{decrypt_aad, encrypt_aad, open_with_nonce, seal_with_nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD open failed: wrong key, tampered ciphertext, or wrong AAD. The
    /// three are deliberately indistinguishable to the caller.
    Open,
    Seal,
    /// A sealed blob was shorter than its own framing.
    Truncated,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "decryption failed"),
            Self::Seal => write!(f, "encryption failed"),
            Self::Truncated => write!(f, "sealed data truncated"),
        }
    }
}
impl std::error::Error for CryptoError {}

/// How this key's nonce is chosen. Deliberately private: it is a property of
/// the derivation, never a caller's choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NoncePolicy {
    /// The key is a function of the plaintext it protects, so a repeated key
    /// implies identical plaintext. A deterministic nonce is safe by
    /// construction — and *required*, since byte-identical ciphertext is
    /// precisely what makes deduplication possible.
    Derived,
    /// Everything else. A fresh random nonce per message, carried with it.
    Random,
}

/// A 32-byte symmetric key that knows how its nonce must be chosen.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key {
    bytes: [u8; KEY_LEN],
    #[zeroize(skip)]
    policy: NoncePolicy,
}

impl std::fmt::Debug for Key {
    /// Never renders key material. A `Debug` that printed bytes would put keys
    /// into logs, which is the most common way good crypto is undone.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({:?}, <redacted>)", self.policy)
    }
}

/// Tenant (or, in `passphrase` mode, per-namespace) convergence secret.
///
/// Without it an outsider cannot compute the ciphertext for a candidate file,
/// which is what defeats confirmation-of-file attacks (SPECS §3.2).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ConvergenceSecret([u8; KEY_LEN]);

impl ConvergenceSecret {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
}

/// A directory's secret in the hierarchical chain (SPECS §3.1, §15.3).
///
/// Each directory derives from its parent, so a capability can later be scoped
/// to a subtree. Retrofitting this once data exists means re-keying everything.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirSecret([u8; KEY_LEN]);

impl DirSecret {
    pub fn root(namespace_root_secret: &[u8; KEY_LEN]) -> Self {
        Self(blake3::derive_key(context::DIR, namespace_root_secret))
    }

    /// Derive a child directory's secret. `dir_id` distinguishes siblings.
    pub fn child(&self, dir_id: &[u8]) -> Self {
        let mut input = Vec::with_capacity(KEY_LEN + dir_id.len());
        input.extend_from_slice(&self.0);
        input.extend_from_slice(dir_id);
        let out = Self(blake3::derive_key(context::DIR, &input));
        input.zeroize();
        out
    }
}

/// Convergent chunk key: `ck = BLAKE3::keyed_hash(CS, plaintext)` (SPECS §3.2).
///
/// Content-derived, so it carries [`NoncePolicy::Derived`] and sealing is
/// deterministic — identical plaintext under one secret yields identical
/// ciphertext, which is what dedup requires.
pub fn chunk_key(cs: &ConvergenceSecret, plaintext: &[u8]) -> Key {
    Key {
        bytes: *blake3::keyed_hash(&cs.0, plaintext).as_bytes(),
        policy: NoncePolicy::Derived,
    }
}

/// Directory manifest key `dk` (SPECS §3.1).
///
/// Path-derived rather than content-derived, so it may encrypt many successive
/// manifest versions — hence [`NoncePolicy::Random`]. Manifest dedup is given
/// up deliberately; it buys subtree capabilities and cheap directory moves.
pub fn manifest_key(dir: &DirSecret) -> Key {
    Key {
        bytes: blake3::derive_key(context::DIR_MANIFEST, &dir.0),
        policy: NoncePolicy::Random,
    }
}

/// Derive the deterministic nonce for a content-derived key.
///
/// Safe only because `ck` is a function of the plaintext: two different
/// plaintexts cannot share a key, so they cannot share a `(key, nonce)` pair.
fn derived_nonce(key: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    let h = blake3::keyed_hash(key, context::NONCE_CHUNK);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&h.as_bytes()[..NONCE_LEN]);
    n
}

/// Encrypt. The nonce follows from the key's policy; callers cannot supply one.
///
/// Output is `ciphertext || tag` for a derived-nonce key (the nonce is
/// recomputable) and `nonce || ciphertext || tag` for a random-nonce key.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.policy {
        NoncePolicy::Derived => {
            let n = derived_nonce(&key.bytes);
            seal_with_nonce(&key.bytes, &n, plaintext, aad).map_err(|_| CryptoError::Seal)
        }
        NoncePolicy::Random => {
            encrypt_aad(&key.bytes, plaintext, aad).map_err(|_| CryptoError::Seal)
        }
    }
}

/// Decrypt data produced by [`seal`] under the same key and AAD.
pub fn open(key: &Key, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.policy {
        NoncePolicy::Derived => {
            let n = derived_nonce(&key.bytes);
            open_with_nonce(&key.bytes, &n, sealed, aad).map_err(|_| CryptoError::Open)
        }
        NoncePolicy::Random => {
            if sealed.len() < NONCE_LEN {
                return Err(CryptoError::Truncated);
            }
            decrypt_aad(&key.bytes, sealed, aad).map_err(|_| CryptoError::Open)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cs(b: u8) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes([b; KEY_LEN])
    }

    #[test]
    fn convergent_sealing_is_deterministic() {
        // The property deduplication is built on. If this ever fails, dedup
        // silently degrades to zero rather than breaking loudly.
        let s = cs(1);
        let pt = b"the same chunk of a file";
        let a = seal(&chunk_key(&s, pt), pt, b"").unwrap();
        let b = seal(&chunk_key(&s, pt), pt, b"").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_convergence_secret_breaks_dedup_and_the_oracle() {
        // Two tenants storing the same file must produce different ciphertext,
        // or a co-tenant learns what you hold (SPECS §3.2).
        let pt = b"payslip.pdf contents";
        let mine = seal(&chunk_key(&cs(1), pt), pt, b"").unwrap();
        let theirs = seal(&chunk_key(&cs(2), pt), pt, b"").unwrap();
        assert_ne!(mine, theirs);
    }

    #[test]
    fn manifest_keys_never_seal_the_same_bytes_twice() {
        // Path-derived keys encrypt many successive versions, so a deterministic
        // nonce here would be keystream reuse. The policy must prevent it.
        let dir = DirSecret::root(&[9u8; KEY_LEN]);
        let k = manifest_key(&dir);
        assert_ne!(
            seal(&k, b"manifest v1", b"").unwrap(),
            seal(&k, b"manifest v1", b"").unwrap()
        );
    }

    #[test]
    fn roundtrip_under_both_policies() {
        let s = cs(3);
        let pt = b"payload";
        let ck = chunk_key(&s, pt);
        assert_eq!(
            open(&ck, &seal(&ck, pt, b"aad").unwrap(), b"aad").unwrap(),
            pt
        );

        let mk = manifest_key(&DirSecret::root(&[4u8; KEY_LEN]));
        assert_eq!(
            open(&mk, &seal(&mk, pt, b"aad").unwrap(), b"aad").unwrap(),
            pt
        );
    }

    #[test]
    fn wrong_aad_or_key_fails_to_open() {
        let s = cs(5);
        let pt = b"payload";
        let k = chunk_key(&s, pt);
        let sealed = seal(&k, pt, b"header").unwrap();
        assert_eq!(open(&k, &sealed, b"other").unwrap_err(), CryptoError::Open);
        let other = chunk_key(&cs(6), pt);
        assert_eq!(
            open(&other, &sealed, b"header").unwrap_err(),
            CryptoError::Open
        );
    }

    #[test]
    fn sibling_directories_get_independent_secrets() {
        let root = DirSecret::root(&[1u8; KEY_LEN]);
        let a = manifest_key(&root.child(b"photos"));
        let b = manifest_key(&root.child(b"documents"));
        // Distinct keys must not open each other's data.
        let sealed = seal(&a, b"x", b"").unwrap();
        assert!(open(&b, &sealed, b"").is_err());
    }

    #[test]
    fn debug_never_reveals_key_material() {
        let k = chunk_key(&cs(7), b"secret");
        let rendered = format!("{k:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&format!("{}", k.bytes[0])));
    }

    proptest! {
        #[test]
        fn convergent_roundtrip(pt in prop::collection::vec(any::<u8>(), 0..512)) {
            let s = cs(11);
            let k = chunk_key(&s, &pt);
            prop_assert_eq!(open(&k, &seal(&k, &pt, b"").unwrap(), b"").unwrap(), pt);
        }

        /// Identical plaintext always converges; different plaintext never does.
        #[test]
        fn convergence_iff_same_plaintext(
            a in prop::collection::vec(any::<u8>(), 0..128),
            b in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            let s = cs(13);
            let sa = seal(&chunk_key(&s, &a), &a, b"").unwrap();
            let sb = seal(&chunk_key(&s, &b), &b, b"").unwrap();
            prop_assert_eq!(a == b, sa == sb);
        }

        /// Never panics on adversarial sealed input -- a hostile peer supplies it.
        #[test]
        fn open_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let s = cs(17);
            let _ = open(&chunk_key(&s, b"k"), &bytes, b"");
            let _ = open(&manifest_key(&DirSecret::root(&[2u8; KEY_LEN])), &bytes, b"");
        }
    }
}
