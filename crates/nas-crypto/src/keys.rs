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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD open failed: wrong key, tampered ciphertext, or wrong AAD. The
    /// three are deliberately indistinguishable to the caller.
    Open,
    Seal,
    /// A sealed blob was shorter than its own framing.
    Truncated,
    /// A content-derived key was passed to [`seal`].
    ///
    /// Its nonce is a function of the key, so sealing anything other than the
    /// key's own derivation input reuses a keystream. Use [`seal_chunk`], which
    /// derives and seals from the same bytes and cannot desynchronise them.
    DerivedKeyNeedsSealChunk,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "decryption failed"),
            Self::Seal => write!(f, "encryption failed"),
            Self::Truncated => write!(f, "sealed data truncated"),
            Self::DerivedKeyNeedsSealChunk => write!(
                f,
                "a content-derived key cannot be used with seal(); use seal_chunk(), \
                 which derives and seals from the same bytes"
            ),
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

/// A key-encryption key built from bytes a caller already holds.
///
/// # Why this is not the hole [`ChunkReadKey`] exists to avoid
///
/// The dangerous pairing is *a deterministic nonce over caller-chosen bytes*:
/// two different plaintexts under one such key reuse a keystream. This
/// constructor produces a [`NoncePolicy::Random`] key, where every message
/// carries a fresh 24-byte nonce, so the pairing is safe no matter where the
/// bytes came from. That is precisely why the nonce policy is a property of the
/// derivation rather than of the caller: the answer differs per derivation, and
/// only the derivation knows it.
///
/// The intended input is an Argon2id output (SPECS §2.2.2's `KEK`), which wraps
/// one DEK and may re-wrap it on every passphrase change — many plaintexts under
/// one key, which is exactly the case that mandates a random nonce.
pub fn wrapping_key(bytes: [u8; KEY_LEN]) -> Key {
    Key {
        bytes,
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

/// Derive a chunk key from `plaintext` **and seal that same plaintext**.
///
/// # Why this exists, and why [`seal`] now refuses derived keys
///
/// The module claimed a deterministic nonce was unreachable for anything but a
/// content-derived key, and that "the type system does" what prose could not.
/// It enforced half of that. `chunk_key(cs, A)` derives from `A`, but
/// `seal(&key, B)` encrypted whatever `B` the caller passed — the derivation
/// input and the sealed plaintext were never bound together. Two calls with the
/// same `A` and different `B` reuse a `(key, nonce)` pair, and a review's probe
/// confirmed the consequence directly:
///
/// ```text
/// XOR(ciphertext_bodies) == XOR(plaintexts)
/// ```
///
/// which is the keystream disclosure `seal_with_nonce`'s own documentation
/// warns about. No caller in the tree ever misused it — every one passed the
/// same bytes to both — but that is caller discipline, which is precisely what
/// the module was written not to rely on.
///
/// Fusing the two operations makes the sealed bytes *always* the derivation
/// input. [`seal`] now returns [`CryptoError::DerivedKeyNeedsSealChunk`] for a
/// derived key, so the desynchronised call is no longer expressible.
pub fn seal_chunk(
    cs: &ConvergenceSecret,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; KEY_LEN]), CryptoError> {
    let key = chunk_key(cs, plaintext);
    let n = derived_nonce(&key.bytes);
    let sealed = seal_with_nonce(&key.bytes, &n, plaintext, aad).map_err(|_| CryptoError::Seal)?;
    Ok((sealed, key.bytes))
}

/// Encrypt. The nonce follows from the key's policy; callers cannot supply one.
///
/// Output is `ciphertext || tag` for a derived-nonce key (the nonce is
/// recomputable) and `nonce || ciphertext || tag` for a random-nonce key.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.policy {
        // Refused, not handled. A derived key's nonce is a function of the key
        // alone, so sealing a plaintext that is not the key's own derivation
        // input reuses a keystream. `seal_chunk` cannot desynchronise the two.
        NoncePolicy::Derived => Err(CryptoError::DerivedKeyNeedsSealChunk),
        NoncePolicy::Random => {
            encrypt_aad(&key.bytes, plaintext, aad).map_err(|_| CryptoError::Seal)
        }
    }
}

/// A chunk key recovered from a manifest, usable **only for decryption**.
///
/// # Why this is a separate type
///
/// A manifest must store `ck` (SPECS §4.3): a reader holds no plaintext and so
/// cannot re-derive it. That forces a way back from 32 stored bytes to a usable
/// key — and a naive `Key::from_bytes(.., Derived)` would hand any caller a
/// deterministic-nonce key over bytes of their choosing. Sealing two different
/// plaintexts under it would then reuse a `(key, nonce)` pair, which is exactly
/// the failure this module was written to make unreachable.
///
/// The escape is that a stored `ck` is only ever needed to *open*. A writer
/// always holds the plaintext and calls [`chunk_key`], which re-derives the key
/// from it. So the reconstruction path yields a type with no [`seal`] at all:
/// the dangerous operation is not merely discouraged, it is inexpressible.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChunkReadKey {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for ChunkReadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkReadKey(<redacted>)")
    }
}

/// Rebuild a chunk key from the `ck` bytes stored in a manifest.
///
/// The result cannot seal. See [`ChunkReadKey`].
pub fn chunk_key_from_stored(bytes: [u8; KEY_LEN]) -> ChunkReadKey {
    ChunkReadKey { bytes }
}

/// Decrypt a chunk using a `ck` recovered from a manifest.
pub fn open_chunk(key: &ChunkReadKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let n = derived_nonce(&key.bytes);
    open_with_nonce(&key.bytes, &n, sealed, aad).map_err(|_| CryptoError::Open)
}

impl Key {
    /// Expose a **content-derived** key so it can be written into a manifest.
    ///
    /// Returns `None` for a random-nonce key. Manifest keys are path-derived
    /// and reachable from a capability; writing one into a manifest would
    /// publish it to anyone who could read that manifest, so this path refuses
    /// rather than trusting the caller to only ask about chunks.
    pub fn expose_derived(&self) -> Option<&[u8; KEY_LEN]> {
        match self.policy {
            NoncePolicy::Derived => Some(&self.bytes),
            NoncePolicy::Random => None,
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
    fn a_stored_ck_reopens_the_chunk_it_came_from() {
        // SPECS §4.3: the manifest stores ck because the reader cannot derive
        // it. This is that round trip.
        let s = cs(1);
        let pt = b"a chunk that will be read back later";
        let (sealed, stored) = seal_chunk(&s, pt, b"aad").unwrap();
        let rk = chunk_key_from_stored(stored);
        assert_eq!(open_chunk(&rk, &sealed, b"aad").unwrap(), pt);
    }

    #[test]
    fn a_stored_ck_still_authenticates_the_aad() {
        let s = cs(1);
        let pt = b"chunk";
        let (sealed, stored) = seal_chunk(&s, pt, b"right").unwrap();
        let rk = chunk_key_from_stored(stored);
        assert_eq!(open_chunk(&rk, &sealed, b"wrong"), Err(CryptoError::Open));
    }

    #[test]
    fn seal_refuses_a_derived_key_so_the_desync_is_unreachable() {
        // The bug this closes: chunk_key(cs, A) then seal(key, B) reused a
        // (key, nonce) pair over two different plaintexts, leaking
        // XOR(plaintexts). No caller did it, but the module claimed the type
        // system made it impossible and it did not.
        let s = cs(1);
        let k = chunk_key(&s, b"derived from A");
        assert_eq!(
            seal(&k, b"but sealing B", b""),
            Err(CryptoError::DerivedKeyNeedsSealChunk)
        );
        // Even sealing the SAME bytes goes through seal_chunk now, so there is
        // no path where the two can drift apart.
        assert!(seal(&k, b"derived from A", b"").is_err());
        assert!(seal_chunk(&s, b"derived from A", b"").is_ok());
    }

    #[test]
    fn seal_chunk_is_deterministic_and_returns_the_key_it_used() {
        let s = cs(2);
        let pt = b"a chunk";
        let (a, ka) = seal_chunk(&s, pt, b"aad").unwrap();
        let (b, kb) = seal_chunk(&s, pt, b"aad").unwrap();
        assert_eq!(a, b, "convergence requires determinism");
        assert_eq!(ka, kb);
        // The returned key is the one that must go into the manifest.
        assert_eq!(
            open_chunk(&chunk_key_from_stored(ka), &a, b"aad").unwrap(),
            pt
        );
    }

    #[test]
    fn a_manifest_key_refuses_to_be_written_into_a_manifest() {
        // Random-nonce keys are path-derived and reachable from a capability.
        // Serialising one would publish it to every reader of that manifest.
        let d = DirSecret::root(&[7u8; KEY_LEN]);
        assert!(manifest_key(&d).expose_derived().is_none());
        assert!(chunk_key(&cs(1), b"x").expose_derived().is_some());
    }

    #[test]
    fn open_chunk_rejects_a_key_that_did_not_seal_it() {
        let s = cs(1);
        let pt = b"chunk";
        let sealed = seal_chunk(&s, pt, b"").unwrap().0;
        let wrong = chunk_key_from_stored([0u8; KEY_LEN]);
        assert_eq!(open_chunk(&wrong, &sealed, b""), Err(CryptoError::Open));
    }

    #[test]
    fn convergent_sealing_is_deterministic() {
        // The property deduplication is built on. If this ever fails, dedup
        // silently degrades to zero rather than breaking loudly.
        let s = cs(1);
        let pt = b"the same chunk of a file";
        let a = seal_chunk(&s, pt, b"").unwrap().0;
        let b = seal_chunk(&s, pt, b"").unwrap().0;
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_convergence_secret_breaks_dedup_and_the_oracle() {
        // Two tenants storing the same file must produce different ciphertext,
        // or a co-tenant learns what you hold (SPECS §3.2).
        let pt = b"payslip.pdf contents";
        let (mine, _) = seal_chunk(&cs(1), pt, b"").unwrap();
        let (theirs, _) = seal_chunk(&cs(2), pt, b"").unwrap();
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
        let (sealed, _) = seal_chunk(&s, pt, b"aad").unwrap();
        assert_eq!(open(&ck, &sealed, b"aad").unwrap(), pt);

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
        let (sealed, _) = seal_chunk(&s, pt, b"header").unwrap();
        let k = chunk_key(&s, pt);
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
            let (sealed, _) = seal_chunk(&s, &pt, b"").unwrap();
            prop_assert_eq!(open(&k, &sealed, b"").unwrap(), pt);
        }

        /// Identical plaintext always converges; different plaintext never does.
        #[test]
        fn convergence_iff_same_plaintext(
            a in prop::collection::vec(any::<u8>(), 0..128),
            b in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            let s = cs(13);
            let (sa, _) = seal_chunk(&s, &a, b"").unwrap();
            let (sb, _) = seal_chunk(&s, &b, b"").unwrap();
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
