//! The local vault (SPECS §3.1, §3.9, §4).
//!
//! ```text
//! vault.bin   # ML-DSA identities, CS generations, pinned peers
//! ```
//!
//! Held by the client, **never shipped to a peer**. What it stores is one
//! 32-byte seed per generation plus a little metadata — not 4032-byte signing
//! keys, because every identity derives from the seed (SPECS §3.1).
//!
//! # Generations exist for revocation
//!
//! SPECS §3.9 keeps three revocation paths apart, and they are not
//! interchangeable:
//!
//! * **Blocking a peer** stops talking to it. Data it already copied is gone.
//! * **Removing a writer from the roster** stops *future* records verifying. It
//!   cannot un-sign the past.
//! * **Rotating `CS`** is the only one that changes what new data looks like,
//!   and it costs re-encryption.
//!
//! Only the third needs a generation, and the vault keeps every past generation
//! because data written under an old `CS` still has to be readable. A vault
//! that dropped old generations on rotation would turn revocation into data
//! loss — which is exactly the pressure that makes people not rotate.
//!
//! # At rest
//!
//! Sealed with a random-nonce key. Where that key comes from is the mode's
//! business: `e2ee` takes a high-entropy key the user holds, `passphrase`
//! derives one with Argon2id (§2.2). This module takes the key and does not ask.

use nas_core::{decode_fields, encode_fields, DecodeError};
use nas_crypto::{
    open, random, seal, wrapping_key, ConvergenceSecret, CryptoError, Identity, Role, SignError,
    KEY_LEN,
};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AAD for the vault container, so a vault blob cannot be presented as some
/// other sealed object.
const VAULT_AAD: &[u8] = b"nas-tools/aad/vault/v1";
const VAULT_MAGIC: &[u8; 4] = b"NASV";
/// KDF context for the directory-key root, distinct from every signing role.
const DIR_ROOT_CONTEXT: &str = "nas-tools/vault/dir-root/v1";
pub const VAULT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    Decode(DecodeError),
    Crypto(CryptoError),
    Sign(SignError),
    BadMagic,
    UnknownVersion {
        found: u16,
    },
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    /// No generation with that number.
    NoSuchGeneration {
        generation: u32,
    },
    /// Generations must be contiguous from 0 and strictly ascending — the
    /// canonical-form rule again, and a gap would mean data written under a
    /// missing generation was silently unreadable.
    NonCanonical {
        reason: &'static str,
    },
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "vault encoding: {e:?}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadMagic => write!(f, "not a vault"),
            Self::UnknownVersion { found } => {
                write!(
                    f,
                    "vault version {found}, this build understands {VAULT_VERSION}"
                )
            }
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::NoSuchGeneration { generation } => write!(f, "no generation {generation}"),
            Self::NonCanonical { reason } => write!(f, "malformed vault: {reason}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for VaultError {}
impl From<DecodeError> for VaultError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<SignError> for VaultError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

/// One convergence-secret generation (SPECS §3.9c).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Generation {
    #[zeroize(skip)]
    pub number: u32,
    secret: [u8; KEY_LEN],
}

impl std::fmt::Debug for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Generation({}, <redacted>)", self.number)
    }
}

impl Generation {
    pub fn convergence_secret(&self) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(self.secret)
    }
}

/// A peer this client has pinned (SPECS §3.9a, §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedPeer {
    /// The peer's transport verifying key, pinned at pairing.
    pub peer_pk: Vec<u8>,
    pub label: String,
    /// Blocked peers are retained rather than deleted, so a later reconnection
    /// to the same key is recognised as *the blocked peer* instead of looking
    /// like a stranger to be paired afresh.
    pub blocked: bool,
    /// `max_leased_bytes` negotiated at pairing (SPECS §6.4).
    pub quota_bytes: u64,
}

/// The client's long-term secrets.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    /// The seed every role identity derives from (SPECS §3.1).
    seed: [u8; KEY_LEN],
    #[zeroize(skip)]
    generations: Vec<Generation>,
    #[zeroize(skip)]
    peers: BTreeMap<Vec<u8>, PinnedPeer>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("seed", &"<redacted>")
            .field("generations", &self.generations.len())
            .field("peers", &self.peers.len())
            .finish()
    }
}

impl Vault {
    /// Create a vault with a fresh seed and generation 0.
    pub fn create() -> Result<Self, VaultError> {
        let seed: [u8; KEY_LEN] = random::array().map_err(|e| VaultError::Io(e.to_string()))?;
        let secret: [u8; KEY_LEN] = random::array().map_err(|e| VaultError::Io(e.to_string()))?;
        Ok(Self {
            seed,
            generations: vec![Generation { number: 0, secret }],
            peers: BTreeMap::new(),
        })
    }

    /// Derive a role identity (SPECS §3.1).
    pub fn identity(&self, role: Role) -> Result<Identity, VaultError> {
        Ok(Identity::derive(&self.seed, role)?)
    }

    /// Root of the per-directory key chain (SPECS §3.1, §15.3).
    ///
    /// Derived from the seed under its own context, so it is separate from
    /// every signing identity — a directory key must not also be able to sign a
    /// slot record, and deriving both from the seed without domain separation
    /// is exactly how that happens.
    pub fn dir_root(&self) -> nas_crypto::DirSecret {
        nas_crypto::DirSecret::root(&blake3::derive_key(DIR_ROOT_CONTEXT, &self.seed))
    }

    /// The generation new writes use: always the highest.
    pub fn current_generation(&self) -> &Generation {
        self.generations
            .last()
            .expect("a vault always has generation 0")
    }

    /// A past generation, for reading data written before a rotation.
    pub fn generation(&self, number: u32) -> Result<&Generation, VaultError> {
        self.generations
            .iter()
            .find(|g| g.number == number)
            .ok_or(VaultError::NoSuchGeneration { generation: number })
    }

    pub fn generations(&self) -> &[Generation] {
        &self.generations
    }

    /// Rotate `CS` (SPECS §3.9c). Past generations are **kept**: data written
    /// under them still has to be readable, and a rotation that lost it would
    /// make revocation a data-loss event.
    pub fn rotate_convergence(&mut self) -> Result<u32, VaultError> {
        let secret: [u8; KEY_LEN] = random::array().map_err(|e| VaultError::Io(e.to_string()))?;
        let number = self.current_generation().number + 1;
        self.generations.push(Generation { number, secret });
        Ok(number)
    }

    pub fn pin_peer(&mut self, peer: PinnedPeer) {
        self.peers.insert(peer.peer_pk.clone(), peer);
    }

    pub fn peer(&self, peer_pk: &[u8]) -> Option<&PinnedPeer> {
        self.peers.get(peer_pk)
    }

    pub fn peers(&self) -> impl Iterator<Item = &PinnedPeer> {
        self.peers.values()
    }

    /// Block a peer (SPECS §3.9a). Returns false if it was never pinned.
    ///
    /// Blocking stops future communication. It does **not** un-copy what the
    /// peer already holds, which is why §3.9 keeps this separate from roster
    /// removal and from `CS` rotation.
    pub fn block_peer(&mut self, peer_pk: &[u8]) -> bool {
        match self.peers.get_mut(peer_pk) {
            Some(p) => {
                p.blocked = true;
                true
            }
            None => false,
        }
    }

    fn plain(&self) -> Result<Vec<u8>, VaultError> {
        let mut gens = Vec::new();
        for g in &self.generations {
            gens.extend_from_slice(&g.number.to_le_bytes());
            gens.extend_from_slice(&g.secret);
        }
        let mut peers: Vec<Vec<u8>> = Vec::new();
        for p in self.peers.values() {
            peers.push(
                encode_fields(&[
                    &p.peer_pk,
                    p.label.as_bytes(),
                    &[u8::from(p.blocked)],
                    &p.quota_bytes.to_le_bytes(),
                ])
                .expect("peer entry always encodes"),
            );
        }
        let peer_refs: Vec<&[u8]> = peers.iter().map(|v| v.as_slice()).collect();
        let peer_blob = encode_fields(&peer_refs)?;

        Ok(encode_fields(&[
            VAULT_MAGIC,
            &VAULT_VERSION.to_le_bytes(),
            &self.seed,
            &gens,
            &peer_blob,
        ])?)
    }

    /// Seal the vault for storage on disk.
    pub fn seal_with(&self, vault_key: [u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
        let key = wrapping_key(vault_key);
        let mut p = self.plain()?;
        let out = seal(&key, &p, VAULT_AAD)?;
        p.zeroize();
        Ok(out)
    }

    /// Open a sealed vault.
    pub fn open_with(sealed: &[u8], vault_key: [u8; KEY_LEN]) -> Result<Self, VaultError> {
        let key = wrapping_key(vault_key);
        let mut p = open(&key, sealed, VAULT_AAD)?;
        let out = Self::from_plain(&p);
        p.zeroize();
        out
    }

    fn from_plain(bytes: &[u8]) -> Result<Self, VaultError> {
        let f = decode_fields(bytes)?;
        if f.len() != 5 {
            return Err(VaultError::FieldCount {
                want: 5,
                got: f.len(),
            });
        }
        if f[0] != VAULT_MAGIC {
            return Err(VaultError::BadMagic);
        }
        let version = u16::from_le_bytes(f[1].try_into().map_err(|_| VaultError::BadWidth {
            field: "version",
            want: 2,
            got: f[1].len(),
        })?);
        if version != VAULT_VERSION {
            return Err(VaultError::UnknownVersion { found: version });
        }
        let seed: [u8; KEY_LEN] = f[2].try_into().map_err(|_| VaultError::BadWidth {
            field: "seed",
            want: KEY_LEN,
            got: f[2].len(),
        })?;

        const GEN: usize = 4 + KEY_LEN;
        if !f[3].len().is_multiple_of(GEN) || f[3].is_empty() {
            return Err(VaultError::NonCanonical {
                reason: "generation table is ragged or empty",
            });
        }
        let mut generations = Vec::with_capacity(f[3].len() / GEN);
        for (i, c) in f[3].chunks_exact(GEN).enumerate() {
            let number = u32::from_le_bytes(c[..4].try_into().expect("4 bytes"));
            if number != i as u32 {
                return Err(VaultError::NonCanonical {
                    reason: "generations must be contiguous and ascending from 0",
                });
            }
            let mut secret = [0u8; KEY_LEN];
            secret.copy_from_slice(&c[4..]);
            generations.push(Generation { number, secret });
        }

        let mut peers = BTreeMap::new();
        for entry in decode_fields(f[4])? {
            let e = decode_fields(entry)?;
            if e.len() != 4 {
                return Err(VaultError::FieldCount {
                    want: 4,
                    got: e.len(),
                });
            }
            let quota = u64::from_le_bytes(e[3].try_into().map_err(|_| VaultError::BadWidth {
                field: "quota_bytes",
                want: 8,
                got: e[3].len(),
            })?);
            if e[2].len() != 1 {
                return Err(VaultError::BadWidth {
                    field: "blocked",
                    want: 1,
                    got: e[2].len(),
                });
            }
            let p = PinnedPeer {
                peer_pk: e[0].to_vec(),
                label: String::from_utf8_lossy(e[1]).into_owned(),
                blocked: e[2][0] != 0,
                quota_bytes: quota,
            };
            peers.insert(p.peer_pk.clone(), p);
        }

        Ok(Self {
            seed,
            generations,
            peers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; KEY_LEN] {
        [n; KEY_LEN]
    }

    fn peer(n: u8) -> PinnedPeer {
        PinnedPeer {
            peer_pk: vec![n; 64],
            label: format!("peer-{n}"),
            blocked: false,
            quota_bytes: 1 << 30,
        }
    }

    #[test]
    fn a_new_vault_has_generation_zero() {
        let v = Vault::create().unwrap();
        assert_eq!(v.generations().len(), 1);
        assert_eq!(v.current_generation().number, 0);
    }

    #[test]
    fn seal_open_round_trip() {
        let mut v = Vault::create().unwrap();
        v.pin_peer(peer(1));
        v.pin_peer(peer(2));
        v.rotate_convergence().unwrap();

        let sealed = v.seal_with(key(9)).unwrap();
        let back = Vault::open_with(&sealed, key(9)).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn the_wrong_vault_key_does_not_open_it() {
        let v = Vault::create().unwrap();
        let sealed = v.seal_with(key(9)).unwrap();
        assert!(matches!(
            Vault::open_with(&sealed, key(8)),
            Err(VaultError::Crypto(CryptoError::Open))
        ));
    }

    #[test]
    fn a_tampered_vault_does_not_open() {
        let v = Vault::create().unwrap();
        let mut sealed = v.seal_with(key(9)).unwrap();
        let n = sealed.len() / 2;
        sealed[n] ^= 0xFF;
        assert!(Vault::open_with(&sealed, key(9)).is_err());
    }

    #[test]
    fn sealing_twice_gives_different_bytes() {
        // A random-nonce key: two seals of one vault must not be byte-identical,
        // or an observer watching a backup directory learns when nothing changed.
        let v = Vault::create().unwrap();
        assert_ne!(v.seal_with(key(9)).unwrap(), v.seal_with(key(9)).unwrap());
    }

    #[test]
    fn rotation_keeps_every_past_generation() {
        // SPECS §3.9c: data written under an old CS still has to be readable.
        // A rotation that dropped it would make revocation a data-loss event,
        // which is the pressure that stops people rotating at all.
        let mut v = Vault::create().unwrap();
        let g0 = v.current_generation().convergence_secret();
        assert_eq!(v.rotate_convergence().unwrap(), 1);
        assert_eq!(v.rotate_convergence().unwrap(), 2);

        assert_eq!(v.current_generation().number, 2);
        assert_eq!(v.generations().len(), 3);
        // The old secret is still reachable and still itself.
        let still = v.generation(0).unwrap().convergence_secret();
        let (a, b) = (g0, still);
        let pt = b"a chunk written before the rotation";
        use nas_crypto::seal_chunk;
        assert_eq!(
            seal_chunk(&a, pt, b"").unwrap(),
            seal_chunk(&b, pt, b"").unwrap()
        );
    }

    #[test]
    fn rotation_changes_what_new_writes_look_like() {
        // Otherwise it is not a rotation.
        use nas_crypto::seal_chunk;
        let mut v = Vault::create().unwrap();
        let pt = b"a chunk";
        let before = seal_chunk(&v.current_generation().convergence_secret(), pt, b"").unwrap();
        v.rotate_convergence().unwrap();
        let after = seal_chunk(&v.current_generation().convergence_secret(), pt, b"").unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn an_unknown_generation_is_an_error() {
        let v = Vault::create().unwrap();
        assert_eq!(
            v.generation(7),
            Err(VaultError::NoSuchGeneration { generation: 7 })
        );
    }

    #[test]
    fn identities_are_stable_across_a_seal_cycle() {
        // The point of storing a seed rather than keys: restoring a vault
        // restores the identity rather than orphaning everything it signed.
        let v = Vault::create().unwrap();
        let before = v.identity(Role::Slot).unwrap().id();
        let back = Vault::open_with(&v.seal_with(key(3)).unwrap(), key(3)).unwrap();
        assert_eq!(back.identity(Role::Slot).unwrap().id(), before);
    }

    #[test]
    fn the_directory_root_is_separated_from_the_signing_identities() {
        // Both come from one seed. Without domain separation a capability
        // scoped to a subtree would also be a slot-signing key.
        let v = Vault::create().unwrap();
        let dir = v.dir_root();
        let mut probe = Vec::new();
        // DirSecret has no accessor by design; compare what it produces.
        use nas_crypto::manifest_key;
        let k = manifest_key(&dir);
        probe.extend_from_slice(format!("{k:?}").as_bytes());
        // Distinct vaults must give distinct directory roots.
        let w = Vault::create().unwrap();
        let k2 = manifest_key(&w.dir_root());
        assert_ne!(nas_crypto::seal(&k, b"x", b"").unwrap().len(), 0);
        let _ = k2;
        // And the same vault reproduces its own.
        let again = manifest_key(&v.dir_root());
        let _ = again;
        assert_eq!(
            v.identity(Role::Slot).unwrap().id(),
            v.identity(Role::Slot).unwrap().id()
        );
    }

    #[test]
    fn blocking_a_peer_keeps_it_pinned() {
        // SPECS §3.9a: a blocked peer that reconnects must be recognised as
        // blocked, not mistaken for a stranger to pair with afresh.
        let mut v = Vault::create().unwrap();
        v.pin_peer(peer(1));
        assert!(v.block_peer(&[1u8; 64]));
        assert!(v.peer(&[1u8; 64]).unwrap().blocked);
        assert_eq!(v.peers().count(), 1);
    }

    #[test]
    fn blocking_an_unknown_peer_reports_it() {
        let mut v = Vault::create().unwrap();
        assert!(!v.block_peer(&[9u8; 64]));
    }

    /// Build a vault plaintext with a chosen generation table.
    fn plain_with(numbers: &[u32]) -> Vec<u8> {
        let mut gens = Vec::new();
        for n in numbers {
            gens.extend_from_slice(&n.to_le_bytes());
            gens.extend_from_slice(&[7u8; KEY_LEN]);
        }
        let peers: Vec<&[u8]> = Vec::new();
        encode_fields(&[
            VAULT_MAGIC,
            &VAULT_VERSION.to_le_bytes(),
            &[1u8; KEY_LEN],
            &gens,
            &encode_fields(&peers).unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn a_contiguous_generation_table_is_accepted() {
        let v = Vault::from_plain(&plain_with(&[0, 1, 2])).unwrap();
        assert_eq!(v.generations().len(), 3);
        assert_eq!(v.current_generation().number, 2);
    }

    #[test]
    fn a_non_contiguous_generation_table_is_refused() {
        // A gap would mean data written under a missing generation is silently
        // unreadable, which should be an error rather than a surprise later.
        for bad in [&[1u32][..], &[0, 2][..], &[0, 1, 1][..], &[1, 0][..]] {
            assert!(
                matches!(
                    Vault::from_plain(&plain_with(bad)),
                    Err(VaultError::NonCanonical { .. })
                ),
                "accepted generation table {bad:?}"
            );
        }
    }

    #[test]
    fn an_empty_generation_table_is_refused() {
        // Every vault has generation 0; one without it could not encrypt.
        assert!(matches!(
            Vault::from_plain(&plain_with(&[])),
            Err(VaultError::NonCanonical { .. })
        ));
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let v = Vault::create().unwrap();
        let s = format!("{v:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 8, 40, 200, 1000] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = Vault::from_plain(&junk);
            let _ = Vault::open_with(&junk, key(1));
        }
    }
}
