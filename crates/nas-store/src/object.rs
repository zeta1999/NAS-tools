//! The write and read pipelines (SPECS §4).
//!
//! ```text
//! write:  plaintext → CDC → pad → ck = keyed_hash(CS, padded) → seal → blob
//! read:   blob → verify addr → open(ck) → unpad → check pt_hash → plaintext
//! ```
//!
//! # Why the chunk AAD is a constant
//!
//! It is tempting to bind a chunk to its file or its offset by putting them in
//! the associated data. Doing so would end deduplication: the same chunk in two
//! files, or at two offsets, would seal to different ciphertext and be stored
//! twice. Convergent encryption *requires* that everything fed to the AEAD be a
//! function of the chunk content alone, so the AAD is a fixed domain string —
//! present for separation from other ciphertext in the system, and carrying no
//! per-object information at all.
//!
//! The binding that a per-chunk AAD would have provided is done instead by the
//! manifest, which lists the chunks in order and is itself authenticated.
//!
//! # Two at-rest shapes, one pipeline
//!
//! [`Sealer`] is the only place the confidentiality modes differ. `e2ee` and
//! `passphrase` seal each chunk convergently and address the **ciphertext**;
//! `transit-only` stores plaintext and addresses `BLAKE3(tenant_salt ‖ plaintext)`.
//!
//! The salt is why `transit-only` is not simply "no encryption". Revision 4 of
//! the spec used bare `BLAKE3(plaintext)` and called global dedup harmless
//! because there is no confidentiality claim to leak — which considered only
//! the peer as a reader. On a **shared** peer it hands every co-tenant a
//! confirmation oracle: upload a candidate file into your own namespace, watch
//! for the dedup skip, and learn that somebody else on this box holds it. "Not
//! secret from my own NAS" is a very different statement from "confirmable by
//! anyone who rents space beside me". A per-tenant salt restores tenant-scoped
//! dedup and removes the oracle. It is not secret; it only has to be unshared.
//!
//! # Memory
//!
//! Both directions are streaming. Peak resident bytes are bounded by the
//! chunker window (`2 × max`, 512 KiB by default) plus one chunk in flight,
//! independent of file size.

use crate::blobs::{BlobStore, StoreError};
use crate::chunker::{Chunker, ChunkerConfig, ConfigError};
use crate::manifest::{ChunkRef, Kind, Manifest, ManifestError};
use crate::padding::{self, PadError};
use nas_core::{Addr, KeyScheme, PaddingProfile};
use nas_crypto::{
    chunk_key_from_stored, open_chunk, seal_chunk, ConvergenceSecret, CryptoError, KEY_LEN,
};
use std::io::{self, Read, Write};

/// Domain separation only. Must not vary per object — see the module docs.
pub const CHUNK_AAD: &[u8] = b"nas-tools/aad/chunk/v1";

#[derive(Debug)]
pub enum ObjectError {
    Io(io::Error),
    Pad(PadError),
    Crypto(CryptoError),
    Store(StoreError),
    Manifest(ManifestError),
    Config(ConfigError),
    /// The chunker can emit chunks the padding profile cannot frame. Caught
    /// when the writer is constructed, not on whichever chunk happens to be
    /// large enough to expose it.
    ProfileMismatch {
        chunk_max: usize,
        pad_max: usize,
    },
    /// Decryption succeeded and the plaintext still is not what the manifest
    /// says it should be. The AEAD tag cannot catch this: it proves the
    /// ciphertext is intact, not that the manifest points at the right chunk.
    PlaintextMismatch {
        addr: Addr,
    },
    /// A chunk decrypted to a different length than the manifest recorded.
    LengthMismatch {
        addr: Addr,
        want: u32,
        got: usize,
    },
    /// A manifest cannot carry chunk keys under a scheme that does not produce
    /// them this way.
    UnsupportedKeyScheme {
        scheme: KeyScheme,
    },
    /// The writer's salt and the store's disagree. Blobs written this way would
    /// be unverifiable by any reader, and the failure would otherwise be silent.
    AddressingMismatch {
        expected: Addr,
        got: Addr,
    },
}

impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Pad(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Manifest(e) => write!(f, "{e}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::ProfileMismatch { chunk_max, pad_max } => write!(
                f,
                "chunker may emit {chunk_max} B chunks but the padding profile tops out at {pad_max} B"
            ),
            Self::PlaintextMismatch { addr } => {
                write!(f, "chunk {} decrypted to the wrong plaintext", addr.to_hex())
            }
            Self::LengthMismatch { addr, want, got } => write!(
                f,
                "chunk {} decrypted to {got} B, manifest says {want} B",
                addr.to_hex()
            ),
            Self::UnsupportedKeyScheme { scheme } => {
                write!(f, "key scheme {scheme:?} is not implemented")
            }
            Self::AddressingMismatch { expected, got } => write!(
                f,
                "writer expected address {} but the store filed {}: salts disagree",
                expected.to_hex(),
                got.to_hex()
            ),
        }
    }
}
impl std::error::Error for ObjectError {}

macro_rules! from_err {
    ($($t:ty => $v:ident),* $(,)?) => {$(
        impl From<$t> for ObjectError { fn from(e: $t) -> Self { Self::$v(e) } }
    )*};
}
from_err!(io::Error => Io, PadError => Pad, CryptoError => Crypto,
          StoreError => Store, ManifestError => Manifest, ConfigError => Config);

/// How chunks are protected at rest, and therefore how they are addressed.
///
/// Not a boolean: the two arms carry different material and produce different
/// addresses, and a `bool` would leave the salt and the secret to be threaded
/// separately and mismatched.
#[derive(Clone, Copy)]
pub enum Sealer<'a> {
    /// `e2ee` / `passphrase`: convergent encryption, `addr = BLAKE3(ciphertext)`.
    Convergent(&'a ConvergenceSecret),
    /// `transit-only`: plaintext at rest, `addr = BLAKE3(tenant_salt ‖ plaintext)`.
    Plaintext { tenant_salt: &'a [u8] },
}

impl Sealer<'_> {
    pub fn key_scheme(&self) -> KeyScheme {
        match self {
            Self::Convergent(_) => KeyScheme::Convergent,
            Self::Plaintext { .. } => KeyScheme::Plaintext,
        }
    }

    /// Whether the bytes written to the store are readable.
    pub fn stores_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext { .. })
    }
}

/// `BLAKE3(len(salt) ‖ salt ‖ plaintext)` — the `transit-only` address.
///
/// Length-prefixed so two tenants whose salts differ only by a boundary cannot
/// collide, which would put them back in one dedup pool and reinstate the
/// oracle the salt exists to remove.
pub fn salted_addr(tenant_salt: &[u8], plaintext: &[u8]) -> Addr {
    let mut h = blake3::Hasher::new();
    h.update(&(tenant_salt.len() as u64).to_le_bytes());
    h.update(tenant_salt);
    h.update(plaintext);
    Addr::from_bytes(*h.finalize().as_bytes())
}

/// Turns plaintext into blobs plus a manifest.
pub struct ObjectWriter<'a> {
    store: &'a BlobStore,
    sealer: Sealer<'a>,
    chunker: Chunker,
    profile: PaddingProfile,
}

impl<'a> ObjectWriter<'a> {
    /// Build a writer, refusing a chunker and profile that cannot agree.
    pub fn new(
        store: &'a BlobStore,
        sealer: Sealer<'a>,
        profile: PaddingProfile,
        cfg: ChunkerConfig,
    ) -> Result<Self, ObjectError> {
        if let Some(pad_max) = padding::max_plaintext(profile) {
            if cfg.max > pad_max {
                return Err(ObjectError::ProfileMismatch {
                    chunk_max: cfg.max,
                    pad_max,
                });
            }
        }
        Ok(Self {
            store,
            sealer,
            chunker: Chunker::new(cfg)?,
            profile,
        })
    }

    /// A writer with a chunker configuration derived from the profile.
    pub fn with_defaults(
        store: &'a BlobStore,
        sealer: Sealer<'a>,
        profile: PaddingProfile,
    ) -> Result<Self, ObjectError> {
        Self::new(
            store,
            sealer,
            profile,
            ChunkerConfig::for_profile(profile, ChunkerConfig::default()),
        )
    }

    /// Convenience for the encrypted modes, which are the common case.
    pub fn convergent(
        store: &'a BlobStore,
        cs: &'a ConvergenceSecret,
        profile: PaddingProfile,
    ) -> Result<Self, ObjectError> {
        Self::with_defaults(store, Sealer::Convergent(cs), profile)
    }

    /// Chunk, pad, encrypt and store `reader`, returning its manifest.
    pub fn write<R: Read>(&self, kind: Kind, reader: R) -> Result<Manifest, ObjectError> {
        let mut m = Manifest::new(kind, self.sealer.key_scheme(), self.profile);
        for chunk in self.chunker.stream(reader) {
            let plain = chunk?;
            let padded = padding::pad(self.profile, &plain)?;

            let (addr, ck) = match self.sealer {
                Sealer::Convergent(cs) => {
                    // §4.2.1: keyed over the PADDED bytes. §3.1's table says
                    // "plaintext chunk", which is the same thing when the
                    // profile is `none` and is the looser of the two.
                    //
                    // `seal_chunk` derives and seals in one step on purpose:
                    // the derived nonce is a function of the key, so sealing
                    // any *other* plaintext under that key would reuse the
                    // nonce. Deriving here and sealing there made that a
                    // convention two call sites had to keep; it is now one
                    // operation that cannot desynchronise.
                    let (sealed, ck) = seal_chunk(cs, &padded, CHUNK_AAD)?;
                    (self.store.put(&sealed)?, ck)
                }
                Sealer::Plaintext { tenant_salt } => {
                    // The store knows its own addressing scheme, so `put`
                    // already salts. Checking the two agree here would be
                    // cheap, but disagreeing is the interesting case: a writer
                    // salting one way and a store the other would produce blobs
                    // no reader could verify, silently.
                    let expected = salted_addr(tenant_salt, &padded);
                    let addr = self.store.put(&padded)?;
                    if addr != expected {
                        return Err(ObjectError::AddressingMismatch {
                            expected,
                            got: addr,
                        });
                    }
                    (addr, [0u8; KEY_LEN])
                }
            };

            m.chunks.push(ChunkRef {
                addr,
                ck,
                pt_hash: *blake3::hash(&plain).as_bytes(),
                len: u32::try_from(plain.len()).expect("chunks are bounded by cfg.max"),
            });
            m.size += plain.len() as u64;
        }
        m.validate()?;
        Ok(m)
    }
}

/// Reconstruct an object's plaintext from its manifest.
///
/// Every chunk is checked three ways: the blob store verifies the address, the
/// AEAD verifies the ciphertext, and `pt_hash` verifies that the manifest
/// pointed at the chunk it claimed to. The third is not redundant — the first
/// two would both pass if a manifest were rewritten to reference a *different*
/// but perfectly valid chunk.
pub fn read_object<W: Write>(
    store: &BlobStore,
    m: &Manifest,
    out: &mut W,
) -> Result<u64, ObjectError> {
    if m.key_scheme == KeyScheme::IndexedRandom {
        return Err(ObjectError::UnsupportedKeyScheme {
            scheme: m.key_scheme,
        });
    }
    m.validate()?;
    let mut written = 0u64;
    for c in &m.chunks {
        let stored = store.get(&c.addr)?;
        let opened;
        let padded: &[u8] = match m.key_scheme {
            KeyScheme::Convergent => {
                let key = chunk_key_from_stored(c.ck);
                opened = open_chunk(&key, &stored, CHUNK_AAD)?;
                &opened
            }
            // Nothing to decrypt. `pt_hash` below is then the whole integrity
            // story -- there is no AEAD tag to fall back on, which is exactly
            // why the manifest stores it.
            KeyScheme::Plaintext => &stored,
            KeyScheme::IndexedRandom => unreachable!("rejected above"),
        };
        let plain = padding::unpad(m.padding_profile, padded)?;

        if plain.len() != c.len as usize {
            return Err(ObjectError::LengthMismatch {
                addr: c.addr,
                want: c.len,
                got: plain.len(),
            });
        }
        if blake3::hash(plain).as_bytes() != &c.pt_hash {
            return Err(ObjectError::PlaintextMismatch { addr: c.addr });
        }
        out.write_all(plain)?;
        written += plain.len() as u64;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-obj-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn corpus(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        blake3::Hasher::new_keyed(&[seed; 32])
            .finalize_xof()
            .fill(&mut out);
        out
    }

    fn cs() -> ConvergenceSecret {
        ConvergenceSecret::from_bytes([42u8; KEY_LEN])
    }

    fn roundtrip(profile: PaddingProfile, data: &[u8], tag: &str) {
        let s = Scratch::new(tag);
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let w = ObjectWriter::convergent(&st, &c, profile).unwrap();
        let m = w.write(Kind::File, data).unwrap();
        assert_eq!(m.size, data.len() as u64, "{tag}: size");
        assert_eq!(m.padding_profile, profile);

        let mut got = Vec::new();
        let n = read_object(&st, &m, &mut got).unwrap();
        assert_eq!(n, data.len() as u64, "{tag}: bytes read");
        assert_eq!(got, data, "{tag}: content");
    }

    #[test]
    fn roundtrip_every_profile() {
        let data = corpus(3 << 20, 1);
        roundtrip(PaddingProfile::None, &data, "none");
        roundtrip(PaddingProfile::Classes, &data, "classes");
        roundtrip(PaddingProfile::Fixed, &data, "fixed");
    }

    #[test]
    fn roundtrip_edge_sizes() {
        for (i, n) in [0usize, 1, 4095, 16 << 10, (64 << 10) + 1, 300 << 10]
            .iter()
            .enumerate()
        {
            roundtrip(
                PaddingProfile::None,
                &corpus(*n, 2),
                &format!("edge-none-{i}"),
            );
            roundtrip(
                PaddingProfile::Classes,
                &corpus(*n, 2),
                &format!("edge-cls-{i}"),
            );
        }
    }

    #[test]
    fn the_plaintext_never_reaches_the_disk() {
        // SPECS §1: the peer holds ciphertext. If a recognisable run of
        // plaintext appears in any blob, the pipeline is broken.
        let s = Scratch::new("noplain");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let needle = b"SECRET-CANARY-STRING-0123456789";
        let mut data = corpus(200 << 10, 3);
        data.splice(1000..1000 + needle.len(), needle.iter().copied());

        let w = ObjectWriter::convergent(&st, &c, PaddingProfile::None).unwrap();
        w.write(Kind::File, &data[..]).unwrap();

        for a in st.addrs().unwrap() {
            let ct = st.get(&a).unwrap();
            assert!(
                !ct.windows(needle.len()).any(|w| w == needle),
                "plaintext canary found in blob {}",
                a.to_hex()
            );
        }
    }

    #[test]
    fn identical_files_dedup_completely() {
        let s = Scratch::new("dedup");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let data = corpus(2 << 20, 4);
        let w = ObjectWriter::convergent(&st, &c, PaddingProfile::None).unwrap();

        let a = w.write(Kind::File, &data[..]).unwrap();
        let before = st.addrs().unwrap().len();
        let b = w.write(Kind::File, &data[..]).unwrap();
        assert_eq!(
            st.addrs().unwrap().len(),
            before,
            "a second copy stored new blobs"
        );
        assert_eq!(a.chunks, b.chunks);
    }

    #[test]
    fn an_edited_file_reuses_most_of_its_chunks() {
        // CDC plus convergent encryption: the point of both.
        let s = Scratch::new("incremental");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let w = ObjectWriter::convergent(&st, &c, PaddingProfile::None).unwrap();

        let base = corpus(2 << 20, 5);
        let m1 = w.write(Kind::File, &base[..]).unwrap();
        let stored_after_first = st.addrs().unwrap().len();

        let mut edited = base.clone();
        edited.splice(500..500, *b"a few inserted bytes");
        let m2 = w.write(Kind::File, &edited[..]).unwrap();

        let new_blobs = st.addrs().unwrap().len() - stored_after_first;
        assert!(
            new_blobs * 5 <= m1.chunks.len(),
            "{new_blobs} new blobs for a 20-byte edit across {} chunks",
            m1.chunks.len()
        );

        let mut got = Vec::new();
        read_object(&st, &m2, &mut got).unwrap();
        assert_eq!(got, edited);
    }

    #[test]
    fn a_different_convergence_secret_shares_nothing() {
        // SPECS §3.2: without CS an outsider cannot compute the ciphertext of
        // a candidate file, which is what defeats confirmation-of-file.
        let s = Scratch::new("cs");
        let st = BlobStore::open(&s.0).unwrap();
        let data = corpus(512 << 10, 6);
        let (a, b) = (cs(), ConvergenceSecret::from_bytes([43u8; KEY_LEN]));

        let ma = ObjectWriter::convergent(&st, &a, PaddingProfile::None)
            .unwrap()
            .write(Kind::File, &data[..])
            .unwrap();
        let mb = ObjectWriter::convergent(&st, &b, PaddingProfile::None)
            .unwrap()
            .write(Kind::File, &data[..])
            .unwrap();

        assert_eq!(
            ma.chunks.len(),
            mb.chunks.len(),
            "same cut points either way"
        );
        for (x, y) in ma.chunks.iter().zip(&mb.chunks) {
            assert_ne!(
                x.addr, y.addr,
                "a tenant's ciphertext was guessable from another's"
            );
        }
    }

    #[test]
    fn a_manifest_repointed_at_a_valid_but_wrong_chunk_is_caught() {
        // Both the address check and the AEAD tag pass here. Only pt_hash
        // notices, which is why it is stored.
        let s = Scratch::new("swap");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let w = ObjectWriter::convergent(&st, &c, PaddingProfile::None).unwrap();
        let mut m = w.write(Kind::File, &corpus(1 << 20, 7)[..]).unwrap();
        assert!(m.chunks.len() >= 2);

        let victim = m.chunks[1].clone();
        m.chunks[0] = ChunkRef {
            len: m.chunks[0].len,
            ..victim
        };
        m.size = m.chunk_bytes();

        match read_object(&st, &m, &mut Vec::new()) {
            Err(ObjectError::LengthMismatch { .. })
            | Err(ObjectError::PlaintextMismatch { .. }) => {}
            other => panic!("chunk substitution not detected: {other:?}"),
        }
    }

    #[test]
    fn a_tampered_blob_fails_the_read() {
        let s = Scratch::new("tamper");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let w = ObjectWriter::convergent(&st, &c, PaddingProfile::None).unwrap();
        let m = w.write(Kind::File, &corpus(100 << 10, 8)[..]).unwrap();

        let p = st.path(&m.chunks[0].addr);
        let mut ct = fs::read(&p).unwrap();
        ct[0] ^= 0xFF;
        fs::write(&p, &ct).unwrap();

        match read_object(&st, &m, &mut Vec::new()) {
            Err(ObjectError::Store(StoreError::Corrupt { .. })) => {}
            other => panic!("tampering not detected: {other:?}"),
        }
    }

    #[test]
    fn a_mismatched_profile_and_chunker_are_refused_up_front() {
        // Not on whichever chunk first happens to be 256 KiB.
        let s = Scratch::new("mismatch");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        match ObjectWriter::new(
            &st,
            Sealer::Convergent(&c),
            PaddingProfile::Classes,
            ChunkerConfig::default(),
        ) {
            Err(ObjectError::ProfileMismatch { .. }) => {}
            other => panic!("mismatch accepted: {:?}", other.map(|_| "writer")),
        }
    }

    #[test]
    fn padded_writes_cost_storage_and_the_cost_is_visible() {
        // SPECS §4.2.1 and §12: the padding premium must be measured before
        // anyone opts in, so the measurement has to be reachable from a test.
        let s = Scratch::new("overhead");
        let st = BlobStore::open(&s.0).unwrap();
        let c = cs();
        let data = corpus(4 << 20, 9);

        let mut bytes = std::collections::BTreeMap::new();
        for profile in [PaddingProfile::None, PaddingProfile::Classes] {
            let sub = s.0.join(format!("{profile:?}"));
            let st2 = BlobStore::open(&sub).unwrap();
            ObjectWriter::convergent(&st2, &c, profile)
                .unwrap()
                .write(Kind::File, &data[..])
                .unwrap();
            let total: u64 = st2
                .addrs()
                .unwrap()
                .iter()
                .map(|a| fs::metadata(st2.path(a)).unwrap().len())
                .sum();
            bytes.insert(format!("{profile:?}"), total);
        }
        drop(st);
        let none = bytes["None"];
        let classes = bytes["Classes"];
        assert!(
            classes > none,
            "padding must cost something or it is not padding"
        );
        // Loose bound: the assertion is that it is measured, not that it hits
        // a number. MANUAL-TESTING.md carries the observed figure.
        assert!(
            classes < none * 3,
            "padding overhead {:.1}% is implausible",
            (classes as f64 / none as f64 - 1.0) * 100.0
        );
    }
}
