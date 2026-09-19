//! Bucket manifests — the S3 key → object map (SPECS §7.1).
//!
//! One slot per bucket. Per-key slots would cost ~3.3 KB of ML-DSA per object
//! (§3.8); instead the bucket keeps one slot and the manifest versions each
//! key:
//!
//! ```text
//! key → { chunks, lamport: u64, writer_id, deleted: bool }
//! ```
//!
//! Merge on a CAS retry is last-writer-wins by `(lamport, writer_id)`.
//! Concurrent PUTs of *different* keys both survive; concurrent PUTs of the
//! *same* key resolve LWW, which is genuine S3 behaviour. Tombstones stay
//! until a later compaction — a delete that vanished would be undone by a
//! stale writer.

use crate::blobs::{BlobStore, StoreError};
use crate::manifest::{Manifest, ManifestError};
use crate::object::{ObjectError, Sealer};
use nas_core::{decode_fields, encode_fields, Addr, DecodeError};
use nas_crypto::{manifest_key, open, seal, DirSecret};
use std::collections::BTreeMap;

/// Distinguishes a bucket manifest from a directory one (`NASD`) or a file
/// one (`NASM`). A decoder that accepted the wrong magic would treat a tree
/// as a key map.
pub const BUCKET_MAGIC: &[u8; 4] = b"NASB";
pub const BUCKET_AAD: &[u8] = b"nas-tools/aad/bucket/v1";
const VERSION: u8 = 1;
const WRITER_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyObject {
    pub lamport: u64,
    pub writer_id: [u8; WRITER_LEN],
    /// `None` is a tombstone. A live key always carries its chunk table.
    pub object: Option<Manifest>,
}

impl KeyObject {
    pub fn deleted(&self) -> bool {
        self.object.is_none()
    }

    /// SPECS §7.1: LWW ordered by `(lamport, writer_id)`.
    fn beats(&self, other: &Self) -> bool {
        (self.lamport, self.writer_id) > (other.lamport, other.writer_id)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BucketManifest {
    /// Sorted by key, so an unchanged bucket encodes identically.
    pub entries: BTreeMap<Vec<u8>, KeyObject>,
}

#[derive(Debug)]
pub enum BucketError {
    Object(ObjectError),
    Store(StoreError),
    Manifest(ManifestError),
    Crypto(nas_crypto::CryptoError),
    Decode(DecodeError),
    BadMagic,
    BadVersion {
        value: u8,
    },
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    RaggedEntries {
        fields: usize,
    },
    BadKey {
        reason: &'static str,
    },
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for BucketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Manifest(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "encoding: {e:?}"),
            Self::BadMagic => write!(f, "not a bucket manifest"),
            Self::BadVersion { value } => write!(f, "bucket manifest version {value}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "bucket {field} is {got} B, want {want} B")
            }
            Self::RaggedEntries { fields } => {
                write!(f, "{fields} bucket fields is not a multiple of 5")
            }
            Self::BadKey { reason } => write!(f, "refusing bucket key: {reason}"),
            Self::NonCanonical { reason } => write!(f, "non-canonical bucket: {reason}"),
        }
    }
}
impl std::error::Error for BucketError {}

macro_rules! from_err {
    ($($t:ty => $v:ident),* $(,)?) => {$(
        impl From<$t> for BucketError { fn from(e: $t) -> Self { Self::$v(e) } }
    )*};
}
from_err!(
    ObjectError => Object,
    StoreError => Store,
    ManifestError => Manifest,
    nas_crypto::CryptoError => Crypto,
    DecodeError => Decode,
);

fn safe_key(key: &[u8]) -> Result<(), BucketError> {
    if key.is_empty() {
        return Err(BucketError::BadKey { reason: "empty" });
    }
    if key.contains(&0) {
        return Err(BucketError::BadKey {
            reason: "contains NUL",
        });
    }
    Ok(())
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], BucketError> {
    b.try_into().map_err(|_| BucketError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

impl BucketManifest {
    pub fn get(&self, key: &[u8]) -> Option<&KeyObject> {
        self.entries.get(key)
    }

    /// Live (not tombstoned) object at `key`.
    pub fn live(&self, key: &[u8]) -> Option<&Manifest> {
        self.entries.get(key).and_then(|e| e.object.as_ref())
    }

    pub fn put(&mut self, key: Vec<u8>, object: KeyObject) -> Result<(), BucketError> {
        safe_key(&key)?;
        if object.deleted() != object.object.is_none() {
            unreachable!("deleted iff object is None");
        }
        self.entries.insert(key, object);
        Ok(())
    }

    /// Next lamport for `key`: one past whatever is already there, or 1.
    pub fn next_lamport(&self, key: &[u8]) -> u64 {
        self.entries
            .get(key)
            .map(|e| e.lamport.saturating_add(1))
            .unwrap_or(1)
    }

    /// Per-key LWW. Keys only on one side survive; the same key keeps the
    /// greater `(lamport, writer_id)`.
    pub fn merge(a: &Self, b: &Self) -> Self {
        let mut entries = a.entries.clone();
        for (k, v) in &b.entries {
            match entries.get(k) {
                Some(have) if !v.beats(have) => {}
                _ => {
                    entries.insert(k.clone(), v.clone());
                }
            }
        }
        Self { entries }
    }

    pub fn encode(&self) -> Result<Vec<u8>, BucketError> {
        let mut fields: Vec<Vec<u8>> = vec![BUCKET_MAGIC.to_vec(), vec![VERSION]];
        for (key, e) in &self.entries {
            safe_key(key)?;
            fields.push(key.clone());
            fields.push(e.lamport.to_le_bytes().to_vec());
            fields.push(e.writer_id.to_vec());
            fields.push(vec![u8::from(e.deleted())]);
            match &e.object {
                None => fields.push(Vec::new()),
                Some(m) => fields.push(m.encode()?),
            }
        }
        let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
        Ok(encode_fields(&refs)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BucketError> {
        let f = decode_fields(bytes)?;
        if f.first() != Some(&&BUCKET_MAGIC[..]) {
            return Err(BucketError::BadMagic);
        }
        if f.len() < 2 {
            return Err(BucketError::RaggedEntries { fields: f.len() });
        }
        let version = fixed::<1>("version", f[1])?[0];
        if version != VERSION {
            return Err(BucketError::BadVersion { value: version });
        }
        let body = f.len() - 2;
        if !body.is_multiple_of(5) {
            return Err(BucketError::RaggedEntries { fields: body });
        }
        let mut entries = BTreeMap::new();
        let mut prev: Option<&[u8]> = None;
        let mut i = 2;
        while i + 4 < f.len() {
            let key = f[i];
            safe_key(key)?;
            if let Some(p) = prev {
                if key <= p {
                    return Err(BucketError::NonCanonical {
                        reason: "keys are not in ascending order",
                    });
                }
            }
            prev = Some(key);

            let lamport = u64::from_le_bytes(fixed::<8>("lamport", f[i + 1])?);
            let writer_id = fixed::<WRITER_LEN>("writer_id", f[i + 2])?;
            let deleted_f = f[i + 3];
            if deleted_f.len() != 1 {
                return Err(BucketError::NonCanonical {
                    reason: "deleted field is not one byte",
                });
            }
            let deleted = match deleted_f[0] {
                0 => false,
                1 => true,
                _ => {
                    return Err(BucketError::NonCanonical {
                        reason: "deleted is not 0 or 1",
                    })
                }
            };
            let body = f[i + 4];
            let object = match (deleted, body.is_empty()) {
                (true, true) => None,
                (false, false) => Some(Manifest::decode(body)?),
                (true, false) => {
                    return Err(BucketError::NonCanonical {
                        reason: "tombstone carries a chunk table",
                    })
                }
                (false, true) => {
                    return Err(BucketError::NonCanonical {
                        reason: "live key has no object",
                    })
                }
            };
            if entries
                .insert(
                    key.to_vec(),
                    KeyObject {
                        lamport,
                        writer_id,
                        object,
                    },
                )
                .is_some()
            {
                return Err(BucketError::NonCanonical {
                    reason: "duplicate key",
                });
            }
            i += 5;
        }
        Ok(Self { entries })
    }
}

/// Load and store a sealed (or transit-only plaintext) bucket.
pub struct BucketStore<'a> {
    pub blobs: &'a BlobStore,
    pub sealer: Sealer<'a>,
}

impl<'a> BucketStore<'a> {
    pub fn new(blobs: &'a BlobStore, sealer: Sealer<'a>) -> Self {
        Self { blobs, sealer }
    }

    fn put_plain(&self, dir: &DirSecret, plain: &[u8]) -> Result<Addr, BucketError> {
        match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                let sealed = seal(&key, plain, BUCKET_AAD)?;
                Ok(self.blobs.put(&sealed)?)
            }
            Sealer::Plaintext { .. } => Ok(self.blobs.put(plain)?),
        }
    }

    pub fn store(&self, dir: &DirSecret, bucket: &BucketManifest) -> Result<Addr, BucketError> {
        self.put_plain(dir, &bucket.encode()?)
    }

    pub fn load(&self, dir: &DirSecret, addr: &Addr) -> Result<BucketManifest, BucketError> {
        let stored = self.blobs.get(addr)?;
        let plain = match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                open(&key, &stored, BUCKET_AAD)?
            }
            Sealer::Plaintext { .. } => stored,
        };
        BucketManifest::decode(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::Addressing;
    use crate::object::ObjectWriter;
    use nas_core::PaddingProfile;
    use nas_crypto::{ConvergenceSecret, KEY_LEN};
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-bucket-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file_manifest(tag: u8) -> Manifest {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        // Unique per call: several tests build a live(1, …, 1) at once, and
        // a shared scratch is deleted out from under the other writer.
        let scratch = Scratch::new(&format!("obj-{tag}-{}", N.fetch_add(1, Ordering::Relaxed)));
        let blobs = BlobStore::open_with(&scratch.0, Addressing::Content).unwrap();
        let cs = ConvergenceSecret::from_bytes([tag; KEY_LEN]);
        let w = ObjectWriter::convergent(&blobs, &cs, PaddingProfile::None).unwrap();
        w.write(crate::Kind::File, &b"body"[..]).unwrap()
    }

    fn live(lamport: u64, writer: u8, tag: u8) -> KeyObject {
        KeyObject {
            lamport,
            writer_id: [writer; WRITER_LEN],
            object: Some(file_manifest(tag)),
        }
    }

    fn tomb(lamport: u64, writer: u8) -> KeyObject {
        KeyObject {
            lamport,
            writer_id: [writer; WRITER_LEN],
            object: None,
        }
    }

    #[test]
    fn empty_round_trips() {
        let b = BucketManifest::default();
        assert_eq!(BucketManifest::decode(&b.encode().unwrap()).unwrap(), b);
    }

    #[test]
    fn two_keys_round_trip() {
        let mut b = BucketManifest::default();
        b.put(b"a/one".to_vec(), live(1, 1, 1)).unwrap();
        b.put(b"b/two".to_vec(), live(2, 2, 2)).unwrap();
        assert_eq!(BucketManifest::decode(&b.encode().unwrap()).unwrap(), b);
    }

    #[test]
    fn a_tombstone_round_trips() {
        let mut b = BucketManifest::default();
        b.put(b"gone".to_vec(), tomb(3, 9)).unwrap();
        let got = BucketManifest::decode(&b.encode().unwrap()).unwrap();
        assert!(got.get(b"gone").unwrap().deleted());
        assert_eq!(got, b);
    }

    #[test]
    fn merge_keeps_both_keys() {
        // The whole point of §7.1: two devices PUT different keys and both
        // survive. Bucket-granular LWW erased one of them.
        let mut a = BucketManifest::default();
        a.put(b"from-a".to_vec(), live(1, 1, 1)).unwrap();
        let mut b = BucketManifest::default();
        b.put(b"from-b".to_vec(), live(1, 2, 2)).unwrap();
        let m = BucketManifest::merge(&a, &b);
        assert!(m.live(b"from-a").is_some());
        assert!(m.live(b"from-b").is_some());
    }

    #[test]
    fn merge_same_key_is_lamport_lww() {
        let mut a = BucketManifest::default();
        a.put(b"k".to_vec(), live(1, 9, 1)).unwrap();
        let mut b = BucketManifest::default();
        b.put(b"k".to_vec(), live(2, 1, 2)).unwrap();
        let m = BucketManifest::merge(&a, &b);
        assert_eq!(m.get(b"k").unwrap().lamport, 2);
        assert_eq!(m.get(b"k").unwrap().writer_id[0], 1);
    }

    #[test]
    fn merge_ties_break_on_writer_id() {
        let mut a = BucketManifest::default();
        a.put(b"k".to_vec(), live(5, 1, 1)).unwrap();
        let mut b = BucketManifest::default();
        b.put(b"k".to_vec(), live(5, 2, 2)).unwrap();
        let m = BucketManifest::merge(&a, &b);
        assert_eq!(m.get(b"k").unwrap().writer_id[0], 2);
    }

    #[test]
    fn a_newer_tombstone_beats_a_live_key() {
        let mut a = BucketManifest::default();
        a.put(b"k".to_vec(), live(1, 1, 1)).unwrap();
        let mut b = BucketManifest::default();
        b.put(b"k".to_vec(), tomb(2, 1)).unwrap();
        assert!(BucketManifest::merge(&a, &b).get(b"k").unwrap().deleted());
    }

    #[test]
    fn an_unknown_version_is_refused_before_the_body_is_read() {
        let bytes = encode_fields(&[&BUCKET_MAGIC[..], &[2u8], &[0u8; 7]]).unwrap();
        assert!(matches!(
            BucketManifest::decode(&bytes),
            Err(BucketError::BadVersion { value: 2 })
        ));
    }

    #[test]
    fn a_dir_manifest_is_not_a_bucket() {
        let dir_shaped = encode_fields(&[b"NASD", &[VERSION]]).unwrap();
        assert!(matches!(
            BucketManifest::decode(&dir_shaped),
            Err(BucketError::BadMagic)
        ));
    }

    #[test]
    fn unsorted_keys_are_refused() {
        let a = live(1, 1, 1).object.unwrap().encode().unwrap();
        let b = live(1, 1, 2).object.unwrap().encode().unwrap();
        let bytes = encode_fields(&[
            &BUCKET_MAGIC[..],
            &[VERSION],
            b"z",
            &1u64.to_le_bytes(),
            &[1u8; 32],
            &[0],
            &a,
            b"a",
            &1u64.to_le_bytes(),
            &[1u8; 32],
            &[0],
            &b,
        ])
        .unwrap();
        assert!(matches!(
            BucketManifest::decode(&bytes),
            Err(BucketError::NonCanonical {
                reason: "keys are not in ascending order"
            })
        ));
    }

    #[test]
    fn a_tombstone_with_chunks_is_refused() {
        let body = live(1, 1, 1).object.unwrap().encode().unwrap();
        let bytes = encode_fields(&[
            &BUCKET_MAGIC[..],
            &[VERSION],
            b"k",
            &1u64.to_le_bytes(),
            &[1u8; 32],
            &[1],
            &body,
        ])
        .unwrap();
        assert!(matches!(
            BucketManifest::decode(&bytes),
            Err(BucketError::NonCanonical {
                reason: "tombstone carries a chunk table"
            })
        ));
    }

    #[test]
    fn empty_key_is_refused() {
        let mut b = BucketManifest::default();
        assert!(matches!(
            b.put(vec![], live(1, 1, 1)),
            Err(BucketError::BadKey { reason: "empty" })
        ));
    }

    #[test]
    fn sealed_store_round_trips() {
        let scratch = Scratch::new("store");
        let blobs = BlobStore::open_with(&scratch.0, Addressing::Content).unwrap();
        let cs = ConvergenceSecret::from_bytes([7u8; KEY_LEN]);
        let store = BucketStore::new(&blobs, Sealer::Convergent(&cs));
        let dir = DirSecret::root(&[9u8; KEY_LEN]);
        let mut b = BucketManifest::default();
        b.put(b"scan.pdf".to_vec(), live(1, 3, 3)).unwrap();
        let addr = store.store(&dir, &b).unwrap();
        assert_eq!(store.load(&dir, &addr).unwrap(), b);
    }

    #[test]
    fn transit_only_stores_plaintext() {
        let scratch = Scratch::new("plain");
        let salt = b"tenant".to_vec();
        let blobs = BlobStore::open_with(&scratch.0, Addressing::Salted(salt.clone())).unwrap();
        let store = BucketStore::new(&blobs, Sealer::Plaintext { tenant_salt: &salt });
        let dir = DirSecret::root(&[1u8; KEY_LEN]);
        let mut b = BucketManifest::default();
        b.put(b"visible".to_vec(), live(1, 1, 4)).unwrap();
        let addr = store.store(&dir, &b).unwrap();
        // The blob itself is the encoding — no AEAD framing — so a peer that
        // is supposed to browse can.
        let stored = blobs.get(&addr).unwrap();
        assert_eq!(BucketManifest::decode(&stored).unwrap(), b);
    }

    #[test]
    fn next_lamport_steps() {
        let mut b = BucketManifest::default();
        assert_eq!(b.next_lamport(b"k"), 1);
        b.put(b"k".to_vec(), live(4, 1, 1)).unwrap();
        assert_eq!(b.next_lamport(b"k"), 5);
    }
}
