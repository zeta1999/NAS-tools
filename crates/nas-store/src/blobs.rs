//! Content-addressed blob storage (SPECS §4, `blobs/<ab>/<cdef…>`).
//!
//! An address is `BLAKE3(ciphertext)` — of the *ciphertext*, never the
//! plaintext (SPECS §3.4). That is what lets an untrusted peer run exactly this
//! code: verifying a blob needs no key, so integrity checking can be delegated
//! to a machine that is handed nothing readable.
//!
//! # Two addressing schemes, one property
//!
//! `transit-only` stores plaintext and addresses `BLAKE3(tenant_salt ‖ bytes)`
//! (SPECS §2.2.3), so the store has to know which scheme it is running. It is a
//! property of the store rather than an argument to each call, because a store
//! that could be asked to file one blob one way and the next another would
//! produce a directory in which `get` cannot verify anything.
//!
//! The property that matters survives both: **verification still needs no
//! secret.** The tenant salt is not secret — it only has to be unshared — so a
//! peer holding it can check every blob it stores without being able to read
//! any of them in the encrypted modes, and without gaining anything it did not
//! already have in `transit-only`.

use nas_core::Addr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// The bytes on disk do not hash to the address they are filed under.
    /// Distinct from `Io` because the response differs: a read error is
    /// retryable, a corrupt blob must be refetched from a peer.
    Corrupt {
        addr: Addr,
        found: Addr,
    },
    /// No blob under that address.
    Missing {
        addr: Addr,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "blob store I/O: {e}"),
            Self::Corrupt { addr, found } => write!(
                f,
                "blob {} hashes to {} — corrupt or substituted",
                addr.to_hex(),
                found.to_hex()
            ),
            Self::Missing { addr } => write!(f, "no blob {}", addr.to_hex()),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// How a blob's address is derived from its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addressing {
    /// `addr = BLAKE3(bytes)`. The encrypted modes, where the bytes are
    /// ciphertext (SPECS §3.4).
    Content,
    /// `addr = BLAKE3(len(salt) ‖ salt ‖ bytes)`. `transit-only`, where the
    /// bytes are plaintext and an unsalted address would hand every co-tenant
    /// on a shared peer a confirmation oracle (SPECS §2.2.3).
    Salted(Vec<u8>),
}

impl Addressing {
    pub fn addr_of(&self, bytes: &[u8]) -> Addr {
        match self {
            Self::Content => Addr::of_ciphertext(bytes),
            Self::Salted(salt) => {
                let mut h = blake3::Hasher::new();
                h.update(&(salt.len() as u64).to_le_bytes());
                h.update(salt);
                h.update(bytes);
                Addr::from_bytes(*h.finalize().as_bytes())
            }
        }
    }

    pub fn verifies(&self, addr: &Addr, bytes: &[u8]) -> bool {
        self.addr_of(bytes) == *addr
    }
}

/// A directory of blobs.
#[derive(Debug)]
pub struct BlobStore {
    root: PathBuf,
    addressing: Addressing,
    /// Makes temporary names unique within a process. Two processes are
    /// separated by the pid also in the name.
    seq: AtomicU64,
}

impl BlobStore {
    /// Open (creating if absent) a content-addressed blob store.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_with(root, Addressing::Content)
    }

    /// Open a store with an explicit addressing scheme.
    pub fn open_with(root: impl Into<PathBuf>, addressing: Addressing) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            root,
            addressing,
            seq: AtomicU64::new(0),
        })
    }

    pub fn addressing(&self) -> &Addressing {
        &self.addressing
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where a given address is filed. Two hex characters of fan-out keeps
    /// directory sizes tolerable for filesystems that degrade on wide dirs.
    pub fn path(&self, addr: &Addr) -> PathBuf {
        let (shard, rest) = addr.shard();
        self.root.join("blobs").join(shard).join(rest)
    }

    pub fn has(&self, addr: &Addr) -> bool {
        self.path(addr).exists()
    }

    /// Store a ciphertext blob, returning its address.
    ///
    /// Writes to a temporary file and renames, so a crash mid-write can never
    /// leave a truncated blob filed under a valid address — a reader would
    /// otherwise get a hash mismatch it could only interpret as an attack.
    ///
    /// If the address is already present its contents are **verified** rather
    /// than assumed. Content addressing makes "already there" mean "identical",
    /// but only if what is there is actually intact; skipping the check would
    /// turn a corrupt local blob into permanent silent data loss the moment a
    /// second copy of the same chunk was offered and discarded.
    pub fn put(&self, ciphertext: &[u8]) -> Result<Addr, StoreError> {
        let addr = self.addressing.addr_of(ciphertext);
        let dest = self.path(&addr);

        if dest.exists() {
            match fs::read(&dest) {
                Ok(existing) if self.addressing.verifies(&addr, &existing) => return Ok(addr),
                Ok(_) | Err(_) => { /* fall through and rewrite it */ }
            }
        }

        let dir = dest.parent().expect("blob paths always have a shard dir");
        fs::create_dir_all(dir)?;

        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.{}.tmp", std::process::id(), n));
        fs::write(&tmp, ciphertext)?;
        // Same filesystem, so this is atomic; it also overwrites, which is what
        // repairing a corrupt blob needs.
        match fs::rename(&tmp, &dest) {
            Ok(()) => Ok(addr),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(StoreError::Io(e))
            }
        }
    }

    /// Fetch a blob, **verifying** it against its address.
    ///
    /// Verification is not optional and not a debug assertion. This is the
    /// single point where a tampered or bit-rotted blob is caught, and the
    /// caller has no other way to notice.
    pub fn get(&self, addr: &Addr) -> Result<Vec<u8>, StoreError> {
        let p = self.path(addr);
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Missing { addr: *addr })
            }
            Err(e) => return Err(StoreError::Io(e)),
        };
        if !self.addressing.verifies(addr, &bytes) {
            return Err(StoreError::Corrupt {
                addr: *addr,
                found: self.addressing.addr_of(&bytes),
            });
        }
        Ok(bytes)
    }

    /// Answer a proof-of-possession challenge: `BLAKE3(nonce ‖ ciphertext)`
    /// (SPECS §4.5).
    ///
    /// A peer that claims "already have it" and thereby persuades a client to
    /// skip an upload has, if it is lying, performed a silent deletion
    /// discovered only at a future read. Only a holder of the ciphertext can
    /// answer this.
    pub fn prove(&self, addr: &Addr, nonce: &[u8; 32]) -> Result<[u8; 32], StoreError> {
        let ct = self.get(addr)?;
        let mut h = blake3::Hasher::new();
        h.update(nonce);
        h.update(&ct);
        Ok(*h.finalize().as_bytes())
    }

    /// Verify a peer's proof-of-possession answer against local plaintext.
    pub fn check_proof(ciphertext: &[u8], nonce: &[u8; 32], answer: &[u8; 32]) -> bool {
        let mut h = blake3::Hasher::new();
        h.update(nonce);
        h.update(ciphertext);
        h.finalize().as_bytes() == answer
    }

    /// Every address currently stored. Used by the lease sweep (SPECS §6).
    pub fn addrs(&self) -> Result<Vec<Addr>, StoreError> {
        let mut out = Vec::new();
        let blobs = self.root.join("blobs");
        for shard in fs::read_dir(&blobs)? {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            let prefix = shard.file_name().to_string_lossy().into_owned();
            for f in fs::read_dir(shard.path())? {
                let name = f?.file_name().to_string_lossy().into_owned();
                // Junk in the blob directory is skipped, not an error: a peer
                // cannot be allowed to break a GC sweep by dropping a file in.
                if let Ok(a) = Addr::from_hex(&format!("{prefix}{name}")) {
                    out.push(a);
                }
            }
        }
        out.sort_by_key(|a| *a.as_bytes());
        Ok(out)
    }

    /// Remove a blob. Only the lease sweep should call this.
    pub fn remove(&self, addr: &Addr) -> Result<(), StoreError> {
        match fs::remove_file(self.path(addr)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that cleans itself up, without a tempfile
    /// dependency and without randomness (which the formal-model rules ban).
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "nas-store-test-{}-{}-{tag}",
                std::process::id(),
                line!()
            ));
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

    #[test]
    fn put_then_get_roundtrips() {
        let s = Scratch::new("roundtrip");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"some ciphertext").unwrap();
        assert!(st.has(&a));
        assert_eq!(st.get(&a).unwrap(), b"some ciphertext");
    }

    #[test]
    fn identical_bytes_are_stored_once() {
        let s = Scratch::new("dedup");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"chunk").unwrap();
        let b = st.put(b"chunk").unwrap();
        assert_eq!(a, b);
        assert_eq!(st.addrs().unwrap().len(), 1);
    }

    #[test]
    fn a_tampered_blob_is_caught_on_read() {
        let s = Scratch::new("tamper");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"trustworthy bytes").unwrap();
        fs::write(st.path(&a), b"trustworthy bytez").unwrap();
        match st.get(&a) {
            Err(StoreError::Corrupt { .. }) => {}
            other => panic!("tampering not detected: {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_blob_is_repaired_rather_than_assumed_good() {
        // The silent-data-loss path: a corrupt blob is present, the same chunk
        // is offered again, and a store that trusted `exists()` would discard
        // the good copy.
        let s = Scratch::new("repair");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"original").unwrap();
        fs::write(st.path(&a), b"corrupted!").unwrap();
        assert!(st.get(&a).is_err());
        let a2 = st.put(b"original").unwrap();
        assert_eq!(a, a2);
        assert_eq!(st.get(&a).unwrap(), b"original");
    }

    #[test]
    fn a_missing_blob_is_missing_not_corrupt() {
        let s = Scratch::new("missing");
        let st = BlobStore::open(&s.0).unwrap();
        let a = Addr::of_ciphertext(b"never stored");
        match st.get(&a) {
            Err(StoreError::Missing { .. }) => {}
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn proof_of_possession_needs_the_actual_bytes() {
        let s = Scratch::new("pop");
        let st = BlobStore::open(&s.0).unwrap();
        let ct = b"the ciphertext a lying peer claims to hold";
        let a = st.put(ct).unwrap();
        let nonce = [7u8; 32];

        let honest = st.prove(&a, &nonce).unwrap();
        assert!(BlobStore::check_proof(ct, &nonce, &honest));

        // A peer that kept only the address cannot produce this.
        assert!(!BlobStore::check_proof(ct, &nonce, a.as_bytes()));
        // Nor can a stale answer be replayed under a fresh challenge.
        assert!(!BlobStore::check_proof(ct, &[8u8; 32], &honest));
    }

    #[test]
    fn junk_in_the_blob_directory_does_not_break_a_sweep() {
        let s = Scratch::new("junk");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"real").unwrap();
        let (shard, _) = a.shard();
        fs::write(s.0.join("blobs").join(&shard).join("not-an-address"), b"x").unwrap();
        fs::create_dir_all(s.0.join("blobs").join("zz")).unwrap();
        assert_eq!(st.addrs().unwrap(), vec![a]);
    }

    #[test]
    fn a_salted_store_addresses_and_verifies_consistently() {
        let s = Scratch::new("salted");
        let st = BlobStore::open_with(&s.0, Addressing::Salted(b"tenant-a".to_vec())).unwrap();
        let a = st.put(b"plaintext at rest").unwrap();
        assert_eq!(st.get(&a).unwrap(), b"plaintext at rest");
        // Integrity still checks without any secret.
        fs::write(st.path(&a), b"plaintext at rezt").unwrap();
        assert!(matches!(st.get(&a), Err(StoreError::Corrupt { .. })));
    }

    #[test]
    fn two_tenants_do_not_share_an_address_for_one_file() {
        // SPECS §2.2.3: an unsalted address hands every co-tenant on a shared
        // peer a confirmation oracle -- upload a candidate, watch for the
        // dedup skip, learn somebody else holds it.
        let a = Addressing::Salted(b"tenant-a".to_vec());
        let b = Addressing::Salted(b"tenant-b".to_vec());
        let file = b"a candidate file an attacker also has";
        assert_ne!(a.addr_of(file), b.addr_of(file));
        // And neither matches the unsalted address, so a Content store and a
        // Salted store never collide either.
        assert_ne!(a.addr_of(file), Addressing::Content.addr_of(file));
    }

    #[test]
    fn salt_boundaries_are_unambiguous() {
        // Without the length prefix, salts "ab"+"c" and "a"+"bc" would put two
        // tenants back in one dedup pool and reinstate the oracle.
        let x = Addressing::Salted(b"ab".to_vec()).addr_of(b"c-payload");
        let y = Addressing::Salted(b"a".to_vec()).addr_of(b"bc-payload");
        assert_ne!(x, y);
    }

    #[test]
    fn a_salted_store_still_deduplicates_within_the_tenant() {
        let s = Scratch::new("salted-dedup");
        let st = BlobStore::open_with(&s.0, Addressing::Salted(b"t".to_vec())).unwrap();
        let a = st.put(b"same chunk").unwrap();
        let b = st.put(b"same chunk").unwrap();
        assert_eq!(a, b);
        assert_eq!(st.addrs().unwrap().len(), 1);
    }

    #[test]
    fn remove_is_idempotent() {
        let s = Scratch::new("remove");
        let st = BlobStore::open(&s.0).unwrap();
        let a = st.put(b"transient").unwrap();
        st.remove(&a).unwrap();
        st.remove(&a).unwrap();
        assert!(!st.has(&a));
    }

    #[test]
    fn no_temporary_files_survive_a_successful_put() {
        let s = Scratch::new("tmp");
        let st = BlobStore::open(&s.0).unwrap();
        for i in 0..10u8 {
            st.put(&[i; 64]).unwrap();
        }
        assert_eq!(fs::read_dir(s.0.join("tmp")).unwrap().count(), 0);
    }
}
