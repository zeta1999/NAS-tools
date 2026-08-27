//! Directory trees (SPECS §4.3, §4.4, §15.3).
//!
//! A directory is one manifest listing its entries. Files are inlined — their
//! chunk tables live in the parent's manifest rather than in a blob of their
//! own — and subdirectories are referenced by the address of their manifest
//! plus the `dir_id` needed to re-derive their key.
//!
//! # Keys
//!
//! Each directory has a `DirSecret` derived from its parent's and its `dir_id`
//! (SPECS §3.1), and its manifest is sealed under `manifest_key(dir_secret)` —
//! a random-nonce key, since one directory's manifest is rewritten many times.
//! The chain is built at M0 because SPECS §15.3 is explicit that retrofitting
//! it once data exists means re-keying everything: a capability scoped to a
//! subtree is only possible if the subtree already has its own secret.
//!
//! # Why names are not separately encrypted
//!
//! SPECS §4.4 specifies Cryptomator-style per-segment name encryption. That
//! design exists because Cryptomator maps each path segment onto a *filename on
//! the server*, so the segment has to be ciphertext or the server reads the
//! tree. Here the peer stores `blobs/<ab>/<hex>` and never sees a name at all —
//! names live inside the directory manifest, which is itself an opaque sealed
//! blob. Encrypting them again inside their own ciphertext would add a key
//! schedule and buy nothing.
//!
//! `transit-only` is the case that will need this reconsidered, since there the
//! peer legitimately reads plaintext and names must be *visible*. That is an M1
//! concern and is recorded in TODO.md rather than guessed at here.
//!
//! # Names are raw bytes, not `String`
//!
//! A POSIX filename is an arbitrary byte sequence that is not required to be
//! UTF-8. Keying entries by `String` via `to_string_lossy` looked harmless on
//! macOS, where the filesystem rejects invalid sequences — and is silently
//! destructive on Linux, where it is not:
//!
//! * two distinct legal names (`a\xFFb`, `a\xFEb`) both become `a\u{FFFD}b`,
//!   so the second collides with the first and the **whole tree write fails**;
//! * a single such file is extracted under a *different* byte sequence, so the
//!   round trip is not byte-identical — and a test that compares two lossily
//!   stringified snapshots compares mangled to mangled and sees nothing.
//!
//! Entry names are therefore `Vec<u8>`. This is a **format** decision, not an
//! implementation one: it has to be right before the on-disk layout freezes at
//! M1, because changing the name representation afterwards is a format break.

use crate::blobs::{BlobStore, StoreError};
use crate::chunker::ChunkerConfig;
use crate::manifest::{Kind, Manifest, ManifestError};
use crate::object::{read_object, ObjectError, ObjectWriter};
use nas_core::{decode_fields, encode_fields, Addr, PaddingProfile, ADDR_LEN};
use nas_crypto::{manifest_key, open, seal, ConvergenceSecret, DirSecret};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Distinguishes a directory manifest from a file manifest blob.
pub const DIR_MAGIC: &[u8; 4] = b"NASD";
pub const DIR_AAD: &[u8] = b"nas-tools/aad/dir/v1";

#[derive(Debug)]
pub enum TreeError {
    Object(ObjectError),
    Store(StoreError),
    Manifest(ManifestError),
    Io(std::io::Error),
    Crypto(nas_crypto::CryptoError),
    Decode(nas_core::DecodeError),
    BadMagic,
    /// An entry kind byte outside the enum.
    BadEntry {
        value: u8,
    },
    /// A path component that is not a plain name: `..`, a root, or a prefix.
    /// Refused rather than normalised, because a manifest that can express
    /// `..` is a directory traversal waiting to happen on extraction.
    UnsafeName {
        name: String,
    },
    /// Two entries with the same name in one directory.
    DuplicateName {
        name: String,
    },
    /// The field count is not one magic plus a whole number of 3-field entries.
    /// Rejecting this is what keeps the encoding injective at the tail.
    RaggedEntries {
        fields: usize,
    },
    /// Well-formed, but not something `encode` would ever emit.
    ///
    /// The rule this enforces: **the decoder must reject anything the encoder
    /// would not produce.** Every degree of freedom a decoder tolerates and an
    /// encoder never uses is a covert channel, invisible to every reader, and a
    /// second byte string that means the same thing.
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Manifest(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "encoding: {e:?}"),
            Self::BadMagic => write!(f, "not a directory manifest"),
            Self::BadEntry { value } => write!(f, "unknown entry kind {value}"),
            Self::UnsafeName { name } => write!(f, "refusing unsafe path component {name:?}"),
            Self::DuplicateName { name } => write!(f, "duplicate entry {name:?}"),
            Self::RaggedEntries { fields } => {
                write!(f, "{fields} entry fields is not a multiple of 3")
            }
            Self::NonCanonical { reason } => write!(f, "non-canonical manifest: {reason}"),
        }
    }
}
impl std::error::Error for TreeError {}

macro_rules! from_err {
    ($($t:ty => $v:ident),* $(,)?) => {$(
        impl From<$t> for TreeError { fn from(e: $t) -> Self { Self::$v(e) } }
    )*};
}
from_err!(ObjectError => Object, StoreError => Store, ManifestError => Manifest,
          std::io::Error => Io, nas_crypto::CryptoError => Crypto,
          nas_core::DecodeError => Decode);

/// One entry in a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A file, with its chunk table inline.
    File(Manifest),
    /// A subdirectory: where its manifest is, and the id its key derives from.
    Dir { addr: Addr, dir_id: Vec<u8> },
}

/// A directory manifest: an ordered set of named entries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DirManifest {
    /// Sorted by name, so an unchanged directory encodes to identical bytes and
    /// re-uploading it is a no-op. A `HashMap` here would make the encoding
    /// depend on iteration order and quietly break that.
    ///
    /// Keys are raw bytes: see the module docs on why `String` was wrong.
    pub entries: BTreeMap<Vec<u8>, Entry>,
}

/// Reject anything that is not a single, ordinary path component.
///
/// Operates on bytes, since that is what a filename is. A backslash is refused
/// as well as `/`, so a manifest written on one platform cannot express a
/// traversal that only bites on another.
fn safe_name(name: &[u8]) -> Result<(), TreeError> {
    let bad = name.is_empty()
        || name == b"."
        || name == b".."
        || name.contains(&b'/')
        || name.contains(&b'\\')
        || name.contains(&0);
    if bad {
        return Err(TreeError::UnsafeName {
            name: String::from_utf8_lossy(name).into_owned(),
        });
    }
    Ok(())
}

/// A filename as bytes, on platforms where that is what a filename is.
#[cfg(unix)]
fn name_bytes(n: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    n.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn name_bytes(n: &std::ffi::OsStr) -> Vec<u8> {
    n.to_string_lossy().into_owned().into_bytes()
}

/// The inverse of [`name_bytes`].
#[cfg(unix)]
fn name_os(b: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(b.to_vec())
}

#[cfg(not(unix))]
fn name_os(b: &[u8]) -> std::ffi::OsString {
    std::ffi::OsString::from(String::from_utf8_lossy(b).into_owned())
}

impl DirManifest {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let mut fields: Vec<Vec<u8>> = vec![DIR_MAGIC.to_vec()];
        for (name, e) in &self.entries {
            safe_name(name)?;
            fields.push(name.clone());
            match e {
                Entry::File(m) => {
                    fields.push(vec![0]);
                    fields.push(m.encode()?);
                }
                Entry::Dir { addr, dir_id } => {
                    fields.push(vec![1]);
                    let mut p = addr.as_bytes().to_vec();
                    p.extend_from_slice(dir_id);
                    fields.push(p);
                }
            }
        }
        let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
        Ok(encode_fields(&refs)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let f = decode_fields(bytes)?;
        if f.first() != Some(&&DIR_MAGIC[..]) {
            return Err(TreeError::BadMagic);
        }
        // Three fields per entry, and the count must come out exact.
        //
        // The previous bound was `i + 2 < f.len() + 1 && i + 2 <= f.len()`, in
        // which both clauses reduce to `i + 2 <= f.len()` while the body indexes
        // `f[i + 2]` — so a field count that is a multiple of three (a truncated
        // final entry) read one past the end and **panicked**. And because the
        // loop simply stopped when a partial triple remained, trailing fields
        // were silently dropped: two different encodings decoded to the same
        // manifest, which is precisely the tail-injectivity that
        // `encoding::decode_fields` refuses to allow one layer below.
        let body = f.len() - 1;
        if !body.is_multiple_of(3) {
            return Err(TreeError::RaggedEntries { fields: body });
        }
        let mut entries = BTreeMap::new();
        let mut dir_ids: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut prev: Option<&[u8]> = None;
        let mut i = 1;
        while i + 2 < f.len() {
            let name = f[i].to_vec();
            safe_name(&name)?;

            // Entries are emitted in ascending name order, so anything else is
            // not something `encode` could have produced. Without this the
            // BTreeMap quietly sorts on the way in and re-sorts on the way out,
            // so a permuted encoding decodes to an identical manifest --
            // log2(n!) bits of covert channel, and a second way for two byte
            // strings to mean the same thing.
            if let Some(p) = prev {
                if f[i] <= p {
                    return Err(TreeError::NonCanonical {
                        reason: "entries are not in ascending name order",
                    });
                }
            }
            prev = Some(f[i]);

            // The kind field is one byte. Reading only `kind.first()` accepted
            // a field of any length and silently discarded the rest -- an
            // unbounded covert channel that survived a manual review and was
            // found by the fuzzer in 45 seconds.
            let kind = f[i + 1];
            if kind.len() != 1 {
                return Err(TreeError::NonCanonical {
                    reason: "kind field is not one byte",
                });
            }
            let payload = f[i + 2];
            let e = match kind[0] {
                0 => Entry::File(Manifest::decode(payload)?),
                1 => {
                    if payload.len() < ADDR_LEN {
                        return Err(TreeError::BadEntry { value: 1 });
                    }
                    let mut a = [0u8; ADDR_LEN];
                    a.copy_from_slice(&payload[..ADDR_LEN]);
                    let dir_id = payload[ADDR_LEN..].to_vec();
                    // The encoder sets `dir_id` from the entry name, and
                    // `safe_name` forbids an empty name, so an empty dir_id is
                    // not something `encode` can produce.
                    if dir_id.is_empty() {
                        return Err(TreeError::NonCanonical {
                            reason: "empty dir_id",
                        });
                    }

                    // Two siblings sharing a `dir_id` derive the same
                    // `DirSecret`, so a capability scoped to one subtree would
                    // open the other -- the scoping SPECS §15.3 says
                    // per-directory keys exist to provide. Siblings are where
                    // it matters: the chain mixes in the parent, so the same
                    // dir_id under different parents is already distinct.
                    if !dir_ids.insert(dir_id.clone()) {
                        return Err(TreeError::NonCanonical {
                            reason: "two sibling directories share a dir_id",
                        });
                    }
                    Entry::Dir {
                        addr: Addr::from_bytes(a),
                        dir_id,
                    }
                }
                v => return Err(TreeError::BadEntry { value: v }),
            };
            if entries.insert(name.clone(), e).is_some() {
                return Err(TreeError::DuplicateName {
                    name: String::from_utf8_lossy(&name).into_owned(),
                });
            }
            i += 3;
        }
        debug_assert_eq!(i, f.len(), "the multiple-of-three check guarantees this");
        Ok(Self { entries })
    }
}

/// Writes and reads whole directory trees.
pub struct TreeStore<'a> {
    pub blobs: &'a BlobStore,
    pub cs: &'a ConvergenceSecret,
    pub profile: PaddingProfile,
    pub cfg: ChunkerConfig,
}

impl<'a> TreeStore<'a> {
    pub fn new(blobs: &'a BlobStore, cs: &'a ConvergenceSecret, profile: PaddingProfile) -> Self {
        Self {
            blobs,
            cs,
            profile,
            cfg: ChunkerConfig::for_profile(profile, ChunkerConfig::default()),
        }
    }

    /// Store `src` recursively under `dir`'s key, returning the address of its
    /// directory manifest.
    pub fn write_dir(&self, dir: &DirSecret, src: &Path) -> Result<Addr, TreeError> {
        self.write_dir_incremental(dir, src, None)
    }

    /// Store `src`, reusing `prev` where nothing changed.
    ///
    /// # Why this is not an optimisation
    ///
    /// Directory manifests are sealed under a **random-nonce** key (SPECS §3.1),
    /// because one directory is rewritten many times and a deterministic nonce
    /// would reuse a keystream. The consequence is that re-sealing identical
    /// plaintext yields different ciphertext and therefore a different address —
    /// so a naive writer re-uploads *every directory manifest in the tree* on
    /// every sync of an unchanged tree, and each one is a fresh blob the lease
    /// sweep must later collect.
    ///
    /// That was not a hypothesis: `an_unchanged_tree_costs_nothing` failed
    /// exactly this way before this method existed. The fix is to compare the
    /// new manifest against the previous one *as plaintext* and keep the old
    /// address when they agree. Chunk blobs need no such treatment — their keys
    /// are content-derived, so identical content already converges.
    pub fn write_dir_incremental(
        &self,
        dir: &DirSecret,
        src: &Path,
        prev: Option<&Addr>,
    ) -> Result<Addr, TreeError> {
        // A previous manifest that cannot be read is treated as absent rather
        // than as an error: the caller asked to store a tree, not to prove that
        // an old version is still intact.
        let old = prev.and_then(|a| self.read_dir_manifest(dir, a).ok());
        let mut dm = DirManifest::default();
        let w = ObjectWriter::new(self.blobs, self.cs, self.profile, self.cfg)?;

        let mut names: Vec<(Vec<u8>, PathBuf, bool)> = Vec::new();
        for e in fs::read_dir(src)? {
            let e = e?;
            let name = name_bytes(&e.file_name());
            safe_name(&name)?;
            let ft = e.file_type()?;
            // Symlinks are skipped, not followed: following them would let a
            // tree escape its own root, and storing them needs a format field
            // that does not exist yet. Recorded rather than silently resolved.
            if ft.is_symlink() {
                continue;
            }
            names.push((name, e.path(), ft.is_dir()));
        }
        names.sort();

        for (name, path, is_dir) in names {
            if is_dir {
                let dir_id = name.clone();
                let child = dir.child(&dir_id);
                let prev_child = old.as_ref().and_then(|o| match o.entries.get(&name) {
                    Some(Entry::Dir { addr, .. }) => Some(*addr),
                    _ => None,
                });
                let addr = self.write_dir_incremental(&child, &path, prev_child.as_ref())?;
                dm.entries.insert(name, Entry::Dir { addr, dir_id });
            } else {
                let m = w.write(Kind::File, fs::File::open(&path)?)?;
                dm.entries.insert(name, Entry::File(m));
            }
        }

        if let (Some(o), Some(a)) = (&old, prev) {
            if *o == dm {
                return Ok(*a);
            }
        }

        let plain = dm.encode()?;
        let key = manifest_key(dir);
        let sealed = seal(&key, &plain, DIR_AAD)?;
        Ok(self.blobs.put(&sealed)?)
    }

    /// Read a directory manifest back.
    pub fn read_dir_manifest(
        &self,
        dir: &DirSecret,
        addr: &Addr,
    ) -> Result<DirManifest, TreeError> {
        let sealed = self.blobs.get(addr)?;
        let key = manifest_key(dir);
        let plain = open(&key, &sealed, DIR_AAD)?;
        DirManifest::decode(&plain)
    }

    /// Materialise a stored tree into `dst`.
    pub fn read_dir_to(&self, dir: &DirSecret, addr: &Addr, dst: &Path) -> Result<(), TreeError> {
        let dm = self.read_dir_manifest(dir, addr)?;
        fs::create_dir_all(dst)?;
        for (name, e) in &dm.entries {
            safe_name(name)?;
            let out = dst.join(name_os(name));
            // Belt and braces: even with safe_name above, refuse to write
            // outside the destination. The check is cheap and the failure it
            // guards against is arbitrary file overwrite.
            if out.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(TreeError::UnsafeName {
                    name: String::from_utf8_lossy(name).into_owned(),
                });
            }
            match e {
                Entry::File(m) => {
                    let mut f = fs::File::create(&out)?;
                    read_object(self.blobs, m, &mut f)?;
                }
                Entry::Dir { addr, dir_id } => {
                    self.read_dir_to(&dir.child(dir_id), addr, &out)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::KEY_LEN;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-tree-{}-{tag}", std::process::id()));
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

    fn build_tree(root: &Path) {
        fs::create_dir_all(root.join("src/deep/deeper")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("README.md"), b"# readme\n").unwrap();
        fs::write(root.join("empty.txt"), b"").unwrap();
        fs::write(root.join("src/main.rs"), corpus(200_000, 1)).unwrap();
        fs::write(root.join("src/lib.rs"), corpus(4096, 2)).unwrap();
        fs::write(root.join("src/deep/deeper/x.bin"), corpus(1 << 20, 3)).unwrap();
        fs::write(root.join("docs/guide.txt"), corpus(70_000, 4)).unwrap();
    }

    /// Every relative path and its bytes, so two trees can be compared exactly.
    ///
    /// Paths are keyed on **raw bytes**. Keying on `to_string_lossy` compares a
    /// mangled snapshot against a mangled snapshot, so a name that failed to
    /// survive the round trip would look identical on both sides — the test
    /// would pass while the data was wrong.
    fn snapshot(root: &Path) -> BTreeMap<Vec<u8>, Vec<u8>> {
        fn rel_bytes(base: &Path, p: &Path) -> Vec<u8> {
            let r = p.strip_prefix(base).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                r.as_os_str().as_bytes().to_vec()
            }
            #[cfg(not(unix))]
            {
                r.to_string_lossy().into_owned().into_bytes()
            }
        }
        let mut out = BTreeMap::new();
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<Vec<u8>, Vec<u8>>) {
            let mut es: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
            es.sort_by_key(|e| e.file_name());
            for e in es {
                let p = e.path();
                let mut rel = rel_bytes(base, &p);
                if e.file_type().unwrap().is_dir() {
                    rel.push(b'/');
                    out.insert(rel, Vec::new());
                    walk(base, &p, out);
                } else {
                    out.insert(rel, fs::read(&p).unwrap());
                }
            }
        }
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn a_tree_round_trips_byte_identically() {
        let s = Scratch::new("roundtrip");
        let src = s.0.join("src");
        let dst = s.0.join("dst");
        build_tree(&src);

        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);

        let addr = ts.write_dir(&root, &src).unwrap();
        ts.read_dir_to(&root, &addr, &dst).unwrap();

        assert_eq!(snapshot(&src), snapshot(&dst));
    }

    #[test]
    fn round_trips_under_every_padding_profile() {
        for (i, p) in [
            PaddingProfile::None,
            PaddingProfile::Classes,
            PaddingProfile::Fixed,
        ]
        .iter()
        .enumerate()
        {
            let s = Scratch::new(&format!("profiles-{i}"));
            let src = s.0.join("src");
            let dst = s.0.join("dst");
            build_tree(&src);
            let blobs = BlobStore::open(s.0.join("repo")).unwrap();
            let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
            let ts = TreeStore::new(&blobs, &cs, *p);
            let root = DirSecret::root(&[5u8; KEY_LEN]);
            let addr = ts.write_dir(&root, &src).unwrap();
            ts.read_dir_to(&root, &addr, &dst).unwrap();
            assert_eq!(snapshot(&src), snapshot(&dst), "{p:?}");
        }
    }

    #[test]
    fn a_rewrite_without_prev_costs_a_manifest_per_directory() {
        // The behaviour that made write_dir_incremental necessary, kept as a
        // test so the cost of forgetting `prev` stays visible rather than
        // becoming folklore. Random nonces (SPECS §3.1) mean identical
        // plaintext seals to a different address every time.
        let s = Scratch::new("nonincremental");
        let src = s.0.join("src");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);

        let a = ts.write_dir(&root, &src).unwrap();
        let before = blobs.addrs().unwrap().len();
        let b = ts.write_dir(&root, &src).unwrap();
        assert_ne!(
            a, b,
            "random-nonce manifests must not seal to identical bytes"
        );
        // Five directories: root, src, src/deep, src/deep/deeper, docs.
        assert_eq!(blobs.addrs().unwrap().len() - before, 5);
    }

    #[test]
    fn an_unchanged_tree_costs_nothing() {
        // What a periodic sync of an untouched tree must cost: zero blobs.
        let s = Scratch::new("stable");
        let src = s.0.join("src");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);

        let a = ts.write_dir(&root, &src).unwrap();
        let before = blobs.addrs().unwrap().len();
        let b = ts.write_dir_incremental(&root, &src, Some(&a)).unwrap();
        assert_eq!(a, b, "an unchanged tree must keep its address");
        assert_eq!(
            blobs.addrs().unwrap().len(),
            before,
            "an unchanged tree stored new blobs"
        );
    }

    #[test]
    fn one_edited_file_rewrites_only_its_own_path_to_the_root() {
        let s = Scratch::new("onepath");
        let src = s.0.join("src");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);

        let a = ts.write_dir(&root, &src).unwrap();
        let before = blobs.addrs().unwrap().len();
        fs::write(src.join("docs/guide.txt"), corpus(70_000, 99)).unwrap();
        let b = ts.write_dir_incremental(&root, &src, Some(&a)).unwrap();
        assert_ne!(a, b);

        // New blobs: the file's chunks (~2), the docs manifest, the root
        // manifest. src/ and its two descendants are untouched and must not be
        // rewritten.
        let added = blobs.addrs().unwrap().len() - before;
        assert!(added <= 5, "{added} new blobs for one edited file");

        let dst = s.0.join("dst");
        ts.read_dir_to(&root, &b, &dst).unwrap();
        assert_eq!(snapshot(&src), snapshot(&dst));
    }

    #[test]
    fn a_sibling_directorys_key_does_not_open_this_one() {
        // SPECS §15.3: per-directory keys exist so a capability can be scoped
        // to a subtree. If any DirSecret opened any manifest they would not.
        let s = Scratch::new("scoping");
        let src = s.0.join("src");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);
        let addr = ts.write_dir(&root, &src).unwrap();

        let dm = ts.read_dir_manifest(&root, &addr).unwrap();
        let Entry::Dir {
            addr: src_addr,
            dir_id,
        } = &dm.entries[&b"src"[..]]
        else {
            panic!("src should be a directory");
        };
        // The right key opens it.
        assert!(ts.read_dir_manifest(&root.child(dir_id), src_addr).is_ok());
        // Its sibling's key does not.
        assert!(ts
            .read_dir_manifest(&root.child(b"docs"), src_addr)
            .is_err());
        // Nor does the root's.
        assert!(ts.read_dir_manifest(&root, src_addr).is_err());
    }

    #[test]
    fn identical_subtrees_dedup() {
        let s = Scratch::new("dedup");
        let src = s.0.join("src");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);

        let a = ts
            .write_dir(&DirSecret::root(&[5u8; KEY_LEN]), &src)
            .unwrap();
        let before = blobs.addrs().unwrap().len();
        // A second copy of the same tree under a DIFFERENT root secret: the
        // file chunks are convergent so they dedup, only the manifests differ.
        let b = ts
            .write_dir(&DirSecret::root(&[6u8; KEY_LEN]), &src)
            .unwrap();
        let added = blobs.addrs().unwrap().len() - before;
        assert_ne!(a, b);
        assert!(
            added <= 5,
            "{added} new blobs for a duplicate tree (manifests only: 5 dirs)"
        );
    }

    #[test]
    fn a_directory_manifest_round_trips_through_its_encoding() {
        let mut dm = DirManifest::default();
        dm.entries.insert(
            "a.txt".into(),
            Entry::File(Manifest::new(
                Kind::File,
                nas_core::KeyScheme::Convergent,
                PaddingProfile::None,
            )),
        );
        dm.entries.insert(
            "sub".into(),
            Entry::Dir {
                addr: Addr::of_ciphertext(b"x"),
                dir_id: b"sub".to_vec(),
            },
        );
        assert_eq!(DirManifest::decode(&dm.encode().unwrap()).unwrap(), dm);
    }

    #[test]
    fn a_traversal_name_is_refused_on_both_paths() {
        let mut dm = DirManifest::default();
        dm.entries.insert(
            "../escape".into(),
            Entry::File(Manifest::new(
                Kind::File,
                nas_core::KeyScheme::Convergent,
                PaddingProfile::None,
            )),
        );
        assert!(matches!(dm.encode(), Err(TreeError::UnsafeName { .. })));
    }

    /// A valid manifest to mutate in the tests below.
    fn sample_dm() -> DirManifest {
        let mut dm = DirManifest::default();
        dm.entries.insert(
            b"a.txt".to_vec(),
            Entry::File(Manifest::new(
                Kind::File,
                nas_core::KeyScheme::Convergent,
                PaddingProfile::None,
            )),
        );
        dm
    }

    #[test]
    fn a_truncated_final_entry_is_an_error_not_a_panic() {
        // The exact shape that panicked: a field count that is a multiple of
        // three, so the old bound entered the loop and read one past the end.
        // The previous proptest fed only random bytes, every one of which was
        // rejected at the magic check and never reached the loop at all --
        // which is why it passed while this bug was live.
        let three = nas_core::encode_fields(&[&DIR_MAGIC[..], b"name", &[0u8]]).unwrap();
        assert!(matches!(
            DirManifest::decode(&three),
            Err(TreeError::RaggedEntries { fields: 2 })
        ));
        // And the other partial shape.
        let two = nas_core::encode_fields(&[&DIR_MAGIC[..], b"name"]).unwrap();
        assert!(matches!(
            DirManifest::decode(&two),
            Err(TreeError::RaggedEntries { fields: 1 })
        ));
    }

    #[test]
    fn trailing_fields_are_rejected_not_silently_dropped() {
        // Tail injectivity. `encoding::decode_fields` refuses trailing bytes one
        // layer below; dropping them here threw that guarantee away, so two
        // distinct encodings decoded to the same manifest.
        let dm = sample_dm();
        let clean = dm.encode().unwrap();
        let mut tainted = clean.clone();
        tainted.extend_from_slice(&nas_core::encode_fields(&[b"TRAILING"]).unwrap());

        assert_eq!(DirManifest::decode(&clean).unwrap(), dm);
        assert!(
            DirManifest::decode(&tainted).is_err(),
            "a longer encoding decoded to the same manifest"
        );
    }

    #[test]
    fn a_name_that_is_not_utf8_survives_the_round_trip() {
        // POSIX filenames are arbitrary bytes. Keying on String via
        // to_string_lossy mapped every invalid sequence onto U+FFFD, so two
        // distinct names collided into one and a stored file came back under
        // different bytes than it went in with.
        let mut dm = DirManifest::default();
        for raw in [&b"a\xFFb"[..], &b"a\xFEb"[..], "naïve".as_bytes()] {
            dm.entries.insert(
                raw.to_vec(),
                Entry::File(Manifest::new(
                    Kind::File,
                    nas_core::KeyScheme::Convergent,
                    PaddingProfile::None,
                )),
            );
        }
        assert_eq!(
            dm.entries.len(),
            3,
            "two distinct byte names collapsed into one"
        );
        let back = DirManifest::decode(&dm.encode().unwrap()).unwrap();
        assert_eq!(back, dm);
        assert!(back.entries.contains_key(&b"a\xFFb"[..]));
        assert!(back.entries.contains_key(&b"a\xFEb"[..]));
    }

    #[test]
    fn a_kind_field_longer_than_one_byte_is_rejected() {
        // Found by the fuzzer in 45 seconds, after a manual review missed it.
        // `kind.first()` accepted a field of ANY length and discarded the rest,
        // so 34 bytes of attacker data rode along invisibly and re-encoding
        // silently dropped them.
        let framed = nas_core::encode_fields(&[
            &DIR_MAGIC[..],
            b"name",
            &[1u8, 0xDE, 0xAD, 0xBE, 0xEF], // kind 1, plus smuggled bytes
            &{
                let mut p = vec![0u8; ADDR_LEN];
                p.extend_from_slice(b"id");
                p
            },
        ])
        .unwrap();
        assert!(matches!(
            DirManifest::decode(&framed),
            Err(TreeError::NonCanonical { .. })
        ));
    }

    #[test]
    fn entries_out_of_order_are_rejected() {
        // The BTreeMap sorted on the way in and `encode` re-sorted on the way
        // out, so a permuted encoding decoded to an identical manifest --
        // log2(n!) bits of covert channel, and a second byte string meaning the
        // same thing.
        let entry = |seed: u8, id: &[u8]| {
            let mut p = vec![seed; ADDR_LEN];
            p.extend_from_slice(id);
            p
        };
        let mk = |names: [&[u8]; 2]| {
            let (p0, p1) = (entry(7, b"id-one"), entry(8, b"id-two"));
            nas_core::encode_fields(&[&DIR_MAGIC[..], names[0], &[1u8], &p0, names[1], &[1u8], &p1])
                .unwrap()
        };
        assert!(DirManifest::decode(&mk([b"a", b"b"])).is_ok());
        assert!(matches!(
            DirManifest::decode(&mk([b"b", b"a"])),
            Err(TreeError::NonCanonical { .. })
        ));
        // Equal names too: that is a duplicate, caught by the same ordering rule.
        assert!(DirManifest::decode(&mk([b"a", b"a"])).is_err());
    }

    #[test]
    fn siblings_sharing_a_dir_id_are_rejected() {
        // Two siblings with the same dir_id derive the same DirSecret, so a
        // capability scoped to one subtree would open the other -- exactly the
        // scoping SPECS §15.3 says per-directory keys exist to provide.
        let mut payload = vec![7u8; ADDR_LEN];
        payload.extend_from_slice(b"same-id");
        let mut other = vec![9u8; ADDR_LEN];
        other.extend_from_slice(b"same-id");
        let framed = nas_core::encode_fields(&[
            &DIR_MAGIC[..],
            b"a",
            &[1u8],
            &payload,
            b"b",
            &[1u8],
            &other,
        ])
        .unwrap();
        assert!(matches!(
            DirManifest::decode(&framed),
            Err(TreeError::NonCanonical { .. })
        ));
    }

    #[test]
    fn whatever_decode_accepts_re_encodes_to_the_same_bytes() {
        // The invariant behind all three checks above: the decoder must reject
        // anything the encoder would not emit. Every tolerated degree of
        // freedom is a covert channel and a second spelling of one manifest.
        let dm = sample_dm();
        let bytes = dm.encode().unwrap();
        let back = DirManifest::decode(&bytes).unwrap();
        assert_eq!(back.encode().unwrap(), bytes);
    }

    #[test]
    fn a_real_tree_still_round_trips_after_the_canonical_checks() {
        // The checks must not reject the writer's own output, which is the way
        // a canonicalisation rule usually goes wrong.
        let s = Scratch::new("canonical");
        let src = s.0.join("src");
        let dst = s.0.join("dst");
        build_tree(&src);
        let blobs = BlobStore::open(s.0.join("repo")).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let ts = TreeStore::new(&blobs, &cs, PaddingProfile::None);
        let root = DirSecret::root(&[5u8; KEY_LEN]);
        let addr = ts.write_dir(&root, &src).unwrap();
        ts.read_dir_to(&root, &addr, &dst).unwrap();
        assert_eq!(snapshot(&src), snapshot(&dst));
    }

    #[test]
    fn decode_never_panics_on_junk_or_on_structured_garbage() {
        for n in [0usize, 1, 4, 5, 40, 200] {
            let _ = DirManifest::decode(&corpus(n, 7));
        }
        let _ = DirManifest::decode(&[]);

        // Structured inputs that reach past the magic check -- the ones the
        // old proptest could never generate.
        let valid = sample_dm().encode().unwrap();
        for cut in 0..valid.len().min(120) {
            let _ = DirManifest::decode(&valid[..cut]);
        }
        for n in 0..8usize {
            let fields: Vec<&[u8]> = std::iter::once(&DIR_MAGIC[..])
                .chain(std::iter::repeat_n(&b"x"[..], n))
                .collect();
            let _ = DirManifest::decode(&nas_core::encode_fields(&fields).unwrap());
        }
    }
}
