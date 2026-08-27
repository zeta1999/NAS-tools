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

use crate::blobs::{BlobStore, StoreError};
use crate::chunker::ChunkerConfig;
use crate::manifest::{Kind, Manifest, ManifestError};
use crate::object::{read_object, ObjectError, ObjectWriter};
use nas_core::{decode_fields, encode_fields, Addr, PaddingProfile, ADDR_LEN};
use nas_crypto::{manifest_key, open, seal, ConvergenceSecret, DirSecret};
use std::collections::BTreeMap;
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
    pub entries: BTreeMap<String, Entry>,
}

/// Reject anything that is not a single, ordinary path component.
fn safe_name(name: &str) -> Result<(), TreeError> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0');
    if bad {
        return Err(TreeError::UnsafeName {
            name: name.to_string(),
        });
    }
    Ok(())
}

impl DirManifest {
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        let mut fields: Vec<Vec<u8>> = vec![DIR_MAGIC.to_vec()];
        for (name, e) in &self.entries {
            safe_name(name)?;
            fields.push(name.as_bytes().to_vec());
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
        let mut entries = BTreeMap::new();
        let mut i = 1;
        while i + 2 < f.len() + 1 && i + 2 <= f.len() {
            let name = String::from_utf8_lossy(f[i]).into_owned();
            safe_name(&name)?;
            let kind = f[i + 1];
            let payload = f[i + 2];
            let e = match kind.first() {
                Some(0) => Entry::File(Manifest::decode(payload)?),
                Some(1) => {
                    if payload.len() < ADDR_LEN {
                        return Err(TreeError::BadEntry { value: 1 });
                    }
                    let mut a = [0u8; ADDR_LEN];
                    a.copy_from_slice(&payload[..ADDR_LEN]);
                    Entry::Dir {
                        addr: Addr::from_bytes(a),
                        dir_id: payload[ADDR_LEN..].to_vec(),
                    }
                }
                Some(v) => return Err(TreeError::BadEntry { value: *v }),
                None => return Err(TreeError::BadEntry { value: 255 }),
            };
            if entries.insert(name.clone(), e).is_some() {
                return Err(TreeError::DuplicateName { name });
            }
            i += 3;
        }
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

        let mut names: Vec<(String, PathBuf, bool)> = Vec::new();
        for e in fs::read_dir(src)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
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
                let dir_id = name.as_bytes().to_vec();
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
            let out = dst.join(name);
            // Belt and braces: even with safe_name above, refuse to write
            // outside the destination. The check is cheap and the failure it
            // guards against is arbitrary file overwrite.
            if out.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(TreeError::UnsafeName { name: name.clone() });
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
    fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            let mut es: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
            es.sort_by_key(|e| e.file_name());
            for e in es {
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                if e.file_type().unwrap().is_dir() {
                    out.insert(format!("{rel}/"), Vec::new());
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
        } = &dm.entries["src"]
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

    #[test]
    fn decode_never_panics_on_junk() {
        for n in [0usize, 1, 4, 5, 40, 200] {
            let _ = DirManifest::decode(&corpus(n, 7));
        }
        let _ = DirManifest::decode(&[]);
    }
}
