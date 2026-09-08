//! The "no plaintext on the peer" scan (SPECS §1, §12.2, §19.1, §19.3, §20).
//!
//! # Why a walk, and not a list of directories
//!
//! The first version of this check looked in one place: it enumerated the blob
//! store's addresses and read each blob back through [`nas_store::BlobStore`].
//! That is a scan of `blobs/` and of nothing else. The peer's root also holds
//! `slots/`, `witnesses/`, `handoffs/`, `checkpoints/`, `leases/`, `delete/`
//! and `retention` (SPECS §20), none of which were looked at — and the set is
//! still growing, so a fixed list of directories to scan is a list that goes
//! stale the next time the peer learns to persist something. Whatever the peer
//! writes next would have been outside the scan on the day it was written, and
//! nothing would have failed.
//!
//! So this walks the root instead. A directory nobody has thought of yet is
//! scanned because it is *there*, not because it is named here.
//!
//! # What counts as a leak
//!
//! Two different things, and they are not interchangeable:
//!
//! 1. **Content.** A marker the fixture corpus carries in its bytes. If it is
//!    on the peer, the peer can read the file.
//! 2. **Names.** SPECS §4.4 and §15.3 put path segments *inside* sealed
//!    directory manifests precisely so the peer never sees them. A name is a
//!    leak whether it turns up inside a file's bytes (an unsealed manifest) or
//!    as a path component of the peer's own tree (a store that filed a blob
//!    under its source name). Both are checked.
//!
//! In `transit-only` both are *correct* (SPECS §2.2.3): the peer is meant to
//! read the content and browse the names. The scanner does not know about
//! modes — it reports what it found, and the caller flips the expectation. That
//! is what makes UC01 a usable control on UC02 and UC03: the same code that
//! must find nothing there must find something here, or it is not working.

use std::fs;
use std::path::{Path, PathBuf};

/// The fixture corpus's content marker — the first line of
/// `tests/usecases/fixtures/tree/README.md`.
pub const FIXTURE_MARKER: &str = "# work tree fixture";

/// Planted through the object writer rather than through the tree writer, so
/// the chunk/pad/seal path is exercised on a payload the corpus does not
/// already contain.
pub const CANARY: &str = "CANARY-PLAINTEXT-MUST-NOT-APPEAR";

/// Byte strings that must not be readable on the peer in an encrypted mode.
pub const CONTENT_MARKERS: &[&str] = &[FIXTURE_MARKER, CANARY];

/// Fixture file names distinctive enough to be *evidence*.
///
/// Most of the corpus is named the way a real source tree is named — `config`,
/// `main.rs`, `lib.rs`, `tiny.txt`, `empty`, `data.bin`, `guide.txt`,
/// `README.md` — and a generic name is not evidence of anything. `config` is
/// the clearest case: the namespace's own plaintext configuration file is also
/// called `config` (SPECS §2.2 puts the mode and the Object Lock policy there
/// deliberately), so a scanner that flagged the name `config` would flag an
/// honest peer on every run and be switched off within a week.
///
/// These two cannot collide with anything the peer legitimately writes.
pub const FIXTURE_NAMES: &[&str] = &["copy-of-lib.rs", "q3-board-minutes-CONFIDENTIAL.md"];

/// What kind of thing was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leak {
    /// Readable file content.
    Content,
    /// A file name inside a file's bytes — an unsealed manifest.
    NameInBytes,
    /// A file name as a path component of the peer's own tree.
    NameInPath,
}

impl Leak {
    fn label(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::NameInBytes => "name in bytes",
            Self::NameInPath => "name in path",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub leak: Leak,
    /// Relative to the scanned root.
    pub path: PathBuf,
    pub needle: &'static str,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:?} at {}",
            self.leak.label(),
            self.needle,
            self.path.display()
        )
    }
}

#[derive(Debug, Default)]
pub struct Scan {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    /// Entries whose bytes were not read: symlinks, sockets, fifos, and files
    /// that would not open. Tracked rather than skipped silently, because "no
    /// plaintext on the peer" is not a claim anyone can make about bytes
    /// nobody looked at.
    pub not_read: Vec<PathBuf>,
    pub findings: Vec<Finding>,
}

impl Scan {
    pub fn content_hits(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.leak == Leak::Content)
            .count()
    }

    pub fn name_hits(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.leak != Leak::Content)
            .count()
    }

    /// The first `limit` findings, for an error message that says where.
    pub fn report(&self, limit: usize) -> String {
        let shown: Vec<String> = self
            .findings
            .iter()
            .take(limit)
            .map(|f| f.to_string())
            .collect();
        let more = self.findings.len().saturating_sub(shown.len());
        if more == 0 {
            shown.join("; ")
        } else {
            format!("{} (+{more} more)", shown.join("; "))
        }
    }

    pub fn list_not_read(&self, limit: usize) -> String {
        self.not_read
            .iter()
            .take(limit)
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Walk `root` and report every marker and every fixture name found under it.
///
/// Errors only if `root` itself cannot be read: a peer root that is not there
/// stored nothing, and the caller has to say so rather than score an empty
/// scan as clean.
pub fn scan(root: &Path) -> std::io::Result<Scan> {
    let mut s = Scan::default();
    walk(root, root, &mut s)?;
    Ok(s)
}

/// Confirm the fixture corpus actually carries what [`scan`] looks for.
///
/// Without this the negative assertion has a silent failure mode shaped
/// exactly like success. `tests/usecases/fixtures/tree` is generated and
/// gitignored, so a corpus built before a name was added to [`FIXTURE_NAMES`]
/// can still be on disk and still be used. The scan then finds nothing because
/// nothing was planted, and calls the peer clean. `run.sh` rebuilds a corpus
/// older than `make.sh`; this is the check that does not depend on it having.
///
/// The check is the scanner run against the corpus: every content marker must
/// be in some file's bytes, and every fixture name must be a real file.
pub fn check_corpus(tree: &Path) -> Result<String, String> {
    let s = scan(tree).map_err(|e| format!("reading the corpus at {}: {e}", tree.display()))?;
    let stale = |what: &str| {
        format!(
            "the corpus at {} carries no {what} — it predates this check, so the scan \
             would look for bytes nobody planted and report every namespace clean. \
             `fixtures/tree` is generated and gitignored: delete it and re-run \
             tests/usecases/fixtures/make.sh",
            tree.display()
        )
    };
    if !s
        .findings
        .iter()
        .any(|f| f.leak == Leak::Content && f.needle == FIXTURE_MARKER)
    {
        return Err(stale(&format!("{FIXTURE_MARKER:?}")));
    }
    for n in FIXTURE_NAMES {
        if !s
            .findings
            .iter()
            .any(|f| f.leak == Leak::NameInPath && f.needle == *n)
        {
            return Err(stale(&format!("file named {n:?}")));
        }
    }
    Ok(format!(
        "{} file(s) carrying {:?} and {} distinctive name(s)",
        s.files,
        FIXTURE_MARKER,
        FIXTURE_NAMES.len()
    ))
}

fn walk(base: &Path, dir: &Path, s: &mut Scan) -> std::io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let rel = p.strip_prefix(base).unwrap_or(&p).to_path_buf();

        // The entry's own name only. Its ancestors were checked when the walk
        // visited them, so a leaked directory is reported once and not once
        // per file underneath it.
        let name = e.file_name().to_string_lossy().into_owned();
        for n in FIXTURE_NAMES {
            if name.contains(n) {
                s.findings.push(Finding {
                    leak: Leak::NameInPath,
                    path: rel.clone(),
                    needle: n,
                });
            }
        }

        let ft = e.file_type()?;
        if ft.is_symlink() {
            // Not followed: a link out of the root would take the scan
            // somewhere that is not the peer's, and a cycle would not
            // terminate. Recorded so the caller can refuse to call the scan
            // complete.
            s.not_read.push(rel);
        } else if ft.is_dir() {
            s.dirs += 1;
            walk(base, &p, s)?;
        } else if ft.is_file() {
            s.files += 1;
            match fs::read(&p) {
                Ok(b) => {
                    s.bytes += b.len() as u64;
                    for m in CONTENT_MARKERS {
                        if contains(&b, m.as_bytes()) {
                            s.findings.push(Finding {
                                leak: Leak::Content,
                                path: rel.clone(),
                                needle: m,
                            });
                        }
                    }
                    for n in FIXTURE_NAMES {
                        if contains(&b, n.as_bytes()) {
                            s.findings.push(Finding {
                                leak: Leak::NameInBytes,
                                path: rel.clone(),
                                needle: n,
                            });
                        }
                    }
                }
                Err(_) => s.not_read.push(rel),
            }
        } else {
            s.not_read.push(rel);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "nas-peerscan-{}-{tag}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn put(&self, rel: &str, body: &[u8]) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sealed(seed: &str, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        blake3::Hasher::new_derive_key(seed)
            .finalize_xof()
            .fill(&mut out);
        out
    }

    /// A peer root shaped like the real one (SPECS §20): a blob store, the
    /// five plaintext record families, the retention set, and the namespace's
    /// own plaintext `config`. Nothing readable in any of it.
    fn honest_root() -> Scratch {
        let s = Scratch::new("honest");
        let slot = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        s.put("blobs/ab/cdef0123456789", &sealed("blob-1", 4096));
        s.put("blobs/0f/fedcba98765432", &sealed("blob-2", 65536));
        s.put(&format!("slots/{slot}"), &sealed("slot", 4000));
        s.put(
            &format!("witnesses/{slot}/w-0001"),
            &sealed("witness", 3800),
        );
        s.put(
            &format!("handoffs/{slot}/0-aa-bb"),
            &sealed("handoff", 7000),
        );
        s.put(&format!("checkpoints/{slot}/12-cc"), &sealed("ckpt", 4200));
        s.put("leases/deadbeef", &sealed("lease", 512));
        s.put("delete/requests/aa11", &sealed("delreq", 900));
        s.put("retention", &sealed("retention", 320));
        // Client-side neighbours that live in the same directory in the
        // acceptance topology, and that an honest run always has.
        s.put(
            "config",
            b"version 1\nmode e2ee\nkey_scheme convergent\npadding_profile classes\n",
        );
        s.put("wraps/0.bin", &sealed("wrap", 1024));
        s.put("state/HEAD", b"3f9a0c11\n");
        s.put("vault.bin", &sealed("vault", 512));
        s
    }

    #[test]
    fn an_honest_peer_root_is_clean() {
        let s = honest_root();
        let scan = scan(s.path()).unwrap();
        assert!(
            scan.findings.is_empty(),
            "false positive on an honest root: {}",
            scan.report(10)
        );
        assert!(scan.not_read.is_empty(), "{:?}", scan.not_read);
        assert!(scan.files >= 13, "walked only {} files", scan.files);
        assert!(scan.dirs >= 8, "walked only {} directories", scan.dirs);
    }

    /// The namespace's own `config` is not a leak. This is the reason
    /// [`FIXTURE_NAMES`] excludes the generic half of the corpus: `config` is
    /// also `fixtures/tree/.hidden/config`, and a check that used it would be
    /// red on every honest run.
    #[test]
    fn the_namespaces_own_config_is_not_a_finding() {
        let s = honest_root();
        let scan = scan(s.path()).unwrap();
        assert!(!scan
            .findings
            .iter()
            .any(|f| f.path.to_string_lossy().contains("config")));
    }

    /// Each of these is a place the old blob-only scan did not look. The last
    /// one is the point of the walk: the code has never heard of that
    /// directory and must still scan it.
    #[test]
    fn a_marker_anywhere_under_the_root_fails() {
        for (tag, rel) in [
            ("blob", "blobs/ab/cdef0123456789"),
            ("slot", "slots/a1b2c3d4e5f60718293a4b5c6d7e8f90"),
            ("lease", "leases/deadbeef"),
            (
                "witness",
                "witnesses/a1b2c3d4e5f60718293a4b5c6d7e8f90/w-0001",
            ),
            ("unknown", "quorum-vouchers/2027/q1/voucher-0001.bin"),
        ] {
            let s = honest_root();
            let mut body = sealed(tag, 2048);
            let m = FIXTURE_MARKER.as_bytes();
            body.splice(700..700 + m.len(), m.iter().copied());
            s.put(rel, &body);

            let scan = scan(s.path()).unwrap();
            assert_eq!(
                scan.content_hits(),
                1,
                "marker planted in {rel} was not found: {}",
                scan.report(10)
            );
            assert_eq!(scan.name_hits(), 0, "{}", scan.report(10));
            assert_eq!(scan.findings[0].path, PathBuf::from(rel));
        }
    }

    /// The canary travels a different write path from the corpus, so it is
    /// checked separately.
    #[test]
    fn the_canary_is_found_too() {
        let s = honest_root();
        let mut body = sealed("canary-blob", 8192);
        let c = CANARY.as_bytes();
        body.splice(4096..4096 + c.len(), c.iter().copied());
        s.put("blobs/77/aabbccddeeff", &body);

        let scan = scan(s.path()).unwrap();
        assert_eq!(scan.content_hits(), 1, "{}", scan.report(10));
        assert_eq!(scan.findings[0].needle, CANARY);
    }

    /// A store that filed a blob under the name it came from. Nothing in the
    /// file's bytes gives it away; the path does.
    #[test]
    fn a_fixture_name_as_a_path_component_is_caught() {
        let s = honest_root();
        s.put("blobs/ab/copy-of-lib.rs", &sealed("looks-sealed", 4096));
        let scan = scan(s.path()).unwrap();
        assert_eq!(scan.content_hits(), 0, "{}", scan.report(10));
        assert_eq!(scan.name_hits(), 1, "{}", scan.report(10));
        assert_eq!(scan.findings[0].leak, Leak::NameInPath);
    }

    /// The same, one level up: a *directory* named after a fixture path, with
    /// files under it. Reported once, not once per file.
    #[test]
    fn a_fixture_name_as_a_directory_is_reported_once() {
        let s = honest_root();
        s.put("blobs/copy-of-lib.rs/one", &sealed("one", 64));
        s.put("blobs/copy-of-lib.rs/two", &sealed("two", 64));
        let scan = scan(s.path()).unwrap();
        assert_eq!(scan.name_hits(), 1, "{}", scan.report(10));
        assert_eq!(scan.findings[0].path, PathBuf::from("blobs/copy-of-lib.rs"));
    }

    /// An unsealed directory manifest: the name is in the bytes.
    #[test]
    fn a_fixture_name_inside_a_file_is_caught() {
        let s = honest_root();
        let mut body = sealed("manifest", 2048);
        let n = FIXTURE_NAMES[1].as_bytes();
        body.splice(100..100 + n.len(), n.iter().copied());
        s.put("blobs/12/34567890abcdef", &body);

        let scan = scan(s.path()).unwrap();
        assert_eq!(scan.content_hits(), 0, "{}", scan.report(10));
        assert_eq!(scan.name_hits(), 1, "{}", scan.report(10));
        assert_eq!(scan.findings[0].leak, Leak::NameInBytes);
        assert_eq!(scan.findings[0].needle, FIXTURE_NAMES[1]);
    }

    /// A symlink is not followed, and the scan says so rather than reporting a
    /// clean root it did not fully read.
    #[test]
    #[cfg(unix)]
    fn an_unread_entry_is_recorded() {
        let s = honest_root();
        let target = s.path().join("blobs/ab/cdef0123456789");
        std::os::unix::fs::symlink(target, s.path().join("blobs/link")).unwrap();
        let scan = scan(s.path()).unwrap();
        assert_eq!(scan.not_read.len(), 1, "{:?}", scan.not_read);
    }

    #[test]
    fn a_missing_root_is_an_error_not_a_clean_scan() {
        let s = Scratch::new("missing");
        assert!(scan(&s.path().join("nope")).is_err());
    }

    /// A corpus that predates a name in [`FIXTURE_NAMES`] must be rejected, not
    /// searched for: a scan looking for bytes nobody planted reports every
    /// namespace clean.
    #[test]
    fn a_stale_corpus_is_rejected() {
        let s = Scratch::new("corpus");
        s.put("README.md", FIXTURE_MARKER.as_bytes());
        s.put("docs/copy-of-lib.rs", b"fn main() {}\n");
        let e = check_corpus(s.path()).unwrap_err();
        assert!(e.contains(FIXTURE_NAMES[1]), "{e}");

        s.put(&format!("docs/{}", FIXTURE_NAMES[1]), b"minutes\n");
        check_corpus(s.path()).unwrap();

        // And the same for the content marker.
        let t = Scratch::new("corpus-no-marker");
        t.put("docs/copy-of-lib.rs", b"fn main() {}\n");
        t.put(&format!("docs/{}", FIXTURE_NAMES[1]), b"minutes\n");
        assert!(check_corpus(t.path()).unwrap_err().contains(FIXTURE_MARKER));
    }

    /// The harness's fixture script is the source of truth for what the corpus
    /// carries, so the constants are checked against *it*: `make.sh` must plant
    /// [`FIXTURE_MARKER`] and every name in [`FIXTURE_NAMES`] literally. The
    /// generated `fixtures/tree` is checked too, but only when it is at least
    /// as new as `make.sh` — the rule `run.sh` uses to decide whether to
    /// rebuild it. A tree older than the script is what `run.sh` is about to
    /// replace, not evidence of drift, and `cargo test` does not generate it;
    /// failing on it made `cargo test` depend on which `run.sh` ran last.
    #[test]
    fn the_real_corpus_carries_what_the_scan_looks_for() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/usecases/fixtures");
        let script = fixtures.join("make.sh");
        let src =
            fs::read_to_string(&script).unwrap_or_else(|e| panic!("{}: {e}", script.display()));
        assert!(
            src.contains(FIXTURE_MARKER),
            "make.sh no longer plants {FIXTURE_MARKER:?}"
        );
        for name in FIXTURE_NAMES {
            assert!(src.contains(name), "make.sh no longer creates {name:?}");
        }

        let tree = fixtures.join("tree");
        let (Ok(t), Ok(s)) = (fs::metadata(&tree), fs::metadata(&script)) else {
            return;
        };
        let (Ok(tree_at), Ok(script_at)) = (t.modified(), s.modified()) else {
            return;
        };
        if !t.is_dir() || tree_at < script_at {
            return;
        }
        check_corpus(&tree).unwrap();
    }
}
