//! Offline write staging (SPECS §5.6).
//!
//! The gateway accepts writes with no peer reachable. Each write is a one-key
//! [`BucketManifest`] in `state/outbox/`. Local listing reads the published
//! `HEAD` merged with those deltas. Replay on reconnect folds the outbox onto
//! whatever HEAD has become — a CAS conflict is a merge, not an error.

use crate::exit;
use crate::objectcmd;
use crate::repo::Repo;
use nas_core::{KeyScheme, Mode, PaddingProfile};
use nas_store::{BucketManifest, BucketStore, KeyObject, Kind, ObjectWriter};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn refuse(msg: impl std::fmt::Display) -> i32 {
    eprintln!("refused: {msg}");
    exit::REFUSED
}

pub struct Outbox {
    dir: PathBuf,
}

impl Outbox {
    pub fn open(repo_root: &Path) -> std::io::Result<Self> {
        let dir = repo_root.join("state/outbox");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn is_empty(&self) -> bool {
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .all(|e| e.path().extension().is_none_or(|x| x != "nasb")),
            Err(_) => true,
        }
    }

    fn next_seq(&self) -> std::io::Result<u64> {
        let mut best = 0u64;
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let name = e.file_name();
                let s = name.to_string_lossy();
                if let Some(n) = s.strip_suffix(".nasb").and_then(|n| n.parse::<u64>().ok()) {
                    best = best.max(n);
                }
            }
        }
        Ok(best.saturating_add(1))
    }

    pub fn enqueue(&self, delta: &BucketManifest) -> Result<u64, String> {
        let seq = self.next_seq().map_err(|e| e.to_string())?;
        let bytes = delta.encode().map_err(|e| e.to_string())?;
        let path = self.dir.join(format!("{seq:08}.nasb"));
        fs::write(&path, bytes).map_err(|e| e.to_string())?;
        Ok(seq)
    }

    pub fn load(&self) -> Result<Vec<BucketManifest>, String> {
        let mut files: Vec<PathBuf> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "nasb"))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        files.sort();
        let mut out = Vec::with_capacity(files.len());
        for p in files {
            let bytes = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            out.push(BucketManifest::decode(&bytes).map_err(|e| format!("{}: {e}", p.display()))?);
        }
        Ok(out)
    }

    pub fn clear(&self) -> std::io::Result<()> {
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "nasb") {
                    fs::remove_file(p)?;
                }
            }
        }
        Ok(())
    }

    pub fn fold(base: BucketManifest, deltas: &[BucketManifest]) -> BucketManifest {
        deltas
            .iter()
            .fold(base, |acc, d| BucketManifest::merge(&acc, d))
    }
}

/// Published HEAD, or empty. A directory-tree HEAD is not a bucket — the
/// caller decides whether that is an error or a reason to stay out of the way.
pub fn load_published(
    store: &BucketStore<'_>,
    repo: &Repo,
) -> Result<BucketManifest, objectcmd::LoadError> {
    objectcmd::load_published_head(store, repo)
}

/// HEAD merged with every outbox delta — what `ls` / `get` / the gateway see.
pub fn working_view(
    store: &BucketStore<'_>,
    repo: &Repo,
) -> Result<BucketManifest, objectcmd::LoadError> {
    let base = load_published(store, repo)?;
    let box_ = Outbox::open(&repo.root).map_err(objectcmd::LoadError::io)?;
    let deltas = box_.load().map_err(objectcmd::LoadError::other)?;
    Ok(Outbox::fold(base, &deltas))
}

/// Fold the outbox onto HEAD and clear it. Used by `nas test outbox-replay`
/// and by `nas peer sync` so reconnect is the replay the spec names.
pub fn replay_into_head(repo: &Repo) -> Result<usize, String> {
    let box_ = Outbox::open(&repo.root).map_err(|e| e.to_string())?;
    let deltas = box_.load()?;
    if deltas.is_empty() {
        return Ok(0);
    }
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = BucketStore::new(&blobs, repo.sealer());
    let base = match objectcmd::load_published_head(&store, repo) {
        Ok(b) => b,
        Err(objectcmd::LoadError::NotABucket) => {
            return Err("state/HEAD is a directory tree; this namespace is not an S3 face".into());
        }
        Err(e) => return Err(e.to_string()),
    };
    let n = deltas.len();
    let merged = Outbox::fold(base, &deltas);
    objectcmd::save_published(&store, repo, &merged).map_err(|e| e.to_string())?;
    box_.clear().map_err(|e| e.to_string())?;
    Ok(n)
}

fn ensure_ns(ns: &str) -> Result<String, String> {
    // Isolated from whatever the suite already stored under `ns` (UC03 writes
    // a directory tree to `work`). The argument is the cookbook name; the
    // lab is a sibling namespace that is always a bucket.
    let lab = format!("{ns}-s3");
    if !Repo::exists(&lab) {
        Repo::create(
            &lab,
            Mode::E2ee,
            KeyScheme::Convergent,
            PaddingProfile::None,
            None,
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(lab)
}

fn put_lab(ns: &str, key: &str, body: &[u8]) -> Result<u64, String> {
    let target = format!("{ns}/{key}");
    let tmp = std::env::temp_dir().join(format!(
        "nas-outbox-{}-{}",
        std::process::id(),
        key.replace('/', "_")
    ));
    fs::write(&tmp, body).map_err(|e| e.to_string())?;
    let rc = objectcmd::put(&target, tmp.to_str().unwrap(), None);
    let _ = fs::remove_file(&tmp);
    if rc != exit::OK {
        return Err(format!("put {target} exited {rc}"));
    }
    Ok(body.len() as u64)
}

/// `nas test offline-write <ns>` — SPECS §5.6, UC07.
///
/// Writes must succeed with no peer at all. The proof is an outbox entry
/// plus a working-view read; a write that only updated HEAD would look the
/// same as an online write and would not be replayable against a later head.
pub fn offline_write(ns: &str) -> i32 {
    let lab = match ensure_ns(ns) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let body = b"offline-write-payload\n";
    if let Err(e) = put_lab(&lab, "cafe/notes.txt", body) {
        return err(e);
    }
    let repo = match Repo::open_with(&lab, crate::repo::passphrase_from(None)) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let box_ = match Outbox::open(&repo.root) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    if box_.is_empty() {
        return refuse("write succeeded but the outbox is empty — nothing to replay");
    }
    match objectcmd::get_bytes(&lab, "cafe/notes.txt") {
        Ok(got) if got == body => {
            println!("offline-write: accepted with no peer; staged in outbox; namespace {ns}");
            exit::OK
        }
        Ok(got) => err(format!(
            "working view returned {} B, want {} B",
            got.len(),
            body.len()
        )),
        Err(e) => err(e),
    }
}

/// `nas test outbox-replay <ns>`
pub fn outbox_replay(ns: &str) -> i32 {
    let lab = match ensure_ns(ns) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if let Err(e) = put_lab(&lab, "replay/one.txt", b"one\n") {
        return err(e);
    }
    let repo = match Repo::open_with(&lab, crate::repo::passphrase_from(None)) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let n = match replay_into_head(&repo) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    if n == 0 {
        return refuse("replay found an empty outbox after a write");
    }
    let box_ = match Outbox::open(&repo.root) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    if !box_.is_empty() {
        return refuse("outbox still has entries after replay");
    }
    if repo.head().is_none() {
        return refuse("replay did not publish HEAD");
    }
    match objectcmd::get_bytes(&lab, "replay/one.txt") {
        Ok(got) if got == b"one\n" => {
            println!("outbox-replay: {n} write(s) merged onto HEAD; namespace {ns}");
            exit::OK
        }
        Ok(_) => err("replay published a HEAD that does not read back"),
        Err(e) => err(e),
    }
}

/// `nas test outbox-conflict-merges <ns>` — SPECS §7.1 / §12.6.
///
/// A write sits in the outbox. Meanwhile HEAD becomes a different key (the
/// other device that published while we were away). Replay must keep both.
pub fn outbox_conflict_merges(ns: &str) -> i32 {
    let lab = match ensure_ns(ns) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if let Err(e) = put_lab(&lab, "from-a", b"alpha\n") {
        return err(e);
    }
    let repo = match Repo::open_with(&lab, crate::repo::passphrase_from(None)) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let store = BucketStore::new(&blobs, repo.sealer());
    let writer = match ObjectWriter::with_defaults(&blobs, repo.sealer(), repo.padding) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let object = match writer.write(Kind::File, Cursor::new(b"beta\n")) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let wid = match repo.identity(nas_crypto::Role::Slot) {
        Ok(id) => {
            let mut w = id.id();
            w[0] ^= 0xFF; // a different writer; same-device id would still merge
            w
        }
        Err(e) => return err(e),
    };
    let mut other = BucketManifest::default();
    if let Err(e) = other.put(
        b"from-b".to_vec(),
        KeyObject {
            lamport: 1,
            writer_id: wid,
            object: Some(object),
        },
    ) {
        return err(e);
    }
    if let Err(e) = objectcmd::save_published(&store, &repo, &other) {
        return err(e);
    }
    match replay_into_head(&repo) {
        Ok(0) => return refuse("nothing in the outbox to merge against the foreign HEAD"),
        Ok(_) => {}
        Err(e) => return err(e),
    }
    let a = match objectcmd::get_bytes(&lab, "from-a") {
        Ok(b) => b,
        Err(e) => return refuse(format!("from-a did not survive the merge: {e}")),
    };
    let b = match objectcmd::get_bytes(&lab, "from-b") {
        Ok(b) => b,
        Err(e) => return refuse(format!("from-b did not survive the merge: {e}")),
    };
    if a != b"alpha\n" || b != b"beta\n" {
        return refuse("both keys survived but the bytes did not");
    }
    println!("outbox-conflict-merges: both keys survived; namespace {ns}");
    exit::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_keeps_disjoint_keys() {
        let mut a = BucketManifest::default();
        a.put(
            b"a".to_vec(),
            KeyObject {
                lamport: 1,
                writer_id: [1u8; 32],
                object: None,
            },
        )
        .unwrap();
        let mut b = BucketManifest::default();
        b.put(
            b"b".to_vec(),
            KeyObject {
                lamport: 1,
                writer_id: [2u8; 32],
                object: None,
            },
        )
        .unwrap();
        let m = Outbox::fold(a, std::slice::from_ref(&b));
        assert!(m.get(b"a").is_some());
        assert!(m.get(b"b").is_some());
    }
}
