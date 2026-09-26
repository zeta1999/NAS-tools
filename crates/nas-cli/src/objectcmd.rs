//! `nas put` / `nas rm` / `nas ls` — the key → object map (SPECS §7.1).
//!
//! A namespace used as an S3 bucket stores a [`BucketManifest`] at `state/HEAD`.
//! Each key carries its own lamport clock and writer id, so two devices PUT
//! different keys and a CAS-retry merge keeps both.
//!
//! # Who may write
//!
//! In an encrypted mode the peer cannot see keys, so append-only is an honest
//! *client* check (SPECS §2.2). The everyday device named at `ns create
//! --device` is the subject. `Append` may create a key; `Write` may overwrite
//! or delete one. An empty ACL is the owner holding the vault — nothing is
//! granted implicitly to anyone else, and nothing is refused to the holder of
//! the keys.

use crate::aclcmd;
use crate::exit;
use crate::outbox::{self, Outbox};
use crate::repo::Repo;
use nas_core::Addr;
use nas_crypto::Role;
use nas_delete::Scope;
use nas_gateway::s3::{Buckets, FaceError, ObjectInfo, RangeBody};
use nas_peer::{Decision, Right};
use nas_store::{
    read_object, read_object_range, BucketManifest, BucketStore, ChunkCache, KeyObject, Kind,
    ObjectWriter, DEFAULT_CAP,
};
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::Path;

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn refuse(msg: impl std::fmt::Display) -> i32 {
    eprintln!("refused: {msg}");
    exit::REFUSED
}

/// Split `ns/key` on the first `/`. The key may itself contain `/`.
pub fn split_target(target: &str) -> Result<(&str, &str), String> {
    match target.split_once('/') {
        Some((ns, key)) if !ns.is_empty() && !key.is_empty() => Ok((ns, key)),
        _ => Err("usage: nas put|rm|ls <namespace>/<key> …".into()),
    }
}

fn acting_subject(ns: &str, explicit: Option<&str>) -> Result<Option<String>, String> {
    if let Some(s) = explicit {
        return Ok(Some(s.to_string()));
    }
    match Repo::describe(ns) {
        Ok(d) => Ok(d.device),
        Err(e) => Err(format!("namespace {ns}: {e}")),
    }
}

/// Client-side right check. Empty ACL → the local owner proceeds.
///
/// `Write` subsumes `Append` for creating a new key: a writer may add.
fn require(ns: &str, subject: Option<&str>, need: Right) -> Result<(), i32> {
    let acl = aclcmd::load(ns).map_err(err)?;
    if acl.subjects().next().is_none() {
        return Ok(());
    }
    let Some(subject) = subject else {
        return Err(refuse(
            "this namespace has an ACL and no everyday device; pass --subject",
        ));
    };
    let mode = Repo::describe(ns)
        .map_err(|e| err(format!("namespace {ns}: {e}")))?
        .mode;
    // Creating a key is allowed with either Append or Write.
    let decision = match need {
        Right::Append => {
            let a = acl.check(subject, Right::Append, mode);
            if a.permits() {
                a
            } else {
                acl.check(subject, Right::Write, mode)
            }
        }
        other => acl.check(subject, other, mode),
    };
    match decision {
        Decision::Allowed => Ok(()),
        Decision::Denied | Decision::UnknownSubject => Err(refuse(format!(
            "{subject} may not {} on {ns}: {decision}",
            need.as_str()
        ))),
        Decision::NotEnforceable { .. } => Err(err(decision)),
    }
}

fn open_repo(ns: &str) -> Result<Repo, i32> {
    Repo::open_with(ns, crate::repo::passphrase_from(None))
        .map_err(|e| err(format!("namespace {ns}: {e}")))
}

fn writer_id(repo: &Repo) -> Result<[u8; 32], i32> {
    repo.identity(Role::Slot)
        .map(|id| id.id())
        .map_err(|e| err(format!("identity: {e}")))
}

/// Why a HEAD could not be read as a bucket. Distinguished so sync can skip
/// a tree namespace instead of treating every `work` checkout as broken.
#[derive(Debug)]
pub enum LoadError {
    NotABucket,
    Other(String),
}

impl LoadError {
    pub fn io(e: impl std::fmt::Display) -> Self {
        Self::Other(e.to_string())
    }
    pub fn other(e: impl std::fmt::Display) -> Self {
        Self::Other(e.to_string())
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotABucket => write!(
                f,
                "state/HEAD points at a directory tree, not a bucket; this namespace is not an S3 face"
            ),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Addresses a delete `Scope` names, via the S3/object map the peer cannot
/// read in `e2ee`. Tombstones contribute nothing.
pub fn addrs_for_scope(repo: &Repo, scope: &Scope) -> Result<Vec<Addr>, String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = BucketStore::new(&blobs, repo.sealer());
    let bucket = match load_published_head(&store, repo) {
        Ok(b) => b,
        Err(LoadError::NotABucket) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for (key, obj) in &bucket.entries {
        let name = String::from_utf8_lossy(key);
        let keep = match scope {
            Scope::Namespace => true,
            Scope::Prefix(p) => name.starts_with(p.as_str()),
            Scope::Object(p) => name == p.as_str(),
        };
        if !keep {
            continue;
        }
        if let Some(m) = &obj.object {
            for c in &m.chunks {
                out.push(c.addr);
            }
        }
    }
    Ok(out)
}

pub fn load_published_head(
    store: &BucketStore<'_>,
    repo: &Repo,
) -> Result<BucketManifest, LoadError> {
    let Some(head) = repo.head() else {
        return Ok(BucketManifest::default());
    };
    let addr = Addr::from_hex(&head)
        .map_err(|_| LoadError::Other(format!("state/HEAD is not an address: {head}")))?;
    match store.load(&repo.dir_root(), &addr) {
        Ok(b) => Ok(b),
        Err(nas_store::BucketError::BadMagic) => Err(LoadError::NotABucket),
        Err(e) => Err(LoadError::Other(e.to_string())),
    }
}

pub fn save_published(
    store: &BucketStore<'_>,
    repo: &Repo,
    bucket: &BucketManifest,
) -> Result<Addr, LoadError> {
    let addr = store
        .store(&repo.dir_root(), bucket)
        .map_err(LoadError::other)?;
    repo.set_head(&addr.to_hex()).map_err(LoadError::io)?;
    Ok(addr)
}

fn load_or_empty(store: &BucketStore<'_>, repo: &Repo) -> Result<BucketManifest, i32> {
    match outbox::working_view(store, repo) {
        Ok(b) => Ok(b),
        Err(LoadError::NotABucket) => Err(err(LoadError::NotABucket)),
        Err(e) => Err(err(e)),
    }
}

fn enqueue_delta(repo: &Repo, key: &[u8], object: KeyObject) -> Result<(), i32> {
    let mut delta = BucketManifest::default();
    if let Err(e) = delta.put(key.to_vec(), object) {
        return Err(err(e));
    }
    let box_ = Outbox::open(&repo.root).map_err(err)?;
    box_.enqueue(&delta).map_err(err)?;
    Ok(())
}

/// `nas put <ns>/<key> <file>`
pub fn put(target: &str, file: &str, subject: Option<&str>) -> i32 {
    let (ns, key) = match split_target(target) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    if !Repo::exists(ns) {
        return err(format!("no namespace {ns}"));
    }
    let src = Path::new(file);
    if !src.is_file() {
        return err(format!("{file} is not a file"));
    }
    let who = match acting_subject(ns, subject) {
        Ok(s) => s,
        Err(e) => return err(e),
    };

    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let store = BucketStore::new(&blobs, repo.sealer());
    let mut bucket = match load_or_empty(&store, &repo) {
        Ok(b) => b,
        Err(c) => return c,
    };

    let overwriting = bucket.live(key.as_bytes()).is_some();
    let need = if overwriting {
        Right::Write
    } else {
        Right::Append
    };
    if let Err(c) = require(ns, who.as_deref(), need) {
        return c;
    }

    let writer = match ObjectWriter::with_defaults(&blobs, repo.sealer(), repo.padding) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let object = match File::open(src) {
        Ok(f) => match writer.write(Kind::File, f) {
            Ok(m) => m,
            Err(e) => return err(e),
        },
        Err(e) => return err(e),
    };
    let size = object.size;
    let wid = match writer_id(&repo) {
        Ok(w) => w,
        Err(c) => return c,
    };
    let entry = KeyObject {
        lamport: bucket.next_lamport(key.as_bytes()),
        writer_id: wid,
        object: Some(object),
    };
    if let Err(e) = bucket.put(key.as_bytes().to_vec(), entry.clone()) {
        return err(e);
    }
    if let Err(c) = enqueue_delta(&repo, key.as_bytes(), entry) {
        return c;
    }
    println!("put {ns}/{key} ({size} B)");
    exit::OK
}

/// `nas rm <ns>/<key>`
pub fn rm(target: &str, subject: Option<&str>) -> i32 {
    let (ns, key) = match split_target(target) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    if !Repo::exists(ns) {
        return err(format!("no namespace {ns}"));
    }
    let who = match acting_subject(ns, subject) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if let Err(c) = require(ns, who.as_deref(), Right::Write) {
        return c;
    }

    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let store = BucketStore::new(&blobs, repo.sealer());
    let mut bucket = match load_or_empty(&store, &repo) {
        Ok(b) => b,
        Err(c) => return c,
    };
    if bucket.live(key.as_bytes()).is_none() {
        return err(format!("no such key {ns}/{key}"));
    }
    let wid = match writer_id(&repo) {
        Ok(w) => w,
        Err(c) => return c,
    };
    let entry = KeyObject {
        lamport: bucket.next_lamport(key.as_bytes()),
        writer_id: wid,
        object: None,
    };
    if let Err(e) = bucket.put(key.as_bytes().to_vec(), entry.clone()) {
        return err(e);
    }
    if let Err(c) = enqueue_delta(&repo, key.as_bytes(), entry) {
        return c;
    }
    println!("deleted {ns}/{key}");
    exit::OK
}

/// `nas ls <ns>` or `nas ls <ns>/<prefix>`
pub fn ls(target: &str) -> i32 {
    let (ns, prefix) = match target.split_once('/') {
        Some((ns, rest)) if !ns.is_empty() => (ns, rest),
        _ if !target.is_empty() && !target.contains('/') => (target, ""),
        _ => return err("usage: nas ls <namespace>[/<prefix>]"),
    };
    if !Repo::exists(ns) {
        return err(format!("no namespace {ns}"));
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let store = BucketStore::new(&blobs, repo.sealer());
    let bucket = match load_or_empty(&store, &repo) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let pref = prefix.as_bytes();
    for (key, e) in &bucket.entries {
        if !pref.is_empty() && !key.starts_with(pref) {
            continue;
        }
        let name = String::from_utf8_lossy(key);
        match &e.object {
            Some(m) => println!("{name}\t{}\tlamport {}", m.size, e.lamport),
            None => println!("{name}\tTOMBSTONE\tlamport {}", e.lamport),
        }
    }
    exit::OK
}

/// `nas get <ns>/<key> <out>` — local read, for the listing to be checkable.
pub fn get(target: &str, out: &str) -> i32 {
    let (ns, key) = match split_target(target) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let store = BucketStore::new(&blobs, repo.sealer());
    let bucket = match load_or_empty(&store, &repo) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let Some(m) = bucket.live(key.as_bytes()) else {
        return err(format!("no such key {ns}/{key}"));
    };
    let mut f = match File::create(out) {
        Ok(f) => f,
        Err(e) => return err(e),
    };
    match read_object(&blobs, m, &mut f) {
        Ok(n) => {
            if let Err(e) = f.flush() {
                return err(e);
            }
            println!("got {ns}/{key} ({n} B) → {out}");
            exit::OK
        }
        Err(e) => err(e),
    }
}

/// Bytes of a live key, for tests that must not go through a file.
pub fn get_bytes(ns: &str, key: &str) -> Result<Vec<u8>, String> {
    let repo = Repo::open_with(ns, crate::repo::passphrase_from(None))
        .map_err(|e| format!("namespace {ns}: {e}"))?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = BucketStore::new(&blobs, repo.sealer());
    let bucket = outbox::working_view(&store, &repo).map_err(|e| e.to_string())?;
    let m = bucket
        .live(key.as_bytes())
        .ok_or_else(|| format!("no such key {ns}/{key}"))?;
    let mut out = Vec::new();
    read_object(&blobs, m, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn map_err(e: impl std::fmt::Display) -> FaceError {
    FaceError::Error(e.to_string())
}

fn check_right(ns: &str, subject: Option<&str>, need: Right) -> Result<(), FaceError> {
    let acl = aclcmd::load(ns).map_err(map_err)?;
    if acl.subjects().next().is_none() {
        return Ok(());
    }
    let Some(subject) = subject else {
        return Err(FaceError::Refused(
            "this namespace has an ACL and no everyday device".into(),
        ));
    };
    let mode = Repo::describe(ns)
        .map_err(|e| FaceError::Error(format!("namespace {ns}: {e}")))?
        .mode;
    let decision = match need {
        Right::Append => {
            let a = acl.check(subject, Right::Append, mode);
            if a.permits() {
                a
            } else {
                acl.check(subject, Right::Write, mode)
            }
        }
        other => acl.check(subject, other, mode),
    };
    match decision {
        Decision::Allowed => Ok(()),
        Decision::Denied | Decision::UnknownSubject => Err(FaceError::Refused(format!(
            "{subject} may not {} on {ns}: {decision}",
            need.as_str()
        ))),
        Decision::NotEnforceable { .. } => Err(FaceError::Error(decision.to_string())),
    }
}

fn open_repo_face(ns: &str) -> Result<Repo, FaceError> {
    Repo::open_with(ns, crate::repo::passphrase_from(None))
        .map_err(|e| FaceError::Error(format!("namespace {ns}: {e}")))
}

/// The localhost S3 + WebDAV face. Each call opens the namespace; the
/// gateway is a shim. The chunk cache is the one exception: it lives for
/// the process (one boot key) so a ranged GET does not refetch.
pub struct LocalBuckets {
    cache: Option<ChunkCache>,
}

impl LocalBuckets {
    pub fn new() -> Self {
        let dir = crate::repo::nas_home().join("state/cache");
        Self {
            cache: ChunkCache::open(dir, DEFAULT_CAP).ok(),
        }
    }
}

impl Default for LocalBuckets {
    fn default() -> Self {
        Self::new()
    }
}

impl Buckets for LocalBuckets {
    fn list_buckets(&self) -> Result<Vec<String>, FaceError> {
        let home = crate::repo::nas_home();
        let rd = match std::fs::read_dir(&home) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(FaceError::Error(e.to_string())),
        };
        let mut names: Vec<String> = rd
            .flatten()
            .filter(|e| e.path().join("config").exists())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        Ok(names)
    }

    fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectInfo>, FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let b = load_or_empty_face(&store, &repo)?;
        let pref = prefix.as_bytes();
        Ok(b.entries
            .iter()
            .filter(|(k, _)| pref.is_empty() || k.starts_with(pref))
            .map(|(k, e)| ObjectInfo {
                key: String::from_utf8_lossy(k).into_owned(),
                size: e.object.as_ref().map(|m| m.size).unwrap_or(0),
                tombstone: e.deleted(),
            })
            .collect())
    }

    fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let b = load_or_empty_face(&store, &repo)?;
        let m = b
            .live(key.as_bytes())
            .ok_or_else(|| FaceError::NotFound(key.into()))?;
        let mut out = Vec::new();
        read_object_range(&blobs, m, 0, u64::MAX, self.cache.as_ref(), &mut out)
            .map_err(map_err)?;
        Ok(out)
    }

    fn get_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<RangeBody, FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let b = load_or_empty_face(&store, &repo)?;
        let m = b
            .live(key.as_bytes())
            .ok_or_else(|| FaceError::NotFound(key.into()))?;
        let total = m.size;
        let start = start.min(total);
        let end = end.min(total).max(start);
        let mut out = Vec::new();
        let (_, stats) = read_object_range(&blobs, m, start, end, self.cache.as_ref(), &mut out)
            .map_err(map_err)?;
        Ok(RangeBody {
            data: out,
            total,
            start,
            end,
            chunks_fetched: stats.chunks_fetched,
            bytes_fetched: stats.bytes_fetched,
        })
    }

    fn put(&self, bucket: &str, key: &str, body: &[u8]) -> Result<u64, FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let who = acting_subject(bucket, None).map_err(map_err)?;
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let mut bkt = load_or_empty_face(&store, &repo)?;
        let overwriting = bkt.live(key.as_bytes()).is_some();
        let need = if overwriting {
            Right::Write
        } else {
            Right::Append
        };
        check_right(bucket, who.as_deref(), need)?;
        let writer =
            ObjectWriter::with_defaults(&blobs, repo.sealer(), repo.padding).map_err(map_err)?;
        let object = writer
            .write(Kind::File, Cursor::new(body))
            .map_err(map_err)?;
        let size = object.size;
        let wid = repo
            .identity(Role::Slot)
            .map(|id| id.id())
            .map_err(map_err)?;
        let entry = KeyObject {
            lamport: bkt.next_lamport(key.as_bytes()),
            writer_id: wid,
            object: Some(object),
        };
        bkt.put(key.as_bytes().to_vec(), entry.clone())
            .map_err(map_err)?;
        enqueue_delta_face(&repo, key.as_bytes(), entry)?;
        Ok(size)
    }

    fn delete(&self, bucket: &str, key: &str) -> Result<(), FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let who = acting_subject(bucket, None).map_err(map_err)?;
        check_right(bucket, who.as_deref(), Right::Write)?;
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let mut bkt = load_or_empty_face(&store, &repo)?;
        if bkt.live(key.as_bytes()).is_none() {
            return Err(FaceError::NotFound(key.into()));
        }
        let wid = repo
            .identity(Role::Slot)
            .map(|id| id.id())
            .map_err(map_err)?;
        let entry = KeyObject {
            lamport: bkt.next_lamport(key.as_bytes()),
            writer_id: wid,
            object: None,
        };
        bkt.put(key.as_bytes().to_vec(), entry.clone())
            .map_err(map_err)?;
        enqueue_delta_face(&repo, key.as_bytes(), entry)?;
        Ok(())
    }

    fn head(&self, bucket: &str, key: &str) -> Result<u64, FaceError> {
        if !Repo::exists(bucket) {
            return Err(FaceError::NotFound(bucket.into()));
        }
        let repo = open_repo_face(bucket)?;
        let blobs = repo.blobs().map_err(map_err)?;
        let store = BucketStore::new(&blobs, repo.sealer());
        let b = load_or_empty_face(&store, &repo)?;
        b.live(key.as_bytes())
            .map(|m| m.size)
            .ok_or_else(|| FaceError::NotFound(key.into()))
    }
}

fn load_or_empty_face(store: &BucketStore<'_>, repo: &Repo) -> Result<BucketManifest, FaceError> {
    match outbox::working_view(store, repo) {
        Ok(b) => Ok(b),
        Err(LoadError::NotABucket) => Err(FaceError::Error(LoadError::NotABucket.to_string())),
        Err(e) => Err(FaceError::Error(e.to_string())),
    }
}

fn enqueue_delta_face(repo: &Repo, key: &[u8], object: KeyObject) -> Result<(), FaceError> {
    let mut delta = BucketManifest::default();
    delta.put(key.to_vec(), object).map_err(map_err)?;
    let box_ = Outbox::open(&repo.root).map_err(map_err)?;
    box_.enqueue(&delta).map_err(map_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_slashes_in_the_key() {
        assert_eq!(
            split_target("records/2024/scan.pdf").unwrap(),
            ("records", "2024/scan.pdf")
        );
        assert!(split_target("records").is_err());
        assert!(split_target("/no-ns").is_err());
        assert!(split_target("ns/").is_err());
    }
}
