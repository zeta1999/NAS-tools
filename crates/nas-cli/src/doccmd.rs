//! Doc face: CRDT op-log, merge, compaction, adaptive poll (SPECS §7, §7.2).

use crate::exit;
use crate::repo::Repo;
use nas_core::{Addr, KeyScheme, Mode, PaddingProfile};
use nas_store::{poll_interval_ms, DocLog, DocStore, POLL_ACTIVE_MS, POLL_IDLE_MS};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn ensure_ns(ns: &str) -> Result<(), String> {
    if Repo::exists(ns) {
        return Ok(());
    }
    Repo::create(
        ns,
        Mode::E2ee,
        KeyScheme::Convergent,
        PaddingProfile::None,
        None,
        None,
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn open_repo(ns: &str) -> Result<Repo, String> {
    Repo::open_with(ns, crate::repo::passphrase_from(None))
        .map_err(|e| format!("namespace {ns}: {e}"))
}

fn writer_of(repo: &Repo) -> Result<[u8; 32], String> {
    Ok(repo
        .identity(nas_crypto::Role::Slot)
        .map_err(|e| e.to_string())?
        .id())
}

fn doc_ptr(repo: &Repo, name: &str) -> PathBuf {
    repo.root.join("state/docs").join(name)
}

fn load_doc(repo: &Repo, name: &str) -> Result<DocLog, String> {
    let Some(hex) = fs::read_to_string(doc_ptr(repo, name)).ok() else {
        return Ok(DocLog::default());
    };
    let addr = Addr::from_hex(hex.trim()).map_err(|e| e.to_string())?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = DocStore::new(&blobs, repo.sealer());
    store
        .load(&repo.dir_root(), &addr)
        .map_err(|e| e.to_string())
}

fn save_doc(repo: &Repo, name: &str, log: &DocLog) -> Result<(), String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = DocStore::new(&blobs, repo.sealer());
    let addr = store
        .store(&repo.dir_root(), log)
        .map_err(|e| e.to_string())?;
    let p = doc_ptr(repo, name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, format!("{}\n", addr.to_hex())).map_err(|e| e.to_string())
}

fn touch_edit(repo: &Repo, name: &str) -> Result<(), String> {
    let p = repo.root.join("state/docs").join(format!("{name}.edited"));
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, b"1").map_err(|e| e.to_string())
}

/// `nas doc get <ns>/<name>`
pub fn get(target: &str) -> i32 {
    let (ns, name) = match target.split_once('/') {
        Some(v) => v,
        None => {
            eprintln!("usage: nas doc get <ns>/<name>");
            return exit::ERROR;
        }
    };
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match load_doc(&repo, name) {
        Ok(log) => match log.text() {
            Ok(t) => {
                print!("{t}");
                exit::OK
            }
            Err(e) => err(e),
        },
        Err(e) => err(e),
    }
}

/// `nas test doc-roundtrip <ns>`
pub fn roundtrip(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let w = match writer_of(&repo) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let mut log = DocLog::default();
    if let Err(e) = log.insert_text(w, 0, "hello-nas") {
        return err(e);
    }
    if let Err(e) = save_doc(&repo, "notes", &log) {
        return err(e);
    }
    let _ = touch_edit(&repo, "notes");
    let got = match load_doc(&repo, "notes") {
        Ok(l) => match l.text() {
            Ok(t) => t,
            Err(e) => return err(e),
        },
        Err(e) => return err(e),
    };
    if got != "hello-nas" {
        return err(format!("round-trip produced {got:?}"));
    }
    println!("doc-roundtrip: {ns}/notes = {got}");
    exit::OK
}

/// `nas test doc-concurrent-merge <ns>`
pub fn concurrent_merge(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let a = [0xA1; 32];
    let b = [0xB2; 32];
    let mut base = DocLog::default();
    if let Err(e) = base.insert_text(a, 0, "xy") {
        return err(e);
    }
    let mut left = base.clone();
    let mut right = base;
    if let Err(e) = left.insert_text(a, 1, "A") {
        return err(e);
    }
    if let Err(e) = right.insert_text(b, 1, "B") {
        return err(e);
    }
    let mut ab = left.clone();
    ab.merge(&right);
    let mut ba = right.clone();
    ba.merge(&left);
    let ta = match ab.text() {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    let tb = match ba.text() {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    if ta != tb {
        return err(format!("merge not commutative: {ta:?} vs {tb:?}"));
    }
    if !(ta.contains('A') && ta.contains('B')) {
        return err(format!("a writer was lost: {ta:?}"));
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = save_doc(&repo, "notes", &ab) {
        return err(e);
    }
    println!("doc-concurrent-merge: both writers survived ({ta})");
    exit::OK
}

/// `nas test doc-oplog-encrypted <ns>`
pub fn oplog_encrypted(ns: &str) -> i32 {
    if roundtrip(ns) != exit::OK {
        return err("need a document to inspect");
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let blobs = repo.blobs_root().join("blobs");
    if !blobs.exists() {
        return err("no blob store");
    }
    let status = Command::new("grep")
        .args(["-rqa", "--", "hello-nas", blobs.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => return err("plaintext found under blobs/ — the op-log leaked"),
        Ok(_) => {}
        Err(e) => return err(e),
    }
    println!("doc-oplog-encrypted: document text is not in the blob store");
    exit::OK
}

/// `nas test doc-compact <ns>`
pub fn compact(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let w = match writer_of(&repo) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let mut log = DocLog::default();
    if let Err(e) = log.insert_text(w, 0, "abcdef") {
        return err(e);
    }
    if let Err(e) = log.delete_range(w, 1, 3) {
        return err(e);
    }
    let before = log.ops.len();
    let compact = match log.compact() {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let text = match compact.text() {
        Ok(t) => t,
        Err(e) => return err(e),
    };
    if text != "aef" {
        return err(format!("compact rewrote the text to {text:?}"));
    }
    if compact.ops.len() >= before {
        return err("compaction did not shrink the op-log");
    }
    if let Err(e) = save_doc(&repo, "notes", &compact) {
        return err(e);
    }
    println!(
        "doc-compact: {before} ops → {}, text {text}",
        compact.ops.len()
    );
    exit::OK
}

/// `nas test doc-poll-active <ns>`
pub fn poll_active(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let ms = poll_interval_ms(0);
    if ms >= 1_000 {
        return err(format!(
            "active poll is {ms} ms; SPECS §7.2 wants sub-second"
        ));
    }
    if ms != POLL_ACTIVE_MS {
        return err(format!("active poll is {ms}, want {POLL_ACTIVE_MS}"));
    }
    println!("doc-poll-active: {ms} ms while editing");
    exit::OK
}

/// `nas test doc-poll-idle <ns>`
pub fn poll_idle(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let ms = poll_interval_ms(60_000);
    if ms < 60_000 {
        return err(format!("idle poll is {ms} ms; SPECS §7.2 wants minutes"));
    }
    if ms != POLL_IDLE_MS {
        return err(format!("idle poll is {ms}, want {POLL_IDLE_MS}"));
    }
    println!("doc-poll-idle: {ms} ms when idle");
    exit::OK
}
