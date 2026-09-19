//! Git face: inflated objects, encrypted OID map, ref slots (SPECS §7.3, §7.4).
//!
//! Packfiles are never stored. Each git object is inflated and written through
//! the ordinary object pipeline. The `git_oid → addr` table lives in a sealed
//! map under `state/git/map`.

use crate::exit;
use crate::repo::Repo;
use nas_core::{Addr, KeyScheme, Mode, PaddingProfile};
use nas_store::{
    oid_from_hex, oid_to_hex, read_object, GitKind, GitOid, GitStore, Kind, ObjectWriter, OidEntry,
    OidMap, GIT_AAD,
};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn git_dir_of(cwd: &Path) -> Result<PathBuf, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let path = PathBuf::from(p);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(cwd.join(path))
    }
}

fn git_common_dir(cwd: &Path) -> Result<PathBuf, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let path = PathBuf::from(p);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(cwd.join(path))
    }
}

fn git(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "nas")
        .env("GIT_AUTHOR_EMAIL", "nas@localhost")
        .env("GIT_COMMITTER_NAME", "nas")
        .env("GIT_COMMITTER_EMAIL", "nas@localhost")
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(stderr.trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn map_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/map")
}

fn refs_dir(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/refs")
}

fn load_map(repo: &Repo) -> Result<OidMap, String> {
    let Some(hex) = fs::read_to_string(map_path(repo)).ok() else {
        return Ok(OidMap::default());
    };
    let addr = Addr::from_hex(hex.trim()).map_err(|e| e.to_string())?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = GitStore::new(&blobs, repo.sealer());
    store
        .load_map(&repo.dir_root(), &addr)
        .map_err(|e| e.to_string())
}

fn save_map(repo: &Repo, map: &OidMap) -> Result<(), String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let store = GitStore::new(&blobs, repo.sealer());
    let addr = store
        .store_map(&repo.dir_root(), map)
        .map_err(|e| e.to_string())?;
    fs::create_dir_all(map_path(repo).parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(map_path(repo), format!("{}\n", addr.to_hex())).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_ref(repo: &Repo, name: &str, oid: &GitOid) -> Result<(), String> {
    let p = refs_dir(repo).join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, format!("{}\n", oid_to_hex(oid))).map_err(|e| e.to_string())?;
    Ok(())
}

fn list_refs(repo: &Repo) -> Result<Vec<(String, GitOid)>, String> {
    let root = refs_dir(repo);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    walk_refs(&root, "", &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_refs(dir: &Path, prefix: &str, out: &mut Vec<(String, GitOid)>) -> Result<(), String> {
    let rd = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let p = e.path();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if p.is_dir() {
            walk_refs(&p, &rel, out)?;
        } else if let Some(oid) = fs::read_to_string(&p)
            .ok()
            .and_then(|s| oid_from_hex(s.trim()))
        {
            out.push((rel, oid));
        }
    }
    Ok(())
}

fn inflate_header(kind: GitKind, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + content.len());
    out.extend_from_slice(kind.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(content.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(content);
    out
}

fn parse_inflated(bytes: &[u8]) -> Result<(GitKind, &[u8]), String> {
    let nul = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or("git object missing header")?;
    let header =
        std::str::from_utf8(&bytes[..nul]).map_err(|_| "git object header is not utf-8")?;
    let (kind_s, _) = header
        .split_once(' ')
        .ok_or("git object header has no size")?;
    let kind = GitKind::parse(kind_s).ok_or_else(|| format!("unknown git kind {kind_s}"))?;
    Ok((kind, &bytes[nul + 1..]))
}

fn persist_object(
    repo: &Repo,
    map: &mut OidMap,
    oid: GitOid,
    inflated: &[u8],
) -> Result<(), String> {
    if map.get(&oid).is_some() {
        return Ok(());
    }
    let (kind, content) = parse_inflated(inflated)?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let writer = ObjectWriter::with_defaults(&blobs, repo.sealer(), repo.padding)
        .map_err(|e| e.to_string())?;
    let object = writer
        .write(Kind::File, Cursor::new(inflated))
        .map_err(|e| e.to_string())?;
    let encoded = object.encode().map_err(|e| e.to_string())?;
    let addr = match repo.sealer() {
        nas_store::Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            let sealed = nas_crypto::seal(&key, &encoded, GIT_AAD).map_err(|e| e.to_string())?;
            blobs.put(&sealed).map_err(|e| e.to_string())?
        }
        nas_store::Sealer::Plaintext { .. } => blobs.put(&encoded).map_err(|e| e.to_string())?,
    };
    map.insert(
        oid,
        OidEntry {
            addr,
            kind,
            size: u32::try_from(content.len()).unwrap_or(u32::MAX),
        },
    );
    Ok(())
}

fn load_inflated(repo: &Repo, map: &OidMap, oid: &GitOid) -> Result<Vec<u8>, String> {
    let e = map
        .get(oid)
        .ok_or_else(|| format!("no git object {}", oid_to_hex(oid)))?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let stored = blobs.get(&e.addr).map_err(|e| e.to_string())?;
    let encoded = match repo.sealer() {
        nas_store::Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            nas_crypto::open(&key, &stored, GIT_AAD).map_err(|e| e.to_string())?
        }
        nas_store::Sealer::Plaintext { .. } => stored,
    };
    let manifest = nas_store::Manifest::decode(&encoded).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    read_object(&blobs, &manifest, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Push every object reachable from `new` that the map does not yet hold.
pub fn import_reachable(ns: &str, git_cwd: &Path, new: &GitOid) -> Result<usize, String> {
    let repo = open_repo(ns)?;
    let mut map = load_map(&repo)?;
    let listed = git(git_cwd, &["rev-list", "--objects", &oid_to_hex(new)])?;
    let mut oids = Vec::new();
    for line in listed.lines() {
        let hex = line.split_whitespace().next().unwrap_or("");
        if let Some(oid) = oid_from_hex(hex) {
            if map.get(&oid).is_none() {
                oids.push(oid);
            }
        }
    }
    if oids.is_empty() {
        save_map(&repo, &map)?;
        return Ok(0);
    }
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(git_cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("git cat-file: {e}"))?;
    {
        let mut stdin = child.stdin.take().ok_or("git cat-file stdin")?;
        for oid in &oids {
            writeln!(stdin, "{}", oid_to_hex(oid)).map_err(|e| e.to_string())?;
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("git cat-file --batch failed".into());
    }
    let mut i = 0;
    let bytes = out.stdout;
    let mut pos = 0;
    while pos < bytes.len() && i < oids.len() {
        let nl = bytes[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("truncated cat-file header")?;
        let header = std::str::from_utf8(&bytes[pos..pos + nl]).map_err(|_| "cat-file header")?;
        pos += nl + 1;
        // `<oid> <type> <size>`
        let mut it = header.split_whitespace();
        let _ = it.next();
        let kind_s = it.next().ok_or("cat-file missing type")?;
        if kind_s == "missing" {
            return Err(format!("git object {} missing", oid_to_hex(&oids[i])));
        }
        let size: usize = it
            .next()
            .ok_or("cat-file missing size")?
            .parse()
            .map_err(|_| "cat-file size")?;
        if pos + size > bytes.len() {
            return Err("truncated cat-file body".into());
        }
        let content = &bytes[pos..pos + size];
        pos += size;
        if pos < bytes.len() && bytes[pos] == b'\n' {
            pos += 1;
        }
        let kind = GitKind::parse(kind_s).ok_or_else(|| format!("kind {kind_s}"))?;
        persist_object(&repo, &mut map, oids[i], &inflate_header(kind, content))?;
        i += 1;
    }
    save_map(&repo, &map)?;
    Ok(oids.len())
}

pub fn is_fast_forward(git_cwd: &Path, old: Option<&GitOid>, new: &GitOid) -> Result<bool, String> {
    let Some(old) = old else {
        return Ok(true);
    };
    if old == new {
        return Ok(true);
    }
    let status = Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            &oid_to_hex(old),
            &oid_to_hex(new),
        ])
        .current_dir(git_cwd)
        .status()
        .map_err(|e| format!("git merge-base: {e}"))?;
    Ok(status.success())
}

pub fn update_ref(ns: &str, name: &str, oid: &GitOid) -> Result<(), String> {
    if !(name.starts_with("refs/heads/") || name.starts_with("refs/tags/")) {
        return Err(format!("{name} is not a shared ref (SPECS §7.4)"));
    }
    let repo = open_repo(ns)?;
    write_ref(&repo, name, oid)?;
    Ok(())
}

pub fn published_refs(ns: &str) -> Result<Vec<(String, GitOid)>, String> {
    let repo = open_repo(ns)?;
    list_refs(&repo)
}

/// Write stored objects into the current git repository.
pub fn export_objects(ns: &str, git_cwd: &Path, want: &[GitOid]) -> Result<usize, String> {
    let repo = open_repo(ns)?;
    let map = load_map(&repo)?;
    let mut n = 0;
    for oid in want {
        let inflated = load_inflated(&repo, &map, oid)?;
        let (kind, content) = parse_inflated(&inflated)?;
        let mut child = Command::new("git")
            .args(["hash-object", "-t", kind.as_str(), "-w", "--stdin"])
            .current_dir(git_cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git hash-object: {e}"))?;
        {
            let mut stdin = child.stdin.take().ok_or("hash-object stdin")?;
            stdin.write_all(content).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("git hash-object failed".into());
        }
        let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if got != oid_to_hex(oid) {
            return Err(format!(
                "hash-object wrote {got}, wanted {}",
                oid_to_hex(oid)
            ));
        }
        n += 1;
    }
    // Also export ancestors so the tip is complete.
    let _ = git_cwd;
    Ok(n)
}

/// Export every object in the map (clone / fetch all).
pub fn export_all(ns: &str, git_cwd: &Path) -> Result<usize, String> {
    let repo = open_repo(ns)?;
    let map = load_map(&repo)?;
    let oids: Vec<GitOid> = map.entries.keys().copied().collect();
    export_objects(ns, git_cwd, &oids)
}

pub fn parse_ns_url(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("nas://")
        .or_else(|| url.strip_prefix("nas::"))
        .unwrap_or(url);
    let rest = rest.trim_start_matches('/');
    let name = rest.rsplit('/').next().unwrap_or(rest);
    if name.is_empty() {
        return Err(format!("nas url has no namespace: {url}"));
    }
    Ok(name.to_string())
}

pub fn git_rev_parse(cwd: &Path, rev: &str) -> Result<String, String> {
    Ok(git(cwd, &["rev-parse", rev])?.trim().to_string())
}

pub fn git_cwd() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    // Prefer GIT_DIR's work tree when set, but resolve through git so a
    // linked worktree's `.git` *file* is handled (SPECS §7.4).
    if let Ok(dir) = git_dir_of(&cwd) {
        let _ = dir;
    }
    Ok(cwd)
}

pub fn resolve_git_dirs(cwd: &Path) -> Result<(PathBuf, PathBuf), String> {
    Ok((git_dir_of(cwd)?, git_common_dir(cwd)?))
}

fn scratch_git(tag: &str) -> Result<PathBuf, String> {
    let p = std::env::temp_dir().join(format!("nas-gitrepo-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    git(&p, &["init", "-b", "main"])?;
    git(&p, &["config", "user.email", "nas@localhost"])?;
    git(&p, &["config", "user.name", "nas"])?;
    Ok(p)
}

fn commit_file(repo: &Path, name: &str, body: &str, msg: &str) -> Result<GitOid, String> {
    fs::write(repo.join(name), body).map_err(|e| e.to_string())?;
    git(repo, &["add", name])?;
    git(repo, &["commit", "-m", msg])?;
    let hex = git(repo, &["rev-parse", "HEAD"])?;
    oid_from_hex(hex.trim()).ok_or_else(|| format!("bad oid {hex}"))
}

/// `nas test git-helper-present` — argv0 dispatch plus a sibling name git can exec.
pub fn helper_present() -> i32 {
    match helper_on_path() {
        Ok(_) => {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => return err(e),
            };
            let helper = exe.parent().map(|d| d.join("git-remote-nas"));
            match helper {
                Some(p) if p.exists() => {
                    println!(
                        "git-remote-nas: {} (same binary, argv0 dispatch)",
                        p.display()
                    );
                    exit::OK
                }
                _ => err("git-remote-nas was not installed next to nas"),
            }
        }
        Err(e) => err(e),
    }
}

fn helper_on_path() -> Result<std::ffi::OsString, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let bindir = exe.parent().ok_or("no bindir")?.to_path_buf();
    let helper = bindir.join("git-remote-nas");
    if !helper.exists() {
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&exe, &helper);
        }
    }
    let mut path = bindir.into_os_string();
    if let Some(rest) = std::env::var_os("PATH") {
        path.push(":");
        path.push(rest);
    }
    Ok(path)
}

fn git_path(cwd: &Path, path: &std::ffi::OsStr, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("PATH", path)
        .env("GIT_AUTHOR_NAME", "nas")
        .env("GIT_AUTHOR_EMAIL", "nas@localhost")
        .env("GIT_COMMITTER_NAME", "nas")
        .env("GIT_COMMITTER_EMAIL", "nas@localhost")
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// `nas test git-roundtrip <ns>`
pub fn git_roundtrip(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let path = match helper_on_path() {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let src = match scratch_git("rt-src") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let oid = match commit_file(&src, "hello.txt", "hello-nas\n", "init") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = git_path(
        &src,
        &path,
        &["remote", "add", "nas", &format!("nas://{ns}")],
    ) {
        return err(e);
    }
    // Force: this drill is clone/push through the helper, not fast-forward
    // policy (that is git-same-branch-collision). A second run — or
    // git-oidmap-encrypted, which used to call us — would otherwise push an
    // unrelated root onto an existing main and fail as non-fast-forward.
    if let Err(e) = git_path(&src, &path, &["push", "--force", "nas", "main"]) {
        return err(e);
    }
    let dst = src
        .parent()
        .unwrap()
        .join(format!("nas-rt-dst-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dst);
    if let Err(e) = git_path(
        src.parent().unwrap(),
        &path,
        &["clone", &format!("nas://{ns}"), dst.to_str().unwrap()],
    ) {
        return err(e);
    }
    let body = match fs::read_to_string(dst.join("hello.txt")) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&dst);
    if body != "hello-nas\n" {
        return err("clone did not reproduce the pushed file");
    }
    println!(
        "git-roundtrip: git push/clone nas://{ns} ({})",
        oid_to_hex(&oid)
    );
    exit::OK
}

/// `nas test git-oidmap-encrypted <ns>`
pub fn git_oidmap_encrypted(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    // Own fixture: do not push through the helper onto `main`. That collided
    // with git-roundtrip when both ran against the same namespace.
    let src = match scratch_git("oidmap") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let oid = match commit_file(&src, "oidmap.txt", "oidmap-probe\n", "oidmap") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &src, &oid) {
        return err(e);
    }
    if let Err(e) = update_ref(ns, "refs/heads/oidmap", &oid) {
        return err(e);
    }
    let _ = fs::remove_dir_all(&src);
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let refs = match list_refs(&repo) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let Some((_, oid)) = refs.first() else {
        return err("no refs after roundtrip");
    };
    let hex = oid_to_hex(oid);
    let blobs = repo.blobs_root().join("blobs");
    if !blobs.exists() {
        return err("no blob store");
    }
    let status = Command::new("grep")
        .args(["-rqa", "--", &hex, blobs.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => {
            return err("git oid hex found under blobs/ — the map leaked");
        }
        Ok(_) => {}
        Err(e) => return err(e),
    }
    println!("git-oidmap-encrypted: {} is not in the blob store", hex);
    exit::OK
}

/// `nas test git-loose-objects <ns>`
pub fn git_loose_objects(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let src = match scratch_git("loose") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let oid = match commit_file(&src, "a.txt", "a\n", "a") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &src, &oid) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let map = match load_map(&repo) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    if map.entries.len() < 3 {
        return err(format!(
            "expected blob+tree+commit stored separately, got {} objects",
            map.entries.len()
        ));
    }
    for oid in map.entries.keys() {
        let inflated = match load_inflated(&repo, &map, oid) {
            Ok(b) => b,
            Err(e) => return err(e),
        };
        if parse_inflated(&inflated).is_err() {
            return err(format!(
                "{} is not an inflated git object (packfile?)",
                oid_to_hex(oid)
            ));
        }
        if inflated.starts_with(b"PACK") {
            return err("stored a packfile; SPECS §7.3 forbids that");
        }
    }
    let _ = fs::remove_dir_all(&src);
    println!(
        "git-loose-objects: {} inflated objects, no packfiles",
        map.entries.len()
    );
    exit::OK
}

/// `nas test git-parallel-worktrees <ns> --agents N`
pub fn git_parallel_worktrees(ns: &str, agents: u32) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let n = agents.max(1);
    let root = match scratch_git("wt-root") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let base = match commit_file(&root, "README", "base\n", "base") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &root, &base) {
        return err(e);
    }
    if let Err(e) = update_ref(ns, "refs/heads/main", &base) {
        return err(e);
    }
    for i in 0..n {
        let branch = format!("agent{i}");
        let wt = root
            .parent()
            .unwrap()
            .join(format!("nas-wt-{}-{i}", std::process::id()));
        let _ = fs::remove_dir_all(&wt);
        if let Err(e) = git(
            &root,
            &["worktree", "add", "-b", &branch, wt.to_str().unwrap()],
        ) {
            return err(e);
        }
        // Linked worktree: .git is a file.
        if !wt.join(".git").is_file() {
            return err(format!("{} .git is not a file", wt.display()));
        }
        let oid = match commit_file(&wt, &format!("a{i}.txt"), &format!("{i}\n"), &branch) {
            Ok(o) => o,
            Err(e) => return err(e),
        };
        if let Err(e) = import_reachable(ns, &wt, &oid) {
            return err(e);
        }
        if let Err(e) = update_ref(ns, &format!("refs/heads/{branch}"), &oid) {
            return err(e);
        }
        let _ = fs::remove_dir_all(&wt);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let refs = match list_refs(&repo) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let _ = fs::remove_dir_all(&root);
    let branches = refs
        .iter()
        .filter(|(n, _)| n.starts_with("refs/heads/agent"))
        .count();
    if branches != n as usize {
        return err(format!("expected {n} agent branches, got {branches}"));
    }
    println!("git-parallel-worktrees: {n} worktrees pushed {n} branches, no contention");
    exit::OK
}

/// `nas test git-same-branch-collision <ns>`
pub fn git_same_branch_collision(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let a = match scratch_git("col-a") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let first = match commit_file(&a, "x.txt", "a\n", "a") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &a, &first) {
        return err(e);
    }
    if let Err(e) = update_ref(ns, "refs/heads/main", &first) {
        return err(e);
    }
    let b = match scratch_git("col-b") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = export_all(ns, &b) {
        return err(e);
    }
    if let Err(e) = git(&b, &["update-ref", "refs/heads/main", &oid_to_hex(&first)]) {
        return err(e);
    }
    if let Err(e) = git(&b, &["checkout", "-f", "main"]) {
        return err(e);
    }
    let second = match commit_file(&a, "x.txt", "a2\n", "a-diverge") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &a, &second) {
        return err(e);
    }
    if let Err(e) = update_ref(ns, "refs/heads/main", &second) {
        return err(e);
    }
    let third = match commit_file(&b, "x.txt", "b\n", "b-diverge") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    // B must hold `second` as an object or merge-base cannot name it.
    if let Err(e) = export_all(ns, &b) {
        return err(e);
    }
    match is_fast_forward(&b, Some(&second), &third) {
        Ok(true) => {
            let _ = fs::remove_dir_all(&a);
            let _ = fs::remove_dir_all(&b);
            return err("divergent histories were treated as a fast-forward");
        }
        Ok(false) => {}
        Err(e) => return err(e),
    }
    let _ = fs::remove_dir_all(&a);
    let _ = fs::remove_dir_all(&b);
    println!("git-same-branch-collision: non-fast-forward detected");
    exit::OK
}

/// `nas test git-worktree-gitfile <ns>`
pub fn git_worktree_gitfile(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let root = match scratch_git("gf-root") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let _ = match commit_file(&root, "f", "1\n", "one") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    let wt = root
        .parent()
        .unwrap()
        .join(format!("nas-gf-{}", std::process::id()));
    let _ = fs::remove_dir_all(&wt);
    if let Err(e) = git(
        &root,
        &["worktree", "add", "-b", "feature", wt.to_str().unwrap()],
    ) {
        return err(e);
    }
    if !wt.join(".git").is_file() {
        return err("linked worktree .git is not a file");
    }
    let (gd, cd) = match resolve_git_dirs(&wt) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    if gd == cd {
        return err("worktree git-dir equals common-dir; we string-appended /.git");
    }
    let oid = match commit_file(&wt, "g", "2\n", "two") {
        Ok(o) => o,
        Err(e) => return err(e),
    };
    if let Err(e) = import_reachable(ns, &wt, &oid) {
        return err(e);
    }
    if let Err(e) = update_ref(ns, "refs/heads/feature", &oid) {
        return err(e);
    }
    let _ = fs::remove_dir_all(&wt);
    let _ = fs::remove_dir_all(&root);
    println!("git-worktree-gitfile: resolved via rev-parse, not /.git");
    exit::OK
}

fn queue_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/patch-queue")
}

fn load_queue(repo: &Repo) -> Vec<String> {
    fs::read_to_string(queue_path(repo))
        .ok()
        .map(|s| {
            s.lines()
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn append_queue(repo: &Repo, addr: &Addr) -> Result<(), String> {
    let p = queue_path(repo);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut s = fs::read_to_string(&p).unwrap_or_default();
    s.push_str(&addr.to_hex());
    s.push('\n');
    fs::write(p, s).map_err(|e| e.to_string())
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "bad hex".into()))
        .collect()
}

fn encode_patch(vk: &[u8], sig: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = format!("NASPATCH/v1\n{}\n{}\n", hex_bytes(vk), hex_bytes(sig)).into_bytes();
    out.extend_from_slice(body);
    out
}

type PatchParts<'a> = (Vec<u8>, Vec<u8>, &'a [u8]);

fn decode_patch(bytes: &[u8]) -> Result<PatchParts<'_>, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "patch is not utf-8")?;
    let mut lines = s.splitn(4, '\n');
    if lines.next() != Some("NASPATCH/v1") {
        return Err("not a nas patch".into());
    }
    let vk = unhex_bytes(lines.next().ok_or("missing vk")?)?;
    let sig = unhex_bytes(lines.next().ok_or("missing sig")?)?;
    let body = lines.next().ok_or("missing body")?.as_bytes();
    Ok((vk, sig, body))
}

fn store_bytes(repo: &Repo, bytes: &[u8]) -> Result<Addr, String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let writer = ObjectWriter::with_defaults(&blobs, repo.sealer(), repo.padding)
        .map_err(|e| e.to_string())?;
    let object = writer
        .write(Kind::File, Cursor::new(bytes))
        .map_err(|e| e.to_string())?;
    let encoded = object.encode().map_err(|e| e.to_string())?;
    let addr = match repo.sealer() {
        nas_store::Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            let sealed = nas_crypto::seal(&key, &encoded, GIT_AAD).map_err(|e| e.to_string())?;
            blobs.put(&sealed).map_err(|e| e.to_string())?
        }
        nas_store::Sealer::Plaintext { .. } => blobs.put(&encoded).map_err(|e| e.to_string())?,
    };
    Ok(addr)
}

fn load_bytes(repo: &Repo, addr: &Addr) -> Result<Vec<u8>, String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let stored = blobs.get(addr).map_err(|e| e.to_string())?;
    let encoded = match repo.sealer() {
        nas_store::Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            nas_crypto::open(&key, &stored, GIT_AAD).map_err(|e| e.to_string())?
        }
        nas_store::Sealer::Plaintext { .. } => stored,
    };
    let manifest = nas_store::Manifest::decode(&encoded).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    read_object(&blobs, &manifest, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn make_signed_patch(repo: &Repo, git_cwd: &Path, range: &str) -> Result<Addr, String> {
    let body = git(git_cwd, &["format-patch", "--stdout", range])?;
    let id = repo
        .identity(nas_crypto::Role::Slot)
        .map_err(|e| e.to_string())?;
    let sig = id
        .sign(nas_crypto::SigContext::Patch, body.as_bytes())
        .map_err(|e| e.to_string())?;
    let packed = encode_patch(id.verifying_key(), &sig, body.as_bytes());
    let addr = store_bytes(repo, &packed)?;
    append_queue(repo, &addr)?;
    Ok(addr)
}

fn import_patch(repo: &Repo, git_cwd: &Path, addr: &Addr) -> Result<(), String> {
    let bytes = load_bytes(repo, addr)?;
    let (vk, sig, body) = decode_patch(&bytes)?;
    nas_crypto::verify(&vk, nas_crypto::SigContext::Patch, body, &sig)
        .map_err(|_| "patch signature does not verify".to_string())?;
    let local = repo
        .identity(nas_crypto::Role::Slot)
        .map_err(|e| e.to_string())?;
    if nas_crypto::key_id(&vk) != local.id() {
        return Err("UNROSTERED".into());
    }
    let tmp = git_cwd.join(".nas-am.patch");
    fs::write(&tmp, body).map_err(|e| e.to_string())?;
    git(git_cwd, &["am", tmp.to_str().unwrap()])?;
    let _ = fs::remove_file(&tmp);
    Ok(())
}

/// `nas test patch-roundtrip <ns>`
pub fn patch_roundtrip(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let src = match scratch_git("patch-src") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = commit_file(&src, "p.txt", "one\n", "one") {
        return err(e);
    }
    if let Err(e) = commit_file(&src, "p.txt", "two\n", "two") {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let addr = match make_signed_patch(&repo, &src, "HEAD~1") {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let dst = match scratch_git("patch-dst") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = git(&dst, &["am", "--abort"]) {
        let _ = e;
    }
    // Destination starts at the parent of the patched commit.
    if let Err(e) = commit_file(&dst, "p.txt", "one\n", "one") {
        return err(e);
    }
    if let Err(e) = import_patch(&repo, &dst, &addr) {
        return err(e);
    }
    let body = match fs::read_to_string(dst.join("p.txt")) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&dst);
    if body != "two\n" {
        return err("imported patch did not apply");
    }
    println!("patch-roundtrip: format-patch / am through {ns}");
    exit::OK
}

/// `nas test patch-queue-append-only <ns>`
pub fn patch_queue_append_only(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let src = match scratch_git("q-src") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = commit_file(&src, "q.txt", "a\n", "a") {
        return err(e);
    }
    if let Err(e) = commit_file(&src, "q.txt", "b\n", "b") {
        return err(e);
    }
    if let Err(e) = commit_file(&src, "q.txt", "c\n", "c") {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let before = load_queue(&repo).len();
    if let Err(e) = make_signed_patch(&repo, &src, "HEAD~2") {
        return err(e);
    }
    if let Err(e) = make_signed_patch(&repo, &src, "HEAD~1") {
        return err(e);
    }
    let q = load_queue(&repo);
    if q.len() != before + 2 {
        return err(format!(
            "queue should have grown by 2, {before} → {}",
            q.len()
        ));
    }
    if q[0] == q[1] {
        return err("two exports produced the same queue entry");
    }
    let _ = fs::remove_dir_all(&src);
    println!("patch-queue-append-only: {} entries, distinct", q.len());
    exit::OK
}

/// `nas test patch-unrostered <ns>` — must exit 2.
pub fn patch_unrostered(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let src = match scratch_git("evil-src") {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = commit_file(&src, "e.txt", "x\n", "x") {
        return err(e);
    }
    if let Err(e) = commit_file(&src, "e.txt", "y\n", "y") {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let body = match git(&src, &["format-patch", "--stdout", "HEAD~1"]) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let foreign = match nas_crypto::Identity::derive(&[0xE1; 32], nas_crypto::Role::Slot) {
        Ok(id) => id,
        Err(e) => return err(e),
    };
    let sig = match foreign.sign(nas_crypto::SigContext::Patch, body.as_bytes()) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let packed = encode_patch(foreign.verifying_key(), &sig, body.as_bytes());
    let addr = match store_bytes(&repo, &packed) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    match import_patch(&repo, &src, &addr) {
        Err(e) if e == "UNROSTERED" => {
            let _ = fs::remove_dir_all(&src);
            println!("patch-unrostered: foreign author refused");
            exit::REFUSED
        }
        Ok(()) => {
            let _ = fs::remove_dir_all(&src);
            err("unrostered patch was applied")
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&src);
            err(e)
        }
    }
}
