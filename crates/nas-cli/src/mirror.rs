//! Filtered public mirror (SPECS §7.6 / UC06).
//!
//! A filtered mirror is a *derived* repository: path rules rewrite history, so
//! every public SHA differs from its private source. The `private_sha →
//! public_sha` map is sealed in the namespace; without it every re-publish
//! invents new SHAs and force-pushes. Rules fail closed. Publish requires a
//! dry run, a secret scan, and a signature under `SigContext::MirrorPublish`.

use crate::exit;
use crate::gitcmd::{export_all, import_reachable, published_refs, update_ref};
use crate::repo::Repo;
use nas_core::{Addr, KeyScheme, Mode, PaddingProfile};
use nas_store::{
    oid_from_hex, oid_to_hex, read_object, GitOid, Kind, Manifest, ObjectWriter, Sealer,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MIRROR_AAD: &[u8] = b"nas-tools/aad/git-shamap/v1";
const PLANTED_SECRET: &str = "NAS_PLANTED_SECRET";

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn refuse(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::REFUSED
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
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn scratch_git(tag: &str) -> Result<PathBuf, String> {
    let p = std::env::temp_dir().join(format!("nas-mirror-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    git(&p, &["init", "-b", "main"])?;
    git(&p, &["config", "user.email", "nas@localhost"])?;
    git(&p, &["config", "user.name", "nas"])?;
    Ok(p)
}

fn write_file(root: &Path, rel: &str, body: &str) -> Result<(), String> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, body).map_err(|e| e.to_string())
}

fn commit_files(repo: &Path, files: &[(&str, &str)], msg: &str) -> Result<GitOid, String> {
    for (name, body) in files {
        write_file(repo, name, body)?;
        git(repo, &["add", name])?;
    }
    git(repo, &["commit", "-m", msg])?;
    let hex = git(repo, &["rev-parse", "HEAD"])?;
    oid_from_hex(hex.trim()).ok_or_else(|| format!("bad oid {hex}"))
}

fn rules_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/mirror.rules")
}

fn receipt_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/mirror-dryrun")
}

fn shamap_ptr(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/mirror-shamap")
}

fn public_dir(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/public")
}

fn approval_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/git/mirror-approval")
}

#[derive(Clone, Debug)]
struct Rules {
    exclude_paths: Vec<String>,
    drop_empty_commits: bool,
    filter_messages: bool,
}

impl Rules {
    fn default_pub() -> Self {
        Self {
            exclude_paths: vec!["fixes/**".into(), "internal/**".into()],
            drop_empty_commits: true,
            filter_messages: true,
        }
    }

    fn encode(&self) -> String {
        format!(
            "exclude_paths={}\ndrop_empty_commits={}\nfilter_messages={}\n",
            self.exclude_paths.join(","),
            self.drop_empty_commits,
            self.filter_messages
        )
    }

    fn hash(&self) -> String {
        hex_bytes(blake3::hash(self.encode().as_bytes()).as_bytes())
    }
}

fn validate_glob(pat: &str) -> Result<(), String> {
    if pat.is_empty() {
        return Err("empty exclude glob".into());
    }
    let opens = pat.bytes().filter(|b| *b == b'[').count();
    let closes = pat.bytes().filter(|b| *b == b']').count();
    if opens != closes {
        return Err(format!("malformed glob {pat:?}: unbalanced brackets"));
    }
    Ok(())
}

fn parse_bool(s: &str, key: &str) -> Result<bool, String> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{key} must be true or false, got {s:?}")),
    }
}

fn parse_rules(text: &str) -> Result<Rules, String> {
    let mut rules = Rules {
        exclude_paths: Vec::new(),
        drop_empty_commits: true,
        filter_messages: true,
    };
    let mut saw_excludes = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: not key=value", i + 1))?;
        let k = k.trim();
        let v = v.trim();
        match k {
            "exclude_paths" => {
                if v.is_empty() {
                    return Err("exclude_paths is empty".into());
                }
                let mut globs = Vec::new();
                for g in v.split(',') {
                    let g = g.trim();
                    validate_glob(g)?;
                    globs.push(g.to_string());
                }
                rules.exclude_paths = globs;
                saw_excludes = true;
            }
            "drop_empty_commits" => rules.drop_empty_commits = parse_bool(v, k)?,
            "filter_messages" => rules.filter_messages = parse_bool(v, k)?,
            other => return Err(format!("unknown rule {other:?}")),
        }
    }
    if !saw_excludes {
        return Err("exclude_paths is required".into());
    }
    Ok(rules)
}

fn load_rules(repo: &Repo) -> Result<Rules, String> {
    let p = rules_path(repo);
    if !p.exists() {
        let r = Rules::default_pub();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&p, r.encode()).map_err(|e| e.to_string())?;
        return Ok(r);
    }
    let text = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    parse_rules(&text)
}

fn write_rules(repo: &Repo, text: &str) -> Result<(), String> {
    let p = rules_path(repo);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, text).map_err(|e| e.to_string())
}

fn write_defaults(repo: &Repo) -> Result<Rules, String> {
    let r = Rules::default_pub();
    write_rules(repo, &r.encode())?;
    Ok(r)
}

fn glob_match(pat: &str, path: &str) -> bool {
    let pat: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    glob_rec(&pat, &path)
}

fn glob_rec(pat: &[&str], path: &[&str]) -> bool {
    match pat.first().copied() {
        None => path.is_empty(),
        Some("**") => {
            if glob_rec(&pat[1..], path) {
                return true;
            }
            if !path.is_empty() && glob_rec(pat, &path[1..]) {
                return true;
            }
            false
        }
        Some(p) => {
            if path.is_empty() {
                return false;
            }
            if !seg_match(p, path[0]) {
                return false;
            }
            glob_rec(&pat[1..], &path[1..])
        }
    }
}

fn seg_match(pat: &str, seg: &str) -> bool {
    if !pat.contains('*') && !pat.contains('?') {
        return pat == seg;
    }
    glob_seg(pat.as_bytes(), seg.as_bytes())
}

fn glob_seg(pat: &[u8], seg: &[u8]) -> bool {
    match (pat.first(), seg.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            if glob_seg(&pat[1..], seg) {
                return true;
            }
            if !seg.is_empty() && glob_seg(pat, &seg[1..]) {
                return true;
            }
            false
        }
        (Some(b'?'), Some(_)) => glob_seg(&pat[1..], &seg[1..]),
        (Some(a), Some(b)) if a == b => glob_seg(&pat[1..], &seg[1..]),
        _ => false,
    }
}

fn excluded(path: &str, rules: &Rules) -> bool {
    rules.exclude_paths.iter().any(|g| glob_match(g, path))
}

#[derive(Clone, Debug, Default)]
struct ShaMap {
    entries: BTreeMap<String, String>,
}

impl ShaMap {
    fn encode(&self) -> String {
        let mut s = String::from("NASM/v1\n");
        for (k, v) in &self.entries {
            s.push_str(k);
            s.push(' ');
            s.push_str(v);
            s.push('\n');
        }
        s
    }

    fn decode(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        match lines.next() {
            Some("NASM/v1") => {}
            _ => return Err("not a nas shamap".into()),
        }
        let mut entries = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (a, b) = line.split_once(' ').ok_or("ragged shamap line")?;
            entries.insert(a.to_string(), b.to_string());
        }
        Ok(Self { entries })
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
        Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            let sealed = nas_crypto::seal(&key, &encoded, MIRROR_AAD).map_err(|e| e.to_string())?;
            blobs.put(&sealed).map_err(|e| e.to_string())?
        }
        Sealer::Plaintext { .. } => blobs.put(&encoded).map_err(|e| e.to_string())?,
    };
    Ok(addr)
}

fn load_bytes(repo: &Repo, addr: &Addr) -> Result<Vec<u8>, String> {
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let stored = blobs.get(addr).map_err(|e| e.to_string())?;
    let encoded = match repo.sealer() {
        Sealer::Convergent(_) => {
            let key = nas_crypto::manifest_key(&repo.dir_root());
            nas_crypto::open(&key, &stored, MIRROR_AAD).map_err(|e| e.to_string())?
        }
        Sealer::Plaintext { .. } => stored,
    };
    let manifest = Manifest::decode(&encoded).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    read_object(&blobs, &manifest, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn load_shamap(repo: &Repo) -> Result<ShaMap, String> {
    let Some(hex) = fs::read_to_string(shamap_ptr(repo)).ok() else {
        return Ok(ShaMap::default());
    };
    let addr = Addr::from_hex(hex.trim()).map_err(|e| e.to_string())?;
    let bytes = load_bytes(repo, &addr)?;
    let text = String::from_utf8(bytes).map_err(|_| "shamap is not utf-8")?;
    ShaMap::decode(&text)
}

fn save_shamap(repo: &Repo, map: &ShaMap) -> Result<(), String> {
    let addr = store_bytes(repo, map.encode().as_bytes())?;
    if let Some(parent) = shamap_ptr(repo).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(shamap_ptr(repo), format!("{}\n", addr.to_hex())).map_err(|e| e.to_string())
}

fn write_receipt(repo: &Repo, rules: &Rules, head: &str) -> Result<(), String> {
    let p = receipt_path(repo);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(p, format!("{}\n{head}\n", rules.hash())).map_err(|e| e.to_string())
}

fn clear_receipt(repo: &Repo) {
    let _ = fs::remove_file(receipt_path(repo));
}

fn has_receipt(repo: &Repo) -> bool {
    receipt_path(repo).exists()
}

fn materialize_private(ns: &str) -> Result<PathBuf, String> {
    let tmp = scratch_git("priv")?;
    export_all(ns, &tmp)?;
    let refs = published_refs(ns).unwrap_or_default();
    for (name, oid) in &refs {
        if name.starts_with("refs/heads/") || name.starts_with("refs/tags/") {
            git(&tmp, &["update-ref", name, &oid_to_hex(oid)])?;
        }
    }
    if refs.iter().any(|(n, _)| n == "refs/heads/main") {
        let _ = git(&tmp, &["checkout", "-f", "main"]);
    }
    Ok(tmp)
}

struct TreeEnt {
    mode: String,
    oid: String,
    path: String,
}

fn ls_tree(cwd: &Path, rev: &str) -> Result<Vec<TreeEnt>, String> {
    let out = git(cwd, &["ls-tree", "-r", rev])?;
    let mut ents = Vec::new();
    for line in out.lines() {
        // <mode> <type> <oid>\t<path>
        let (meta, path) = line.split_once('\t').ok_or("ls-tree: no tab")?;
        let mut it = meta.split_whitespace();
        let mode = it.next().ok_or("ls-tree mode")?.to_string();
        let _kind = it.next();
        let oid = it.next().ok_or("ls-tree oid")?.to_string();
        ents.push(TreeEnt {
            mode,
            oid,
            path: path.to_string(),
        });
    }
    Ok(ents)
}

struct CommitMeta {
    parents: Vec<String>,
    author_name: String,
    author_email: String,
    author_date: String,
    committer_name: String,
    committer_email: String,
    committer_date: String,
    message: String,
}

fn parse_ident(s: &str) -> Result<(String, String, String), String> {
    let (name, rest) = s.split_once(" <").ok_or("commit ident: no <")?;
    let (email, date) = rest.split_once("> ").ok_or("commit ident: no >")?;
    Ok((name.to_string(), email.to_string(), date.to_string()))
}

fn parse_commit(cwd: &Path, hex: &str) -> Result<CommitMeta, String> {
    let raw = git(cwd, &["cat-file", "commit", hex])?;
    let (header, message) = raw.split_once("\n\n").ok_or("commit has no body")?;
    let mut parents = Vec::new();
    let mut author = None;
    let mut committer = None;
    for line in header.lines() {
        if let Some(p) = line.strip_prefix("parent ") {
            parents.push(p.to_string());
        } else if let Some(a) = line.strip_prefix("author ") {
            author = Some(parse_ident(a)?);
        } else if let Some(c) = line.strip_prefix("committer ") {
            committer = Some(parse_ident(c)?);
        }
    }
    let (author_name, author_email, author_date) = author.ok_or("commit has no author")?;
    let (committer_name, committer_email, committer_date) =
        committer.ok_or("commit has no committer")?;
    Ok(CommitMeta {
        parents,
        author_name,
        author_email,
        author_date,
        committer_name,
        committer_email,
        committer_date,
        message: message.to_string(),
    })
}

fn copy_blob(src: &Path, dst: &Path, oid: &str) -> Result<(), String> {
    let mut child = Command::new("git")
        .args(["cat-file", "blob", oid])
        .current_dir(src)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("cat-file stdout")?;
    let hashed = Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(dst)
        .stdin(stdout)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = child.wait();
    if !hashed.status.success() {
        return Err("hash-object failed while copying a blob".into());
    }
    let got = String::from_utf8_lossy(&hashed.stdout).trim().to_string();
    if got != oid {
        return Err(format!("copied blob {got}, wanted {oid}"));
    }
    Ok(())
}

fn write_tree(dst: &Path, files: &[TreeEnt]) -> Result<String, String> {
    let index = dst.join(".git/nas-mirror-index");
    let _ = fs::remove_file(&index);
    if files.is_empty() {
        // Empty tree. git write-tree on an empty index.
        let out = Command::new("git")
            .args(["write-tree"])
            .current_dir(dst)
            .env("GIT_INDEX_FILE", &index)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    for f in files {
        let spec = format!("{},{},{}", f.mode, f.oid, f.path);
        let st = Command::new("git")
            .args(["update-index", "--add", "--cacheinfo", &spec])
            .current_dir(dst)
            .env("GIT_INDEX_FILE", &index)
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err(format!("update-index failed for {}", f.path));
        }
    }
    let out = Command::new("git")
        .args(["write-tree"])
        .current_dir(dst)
        .env("GIT_INDEX_FILE", &index)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn tree_of(cwd: &Path, rev: &str) -> Result<String, String> {
    Ok(git(cwd, &["rev-parse", &format!("{rev}^{{tree}}")])?
        .trim()
        .to_string())
}

fn filter_msg(msg: &str, rules: &Rules) -> String {
    let mut s = msg.to_string();
    for g in &rules.exclude_paths {
        let prefix = g.trim_end_matches('*').trim_end_matches('/');
        if !prefix.is_empty() {
            s = s.replace(prefix, "[filtered]");
        }
    }
    s
}

fn commit_tree(
    dst: &Path,
    tree: &str,
    parents: &[String],
    meta: &CommitMeta,
    message: &str,
) -> Result<String, String> {
    let mut args = vec!["commit-tree".to_string(), tree.to_string()];
    for p in parents {
        args.push("-p".into());
        args.push(p.clone());
    }
    args.push("-F".into());
    args.push("-".into());
    let mut child = Command::new("git")
        .args(&args)
        .current_dir(dst)
        .env("GIT_AUTHOR_NAME", &meta.author_name)
        .env("GIT_AUTHOR_EMAIL", &meta.author_email)
        .env("GIT_AUTHOR_DATE", &meta.author_date)
        .env("GIT_COMMITTER_NAME", &meta.committer_name)
        .env("GIT_COMMITTER_EMAIL", &meta.committer_email)
        .env("GIT_COMMITTER_DATE", &meta.committer_date)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    {
        let mut stdin = child.stdin.take().ok_or("commit-tree stdin")?;
        stdin
            .write_all(message.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

struct Derive {
    public_head: Option<String>,
    kept: usize,
    dropped: usize,
}

fn derive(
    private: &Path,
    public: &Path,
    rules: &Rules,
    map: &mut ShaMap,
) -> Result<Derive, String> {
    if !public.join(".git").exists() {
        fs::create_dir_all(public).map_err(|e| e.to_string())?;
        git(public, &["init", "-b", "main"])?;
        git(public, &["config", "user.email", "nas@localhost"])?;
        git(public, &["config", "user.name", "nas"])?;
    }
    let listed = match git(private, &["rev-list", "--reverse", "--topo-order", "HEAD"]) {
        Ok(s) => s,
        Err(_) => {
            return Ok(Derive {
                public_head: None,
                kept: 0,
                dropped: 0,
            });
        }
    };
    let mut kept = 0;
    let mut dropped = 0;
    let mut last_public: Option<String> = None;
    for hex in listed.lines() {
        if hex.is_empty() {
            continue;
        }
        let meta = parse_commit(private, hex)?;
        let files = ls_tree(private, hex)?;
        let kept_files: Vec<TreeEnt> = files
            .into_iter()
            .filter(|f| !excluded(&f.path, rules))
            .collect();
        for f in &kept_files {
            copy_blob(private, public, &f.oid)?;
        }
        let tree = write_tree(public, &kept_files)?;
        let parents: Vec<String> = meta
            .parents
            .iter()
            .filter_map(|p| map.entries.get(p).cloned())
            .collect();
        if rules.drop_empty_commits {
            let empty_root = kept_files.is_empty() && parents.is_empty();
            let empty_child = parents
                .first()
                .and_then(|p| tree_of(public, p).ok())
                .is_some_and(|pt| pt == tree);
            if empty_root || empty_child {
                dropped += 1;
                if let Some(p) = parents.first() {
                    map.entries.insert(hex.to_string(), p.clone());
                    last_public = Some(p.clone());
                }
                continue;
            }
        }
        let message = if rules.filter_messages {
            filter_msg(&meta.message, rules)
        } else {
            meta.message.clone()
        };
        let pub_sha = commit_tree(public, &tree, &parents, &meta, &message)?;
        map.entries.insert(hex.to_string(), pub_sha.clone());
        last_public = Some(pub_sha);
        kept += 1;
    }
    if let Some(head) = &last_public {
        // commit-tree writes the object; refuse to point main at a SHA we
        // cannot name in this repo (the previous re-publish bug).
        git(public, &["cat-file", "-e", head])
            .map_err(|e| format!("public HEAD {head} missing after rewrite: {e}"))?;
        git(public, &["update-ref", "refs/heads/main", head])?;
        let _ = git(public, &["checkout", "-f", "main"]);
    }
    Ok(Derive {
        public_head: last_public,
        kept,
        dropped,
    })
}

fn public_paths(public: &Path) -> Result<Vec<String>, String> {
    if !public.join(".git").exists() {
        return Ok(Vec::new());
    }
    let listed = match git(public, &["rev-list", "--all"]) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let mut paths = Vec::new();
    for hex in listed.lines() {
        if hex.is_empty() {
            continue;
        }
        for e in ls_tree(public, hex)? {
            paths.push(e.path);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn scan_secrets(public: &Path) -> Result<Option<String>, String> {
    if !public.join(".git").exists() {
        return Ok(None);
    }
    let listed = match git(public, &["rev-list", "--all"]) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    for hex in listed.lines() {
        if hex.is_empty() {
            continue;
        }
        for e in ls_tree(public, hex)? {
            let blob = Command::new("git")
                .args(["cat-file", "blob", &e.oid])
                .current_dir(public)
                .output()
                .map_err(|e| e.to_string())?;
            if !blob.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&blob.stdout);
            if text.contains(PLANTED_SECRET)
                || text.contains("-----BEGIN PRIVATE KEY-----")
                || text.contains("-----BEGIN RSA PRIVATE KEY-----")
                || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
                || text.contains("AKIA")
            {
                return Ok(Some(e.path));
            }
        }
    }
    Ok(None)
}

fn sign_publish(repo: &Repo, public_head: &str, rules: &Rules) -> Result<(), String> {
    let id = repo
        .identity(nas_crypto::Role::Slot)
        .map_err(|e| e.to_string())?;
    let body = format!("mirror-publish {} {}", public_head, rules.hash());
    let sig = id
        .sign(nas_crypto::SigContext::MirrorPublish, body.as_bytes())
        .map_err(|e| e.to_string())?;
    if let Some(parent) = approval_path(repo).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        approval_path(repo),
        format!("{}\n{}\n", hex_bytes(id.verifying_key()), hex_bytes(&sig)),
    )
    .map_err(|e| e.to_string())
}

enum Gate {
    Ok(Derive),
    Refuse(String),
    Error(String),
}

fn run_derive(ns: &str, persist: bool, require_dry: bool, scan: bool) -> Gate {
    if let Err(e) = ensure_ns(ns) {
        return Gate::Error(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return Gate::Error(e),
    };
    let rules = match load_rules(&repo) {
        Ok(r) => r,
        Err(e) => return Gate::Refuse(format!("rules fail closed: {e}")),
    };
    if require_dry && !has_receipt(&repo) {
        return Gate::Refuse("dry run is required before publish (SPECS §7.6)".into());
    }
    let private = match materialize_private(ns) {
        Ok(p) => p,
        Err(e) => return Gate::Error(e),
    };
    let dest = if persist {
        let p = public_dir(&repo);
        let _ = fs::remove_dir_all(&p);
        p
    } else {
        match scratch_git("preview") {
            Ok(p) => p,
            Err(e) => {
                let _ = fs::remove_dir_all(&private);
                return Gate::Error(e);
            }
        }
    };
    // Full rewrite every time. The map is an output, not a cache: skipping
    // already-mapped commits after wiping `state/git/public` left us pointing
    // at SHAs whose objects were gone, and a cached rewrite would hide a
    // non-deterministic filter. Same private history + same rules → same
    // public SHAs (SPECS §7.6).
    let mut map = ShaMap::default();
    let derived = match derive(&private, &dest, &rules, &mut map) {
        Ok(d) => d,
        Err(e) => {
            let _ = fs::remove_dir_all(&private);
            if !persist {
                let _ = fs::remove_dir_all(&dest);
            }
            return Gate::Error(e);
        }
    };
    if scan {
        match scan_secrets(&dest) {
            Ok(Some(path)) => {
                let _ = fs::remove_dir_all(&private);
                let _ = fs::remove_dir_all(&dest);
                return Gate::Refuse(format!("secret scan refused publish ({path})"));
            }
            Ok(None) => {}
            Err(e) => {
                let _ = fs::remove_dir_all(&private);
                return Gate::Error(e);
            }
        }
    }
    if persist {
        if let Err(e) = save_shamap(&repo, &map) {
            let _ = fs::remove_dir_all(&private);
            return Gate::Error(e);
        }
        if let Some(head) = &derived.public_head {
            if let Err(e) = sign_publish(&repo, head, &rules) {
                let _ = fs::remove_dir_all(&private);
                return Gate::Error(e);
            }
        }
    } else {
        let head = derived
            .public_head
            .clone()
            .unwrap_or_else(|| "empty".into());
        if let Err(e) = write_receipt(&repo, &rules, &head) {
            let _ = fs::remove_dir_all(&private);
            let _ = fs::remove_dir_all(&dest);
            return Gate::Error(e);
        }
        let _ = fs::remove_dir_all(&dest);
    }
    let _ = fs::remove_dir_all(&private);
    Gate::Ok(derived)
}

fn import_history(ns: &str, commits: &[(&str, &[(&str, &str)])]) -> Result<(), String> {
    let src = scratch_git("hist")?;
    let mut last = None;
    for (msg, files) in commits {
        let oid = commit_files(&src, files, msg)?;
        last = Some(oid);
    }
    let oid = last.ok_or("no commits")?;
    import_reachable(ns, &src, &oid)?;
    update_ref(ns, "refs/heads/main", &oid)?;
    let _ = fs::remove_dir_all(&src);
    Ok(())
}

fn standard_history() -> [(&'static str, &'static [(&'static str, &'static str)]); 4] {
    [
        (
            "public start",
            &[("README.md", "hello\n"), ("src/app.rs", "fn main() {}\n")],
        ),
        ("private fix", &[("fixes/leak.txt", "do not publish\n")]),
        (
            "internal note",
            &[("internal/notes.md", "private discussion\n")],
        ),
        ("more public", &[("src/lib.rs", "pub fn f() {}\n")]),
    ]
}

fn gate_to_i32(g: Gate, ok_msg: impl Fn(&Derive) -> String) -> i32 {
    match g {
        Gate::Ok(d) => {
            println!("{}", ok_msg(&d));
            exit::OK
        }
        Gate::Refuse(m) => refuse(m),
        Gate::Error(m) => err(m),
    }
}

/// `nas mirror dry-run <ns>`
pub fn dry_run(ns: &str) -> i32 {
    gate_to_i32(run_derive(ns, false, false, false), |d| {
        format!(
            "dry-run {ns}: {} commit(s) would publish, {} dropped",
            d.kept, d.dropped
        )
    })
}

/// `nas mirror publish <ns>`
pub fn publish(ns: &str) -> i32 {
    gate_to_i32(run_derive(ns, true, true, true), |d| {
        format!(
            "published {ns}: {} commit(s), {} dropped",
            d.kept, d.dropped
        )
    })
}

/// `nas test mirror-publish-without-dryrun <ns>`
pub fn publish_without_dryrun(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    clear_receipt(&repo);
    if let Err(e) = import_history(ns, &standard_history()) {
        return err(e);
    }
    match run_derive(ns, true, true, true) {
        Gate::Refuse(_) => {
            println!("mirror-publish-without-dryrun: refused");
            exit::REFUSED
        }
        Gate::Ok(_) => err("publish succeeded without a dry run"),
        Gate::Error(m) => err(m),
    }
}

/// `nas test mirror-excludes <ns> <glob>`
pub fn excludes(ns: &str, glob: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    if let Err(e) = import_history(ns, &standard_history()) {
        return err(e);
    }
    match run_derive(ns, false, false, false) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) | Gate::Error(m) => return err(m),
    }
    match run_derive(ns, true, true, true) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) => return refuse(m),
        Gate::Error(m) => return err(m),
    }
    let paths = match public_paths(&public_dir(&repo)) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let leaked: Vec<_> = paths
        .iter()
        .filter(|p| glob_match(glob, p))
        .cloned()
        .collect();
    if !leaked.is_empty() {
        return err(format!("{glob} leaked into the public repo: {leaked:?}"));
    }
    println!("mirror-excludes: {glob} is absent from every published commit");
    exit::OK
}

/// `nas test mirror-no-empty-commits <ns>`
pub fn no_empty_commits(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    if let Err(e) = import_history(ns, &standard_history()) {
        return err(e);
    }
    let private = match materialize_private(ns) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let priv_n = git(&private, &["rev-list", "--count", "HEAD"])
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let _ = fs::remove_dir_all(&private);
    match run_derive(ns, false, false, false) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) | Gate::Error(m) => return err(m),
    }
    let derived = match run_derive(ns, true, true, true) {
        Gate::Ok(d) => d,
        Gate::Refuse(m) => return refuse(m),
        Gate::Error(m) => return err(m),
    };
    if derived.dropped == 0 {
        return err("a fixes/-only commit should have been dropped");
    }
    let public = public_dir(&repo);
    let pub_n = git(&public, &["rev-list", "--count", "HEAD"])
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if pub_n >= priv_n {
        return err(format!(
            "public still has {pub_n} commits, private had {priv_n}"
        ));
    }
    println!("mirror-no-empty-commits: private {priv_n} → public {pub_n}");
    exit::OK
}

/// `nas test mirror-shamap-exists <ns>`
pub fn shamap_exists(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    if let Err(e) = import_history(ns, &standard_history()) {
        return err(e);
    }
    match run_derive(ns, false, false, false) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) | Gate::Error(m) => return err(m),
    }
    match run_derive(ns, true, true, true) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) => return refuse(m),
        Gate::Error(m) => return err(m),
    }
    if !shamap_ptr(&repo).exists() {
        return err("shamap pointer is missing");
    }
    let map = match load_shamap(&repo) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    if map.entries.is_empty() {
        return err("shamap is empty");
    }
    println!(
        "mirror-shamap-exists: {} private→public mappings",
        map.entries.len()
    );
    exit::OK
}

/// `nas test mirror-shamap-stable <ns>`
pub fn shamap_stable(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    if let Err(e) = import_history(ns, &standard_history()) {
        return err(e);
    }
    match run_derive(ns, false, false, false) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) | Gate::Error(m) => return err(m),
    }
    match run_derive(ns, true, true, true) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) => return refuse(m),
        Gate::Error(m) => return err(m),
    }
    let first = match load_shamap(&repo) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    match run_derive(ns, true, true, true) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) => return refuse(m),
        Gate::Error(m) => return err(m),
    }
    let second = match load_shamap(&repo) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    if first.entries != second.entries {
        return err("re-publish rewrote public SHAs");
    }
    println!(
        "mirror-shamap-stable: {} mappings unchanged on re-publish",
        first.entries.len()
    );
    exit::OK
}

/// `nas test mirror-shamap-encrypted <ns>`
pub fn shamap_encrypted(ns: &str) -> i32 {
    let rc = shamap_exists(ns);
    if rc != exit::OK {
        return rc;
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let map = match load_shamap(&repo) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let Some((priv_hex, _)) = map.entries.iter().next() else {
        return err("empty shamap");
    };
    let blobs = repo.blobs_root().join("blobs");
    if !blobs.exists() {
        return err("no blob store");
    }
    let status = Command::new("grep")
        .args(["-rqa", "--", priv_hex, blobs.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => {
            return err("private git SHA found under blobs/ — the shamap leaked");
        }
        Ok(_) => {}
        Err(e) => return err(e),
    }
    println!("mirror-shamap-encrypted: {priv_hex} is not in the blob store");
    exit::OK
}

/// `nas test mirror-failclosed <ns>`
pub fn failclosed(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_rules(&repo, "exclude_paths=[unclosed\n") {
        return err(e);
    }
    clear_receipt(&repo);
    let _ = fs::remove_file(shamap_ptr(&repo));
    let _ = fs::remove_dir_all(public_dir(&repo));
    match run_derive(ns, true, false, false) {
        Gate::Refuse(_) => {
            if shamap_ptr(&repo).exists() || public_dir(&repo).join(".git").exists() {
                let _ = write_defaults(&repo);
                return err("malformed rules still published");
            }
            let _ = write_defaults(&repo);
            println!("mirror-failclosed: malformed rule published nothing");
            exit::REFUSED
        }
        Gate::Ok(_) => {
            let _ = write_defaults(&repo);
            err("malformed rules were accepted")
        }
        Gate::Error(m) => {
            let _ = write_defaults(&repo);
            err(m)
        }
    }
}

/// `nas test mirror-secret-scan <ns>`
pub fn secret_scan(ns: &str) -> i32 {
    if let Err(e) = ensure_ns(ns) {
        return err(e);
    }
    let repo = match open_repo(ns) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if let Err(e) = write_defaults(&repo) {
        return err(e);
    }
    let planted = format!("let x = \"{PLANTED_SECRET}\";\n");
    if let Err(e) = import_history(
        ns,
        &[(
            "plant",
            &[("README.md", "hello\n"), ("src/app.rs", planted.as_str())][..],
        )],
    ) {
        return err(e);
    }
    match run_derive(ns, false, false, false) {
        Gate::Ok(_) => {}
        Gate::Refuse(m) | Gate::Error(m) => return err(m),
    }
    let _ = fs::remove_file(shamap_ptr(&repo));
    let _ = fs::remove_dir_all(public_dir(&repo));
    match run_derive(ns, true, true, true) {
        Gate::Refuse(_) => {
            if public_dir(&repo).join(".git").exists() {
                return err("secret scan refused but the public repo was left behind");
            }
            println!("mirror-secret-scan: planted secret refused");
            exit::REFUSED
        }
        Gate::Ok(_) => err("planted secret was published"),
        Gate::Error(m) => err(m),
    }
}
