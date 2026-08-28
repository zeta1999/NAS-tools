//! `nas test …` — the substrate the acceptance harness drives.
//!
//! These are not unit tests. They are the executable form of SPECS §19's
//! cookbook, run against the same binary a user would run, and they must fail
//! honestly: a command that is specified but unbuilt exits
//! [`exit::UNIMPLEMENTED`], never [`exit::REFUSED`], so the harness scores it as
//! pending rather than as a passing security control.

use crate::exit;
use crate::repo::Repo;
use nas_core::{Addr, PaddingProfile};
use nas_crypto::{chunk_key, seal, ConvergenceSecret};
use nas_store::{
    padding, BlobStore, Chunker, ChunkerConfig, Kind, ObjectWriter, TreeStore, CHUNK_AAD,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn refuse(msg: impl std::fmt::Display) -> i32 {
    eprintln!("refused: {msg}");
    exit::REFUSED
}

/// Relative path → contents, for exact tree comparison.
///
/// Keyed on **raw path bytes**, not on a lossy `String`: a POSIX filename need
/// not be UTF-8, and comparing two lossily-stringified snapshots would compare
/// mangled against mangled and report a byte-identical round trip that was not.
fn snapshot(root: &Path) -> std::io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    fn rel_bytes(base: &Path, p: &Path) -> Vec<u8> {
        let r = p.strip_prefix(base).unwrap_or(p);
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
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> std::io::Result<()> {
        let mut es: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let p = e.path();
            let mut rel = rel_bytes(base, &p);
            let ft = e.file_type()?;
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                rel.push(b'/');
                out.insert(rel, Vec::new());
                walk(base, &p, out)?;
            } else {
                out.insert(rel, fs::read(&p)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("nas-cli-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

/// Deterministic pseudo-random bytes. No RNG: a corpus that varies between runs
/// makes a dedup ratio unreproducible.
fn bytes(n: usize, seed: &str) -> Vec<u8> {
    let mut out = vec![0u8; n];
    blake3::Hasher::new_derive_key(seed)
        .finalize_xof()
        .fill(&mut out);
    out
}

fn stored_bytes(st: &BlobStore) -> u64 {
    st.addrs()
        .map(|a| {
            a.iter()
                .filter_map(|x| fs::metadata(st.path(x)).ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// `nas test roundtrip <ns> <path>` — SPECS §19.3.
pub fn roundtrip(ns: &str, src: &str) -> i32 {
    let repo = match Repo::open(ns) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let src = Path::new(src);
    if !src.is_dir() {
        return err(format!("{} is not a directory", src.display()));
    }

    let blobs = match BlobStore::open(repo.blobs_root()) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let cs = repo.convergence_secret();
    let ts = TreeStore::new(&blobs, &cs, repo.padding);
    let root = repo.dir_root();

    // Reuse the previous root when there is one, so a second run of the same
    // tree stores nothing. Directory manifests are random-nonce (SPECS §3.1),
    // so without this every run rewrites every manifest in the tree.
    let prev = repo.head().and_then(|h| Addr::from_hex(&h).ok());
    let addr = match ts.write_dir_incremental(&root, src, prev.as_ref()) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    if let Err(e) = repo.set_head(&addr.to_hex()) {
        return err(e);
    }

    let out = scratch("roundtrip");
    if let Err(e) = ts.read_dir_to(&root, &addr, &out) {
        return err(e);
    }

    let (a, b) = match (snapshot(src), snapshot(&out)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return err("could not snapshot both trees"),
    };
    let _ = fs::remove_dir_all(&out);

    if a != b {
        let show = |k: &Vec<u8>| String::from_utf8_lossy(k).into_owned();
        let missing: Vec<_> = a
            .keys()
            .filter(|k| !b.contains_key(*k))
            .take(5)
            .map(show)
            .collect();
        let extra: Vec<_> = b
            .keys()
            .filter(|k| !a.contains_key(*k))
            .take(5)
            .map(show)
            .collect();
        let differing: Vec<_> = a
            .iter()
            .filter(|(k, v)| b.get(*k).is_some_and(|w| w != *v))
            .map(|(k, _)| show(k))
            .take(5)
            .collect();
        return err(format!(
            "tree differs: {} missing {missing:?}, {} extra {extra:?}, differing {differing:?}",
            a.len(),
            b.len()
        ));
    }
    println!(
        "roundtrip ok: {} entries, mode {:?}, key_scheme {:?}, padding {:?}, root {}",
        a.len(),
        repo.mode,
        repo.key_scheme,
        repo.padding,
        addr.to_hex()
    );
    exit::OK
}

/// `nas test dedup-ratio <ns> --shared <pct> --max-transfer <pct>` — SPECS §19.3.
///
/// Builds two trees sharing `shared`% of their bytes, stores the first, then
/// measures what storing the second actually costs.
pub fn dedup_ratio(ns: &str, shared_pct: u32, max_transfer_pct: u32) -> i32 {
    let repo = match Repo::open(ns) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    if shared_pct > 100 {
        return err("--shared must be a percentage");
    }

    let dir = scratch("dedup");
    let (a, b) = (dir.join("a"), dir.join("b"));
    let total = 8usize << 20;
    let common = total * shared_pct as usize / 100;
    let unique = total - common;

    let shared_bytes = bytes(common, "nas-tools/test/dedup/shared");
    let mk = |root: &Path, tag: &str| -> std::io::Result<()> {
        fs::create_dir_all(root.join("sub"))?;
        fs::write(root.join("sub/shared.bin"), &shared_bytes)?;
        fs::write(root.join("unique.bin"), bytes(unique, tag))?;
        Ok(())
    };
    if let Err(e) = mk(&a, "nas-tools/test/dedup/a").and_then(|_| mk(&b, "nas-tools/test/dedup/b"))
    {
        return err(e);
    }

    let blobs = match BlobStore::open(dir.join("repo")) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let cs = repo.convergence_secret();
    let ts = TreeStore::new(&blobs, &cs, repo.padding);

    if let Err(e) = ts.write_dir(&repo.dir_root().child(b"a"), &a) {
        return err(e);
    }
    let after_first = stored_bytes(&blobs);
    if let Err(e) = ts.write_dir(&repo.dir_root().child(b"b"), &b) {
        return err(e);
    }
    let added = stored_bytes(&blobs).saturating_sub(after_first);
    let _ = fs::remove_dir_all(&dir);

    let pct = added as f64 / total as f64 * 100.0;
    println!("second tree of {total} B added {added} B ({pct:.1}%), budget {max_transfer_pct}%");
    if pct > max_transfer_pct as f64 {
        return err(format!(
            "dedup worse than budget: {pct:.1}% > {max_transfer_pct}%"
        ));
    }
    exit::OK
}

/// `nas test confirmation-attack <ns> --with-cs | --without-cs` — SPECS §3.2, §12.5.
///
/// The attacker holds a *candidate file* and wants to learn whether the victim
/// stored it. They compute what its ciphertext address would be and look for it.
///
/// With `CS`, that succeeds — convergent encryption really does leak this, and
/// the test asserts it does, because a control that cannot be demonstrated to
/// work when disabled is not known to be doing anything (SPECS §12.5).
/// Without `CS`, the address is unguessable and the attempt is **refused**.
pub fn confirmation_attack(ns: &str, with_cs: bool) -> i32 {
    let repo = match Repo::open(ns) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let blobs = match BlobStore::open(repo.blobs_root()) {
        Ok(b) => b,
        Err(e) => return err(e),
    };

    // The victim stores a file the attacker also has a copy of.
    let candidate = bytes(200 << 10, "nas-tools/test/candidate-file");
    let cs = repo.convergence_secret();
    let w = match ObjectWriter::with_defaults(&blobs, &cs, repo.padding) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    if let Err(e) = w.write(Kind::File, &candidate[..]) {
        return err(e);
    }

    // The attacker recomputes the addresses from their own copy.
    let guess_cs: ConvergenceSecret = if with_cs {
        repo.convergence_secret()
    } else {
        Repo::foreign_secret(b"attacker")
    };
    let addrs = match attacker_addrs(&candidate, &guess_cs, repo.padding) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let found = addrs.iter().filter(|a| blobs.has(a)).count();

    if with_cs {
        if found == addrs.len() && found > 0 {
            println!(
                "confirmation attack SUCCEEDED with CS: {found}/{} chunks located",
                addrs.len()
            );
            exit::OK
        } else {
            err(format!(
                "convergence is not working: only {found}/{} chunks located WITH the secret",
                addrs.len()
            ))
        }
    } else if found == 0 {
        refuse(format!(
            "confirmation attack without CS located 0/{} chunks — the secret is load-bearing",
            addrs.len()
        ))
    } else {
        err(format!(
            "LEAK: {found}/{} chunks located WITHOUT the convergence secret",
            addrs.len()
        ))
    }
}

/// Recompute the addresses a candidate file would have under `cs`.
///
/// Deliberately reimplements the write path rather than calling it, so that a
/// change which broke convergence would show up as a mismatch here instead of
/// being masked by both sides sharing a bug.
fn attacker_addrs(
    data: &[u8],
    cs: &ConvergenceSecret,
    profile: PaddingProfile,
) -> Result<Vec<Addr>, String> {
    let cfg = ChunkerConfig::for_profile(profile, ChunkerConfig::default());
    let ch = Chunker::new(cfg).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for chunk in ch.split(data) {
        let padded = padding::pad(profile, chunk).map_err(|e| e.to_string())?;
        let key = chunk_key(cs, &padded);
        let sealed = seal(&key, &padded, CHUNK_AAD).map_err(|e| e.to_string())?;
        out.push(Addr::of_ciphertext(&sealed));
    }
    Ok(out)
}

/// Everything specified but not built. Exits [`exit::UNIMPLEMENTED`] — never
/// [`exit::REFUSED`], which would score unwritten code as a security control.
pub fn unimplemented(what: &str, milestone: &str) -> i32 {
    eprintln!("unimplemented: `{what}` is specified and lands in {milestone}");
    exit::UNIMPLEMENTED
}

// ── Passphrase mode (SPECS §2.2.2) ──────────────────────────────────────

use nas_vault::{Argon2Params, WrapPolicy, WrapRecord};

/// Parse `256MiB`, `262144KiB`, or a bare number of MiB.
fn parse_mem(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(n) = t.strip_suffix("MiB").or_else(|| t.strip_suffix("M")) {
        n.trim().parse::<u32>().ok().map(|m| m * 1024)
    } else if let Some(n) = t.strip_suffix("KiB").or_else(|| t.strip_suffix("K")) {
        n.trim().parse::<u32>().ok()
    } else {
        t.parse::<u32>().ok().map(|m| m * 1024)
    }
}

/// `nas test argon2-params <ns> --min-mem 256MiB --min-time 3`
///
/// Reads the parameters **from the stored wrap record**, not from a constant in
/// this binary. A test that checked the constant would pass on a namespace
/// written by a weaker build, which is exactly the case that matters.
pub fn argon2_params(ns: &str, min_mem: &str, min_time: u32) -> i32 {
    let Some(min_kib) = parse_mem(min_mem) else {
        return err(format!("could not parse --min-mem {min_mem:?}"));
    };
    let root = crate::repo::path_of(ns);
    let seq = match Repo::latest_wrap_seq(&root) {
        Ok(s) => s,
        Err(e) => return err(format!("{ns}: {e}")),
    };
    let w = match Repo::load_wrap(&root, seq) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let policy = WrapPolicy {
        min_memory_kib: min_kib,
        min_iterations: min_time,
    };
    match w.params.check(&policy) {
        Ok(()) => {
            println!(
                "argon2id m={} KiB, t={}, p={} — meets the {} KiB / t={} floor",
                w.params.memory_kib, w.params.iterations, w.params.parallelism, min_kib, min_time
            );
            exit::OK
        }
        Err(e) => err(format!(
            "stored parameters are below the required floor: {e}"
        )),
    }
}

/// `nas test peer-no-plaintext <ns>` — SPECS §1, §12.2.
///
/// Writes a canary through the real pipeline, then scans every stored blob for
/// it. In `transit-only` the expectation is inverted (§12.2), which is why the
/// mode is consulted rather than assumed.
pub fn peer_no_plaintext(ns: &str) -> i32 {
    let repo = match Repo::open_with(ns, crate::repo::passphrase_from(None)) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let blobs = match BlobStore::open(repo.blobs_root()) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let needle = b"CANARY-PLAINTEXT-MUST-NOT-APPEAR";
    let mut data = bytes(300 << 10, "nas-tools/test/canary");
    data.splice(4096..4096 + needle.len(), needle.iter().copied());

    let cs = repo.convergence_secret();
    let w = match ObjectWriter::with_defaults(&blobs, &cs, repo.padding) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    if let Err(e) = w.write(Kind::File, &data[..]) {
        return err(e);
    }

    let mut found = 0usize;
    for a in blobs.addrs().unwrap_or_default() {
        if let Ok(ct) = blobs.get(&a) {
            if ct.windows(needle.len()).any(|x| x == needle) {
                found += 1;
            }
        }
    }
    let expect_plaintext = repo.mode.peer_reads_plaintext();
    match (found > 0, expect_plaintext) {
        (false, false) => {
            println!("no plaintext canary in any blob ({:?})", repo.mode);
            exit::OK
        }
        (true, true) => {
            println!("plaintext present as {:?} requires", repo.mode);
            exit::OK
        }
        (true, false) => err(format!("LEAK: canary found in {found} blob(s)")),
        (false, true) => err(format!(
            "{:?} should store plaintext and does not",
            repo.mode
        )),
    }
}

/// `nas test open-with-passphrase <ns>`
pub fn open_with_passphrase(ns: &str) -> i32 {
    let Some(pw) = crate::repo::passphrase_from(None) else {
        return err("set $NAS_PASSPHRASE");
    };
    match Repo::open_with(ns, Some(pw)) {
        Ok(r) => {
            println!("opened {ns} from the passphrase alone (mode {:?})", r.mode);
            exit::OK
        }
        Err(e) => err(e),
    }
}

/// `nas test recovery-has-freshness-anchor <ns>` — SPECS §2.2.2, review C4.
///
/// The gap this closes: a client recovering from a passphrase holds no
/// capability, so under revision 4 it had no anchor at all — reopening the
/// bootstrapping rollback hole §5.3(1) exists to close. The wrap record must
/// therefore carry the floor, and it must be the *current* floor, not zero.
pub fn recovery_has_freshness_anchor(ns: &str) -> i32 {
    let Some(pw) = crate::repo::passphrase_from(None) else {
        return err("set $NAS_PASSPHRASE");
    };
    let root = crate::repo::path_of(ns);

    // Publish a new anchor by re-wrapping at the next sequence.
    let seq = match Repo::latest_wrap_seq(&root) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let old = match Repo::load_wrap(&root, seq) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let advanced = nas_slots::Anchor {
        seq: 42,
        sig_hash: [0xA5; 32],
    };
    let next = match old.rewrap(
        &pw,
        &pw,
        Argon2Params::SPEC,
        &WrapPolicy::SPEC,
        seq + 1,
        advanced,
    ) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    if let Err(e) = publish_wrap(&root, &next) {
        return err(e);
    }

    // Now recover from the passphrase alone and check the floor came with it.
    let r = match Repo::open_with(ns, Some(pw.clone())) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match r.recovered_anchor() {
        Some(a) if a == advanced => {
            println!("recovery yielded the published anchor: seq {}", a.seq);
            exit::OK
        }
        Some(a) => err(format!(
            "recovered anchor is seq {}, expected {}",
            a.seq, advanced.seq
        )),
        None => err("recovery produced no freshness anchor"),
    }
}

/// `nas test passphrase-change-is-rewrap <ns>` and
/// `nas test no-reencrypt-on-passphrase-change <ns>` — SPECS §2.2.2.
///
/// One operation, two assertions: the wrap changes, and not one stored byte
/// does. That is what the KEK/DEK indirection buys.
pub fn passphrase_change(ns: &str, check_blobs: bool) -> i32 {
    let Some(pw) = crate::repo::passphrase_from(None) else {
        return err("set $NAS_PASSPHRASE");
    };
    let root = crate::repo::path_of(ns);
    let repo = match Repo::open_with(ns, Some(pw.clone())) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let blobs = match BlobStore::open(repo.blobs_root()) {
        Ok(b) => b,
        Err(e) => return err(e),
    };

    // Put something in the namespace so "nothing was re-encrypted" has content
    // to be true about. An empty namespace would pass vacuously.
    let cs = repo.convergence_secret();
    if let Ok(w) = ObjectWriter::with_defaults(&blobs, &cs, repo.padding) {
        let _ = w.write(Kind::File, &bytes(400 << 10, "nas-tools/test/rewrap")[..]);
    }
    let before: Vec<(String, u64)> = snapshot_blobs(&blobs);
    if before.is_empty() {
        return err("no blobs stored; the assertion would pass vacuously");
    }

    let seq = match Repo::latest_wrap_seq(&root) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let old = match Repo::load_wrap(&root, seq) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let new_pw = b"a completely different passphrase entirely".to_vec();
    let next = match old.rewrap(
        &pw,
        &new_pw,
        Argon2Params::SPEC,
        &WrapPolicy::SPEC,
        seq + 1,
        old.anchor,
    ) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    if let Err(e) = publish_wrap(&root, &next) {
        return err(e);
    }
    let after = snapshot_blobs(&blobs);
    if check_blobs && after != before {
        return err(format!(
            "a passphrase change touched stored data: {} blobs before, {} after",
            before.len(),
            after.len()
        ));
    }

    // The new passphrase opens it, the old one does not, and the data is intact.
    let reopened = match Repo::open_with(ns, Some(new_pw.clone())) {
        Ok(r) => r,
        Err(e) => return err(format!("the new passphrase does not open it: {e}")),
    };
    if reopened.convergence_secret_fingerprint() != repo.convergence_secret_fingerprint() {
        return err("re-wrapping changed the namespace secrets");
    }
    if Repo::open_with(ns, Some(pw.clone())).is_ok() {
        return err("the OLD passphrase still opens the namespace after a change");
    }

    // Change back, so the namespace is left as it was found.
    //
    // An acceptance assertion that mutates shared state breaks whichever
    // assertion happens to run after it -- which is exactly what this one did:
    // it left the namespace on a passphrase nothing else knew, and the next two
    // assertions in UC02 failed for a reason that had nothing to do with what
    // they were testing. Assertions have to be order-independent.
    let restored = match next.rewrap(
        &new_pw,
        &pw,
        Argon2Params::SPEC,
        &WrapPolicy::SPEC,
        next.seq + 1,
        next.anchor,
    ) {
        Ok(w) => w,
        Err(e) => return err(format!("could not restore the original passphrase: {e}")),
    };
    if let Err(e) = publish_wrap(&root, &restored) {
        return err(e);
    }
    if Repo::open_with(ns, Some(pw)).is_err() {
        return err("failed to restore the original passphrase");
    }

    let after_restore = snapshot_blobs(&blobs);
    if check_blobs && after_restore != before {
        return err("restoring the passphrase touched stored data");
    }

    println!(
        "re-wrapped 32 bytes twice (change and restore); {} blobs unchanged ({} B)",
        before.len(),
        before.iter().map(|(_, n)| n).sum::<u64>()
    );
    exit::OK
}

/// `nas test old-wrap-deleted <ns>` — SPECS §2.2.2.
pub fn old_wrap_deleted(ns: &str) -> i32 {
    let root = crate::repo::path_of(ns);
    let seq = match Repo::latest_wrap_seq(&root) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if seq == 0 {
        return err("no passphrase change has happened yet; nothing to supersede");
    }
    let mut lingering = Vec::new();
    for old in 0..seq {
        if crate::repo::wrap_path(&root, old).exists() {
            lingering.push(old);
        }
    }
    if lingering.is_empty() {
        println!(
            "wrap {seq} is current; {seq} superseded record(s) removed. \
             Note: against a hostile peer this is best-effort — it may keep a copy."
        );
        exit::OK
    } else {
        err(format!(
            "superseded wrap records still present: {lingering:?}"
        ))
    }
}

/// Publish a wrap record and retire every earlier one.
///
/// The retirement is part of publishing rather than a separate step a caller
/// might forget -- and one did: the re-anchor path left wrap 0 on disk, and
/// `old-wrap-deleted` caught it. SPECS §2.2.2 wants superseded wraps gone
/// because each one is a standing brute-force target against the passphrase it
/// was made with, and it still unwraps the same DEK.
///
/// Against a hostile peer this is best-effort: it may keep a copy, and nothing
/// here can stop it. Genuinely retiring a compromised passphrase means rotating
/// the DEK and re-encrypting (§3.9c).
fn publish_wrap(root: &Path, w: &WrapRecord) -> Result<(), String> {
    let bytes = w.encode().map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("wraps")).map_err(|e| e.to_string())?;
    crate::repo::write_private_pub(&crate::repo::wrap_path(root, w.seq), &bytes)
        .map_err(|e| e.to_string())?;
    for old in 0..w.seq {
        let _ = fs::remove_file(crate::repo::wrap_path(root, old));
    }
    Ok(())
}

fn snapshot_blobs(st: &BlobStore) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = st
        .addrs()
        .unwrap_or_default()
        .iter()
        .map(|a| {
            (
                a.to_hex(),
                fs::metadata(st.path(a)).map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    v.sort();
    v
}
