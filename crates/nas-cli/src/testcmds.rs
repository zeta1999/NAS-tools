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
fn snapshot(root: &Path) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> std::io::Result<()> {
        let mut es: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            let ft = e.file_type()?;
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
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
        let missing: Vec<_> = a.keys().filter(|k| !b.contains_key(*k)).take(5).collect();
        let extra: Vec<_> = b.keys().filter(|k| !a.contains_key(*k)).take(5).collect();
        let differing: Vec<_> = a
            .iter()
            .filter(|(k, v)| b.get(*k).is_some_and(|w| w != *v))
            .map(|(k, _)| k)
            .take(5)
            .collect();
        return err(format!(
            "tree differs: {} missing {missing:?}, {} extra {extra:?}, differing {differing:?}",
            a.len(),
            b.len()
        ));
    }
    println!(
        "roundtrip ok: {} entries, mode {:?}, padding {:?}, root {}",
        a.len(),
        repo.mode,
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
