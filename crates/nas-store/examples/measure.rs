//! Measures padding overhead and peak memory on a real corpus.
//!
//! SPECS §4.2.1 estimates the padding premium at 20-35% and says it "must be
//! measured, not assumed" before anyone opts in. This is that measurement, and
//! its output belongs in MANUAL-TESTING.md.
//!
//! Usage: `cargo run --release -p nas-store --example measure -- <dir> [dir...]`

use nas_core::PaddingProfile;
use nas_crypto::{ConvergenceSecret, KEY_LEN};
use nas_store::{BlobStore, Kind, ObjectWriter};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        // Build output and VCS internals are not a user's data.
        if name == "target" || name == ".git" || name == "node_modules" {
            continue;
        }
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out),
            Ok(t) if t.is_file() => out.push(p),
            _ => {}
        }
    }
}

/// Peak resident set size in bytes, from the OS rather than from a guess.
fn peak_rss() -> u64 {
    #[cfg(unix)]
    unsafe {
        let mut ru: libc_rusage = std::mem::zeroed();
        if getrusage(0, &mut ru) == 0 {
            // Linux reports kilobytes, macOS bytes.
            return if cfg!(target_os = "macos") {
                ru.ru_maxrss as u64
            } else {
                ru.ru_maxrss as u64 * 1024
            };
        }
    }
    0
}

#[repr(C)]
#[derive(Default)]
struct libc_rusage {
    ru_utime: [i64; 2],
    ru_stime: [i64; 2],
    ru_maxrss: i64,
    rest: [i64; 14],
}
extern "C" {
    fn getrusage(who: i32, usage: *mut libc_rusage) -> i32;
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: measure <dir> [dir...]");
        std::process::exit(2);
    }

    let mut files = Vec::new();
    for a in &args {
        walk(Path::new(a), &mut files);
    }
    files.sort();
    println!("corpus: {} files under {}", files.len(), args.join(", "));
    println!();
    // `overhead` is net of deduplication, so on a corpus with duplicates it
    // goes negative and says nothing about padding. `vs none` isolates the
    // padding premium, which is the figure SPECS §4.2.1 estimates at 20-35%.
    println!(
        "{:<10} {:>13} {:>13} {:>9} {:>8} {:>8} {:>7}",
        "profile", "plaintext B", "stored B", "overhead", "vs none", "chunks", "dedup"
    );

    let root = std::env::temp_dir().join(format!("nas-measure-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let cs = ConvergenceSecret::from_bytes([1u8; KEY_LEN]);
    let mut results = BTreeMap::new();

    for profile in [
        PaddingProfile::None,
        PaddingProfile::Classes,
        PaddingProfile::Fixed,
    ] {
        let dir = root.join(format!("{profile:?}"));
        let st = BlobStore::open(&dir).unwrap();
        let w = ObjectWriter::with_defaults(&st, &cs, profile).unwrap();

        // Count only what was actually written. Summing metadata over the
        // whole file list instead would divide stored bytes by a plaintext
        // total that includes files the writer never saw -- which is how the
        // first run of this tool reported NEGATIVE overhead for `none`.
        let mut chunks_written = 0usize;
        let mut plaintext = 0u64;
        let mut written = 0usize;
        let mut skipped = 0usize;
        for f in &files {
            let Ok(fh) = fs::File::open(f) else {
                skipped += 1;
                continue;
            };
            // Streaming: peak memory must not track file size.
            match w.write(Kind::File, fh) {
                Ok(m) => {
                    chunks_written += m.chunks.len();
                    plaintext += m.size;
                    written += 1;
                }
                Err(e) => {
                    skipped += 1;
                    eprintln!("  skip {}: {e}", f.display());
                }
            }
        }
        if skipped > 0 {
            eprintln!("  {profile:?}: {written} written, {skipped} skipped");
        }

        let addrs = st.addrs().unwrap();
        let stored: u64 = addrs
            .iter()
            .map(|a| fs::metadata(st.path(a)).map(|m| m.len()).unwrap_or(0))
            .sum();
        let overhead = stored as f64 / plaintext.max(1) as f64 - 1.0;
        let dedup = if chunks_written > 0 {
            (1.0 - addrs.len() as f64 / chunks_written as f64) * 100.0
        } else {
            0.0
        };
        let baseline = results.get("None").map(|&(b, _, _)| b).unwrap_or(stored);
        let vs_none = stored as f64 / baseline.max(1) as f64 - 1.0;
        println!(
            "{:<10} {:>13} {:>13} {:>8.1}% {:>7.1}% {:>8} {:>6.1}%",
            format!("{profile:?}"),
            plaintext,
            stored,
            overhead * 100.0,
            vs_none * 100.0,
            chunks_written,
            dedup
        );
        results.insert(format!("{profile:?}"), (stored, overhead, addrs.len()));
        let _ = fs::remove_dir_all(&dir);
    }

    println!();
    println!(
        "peak RSS: {} bytes ({:.1} MiB)",
        peak_rss(),
        peak_rss() as f64 / (1024.0 * 1024.0)
    );
    let _ = fs::remove_dir_all(&root);
}
