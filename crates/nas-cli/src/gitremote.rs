//! `git-remote-nas` line protocol (SPECS §7.3).
//!
//! Invoked as `git-remote-nas <remote> <url>` or as `nas` when argv0 ends
//! with `git-remote-nas`. Speaks `fetch`/`push`, never `import`/`export`, so
//! commit SHAs are preserved.

use crate::exit;
use crate::gitcmd::{
    export_all, git_cwd, import_reachable, is_fast_forward, parse_ns_url, published_refs,
    resolve_git_dirs, update_ref,
};
use nas_store::{oid_from_hex, oid_to_hex};
use std::io::{self, BufRead, Write};

pub fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // git passes: <remote-name> <url>
    let url = argv
        .get(1)
        .or(argv.first())
        .map(String::as_str)
        .unwrap_or("");
    let ns = match parse_ns_url(url) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {e}");
            return exit::ERROR;
        }
    };
    if let Err(e) = serve(&ns) {
        eprintln!("error: {e}");
        return exit::ERROR;
    }
    exit::OK
}

fn serve(ns: &str) -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
        let line = line.map_err(|e| e.to_string())?;
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        match cmd {
            "capabilities" => {
                writeln!(stdout, "fetch").map_err(|e| e.to_string())?;
                writeln!(stdout, "push").map_err(|e| e.to_string())?;
                writeln!(stdout, "option").map_err(|e| e.to_string())?;
                writeln!(stdout).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            "option" => {
                writeln!(stdout, "ok").map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            "list" => {
                let _for_push = parts.next() == Some("for-push");
                list_refs(ns, &mut stdout)?;
            }
            "fetch" => {
                let mut wants = Vec::new();
                if let (Some(hex), Some(_)) = (parts.next(), parts.next()) {
                    if let Some(oid) = oid_from_hex(hex) {
                        wants.push(oid);
                    }
                }
                for extra in lines.by_ref() {
                    let extra = extra.map_err(|e| e.to_string())?;
                    if extra.is_empty() {
                        break;
                    }
                    if let Some(rest) = extra.strip_prefix("fetch ") {
                        let hex = rest.split_whitespace().next().unwrap_or("");
                        if let Some(oid) = oid_from_hex(hex) {
                            wants.push(oid);
                        }
                    }
                }
                let cwd = git_cwd()?;
                export_all(ns, &cwd)?;
                writeln!(stdout).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
                let _ = wants;
            }
            "push" => {
                let mut specs = vec![line[5..].trim().to_string()];
                for extra in lines.by_ref() {
                    let extra = extra.map_err(|e| e.to_string())?;
                    if extra.is_empty() {
                        break;
                    }
                    if let Some(rest) = extra.strip_prefix("push ") {
                        specs.push(rest.to_string());
                    }
                }
                let cwd = git_cwd()?;
                let _ = resolve_git_dirs(&cwd)?;
                for spec in specs {
                    push_one(ns, &cwd, &spec, &mut stdout)?;
                }
                writeln!(stdout).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn list_refs<W: Write>(ns: &str, w: &mut W) -> Result<(), String> {
    let refs = published_refs(ns).unwrap_or_default();
    let mut head = None;
    for (name, oid) in &refs {
        writeln!(w, "{} {name}", oid_to_hex(oid)).map_err(|e| e.to_string())?;
        if name == "refs/heads/main" || name == "refs/heads/master" {
            head = Some(name.clone());
        }
    }
    if let Some(h) = head {
        writeln!(w, "@{h} HEAD").map_err(|e| e.to_string())?;
    }
    writeln!(w).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn push_one<W: Write>(
    ns: &str,
    cwd: &std::path::Path,
    spec: &str,
    w: &mut W,
) -> Result<(), String> {
    let force = spec.starts_with('+');
    let spec = spec.trim_start_matches('+');
    let (src, dst) = spec
        .split_once(':')
        .ok_or_else(|| format!("bad push spec {spec}"))?;
    if src.is_empty() {
        // delete
        writeln!(w, "error {dst} delete is not implemented").map_err(|e| e.to_string())?;
        return Ok(());
    }
    let hex = crate::gitcmd::git_rev_parse(cwd, src)?;
    let new = oid_from_hex(&hex).ok_or_else(|| format!("bad src oid {hex}"))?;
    let old = published_refs(ns)
        .unwrap_or_default()
        .into_iter()
        .find(|(n, _)| n == dst)
        .map(|(_, o)| o);
    if !force && !is_fast_forward(cwd, old.as_ref(), &new)? {
        writeln!(w, "error {dst} non-fast-forward").map_err(|e| e.to_string())?;
        return Ok(());
    }
    import_reachable(ns, cwd, &new)?;
    update_ref(ns, dst, &new)?;
    writeln!(w, "ok {dst}").map_err(|e| e.to_string())?;
    Ok(())
}
