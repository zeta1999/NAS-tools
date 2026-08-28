//! `nas acl …` — the peer-evaluated access list (SPECS §15.3, §19.1).
//!
//! The ACL is **configuration**, not a secret: §19.1 declares it in the
//! namespace's own definition, and in `transit-only` the peer must be able to
//! read it in order to enforce it. So it lives beside `config`, in the clear.
//!
//! # Exit codes here are a claim about reality
//!
//! `acl check` maps [`Decision`] onto the exit-code contract, and the mapping
//! is the interesting part:
//!
//! * `Allowed` → 0.
//! * `Denied` / `UnknownSubject` → **2**, refused by policy. The peer evaluated
//!   the list and the answer was no.
//! * `NotEnforceable` → **1**, an error. Not 2, because that would report a
//!   policy decision the peer never made; and certainly not 0. Asking the peer
//!   to adjudicate *read* in an encrypted namespace is a category error — there
//!   possession of a capability is the only access control, and the peer has no
//!   opinion it could offer. Answering "denied" would describe a control that
//!   does not exist, which is the confusion SPECS §15 opens by warning about.

use crate::exit;
use crate::repo::{path_of, Repo};
use nas_peer::{Acl, Decision, Right};
use std::fs;
use std::path::{Path, PathBuf};

fn acl_path(ns: &str) -> PathBuf {
    path_of(ns).join("acl")
}

pub fn load(ns: &str) -> Result<Acl, String> {
    match fs::read(acl_path(ns)) {
        Ok(b) => Acl::decode(&b).map_err(|e| e.to_string()),
        // A namespace with no ACL file has an empty one. Every subject is then
        // unknown, which is the safe default: nothing is granted implicitly.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Acl::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn store(ns: &str, acl: &Acl) -> Result<(), String> {
    let bytes = acl.encode().map_err(|e| e.to_string())?;
    let p = acl_path(ns);
    fs::create_dir_all(Path::new(&p).parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&p, bytes).map_err(|e| e.to_string())
}

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

pub fn grant(ns: &str, subject: &str, right: Right) -> i32 {
    if !Repo::exists(ns) {
        return err(format!("no namespace {ns}"));
    }
    let mut acl = match load(ns) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    acl.grant(subject, &[right]);
    match store(ns, &acl) {
        Ok(()) => {
            println!("granted {} to {subject} on {ns}", right.as_str());
            exit::OK
        }
        Err(e) => err(e),
    }
}

pub fn revoke(ns: &str, subject: &str, right: Right) -> i32 {
    let mut acl = match load(ns) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let removed = acl.revoke(subject, right);
    if let Err(e) = store(ns, &acl) {
        return err(e);
    }
    if removed {
        // SPECS §15.3: in transit-only this is revocation, and it is instant --
        // the advantage that mode buys over re-keying a namespace.
        println!("revoked {} from {subject} on {ns}", right.as_str());
    } else {
        println!("{subject} did not hold {} on {ns}", right.as_str());
    }
    exit::OK
}

pub fn list(ns: &str) -> i32 {
    let acl = match load(ns) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let mode = match Repo::describe(ns) {
        Ok(d) => d.mode,
        Err(e) => return err(e),
    };
    if acl.subjects().next().is_none() {
        println!("{ns}: no access entries");
        return exit::OK;
    }
    for s in acl.subjects() {
        let rights: Vec<&str> = acl
            .rights_of(s)
            .map(|r| r.iter().map(|x| x.as_str()).collect())
            .unwrap_or_default();
        println!("{s}\t{}", rights.join(","));
    }
    if !mode.peer_can_enforce_read_acl() {
        // Say it every time the list is shown, not once in a manual: a tidy
        // table is exactly what makes people believe they have read control.
        println!(
            "\nnote: {mode:?} has NO peer-enforced read control. `read` entries above are \
             advisory; possession of a capability is the only thing that governs reading."
        );
    }
    exit::OK
}

pub fn check(ns: &str, subject: &str, right: Right) -> i32 {
    let acl = match load(ns) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let mode = match Repo::describe(ns) {
        Ok(d) => d.mode,
        Err(e) => return err(format!("no namespace {ns}: {e}")),
    };
    match acl.check(subject, right, mode) {
        Decision::Allowed => {
            println!(
                "{subject} may {} on {ns} ({mode:?}, peer-enforced)",
                right.as_str()
            );
            exit::OK
        }
        d @ (Decision::Denied | Decision::UnknownSubject) => {
            eprintln!("refused: {subject} may not {} on {ns}: {d}", right.as_str());
            exit::REFUSED
        }
        d @ Decision::NotEnforceable { .. } => {
            // See the module docs: neither 0 nor 2 would be true.
            eprintln!("error: {d}");
            exit::ERROR
        }
    }
}
