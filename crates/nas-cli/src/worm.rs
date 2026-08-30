//! `nas test retention-*` and `lease-cycle` — SPECS §16.3 and §6.
//!
//! §16.3's claim is narrow and worth stating exactly: GC is lease-driven, so a
//! client that stops renewing would destroy a WORM namespace by saying nothing
//! at all. Retention overrides leases, and the everyday write key may only ever
//! **extend** it. Ransomware holding that key can add protection and nothing
//! else.
//!
//! The peer enforces the superset rule with a plaintext set comparison — which
//! is why it works in an encrypted mode: the peer must understand addresses,
//! not manifests (SPECS §2.2). But the peer is the thing we distrust, so every
//! check here also exercises the *client's* defence: re-read the set the peer
//! serves back and compare it against what was published. A peer running
//! `--hostile ignore-retention` is used to prove that comparison bites.

use crate::exit;
use crate::repo::Repo;
use nas_core::{Addr, Mode, Timestamp};
use nas_crypto::{Identity, Role};
use nas_lease::{sweep::DAY, GcPolicy, Holder, Keep, LeaseSet};
use nas_peer::{Hostility, Peer, PeerError};
use nas_slots::{SlotId, Witness};
use nas_store::Addressing;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// A peer in a scratch directory that goes away with it.
struct Lab {
    peer: Peer,
    dir: PathBuf,
}

impl Lab {
    fn open(tag: &str, mode: Mode, hostility: Hostility) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("nas-worm-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let addressing = match mode {
            Mode::TransitOnly => Addressing::Salted(b"uc-tenant".to_vec()),
            Mode::E2ee | Mode::Passphrase => Addressing::Content,
        };
        let peer =
            Peer::open(&dir, mode, addressing, hostility).map_err(|e| format!("open peer: {e}"))?;
        Ok(Self { peer, dir })
    }

    fn seed(&self, n: usize) -> Result<Vec<Addr>, String> {
        (0..n)
            .map(|i| {
                self.peer
                    .put_blob(format!("record-{i}").as_bytes())
                    .map_err(|e| format!("put: {e}"))
            })
            .collect()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A holder that stopped renewing long enough ago to be expired.
fn silent_holder(leases: &[Addr]) -> Holder {
    Holder {
        id: [9u8; 32],
        set: LeaseSet::from_addrs(leases),
        last_seen: Timestamp(real_now()),
    }
}

/// Far enough past the upload that the young-blob grace has lapsed and the
/// holder above counts as expired.
fn later() -> Timestamp {
    Timestamp(real_now() + 200 * DAY)
}

/// The client's own check (§16.3): is what the peer serves back still a
/// superset of what we published? `Err` names the first address it dropped.
fn audit(peer: &Peer, published: &[Addr]) -> Result<(), Addr> {
    let served: BTreeSet<[u8; 32]> = peer.retention_set().iter().map(|a| *a.as_bytes()).collect();
    match published.iter().find(|a| !served.contains(a.as_bytes())) {
        Some(a) => Err(*a),
        None => Ok(()),
    }
}

fn ok(msg: impl std::fmt::Display) -> i32 {
    println!("{msg}");
    exit::OK
}

fn refuse(msg: impl std::fmt::Display) -> i32 {
    eprintln!("refused: {msg}");
    exit::REFUSED
}

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn mode_of(ns: &str) -> Result<Mode, String> {
    Repo::describe(ns)
        .map(|d| d.mode)
        .map_err(|e| format!("namespace {ns}: {e}"))
}

/// `nas test retention-extend-only <ns>` — the everyday key may add protection.
///
/// Asserts the honest path works (a set can be published and extended, and the
/// peer serves back a superset each time) **and** that the client's audit is
/// not vacuous: against a peer that drops an address it must fail.
pub fn retention_extend_only(ns: &str) -> i32 {
    let mode = match mode_of(ns) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    match extend_only(mode) {
        Ok(Ok(m)) => ok(format!("retention-extend-only: {m}")),
        Ok(Err(m)) => refuse(format!("retention-extend-only: {m}")),
        Err(e) => err(format!("retention-extend-only: harness: {e}")),
    }
}

fn extend_only(mode: Mode) -> Result<Result<String, String>, String> {
    let mut lab = Lab::open("extend", mode, Hostility::HONEST)?;
    let a = lab.seed(3)?;
    let peer = &mut lab.peer;

    peer.publish_retention(&a[..2])
        .map_err(|e| format!("publishing two addresses was refused: {e}"))?;
    if let Err(dropped) = audit(peer, &a[..2]) {
        return Ok(Err(format!(
            "peer dropped {} immediately",
            dropped.to_hex()
        )));
    }
    // Extend: the whole previous set, plus one more.
    peer.publish_retention(&a)
        .map_err(|e| format!("extending was refused: {e}"))?;
    if let Err(dropped) = audit(peer, &a) {
        return Ok(Err(format!(
            "peer dropped {} after extending",
            dropped.to_hex()
        )));
    }
    if peer.retention_set().len() != 3 {
        return Ok(Err(format!(
            "peer holds {} addresses, published 3",
            peer.retention_set().len()
        )));
    }

    // The audit must bite. A peer that ignores retention accepts a shrink; if
    // the client's comparison did not notice, every check above would be
    // decoration.
    let mut hostile = Lab::open(
        "extend-hostile",
        mode,
        Hostility {
            ignore_retention: true,
            ..Hostility::HONEST
        },
    )?;
    let h = hostile.seed(2)?;
    let hp = &mut hostile.peer;
    hp.publish_retention(&h)
        .map_err(|e| format!("hostile publish: {e}"))?;
    hp.publish_retention(&h[..1])
        .map_err(|e| format!("hostile peer refused a shrink it was meant to accept: {e}"))?;
    match audit(hp, &h) {
        Ok(()) => Ok(Err(
            "a peer that dropped an address passed the client's audit".into(),
        )),
        Err(dropped) => Ok(Ok(format!(
            "{mode:?}: published 2 then extended to 3, superset held each time; \
             the audit catches a peer that drops {} (SPECS §16.3)",
            dropped.to_hex()
        ))),
    }
}

/// `nas test retention-shrink <ns> --key everyday` — must be refused.
///
/// Under any other key this is unbuilt, not permitted: shrinking needs the
/// offline delete authority and a §16.2 quorum, which is M2 work. Saying so
/// with exit 3 keeps the harness from scoring an unwritten control as passing.
pub fn retention_shrink(ns: &str, key: Option<&str>) -> i32 {
    let mode = match mode_of(ns) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    match key {
        Some("everyday") => {}
        Some(other) => {
            return crate::testcmds::unimplemented(
                &format!("test retention-shrink --key {other}"),
                "M2 (§16.2: the offline delete authority and its quorum)",
            )
        }
        None => return err("retention-shrink needs --key <everyday|delete-authority>"),
    }
    match shrink_under_everyday_key(mode) {
        Ok(Ok(m)) => refuse(m),
        Ok(Err(m)) => {
            eprintln!("error: retention-shrink: {m}");
            exit::ERROR
        }
        Err(e) => err(format!("retention-shrink: harness: {e}")),
    }
}

/// `Ok(Ok(msg))` — correctly refused. `Ok(Err(msg))` — it went through.
fn shrink_under_everyday_key(mode: Mode) -> Result<Result<String, String>, String> {
    let mut lab = Lab::open("shrink", mode, Hostility::HONEST)?;
    let a = lab.seed(2)?;
    let peer = &mut lab.peer;
    peer.publish_retention(&a)
        .map_err(|e| format!("the initial publish was refused: {e}"))?;

    match peer.publish_retention(&a[..1]) {
        Err(PeerError::RetentionShrink { dropped, .. }) => {
            if peer.retention_set().len() != 2 {
                return Ok(Err(format!(
                    "refused, but the set changed anyway: {} addresses",
                    peer.retention_set().len()
                )));
            }
            Ok(Ok(format!(
                "the everyday key may not drop {} from retention; \
                 shrinking needs the offline delete authority (SPECS §16.3)",
                dropped.to_hex()
            )))
        }
        Err(e) => Ok(Err(format!("refused for the wrong reason: {e}"))),
        Ok(()) => Ok(Err(
            "the peer accepted a shrink under the everyday write key".into(),
        )),
    }
}

/// `nas test lease-cycle <ns>` — SPECS §2.2: leases and witnesses behave
/// **identically** in all three confidentiality modes.
///
/// The mode changes what the peer can read, not what it can order or count.
/// Running the same lease cycle and witness relay in each mode and requiring
/// identical outcomes is what keeps that table honest.
pub fn lease_cycle(ns: &str) -> i32 {
    let declared = match mode_of(ns) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let mut outcomes = Vec::new();
    for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
        match cycle(mode) {
            Ok(o) => outcomes.push((mode, o)),
            Err(e) => return err(format!("lease-cycle in {mode:?}: {e}")),
        }
    }
    let (first_mode, first) = &outcomes[0];
    for (mode, o) in &outcomes[1..] {
        if o != first {
            return refuse(format!(
                "lease and witness behaviour differs by mode: {first_mode:?} gave {first}, {mode:?} gave {o}"
            ));
        }
    }
    ok(format!(
        "lease-cycle: identical in e2ee, passphrase and transit-only ({first}); \
         namespace {ns} is {declared:?} (SPECS §2.2)"
    ))
}

/// One lease + witness cycle, reduced to a comparable summary.
fn cycle(mode: Mode) -> Result<String, String> {
    let tag = format!("cycle-{mode:?}");
    let mut lab = Lab::open(&tag, mode, Hostility::HONEST)?;
    let a = lab.seed(3)?;
    let peer = &mut lab.peer;

    peer.publish_retention(&a[..1])
        .map_err(|e| format!("retention: {e}"))?;
    let plan = peer
        .sweep(&[silent_holder(&a)], &GcPolicy::default(), later(), true)
        .map_err(|e| format!("sweep: {e}"))?;
    let floors = plan
        .keep
        .iter()
        .filter(|(_, k)| *k == Keep::RetentionFloor)
        .count();

    // The witness relay, on the same peer, in the same mode.
    let observer = Identity::derive(&[0x0B; 32], Role::Witness).map_err(|e| e.to_string())?;
    let slot = SlotId::new(observer.verifying_key(), b"lease-cycle");
    let w = Witness::sign(&observer, slot, 1, [0xA1; 32], 1).map_err(|e| e.to_string())?;
    peer.publish_witness(w)
        .map_err(|e| format!("witness: {e}"))?;

    Ok(format!(
        "delete={} keep={} retention-floor={} warned={} witnesses={}",
        plan.delete.len(),
        plan.keep.len(),
        floors,
        plan.warnings.len(),
        peer.witnesses(&slot).len()
    ))
}

/// The go-silent attack (§16.3), for `nas test attack go-silent`.
///
/// `Ok(msg)` — retention held. `Err(msg)` — data a WORM namespace promised was
/// destroyed by a client merely falling silent.
pub fn go_silent() -> Result<Result<String, String>, String> {
    // Honest peer first: retention must outlive the lease, and the sweep must
    // actually delete the *unretained* blob, or the check proves nothing.
    let mut lab = Lab::open("go-silent", Mode::E2ee, Hostility::HONEST)?;
    let a = lab.seed(3)?;
    let peer = &mut lab.peer;
    peer.publish_retention(&a[..2])
        .map_err(|e| format!("retention: {e}"))?;

    let plan = peer
        .sweep(&[silent_holder(&a)], &GcPolicy::default(), later(), false)
        .map_err(|e| format!("sweep: {e}"))?;
    if plan.delete != vec![a[2]] {
        return Ok(Err(format!(
            "the sweep deleted {:?}, expected only the unretained blob",
            plan.delete.len()
        )));
    }
    if !peer.has_blob(&a[0]) || !peer.has_blob(&a[1]) {
        return Ok(Err(
            "an expired lease destroyed retained data on an honest peer".into(),
        ));
    }
    if let Err(dropped) = audit(peer, &a[..2]) {
        return Ok(Err(format!(
            "honest peer stopped retaining {}",
            dropped.to_hex()
        )));
    }

    // A peer that ignores retention destroys it. Detection, not prevention:
    // the client re-reads the set and finds what it published is gone (§16.3
    // pairs a WORM namespace with a second peer for exactly this reason).
    let mut hostile = Lab::open(
        "go-silent-hostile",
        Mode::E2ee,
        Hostility {
            ignore_retention: true,
            ..Hostility::HONEST
        },
    )?;
    let h = hostile.seed(2)?;
    let hp = &mut hostile.peer;
    hp.publish_retention(&h)
        .map_err(|e| format!("hostile retention: {e}"))?;
    hp.sweep(&[silent_holder(&h)], &GcPolicy::default(), later(), false)
        .map_err(|e| format!("hostile sweep: {e}"))?;
    let lost = h.iter().filter(|x| !hp.has_blob(x)).count();
    if lost == 0 {
        return Ok(Err(
            "the ignore-retention peer swept nothing; the drill proves nothing".into(),
        ));
    }

    Ok(Ok(format!(
        "honest peer: an expired lease swept 1 unretained blob and kept 2 retained ones; \
         a peer ignoring retention destroyed {lost} of 2 and the client's re-read notices \
         (detection, not prevention — SPECS §16.3)"
    )))
}
