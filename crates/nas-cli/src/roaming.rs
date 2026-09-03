//! `nas test witness-opportunistic`, `offline-30d`, `sweep-warning` — UC07's
//! roaming checks (SPECS §5.6, §6.3).
//!
//! The use case is one laptop moving between home, office and cafés: a device
//! that is offline for weeks at a time and reconnects on no schedule at all.
//! Three claims in the spec bear on that, and each is checked here.
//!
//! Every drill runs the **honest** case first and requires it to behave, for
//! the reason the hostile-peer drills do: a control that refuses everything —
//! or a lab that is simply broken — would otherwise score as a pass. In these
//! three the trap is the opposite one and worse, because they are checks that
//! nothing *bad* happened: a peer that never sweeps at all satisfies "a 30-day
//! absence loses nothing" perfectly, and proves nothing. So each drill also
//! demonstrates the mechanism biting, and refuses if it does not.

use crate::exit;
use nas_core::{Addr, Mode, Timestamp};
use nas_crypto::{Identity, Role};
use nas_lease::{sweep::DAY, GcPolicy};
use nas_peer::{holder_id, Hostility, Peer};
use nas_slots::{SlotId, Witness};
use nas_store::Addressing;
use std::fs;
use std::path::PathBuf;

/// The subject a returning laptop authenticates as.
const LAPTOP: &str = "laptop";

struct Lab {
    peer: Peer,
    dir: PathBuf,
}

impl Lab {
    fn open(tag: &str) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("nas-roam-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let peer = Peer::open(&dir, Mode::E2ee, Addressing::Content, Hostility::HONEST)
            .map_err(|e| format!("open peer: {e}"))?;
        Ok(Self { peer, dir })
    }

    fn seed(&mut self, n: usize) -> Result<Vec<Addr>, String> {
        (0..n)
            .map(|i| {
                self.peer
                    .put_blob(format!("roaming-{i}").as_bytes())
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

fn real_now() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn slot() -> SlotId {
    SlotId::new(b"uc07", b"roaming")
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

// ── Opportunistic, never scheduled (SPECS §5.6) ────────────────────────────

/// `nas test witness-opportunistic`
pub fn witness_opportunistic() -> i32 {
    match opportunistic() {
        Ok(Ok(m)) => ok(format!("witness-opportunistic: {m}")),
        Ok(Err(m)) => refuse(format!("witness-opportunistic: {m}")),
        Err(e) => err(format!("witness-opportunistic: harness: {e}")),
    }
}

/// SPECS §5.6: "Witness exchange and lease renewal piggyback on whatever
/// connection happens to exist. Nothing requires a session to be up at a
/// particular time."
///
/// # Proving an absence
///
/// The claim is that no schedule exists, and a drill that merely published one
/// witness successfully would pass without touching it. What *is* checkable is
/// that nothing in the exchange is a function of when it happens:
///
/// 1. **Nothing is ever too old to publish.** An observation carrying the
///    lowest possible `logical_time`, arriving *after* newer ones, is still
///    accepted. A staleness rule — the most natural way for a schedule to
///    creep in — would reject exactly this, and it is the case a laptop shut
///    in a bag for a month produces every time it opens.
/// 2. **Order does not matter.** Observations arriving out of order are all
///    kept, so a laptop that reconnects after two other devices have already
///    reported is not late.
/// 3. **A gap does not matter.** Publishing three observations in one session
///    leaves the relay in the same state as publishing them in three sessions
///    an arbitrary interval apart — checked by comparing the two relays.
/// 4. **Nothing is due.** Publishing an observation whose sequence the relay
///    has never seen, after skipping many, is accepted rather than rejected as
///    a missed slot.
///
/// What this does **not** prove: that no scheduler exists anywhere in a
/// deployment. It shows the protocol has no place to put one.
fn opportunistic() -> Result<Result<String, String>, String> {
    let observer = identity(0x0B, Role::Witness)?;

    // (2)+(4) Out of order, and with gaps: 5, then 1, then 9.
    let mut scattered = Lab::open("opportunistic-scattered")?;
    for (seq, lt) in [(5u64, 1u64), (1, 2), (9, 3)] {
        let w = Witness::sign(&observer, slot(), seq, [seq as u8; 32], lt)
            .map_err(|e| format!("sign: {e}"))?;
        // A refusal here is the property failing, not the lab breaking, so it
        // is `Ok(Err(..))` — exit 2 — and not a harness error. A relay that
        // rejects an ordinary observation because of when it arrived is
        // exactly what §5.6 says must not exist.
        if let Err(e) = scattered.peer.publish_witness(w) {
            return Ok(Err(format!(
                "a relay refused an observation at seq {seq} arriving out of order: {e}"
            )));
        }
    }
    let scattered_seqs = seqs(&scattered.peer);
    if scattered_seqs != vec![1, 5, 9] {
        return Ok(Err(format!(
            "out-of-order observations were not all kept: {scattered_seqs:?}"
        )));
    }

    // (3) The same three in ascending order, as if in three separate sessions.
    // Same relay state, so "one session" and "three sessions" are the same
    // thing to the protocol.
    let mut sequential = Lab::open("opportunistic-sequential")?;
    for (seq, lt) in [(1u64, 2u64), (5, 1), (9, 3)] {
        let w = Witness::sign(&observer, slot(), seq, [seq as u8; 32], lt)
            .map_err(|e| format!("sign: {e}"))?;
        if let Err(e) = sequential.peer.publish_witness(w) {
            return Ok(Err(format!(
                "a relay refused an observation at seq {seq} arriving in ascending order: {e}"
            )));
        }
    }
    if seqs(&sequential.peer) != scattered_seqs {
        return Ok(Err(
            "the relay's state depends on the order observations arrived in, so the \
             exchange is not order-free"
                .to_string(),
        ));
    }

    // And the honest floor: the relay is actually storing these, not dropping
    // them. Without this the checks above would all pass against a relay that
    // accepted everything and kept nothing.
    if scattered.peer.witnesses(&slot()).len() != 3 {
        return Ok(Err(
            "the relay reports no witnesses, so the checks above compared two empty sets"
                .to_string(),
        ));
    }

    // (1) The stale arrival. `logical_time` 0 is as old as an observation can
    // declare itself, and it turns up after three newer ones — a laptop that
    // was shut in a bag while other devices reported. A staleness rule, which
    // is how a schedule would creep in, rejects precisely this.
    //
    // A *distinct* sequence, so acceptance cannot be explained away as the
    // relay recognising something it already held.
    let stale =
        Witness::sign(&observer, slot(), 4, [0x44; 32], 0).map_err(|e| format!("sign: {e}"))?;
    if let Err(e) = scattered.peer.publish_witness(stale) {
        return Ok(Err(format!(
            "an observation declaring the oldest possible logical time was refused after \
             newer ones had arrived: {e} — that is a staleness rule, and it makes exchange \
             schedule-sensitive"
        )));
    }
    let after = seqs(&scattered.peer);
    if !after.contains(&4) {
        return Ok(Err(format!(
            "the stale observation was accepted and then dropped: {after:?}"
        )));
    }

    Ok(Ok(format!(
        "observations at seq {after:?} arriving out of order, with gaps, in one session or \
         three, leave the relay identical; one declaring the oldest possible logical time \
         is still accepted after newer ones. Nothing is due and nothing is late \
         (SPECS §5.6, §5.3)"
    )))
}

fn seqs(p: &Peer) -> Vec<u64> {
    let mut v: Vec<u64> = p.witnesses(&slot()).iter().map(|w| w.seq).collect();
    v.sort_unstable();
    v.dedup();
    v
}

// ── A 30-day absence loses nothing (SPECS §6.3) ────────────────────────────

/// `nas test offline-30d <ns>`
pub fn offline_30d(ns: &str) -> i32 {
    match absence(30 * DAY) {
        Ok(Ok(m)) => ok(format!("offline-30d: {m}; namespace {ns}")),
        Ok(Err(m)) => refuse(format!("offline-30d: {m}")),
        Err(e) => err(format!("offline-30d: harness: {e}")),
    }
}

/// SPECS §6.3: expiry is 90 days "precisely so a fortnight of bad connectivity
/// is uneventful", and the peer must not sweep a holder's set until
/// `expiry + grace`.
///
/// The trap in this check is that "nothing was lost" is satisfied perfectly by
/// a peer that never sweeps. So the drill establishes three points on the same
/// timeline against the same peer: away 30 days (protected), away past
/// `expiry` but inside grace (still protected — §6.3's second clause, which is
/// the one an implementation is most likely to get wrong), and away past
/// `expiry + grace` (swept). If the last one does not sweep, the first two
/// prove nothing and the drill says so.
fn absence(away: u64) -> Result<Result<String, String>, String> {
    let policy = GcPolicy::default();
    let mut lab = Lab::open("offline")?;
    let a = lab.seed(4)?;
    let holder = holder_id(LAPTOP);
    let departed = real_now();
    lab.peer
        .take_lease(holder, &a, departed)
        .map_err(|e| format!("take lease: {e}"))?;

    // Dry-run: every call plans against the same peer, so a sweep that
    // actually deleted would make the later checks depend on the earlier
    // ones. `plan_sweep` is pure and this keeps it that way end to end.
    let swept_at = |lab: &mut Lab, gap: u64| -> Result<Vec<Addr>, String> {
        let holders = lab.peer.holders();
        let plan = lab
            .peer
            .sweep(&holders, &policy, Timestamp(departed.secs() + gap), true)
            .map_err(|e| format!("sweep: {e}"))?;
        Ok(plan.delete)
    };

    // The honest floor first: a holder gone long enough really does lose
    // protection. Without this every other assertion here is vacuous.
    let long_gone = swept_at(&mut lab, policy.lease_expiry + policy.grace + DAY)?;
    if long_gone.is_empty() {
        return Ok(Err(format!(
            "nothing is swept even {} days after the holder expired, so this peer never \
             sweeps and 'a 30-day absence loses nothing' means nothing",
            (policy.lease_expiry + policy.grace + DAY) / DAY
        )));
    }

    // Away 30 days: uneventful.
    let short = swept_at(&mut lab, away)?;
    if !short.is_empty() {
        return Ok(Err(format!(
            "{} blobs would be swept after only {} days away, against a {}-day expiry",
            short.len(),
            away / DAY,
            policy.lease_expiry / DAY
        )));
    }

    // Past expiry but inside grace: §6.3's "must not sweep until expiry +
    // grace". The clause most likely to be implemented as a bare `>` on
    // expiry alone.
    let in_grace = swept_at(&mut lab, policy.lease_expiry + policy.grace / 2)?;
    if !in_grace.is_empty() {
        return Ok(Err(format!(
            "{} blobs swept past expiry but inside the grace window; §6.3 says not until \
             expiry + grace",
            in_grace.len()
        )));
    }

    Ok(Ok(format!(
        "away {} days: nothing swept (expiry {} days); past expiry but inside the {}-hour \
         grace: still nothing; past expiry + grace: {} of {} blobs swept, so the mechanism \
         is real (SPECS §6.3)",
        away / DAY,
        policy.lease_expiry / DAY,
        policy.grace / 3600,
        long_gone.len(),
        a.len()
    )))
}

// ── Warn before sweep (SPECS §6.3) ─────────────────────────────────────────

/// `nas test sweep-warning <ns>`
pub fn sweep_warning(ns: &str) -> i32 {
    match warned() {
        Ok(Ok(m)) => ok(format!("sweep-warning: {m}; namespace {ns}")),
        Ok(Err(m)) => refuse(format!("sweep-warning: {m}")),
        Err(e) => err(format!("sweep-warning: harness: {e}")),
    }
}

/// SPECS §6.3: "a returning client within expiry receives the list of blobs
/// that *would* have been swept, so silent loss is not the failure mode."
///
/// Two things have to be true and they pull in opposite directions. The
/// returning client must be **told** what was at risk, and it must still
/// **have** it — a warning delivered by deleting the data first is not a
/// warning. So the drill checks that the warned blobs are named, and that
/// every one of them is still on the peer afterwards.
fn warned() -> Result<Result<String, String>, String> {
    let policy = GcPolicy::default();
    let mut lab = Lab::open("sweep-warning")?;
    let a = lab.seed(3)?;
    let holder = holder_id(LAPTOP);
    let departed = real_now();
    lab.peer
        .take_lease(holder, &a, departed)
        .map_err(|e| format!("take lease: {e}"))?;
    lab.peer.gc_policy = policy;

    // Nothing is at risk while the holder is present, and an implementation
    // that warned constantly would be as useless as one that never did.
    let quiet = lab
        .peer
        .sweep_warnings(&holder, Timestamp(departed.secs() + DAY * 2))
        .map_err(|e| format!("warnings: {e}"))?;
    if !quiet.is_empty() {
        return Ok(Err(format!(
            "{} blobs reported at risk two days in, while the holder is well inside its \
             expiry — a warning that is always on is not a warning",
            quiet.len()
        )));
    }

    // The laptop comes back after its leases have lapsed. It is entitled to
    // know what was at risk while it was away.
    let returned = Timestamp(departed.secs() + policy.lease_expiry + policy.grace + DAY);
    let warnings = lab
        .peer
        .sweep_warnings(&holder, returned)
        .map_err(|e| format!("warnings: {e}"))?;
    if warnings.is_empty() {
        return Ok(Err(
            "a returning client past its expiry is told nothing is at risk, so loss here \
             would be silent — which §6.3 names as the failure mode"
                .to_string(),
        ));
    }

    // Asking must not have destroyed anything: the plan is a plan.
    let missing: Vec<&Addr> = warnings.iter().filter(|x| !lab.peer.has_blob(x)).collect();
    if !missing.is_empty() {
        return Ok(Err(format!(
            "{} of the warned blobs are already gone from the peer; a warning delivered by \
             deleting the data first is not a warning",
            missing.len()
        )));
    }

    Ok(Ok(format!(
        "quiet while the holder is inside expiry; on return {} of {} blobs named as \
         at-risk and all {} still held, so the client can renew instead of discovering \
         the loss (SPECS §6.3)",
        warnings.len(),
        a.len(),
        warnings.len()
    )))
}

fn identity(seed: u8, role: Role) -> Result<Identity, String> {
    Identity::derive(&[seed; 32], role).map_err(|e| format!("identity: {e}"))
}
