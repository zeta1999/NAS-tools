//! `nas test attack <kind>` — the UC09 hostile-peer drills (SPECS §19, §20).
//!
//! Each drill runs the **same dispatch the network server uses**
//! ([`nas_transfer::handle`]) against a [`Peer`] opened with one hostility
//! flag, and asks the client-side control to notice. The PQC transport is not
//! in the loop: it is UC07's subject, and a socket between two halves of one
//! process would test the socket, not the control.
//!
//! Every drill first runs the same flow against an **honest** peer and requires
//! it to succeed. Without that, a control that rejects everything — or a
//! harness that is simply broken — would score as "attack detected".
//!
//! Exit contract, as the harness scores it:
//! - the control fired → [`exit::OK`];
//! - the attack went through unnoticed → [`exit::REFUSED`]: a missing control
//!   is a security failure, not an error;
//! - the control is specified but unbuilt → [`exit::UNIMPLEMENTED`], never a
//!   pass.

use crate::exit;
use crate::testcmds::unimplemented;
use nas_core::{Addr, Mode};
use nas_crypto::{Identity, Role};
use nas_peer::{Hostility, Peer, Right};
use nas_slots::{
    Anchor, Regime, Roster, SlotClient, SlotId, SlotRecord, Verdict, Witness, ROOT_NONCE_LEN,
};
use nas_store::{Addressing, BlobStore};
use nas_transfer::{handle, Request, Response};
use std::fs;
use std::path::PathBuf;

/// The one ACL subject every drill acts as. Bound to nothing here because the
/// binding (handshake key → subject) is the transport's job, tested in UC07.
const SUBJECT: &str = "device";

pub struct AttackOpts {
    /// A second, honest, witness-only relay exists (SPECS §5.3).
    pub with_witness_node: bool,
    /// The client holds a capability and nothing else: no pin, no history.
    pub cold_start: bool,
}

enum Outcome {
    /// The control fired.
    Detected(String),
    /// The attack went through unnoticed.
    Undetected(String),
    /// Specified, unbuilt.
    Pending(&'static str),
}

/// A peer with the server dispatch in front of it, in a scratch directory
/// that goes away with it.
struct Lab {
    peer: Peer,
    dir: PathBuf,
}

impl Lab {
    fn open(tag: &str, hostility: Hostility, writer: &Identity) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("nas-attack-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut peer = Peer::open(&dir, Mode::E2ee, Addressing::Content, hostility)
            .map_err(|e| format!("open peer: {e}"))?;
        peer.roster
            .add(writer.verifying_key())
            .map_err(|e| format!("roster: {e}"))?;
        peer.acl.grant(SUBJECT, &[Right::Read, Right::Write]);
        Ok(Self { peer, dir })
    }

    fn honest(tag: &str, writer: &Identity) -> Result<Self, String> {
        Self::open(tag, Hostility::HONEST, writer)
    }

    /// One request through the real dispatch.
    fn call(&mut self, req: Request) -> Response {
        handle(&mut self.peer, SUBJECT, req)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<Addr, String> {
        match self.call(Request::PutBlob(bytes.to_vec())) {
            Response::Stored(a) => Ok(a),
            other => Err(format!("put: unexpected reply {other:?}")),
        }
    }

    fn publish(&mut self, rec: &SlotRecord) -> Result<(), String> {
        let bytes = rec.encode().map_err(|e| e.to_string())?;
        match self.call(Request::PublishSlot(bytes)) {
            Response::Ok => Ok(()),
            Response::Error(e) => Err(e),
            other => Err(format!("publish: unexpected reply {other:?}")),
        }
    }

    fn head(&mut self, slot: SlotId) -> Result<Option<SlotRecord>, String> {
        match self.call(Request::SlotHead(slot)) {
            Response::Record(None) => Ok(None),
            Response::Record(Some(b)) => SlotRecord::decode(&b)
                .map(Some)
                .map_err(|e| format!("head: {e}")),
            other => Err(format!("head: unexpected reply {other:?}")),
        }
    }

    fn history(&mut self, slot: SlotId, from: u64) -> Result<Vec<SlotRecord>, String> {
        match self.call(Request::SlotHistory { slot, from }) {
            Response::Records(rs) => rs
                .iter()
                .map(|b| SlotRecord::decode(b).map_err(|e| format!("history: {e}")))
                .collect(),
            other => Err(format!("history: unexpected reply {other:?}")),
        }
    }

    fn publish_witness(&mut self, w: &Witness) -> Result<(), String> {
        let bytes = w.encode().map_err(|e| e.to_string())?;
        match self.call(Request::PublishWitness(bytes)) {
            Response::Ok => Ok(()),
            Response::Error(e) => Err(e),
            other => Err(format!("publish witness: unexpected reply {other:?}")),
        }
    }

    fn witnesses(&mut self, slot: SlotId) -> Result<Vec<Witness>, String> {
        match self.call(Request::Witnesses(slot)) {
            Response::Records(ws) => ws
                .iter()
                .map(|b| Witness::decode(b).map_err(|e| format!("witnesses: {e}")))
                .collect(),
            other => Err(format!("witnesses: unexpected reply {other:?}")),
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

/// Deterministic identities: a drill that varies between runs is not a drill.
fn identity(seed: u8, role: Role) -> Result<Identity, String> {
    Identity::derive(&[seed; 32], role).map_err(|e| format!("identity: {e}"))
}

fn slot() -> SlotId {
    SlotId::new(b"nas test attack", b"root")
}

/// A signed record whose root is distinguishable by `tag`. Genesis when
/// `prev` is all zero, chained otherwise.
fn record(writer: &Identity, seq: u64, prev: [u8; 32], tag: u8) -> Result<SlotRecord, String> {
    let root = Addr::of_ciphertext(&[tag; 16]);
    SlotRecord::sign(
        writer,
        slot(),
        seq,
        root,
        [0u8; ROOT_NONCE_LEN],
        prev,
        Regime::SingleWriter,
    )
    .map_err(|e| format!("sign record: {e}"))
}

/// `[r0, r1, …]` chained, each root distinct.
fn chain(writer: &Identity, n: u64) -> Result<Vec<SlotRecord>, String> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for seq in 0..n {
        let r = record(writer, seq, prev, seq as u8 + 1)?;
        prev = r.record_hash();
        out.push(r);
    }
    Ok(out)
}

fn roster_of(writer: &Identity) -> Result<Roster, String> {
    let mut r = Roster::new();
    r.add(writer.verifying_key())
        .map_err(|e| format!("roster: {e}"))?;
    Ok(r)
}

fn anchored_at(r: &SlotRecord) -> Anchor {
    Anchor {
        seq: r.seq,
        sig_hash: r.sig_hash(),
    }
}

/// Bytes a client would push: anything, since address verification is over
/// the bytes as stored, not their meaning.
fn ciphertext(tag: u8) -> Vec<u8> {
    (0..4096u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
        .collect()
}

// ── Drills ─────────────────────────────────────────────────────────────────

/// SPECS §3.4: the client hashes what it received.
fn tamper(writer: &Identity) -> Result<Outcome, String> {
    let ct = ciphertext(1);
    let addr = Addr::of_ciphertext(&ct);

    let mut honest = Lab::honest("tamper-honest", writer)?;
    honest.put(&ct)?;
    match honest.call(Request::GetBlob(addr)) {
        Response::Blob(b) if addr.verifies(&b) => {}
        other => return Err(format!("honest round trip failed: {other:?}")),
    }

    let mut lab = Lab::open(
        "tamper",
        Hostility {
            tamper: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    lab.put(&ct)?;
    Ok(match lab.call(Request::GetBlob(addr)) {
        Response::Blob(b) if addr.verifies(&b) => {
            Outcome::Undetected("served bytes verified against the address".into())
        }
        Response::Blob(b) => Outcome::Detected(format!(
            "{} B served for {} do not hash to it — address verification refused the blob (SPECS §3.4)",
            b.len(),
            addr.to_hex()
        )),
        other => Outcome::Detected(format!("peer would not serve the blob: {other:?}")),
    })
}

/// SPECS §16: not a cryptographic catch. The client holds a receipt for an
/// upload the peer now denies; what makes that survivable is leases and
/// replication, not a check.
fn withhold(writer: &Identity) -> Result<Outcome, String> {
    let ct = ciphertext(2);
    let addr = Addr::of_ciphertext(&ct);

    let mut honest = Lab::honest("withhold-honest", writer)?;
    honest.put(&ct)?;
    match honest.call(Request::GetBlob(addr)) {
        Response::Blob(b) if addr.verifies(&b) => {}
        other => return Err(format!("honest round trip failed: {other:?}")),
    }

    let mut lab = Lab::open(
        "withhold",
        Hostility {
            withhold: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    let receipt = lab.put(&ct)?;
    if receipt != addr {
        return Err("peer acknowledged a different address than the bytes hash to".into());
    }
    Ok(match lab.call(Request::GetBlob(addr)) {
        Response::Blob(b) if addr.verifies(&b) => {
            Outcome::Undetected("the withholding peer served the blob after all".into())
        }
        Response::Blob(_) => Outcome::Detected("served bytes failed address verification".into()),
        Response::Error(e) => Outcome::Detected(format!(
            "peer acknowledged storing {} and now answers `{e}` — noticed against the client's receipt; indistinguishable from loss, so the remedy is leases and replication (SPECS §16), not a check",
            addr.to_hex()
        )),
        other => Outcome::Detected(format!("unexpected reply {other:?} for a blob the peer acknowledged")),
    })
}

/// SPECS §4.5: a `has` answer is never acted on without a proof-of-possession
/// challenge, because a lie here turns dedup into silent deletion.
fn dedup_lie(writer: &Identity) -> Result<Outcome, String> {
    let ct = ciphertext(3);
    let addr = Addr::of_ciphertext(&ct);
    let nonce = [0x5a; 32];

    let mut honest = Lab::honest("dedup-honest", writer)?;
    match honest.call(Request::HasBlob(addr)) {
        Response::Bool(false) => {}
        other => {
            return Err(format!(
                "honest peer claims a blob it never received: {other:?}"
            ))
        }
    }

    let mut lab = Lab::open(
        "dedup-lie",
        Hostility {
            dedup_lie: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    match lab.call(Request::HasBlob(addr)) {
        Response::Bool(true) => {}
        other => return Err(format!("dedup_lie peer did not lie: {other:?}")),
    }
    // The client does not skip the upload on `true`; it challenges.
    Ok(match lab.call(Request::Prove { addr, nonce }) {
        Response::Proof(p) if BlobStore::check_proof(&ct, &nonce, &p) => Outcome::Undetected(
            "peer answered the possession challenge for bytes it never received".into(),
        ),
        Response::Proof(_) => Outcome::Detected(
            "claimed possession, produced a proof that does not match the bytes — client uploads anyway (SPECS §4.5)".into(),
        ),
        Response::Error(e) => Outcome::Detected(format!(
            "claimed possession of {}, failed the proof-of-possession challenge (`{e}`) — client uploads anyway (SPECS §4.5)",
            addr.to_hex()
        )),
        other => Outcome::Detected(format!("challenge answered with {other:?}")),
    })
}

/// SPECS §5.3: caught by the pin (a client with history) or by the cap anchor
/// (a client with none).
fn rollback(writer: &Identity, cold: bool) -> Result<Outcome, String> {
    let recs = chain(writer, 3)?;
    let roster = roster_of(writer)?;

    let mut honest = Lab::honest("rollback-honest", writer)?;
    for r in &recs {
        honest.publish(r)?;
    }
    match honest.head(slot())? {
        Some(h) if h.seq == 2 => {}
        other => return Err(format!("honest peer head is {other:?}, expected seq 2")),
    }

    let mut lab = Lab::open(
        "rollback",
        Hostility {
            rollback: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    for r in &recs {
        lab.publish(r)?;
    }
    let mut client = if cold {
        // A capability issued at the head, and nothing else.
        SlotClient::new(slot(), Regime::SingleWriter, anchored_at(&recs[2]))
    } else {
        // The device that published: it pins what it wrote.
        let mut c = SlotClient::new(slot(), Regime::SingleWriter, anchored_at(&recs[0]));
        match c.offer(&recs, &roster) {
            Verdict::Accepted { .. } => {}
            v => return Err(format!("writer could not pin its own history: {v:?}")),
        }
        c
    };

    let served = lab
        .head(slot())?
        .ok_or("rolling-back peer served no head at all")?;
    let verdict = client.offer_head_only(&served, &roster);
    Ok(match verdict {
        Verdict::Accepted { .. } | Verdict::Degraded { .. } => Outcome::Undetected(format!(
            "accepted seq {} as head after seq 2 was published",
            served.seq
        )),
        Verdict::Rejected(r) => Outcome::Detected(format!(
            "peer served seq {} as head; {} client refused: {r} (SPECS §5.3)",
            served.seq,
            if cold { "cap-anchored" } else { "pinned" }
        )),
        Verdict::Alarm(_) => Outcome::Detected("fork proof raised".into()),
    })
}

/// A peer that keeps a write compare-and-swap should have refused, and serves
/// that branch to another client (SPECS §5.2, §5.3).
fn cas_non_enforcement(writer: &Identity, cold: bool) -> Result<Outcome, String> {
    let base = chain(writer, 2)?;
    let (r0, r1a) = (&base[0], &base[1]);
    // The loser: same seq, same predecessor, different root.
    let r1b = record(writer, 1, r0.record_hash(), 0xB1)?;
    let roster = roster_of(writer)?;

    let mut honest = Lab::honest("cas-honest", writer)?;
    honest.publish(r0)?;
    honest.publish(r1a)?;
    if honest.publish(&r1b).is_ok() {
        return Err("honest peer accepted a conflicting write at seq 1".into());
    }

    let mut lab = Lab::open(
        "cas",
        Hostility {
            fork: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    lab.publish(r0)?;
    lab.publish(r1a)?;
    if let Err(e) = lab.publish(&r1b) {
        return Err(format!(
            "forking peer refused the conflicting write ({e}); nothing to detect"
        ));
    }

    let mut client = if cold {
        // A capability issued against branch A.
        SlotClient::new(slot(), Regime::SingleWriter, anchored_at(r1a))
    } else {
        let mut c = SlotClient::new(slot(), Regime::SingleWriter, anchored_at(r0));
        match c.offer(&base, &roster) {
            Verdict::Accepted { .. } => {}
            v => return Err(format!("client could not pin branch A: {v:?}")),
        }
        c
    };

    // Another connection: the peer shows this one the other branch.
    lab.peer.set_view(1);
    let served = lab.history(slot(), 0)?;
    let branch_b = served
        .iter()
        .any(|r| r.seq == 1 && r.record_hash() == r1b.record_hash());
    if !branch_b {
        return Err("forking peer served branch A to the second view".into());
    }
    let verdict = client.offer(&served, &roster);
    Ok(match (verdict, client.forked()) {
        (Verdict::Accepted { .. } | Verdict::Degraded { .. }, None) => {
            Outcome::Undetected("branch B accepted with no fork evidence".into())
        }
        (v, forked) => Outcome::Detected(format!(
            "peer kept a CAS loser and served it as seq 1; {} client: {}; fork evidence at seq {:?} (SPECS §5.2, §5.3)",
            if cold { "cap-anchored" } else { "pinned" },
            match v {
                Verdict::Rejected(r) => format!("refused — {r}"),
                Verdict::Alarm(_) => "fork proof raised".into(),
                Verdict::Accepted { .. } => "accepted the walk, but the evidence set shows two heads".into(),
                Verdict::Degraded { .. } => "degraded".into(),
            },
            forked
        )),
    })
}

/// SPECS §5.4: a relay that withholds witnesses is indistinguishable from an
/// idle one, so this is caught only when a second relay exists.
fn witness_withholding(writer: &Identity, with_node: bool, cold: bool) -> Result<Outcome, String> {
    if !with_node {
        return Ok(Outcome::Undetected(
            "from a single relay, withheld witnesses look exactly like none having been published (SPECS §5.4, the `ForkAlwaysDetected` must-fail) — rerun with --with-witness-node".into(),
        ));
    }
    let base = chain(writer, 2)?;
    let (r0, r1a) = (&base[0], &base[1]);
    let r1b = record(writer, 1, r0.record_hash(), 0xB2)?;
    let roster = roster_of(writer)?;
    let observer = identity(0x0B, Role::Witness)?;
    let w = Witness::sign(&observer, slot(), 1, r1a.sig_hash(), 1)
        .map_err(|e| format!("witness: {e}"))?;

    // Relay sanity: an honest peer hands back what was published to it.
    let mut honest = Lab::honest("witness-honest", writer)?;
    honest.publish_witness(&w)?;
    if honest.witnesses(slot())?.len() != 1 {
        return Err("honest peer did not relay the witness".into());
    }

    let mut lab = Lab::open(
        "witness",
        Hostility {
            fork: true,
            withhold_witnesses: true,
            ..Hostility::HONEST
        },
        writer,
    )?;
    let mut node = Lab::honest("witness-node", writer)?;
    node.peer.witness_only = true;

    // Device A publishes branch A and its observation of it — to both relays.
    lab.publish(r0)?;
    lab.publish(r1a)?;
    lab.publish(&r1b)
        .map_err(|e| format!("forking peer refused the conflicting write: {e}"))?;
    lab.publish_witness(&w)?;
    node.publish_witness(&w)?;
    if let Response::Stored(_) = node.call(Request::PutBlob(ciphertext(9))) {
        return Err("the witness-only node accepted a blob".into());
    }

    // Device B is shown branch B. Each walk verifies on its own.
    lab.peer.set_view(1);
    let served = lab.history(slot(), 0)?;
    let mut b = SlotClient::new(slot(), Regime::SingleWriter, anchored_at(r0));
    if !cold {
        // A warm B has already walked branch B once before; a cold B walks it
        // now for the first time. Same evidence either way.
    }
    match b.offer(&served, &roster) {
        Verdict::Accepted { .. } => {}
        v => return Err(format!("branch B did not verify on its own: {v:?}")),
    }
    b.trust_witness(observer.verifying_key())
        .map_err(|e| format!("trust witness: {e}"))?;

    let from_peer = lab.witnesses(slot())?;
    for x in &from_peer {
        b.observe_witness(x);
    }
    let alone = b.forked();
    let from_node = node.witnesses(slot())?;
    let admitted = from_node.iter().filter(|x| b.observe_witness(x)).count();

    Ok(match b.forked() {
        Some(seq) => Outcome::Detected(format!(
            "hostile relay returned {} witnesses (fork invisible: {alone:?}); witness node returned {}, {admitted} admitted; fork evidence at seq {seq} (SPECS §5.3, §5.4)",
            from_peer.len(),
            from_node.len()
        )),
        None => Outcome::Undetected(format!(
            "no fork evidence even with the witness node ({} witnesses returned, {admitted} admitted)",
            from_node.len()
        )),
    })
}

fn lease_griefing() -> Outcome {
    Outcome::Pending("M2 (§16)")
}

// ── Entry point ────────────────────────────────────────────────────────────

const KINDS: &[&str] = &[
    "tamper",
    "rollback",
    "withhold",
    "dedup-lie",
    "cas-non-enforcement",
    "lease-griefing",
    "witness-withholding",
];

fn run(kind: &str, writer: &Identity, o: &AttackOpts) -> Result<Outcome, String> {
    Ok(match kind {
        "tamper" => tamper(writer)?,
        "rollback" => rollback(writer, o.cold_start)?,
        "withhold" => withhold(writer)?,
        "dedup-lie" => dedup_lie(writer)?,
        "cas-non-enforcement" => cas_non_enforcement(writer, o.cold_start)?,
        "witness-withholding" => witness_withholding(writer, o.with_witness_node, o.cold_start)?,
        "lease-griefing" => lease_griefing(),
        other => {
            return Err(format!(
                "unknown attack `{other}`; one of {}, all",
                KINDS.join(", ")
            ))
        }
    })
}

fn report(kind: &str, outcome: &Outcome) {
    match outcome {
        Outcome::Detected(m) => println!("attack {kind}: detected — {m}"),
        Outcome::Undetected(m) => println!("attack {kind}: NOT detected — {m}"),
        Outcome::Pending(ms) => println!("attack {kind}: pending ({ms})"),
    }
}

/// `nas test attack <kind> [--with-witness-node] [--cold-start]`
pub fn attack(kind: &str, o: AttackOpts) -> i32 {
    let writer = match identity(0x0A, Role::Slot) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return exit::ERROR;
        }
    };
    let kinds: Vec<&str> = if kind == "all" {
        KINDS.to_vec()
    } else {
        vec![kind]
    };
    // "All of the above" includes the topology in which the witness attack is
    // detectable at all; without it the single-relay case is provably not.
    let o = AttackOpts {
        with_witness_node: o.with_witness_node || kind == "all",
        cold_start: o.cold_start,
    };
    if o.cold_start {
        println!("client posture: cold start — a capability and nothing else");
    }

    let (mut undetected, mut pending) = (Vec::new(), Vec::new());
    for k in kinds {
        let outcome = match run(k, &writer, &o) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("error: attack {k}: harness: {e}");
                return exit::ERROR;
            }
        };
        report(k, &outcome);
        match outcome {
            Outcome::Detected(_) => {}
            Outcome::Undetected(_) => undetected.push(k),
            Outcome::Pending(ms) => pending.push((k, ms)),
        }
    }
    if !undetected.is_empty() {
        eprintln!("refused: undetected attack(s): {}", undetected.join(", "));
        return exit::REFUSED;
    }
    if let Some((k, ms)) = pending.first() {
        return unimplemented(&format!("test attack {k}"), ms);
    }
    exit::OK
}
