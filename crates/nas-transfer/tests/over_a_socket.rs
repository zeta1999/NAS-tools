//! End-to-end over a real TCP socket and a real PQC handshake.
//!
//! These are the first tests in the project where bytes cross a socket. What
//! they are for is not "does TCP work" but: **do the client-side defences still
//! fire when the peer is on the other end of a wire rather than in the same
//! process?** A check that only ever ran against an in-process peer would be
//! one refactor away from being bypassed by the network path.

use nas_core::{Addr, Mode};
use nas_crypto::{Identity as NasIdentity, Role};
use nas_peer::{Hostility, Peer, Right};
use nas_slots::{
    plan_walk, verify_chain, verify_skip_chain, Checkpoint, Regime, Roster, SlotHandoff, SlotId,
    SlotRecord, WalkPlan, WriterId, ROOT_NONCE_LEN,
};
use nas_store::{Addressing, BlobStore};
use nas_transfer::{Channel, Request, Response};
use simple_network::security::pqc::Identity;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("nas-xfer-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn slot() -> SlotId {
    SlotId::new(b"ns", b"bucket")
}

fn writer() -> NasIdentity {
    NasIdentity::derive(&[3u8; 32], Role::Slot).unwrap()
}

fn record(id: &NasIdentity, seq: u64, prev: [u8; 32], tag: &str) -> SlotRecord {
    SlotRecord::sign(
        id,
        slot(),
        seq,
        Addr::of_ciphertext(tag.as_bytes()),
        [1u8; ROOT_NONCE_LEN],
        prev,
        Regime::CasMerge,
    )
    .unwrap()
}

/// Run a peer on a background thread, hand back a connected client channel.
fn connected(tag: &str, hostility: Hostility, seed: impl FnOnce(&mut Peer)) -> (Scratch, Channel) {
    let s = Scratch::new(tag);
    let mut peer = Peer::open(&s.0, Mode::E2ee, Addressing::Content, hostility).unwrap();
    peer.roster.add(writer().verifying_key()).unwrap();
    peer.acl.grant("laptop", &[Right::Write]);
    seed(&mut peer);

    let server_id = Identity::generate().unwrap();
    let client_id = Identity::generate().unwrap();
    let server_vk = server_id.verifying_key();
    let client_vk = client_id.verifying_key();
    // The subject is bound to the client's transport key, not passed as a
    // string -- so the ACL is evaluated against whoever actually handshook.
    peer.bind_subject(&client_vk, "laptop");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready, wait) = mpsc::channel();

    thread::spawn(move || {
        ready.send(()).unwrap();
        let (sock, _) = listener.accept().unwrap();
        let mut ch = Channel::accept(sock, &server_id, client_vk).unwrap();
        let _ = nas_transfer::serve(&mut peer, &mut ch);
    });
    wait.recv().unwrap();

    let sock = TcpStream::connect(addr).unwrap();
    let ch = Channel::connect(sock, &client_id, server_vk).unwrap();
    (s, ch)
}

#[test]
fn a_blob_round_trips_over_the_wire() {
    let (_s, mut ch) = connected("roundtrip", Hostility::HONEST, |_| {});
    let ct = b"some ciphertext travelling over a socket";

    let stored = match ch.call(&Request::PutBlob(ct.to_vec())).unwrap() {
        Response::Stored(a) => a,
        other => panic!("{other:?}"),
    };
    assert_eq!(stored, Addr::of_ciphertext(ct));

    match ch.call(&Request::GetBlob(stored)).unwrap() {
        Response::Blob(b) => assert_eq!(b, ct),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ch.call(&Request::HasBlob(stored)).unwrap(),
        Response::Bool(true)
    );
}

#[test]
fn a_tampering_peer_is_caught_on_the_client_side_of_the_wire() {
    // The point of this file: the address check fires against a networked peer,
    // not only an in-process one.
    let (_s, mut ch) = connected(
        "tamper",
        Hostility {
            tamper: true,
            ..Hostility::HONEST
        },
        |_| {},
    );
    let ct = b"bytes the peer will corrupt in flight";
    let stored = match ch.call(&Request::PutBlob(ct.to_vec())).unwrap() {
        Response::Stored(a) => a,
        other => panic!("{other:?}"),
    };
    match ch.call(&Request::GetBlob(stored)).unwrap() {
        Response::Blob(b) => {
            assert_ne!(b, ct);
            assert!(
                !stored.verifies(&b),
                "tampering survived the wire undetected"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_dedup_lie_is_caught_by_proof_of_possession_over_the_wire() {
    // SPECS §4.5. The peer says it has the blob so the client skips the
    // upload; the challenge is what makes the claim checkable.
    let (_s, mut ch) = connected(
        "dedup",
        Hostility {
            dedup_lie: true,
            ..Hostility::HONEST
        },
        |_| {},
    );
    let ct = b"a blob the peer never received";
    let addr = Addr::of_ciphertext(ct);

    assert_eq!(
        ch.call(&Request::HasBlob(addr)).unwrap(),
        Response::Bool(true)
    );

    let nonce = [11u8; 32];
    match ch.call(&Request::Prove { addr, nonce }).unwrap() {
        // It cannot answer, because it does not have the bytes.
        Response::Error(_) => {}
        Response::Proof(p) => {
            assert!(
                !BlobStore::check_proof(ct, &nonce, &p),
                "a peer without the bytes produced a valid proof"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_rolling_back_peer_serves_a_stale_head_over_the_wire() {
    let id = writer();
    let (_s, mut ch) = connected(
        "rollback",
        Hostility {
            rollback: true,
            ..Hostility::HONEST
        },
        |p| {
            let mut prev = [0u8; 32];
            for seq in 0..4 {
                let r = record(&id, seq, prev, &format!("root-{seq}"));
                prev = r.record_hash();
                p.publish_slot("laptop", r).unwrap();
            }
        },
    );
    match ch.call(&Request::SlotHead(slot())).unwrap() {
        Response::Record(Some(bytes)) => {
            let r = SlotRecord::decode(&bytes).unwrap();
            assert_eq!(r.seq, 2, "expected the record before the head");
            // Validly signed: only a pin or a witness reveals the omission.
            assert!(r.verify(writer().verifying_key()).is_ok());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn cas_and_acl_refusals_arrive_as_refusals_not_as_disconnects() {
    // A client must be able to tell "you may not do that" from "the peer went
    // away". Dropping the socket would make every refusal look like a fault.
    let id = writer();
    let (_s, mut ch) = connected("refusals", Hostility::HONEST, |p| {
        p.publish_slot("laptop", record(&id, 0, [0u8; 32], "root-0"))
            .unwrap();
    });

    // seq 0 again: compare-and-swap lost.
    let stale = record(&id, 0, [0u8; 32], "root-0-again").encode().unwrap();
    match ch.call(&Request::PublishSlot(stale)).unwrap() {
        Response::Error(m) => assert!(m.contains("compare-and-swap"), "{m}"),
        other => panic!("{other:?}"),
    }

    // And the connection is still usable afterwards.
    assert_eq!(
        ch.call(&Request::HasBlob(Addr::of_ciphertext(b"x")))
            .unwrap(),
        Response::Bool(false)
    );
}

#[test]
fn an_unrostered_writer_is_refused_over_the_wire() {
    let (_s, mut ch) = connected("unrostered", Hostility::HONEST, |_| {});
    let stranger = NasIdentity::derive(&[99u8; 32], Role::Slot).unwrap();
    let bytes = record(&stranger, 0, [0u8; 32], "x").encode().unwrap();
    match ch.call(&Request::PublishSlot(bytes)).unwrap() {
        Response::Error(m) => assert!(m.contains("roster"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_chain_walk_crosses_the_wire_and_verifies() {
    let id = writer();
    let (_s, mut ch) = connected("walk", Hostility::HONEST, |p| {
        let mut prev = [0u8; 32];
        for seq in 0..6 {
            let r = record(&id, seq, prev, &format!("root-{seq}"));
            prev = r.record_hash();
            p.publish_slot("laptop", r).unwrap();
        }
    });
    match ch
        .call(&Request::SlotHistory {
            slot: slot(),
            from: 0,
        })
        .unwrap()
    {
        Response::Records(rs) => {
            let records: Vec<SlotRecord> =
                rs.iter().map(|b| SlotRecord::decode(b).unwrap()).collect();
            assert_eq!(records.len(), 6);
            let mut roster = nas_slots::Roster::new();
            roster.add(writer().verifying_key()).unwrap();
            nas_slots::verify_chain(&records, slot(), &roster, None).unwrap();
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_handshake_pins_the_peer_key() {
    // Trust on first use over an untrusted network is how a peer becomes
    // whoever answered first. The client states who it expects.
    let s = Scratch::new("pin");
    let mut peer = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
    peer.acl.grant("laptop", &[Right::Write]);

    let server_id = Identity::generate().unwrap();
    let client_id = Identity::generate().unwrap();
    let impostor = Identity::generate().unwrap();
    let client_vk = client_id.verifying_key();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready, wait) = mpsc::channel();
    thread::spawn(move || {
        ready.send(()).unwrap();
        if let Ok((sock, _)) = listener.accept() {
            let _ = Channel::accept(sock, &server_id, client_vk);
        }
    });
    wait.recv().unwrap();

    let sock = TcpStream::connect(addr).unwrap();
    // The client expects the impostor's key, not the server's.
    assert!(
        Channel::connect(sock, &client_id, impostor.verifying_key()).is_err(),
        "the client accepted a peer it had not pinned"
    );
}

#[test]
fn an_unbound_identity_is_denied_rather_than_defaulted() {
    // The subject used to be a string the caller passed to `serve`, bound to
    // nothing -- so whoever the server happened to wire was the subject for
    // every client. Now it comes from the handshake, and a key the peer has
    // never been told about maps to no subject at all.
    let s = Scratch::new("unbound");
    let mut peer = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
    peer.roster.add(writer().verifying_key()).unwrap();
    peer.acl.grant("laptop", &[Right::Write]);
    // Deliberately NOT calling bind_subject for this client.

    let server_id = Identity::generate().unwrap();
    let client_id = Identity::generate().unwrap();
    let server_vk = server_id.verifying_key();
    let client_vk = client_id.verifying_key();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready, wait) = mpsc::channel();
    thread::spawn(move || {
        ready.send(()).unwrap();
        let (sock, _) = listener.accept().unwrap();
        let mut ch = Channel::accept(sock, &server_id, client_vk).unwrap();
        let _ = nas_transfer::serve(&mut peer, &mut ch);
    });
    wait.recv().unwrap();

    let sock = TcpStream::connect(addr).unwrap();
    let mut ch = Channel::connect(sock, &client_id, server_vk).unwrap();

    let bytes = record(&writer(), 0, [0u8; 32], "root-0").encode().unwrap();
    match ch.call(&Request::PublishSlot(bytes)).unwrap() {
        Response::Error(m) => assert!(
            m.contains("unknown subject") || m.contains("refused"),
            "an unbound identity was not denied: {m}"
        ),
        other => panic!("an unbound identity was allowed to publish: {other:?}"),
    }
}

#[test]
fn the_subject_follows_the_key_that_handshook() {
    // Two clients, two keys, two subjects -- and the ACL distinguishes them.
    // Impossible to express before, because `serve` took one string.
    let s = Scratch::new("two-subjects");
    let mut peer = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
    peer.roster.add(writer().verifying_key()).unwrap();
    peer.acl.grant("writer-device", &[Right::Write]);
    peer.acl.grant("reader-device", &[Right::Read]);

    let server_id = Identity::generate().unwrap();
    let allowed = Identity::generate().unwrap();
    let refused = Identity::generate().unwrap();
    peer.bind_subject(&allowed.verifying_key(), "writer-device");
    peer.bind_subject(&refused.verifying_key(), "reader-device");
    let server_vk = server_id.verifying_key();

    for (id, should_publish) in [(allowed, true), (refused, false)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_vk = id.verifying_key();
        // The peer is moved into the thread and back out via the channel, so
        // both connections talk to the same peer state.
        let (tx, rx) = mpsc::channel();
        let (ready, wait) = mpsc::channel();
        let mut p = peer;
        let sid = server_id_clone(&server_id);
        thread::spawn(move || {
            ready.send(()).unwrap();
            let (sock, _) = listener.accept().unwrap();
            let mut ch = Channel::accept(sock, &sid, client_vk).unwrap();
            let _ = nas_transfer::serve(&mut p, &mut ch);
            tx.send(p).unwrap();
        });
        wait.recv().unwrap();

        let sock = TcpStream::connect(addr).unwrap();
        let mut ch = Channel::connect(sock, &id, server_vk.clone()).unwrap();
        let bytes = record(&writer(), 0, [0u8; 32], "root-0").encode().unwrap();
        let got = ch.call(&Request::PublishSlot(bytes)).unwrap();
        drop(ch);
        peer = rx.recv().unwrap();

        match (&got, should_publish) {
            (Response::Ok, true) => {}
            (Response::Error(_), false) => {}
            _ => panic!("should_publish={should_publish} but got {got:?}"),
        }
    }
}

/// `Identity` is not `Clone`; round-trip it the same way the session layer does.
fn server_id_clone(id: &Identity) -> Identity {
    let (sk, vk) = id.export().unwrap();
    Identity::from_bytes(&sk, &vk).unwrap()
}

// ── Ownership handoff over the wire (SPECS §5.1) ───────────────────────────
//
// The peer's §5.1 check reads a store nothing could reach from the network
// until these two requests existed: a handoff could only be learned in
// process, which is enough for a test and not enough for two devices. What
// these check is that crossing a socket neither weakens the rule nor makes an
// authorised change unlearnable by a device that did not make it.

fn successor() -> NasIdentity {
    NasIdentity::derive(&[9u8; 32], Role::Slot).unwrap()
}

fn sw_record(id: &NasIdentity, seq: u64, prev: [u8; 32]) -> SlotRecord {
    SlotRecord::sign(
        id,
        slot(),
        seq,
        Addr::of_ciphertext(format!("sw-{seq}").as_bytes()),
        [1u8; ROOT_NONCE_LEN],
        prev,
        Regime::SingleWriter,
    )
    .unwrap()
}

/// A peer serving a single-writer slot at seq 0, with both writers rostered.
fn single_writer_peer(tag: &str) -> (Scratch, Channel, [u8; 32]) {
    let g = sw_record(&writer(), 0, [0u8; 32]);
    let prev = g.record_hash();
    let (s, ch) = connected(tag, Hostility::HONEST, move |p| {
        p.roster.add(successor().verifying_key()).unwrap();
        p.publish_slot("laptop", g).unwrap();
    });
    (s, ch, prev)
}

fn handoff_at(seq: u64) -> SlotHandoff {
    SlotHandoff::sign(
        &writer(),
        slot(),
        seq,
        WriterId::of_key(successor().verifying_key()),
    )
    .unwrap()
}

#[test]
fn ownership_moves_over_the_wire_only_when_the_outgoing_writer_says_so() {
    let (_s, mut ch, prev) = single_writer_peer("handoff");
    let next = sw_record(&successor(), 1, prev).encode().unwrap();

    // The successor announcing itself is a takeover, and the wire does not
    // make it anything else.
    match ch.call(&Request::PublishSlot(next.clone())).unwrap() {
        Response::Error(m) => assert!(m.contains("second writer"), "{m}"),
        other => panic!("a takeover was accepted: {other:?}"),
    }

    // The outgoing writer's signature is the whole difference.
    assert_eq!(
        ch.call(&Request::PublishHandoff(handoff_at(1).encode().unwrap()))
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        ch.call(&Request::PublishSlot(next)).unwrap(),
        Response::Ok,
        "the authorised successor may write"
    );
}

#[test]
fn a_handoff_is_served_back_so_a_device_can_learn_of_a_change_it_did_not_make() {
    // This is what the two requests are for. A second device walking the
    // chain across an ownership change has no way to tell an authorised one
    // from a takeover unless it can ask for the record that authorised it.
    let (_s, mut ch, _prev) = single_writer_peer("serve-back");
    let h = handoff_at(1);
    ch.call(&Request::PublishHandoff(h.encode().unwrap()))
        .unwrap();

    match ch.call(&Request::Handoffs(slot())).unwrap() {
        Response::Records(rs) => {
            assert_eq!(rs.len(), 1);
            assert_eq!(SlotHandoff::decode(&rs[0]).unwrap(), h);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_handoff_for_another_sequence_does_not_travel_any_better_than_it_verifies() {
    let (_s, mut ch, prev) = single_writer_peer("wrong-seq");
    // Signed for seq 7; the successor tries to write seq 1.
    ch.call(&Request::PublishHandoff(handoff_at(7).encode().unwrap()))
        .unwrap();
    match ch
        .call(&Request::PublishSlot(
            sw_record(&successor(), 1, prev).encode().unwrap(),
        ))
        .unwrap()
    {
        Response::Error(m) => assert!(m.contains("second writer"), "{m}"),
        other => panic!("a handoff for seq 7 authorised seq 1: {other:?}"),
    }
}

#[test]
fn a_tampered_handoff_is_refused_at_the_far_end_and_nothing_is_kept() {
    let (_s, mut ch, _prev) = single_writer_peer("tampered");
    let mut h = handoff_at(1);
    h.at_seq = 2; // the signature still covers seq 1

    match ch
        .call(&Request::PublishHandoff(h.encode().unwrap()))
        .unwrap()
    {
        Response::Error(_) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ch.call(&Request::Handoffs(slot())).unwrap(),
        Response::Records(vec![]),
        "an unverifiable handoff must not be stored, or the store is a dumping ground"
    );
}

#[test]
fn undecodable_handoff_bytes_are_a_refusal_not_a_disconnect() {
    let (_s, mut ch, _prev) = single_writer_peer("junk");
    match ch.call(&Request::PublishHandoff(vec![0xFF; 40])).unwrap() {
        Response::Error(_) => {}
        other => panic!("{other:?}"),
    }
    // The session survives, so a client can tell a refusal from a dead peer.
    assert_eq!(
        ch.call(&Request::Handoffs(slot())).unwrap(),
        Response::Records(vec![])
    );
}

#[test]
fn a_witness_only_node_relays_witnesses_and_still_holds_no_handoffs() {
    // SPECS §5.3 says a witness-only node holds no blobs and no caps. A
    // handoff is an authorisation, not an observation, so adding the two
    // requests must not have widened what that node accepts.
    let (_s, mut ch) = connected("witness-only-handoff", Hostility::HONEST, |p| {
        p.witness_only = true;
    });
    for req in [
        Request::PublishHandoff(handoff_at(1).encode().unwrap()),
        Request::Handoffs(slot()),
    ] {
        match ch.call(&req).unwrap() {
            Response::Error(m) => assert!(m.contains("witness-only"), "{req:?}: {m}"),
            other => panic!("{req:?} was accepted: {other:?}"),
        }
    }
}

// ── Skip-chain checkpoints over the wire (SPECS §5.5) ──────────────────────

/// A ladder every `every` records over `records`.
fn ladder(id: &NasIdentity, records: &[SlotRecord], every: u64) -> Vec<Checkpoint> {
    let mut out: Vec<Checkpoint> = Vec::new();
    for r in records.iter().filter(|r| r.seq.is_multiple_of(every)) {
        let c = Checkpoint::of_record(id, r, out.last()).unwrap();
        out.push(c);
    }
    out
}

fn history(n: u64) -> Vec<SlotRecord> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for seq in 0..n {
        let r = record(&writer(), seq, prev, &format!("v{seq}"));
        prev = r.record_hash();
        out.push(r);
    }
    out
}

#[test]
fn a_client_climbs_the_ladder_across_the_wire_instead_of_reading_every_record() {
    // The §5.5 claim, end to end: fetch the rungs and the tail, and verify a
    // head 39 records deep having read 10 of them.
    let recs = history(40);
    let cps = ladder(&writer(), &recs, 10);
    let seeded = (recs.clone(), cps.clone());
    let (_s, mut ch) = connected("skip", Hostility::HONEST, move |p| {
        for r in seeded.0 {
            p.publish_slot("laptop", r).unwrap();
        }
        for c in seeded.1 {
            p.publish_checkpoint(c).unwrap();
        }
    });

    let rungs = match ch
        .call(&Request::Checkpoints {
            slot: slot(),
            from: 0,
        })
        .unwrap()
    {
        Response::Records(rs) => rs
            .iter()
            .map(|b| Checkpoint::decode(b).unwrap())
            .collect::<Vec<_>>(),
        other => panic!("{other:?}"),
    };
    assert_eq!(rungs.len(), 4, "rungs at 0, 10, 20, 30");

    let top = rungs.last().unwrap().seq;
    let tail = match ch
        .call(&Request::SlotHistory {
            slot: slot(),
            from: top,
        })
        .unwrap()
    {
        Response::Records(rs) => rs
            .iter()
            .map(|b| SlotRecord::decode(b).unwrap())
            .collect::<Vec<_>>(),
        other => panic!("{other:?}"),
    };

    let mut roster = Roster::new();
    roster.add(writer().verifying_key()).unwrap();
    let walk = verify_skip_chain(&rungs, &tail, slot(), &roster, None, &[]).unwrap();
    assert_eq!(walk.head_seq, 39);
    assert_eq!(walk.head_hash, recs[39].record_hash());
    assert_eq!(walk.records, 10);
    assert_eq!(walk.skipped, 30, "and it does not pretend otherwise");
}

#[test]
fn the_ladder_is_served_from_a_height_so_an_anchored_client_asks_for_less() {
    let recs = history(40);
    let cps = ladder(&writer(), &recs, 10);
    let seeded = cps.clone();
    let (_s, mut ch) = connected("skip-from", Hostility::HONEST, move |p| {
        for c in seeded {
            p.publish_checkpoint(c).unwrap();
        }
    });

    match ch
        .call(&Request::Checkpoints {
            slot: slot(),
            from: 20,
        })
        .unwrap()
    {
        Response::Records(rs) => {
            let got: Vec<u64> = rs
                .iter()
                .map(|b| Checkpoint::decode(b).unwrap().seq)
                .collect();
            assert_eq!(got, vec![20, 30]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_peer_that_drops_a_rung_cannot_hide_it() {
    // The ladder is hash-linked, so a peer serving a subset of it serves
    // something that does not verify -- which is the difference between a
    // chain of checkpoints and a pile of signed claims.
    let recs = history(40);
    let cps = ladder(&writer(), &recs, 10);
    let mut roster = Roster::new();
    roster.add(writer().verifying_key()).unwrap();

    let cut = vec![cps[0].clone(), cps[2].clone(), cps[3].clone()];
    assert!(verify_skip_chain(&cut, &recs[30..], slot(), &roster, None, &[]).is_err());
}

#[test]
fn a_rung_from_an_unrostered_writer_is_refused_over_the_wire() {
    let stranger = NasIdentity::derive(&[42u8; 32], Role::Slot).unwrap();
    let (_s, mut ch) = connected("skip-stranger", Hostility::HONEST, |_| {});
    let g = record(&stranger, 0, [0u8; 32], "g");
    let c = Checkpoint::of_record(&stranger, &g, None).unwrap();
    match ch
        .call(&Request::PublishCheckpoint(c.encode().unwrap()))
        .unwrap()
    {
        Response::Error(_) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn undecodable_checkpoint_bytes_are_a_refusal_not_a_disconnect() {
    let (_s, mut ch) = connected("skip-junk", Hostility::HONEST, |_| {});
    match ch
        .call(&Request::PublishCheckpoint(vec![0xFF; 40]))
        .unwrap()
    {
        Response::Error(_) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ch.call(&Request::Checkpoints {
            slot: slot(),
            from: 0
        })
        .unwrap(),
        Response::Records(vec![])
    );
}

#[test]
fn a_witness_only_node_holds_no_ladder_either() {
    let (_s, mut ch) = connected("witness-only-skip", Hostility::HONEST, |p| {
        p.witness_only = true;
    });
    for req in [
        Request::PublishCheckpoint(vec![1u8; 10]),
        Request::Checkpoints {
            slot: slot(),
            from: 0,
        },
    ] {
        match ch.call(&req).unwrap() {
            Response::Error(m) => assert!(m.contains("witness-only"), "{req:?}: {m}"),
            other => panic!("{req:?} was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_client_too_far_behind_for_one_response_climbs_instead_of_giving_up() {
    // The §5.5 case, and the one thing the ladder is actually FOR. A history
    // longer than `MAX_RECORDS` cannot be walked in one response: before the
    // ladder this was a dead end, and a client 600 records behind was refused
    // however honest the peer was.
    const N: u64 = 600;
    let recs = history(N);
    let cps = ladder(&writer(), &recs, 256);
    assert_eq!(
        cps.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![0, 256, 512]
    );
    let seeded = (recs.clone(), cps.clone());
    let (_s, mut ch) = connected("skip-long", Hostility::HONEST, move |p| {
        for r in seeded.0 {
            p.publish_slot("laptop", r).unwrap();
        }
        for c in seeded.1 {
            p.publish_checkpoint(c).unwrap();
        }
    });

    let mut roster = Roster::new();
    roster.add(writer().verifying_key()).unwrap();
    let head = &recs[(N - 1) as usize];

    let page = |ch: &mut Channel, from: u64| -> Vec<SlotRecord> {
        match ch
            .call(&Request::SlotHistory { slot: slot(), from })
            .unwrap()
        {
            Response::Records(rs) => rs.iter().map(|b| SlotRecord::decode(b).unwrap()).collect(),
            other => panic!("{other:?}"),
        }
    };
    // Paged, as the client does: one response carries what fits in `MAX_FRAME`,
    // and the checkpoint interval is larger than that, so without paging no
    // rung could ever leave a walkable tail and the ladder would be decorative.
    let fetch = |ch: &mut Channel, from: u64| -> Vec<SlotRecord> {
        let mut out: Vec<SlotRecord> = Vec::new();
        let mut next = from;
        loop {
            let p = page(ch, next);
            if p.is_empty() {
                break;
            }
            let last = p.last().unwrap().seq;
            out.extend(p);
            if last >= N - 1 || last < next {
                break;
            }
            next = last + 1;
        }
        out
    };

    // The dead end: an honest peer, an honest client, and the walk still does
    // not arrive, because one response cannot carry 600 records.
    //
    // Note what bounds it. `MAX_RECORDS` is 256, but a `SlotRecord` is ~3.5 KB
    // and 256 of them are three times `MAX_FRAME` — so the byte budget binds
    // first, well below the count. A client must therefore plan from what a
    // response actually carried, never from the ceiling.
    let one = page(&mut ch, 0);
    assert!(
        one.len() < nas_transfer::MAX_RECORDS,
        "the byte budget binds before the count: {} records",
        one.len()
    );
    let short = verify_chain(&one, slot(), &roster, None).unwrap();
    assert_eq!(
        short.head_seq,
        one.len() as u64 - 1,
        "it verifies, and reaches nowhere near {}",
        N - 1
    );

    // The ladder, and the plan that chooses it.
    let rungs: Vec<Checkpoint> = match ch
        .call(&Request::Checkpoints {
            slot: slot(),
            from: 0,
        })
        .unwrap()
    {
        Response::Records(rs) => rs.iter().map(|b| Checkpoint::decode(b).unwrap()).collect(),
        other => panic!("{other:?}"),
    };
    let seqs: Vec<u64> = rungs.iter().map(|c| c.seq).collect();
    // A budget of 300 rather than the client's real `RETAIN_N` of 1024: this
    // is testing that climbing works over a socket, not what a sensible budget
    // is, and 1024 would mean signing 1024 records to make the point. The
    // arithmetic itself is covered by `plan_tests` with no peer at all.
    let plan = plan_walk(0, N - 1, &seqs, 300);
    assert_eq!(
        plan,
        WalkPlan::Skip {
            top_seq: 512,
            skipped: 512,
            records: 88
        },
        "planned from what one response actually carried"
    );

    let tail = fetch(&mut ch, 512);
    let walk = verify_skip_chain(&rungs, &tail, slot(), &roster, None, &[]).unwrap();
    assert_eq!(walk.head_seq, N - 1, "the head is reached");
    assert_eq!(walk.head_hash, head.record_hash());
    // And the cost of arriving is reported rather than hidden: 88 records
    // verified link by link, 512 taken on the writer's word.
    assert_eq!(walk.records, 88);
    assert_eq!(walk.skipped, 512);
    assert_eq!(walk.records as u64 + walk.skipped, N);
}

#[test]
fn a_response_too_large_to_send_is_shortened_not_dropped() {
    // Regression, and the rule it broke: a partial answer must never arrive as
    // the connection going away. The peer built a 256-record response, failed
    // to encode it because it was three times `MAX_FRAME`, and dropped the
    // socket; the client saw `Truncated`, which is indistinguishable from the
    // peer dying.
    let recs = history(400);
    let seeded = recs.clone();
    let (_s, mut ch) = connected("oversize", Hostility::HONEST, move |p| {
        for r in seeded {
            p.publish_slot("laptop", r).unwrap();
        }
    });

    let got = match ch
        .call(&Request::SlotHistory {
            slot: slot(),
            from: 0,
        })
        .unwrap()
    {
        Response::Records(rs) => rs,
        other => panic!("{other:?}"),
    };
    assert!(!got.is_empty(), "a short answer, not no answer");
    assert!(got.len() < 400);
    // What came back is contiguous from the start, so the client can walk it
    // and ask again from where it ended.
    let chain: Vec<SlotRecord> = got.iter().map(|b| SlotRecord::decode(b).unwrap()).collect();
    let mut roster = Roster::new();
    roster.add(writer().verifying_key()).unwrap();
    let w = verify_chain(&chain, slot(), &roster, None).unwrap();
    assert_eq!(w.head_seq, chain.len() as u64 - 1);

    // And the session is still alive.
    assert_eq!(
        ch.call(&Request::HasBlob(Addr::of_ciphertext(b"nothing")))
            .unwrap(),
        Response::Bool(false)
    );
}

#[test]
fn a_ladder_longer_than_one_response_is_paged_from_the_bottom() {
    // Same defect family as the history walk: one response carries what fits
    // in `MAX_FRAME`, so a client asking once gets the ladder truncated at the
    // BOTTOM — losing exactly the high rungs a far-behind client would climb
    // to, and turning a good ladder into "unreachable".
    const RUNGS: u64 = 100;
    let mut cps: Vec<Checkpoint> = Vec::new();
    for i in 0..RUNGS {
        let c = Checkpoint::sign(
            &writer(),
            slot(),
            i * 10,
            [i as u8; 32],
            cps.last().map(|p: &Checkpoint| p.seq).unwrap_or(0),
            cps.last().map(|p| p.checkpoint_hash()).unwrap_or([0u8; 32]),
        )
        .unwrap();
        cps.push(c);
    }
    let seeded = cps.clone();
    let (_s, mut ch) = connected("ladder-paged", Hostility::HONEST, move |p| {
        for c in seeded {
            p.publish_checkpoint(c).unwrap();
        }
    });

    let page = |ch: &mut Channel, from: u64| -> Vec<Checkpoint> {
        match ch
            .call(&Request::Checkpoints { slot: slot(), from })
            .unwrap()
        {
            Response::Records(rs) => rs.iter().map(|b| Checkpoint::decode(b).unwrap()).collect(),
            other => panic!("{other:?}"),
        }
    };

    let first = page(&mut ch, 0);
    assert!(
        (first.len() as u64) < RUNGS,
        "one response does not hold the ladder: {} of {RUNGS}",
        first.len()
    );

    let mut got: Vec<Checkpoint> = Vec::new();
    let mut next = 0u64;
    loop {
        let p = page(&mut ch, next);
        if p.is_empty() {
            break;
        }
        let last = p.last().unwrap().seq;
        got.extend(p);
        if last < next {
            break;
        }
        next = last + 1;
    }
    assert_eq!(got.len() as u64, RUNGS, "paging reaches the top");
    assert_eq!(got.last().unwrap().seq, (RUNGS - 1) * 10);

    // And the paged ladder is still a chain: it verifies end to end.
    let mut roster = Roster::new();
    roster.add(writer().verifying_key()).unwrap();
    let w = verify_skip_chain(&got, &[], slot(), &roster, None, &[]).unwrap();
    assert_eq!(w.checkpoints as u64, RUNGS);
    assert_eq!(w.head_seq, (RUNGS - 1) * 10);
}
