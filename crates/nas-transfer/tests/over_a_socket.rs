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
use nas_slots::{Regime, SlotId, SlotRecord, ROOT_NONCE_LEN};
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
