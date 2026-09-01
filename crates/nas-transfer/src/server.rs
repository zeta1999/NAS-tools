//! Serving a [`Peer`] over the network.
//!
//! The dispatch below is the only place a request becomes an action, and it
//! calls straight into [`Peer`] — including its hostile branches. There is no
//! separate "hostile server": a peer started with `--hostile tamper` tampers
//! here, through the same `get_blob` an honest peer uses.

use crate::session::{Channel, SessionError};
use crate::wire::{record_cost, Request, Response, MAX_RECORDS, RECORD_BUDGET};
use nas_peer::{Peer, PeerError};
use nas_slots::{Checkpoint, SlotHandoff, SlotRecord, Witness};

/// Collect encoded items into a list response, bounded by both count and
/// bytes.
///
/// One place, because there are four list responses and the bound that was
/// missing — bytes — was missing from all of them. A peer that builds a
/// response it cannot send drops the connection instead of answering, and a
/// dropped connection is exactly what a refusal must never look like.
fn bounded<T, E: std::fmt::Display>(
    items: impl IntoIterator<Item = T>,
    encode: impl Fn(&T) -> Result<Vec<u8>, E>,
) -> Response {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut used = 0usize;
    for item in items {
        if out.len() == MAX_RECORDS {
            break;
        }
        let bytes = match encode(&item) {
            Ok(b) => b,
            Err(e) => return Response::Error(e.to_string()),
        };
        // Stop *before* going over, so what is returned always encodes. A
        // client that wanted more asks again from a higher `from`.
        if used + record_cost(bytes.len()) > RECORD_BUDGET {
            break;
        }
        used += record_cost(bytes.len());
        out.push(bytes);
    }
    Response::Records(out)
}

/// Handle one request against `peer`.
///
/// Errors become [`Response::Error`] rather than closing the connection: a
/// client must be able to tell "you may not do that" from "the peer went away",
/// and dropping the socket makes every refusal look like a network fault.
pub fn handle(peer: &mut Peer, subject: &str, req: Request) -> Response {
    // A witness-only node (SPECS §5.3) answers the two relay requests and
    // refuses the rest HERE, before any store is touched. "Holds no blobs and
    // no caps" is a property of what it will accept, and this is the one
    // place everything it accepts passes through.
    if peer.witness_only && !matches!(req, Request::PublishWitness(_) | Request::Witnesses(_)) {
        return Response::Error(PeerError::WitnessOnly.to_string());
    }
    match req {
        Request::GetBlob(addr) => match peer.get_blob(&addr) {
            Ok(b) => Response::Blob(b),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::HasBlob(addr) => Response::Bool(peer.has_blob(&addr)),
        Request::PutBlob(bytes) => match peer.put_blob(&bytes) {
            Ok(a) => Response::Stored(a),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Prove { addr, nonce } => match peer.prove(&addr, &nonce) {
            Ok(p) => Response::Proof(p),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::SlotHead(slot) => {
            Response::Record(peer.slot_head(&slot).and_then(|r| r.encode().ok()))
        }
        // Bounded by count and by bytes: a peer with a long history must
        // not build a response it then cannot send.
        Request::SlotHistory { slot, from } => {
            bounded(peer.slot_history(&slot, from), |r| r.encode())
        }
        Request::PublishSlot(bytes) => match SlotRecord::decode(&bytes) {
            Ok(rec) => match peer.publish_slot(subject, rec) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Err(e) => Response::Error(format!("{e}")),
        },
        // The witness relay (SPECS §5.3). Every peer relays; a witness-only
        // node relays and does nothing else (see the top of this function).
        Request::PublishWitness(bytes) => match Witness::decode(&bytes) {
            Ok(w) => match peer.publish_witness(w) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Err(e) => Response::Error(format!("{e}")),
        },
        Request::Witnesses(slot) => bounded(peer.witnesses(&slot), |w| w.encode()),
        // Ownership handoff (SPECS §5.1). The peer checks the signature and
        // stores it; whether a handoff is *relevant* is decided where a
        // writer actually changes -- in `publish_slot` here, and in the
        // client's own chain walk, both against the slot and sequence in the
        // signed body. Serving them is what lets a second device learn of a
        // change it did not make.
        Request::PublishHandoff(bytes) => match SlotHandoff::decode(&bytes) {
            Ok(h) => match peer.publish_handoff(h) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Err(e) => Response::Error(format!("{e}")),
        },
        Request::Handoffs(slot) => bounded(peer.handoffs(&slot), |h| h.encode()),
        // The skip chain (SPECS §5.5). The peer stores rungs and serves them
        // in order; it does not link them, prune them or decide which of two
        // conflicting rungs is real. That is the client's walk, against the
        // anchor only the client holds.
        Request::PublishCheckpoint(bytes) => match Checkpoint::decode(&bytes) {
            Ok(c) => match peer.publish_checkpoint(c) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Err(e) => Response::Error(format!("{e}")),
        },
        // A client that hits either cap climbs from a higher `from`, which
        // is the whole point of a ladder.
        Request::Checkpoints { slot, from } => {
            bounded(peer.checkpoints(&slot, from), |c| c.encode())
        }
    }
}

/// Serve requests until the client disconnects.
///
/// The ACL subject is derived from the authenticated identity; see the body.
pub fn serve(peer: &mut Peer, ch: &mut Channel) -> Result<usize, SessionError> {
    // The subject comes from the HANDSHAKE, not from an argument. There is no
    // parameter to pass an unbound string through any more, which is the point:
    // an ACL evaluated against a caller-supplied name enforces nothing.
    //
    // An unknown key gets `"?"`, which is in no ACL, so every rights check
    // returns `UnknownSubject` and every write is refused. Denying by default
    // matters more here than a tidy error.
    let subject = peer
        .subject_for(ch.peer_identity())
        .unwrap_or("?")
        .to_string();
    let mut served = 0usize;
    loop {
        let req = match ch.recv_request() {
            Ok(r) => r,
            // A clean disconnect is how a session ends, not an error.
            Err(SessionError::Truncated) => return Ok(served),
            Err(e) => return Err(e),
        };
        let rsp = handle(peer, &subject, req);
        ch.send_response(&rsp)?;
        served += 1;
    }
}

/// Convert a peer-side error into the text a client will see.
///
/// Kept as a function so the mapping is one place: a refusal must stay
/// recognisable as a refusal, and not turn into "internal error".
pub fn describe(e: &PeerError) -> String {
    e.to_string()
}
