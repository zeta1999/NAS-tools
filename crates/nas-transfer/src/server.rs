//! Serving a [`Peer`] over the network.
//!
//! The dispatch below is the only place a request becomes an action, and it
//! calls straight into [`Peer`] — including its hostile branches. There is no
//! separate "hostile server": a peer started with `--hostile tamper` tampers
//! here, through the same `get_blob` an honest peer uses.

use crate::session::{Channel, SessionError};
use crate::wire::{Request, Response, MAX_RECORDS};
use nas_peer::{Peer, PeerError};
use nas_slots::{SlotRecord, Witness};

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
        Request::SlotHistory { slot, from } => {
            let mut out = Vec::new();
            for r in peer.slot_history(&slot, from) {
                // Bounded here as well as in the encoder: a peer with a long
                // history must not build a response it then cannot send.
                if out.len() == MAX_RECORDS {
                    break;
                }
                match r.encode() {
                    Ok(b) => out.push(b),
                    Err(e) => return Response::Error(e.to_string()),
                }
            }
            Response::Records(out)
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
        Request::Witnesses(slot) => {
            let mut out = Vec::new();
            for w in peer.witnesses(&slot) {
                if out.len() == MAX_RECORDS {
                    break;
                }
                match w.encode() {
                    Ok(b) => out.push(b),
                    Err(e) => return Response::Error(e.to_string()),
                }
            }
            Response::Records(out)
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
