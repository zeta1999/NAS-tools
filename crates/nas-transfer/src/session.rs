//! Framed messages over a PQC session (SPECS §14).
//!
//! `simple-network`'s `Initiator`/`Responder` do the ML-KEM-768 + X25519
//! handshake **synchronously**; only its connection wrappers are async. Using
//! the synchronous core keeps NAS-tools free of an async runtime in its own
//! code paths, which matters here: the rest of the system is `std::fs` and
//! blocking I/O, and half-converting it would be worse than either.
//!
//! # Framing, and why the length is checked twice
//!
//! Each message goes out as `le32(len) ‖ sealed`. The length is checked against
//! [`MAX_FRAME`](crate::wire::MAX_FRAME) **before** the read buffer is
//! allocated, and the decoded body is checked again after opening — because the
//! first check bounds what an attacker can make us allocate, and the second
//! bounds what a *decrypted* body may claim. They are different attackers'
//! budgets and conflating them would leave one of the two unchecked.

use crate::wire::{Request, Response, WireError, MAX_FRAME};
use simple_network::security::pqc::{Identity, Initiator, Responder, SecureSession};
use std::io::{self, Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Wire(WireError),
    /// The handshake or an AEAD open failed. One error on purpose: "wrong peer"
    /// and "tampered frame" are the same event from here.
    Crypto(String),
    /// A length prefix beyond [`MAX_FRAME`], refused before allocating.
    FrameTooLarge {
        len: usize,
    },
    /// The peer closed mid-message.
    Truncated,
    /// The peer stopped sending. Distinct from `Truncated`, because a stall is
    /// an attack and a clean close is not.
    TimedOut,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Crypto(m) => write!(f, "secure channel: {m}"),
            Self::FrameTooLarge { len } => {
                write!(f, "peer announced a {len} B frame, limit is {MAX_FRAME} B")
            }
            Self::Truncated => write!(f, "peer closed mid-message"),
            Self::TimedOut => write!(f, "peer stalled for more than {IO_TIMEOUT:?}"),
        }
    }
}
impl std::error::Error for SessionError {}
impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<WireError> for SessionError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// How long a single framed read may block.
///
/// There were no timeouts at all: a client that completed the handshake, sent a
/// four-byte length prefix and then stopped pinned a server thread forever —
/// a slow loris costing the attacker one socket. The handshake reads are
/// covered too, so a peer can be stalled *before* any session exists.
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A connected, authenticated channel to the other side.
pub struct Channel {
    stream: TcpStream,
    session: SecureSession,
    /// The verifying key this channel is authenticated against.
    ///
    /// Kept so a server can derive *who is asking* from the handshake rather
    /// than from a string a caller passes in. It was discarded before, which
    /// left `serve` taking a free-form `subject` that nothing bound to the
    /// authenticated identity — an ACL evaluated against an unbound string is
    /// decorative.
    peer_vk: Vec<u8>,
}

impl Channel {
    /// Connect and complete the handshake as the initiator.
    ///
    /// `peer_vk` is **pinned**: the caller states which peer it expects, and a
    /// different one fails rather than being trusted on first use. Trust on
    /// first use over an untrusted network is how a peer becomes whoever
    /// answered first.
    pub fn connect(
        stream: TcpStream,
        id: &Identity,
        peer_vk: Vec<u8>,
    ) -> Result<Self, SessionError> {
        let mut stream = stream;
        set_timeouts(&stream)?;
        let pinned = peer_vk.clone();
        let init = Initiator::new(clone_identity(id)?, peer_vk)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        let hello = init
            .hello()
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        write_frame(&mut stream, &hello)?;
        let reply = read_frame(&mut stream)?;
        let session = init
            .finish(&reply)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        Ok(Self {
            stream,
            session,
            peer_vk: pinned,
        })
    }

    /// Complete the handshake as the responder, for one expected client.
    pub fn accept(
        stream: TcpStream,
        id: &Identity,
        peer_vk: Vec<u8>,
    ) -> Result<Self, SessionError> {
        let mut stream = stream;
        set_timeouts(&stream)?;
        let hello = read_frame(&mut stream)?;
        Self::respond(stream, id, peer_vk, &hello)
    }

    /// Complete the handshake as the responder, for any client `allowed`
    /// admits.
    ///
    /// `simple-network`'s responder pins one client key up front, which is the
    /// right shape for a test and the wrong one for a peer with a roster: the
    /// key that is connecting is not known until its hello arrives. So the
    /// hello is read first, the verifying key it *claims* is shown to
    /// `allowed`, and only an admitted key proceeds — to a responder pinned to
    /// exactly that key, so the claim is then proven by the handshake signature
    /// rather than taken on trust. A key `allowed` rejects never reaches the
    /// KEM at all, which also keeps the cost of a stranger's connection to one
    /// JSON parse.
    pub fn accept_from(
        stream: TcpStream,
        id: &Identity,
        allowed: impl FnOnce(&[u8]) -> bool,
    ) -> Result<Self, SessionError> {
        let mut stream = stream;
        set_timeouts(&stream)?;
        let hello = read_frame(&mut stream)?;
        let claimed = claimed_client_vk(&hello)?;
        if !allowed(&claimed) {
            return Err(SessionError::Crypto(
                "client key is not on this peer's list".into(),
            ));
        }
        Self::respond(stream, id, claimed, &hello)
    }

    fn respond(
        mut stream: TcpStream,
        id: &Identity,
        peer_vk: Vec<u8>,
        hello: &[u8],
    ) -> Result<Self, SessionError> {
        let pinned = peer_vk.clone();
        let resp = Responder::new(clone_identity(id)?, peer_vk);
        let (reply, session) = resp
            .respond(hello)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        write_frame(&mut stream, &reply)?;
        Ok(Self {
            stream,
            session,
            peer_vk: pinned,
        })
    }

    /// The verifying key this channel authenticated against.
    ///
    /// A server derives the ACL subject from this, never from an argument.
    pub fn peer_identity(&self) -> &[u8] {
        &self.peer_vk
    }

    fn send(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        let sealed = self
            .session
            .seal(plain)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        write_frame(&mut self.stream, &sealed)
    }

    fn recv(&mut self) -> Result<Vec<u8>, SessionError> {
        let sealed = read_frame(&mut self.stream)?;
        self.session
            .open(&sealed)
            .map_err(|e| SessionError::Crypto(e.to_string()))
    }

    pub fn send_request(&mut self, r: &Request) -> Result<(), SessionError> {
        self.send(&r.encode()?)
    }

    pub fn recv_request(&mut self) -> Result<Request, SessionError> {
        Ok(Request::decode(&self.recv()?)?)
    }

    pub fn send_response(&mut self, r: &Response) -> Result<(), SessionError> {
        self.send(&r.encode()?)
    }

    pub fn recv_response(&mut self) -> Result<Response, SessionError> {
        Ok(Response::decode(&self.recv()?)?)
    }

    /// One round trip.
    pub fn call(&mut self, r: &Request) -> Result<Response, SessionError> {
        self.send_request(r)?;
        self.recv_response()
    }
}

/// The verifying key a client hello says it is from.
///
/// Read as plain JSON rather than through `simple-network`'s private
/// `ClientHello`, because that type is not exported. The field is a
/// `Vec<u8>`, which serde writes as an array of numbers. Nothing here is
/// trusted: the value is only used to pick which pinned key the real
/// handshake then verifies against.
fn claimed_client_vk(hello: &[u8]) -> Result<Vec<u8>, SessionError> {
    let v: serde_json::Value = serde_json::from_slice(hello)
        .map_err(|e| SessionError::Crypto(format!("client hello is not JSON: {e}")))?;
    let arr = v
        .get("client_vk")
        .and_then(|k| k.as_array())
        .ok_or_else(|| SessionError::Crypto("client hello carries no client_vk".into()))?;
    arr.iter()
        .map(|n| {
            n.as_u64()
                .and_then(|x| u8::try_from(x).ok())
                .ok_or_else(|| SessionError::Crypto("client_vk is not a byte array".into()))
        })
        .collect()
}

/// A NAS-tools transport identity (§3.1 `Role::Transport`) as the type
/// `simple-network`'s handshake takes.
///
/// This is the only place a NAS-tools key crosses into `simple-network`, and
/// `export_transport` refuses every role but `Transport`, so a slot or lease
/// key cannot be handed to the wire by mistake.
pub fn transport_identity(id: &nas_crypto::Identity) -> Result<Identity, SessionError> {
    let (sk, vk) = id
        .export_transport()
        .map_err(|e| SessionError::Crypto(e.to_string()))?;
    Identity::from_bytes(&sk, &vk).map_err(|e| SessionError::Crypto(e.to_string()))
}

/// `Identity` is not `Clone` upstream, so round-trip it through its own export.
///
/// Deliberately not "fixed" by deriving `Clone` there: the export path is
/// already the audited way to move key material, and adding a second one to
/// save an allocation would be a poor trade in this particular crate.
fn clone_identity(id: &Identity) -> Result<Identity, SessionError> {
    let (sk, vk) = id
        .export()
        .map_err(|e| SessionError::Crypto(e.to_string()))?;
    Identity::from_bytes(&sk, &vk).map_err(|e| SessionError::Crypto(e.to_string()))
}

/// Bound every blocking read and write, including the handshake.
fn set_timeouts(s: &TcpStream) -> Result<(), SessionError> {
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

fn write_frame(w: &mut impl Write, bytes: &[u8]) -> Result<(), SessionError> {
    if bytes.len() > MAX_FRAME {
        return Err(SessionError::FrameTooLarge { len: bytes.len() });
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, SessionError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(SessionError::Truncated),
        Err(e) => return Err(SessionError::Io(e)),
    }
    let n = u32::from_le_bytes(len) as usize;
    // Checked BEFORE the allocation. This is the whole point of the limit.
    if n > MAX_FRAME {
        return Err(SessionError::FrameTooLarge { len: n });
    }
    let mut body = vec![0u8; n];
    match r.read_exact(&mut body) {
        Ok(()) => Ok(body),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(SessionError::Truncated),
        Err(e) if is_timeout(&e) => Err(SessionError::TimedOut),
        Err(e) => Err(SessionError::Io(e)),
    }
}

/// A read that expired. The kind differs by platform, so both are checked.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(read_frame(&mut &buf[..]).unwrap(), b"hello");
    }

    #[test]
    fn an_announced_frame_beyond_the_limit_is_refused_before_allocating() {
        // A peer says 0xFFFFFFFF and the client would otherwise reserve 4 GiB.
        let mut buf = u32::MAX.to_le_bytes().to_vec();
        buf.extend_from_slice(b"not four gigabytes");
        match read_frame(&mut &buf[..]) {
            Err(SessionError::FrameTooLarge { len }) => {
                assert_eq!(len, u32::MAX as usize)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_truncated_frame_is_reported_not_hung_on() {
        let mut buf = 100u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"only a few bytes");
        assert!(matches!(
            read_frame(&mut &buf[..]),
            Err(SessionError::Truncated)
        ));
        // And a header that never arrives.
        assert!(matches!(
            read_frame(&mut &b"ab"[..]),
            Err(SessionError::Truncated)
        ));
    }

    #[test]
    fn an_empty_frame_is_legal() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();
        assert_eq!(read_frame(&mut &buf[..]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn writing_beyond_the_limit_is_refused() {
        let mut buf = Vec::new();
        assert!(matches!(
            write_frame(&mut buf, &vec![0u8; MAX_FRAME + 1]),
            Err(SessionError::FrameTooLarge { .. })
        ));
        assert!(
            buf.is_empty(),
            "a refused frame must not be partially written"
        );
    }
}
