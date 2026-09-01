//! The request/response format spoken to a peer (SPECS §14).
//!
//! # Every message is bounded before it is believed
//!
//! The peer is the party being distrusted, and it supplies both the length
//! prefix and the body. A framing layer that allocated whatever the prefix said
//! would let a peer answer any request with `0xFFFFFFFF` and have the client
//! reserve four gigabytes — a denial of service that costs the attacker four
//! bytes. [`MAX_FRAME`] is checked **before** any allocation, on both sides.
//!
//! That bound is also why the blob limit is stated in terms of the chunker's
//! maximum rather than picked round: a legitimate blob is one padded chunk, and
//! anything larger is not something an honest peer would ever send.
//!
//! # Canonical, like every other decoder here
//!
//! Whatever `decode` accepts must re-encode to the same bytes. A tolerated
//! degree of freedom is a covert channel between a compromised client and a
//! peer that both speak this protocol, and there is no reason to leave one.

use nas_core::{decode_fields, encode_fields, Addr, DecodeError, ADDR_LEN};
use nas_slots::SlotId;

/// Largest frame either side will read. One padded 256 KiB chunk, its AEAD
/// overhead, and room for the request envelope — deliberately not round, so it
/// is obvious the number came from somewhere.
pub const MAX_FRAME: usize = (256 * 1024) + 4096;

/// Largest number of records one history response may carry.
///
/// A peer answering a chain walk with ten million records is not helping. The
/// client asks again from a higher `from` if it needs more, which also bounds
/// the memory a walk costs regardless of how far behind it is.
///
/// **This is a ceiling, not a promise.** A `SlotRecord` is ~3.5 KB (the
/// signature dominates), so 256 of them are three times [`MAX_FRAME`] and the
/// real limit is whichever binds first — see [`RECORD_BUDGET`].
pub const MAX_RECORDS: usize = 256;

/// Bytes a list response may spend on records.
///
/// Counting records alone was not enough, and the gap was not theoretical: a
/// peer asked for a 600-record history built a 256-record response, failed to
/// encode it because it was three times [`MAX_FRAME`], and **dropped the
/// connection** — turning "here is as much as I can send" into what a client
/// cannot distinguish from the peer going away. The count bound and the byte
/// bound are different questions and both are asked now.
///
/// The slack covers the tag field and one length prefix per record.
pub const RECORD_BUDGET: usize = MAX_FRAME - 4096;

/// Bytes one record costs in a list response: its own length plus the
/// self-delimiting length prefix.
pub const fn record_cost(encoded_len: usize) -> usize {
    encoded_len + 4
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Decode(DecodeError),
    /// A frame larger than [`MAX_FRAME`]. Reported before allocating.
    FrameTooLarge {
        len: usize,
    },
    UnknownTag {
        tag: u8,
    },
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    TooManyRecords {
        got: usize,
    },
    /// Well-formed but not something `encode` would emit.
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "wire encoding: {e:?}"),
            Self::FrameTooLarge { len } => {
                write!(f, "frame claims {len} B, limit is {MAX_FRAME} B")
            }
            Self::UnknownTag { tag } => write!(f, "unknown message tag {tag}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::TooManyRecords { got } => {
                write!(f, "{got} records exceeds the {MAX_RECORDS} limit")
            }
            Self::NonCanonical { reason } => write!(f, "non-canonical message: {reason}"),
        }
    }
}
impl std::error::Error for WireError {}
impl From<DecodeError> for WireError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetBlob(Addr),
    HasBlob(Addr),
    PutBlob(Vec<u8>),
    /// Proof-of-possession challenge (SPECS §4.5).
    Prove {
        addr: Addr,
        nonce: [u8; 32],
    },
    SlotHead(SlotId),
    SlotHistory {
        slot: SlotId,
        from: u64,
    },
    /// An encoded `SlotRecord`. Left encoded on the wire so the peer parses it
    /// with the same decoder a client would, rather than a second one.
    PublishSlot(Vec<u8>),
    PublishWitness(Vec<u8>),
    Witnesses(SlotId),
    /// An encoded `SlotHandoff` (SPECS §5.1). Encoded on the wire for the
    /// same reason as a slot record: the peer parses it with the decoder a
    /// client would, not a second one written to match.
    PublishHandoff(Vec<u8>),
    /// Every handoff a peer holds for a slot, so a client walking history
    /// across an ownership change can ask once rather than guess.
    Handoffs(SlotId),
    /// An encoded `Checkpoint` (SPECS §5.5).
    PublishCheckpoint(Vec<u8>),
    /// The skip-chain ladder from `from` upwards, so a client far behind
    /// climbs it instead of reading every record.
    Checkpoints {
        slot: SlotId,
        from: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Blob(Vec<u8>),
    Bool(bool),
    Stored(Addr),
    Proof([u8; 32]),
    /// An encoded record, or nothing.
    Record(Option<Vec<u8>>),
    Records(Vec<Vec<u8>>),
    Ok,
    /// A refusal or failure, as text. **Never trusted**: it is peer-supplied
    /// and only ever shown to a human or logged, never parsed for control flow.
    ///
    /// Decoded strictly rather than lossily — see the decoder.
    Error(String),
}

const REQ_GET_BLOB: u8 = 0;
const REQ_HAS_BLOB: u8 = 1;
const REQ_PUT_BLOB: u8 = 2;
const REQ_PROVE: u8 = 3;
const REQ_SLOT_HEAD: u8 = 4;
const REQ_SLOT_HISTORY: u8 = 5;
const REQ_PUBLISH_SLOT: u8 = 6;
const REQ_PUBLISH_WITNESS: u8 = 7;
const REQ_WITNESSES: u8 = 8;
const REQ_PUBLISH_HANDOFF: u8 = 9;
const REQ_HANDOFFS: u8 = 10;
const REQ_PUBLISH_CHECKPOINT: u8 = 11;
const REQ_CHECKPOINTS: u8 = 12;

const RSP_BLOB: u8 = 0;
const RSP_BOOL: u8 = 1;
const RSP_STORED: u8 = 2;
const RSP_PROOF: u8 = 3;
const RSP_RECORD: u8 = 4;
const RSP_RECORDS: u8 = 5;
const RSP_OK: u8 = 6;
const RSP_ERROR: u8 = 7;

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], WireError> {
    b.try_into().map_err(|_| WireError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let out = match self {
            Self::GetBlob(a) => encode_fields(&[&[REQ_GET_BLOB], a.as_bytes()])?,
            Self::HasBlob(a) => encode_fields(&[&[REQ_HAS_BLOB], a.as_bytes()])?,
            Self::PutBlob(b) => encode_fields(&[&[REQ_PUT_BLOB], b])?,
            Self::Prove { addr, nonce } => encode_fields(&[&[REQ_PROVE], addr.as_bytes(), nonce])?,
            Self::SlotHead(s) => encode_fields(&[&[REQ_SLOT_HEAD], s.as_bytes()])?,
            Self::SlotHistory { slot, from } => {
                encode_fields(&[&[REQ_SLOT_HISTORY], slot.as_bytes(), &from.to_le_bytes()])?
            }
            Self::PublishSlot(r) => encode_fields(&[&[REQ_PUBLISH_SLOT], r])?,
            Self::PublishWitness(w) => encode_fields(&[&[REQ_PUBLISH_WITNESS], w])?,
            Self::Witnesses(s) => encode_fields(&[&[REQ_WITNESSES], s.as_bytes()])?,
            Self::PublishHandoff(h) => encode_fields(&[&[REQ_PUBLISH_HANDOFF], h])?,
            Self::Handoffs(s) => encode_fields(&[&[REQ_HANDOFFS], s.as_bytes()])?,
            Self::PublishCheckpoint(c) => encode_fields(&[&[REQ_PUBLISH_CHECKPOINT], c])?,
            Self::Checkpoints { slot, from } => {
                encode_fields(&[&[REQ_CHECKPOINTS], slot.as_bytes(), &from.to_le_bytes()])?
            }
        };
        check_size(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_FRAME {
            return Err(WireError::FrameTooLarge { len: bytes.len() });
        }
        let f = decode_fields(bytes)?;
        let tag = tag_of(&f)?;
        let want = |n: usize| -> Result<(), WireError> {
            if f.len() == n {
                Ok(())
            } else {
                Err(WireError::FieldCount {
                    want: n,
                    got: f.len(),
                })
            }
        };
        Ok(match tag {
            REQ_GET_BLOB => {
                want(2)?;
                Self::GetBlob(Addr::from_bytes(fixed::<ADDR_LEN>("addr", f[1])?))
            }
            REQ_HAS_BLOB => {
                want(2)?;
                Self::HasBlob(Addr::from_bytes(fixed::<ADDR_LEN>("addr", f[1])?))
            }
            REQ_PUT_BLOB => {
                want(2)?;
                Self::PutBlob(f[1].to_vec())
            }
            REQ_PROVE => {
                want(3)?;
                Self::Prove {
                    addr: Addr::from_bytes(fixed::<ADDR_LEN>("addr", f[1])?),
                    nonce: fixed::<32>("nonce", f[2])?,
                }
            }
            REQ_SLOT_HEAD => {
                want(2)?;
                Self::SlotHead(SlotId::from_bytes(fixed::<32>("slot", f[1])?))
            }
            REQ_SLOT_HISTORY => {
                want(3)?;
                Self::SlotHistory {
                    slot: SlotId::from_bytes(fixed::<32>("slot", f[1])?),
                    from: u64::from_le_bytes(fixed::<8>("from", f[2])?),
                }
            }
            REQ_PUBLISH_SLOT => {
                want(2)?;
                Self::PublishSlot(f[1].to_vec())
            }
            REQ_PUBLISH_WITNESS => {
                want(2)?;
                Self::PublishWitness(f[1].to_vec())
            }
            REQ_WITNESSES => {
                want(2)?;
                Self::Witnesses(SlotId::from_bytes(fixed::<32>("slot", f[1])?))
            }
            REQ_PUBLISH_HANDOFF => {
                want(2)?;
                Self::PublishHandoff(f[1].to_vec())
            }
            REQ_HANDOFFS => {
                want(2)?;
                Self::Handoffs(SlotId::from_bytes(fixed::<32>("slot", f[1])?))
            }
            REQ_PUBLISH_CHECKPOINT => {
                want(2)?;
                Self::PublishCheckpoint(f[1].to_vec())
            }
            REQ_CHECKPOINTS => {
                want(3)?;
                Self::Checkpoints {
                    slot: SlotId::from_bytes(fixed::<32>("slot", f[1])?),
                    from: u64::from_le_bytes(fixed::<8>("from", f[2])?),
                }
            }
            other => return Err(WireError::UnknownTag { tag: other }),
        })
    }
}

impl Response {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let out = match self {
            Self::Blob(b) => encode_fields(&[&[RSP_BLOB], b])?,
            Self::Bool(v) => encode_fields(&[&[RSP_BOOL], &[u8::from(*v)]])?,
            Self::Stored(a) => encode_fields(&[&[RSP_STORED], a.as_bytes()])?,
            Self::Proof(p) => encode_fields(&[&[RSP_PROOF], p])?,
            Self::Record(None) => encode_fields(&[&[RSP_RECORD], &[0u8]])?,
            Self::Record(Some(r)) => encode_fields(&[&[RSP_RECORD], &[1u8], r])?,
            Self::Records(rs) => {
                if rs.len() > MAX_RECORDS {
                    return Err(WireError::TooManyRecords { got: rs.len() });
                }
                let mut fields: Vec<&[u8]> = vec![&[RSP_RECORDS]];
                fields.extend(rs.iter().map(|r| r.as_slice()));
                encode_fields(&fields)?
            }
            Self::Ok => encode_fields(&[&[RSP_OK]])?,
            Self::Error(m) => encode_fields(&[&[RSP_ERROR], m.as_bytes()])?,
        };
        check_size(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_FRAME {
            return Err(WireError::FrameTooLarge { len: bytes.len() });
        }
        let f = decode_fields(bytes)?;
        let tag = tag_of(&f)?;
        Ok(match tag {
            RSP_BLOB => {
                exact(&f, 2)?;
                Self::Blob(f[1].to_vec())
            }
            RSP_BOOL => {
                exact(&f, 2)?;
                let b = fixed::<1>("bool", f[1])?[0];
                // Only 0 and 1 encode a bool. Accepting 2 would give two
                // spellings of `true` and make the encoding non-canonical.
                match b {
                    0 => Self::Bool(false),
                    1 => Self::Bool(true),
                    _ => {
                        return Err(WireError::NonCanonical {
                            reason: "bool is not 0 or 1",
                        })
                    }
                }
            }
            RSP_STORED => {
                exact(&f, 2)?;
                Self::Stored(Addr::from_bytes(fixed::<ADDR_LEN>("addr", f[1])?))
            }
            RSP_PROOF => {
                exact(&f, 2)?;
                Self::Proof(fixed::<32>("proof", f[1])?)
            }
            RSP_RECORD => match f.len() {
                2 => {
                    if fixed::<1>("present", f[1])?[0] != 0 {
                        return Err(WireError::NonCanonical {
                            reason: "record marked present but absent",
                        });
                    }
                    Self::Record(None)
                }
                3 => {
                    if fixed::<1>("present", f[1])?[0] != 1 {
                        return Err(WireError::NonCanonical {
                            reason: "record marked absent but present",
                        });
                    }
                    Self::Record(Some(f[2].to_vec()))
                }
                got => return Err(WireError::FieldCount { want: 3, got }),
            },
            RSP_RECORDS => {
                if f.len() - 1 > MAX_RECORDS {
                    return Err(WireError::TooManyRecords { got: f.len() - 1 });
                }
                Self::Records(f[1..].iter().map(|r| r.to_vec()).collect())
            }
            RSP_OK => {
                exact(&f, 1)?;
                Self::Ok
            }
            RSP_ERROR => {
                exact(&f, 2)?;
                // Strict, not lossy. `from_utf8_lossy` maps every invalid
                // sequence onto U+FFFD, so two different peer messages decode
                // to one value and re-encode to neither -- found by the fuzzer
                // in seconds, and the third time in this project that a lossy
                // conversion has broken a canonical encoding.
                let text = std::str::from_utf8(f[1]).map_err(|_| WireError::NonCanonical {
                    reason: "error text is not valid UTF-8",
                })?;
                Self::Error(text.to_string())
            }
            other => return Err(WireError::UnknownTag { tag: other }),
        })
    }
}

fn tag_of(f: &[&[u8]]) -> Result<u8, WireError> {
    match f.first() {
        Some(t) if t.len() == 1 => Ok(t[0]),
        Some(t) => Err(WireError::BadWidth {
            field: "tag",
            want: 1,
            got: t.len(),
        }),
        None => Err(WireError::FieldCount { want: 1, got: 0 }),
    }
}

fn exact(f: &[&[u8]], n: usize) -> Result<(), WireError> {
    if f.len() == n {
        Ok(())
    } else {
        Err(WireError::FieldCount {
            want: n,
            got: f.len(),
        })
    }
}

fn check_size(out: Vec<u8>) -> Result<Vec<u8>, WireError> {
    if out.len() > MAX_FRAME {
        return Err(WireError::FrameTooLarge { len: out.len() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Addr {
        Addr::of_ciphertext(&[n])
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"s")
    }

    fn requests() -> Vec<Request> {
        vec![
            Request::GetBlob(addr(1)),
            Request::HasBlob(addr(2)),
            Request::PutBlob(vec![7u8; 1000]),
            Request::Prove {
                addr: addr(3),
                nonce: [9u8; 32],
            },
            Request::SlotHead(slot()),
            Request::SlotHistory {
                slot: slot(),
                from: 42,
            },
            Request::PublishSlot(vec![1u8; 200]),
            Request::PublishWitness(vec![2u8; 200]),
            Request::Witnesses(slot()),
            Request::PublishHandoff(vec![3u8; 200]),
            Request::Handoffs(slot()),
            Request::PublishCheckpoint(vec![4u8; 200]),
            Request::Checkpoints {
                slot: slot(),
                from: 256,
            },
        ]
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Blob(vec![1u8; 500]),
            Response::Bool(true),
            Response::Bool(false),
            Response::Stored(addr(4)),
            Response::Proof([5u8; 32]),
            Response::Record(None),
            Response::Record(Some(vec![6u8; 100])),
            Response::Records(vec![vec![1u8; 10], vec![2u8; 10]]),
            Response::Ok,
            Response::Error("refused".into()),
        ]
    }

    /// Exhaustive by construction: a new variant does not compile until it
    /// is named here.
    fn name(r: &Request) -> &'static str {
        match r {
            Request::GetBlob(_) => "GetBlob",
            Request::HasBlob(_) => "HasBlob",
            Request::PutBlob(_) => "PutBlob",
            Request::Prove { .. } => "Prove",
            Request::SlotHead(_) => "SlotHead",
            Request::SlotHistory { .. } => "SlotHistory",
            Request::PublishSlot(_) => "PublishSlot",
            Request::PublishWitness(_) => "PublishWitness",
            Request::Witnesses(_) => "Witnesses",
            Request::PublishHandoff(_) => "PublishHandoff",
            Request::Handoffs(_) => "Handoffs",
            Request::PublishCheckpoint(_) => "PublishCheckpoint",
            Request::Checkpoints { .. } => "Checkpoints",
        }
    }

    #[test]
    fn the_round_trip_corpus_covers_every_request() {
        // `name` above stops compiling when a variant is added; this then
        // fails until the corpus covers it too. A message nothing round-trips
        // is how a non-canonical encoding gets into the protocol unnoticed.
        const ALL: &[&str] = &[
            "GetBlob",
            "HasBlob",
            "PutBlob",
            "Prove",
            "SlotHead",
            "SlotHistory",
            "PublishSlot",
            "PublishWitness",
            "Witnesses",
            "PublishHandoff",
            "Handoffs",
            "PublishCheckpoint",
            "Checkpoints",
        ];
        let have: std::collections::BTreeSet<&str> = requests().iter().map(name).collect();
        for n in ALL {
            assert!(have.contains(n), "{n} is not in the round-trip corpus");
        }
        assert_eq!(have.len(), ALL.len(), "corpus and ALL disagree");
    }

    #[test]
    fn every_request_round_trips() {
        for r in requests() {
            let b = r.encode().unwrap();
            assert_eq!(Request::decode(&b).unwrap(), r, "{r:?}");
            // Canonical: what decode accepts must re-encode identically.
            assert_eq!(Request::decode(&b).unwrap().encode().unwrap(), b);
        }
    }

    #[test]
    fn every_response_round_trips() {
        for r in responses() {
            let b = r.encode().unwrap();
            assert_eq!(Response::decode(&b).unwrap(), r, "{r:?}");
            assert_eq!(Response::decode(&b).unwrap().encode().unwrap(), b);
        }
    }

    #[test]
    fn an_oversized_frame_is_refused_before_allocating() {
        // The four-byte denial of service: a peer says 0xFFFFFFFF and the
        // client reserves four gigabytes.
        let huge = vec![0u8; MAX_FRAME + 1];
        assert_eq!(
            Response::decode(&huge),
            Err(WireError::FrameTooLarge { len: MAX_FRAME + 1 })
        );
        assert_eq!(
            Request::decode(&huge),
            Err(WireError::FrameTooLarge { len: MAX_FRAME + 1 })
        );
    }

    #[test]
    fn an_oversized_blob_cannot_even_be_encoded() {
        let r = Response::Blob(vec![0u8; MAX_FRAME]);
        assert!(matches!(r.encode(), Err(WireError::FrameTooLarge { .. })));
    }

    #[test]
    fn a_history_response_is_bounded() {
        // A peer answering a chain walk with ten million records is not
        // helping; the client asks again from a higher `from`.
        let many: Vec<Vec<u8>> = (0..MAX_RECORDS + 1).map(|_| vec![0u8; 4]).collect();
        assert_eq!(
            Response::Records(many).encode(),
            Err(WireError::TooManyRecords {
                got: MAX_RECORDS + 1
            })
        );
    }

    #[test]
    fn a_bool_other_than_zero_or_one_is_refused() {
        // Two spellings of `true` would make the encoding non-canonical.
        let b = encode_fields(&[&[RSP_BOOL], &[2u8]]).unwrap();
        assert!(matches!(
            Response::decode(&b),
            Err(WireError::NonCanonical { .. })
        ));
    }

    #[test]
    fn a_record_presence_flag_that_lies_is_refused() {
        let absent_but_present = encode_fields(&[&[RSP_RECORD], &[1u8]]).unwrap();
        assert!(matches!(
            Response::decode(&absent_but_present),
            Err(WireError::NonCanonical { .. })
        ));
        let present_but_absent = encode_fields(&[&[RSP_RECORD], &[0u8], b"x"]).unwrap();
        assert!(matches!(
            Response::decode(&present_but_absent),
            Err(WireError::NonCanonical { .. })
        ));
    }

    #[test]
    fn error_text_that_is_not_utf8_is_refused() {
        // Lossy decoding would map every invalid sequence onto U+FFFD, so two
        // distinct peer messages would decode to one value and re-encode to
        // neither. Found by the fuzzer.
        let b = encode_fields(&[&[RSP_ERROR], &[0xFC, 0xFF, 0xFF, 0xFF]]).unwrap();
        assert!(matches!(
            Response::decode(&b),
            Err(WireError::NonCanonical { .. })
        ));
        // Valid UTF-8 still works, including non-ASCII.
        let ok = Response::Error("refusé".into());
        assert_eq!(Response::decode(&ok.encode().unwrap()).unwrap(), ok);
    }

    #[test]
    fn an_unknown_tag_is_refused() {
        let b = encode_fields(&[&[200u8], b"x"]).unwrap();
        assert_eq!(Request::decode(&b), Err(WireError::UnknownTag { tag: 200 }));
        assert_eq!(
            Response::decode(&b),
            Err(WireError::UnknownTag { tag: 200 })
        );
    }

    #[test]
    fn extra_fields_are_refused() {
        let b = encode_fields(&[&[REQ_GET_BLOB], &[0u8; ADDR_LEN], b"extra"]).unwrap();
        assert!(matches!(
            Request::decode(&b),
            Err(WireError::FieldCount { .. })
        ));
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 4, 33, 200, 5000] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = Request::decode(&junk);
            let _ = Response::decode(&junk);
        }
    }
}
