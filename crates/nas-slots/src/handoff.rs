//! Single-writer ownership handoff (SPECS §5.1).
//!
//! ```text
//! SlotHandoff { slot_id, at_seq, from_pk, to, sig }
//! sig context "nas-tools/sig/slot-handoff/v1"
//! ```
//!
//! Under `single-writer`, exactly one device holds the write-cap at a time and
//! any observed divergence is a genuine alarm rather than something to merge.
//! §5.1 allows ownership to move, but only as "an explicit, signed operation" —
//! and the signature that matters is the **outgoing** writer's. That is the
//! whole distinction between a handover and a takeover: anyone can announce
//! that they are the new writer, and only the current one can say so.
//!
//! # Why a separate record
//!
//! It could have been a field on [`SlotRecord`](crate::SlotRecord). It is not,
//! because that format is peer-facing and frozen (SPECS §20) — adding a field
//! would break every record already written, to express something that occurs
//! once per ownership change. A standalone record costs a lookup during the
//! walk and nothing else.
//!
//! # What it does not do
//!
//! A handoff authorises **one** change, at one sequence, on one slot. It is not
//! a capability grant: it does not let the incoming writer hand on again (that
//! needs its own handoff, signed by it), and it cannot be replayed onto another
//! slot or another sequence, because both are inside the signed body.

use crate::id::{SlotId, WriterId};
use nas_core::{decode_fields, encode_fields, DecodeError};
use nas_crypto::{
    key_id, verify, Identity, SigContext, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    Decode(DecodeError),
    Sign(SignError),
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    BadSignature,
    /// A handoff to the writer that already holds the slot. Refused because it
    /// is either a mistake or an attempt to manufacture an authorisation
    /// record that says nothing.
    SelfHandoff {
        writer: WriterId,
    },
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::BadSignature => f.write_str("handoff signature does not verify"),
            Self::SelfHandoff { writer } => {
                write!(f, "handoff from {} to itself", writer.to_hex())
            }
        }
    }
}
impl std::error::Error for HandoffError {}
impl From<DecodeError> for HandoffError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<SignError> for HandoffError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

fn body(slot_id: &SlotId, at_seq: u64, from: &WriterId, to: &WriterId) -> Vec<u8> {
    encode_fields(&[
        slot_id.as_bytes(),
        &at_seq.to_le_bytes(),
        from.as_bytes(),
        to.as_bytes(),
    ])
    .expect("fixed-width handoff body always encodes")
}

/// One authorised change of writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotHandoff {
    pub slot_id: SlotId,
    /// The first sequence the incoming writer may sign.
    ///
    /// Pinning the sequence is what stops a handoff being replayed later to
    /// re-admit a writer whose turn has passed.
    pub at_seq: u64,
    /// The outgoing writer's full verifying key.
    ///
    /// Carried in full rather than as an id so the record verifies on its own,
    /// like a witness: whoever is walking the chain may hold a roster that no
    /// longer lists a writer who handed off long ago.
    pub from_pk: Vec<u8>,
    pub to: WriterId,
    pub sig: Vec<u8>,
}

impl SlotHandoff {
    /// Sign as the **outgoing** writer.
    pub fn sign(
        outgoing: &Identity,
        slot_id: SlotId,
        at_seq: u64,
        to: WriterId,
    ) -> Result<Self, HandoffError> {
        let from = WriterId::of_key(outgoing.verifying_key());
        if from == to {
            return Err(HandoffError::SelfHandoff { writer: to });
        }
        let b = body(&slot_id, at_seq, &from, &to);
        let sig = outgoing.sign(SigContext::SlotHandoff, &b)?;
        Ok(Self {
            slot_id,
            at_seq,
            from_pk: outgoing.verifying_key().to_vec(),
            to,
            sig,
        })
    }

    pub fn from(&self) -> WriterId {
        WriterId::from_bytes(key_id(&self.from_pk))
    }

    pub fn verify(&self) -> Result<(), HandoffError> {
        let from = self.from();
        if from == self.to {
            return Err(HandoffError::SelfHandoff { writer: self.to });
        }
        let b = body(&self.slot_id, self.at_seq, &from, &self.to);
        verify(&self.from_pk, SigContext::SlotHandoff, &b, &self.sig)
            .map_err(|_| HandoffError::BadSignature)
    }

    /// Does this authorise `from → to` at `at_seq` on `slot`?
    ///
    /// Every component is compared, not just the writers: a handoff is for one
    /// slot at one sequence, and matching loosely would turn a single
    /// authorised change into a reusable token.
    pub fn authorises(&self, slot: SlotId, at_seq: u64, from: WriterId, to: WriterId) -> bool {
        self.slot_id == slot
            && self.at_seq == at_seq
            && self.from() == from
            && self.to == to
            && self.verify().is_ok()
    }

    pub fn encode(&self) -> Result<Vec<u8>, HandoffError> {
        Ok(encode_fields(&[
            self.slot_id.as_bytes(),
            &self.at_seq.to_le_bytes(),
            &self.from_pk,
            self.to.as_bytes(),
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandoffError> {
        let f = decode_fields(bytes)?;
        if f.len() != 5 {
            return Err(HandoffError::FieldCount {
                want: 5,
                got: f.len(),
            });
        }
        let fixed = |field: &'static str, b: &[u8]| -> Result<[u8; 32], HandoffError> {
            b.try_into().map_err(|_| HandoffError::BadWidth {
                field,
                want: 32,
                got: b.len(),
            })
        };
        if f[2].len() != VERIFYING_KEY_LEN {
            return Err(HandoffError::BadWidth {
                field: "from_pk",
                want: VERIFYING_KEY_LEN,
                got: f[2].len(),
            });
        }
        if f[4].len() != SIGNATURE_LEN {
            return Err(HandoffError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[4].len(),
            });
        }
        Ok(Self {
            slot_id: SlotId::from_bytes(fixed("slot_id", f[0])?),
            at_seq: u64::from_le_bytes(f[1].try_into().map_err(|_| HandoffError::BadWidth {
                field: "at_seq",
                want: 8,
                got: f[1].len(),
            })?),
            from_pk: f[2].to_vec(),
            to: WriterId::from_bytes(fixed("to", f[3])?),
            sig: f[4].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::Role;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    fn wid(id: &Identity) -> WriterId {
        WriterId::of_key(id.verifying_key())
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"refs/heads/main")
    }

    #[test]
    fn the_outgoing_writer_authorises_the_incoming_one() {
        let (a, b) = (ident(1), ident(2));
        let h = SlotHandoff::sign(&a, slot(), 5, wid(&b)).unwrap();
        h.verify().unwrap();
        assert!(h.authorises(slot(), 5, wid(&a), wid(&b)));
    }

    #[test]
    fn a_handoff_is_for_one_slot_one_sequence_and_one_pair() {
        // Each component is in the signed body, so none of these is a matter
        // of the verifier remembering to check.
        let (a, b, c) = (ident(1), ident(2), ident(3));
        let h = SlotHandoff::sign(&a, slot(), 5, wid(&b)).unwrap();
        assert!(!h.authorises(SlotId::new(b"ns", b"other"), 5, wid(&a), wid(&b)));
        assert!(!h.authorises(slot(), 6, wid(&a), wid(&b)));
        assert!(!h.authorises(slot(), 5, wid(&c), wid(&b)));
        assert!(!h.authorises(slot(), 5, wid(&a), wid(&c)));
    }

    #[test]
    fn a_takeover_is_not_a_handover() {
        // The incoming writer signing its own arrival proves nothing: that is
        // the difference §5.1 turns on.
        let (a, b) = (ident(1), ident(2));
        let forged = SlotHandoff::sign(&b, slot(), 5, wid(&b));
        assert!(matches!(forged, Err(HandoffError::SelfHandoff { .. })));

        // Nor can a third party authorise someone else's slot.
        let c = ident(3);
        let h = SlotHandoff::sign(&c, slot(), 5, wid(&b)).unwrap();
        assert!(
            !h.authorises(slot(), 5, wid(&a), wid(&b)),
            "a stranger's signature must not move A's ownership"
        );
    }

    #[test]
    fn a_tampered_handoff_does_not_verify() {
        let (a, b, c) = (ident(1), ident(2), ident(3));
        let mut h = SlotHandoff::sign(&a, slot(), 5, wid(&b)).unwrap();
        h.to = wid(&c);
        assert_eq!(h.verify(), Err(HandoffError::BadSignature));
    }

    #[test]
    fn it_round_trips() {
        let (a, b) = (ident(1), ident(2));
        let h = SlotHandoff::sign(&a, slot(), 5, wid(&b)).unwrap();
        assert_eq!(SlotHandoff::decode(&h.encode().unwrap()).unwrap(), h);
    }

    #[test]
    fn a_truncated_record_is_an_error_not_a_panic() {
        let (a, b) = (ident(1), ident(2));
        let bytes = SlotHandoff::sign(&a, slot(), 5, wid(&b))
            .unwrap()
            .encode()
            .unwrap();
        for n in 0..bytes.len() {
            let _ = SlotHandoff::decode(&bytes[..n]);
        }
    }
}
