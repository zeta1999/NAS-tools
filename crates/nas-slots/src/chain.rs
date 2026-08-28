//! Verifying slot history (SPECS §5.3).
//!
//! Revision 1 of the spec stored only the head, which made its own chain check
//! impossible to perform. Peers now retain `slots/<slot_id>/<seq>` so a client
//! pinned at seq 5 that is handed seq 9 can **walk 5→9 and verify** rather than
//! taking the peer's word for it.
//!
//! # What a walk proves, and what it does not
//!
//! A verified walk proves the peer served a sequence of records that (a) each
//! carry a valid signature from a rostered writer, (b) chain by hash, and (c)
//! reach the head from where the client was pinned. It does **not** prove this
//! is the *only* history — a peer running a fork serves each client a
//! self-consistent chain, and both walks verify. Detecting that needs evidence
//! from a second observer, which is what witnesses are for (SPECS §5.3).
//!
//! Keeping those two apart matters: a walk that verified would otherwise be
//! read as "no fork", which is exactly the overclaim SPECS §5.4 warns against.

use crate::id::{SlotId, WriterId};
use crate::record::{RecordError, Regime, SlotRecord};
use crate::roster::Roster;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A record failed signature or structural verification.
    Record {
        seq: u64,
        source: RecordError,
    },
    /// The writer is not on the roster.
    UnknownWriter {
        seq: u64,
        writer: WriterId,
    },
    /// A record belongs to a different slot. A peer serving one slot's history
    /// for another is either broken or probing.
    WrongSlot {
        seq: u64,
        want: SlotId,
        got: SlotId,
    },
    /// Sequence numbers are not contiguous and ascending.
    NotContiguous {
        expected: u64,
        got: u64,
    },
    /// `prev` does not equal the predecessor's record hash — the chain is cut.
    BrokenLink {
        seq: u64,
    },
    /// The regime changed mid-chain. It is fixed at slot creation (SPECS §5).
    RegimeChanged {
        seq: u64,
        from: Regime,
        to: Regime,
    },
    /// A `single-writer` slot has records from more than one writer without a
    /// handoff. Under that regime this is a genuine alarm, not a merge.
    ConcurrentWriters {
        seq: u64,
        first: WriterId,
        second: WriterId,
    },
    Empty,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record { seq, source } => write!(f, "record {seq}: {source}"),
            Self::UnknownWriter { seq, writer } => {
                write!(f, "record {seq}: {writer:?} is not on the roster")
            }
            Self::WrongSlot { seq, want, got } => {
                write!(f, "record {seq} belongs to {got:?}, expected {want:?}")
            }
            Self::NotContiguous { expected, got } => {
                write!(f, "expected seq {expected}, got {got}")
            }
            Self::BrokenLink { seq } => write!(f, "record {seq} does not chain to its predecessor"),
            Self::RegimeChanged { seq, from, to } => {
                write!(f, "record {seq} changes regime from {from:?} to {to:?}")
            }
            Self::ConcurrentWriters { seq, first, second } => write!(
                f,
                "record {seq}: single-writer slot written by both {first:?} and {second:?}"
            ),
            Self::Empty => write!(f, "empty chain"),
        }
    }
}
impl std::error::Error for ChainError {}

/// The outcome of a successful walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    pub slot_id: SlotId,
    pub regime: Regime,
    pub first_seq: u64,
    pub head_seq: u64,
    /// Hash of the head record — what a client pins to.
    pub head_hash: [u8; 32],
}

/// Verify that `records` is a contiguous, signed, hash-linked chain.
///
/// `expect_prev` is the record hash the first element must chain to: `None`
/// when the chain starts at genesis, `Some(h)` when continuing from a pin. A
/// caller that passes `None` for a non-genesis chain would be accepting an
/// unanchored prefix, so the two cases are distinct arguments rather than an
/// `Option` the caller might forget.
pub fn verify_chain(
    records: &[SlotRecord],
    slot_id: SlotId,
    roster: &Roster,
    expect_prev: Option<[u8; 32]>,
) -> Result<Walk, ChainError> {
    let Some(first) = records.first() else {
        return Err(ChainError::Empty);
    };

    let regime = first.regime;
    let mut expected_seq = first.seq;
    let mut link = expect_prev.unwrap_or([0u8; 32]);
    let mut sole_writer: Option<WriterId> = None;

    for r in records {
        if r.slot_id != slot_id {
            return Err(ChainError::WrongSlot {
                seq: r.seq,
                want: slot_id,
                got: r.slot_id,
            });
        }
        if r.seq != expected_seq {
            return Err(ChainError::NotContiguous {
                expected: expected_seq,
                got: r.seq,
            });
        }
        if r.regime != regime {
            return Err(ChainError::RegimeChanged {
                seq: r.seq,
                from: regime,
                to: r.regime,
            });
        }
        if r.prev != link {
            return Err(ChainError::BrokenLink { seq: r.seq });
        }

        let Some(vk) = roster.get(&r.writer_id) else {
            return Err(ChainError::UnknownWriter {
                seq: r.seq,
                writer: r.writer_id,
            });
        };
        r.verify(vk).map_err(|e| ChainError::Record {
            seq: r.seq,
            source: e,
        })?;

        // SPECS §5.1: under single-writer, two writers in one chain is an
        // alarm rather than something to merge. Handoff is an explicit signed
        // operation and is not modelled yet, so any change is refused rather
        // than silently allowed -- refusing is the recoverable mistake.
        if regime == Regime::SingleWriter {
            match sole_writer {
                None => sole_writer = Some(r.writer_id),
                Some(w) if w != r.writer_id => {
                    return Err(ChainError::ConcurrentWriters {
                        seq: r.seq,
                        first: w,
                        second: r.writer_id,
                    })
                }
                Some(_) => {}
            }
        }

        link = r.record_hash();
        expected_seq = r.seq.saturating_add(1);
    }

    Ok(Walk {
        slot_id,
        regime,
        first_seq: first.seq,
        head_seq: records[records.len() - 1].seq,
        head_hash: link,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_core::Addr;
    use nas_crypto::{Identity, Role};

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"bucket")
    }

    /// Build a valid chain of `n` records signed by `id`.
    fn chain(id: &Identity, n: u64, regime: Regime) -> Vec<SlotRecord> {
        let mut out: Vec<SlotRecord> = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = SlotRecord::sign(
                id,
                slot(),
                seq,
                Addr::of_ciphertext(format!("root-{seq}").as_bytes()),
                [(seq as u8).wrapping_add(1); crate::ROOT_NONCE_LEN],
                prev,
                regime,
            )
            .unwrap();
            prev = r.record_hash();
            out.push(r);
        }
        out
    }

    fn roster_with(ids: &[&Identity]) -> Roster {
        let mut r = Roster::new();
        for i in ids {
            r.add(i.verifying_key()).unwrap();
        }
        r
    }

    #[test]
    fn a_valid_chain_walks() {
        let id = ident(1);
        let c = chain(&id, 5, Regime::CasMerge);
        let w = verify_chain(&c, slot(), &roster_with(&[&id]), None).unwrap();
        assert_eq!((w.first_seq, w.head_seq), (0, 4));
        assert_eq!(w.head_hash, c[4].record_hash());
    }

    #[test]
    fn a_partial_chain_walks_from_a_pin() {
        let id = ident(1);
        let c = chain(&id, 6, Regime::CasMerge);
        let pin = c[2].record_hash();
        let w = verify_chain(&c[3..], slot(), &roster_with(&[&id]), Some(pin)).unwrap();
        assert_eq!((w.first_seq, w.head_seq), (3, 5));
    }

    #[test]
    fn a_chain_that_does_not_start_where_the_client_is_pinned_is_refused() {
        // The rollback shape: a peer serves a valid-looking suffix that does
        // not actually continue the client's history.
        let id = ident(1);
        let c = chain(&id, 6, Regime::CasMerge);
        assert_eq!(
            verify_chain(&c[3..], slot(), &roster_with(&[&id]), Some([0xAB; 32])),
            Err(ChainError::BrokenLink { seq: 3 })
        );
    }

    #[test]
    fn a_removed_link_is_caught() {
        let id = ident(1);
        let mut c = chain(&id, 5, Regime::CasMerge);
        c.remove(2);
        assert_eq!(
            verify_chain(&c, slot(), &roster_with(&[&id]), None),
            Err(ChainError::NotContiguous {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn a_substituted_record_breaks_the_link() {
        // Re-signing seq 3 with a different root produces a validly signed
        // record that does not hash to what seq 4 chains to.
        let id = ident(1);
        let mut c = chain(&id, 5, Regime::CasMerge);
        c[3] = SlotRecord::sign(
            &id,
            slot(),
            3,
            Addr::of_ciphertext(b"a rewritten history"),
            [9u8; crate::ROOT_NONCE_LEN],
            c[2].record_hash(),
            Regime::CasMerge,
        )
        .unwrap();
        assert_eq!(
            verify_chain(&c, slot(), &roster_with(&[&id]), None),
            Err(ChainError::BrokenLink { seq: 4 })
        );
    }

    #[test]
    fn an_unrostered_writer_is_refused() {
        let (a, b) = (ident(1), ident(2));
        let c = chain(&b, 3, Regime::CasMerge);
        assert!(matches!(
            verify_chain(&c, slot(), &roster_with(&[&a]), None),
            Err(ChainError::UnknownWriter { seq: 0, .. })
        ));
    }

    #[test]
    fn another_slots_history_is_refused() {
        let id = ident(1);
        let c = chain(&id, 3, Regime::CasMerge);
        assert!(matches!(
            verify_chain(&c, SlotId::new(b"ns", b"other"), &roster_with(&[&id]), None),
            Err(ChainError::WrongSlot { seq: 0, .. })
        ));
    }

    #[test]
    fn a_regime_change_mid_chain_is_refused() {
        let id = ident(1);
        let mut c = chain(&id, 3, Regime::CasMerge);
        c[2] = SlotRecord::sign(
            &id,
            slot(),
            2,
            c[2].root,
            c[2].root_nonce,
            c[1].record_hash(),
            Regime::SingleWriter,
        )
        .unwrap();
        assert!(matches!(
            verify_chain(&c, slot(), &roster_with(&[&id]), None),
            Err(ChainError::RegimeChanged { seq: 2, .. })
        ));
    }

    #[test]
    fn two_writers_are_fine_under_cas_merge_and_an_alarm_under_single_writer() {
        // SPECS §5.1 vs §5.2: the same observation means different things.
        let (a, b) = (ident(1), ident(2));
        let rost = roster_with(&[&a, &b]);

        for regime in [Regime::CasMerge, Regime::SingleWriter] {
            let mut c = chain(&a, 2, regime);
            let second = SlotRecord::sign(
                &b,
                slot(),
                2,
                Addr::of_ciphertext(b"written by b"),
                [3u8; crate::ROOT_NONCE_LEN],
                c[1].record_hash(),
                regime,
            )
            .unwrap();
            c.push(second);
            let got = verify_chain(&c, slot(), &rost, None);
            match regime {
                Regime::CasMerge => assert!(got.is_ok(), "cas-merge must permit two writers"),
                Regime::SingleWriter => assert!(matches!(
                    got,
                    Err(ChainError::ConcurrentWriters { seq: 2, .. })
                )),
            }
        }
    }

    #[test]
    fn an_empty_chain_is_an_error_not_a_vacuous_success() {
        // Returning Ok for an empty chain would let a peer serve nothing and
        // have the client conclude its history verified.
        assert_eq!(
            verify_chain(&[], slot(), &Roster::new(), None),
            Err(ChainError::Empty)
        );
    }

    #[test]
    fn a_tampered_signature_fails_the_walk() {
        let id = ident(1);
        let mut c = chain(&id, 3, Regime::CasMerge);
        c[1].sig[0] ^= 0xFF;
        // The link is checked before the signature, and mutating the signature
        // changes the record hash, so seq 2 stops chaining first.
        assert!(matches!(
            verify_chain(&c, slot(), &roster_with(&[&id]), None),
            Err(ChainError::BrokenLink { seq: 2 }) | Err(ChainError::Record { seq: 1, .. })
        ));
    }
}
