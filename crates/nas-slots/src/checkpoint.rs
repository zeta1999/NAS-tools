//! Skip-chain checkpoints (SPECS §5.5).
//!
//! ```text
//! Checkpoint { slot_id, seq, record_hash, prev_seq, prev_hash, writer_pk, sig }
//! sig context "nas-tools/sig/slot-checkpoint/v1"
//! ```
//!
//! Peers retain history so a client can walk it (§5.3), but retention is
//! bounded and a walk is linear: a client 100 000 updates behind either reads
//! 100 000 records or gives up and takes the head on faith. §5.5 chose
//! retain-N *plus* a signed link every N records, so that client walks ~400
//! checkpoints instead. The writer already signs every version, so one more
//! signature every 256 records is marginal.
//!
//! # What a skip walk proves — and what it does not
//!
//! This is the part that matters, because a checkpoint is easy to over-read.
//!
//! A checkpoint chain is hash-linked and signed at every step, so it proves
//! **the writer committed to this particular ancestry of the head**. A client
//! holding an old checkpoint detects any divergence at or below it: a peer
//! serving a different history must serve a different ladder, and the ladder
//! does not verify against what the client already pinned.
//!
//! It does **not** prove the records strictly between two checkpoints exist,
//! chain, or were ever published. A peer may omit or substitute them and a
//! skip walk will not see it. That is a real weakening, and it is why the full
//! walk stays the default rather than being replaced: the full walk's value is
//! against the *peer* (it served a contiguous set), and skipping is exactly
//! what gives that up.
//!
//! Against a lying *writer* neither helps — a writer can sign any chain it
//! likes, checkpoints or not. Detecting that needs a second observer, which is
//! what witnesses are for (§5.3).
//!
//! So the honest ordering (SPECS §5.4) is:
//!
//! | | ancestry of the head | contiguity between anchors |
//! |---|---|---|
//! | full walk | proven | proven |
//! | **skip walk** | **proven** | **not proven** |
//! | head only (`Verdict::Degraded`) | none | none |
//!
//! A skip walk is strictly stronger than the degraded path and strictly weaker
//! than a full one. [`verify_skip_chain`] therefore reports how much of each it
//! did, and the caller is told in the type ([`SkipWalk::records`] against
//! [`SkipWalk::skipped`]) rather than left to assume.
//!
//! # The tail is walked in full
//!
//! A skip walk is a ladder followed by an ordinary chain walk: checkpoints
//! carry the client from its anchor up to the last checkpoint, and the records
//! from there to the head are verified link by link. Since a writer checkpoints
//! every `CHECKPOINT_INTERVAL` records, that tail is bounded by the interval —
//! the recent history, where an omission matters most, is never skipped.

use crate::chain::{verify_chain_with_handoffs, ChainError};
use crate::handoff::SlotHandoff;
use crate::id::{SlotId, WriterId};
use crate::record::SlotRecord;
use crate::roster::Roster;
use nas_core::{decode_fields, encode_fields, DecodeError};
use nas_crypto::{
    key_id, verify, Identity, SigContext, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

/// Records a peer retains by default (SPECS §5.5, "retain-N", `N = 1024`).
pub const RETAIN_N: usize = 1024;

/// Records between checkpoints (SPECS §5.5).
///
/// A writer's policy, not a verifier's rule: [`verify_skip_chain`] accepts
/// whatever ladder it is given, because a slot whose interval changed would
/// otherwise become unverifiable at exactly the moment its history got long.
pub const CHECKPOINT_INTERVAL: u64 = 256;

/// Should the writer checkpoint at this sequence, under the default interval?
pub fn is_checkpoint_seq(seq: u64) -> bool {
    seq.is_multiple_of(CHECKPOINT_INTERVAL)
}

const CHECKPOINT_HASH_DOMAIN: &[u8] = b"nas-tools/slot-checkpoint-hash/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
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
    /// The first checkpoint must be at seq 0 with a zero back-link, and no
    /// other may be. Without this a writer could sign a "genesis" checkpoint
    /// at any height and cut the ladder, which is the §5.3 attack one level up.
    GenesisMismatch {
        seq: u64,
    },
    /// `prev_seq` is not below `seq`. A checkpoint pointing forward or at
    /// itself is a loop, and a verifier that followed one would not terminate.
    NotDescending {
        seq: u64,
        prev_seq: u64,
    },
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::BadSignature => f.write_str("checkpoint signature does not verify"),
            Self::GenesisMismatch { seq } => write!(
                f,
                "checkpoint {seq}: only the checkpoint at seq 0 may have a zero back-link"
            ),
            Self::NotDescending { seq, prev_seq } => write!(
                f,
                "checkpoint {seq} links back to {prev_seq}, which is not below it"
            ),
        }
    }
}
impl std::error::Error for CheckpointError {}
impl From<DecodeError> for CheckpointError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<SignError> for CheckpointError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

fn body(
    slot_id: &SlotId,
    seq: u64,
    record_hash: &[u8; 32],
    prev_seq: u64,
    prev_hash: &[u8; 32],
) -> Vec<u8> {
    encode_fields(&[
        slot_id.as_bytes(),
        &seq.to_le_bytes(),
        record_hash,
        &prev_seq.to_le_bytes(),
        prev_hash,
    ])
    .expect("fixed-width checkpoint body always encodes")
}

/// `seq == 0` and a zero back-link must imply each other.
fn check_genesis(seq: u64, prev_seq: u64, prev_hash: &[u8; 32]) -> Result<(), CheckpointError> {
    let genesis = prev_hash == &[0u8; 32];
    if genesis != (seq == 0) {
        return Err(CheckpointError::GenesisMismatch { seq });
    }
    if !genesis && prev_seq >= seq {
        return Err(CheckpointError::NotDescending { seq, prev_seq });
    }
    if genesis && prev_seq != 0 {
        return Err(CheckpointError::GenesisMismatch { seq });
    }
    Ok(())
}

/// One rung of the ladder: the writer's signed assertion that the record at
/// `seq` is `record_hash`, and that the checkpoint before it was `prev_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub slot_id: SlotId,
    /// The sequence of the record this checkpoint anchors.
    pub seq: u64,
    /// That record's [`SlotRecord::record_hash`] — the whole record including
    /// its signature, so the checkpoint commits to bytes a client can be
    /// handed rather than to a body several records could share.
    pub record_hash: [u8; 32],
    /// The previous checkpoint's sequence. Carried rather than derived from
    /// [`CHECKPOINT_INTERVAL`], so a slot whose interval changes stays
    /// verifiable and no verifier has to guess which interval was in force.
    pub prev_seq: u64,
    /// The previous checkpoint's own hash; zero only at seq 0. This is what
    /// makes the ladder a chain rather than a pile of independent claims.
    pub prev_hash: [u8; 32],
    /// The writer's full verifying key.
    ///
    /// In full rather than as an id for the same reason a handoff carries one:
    /// the record verifies on its own, and a client walking far-back history
    /// may hold a roster that no longer lists the writer of that era.
    pub writer_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Checkpoint {
    pub fn sign(
        writer: &Identity,
        slot_id: SlotId,
        seq: u64,
        record_hash: [u8; 32],
        prev_seq: u64,
        prev_hash: [u8; 32],
    ) -> Result<Self, CheckpointError> {
        check_genesis(seq, prev_seq, &prev_hash)?;
        let b = body(&slot_id, seq, &record_hash, prev_seq, &prev_hash);
        let sig = writer.sign(SigContext::SlotCheckpoint, &b)?;
        Ok(Self {
            slot_id,
            seq,
            record_hash,
            prev_seq,
            prev_hash,
            writer_pk: writer.verifying_key().to_vec(),
            sig,
        })
    }

    /// Checkpoint the record `rec`, chaining to `prev` (`None` at genesis).
    ///
    /// Preferred over [`Self::sign`] because the record hash and sequence are
    /// taken from the record itself and the back-link from the previous
    /// checkpoint, so the three cannot be made to disagree by a caller.
    pub fn of_record(
        writer: &Identity,
        rec: &SlotRecord,
        prev: Option<&Checkpoint>,
    ) -> Result<Self, CheckpointError> {
        let (prev_seq, prev_hash) = match prev {
            Some(p) => (p.seq, p.checkpoint_hash()),
            None => (0, [0u8; 32]),
        };
        Self::sign(
            writer,
            rec.slot_id,
            rec.seq,
            rec.record_hash(),
            prev_seq,
            prev_hash,
        )
    }

    pub fn writer_id(&self) -> WriterId {
        WriterId::from_bytes(key_id(&self.writer_pk))
    }

    /// `BLAKE3(domain ‖ body ‖ sig)` — what the successor's `prev_hash` must
    /// equal. Over the signature too, for the reason `SlotRecord::record_hash`
    /// is: the ladder must commit to the bytes served, not to a body that two
    /// differently-signed checkpoints could share.
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        let b = body(
            &self.slot_id,
            self.seq,
            &self.record_hash,
            self.prev_seq,
            &self.prev_hash,
        );
        let mut h = blake3::Hasher::new();
        h.update(CHECKPOINT_HASH_DOMAIN);
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(&b);
        h.update(&self.sig);
        *h.finalize().as_bytes()
    }

    pub fn verify(&self, verifying_key: &[u8]) -> Result<(), CheckpointError> {
        check_genesis(self.seq, self.prev_seq, &self.prev_hash)?;
        let b = body(
            &self.slot_id,
            self.seq,
            &self.record_hash,
            self.prev_seq,
            &self.prev_hash,
        );
        verify(verifying_key, SigContext::SlotCheckpoint, &b, &self.sig)
            .map_err(|_| CheckpointError::BadSignature)
    }

    /// Verify against the key the record carries.
    ///
    /// Enough to know the checkpoint is internally consistent; **not** enough
    /// to know the signer may write this slot. [`verify_skip_chain`] checks the
    /// roster, and nothing that skips it should be treated as a verified rung.
    pub fn verify_self(&self) -> Result<(), CheckpointError> {
        self.verify(&self.writer_pk.clone())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        Ok(encode_fields(&[
            self.slot_id.as_bytes(),
            &self.seq.to_le_bytes(),
            &self.record_hash,
            &self.prev_seq.to_le_bytes(),
            &self.prev_hash,
            &self.writer_pk,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        let f = decode_fields(bytes)?;
        if f.len() != 7 {
            return Err(CheckpointError::FieldCount {
                want: 7,
                got: f.len(),
            });
        }
        let fixed = |field: &'static str, b: &[u8]| -> Result<[u8; 32], CheckpointError> {
            b.try_into().map_err(|_| CheckpointError::BadWidth {
                field,
                want: 32,
                got: b.len(),
            })
        };
        let u64_of = |field: &'static str, b: &[u8]| -> Result<u64, CheckpointError> {
            Ok(u64::from_le_bytes(b.try_into().map_err(|_| {
                CheckpointError::BadWidth {
                    field,
                    want: 8,
                    got: b.len(),
                }
            })?))
        };
        if f[5].len() != VERIFYING_KEY_LEN {
            return Err(CheckpointError::BadWidth {
                field: "writer_pk",
                want: VERIFYING_KEY_LEN,
                got: f[5].len(),
            });
        }
        if f[6].len() != SIGNATURE_LEN {
            return Err(CheckpointError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[6].len(),
            });
        }
        Ok(Self {
            slot_id: SlotId::from_bytes(fixed("slot_id", f[0])?),
            seq: u64_of("seq", f[1])?,
            record_hash: fixed("record_hash", f[2])?,
            prev_seq: u64_of("prev_seq", f[3])?,
            prev_hash: fixed("prev_hash", f[4])?,
            writer_pk: f[5].to_vec(),
            sig: f[6].to_vec(),
        })
    }
}

// ── Walking the ladder ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipError {
    Checkpoint {
        seq: u64,
        source: CheckpointError,
    },
    /// A checkpoint for a different slot.
    WrongSlot {
        seq: u64,
    },
    /// The signer is not on the roster.
    UnknownWriter {
        seq: u64,
        writer: WriterId,
    },
    /// `prev_seq`/`prev_hash` do not match the checkpoint below.
    BrokenLadder {
        seq: u64,
    },
    /// The ladder does not start where the caller is anchored.
    ///
    /// Refusing here is the whole point: a ladder that starts anywhere is a
    /// ladder the peer chose, and believing it would make the anchor
    /// decorative.
    NotAnchored {
        seq: u64,
    },
    /// The tail does not begin at the record the top checkpoint anchors.
    TailDetached {
        checkpoint_seq: u64,
        tail_seq: u64,
    },
    /// The tail's first record is not the one the top checkpoint names.
    TailMismatch {
        seq: u64,
    },
    Chain(ChainError),
    /// No checkpoints and no tail: there is nothing to verify, and returning
    /// success for it would be the emptiest possible overclaim.
    Empty,
}

impl std::fmt::Display for SkipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Checkpoint { seq, source } => write!(f, "checkpoint {seq}: {source}"),
            Self::WrongSlot { seq } => write!(f, "checkpoint {seq} belongs to another slot"),
            Self::UnknownWriter { seq, writer } => write!(
                f,
                "checkpoint {seq}: {} is not on the roster",
                writer.to_hex()
            ),
            Self::BrokenLadder { seq } => {
                write!(f, "checkpoint {seq} does not link to the one below it")
            }
            Self::NotAnchored { seq } => write!(
                f,
                "the ladder starts at checkpoint {seq}, which is not where this client is anchored"
            ),
            Self::TailDetached {
                checkpoint_seq,
                tail_seq,
            } => write!(
                f,
                "the top checkpoint is at seq {checkpoint_seq} but the records begin at {tail_seq}"
            ),
            Self::TailMismatch { seq } => write!(
                f,
                "the record at seq {seq} is not the one the checkpoint names"
            ),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Empty => f.write_str("nothing to verify"),
        }
    }
}
impl std::error::Error for SkipError {}
impl From<ChainError> for SkipError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}

/// What a skip walk actually did, in the numbers a caller needs to describe it
/// honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipWalk {
    pub slot_id: SlotId,
    /// Lowest checkpoint verified — how far back the ancestry claim reaches.
    pub from_seq: u64,
    pub head_seq: u64,
    /// Hash of the head record, for pinning.
    pub head_hash: [u8; 32],
    /// Hash of the topmost checkpoint, for pinning the ladder itself. A client
    /// that keeps this can demand the same ladder next time.
    pub top_checkpoint: [u8; 32],
    /// Rungs verified.
    pub checkpoints: usize,
    /// Records verified link by link, in the tail.
    pub records: usize,
    /// Records **not** verified, because a checkpoint was trusted to stand for
    /// them. Reported so "we walked the history" cannot be said of a walk that
    /// mostly did not.
    pub skipped: u64,
}

/// Verify a checkpoint ladder followed by a full record walk to the head.
///
/// `anchor` is the checkpoint hash this client already trusts: `Some(h)` means
/// `checkpoints[0]` must hash to it, `None` means the ladder must start at
/// genesis. There is no third case on purpose — a ladder anchored to nothing
/// is a ladder the peer chose.
///
/// `tail` must be a contiguous record chain whose first element is the record
/// the topmost checkpoint names. Passing an empty `checkpoints` is allowed and
/// degenerates to [`verify_chain_with_handoffs`], so a caller need not special-
/// case a young slot.
pub fn verify_skip_chain(
    checkpoints: &[Checkpoint],
    tail: &[SlotRecord],
    slot_id: SlotId,
    roster: &Roster,
    anchor: Option<[u8; 32]>,
    handoffs: &[SlotHandoff],
) -> Result<SkipWalk, SkipError> {
    if checkpoints.is_empty() && tail.is_empty() {
        return Err(SkipError::Empty);
    }

    let mut link: Option<(u64, [u8; 32])> = None;
    for c in checkpoints {
        if c.slot_id != slot_id {
            return Err(SkipError::WrongSlot { seq: c.seq });
        }
        // The roster is consulted before the signature, so an unrostered
        // writer is reported as one rather than as a bad signature.
        let Some(vk) = roster.get(&c.writer_id()) else {
            return Err(SkipError::UnknownWriter {
                seq: c.seq,
                writer: c.writer_id(),
            });
        };
        c.verify(vk).map_err(|e| SkipError::Checkpoint {
            seq: c.seq,
            source: e,
        })?;

        match link {
            // The first rung: anchored to what the client already trusts, or
            // to genesis. `check_genesis` inside `verify` has already refused
            // a zero back-link anywhere but seq 0.
            None => match anchor {
                Some(h) if c.checkpoint_hash() != h => {
                    return Err(SkipError::NotAnchored { seq: c.seq })
                }
                None if c.seq != 0 => return Err(SkipError::NotAnchored { seq: c.seq }),
                _ => {}
            },
            Some((prev_seq, prev_hash)) => {
                if c.prev_seq != prev_seq || c.prev_hash != prev_hash {
                    return Err(SkipError::BrokenLadder { seq: c.seq });
                }
            }
        }
        link = Some((c.seq, c.checkpoint_hash()));
    }

    let top = checkpoints.last();
    if let (Some(c), Some(first)) = (top, tail.first()) {
        if first.seq != c.seq {
            return Err(SkipError::TailDetached {
                checkpoint_seq: c.seq,
                tail_seq: first.seq,
            });
        }
        if first.record_hash() != c.record_hash {
            return Err(SkipError::TailMismatch { seq: c.seq });
        }
    }

    // With no tail the head is the record the top checkpoint names, and it is
    // named rather than held: the caller has its hash and not its bytes.
    let Some(first) = tail.first() else {
        let c = top.expect("empty checkpoints and empty tail returned Empty above");
        return Ok(SkipWalk {
            slot_id,
            from_seq: checkpoints[0].seq,
            head_seq: c.seq,
            head_hash: c.record_hash,
            top_checkpoint: c.checkpoint_hash(),
            checkpoints: checkpoints.len(),
            records: 0,
            skipped: c.seq.saturating_sub(checkpoints[0].seq),
        });
    };

    // The tail must be anchored by something. A top checkpoint pins its first
    // record by hash, so that record's own predecessor may be unknown — it is
    // one of the records being skipped, and `Some(first.prev)` is how
    // `verify_chain` is told to leave the first link open. Otherwise the tail
    // has to start at genesis.
    //
    // A partial walk anchored to a client's pin rather than to a checkpoint is
    // a different question with a different argument, and
    // `verify_chain_with_handoffs` takes `expect_prev` for exactly it. Quietly
    // accepting one here would mean this function sometimes verified an
    // unanchored prefix depending on what the peer chose to send.
    let expect_prev = match (top, first.seq) {
        (Some(_), _) => Some(first.prev),
        (None, 0) => None,
        (None, seq) => return Err(SkipError::NotAnchored { seq }),
    };
    let walk = verify_chain_with_handoffs(tail, slot_id, roster, expect_prev, handoffs)?;

    let from_seq = checkpoints.first().map(|c| c.seq).unwrap_or(walk.first_seq);
    Ok(SkipWalk {
        slot_id,
        from_seq,
        head_seq: walk.head_seq,
        head_hash: walk.head_hash,
        top_checkpoint: top.map(|c| c.checkpoint_hash()).unwrap_or([0u8; 32]),
        checkpoints: checkpoints.len(),
        records: tail.len(),
        skipped: first.seq.saturating_sub(from_seq),
    })
}

// ── Choosing a walk ────────────────────────────────────────────────────────

/// How a client can reach the head from where its memory starts.
///
/// Separated from doing it, like `plan_sweep` and `decide` elsewhere: which
/// walk is possible is arithmetic over sequence numbers and a list of rungs,
/// and arithmetic is worth testing without a peer, a socket or a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkPlan {
    /// Every record from `from` to the head is within budget. The strongest
    /// walk, and the one to prefer whenever it is available — it proves
    /// contiguity, which no ladder does.
    Full { from: u64, records: u64 },
    /// Climb the ladder to `top_seq`, then walk records from there.
    ///
    /// `skipped` records are taken on the writer's word. The caller is expected
    /// to report that number, not to round it away.
    Skip {
        top_seq: u64,
        skipped: u64,
        records: u64,
    },
    /// Neither walk reaches: the span is longer than the client's budget and no
    /// rung sits close enough to the head to bring the tail inside it.
    ///
    /// `best_rung` is the highest rung that exists at all, so the refusal can
    /// say whether the ladder is missing or merely too short.
    Unreachable { span: u64, best_rung: Option<u64> },
}

/// Pick the walk that reaches `head_seq` from `from`.
///
/// `rung_seqs` are the sequences of verified rungs, ascending. `budget` is how
/// many records the client is willing to fetch and verify link by link — a
/// policy, not a wire limit. A history longer than one response is *paged*, so
/// what bounds the linear part is patience rather than framing.
///
/// The full walk wins ties on purpose. A ladder is cheaper and weaker, and
/// choosing it when the strong walk was affordable would trade away contiguity
/// for nothing.
pub fn plan_walk(from: u64, head_seq: u64, rung_seqs: &[u64], budget: u64) -> WalkPlan {
    let span = head_seq.saturating_sub(from);
    // `span` is a gap; the walk carries the records at both ends.
    if budget > 0 && span < budget {
        return WalkPlan::Full {
            from,
            records: span + 1,
        };
    }
    // The highest rung that leaves a walkable tail, is not below where the
    // client already starts, and is not above the head.
    //
    // All three matter. A rung below `from` shortens nothing and would drop
    // the client's own memory out of the walk. A rung *above* the head is a
    // rung for records the peer is not serving — and `saturating_sub` clamps
    // that gap to zero, so without the bound it looks like the closest rung of
    // all. (Found by `skipped_plus_walked_covers_the_whole_span`, which is why
    // the arithmetic is a function with tests rather than three lines inline.)
    let usable = rung_seqs
        .iter()
        .copied()
        .filter(|&r| r >= from && r <= head_seq && head_seq - r < budget)
        .max();
    match usable {
        Some(top_seq) => WalkPlan::Skip {
            top_seq,
            skipped: top_seq - from,
            records: head_seq - top_seq + 1,
        },
        None => WalkPlan::Unreachable {
            span,
            best_rung: rung_seqs.iter().copied().max(),
        },
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn a_short_span_is_walked_in_full() {
        assert_eq!(
            plan_walk(0, 9, &[0], 256),
            WalkPlan::Full {
                from: 0,
                records: 10
            }
        );
    }

    #[test]
    fn the_full_walk_wins_whenever_it_fits() {
        // A ladder is cheaper and weaker. Taking it when the strong walk was
        // affordable would trade contiguity away for nothing.
        let rungs: Vec<u64> = (0..40).map(|i| i * 256).collect();
        assert!(matches!(
            plan_walk(0, 255, &rungs, 256),
            WalkPlan::Full { .. }
        ));
        // One more record and it no longer fits.
        assert!(matches!(
            plan_walk(0, 256, &rungs, 256),
            WalkPlan::Skip { .. }
        ));
    }

    #[test]
    fn a_long_span_climbs_to_the_highest_rung_with_a_walkable_tail() {
        // The §5.5 case: 100 000 behind, rungs every 256.
        let rungs: Vec<u64> = (0..=390).map(|i| i * 256).collect();
        assert_eq!(
            plan_walk(0, 100_000, &rungs, 256),
            WalkPlan::Skip {
                top_seq: 99_840,
                skipped: 99_840,
                records: 161,
            }
        );
    }

    #[test]
    fn a_rung_below_where_the_client_starts_is_not_usable() {
        // It shortens nothing, and walking from it would drop the client's own
        // memory out of the span being checked.
        assert_eq!(
            plan_walk(500, 1000, &[0, 256], 256),
            WalkPlan::Unreachable {
                span: 500,
                best_rung: Some(256)
            }
        );
    }

    #[test]
    fn a_ladder_that_stops_too_far_below_the_head_does_not_reach() {
        // The peer has rungs but stopped checkpointing; the refusal should be
        // able to say which of the two it is.
        assert_eq!(
            plan_walk(0, 10_000, &[0, 256, 512], 256),
            WalkPlan::Unreachable {
                span: 10_000,
                best_rung: Some(512)
            }
        );
        assert_eq!(
            plan_walk(0, 10_000, &[], 256),
            WalkPlan::Unreachable {
                span: 10_000,
                best_rung: None
            }
        );
    }

    #[test]
    fn a_rung_at_the_head_leaves_a_one_record_tail() {
        assert_eq!(
            plan_walk(0, 512, &[0, 256, 512], 256),
            WalkPlan::Skip {
                top_seq: 512,
                skipped: 512,
                records: 1,
            }
        );
    }

    #[test]
    fn a_client_already_at_the_head_walks_one_record() {
        assert_eq!(
            plan_walk(7, 7, &[], 256),
            WalkPlan::Full {
                from: 7,
                records: 1
            }
        );
    }

    #[test]
    fn the_arithmetic_does_not_underflow_on_a_head_below_the_start() {
        // A peer serving a head below the client's memory is a rollback, and
        // it is caught before this function is reached — but planning must not
        // panic on the way there.
        assert_eq!(
            plan_walk(100, 5, &[], 256),
            WalkPlan::Full {
                from: 100,
                records: 1
            }
        );
    }

    #[test]
    fn skipped_plus_walked_covers_the_whole_span() {
        // The property the honesty of the report rests on.
        let rungs: Vec<u64> = (0..=40).map(|i| i * 256).collect();
        for head in [300u64, 1000, 5000, 10_240] {
            match plan_walk(0, head, &rungs, 256) {
                WalkPlan::Full { records, .. } => assert_eq!(records, head + 1),
                WalkPlan::Skip {
                    skipped, records, ..
                } => assert_eq!(skipped + records, head + 1),
                other => panic!("{other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Regime;
    use crate::record::ROOT_NONCE_LEN;
    use nas_core::Addr;
    use nas_crypto::Role;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"refs/heads/main")
    }

    fn roster_of(ids: &[&Identity]) -> Roster {
        let mut r = Roster::new();
        for i in ids {
            r.add(i.verifying_key()).unwrap();
        }
        r
    }

    /// `n` chained records from genesis.
    fn chain(id: &Identity, n: u64) -> Vec<SlotRecord> {
        let mut out: Vec<SlotRecord> = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = SlotRecord::sign(
                id,
                slot(),
                seq,
                Addr::of_ciphertext(format!("root-{seq}").as_bytes()),
                [1u8; ROOT_NONCE_LEN],
                prev,
                Regime::CasMerge,
            )
            .unwrap();
            prev = r.record_hash();
            out.push(r);
        }
        out
    }

    /// Checkpoint every `every` records of `records`.
    fn ladder(id: &Identity, records: &[SlotRecord], every: u64) -> Vec<Checkpoint> {
        let mut out: Vec<Checkpoint> = Vec::new();
        for r in records.iter().filter(|r| r.seq.is_multiple_of(every)) {
            let c = Checkpoint::of_record(id, r, out.last()).unwrap();
            out.push(c);
        }
        out
    }

    #[test]
    fn a_ladder_from_genesis_reaches_the_head() {
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);
        // Rungs at 0, 10, 20, 30; the tail is 30..=39.
        assert_eq!(cps.len(), 4);
        let w =
            verify_skip_chain(&cps, &recs[30..], slot(), &roster_of(&[&id]), None, &[]).unwrap();
        assert_eq!(w.head_seq, 39);
        assert_eq!(w.head_hash, recs[39].record_hash());
        assert_eq!(w.checkpoints, 4);
        assert_eq!(w.records, 10);
        assert_eq!(w.skipped, 30, "and it says so");
    }

    #[test]
    fn the_skipped_count_is_what_makes_the_claim_honest() {
        // A walk that verified 10 of 40 records must not be describable as
        // having walked the history. The numbers are in the result so the
        // caller cannot phrase it that way by accident.
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);
        let w =
            verify_skip_chain(&cps, &recs[30..], slot(), &roster_of(&[&id]), None, &[]).unwrap();
        assert_eq!(w.records as u64 + w.skipped, 40);
    }

    #[test]
    fn a_ladder_must_start_where_the_client_is_anchored() {
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);
        // Starting mid-ladder without an anchor is a ladder the peer chose.
        assert_eq!(
            verify_skip_chain(
                &cps[1..],
                &recs[30..],
                slot(),
                &roster_of(&[&id]),
                None,
                &[]
            ),
            Err(SkipError::NotAnchored { seq: 10 })
        );
        // With the right anchor it is fine, and reaches less far back.
        let anchor = cps[1].checkpoint_hash();
        let w = verify_skip_chain(
            &cps[1..],
            &recs[30..],
            slot(),
            &roster_of(&[&id]),
            Some(anchor),
            &[],
        )
        .unwrap();
        assert_eq!(w.from_seq, 10);
        assert_eq!(w.skipped, 20);
        // A different anchor is refused.
        assert_eq!(
            verify_skip_chain(
                &cps[1..],
                &recs[30..],
                slot(),
                &roster_of(&[&id]),
                Some([7u8; 32]),
                &[]
            ),
            Err(SkipError::NotAnchored { seq: 10 })
        );
    }

    #[test]
    fn a_rung_removed_from_the_middle_breaks_the_ladder() {
        // This is the whole reason the ladder is hash-linked rather than a set
        // of independent signed claims: each rung names the one below it.
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);
        let cut = vec![cps[0].clone(), cps[2].clone(), cps[3].clone()];
        assert_eq!(
            verify_skip_chain(&cut, &recs[30..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::BrokenLadder { seq: 20 })
        );
    }

    #[test]
    fn a_rung_from_another_history_breaks_the_ladder() {
        // A forking peer's other branch is signed just as well. What it cannot
        // do is make its rung link to ours.
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);

        let mut other = chain(&id, 40);
        other[20] = SlotRecord::sign(
            &id,
            slot(),
            20,
            Addr::of_ciphertext(b"a different root"),
            [1u8; ROOT_NONCE_LEN],
            other[19].record_hash(),
            Regime::CasMerge,
        )
        .unwrap();
        let rogue = Checkpoint::of_record(&id, &other[20], Some(&cps[1])).unwrap();
        rogue.verify_self().expect("it is a real signature");

        let swapped = vec![cps[0].clone(), cps[1].clone(), rogue, cps[3].clone()];
        assert_eq!(
            verify_skip_chain(&swapped, &recs[30..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::BrokenLadder { seq: 30 }),
            "the rung above it no longer links"
        );
    }

    #[test]
    fn the_tail_must_hang_from_the_top_checkpoint() {
        let id = ident(1);
        let recs = chain(&id, 40);
        let cps = ladder(&id, &recs, 10);
        // Records that do not start at the top rung.
        assert_eq!(
            verify_skip_chain(&cps, &recs[31..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::TailDetached {
                checkpoint_seq: 30,
                tail_seq: 31
            })
        );
        // The right sequence, the wrong record: this is a peer substituting
        // the record its own checkpoint names.
        let mut forged = recs[30..].to_vec();
        forged[0] = SlotRecord::sign(
            &id,
            slot(),
            30,
            Addr::of_ciphertext(b"substituted"),
            [1u8; ROOT_NONCE_LEN],
            recs[29].record_hash(),
            Regime::CasMerge,
        )
        .unwrap();
        assert_eq!(
            verify_skip_chain(&cps, &forged, slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::TailMismatch { seq: 30 })
        );
    }

    #[test]
    fn an_unrostered_signer_is_refused_even_with_a_valid_signature() {
        // A checkpoint verifies against the key it carries; that says nothing
        // about whether the signer may write this slot.
        let (id, stranger) = (ident(1), ident(2));
        let recs = chain(&id, 20);
        let mut cps = ladder(&id, &recs, 10);
        cps[1] = Checkpoint::of_record(&stranger, &recs[10], Some(&cps[0])).unwrap();
        cps[1].verify_self().unwrap();
        assert!(matches!(
            verify_skip_chain(&cps, &recs[10..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::UnknownWriter { seq: 10, .. })
        ));
    }

    #[test]
    fn a_tampered_checkpoint_does_not_verify() {
        let id = ident(1);
        let recs = chain(&id, 20);
        let mut cps = ladder(&id, &recs, 10);
        cps[1].record_hash = [9u8; 32];
        assert!(matches!(
            verify_skip_chain(&cps, &recs[10..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::Checkpoint {
                seq: 10,
                source: CheckpointError::BadSignature
            })
        ));
    }

    #[test]
    fn a_genesis_checkpoint_at_a_height_is_refused() {
        // Otherwise a writer could cut the ladder anywhere by declaring a new
        // beginning, which is SPECS §5.3's genesis attack one level up.
        let id = ident(1);
        let recs = chain(&id, 20);
        assert_eq!(
            Checkpoint::sign(&id, slot(), 10, recs[10].record_hash(), 0, [0u8; 32]),
            Err(CheckpointError::GenesisMismatch { seq: 10 })
        );
        // And the converse: seq 0 with a back-link.
        assert_eq!(
            Checkpoint::sign(&id, slot(), 0, recs[0].record_hash(), 0, [1u8; 32]),
            Err(CheckpointError::GenesisMismatch { seq: 0 })
        );
    }

    #[test]
    fn a_checkpoint_pointing_forward_is_refused() {
        // A verifier that followed one would not terminate.
        let id = ident(1);
        let recs = chain(&id, 20);
        assert_eq!(
            Checkpoint::sign(&id, slot(), 10, recs[10].record_hash(), 10, [1u8; 32]),
            Err(CheckpointError::NotDescending {
                seq: 10,
                prev_seq: 10
            })
        );
    }

    #[test]
    fn no_checkpoints_degenerates_to_an_ordinary_walk() {
        // A young slot has no ladder, and a caller should not have to special-
        // case that.
        let id = ident(1);
        let recs = chain(&id, 5);
        let w = verify_skip_chain(&[], &recs, slot(), &roster_of(&[&id]), None, &[]).unwrap();
        assert_eq!(w.head_seq, 4);
        assert_eq!(w.records, 5);
        assert_eq!(w.skipped, 0, "nothing was taken on trust");
        assert_eq!(w.checkpoints, 0);
    }

    #[test]
    fn a_tail_with_no_ladder_and_no_genesis_is_unanchored() {
        // Without a checkpoint pinning its first record, a chain starting at
        // seq 10 is a prefix the peer chose. `verify_chain_with_handoffs`
        // takes `expect_prev` for the pin-anchored case; this function does
        // not guess.
        let id = ident(1);
        let recs = chain(&id, 20);
        assert_eq!(
            verify_skip_chain(&[], &recs[10..], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::NotAnchored { seq: 10 })
        );
    }

    #[test]
    fn nothing_at_all_is_an_error_not_a_success() {
        let id = ident(1);
        assert_eq!(
            verify_skip_chain(&[], &[], slot(), &roster_of(&[&id]), None, &[]),
            Err(SkipError::Empty)
        );
    }

    #[test]
    fn a_checkpoint_for_another_slot_is_refused() {
        let id = ident(1);
        let recs = chain(&id, 20);
        let cps = ladder(&id, &recs, 10);
        assert_eq!(
            verify_skip_chain(
                &cps,
                &recs[10..],
                SlotId::new(b"ns", b"another"),
                &roster_of(&[&id]),
                None,
                &[]
            ),
            Err(SkipError::WrongSlot { seq: 0 })
        );
    }

    #[test]
    fn it_round_trips() {
        let id = ident(1);
        let recs = chain(&id, 20);
        for c in ladder(&id, &recs, 10) {
            let b = c.encode().unwrap();
            assert_eq!(Checkpoint::decode(&b).unwrap(), c);
            assert_eq!(Checkpoint::decode(&b).unwrap().encode().unwrap(), b);
        }
    }

    #[test]
    fn a_truncated_checkpoint_is_an_error_not_a_panic() {
        let id = ident(1);
        let recs = chain(&id, 1);
        let bytes = Checkpoint::of_record(&id, &recs[0], None)
            .unwrap()
            .encode()
            .unwrap();
        for n in 0..bytes.len() {
            let _ = Checkpoint::decode(&bytes[..n]);
        }
    }

    #[test]
    fn the_default_interval_is_what_specs_says() {
        // SPECS §5.5: retain-N = 1024, a checkpoint every 256 records. A
        // client 100 000 behind walks ~400 rungs rather than 100 000 records.
        assert_eq!(RETAIN_N, 1024);
        assert_eq!(CHECKPOINT_INTERVAL, 256);
        assert!(is_checkpoint_seq(0));
        assert!(is_checkpoint_seq(256));
        assert!(!is_checkpoint_seq(255));
        assert_eq!(100_000 / CHECKPOINT_INTERVAL, 390);
    }
}
