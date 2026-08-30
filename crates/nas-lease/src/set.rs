//! Applying a delta chain to reconstruct a holder's leased set (SPECS §6.1).

use crate::record::{LeaseCheckpoint, LeaseDelta, LeaseError};
use nas_core::Addr;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    Lease(LeaseError),
    /// Sequence numbers must be contiguous and ascending.
    NotContiguous {
        expected: u64,
        got: u64,
    },
    /// `prev` does not chain to the predecessor.
    BrokenLink {
        seq: u64,
    },
    /// Records from more than one holder in one chain.
    MixedHolders {
        seq: u64,
    },
    /// A checkpoint disagrees with the set the deltas produce. This is the
    /// check that makes a checkpoint worth having: without it a holder could
    /// publish a compact root that says something different from its own
    /// history, and the peer would compact away the evidence.
    CheckpointMismatch {
        seq: u64,
    },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lease(e) => write!(f, "{e}"),
            Self::NotContiguous { expected, got } => {
                write!(f, "expected lease seq {expected}, got {got}")
            }
            Self::BrokenLink { seq } => write!(f, "lease record {seq} does not chain"),
            Self::MixedHolders { seq } => write!(f, "lease record {seq} is from another holder"),
            Self::CheckpointMismatch { seq } => {
                write!(
                    f,
                    "checkpoint at seq {seq} does not match the delta history"
                )
            }
        }
    }
}
impl std::error::Error for ApplyError {}
impl From<LeaseError> for ApplyError {
    fn from(e: LeaseError) -> Self {
        Self::Lease(e)
    }
}

/// A holder's leased set, reconstructed from its signed history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseSet {
    addrs: BTreeSet<[u8; 32]>,
}

impl LeaseSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// A set built directly from addresses.
    ///
    /// [`replay`] is how a peer reconstructs a holder's set from its *signed*
    /// history, and remains the only path that authenticates anything. This
    /// constructor exists for the callers that already hold a verified set —
    /// a checkpoint's addresses, a sweep planned against known state — and
    /// for tests. It authenticates nothing by itself, which is why the
    /// signature checks live in `replay` rather than here.
    pub fn from_addrs(addrs: &[Addr]) -> Self {
        Self {
            addrs: addrs.iter().map(|a| *a.as_bytes()).collect(),
        }
    }

    pub fn contains(&self, a: &Addr) -> bool {
        self.addrs.contains(a.as_bytes())
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Addr> + '_ {
        self.addrs.iter().map(|b| Addr::from_bytes(*b))
    }

    pub fn to_vec(&self) -> Vec<Addr> {
        self.iter().collect()
    }

    /// Apply one delta. `remove` is applied after `add`, so a delta that both
    /// adds and removes an address ends without it — the conservative reading,
    /// since the alternative silently keeps something the holder asked to drop.
    fn apply(&mut self, d: &LeaseDelta) {
        for a in &d.add {
            self.addrs.insert(*a.as_bytes());
        }
        for a in &d.remove {
            self.addrs.remove(a.as_bytes());
        }
    }
}

/// Replay a verified delta chain, checking any checkpoints along the way.
///
/// `deltas` must be contiguous from seq 0. Checkpoints are matched by `seq`:
/// each is required to describe the set as it stands after the delta of the
/// same sequence number.
pub fn replay(
    deltas: &[LeaseDelta],
    checkpoints: &[LeaseCheckpoint],
) -> Result<LeaseSet, ApplyError> {
    let mut set = LeaseSet::new();
    let mut expected_seq = 0u64;
    let mut link = [0u8; 32];
    let mut holder: Option<[u8; 32]> = None;

    for d in deltas {
        d.verify()?;
        match holder {
            None => holder = Some(d.holder_id()),
            Some(h) if h != d.holder_id() => return Err(ApplyError::MixedHolders { seq: d.seq }),
            Some(_) => {}
        }
        if d.seq != expected_seq {
            return Err(ApplyError::NotContiguous {
                expected: expected_seq,
                got: d.seq,
            });
        }
        if d.prev != link {
            return Err(ApplyError::BrokenLink { seq: d.seq });
        }
        set.apply(d);

        for c in checkpoints.iter().filter(|c| c.seq == d.seq) {
            c.verify()?;
            if Some(c.holder_id()) != holder {
                return Err(ApplyError::MixedHolders { seq: c.seq });
            }
            c.covers(&set.to_vec())
                .map_err(|_| ApplyError::CheckpointMismatch { seq: c.seq })?;
        }

        link = d.chain_hash();
        expected_seq = d.seq.saturating_add(1);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::{Identity, Role};

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Lease).unwrap()
    }

    fn addr(n: u8) -> Addr {
        Addr::of_ciphertext(&[n])
    }

    /// A chain that adds 0..n one per delta.
    fn chain(id: &Identity, n: u8) -> Vec<LeaseDelta> {
        let mut out: Vec<LeaseDelta> = Vec::new();
        let mut prev = [0u8; 32];
        for i in 0..n {
            let d = LeaseDelta::sign(id, 1, i as u64, &[addr(i)], &[], prev).unwrap();
            prev = d.chain_hash();
            out.push(d);
        }
        out
    }

    #[test]
    fn a_chain_replays_to_the_expected_set() {
        let id = ident(1);
        let c = chain(&id, 5);
        let set = replay(&c, &[]).unwrap();
        assert_eq!(set.len(), 5);
        for i in 0..5 {
            assert!(set.contains(&addr(i)));
        }
    }

    #[test]
    fn removes_are_applied() {
        let id = ident(1);
        let mut c = chain(&id, 3);
        let last = c[2].chain_hash();
        c.push(LeaseDelta::sign(&id, 1, 3, &[], &[addr(1)], last).unwrap());
        let set = replay(&c, &[]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(!set.contains(&addr(1)));
    }

    #[test]
    fn add_and_remove_in_one_delta_ends_removed() {
        // The conservative reading: the alternative silently keeps something
        // the holder asked to drop, and a lease is a request to KEEP.
        let id = ident(1);
        let d = LeaseDelta::sign(&id, 1, 0, &[addr(1)], &[addr(1)], [0u8; 32]).unwrap();
        assert!(replay(&[d], &[]).unwrap().is_empty());
    }

    #[test]
    fn a_gap_in_the_chain_is_refused() {
        let id = ident(1);
        let mut c = chain(&id, 4);
        c.remove(2);
        assert_eq!(
            replay(&c, &[]),
            Err(ApplyError::NotContiguous {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn a_broken_link_is_refused() {
        let id = ident(1);
        let mut c = chain(&id, 4);
        // Re-sign seq 2 with different content: validly signed, wrong link.
        c[2] = LeaseDelta::sign(&id, 1, 2, &[addr(99)], &[], c[1].chain_hash()).unwrap();
        assert_eq!(replay(&c, &[]), Err(ApplyError::BrokenLink { seq: 3 }));
    }

    #[test]
    fn two_holders_in_one_chain_are_refused() {
        let (a, b) = (ident(1), ident(2));
        let mut c = chain(&a, 2);
        c.push(LeaseDelta::sign(&b, 1, 2, &[addr(9)], &[], c[1].chain_hash()).unwrap());
        assert_eq!(replay(&c, &[]), Err(ApplyError::MixedHolders { seq: 2 }));
    }

    #[test]
    fn a_matching_checkpoint_is_accepted() {
        let id = ident(1);
        let c = chain(&id, 4);
        let set: Vec<Addr> = (0..4).map(addr).collect();
        let cp = LeaseCheckpoint::sign(&id, 1, 3, &set, [7u8; 32]).unwrap();
        replay(&c, &[cp]).unwrap();
    }

    #[test]
    fn a_checkpoint_that_disagrees_with_the_history_is_refused() {
        // Without this a holder publishes a compact root saying something its
        // own deltas do not, and the peer compacts away the evidence.
        let id = ident(1);
        let c = chain(&id, 4);
        let lying: Vec<Addr> = (0..9).map(addr).collect();
        let cp = LeaseCheckpoint::sign(&id, 1, 3, &lying, [7u8; 32]).unwrap();
        assert_eq!(
            replay(&c, &[cp]),
            Err(ApplyError::CheckpointMismatch { seq: 3 })
        );
    }

    #[test]
    fn another_holders_checkpoint_is_refused() {
        let (a, b) = (ident(1), ident(2));
        let c = chain(&a, 2);
        let set: Vec<Addr> = (0..2).map(addr).collect();
        let cp = LeaseCheckpoint::sign(&b, 1, 1, &set, [7u8; 32]).unwrap();
        assert_eq!(replay(&c, &[cp]), Err(ApplyError::MixedHolders { seq: 1 }));
    }

    #[test]
    fn a_tampered_delta_fails_verification() {
        let id = ident(1);
        let mut c = chain(&id, 3);
        c[1].epoch = 99;
        assert!(matches!(
            replay(&c, &[]),
            Err(ApplyError::Lease(LeaseError::BadSignature))
        ));
    }

    #[test]
    fn an_empty_history_is_an_empty_set_not_an_error() {
        // A holder that leases nothing is a legitimate state -- it is how a
        // holder releases everything without disappearing.
        assert!(replay(&[], &[]).unwrap().is_empty());
    }
}

/// Constructors used only by tests in sibling modules.
///
/// Building a `LeaseSet` directly keeps the sweep tests from depending on
/// ML-DSA signing: replay is tested here, policy is tested there, and neither
/// test needs the other's machinery to fail for the right reason.
#[cfg(test)]
pub(crate) mod test_support {
    use super::LeaseSet;
    use nas_core::Addr;

    pub fn from_addrs(addrs: &[Addr]) -> LeaseSet {
        let mut s = LeaseSet::new();
        for a in addrs {
            s.addrs.insert(*a.as_bytes());
        }
        s
    }
}
