//! The sweep decision (SPECS §6.2, §6.3, §6.4).
//!
//! This is the only code in the system that deletes a user's data, so every
//! guard the specification names is here and each one is a separate, named
//! reason rather than a condition folded into one boolean.
//!
//! The ordering of the guards matters and is not arbitrary: a blob is kept if
//! **any** rule says keep, and the reasons are checked strongest-first so the
//! explanation a user gets names the strongest reason rather than the first one
//! that happened to match.
//!
//! # Nothing here trusts a clock it did not read locally
//!
//! `now` is supplied by the caller and compared with [`Timestamp::saturating_since`],
//! so a clock that jumps backwards produces an elapsed time of zero rather than
//! an enormous one. An enormous elapsed time is precisely what would make
//! everything look expired — the shape of a bug that deletes a NAS.

use crate::set::LeaseSet;
use nas_core::{Addr, Timestamp};
use std::collections::{BTreeMap, BTreeSet};

pub const DAY: u64 = 86_400;

/// GC policy (SPECS §6.2–§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcPolicy {
    /// Blobs younger than this are immune regardless of leases (§6.2).
    pub grace: u64,
    /// How long a holder may be absent before its leases stop protecting (§6.3).
    pub lease_expiry: u64,
    /// Per-holder ceiling on leased bytes (§6.4).
    pub max_leased_bytes: u64,
}

impl Default for GcPolicy {
    /// SPECS defaults: 24 h grace, 90 day expiry.
    fn default() -> Self {
        Self {
            grace: DAY,
            lease_expiry: 90 * DAY,
            max_leased_bytes: u64::MAX,
        }
    }
}

/// What the peer knows about one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobInfo {
    pub addr: Addr,
    pub size: u64,
    pub uploaded_at: Timestamp,
}

/// What the peer knows about one holder.
#[derive(Debug, Clone)]
pub struct Holder {
    pub id: [u8; 32],
    pub set: LeaseSet,
    /// When this holder last published a lease record.
    pub last_seen: Timestamp,
}

impl Holder {
    /// Active, expiring (past expiry but inside the grace window), or expired.
    pub fn status(&self, now: Timestamp, p: &GcPolicy) -> HolderStatus {
        let idle = now.saturating_since(self.last_seen);
        if idle <= p.lease_expiry {
            HolderStatus::Active
        } else if idle <= p.lease_expiry.saturating_add(p.grace) {
            HolderStatus::Expiring
        } else {
            HolderStatus::Expired
        }
    }

    pub fn leased_bytes(&self, blobs: &BTreeMap<[u8; 32], BlobInfo>) -> u64 {
        self.set
            .iter()
            .filter_map(|a| blobs.get(a.as_bytes()))
            .map(|b| b.size)
            .fold(0u64, |acc, n| acc.saturating_add(n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderStatus {
    Active,
    /// Past expiry but still protected: the peer must not sweep until
    /// `expiry + grace` (§6.3), and this is that window.
    Expiring,
    Expired,
}

/// Why a blob is being kept. Strongest reason first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// In the repository's retention floor. Never swept without an
    /// authenticated `forget` (§6.3) — not even for an expired holder, and not
    /// even when nothing leases it.
    RetentionFloor,
    /// Uploaded within the grace period. Immune **regardless of leases** (§6.2):
    /// this closes the race where a blob written mid-epoch has no lease yet,
    /// and the case where a client crashes between upload and lease publication.
    YoungBlob,
    /// Leased by a holder that is still active.
    Leased,
    /// Leased only by holders inside the post-expiry grace window.
    LeasedByExpiring,
}

/// The outcome of planning a sweep. Nothing is deleted by producing one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepPlan {
    /// Blobs that may be deleted.
    pub delete: Vec<Addr>,
    /// Blobs kept, with the reason.
    pub keep: Vec<(Addr, Keep)>,
    /// Per holder, the blobs it leases that are in `delete`.
    ///
    /// SPECS §6.3's warn-before-sweep: a returning client is told what *would*
    /// have gone, so silent loss is not the failure mode.
    pub warnings: BTreeMap<[u8; 32], Vec<Addr>>,
    /// Holders over `max_leased_bytes` (§6.4). Reported, never enforced by
    /// deleting: a quota breach is a pairing problem, and resolving it by
    /// destroying data would turn an accounting dispute into data loss.
    pub over_quota: BTreeMap<[u8; 32], u64>,
}

/// Decide what may be deleted. **Pure**: it reads state and returns a plan.
///
/// Separating the decision from the deletion is deliberate. It makes the policy
/// testable without a filesystem, and it means a caller can show the plan to a
/// human before acting on it — which for the only data-destroying operation in
/// the system is the difference between a bug and an incident.
pub fn plan_sweep(
    blobs: &[BlobInfo],
    holders: &[Holder],
    retention_floor: &BTreeSet<[u8; 32]>,
    policy: &GcPolicy,
    now: Timestamp,
) -> SweepPlan {
    let index: BTreeMap<[u8; 32], BlobInfo> =
        blobs.iter().map(|b| (*b.addr.as_bytes(), *b)).collect();

    let mut plan = SweepPlan::default();

    for (id, bytes) in holders
        .iter()
        .map(|h| (h.id, h.leased_bytes(&index)))
        .filter(|(_, b)| *b > policy.max_leased_bytes)
    {
        plan.over_quota.insert(id, bytes);
    }

    let status: Vec<HolderStatus> = holders.iter().map(|h| h.status(now, policy)).collect();

    for b in blobs {
        let key = b.addr.as_bytes();

        if retention_floor.contains(key) {
            plan.keep.push((b.addr, Keep::RetentionFloor));
            continue;
        }
        if now.saturating_since(b.uploaded_at) < policy.grace {
            plan.keep.push((b.addr, Keep::YoungBlob));
            continue;
        }

        let mut active = false;
        let mut expiring = false;
        for (h, st) in holders.iter().zip(&status) {
            if !h.set.contains(&b.addr) {
                continue;
            }
            match st {
                HolderStatus::Active => active = true,
                HolderStatus::Expiring => expiring = true,
                HolderStatus::Expired => {}
            }
        }

        if active {
            plan.keep.push((b.addr, Keep::Leased));
        } else if expiring {
            plan.keep.push((b.addr, Keep::LeasedByExpiring));
        } else {
            plan.delete.push(b.addr);
            // Tell every holder that leased it, whatever its status: the point
            // is that a client learns what it lost, and the holder whose lease
            // lapsed is exactly the one that needs telling.
            for h in holders.iter().filter(|h| h.set.contains(&b.addr)) {
                plan.warnings.entry(h.id).or_default().push(b.addr);
            }
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Addr {
        Addr::of_ciphertext(&[n])
    }

    fn blob(n: u8, uploaded: u64) -> BlobInfo {
        BlobInfo {
            addr: addr(n),
            size: 1000,
            uploaded_at: Timestamp(uploaded),
        }
    }

    /// Build the set directly: replay is tested in `set.rs`, and going through
    /// signing here would make every policy test depend on ML-DSA — so a
    /// signing regression would fail these too, for the wrong reason.
    fn holder(id: u8, addrs: &[u8], last_seen: u64) -> Holder {
        let list: Vec<Addr> = addrs.iter().copied().map(addr).collect();
        Holder {
            id: [id; 32],
            set: crate::set::test_support::from_addrs(&list),
            last_seen: Timestamp(last_seen),
        }
    }

    const NOW: u64 = 1_000 * DAY;

    fn now() -> Timestamp {
        Timestamp(NOW)
    }

    #[test]
    fn an_unleased_old_blob_is_deleted() {
        let p = GcPolicy::default();
        let plan = plan_sweep(&[blob(1, NOW - 10 * DAY)], &[], &BTreeSet::new(), &p, now());
        assert_eq!(plan.delete, vec![addr(1)]);
    }

    #[test]
    fn a_young_blob_is_immune_even_with_no_lease() {
        // SPECS §6.2: closes the race where a blob written mid-epoch has no
        // lease yet, and the crash between upload and lease publication.
        let p = GcPolicy::default();
        let plan = plan_sweep(&[blob(1, NOW - 3600)], &[], &BTreeSet::new(), &p, now());
        assert!(plan.delete.is_empty());
        assert_eq!(plan.keep, vec![(addr(1), Keep::YoungBlob)]);
    }

    #[test]
    fn a_leased_blob_is_kept() {
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW - DAY);
        let plan = plan_sweep(
            &[blob(1, NOW - 10 * DAY)],
            &[h],
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert!(plan.delete.is_empty());
        assert_eq!(plan.keep, vec![(addr(1), Keep::Leased)]);
    }

    #[test]
    fn a_holder_absent_for_a_month_still_protects_its_set() {
        // The median NAS case: a laptop closed for weeks. Expiry is 90 days
        // precisely so a fortnight of bad connectivity is uneventful (§6.3).
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW - 30 * DAY);
        let plan = plan_sweep(
            &[blob(1, NOW - 60 * DAY)],
            &[h],
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn the_post_expiry_grace_window_still_protects() {
        // SPECS §6.3: the peer must not sweep until expiry + grace.
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW - (90 * DAY + DAY / 2));
        assert_eq!(h.status(now(), &p), HolderStatus::Expiring);
        let plan = plan_sweep(
            &[blob(1, NOW - 200 * DAY)],
            &[h],
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert!(plan.delete.is_empty());
        assert_eq!(plan.keep, vec![(addr(1), Keep::LeasedByExpiring)]);
    }

    #[test]
    fn past_expiry_plus_grace_the_lease_stops_protecting() {
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW - (91 * DAY + 1));
        assert_eq!(h.status(now(), &p), HolderStatus::Expired);
        let plan = plan_sweep(
            &[blob(1, NOW - 200 * DAY)],
            &[h],
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert_eq!(plan.delete, vec![addr(1)]);
    }

    #[test]
    fn one_active_holder_protects_against_many_expired_ones() {
        let p = GcPolicy::default();
        let holders = vec![
            holder(1, &[1], NOW - 200 * DAY),
            holder(2, &[1], NOW - 200 * DAY),
            holder(3, &[1], NOW - DAY),
        ];
        let plan = plan_sweep(
            &[blob(1, NOW - 100 * DAY)],
            &holders,
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn the_retention_floor_survives_everything() {
        // Not leased, not young, every holder long expired -- and still kept.
        // §6.3: never swept without an authenticated forget.
        let p = GcPolicy::default();
        let floor = BTreeSet::from([*addr(1).as_bytes()]);
        let h = holder(1, &[], NOW - 500 * DAY);
        let plan = plan_sweep(&[blob(1, NOW - 500 * DAY)], &[h], &floor, &p, now());
        assert!(plan.delete.is_empty());
        assert_eq!(plan.keep, vec![(addr(1), Keep::RetentionFloor)]);
    }

    #[test]
    fn a_deleted_blob_produces_a_warning_for_every_holder_that_leased_it() {
        // SPECS §6.3's warn-before-sweep, so silent loss is not the failure mode.
        let p = GcPolicy::default();
        let holders = vec![
            holder(1, &[1, 2], NOW - 200 * DAY),
            holder(2, &[1], NOW - 200 * DAY),
        ];
        let blobs = vec![blob(1, NOW - 300 * DAY), blob(2, NOW - 300 * DAY)];
        let plan = plan_sweep(&blobs, &holders, &BTreeSet::new(), &p, now());
        assert_eq!(plan.delete.len(), 2);
        assert_eq!(plan.warnings[&[1u8; 32]].len(), 2);
        assert_eq!(plan.warnings[&[2u8; 32]], vec![addr(1)]);
    }

    #[test]
    fn a_backwards_clock_does_not_expire_everything() {
        // The bug shape that deletes a NAS: a clock that jumps backwards makes
        // `now - last_seen` enormous, so every holder looks long expired.
        // saturating_since gives zero instead.
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW + 500 * DAY); // last seen "in the future"
        assert_eq!(h.status(now(), &p), HolderStatus::Active);
        let plan = plan_sweep(
            &[blob(1, NOW + 500 * DAY)],
            &[h],
            &BTreeSet::new(),
            &p,
            now(),
        );
        assert!(plan.delete.is_empty(), "a backwards clock swept live data");
    }

    #[test]
    fn quota_breaches_are_reported_not_enforced_by_deleting() {
        // §6.4: a quota breach is a pairing problem. Resolving it by destroying
        // data turns an accounting dispute into data loss.
        let p = GcPolicy {
            max_leased_bytes: 1500,
            ..GcPolicy::default()
        };
        let h = holder(1, &[1, 2, 3], NOW - DAY);
        let blobs: Vec<BlobInfo> = (1..=3).map(|n| blob(n, NOW - 100 * DAY)).collect();
        let plan = plan_sweep(&blobs, &[h], &BTreeSet::new(), &p, now());
        assert_eq!(plan.over_quota[&[1u8; 32]], 3000);
        assert!(plan.delete.is_empty(), "quota enforcement deleted data");
    }

    #[test]
    fn planning_is_pure() {
        // Producing a plan must not change anything: the caller shows it to a
        // human, or acts on it, or discards it.
        let p = GcPolicy::default();
        let h = holder(1, &[1], NOW - DAY);
        let blobs = vec![blob(1, NOW - 100 * DAY), blob(2, NOW - 100 * DAY)];
        let floor = BTreeSet::new();
        let a = plan_sweep(&blobs, std::slice::from_ref(&h), &floor, &p, now());
        let b = plan_sweep(&blobs, std::slice::from_ref(&h), &floor, &p, now());
        assert_eq!(a, b);
    }

    #[test]
    fn the_strongest_reason_is_the_one_reported() {
        // A blob that is young AND in the floor reports the floor, because
        // that is the reason that will still hold tomorrow.
        let p = GcPolicy::default();
        let floor = BTreeSet::from([*addr(1).as_bytes()]);
        let plan = plan_sweep(&[blob(1, NOW - 60)], &[], &floor, &p, now());
        assert_eq!(plan.keep, vec![(addr(1), Keep::RetentionFloor)]);
    }
}
