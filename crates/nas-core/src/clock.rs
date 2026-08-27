//! Time, injected rather than read from the world.
//!
//! Lease expiry and grace, sweep decisions, cooling-off windows and "a laptop
//! closed for thirty days" are all time-dependent, and all need to be tested
//! without waiting. Retrofitting this after M0 would touch every crate, so it
//! lands with the first one.
//!
//! # This is a *local* clock, not a trusted one
//!
//! SPECS §16.2: there is no trusted time source anywhere in this design. A
//! peer's clock is adversarial by assumption and a request's timestamp is signed
//! by a requester who may be compromised. Cooling-off is therefore enforced by
//! approver devices against their own clocks — this trait is how a device reads
//! *its own*, and nothing here should be mistaken for agreement between machines.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const fn secs(self) -> u64 {
        self.0
    }
    /// Saturating, because a clock that jumped backwards must not underflow
    /// into a colossal "elapsed" value that silently satisfies a cooling-off.
    pub const fn saturating_since(self, earlier: Timestamp) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
    pub const fn plus_secs(self, s: u64) -> Timestamp {
        Timestamp(self.0.saturating_add(s))
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }
}

/// A clock tests drive by hand. Cheap to clone; clones share one instant.
#[derive(Clone, Debug)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn at(secs: u64) -> Self {
        Self(Arc::new(AtomicU64::new(secs)))
    }
    pub fn advance_secs(&self, s: u64) {
        self.0.fetch_add(s, Ordering::SeqCst);
    }
    pub fn advance_days(&self, d: u64) {
        self.advance_secs(d * 86_400);
    }
    /// Move time backwards — for testing that nothing trusts monotonicity.
    pub fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advances_and_shares_state() {
        let c = TestClock::at(1000);
        let c2 = c.clone();
        c.advance_days(30);
        assert_eq!(c2.now(), Timestamp(1000 + 30 * 86_400));
    }

    #[test]
    fn elapsed_saturates_when_the_clock_goes_backwards() {
        // A backwards jump must not produce a huge elapsed value that would
        // silently satisfy a cooling-off window (SPECS §16.2).
        let c = TestClock::at(1000);
        let before = c.now();
        c.set(10);
        assert_eq!(c.now().saturating_since(before), 0);
    }

    #[test]
    fn system_clock_is_plausible() {
        // Later than 2020, so a broken epoch would be caught.
        assert!(SystemClock.now().secs() > 1_577_836_800);
    }
}
