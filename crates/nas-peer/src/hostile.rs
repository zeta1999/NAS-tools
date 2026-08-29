//! Deliberate misbehaviour, as a first-class configuration (PLAN step 10).
//!
//! # Why this is not a test double
//!
//! The obvious way to test a client against a bad peer is to write a mock that
//! misbehaves. The obvious way is wrong here, because the mock would not be the
//! code that runs in production: the real peer's parsing, ordering and
//! retention logic would never be the thing under attack, and a crafted record
//! that slipped past *the real checks* would go on slipping past them.
//!
//! So hostility is a flag on the real peer. Every behaviour below is a branch
//! inside the same function that serves honest requests, which means the honest
//! path and the attack path share their parsing and their bookkeeping, and a
//! defect in either is reachable from both.
//!
//! PLAN puts this in M1 rather than M2 deliberately: the peer's five plaintext
//! record formats freeze during M1 and are format-breaking to change afterwards
//! (SPECS §20). Adding hostility after they froze would mean they never felt
//! adversarial pressure while they were still cheap to fix.

/// Which lies this peer tells. All off is an honest peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hostility {
    /// Corrupt blob bytes on the way out. Caught by address verification
    /// (SPECS §3.4) — the client hashes what it received.
    pub tamper: bool,
    /// Serve an older slot head than the one it holds. Caught by the client's
    /// pin and the cap anchor (§5.3).
    pub rollback: bool,
    /// Claim not to have a blob it holds. **Not** detectable by cryptography:
    /// withholding is indistinguishable from having lost it, which is why the
    /// answer is leases and replication rather than a check.
    pub withhold: bool,
    /// Claim to already hold a blob it does not, so the client skips the
    /// upload — a silent deletion discovered at a future read. Caught by the
    /// proof-of-possession challenge (§4.5).
    pub dedup_lie: bool,
    /// Serve two different, internally consistent histories to two clients.
    /// Each walk verifies; only a witness from the other side reveals it (§5.3).
    ///
    /// A peer holds no writer key, so it cannot invent a divergent history. It
    /// forks by *keeping* a write an honest peer would have refused by
    /// compare-and-swap, and serving that branch to a different client. Every
    /// record on both branches is one a legitimate writer signed, which is
    /// exactly why neither client can tell from its own view.
    ///
    /// This flag was declared and read nowhere for the whole of M1 — parsed,
    /// described, included in `all`, unit-tested, and wired to nothing — while
    /// the module documentation claimed every mode was a live branch. A review
    /// found it. The fork-detection machinery it is supposed to attack had no
    /// adversary for its entire existence.
    pub fork: bool,
    /// Sweep blobs the retention set protects (§16). Caught by a client that
    /// re-checks the retention superset, and by the blob simply being gone.
    pub ignore_retention: bool,
    /// Accept witnesses and relay none of them (§5.3, §5.4). A forking peer
    /// that also withholds witnesses is undetectable *from that peer alone*:
    /// SPECS §5.4 and the must-fail `ForkAlwaysDetected` check say so. It is
    /// caught only when a second relay (a witness-only node) exists that the
    /// clients also talk to.
    pub withhold_witnesses: bool,
}

impl Hostility {
    pub const HONEST: Self = Self {
        tamper: false,
        rollback: false,
        withhold: false,
        dedup_lie: false,
        fork: false,
        ignore_retention: false,
        withhold_witnesses: false,
    };

    pub fn is_honest(&self) -> bool {
        *self == Self::HONEST
    }

    /// Parse `tamper,rollback,withhold` — the `--hostile` argument.
    ///
    /// An unknown name is an **error**, not something to ignore. A typo that
    /// silently produced an honest peer would make a hostility test pass while
    /// testing nothing, which is the failure mode this whole module exists to
    /// avoid.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut h = Self::HONEST;
        for name in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match name {
                "tamper" => h.tamper = true,
                "rollback" => h.rollback = true,
                "withhold" => h.withhold = true,
                "dedup-lie" => h.dedup_lie = true,
                "fork" => h.fork = true,
                "ignore-retention" => h.ignore_retention = true,
                "withhold-witnesses" => h.withhold_witnesses = true,
                "all" => {
                    h = Self {
                        tamper: true,
                        rollback: true,
                        withhold: true,
                        dedup_lie: true,
                        fork: true,
                        ignore_retention: true,
                        withhold_witnesses: true,
                    }
                }
                other => {
                    return Err(format!(
                        "unknown hostility {other:?}; expected one of \
                         tamper, rollback, withhold, dedup-lie, fork, ignore-retention, \
                         withhold-witnesses, all"
                    ))
                }
            }
        }
        Ok(h)
    }

    /// Human-readable list of what is enabled.
    pub fn describe(&self) -> String {
        if self.is_honest() {
            return "honest".to_string();
        }
        let mut v = Vec::new();
        for (on, name) in [
            (self.tamper, "tamper"),
            (self.rollback, "rollback"),
            (self.withhold, "withhold"),
            (self.dedup_lie, "dedup-lie"),
            (self.fork, "fork"),
            (self.ignore_retention, "ignore-retention"),
            (self.withhold_witnesses, "withhold-witnesses"),
        ] {
            if on {
                v.push(name);
            }
        }
        v.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_peer_is_honest() {
        assert!(Hostility::default().is_honest());
        assert_eq!(Hostility::parse("").unwrap(), Hostility::HONEST);
    }

    #[test]
    fn each_name_sets_exactly_its_own_flag() {
        assert_eq!(Hostility::parse("tamper").unwrap().describe(), "tamper");
        assert_eq!(
            Hostility::parse("dedup-lie").unwrap().describe(),
            "dedup-lie"
        );
        assert_eq!(
            Hostility::parse("rollback,withhold").unwrap().describe(),
            "rollback,withhold"
        );
    }

    #[test]
    fn all_enables_everything() {
        let h = Hostility::parse("all").unwrap();
        assert!(
            h.tamper
                && h.rollback
                && h.withhold
                && h.dedup_lie
                && h.fork
                && h.ignore_retention
                && h.withhold_witnesses
        );
    }

    #[test]
    fn an_unknown_name_is_an_error_not_a_silent_honest_peer() {
        // A typo producing an honest peer would make a hostility test pass
        // while testing nothing at all.
        assert!(Hostility::parse("tampr").is_err());
        assert!(Hostility::parse("tamper,nonsense").is_err());
    }

    #[test]
    fn describe_round_trips_through_parse() {
        for spec in [
            "tamper",
            "fork",
            "tamper,fork,withhold",
            "fork,withhold-witnesses",
            "all",
        ] {
            let h = Hostility::parse(spec).unwrap();
            assert_eq!(Hostility::parse(&h.describe()).unwrap(), h);
        }
    }
}
