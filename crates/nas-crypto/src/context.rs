//! Domain-separation contexts (SPECS §3.1).
//!
//! Every signed object and every derived key names its purpose. Without that, a
//! signature produced for one purpose can be presented as a signature for
//! another, and two keys derived from one secret for different jobs can collide.
//!
//! SPECS §3.1 carries a normative list and one rule: **any signed object added
//! later must land in this list in the same commit that introduces it.**
//! Revision 4 of the spec added six signed objects without contexts, which is
//! precisely the mistake the list exists to prevent — so the list is code here,
//! not prose, and `SigContext` is an enum so a new variant cannot be forgotten.

/// The twelve signing contexts of SPECS §3.1.
///
/// An enum rather than loose constants: adding a signed object means adding a
/// variant, and every `match` over it then fails to compile until the new case
/// is handled.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SigContext {
    Slot,
    Lease,
    Checkpoint,
    Roster,
    Cap,
    Witness,
    Retention,
    DeleteRequest,
    DeleteApproval,
    DeleteExecution,
    Wrap,
    MirrorPublish,
    /// SPECS §5.1: single-writer ownership handoff, signed by the *outgoing*
    /// writer. A distinct context so a handoff can never be replayed as, or
    /// mistaken for, any other statement that writer signs.
    SlotHandoff,
}

impl SigContext {
    /// The exact bytes prefixed to a message before signing.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Slot => b"nas-tools/sig/slot/v1",
            Self::Lease => b"nas-tools/sig/lease/v1",
            Self::Checkpoint => b"nas-tools/sig/checkpoint/v1",
            Self::Roster => b"nas-tools/sig/roster/v1",
            Self::Cap => b"nas-tools/sig/cap/v1",
            Self::Witness => b"nas-tools/sig/witness/v1",
            Self::Retention => b"nas-tools/sig/retention/v1",
            Self::DeleteRequest => b"nas-tools/sig/delete-request/v1",
            Self::DeleteApproval => b"nas-tools/sig/delete-approval/v1",
            Self::DeleteExecution => b"nas-tools/sig/delete-execution/v1",
            Self::Wrap => b"nas-tools/sig/wrap/v1",
            Self::MirrorPublish => b"nas-tools/sig/mirror-publish/v1",
            Self::SlotHandoff => b"nas-tools/sig/slot-handoff/v1",
        }
    }

    /// Every variant, so tests can assert the list is complete and distinct.
    pub const ALL: [SigContext; 13] = [
        Self::Slot,
        Self::Lease,
        Self::Checkpoint,
        Self::Roster,
        Self::Cap,
        Self::Witness,
        Self::Retention,
        Self::DeleteRequest,
        Self::DeleteApproval,
        Self::DeleteExecution,
        Self::Wrap,
        Self::MirrorPublish,
        Self::SlotHandoff,
    ];
}

// ── Key-derivation contexts ────────────────────────────────────────────

/// Nonce derivation for content-derived chunk keys (SPECS §3.2).
pub const NONCE_CHUNK: &[u8] = b"nas-tools/nonce/chunk/v1";
/// Directory secret chain (SPECS §3.1).
pub const DIR: &str = "nas-tools/dir/v1";
/// Directory manifest key (SPECS §3.1).
pub const DIR_MANIFEST: &str = "nas-tools/dir/manifest/v1";
/// Root **manifest** key, derived per version (SPECS §3.1, `rk_v`).
///
/// Not to be confused with [`NS_ROOT`], whose string differs by one path
/// segment. `NS_ROOT` produces a namespace's long-lived root *secret* from a
/// passphrase-mode DEK; this one produces the key that encrypts one *version*
/// of the root manifest, and the caller must mix in `le64(seq)`. Reaching for
/// the wrong one would encrypt every root version under a single key, which is
/// exactly the "may it see two plaintexts" hazard §3.1 exists to prevent.
///
/// Unused until the root slot lands in M1; declared here so the next person to
/// need it does not reach for `NS_ROOT` instead.
pub const ROOT_MANIFEST: &str = "nas-tools/root/v1";

/// Namespace root secret from a passphrase-mode DEK (SPECS §2.2.2).
pub const NS_ROOT: &str = "nas-tools/ns/root/v1";
/// Per-namespace convergence secret from a DEK (SPECS §2.2.2).
pub const NS_CONVERGENCE: &str = "nas-tools/ns/convergence/v1";
/// Slot signing seed from a DEK (SPECS §2.2.2).
pub const NS_SLOT: &str = "nas-tools/ns/slot/v1";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_context_is_present_and_distinct() {
        // SPECS §3.1 names twelve; `SlotHandoff` is the thirteenth, added with
        // §5.1's handoff record. A collision here would silently let one
        // object's signature be accepted for another.
        assert_eq!(SigContext::ALL.len(), 13);
        let set: HashSet<&[u8]> = SigContext::ALL.iter().map(|c| c.as_bytes()).collect();
        assert_eq!(set.len(), 13, "signing contexts must be pairwise distinct");
    }

    /// Every KDF context string in this module.
    const KDF_CONTEXTS: [&str; 6] = [
        DIR,
        DIR_MANIFEST,
        ROOT_MANIFEST,
        NS_ROOT,
        NS_CONVERGENCE,
        NS_SLOT,
    ];

    #[test]
    fn kdf_contexts_are_distinct_and_prefix_free() {
        // There was a test for the twelve signature contexts and none for
        // these, even though ROOT_MANIFEST and NS_ROOT differ by a single path
        // segment and are the pair most likely to be confused.
        let set: HashSet<&str> = KDF_CONTEXTS.iter().copied().collect();
        assert_eq!(set.len(), KDF_CONTEXTS.len(), "two KDF contexts collide");
        for a in KDF_CONTEXTS {
            for b in KDF_CONTEXTS {
                if a != b {
                    assert!(!b.starts_with(a), "{a:?} is a prefix of {b:?}");
                }
            }
        }
        // And they must not collide with the nonce context, which is bytes.
        assert!(!KDF_CONTEXTS.iter().any(|c| c.as_bytes() == NONCE_CHUNK));
    }

    #[test]
    fn no_context_is_a_prefix_of_another() {
        // Prefix-freedom matters because contexts are prepended to messages:
        // if one were a prefix of another, a crafted message body could span
        // the boundary and be read under the wrong context.
        for a in SigContext::ALL {
            for b in SigContext::ALL {
                if a != b {
                    assert!(
                        !b.as_bytes().starts_with(a.as_bytes()),
                        "{:?} is a prefix of {:?}",
                        a,
                        b
                    );
                }
            }
        }
    }
}
