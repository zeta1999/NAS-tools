//! On-disk and on-peer format discriminants.
//!
//! Every stored record carries these. They exist because the alternative —
//! inferring a format from its contents — is how migrations become impossible,
//! and because SPECS §20 lists the peer's five plaintext record types as
//! format-breaking to change once written.

/// Manifest format version. Bump on any layout change.
pub const MANIFEST_VERSION: u16 = 1;

/// How chunk keys are derived (SPECS §20.3).
///
/// Recorded per manifest so the choice is revisitable without a migration.
/// Manifests store `ck` per chunk regardless — a reader has no plaintext and
/// cannot derive it — which is exactly why the *stored* format is agnostic and
/// only the write path and capability format differ.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyScheme {
    /// `ck = BLAKE3::keyed_hash(CS, plaintext)`. Stateless; costs a
    /// confirmation oracle gated on `CS`.
    Convergent = 0,
    /// Random per-chunk keys plus a client-side encrypted index. No oracle;
    /// costs an index to sync, merge and recover.
    IndexedRandom = 1,
    /// No chunk keys at all: `transit-only` stores plaintext at rest (SPECS
    /// §2.2.3), so there is nothing to derive.
    ///
    /// A distinct variant rather than a zeroed `ck` under `Convergent`, because
    /// a reader must be able to tell "this chunk is not encrypted" from "this
    /// chunk's key is all zeros" — and the second is a plausible corruption.
    Plaintext = 2,
}

/// Chunk padding profile (SPECS §4.2.1). Defaults to `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum PaddingProfile {
    /// No padding. Full chunk-length fingerprint, zero overhead.
    #[default]
    None = 0,
    /// Pad to a size-class ladder. Coarsens the fingerprint; costs storage.
    Classes = 1,
    /// Fixed-size chunks, no CDC. Removes the fingerprint entirely at the cost
    /// of shift-resistant dedup — one inserted byte changes every later chunk.
    Fixed = 2,
}

/// Namespace confidentiality mode (SPECS §2.2).
///
/// Fixed at creation and immutable: changing it would mean rewriting every
/// blob. What varies is confidentiality alone — integrity, authenticity,
/// rollback detection, leases and witnesses are identical in all three.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Mode {
    /// Ciphertext at rest under a high-entropy vault key. No recovery path.
    E2ee = 0,
    /// Ciphertext at rest under an Argon2id-wrapped random DEK. Recoverable
    /// from memory; exposed to offline brute force by whoever holds the wrap.
    Passphrase = 1,
    /// Plaintext at rest. The peer can read everything, which is what makes
    /// server-side browsing possible and read ACLs a policy rather than maths.
    TransitOnly = 2,
}

impl Mode {
    /// Whether the peer stores plaintext. Used by the "no plaintext on the
    /// peer" test, which asserts the **opposite** for `TransitOnly` (SPECS
    /// §12.2) — a single test with an inverted expectation, rather than a test
    /// that quietly skips the mode it cannot handle.
    pub const fn peer_reads_plaintext(self) -> bool {
        matches!(self, Self::TransitOnly)
    }

    /// Whether the peer can enforce a *read* ACL (SPECS §2.2).
    ///
    /// In encrypted modes it cannot: possession of a capability is the only
    /// access control, and it is mathematics rather than policy.
    pub const fn peer_can_enforce_read_acl(self) -> bool {
        matches!(self, Self::TransitOnly)
    }

    /// Whether the peer can enforce *semantic* append-only — "no existing key
    /// was removed" (SPECS §2.2).
    ///
    /// It cannot in encrypted modes: a slot update is an opaque root address,
    /// so "added a key" and "deleted every key" are indistinguishable. That is
    /// why §16's ransomware defence rests on retention sets rather than on this.
    pub const fn peer_can_enforce_append_only(self) -> bool {
        matches!(self, Self::TransitOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_scheme_says_whether_there_is_a_key_at_all() {
        // Plaintext must be its own variant: a zeroed ck under Convergent is a
        // plausible corruption, and a reader has to tell the two apart.
        assert_ne!(KeyScheme::Plaintext as u8, KeyScheme::Convergent as u8);
        assert_ne!(KeyScheme::Plaintext as u8, KeyScheme::IndexedRandom as u8);
    }

    #[test]
    fn padding_defaults_to_none() {
        // SPECS §4.2.1: the 20-35% premium is not worth a low-probability
        // targeted attack, so opting in must be deliberate.
        assert_eq!(PaddingProfile::default(), PaddingProfile::None);
    }

    #[test]
    fn only_transit_only_lets_the_peer_read_or_enforce() {
        for m in [Mode::E2ee, Mode::Passphrase] {
            assert!(!m.peer_reads_plaintext());
            assert!(!m.peer_can_enforce_read_acl());
            assert!(
                !m.peer_can_enforce_append_only(),
                "{m:?}: a slot update is an opaque root address"
            );
        }
        assert!(Mode::TransitOnly.peer_reads_plaintext());
        assert!(Mode::TransitOnly.peer_can_enforce_read_acl());
        assert!(Mode::TransitOnly.peer_can_enforce_append_only());
    }
}
