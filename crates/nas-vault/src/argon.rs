//! Argon2id parameters for passphrase mode (SPECS §2.2.2).
//!
//! ```text
//! KEK = derive_key_argon2(passphrase, salt, m ≥ 256 MiB, t ≥ 3, p = 1)
//! ```
//!
//! # Why a policy rather than a constant
//!
//! The floor has to be enforced somewhere, and putting it in the constructor
//! would make every test that touches a wrap record spend 256 MiB and a second
//! of CPU — which in practice means the tests get written against a weakened
//! constructor, and then the weakened constructor is one autocomplete away from
//! production.
//!
//! So the floor is a [`WrapPolicy`] passed explicitly at the call site.
//! Production passes [`WrapPolicy::SPEC`]; tests pass [`WrapPolicy::FAST`] and
//! it is visible in the diff that they did. A production caller reaching for
//! `FAST` is a reviewable line rather than an invisible default.
//!
//! # `sequential_stretch` must not be used here
//!
//! SPECS §2.2.2 is explicit: it is not memory-hard, and a passphrase is
//! precisely the low-entropy input it is unsuited to. This module only ever
//! calls `derive_key_argon2`.

use nas_core::{decode_fields, encode_fields, DecodeError};

/// One mebibyte, in the kibibytes Argon2 counts in.
pub const MIB: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// Below the floor the policy requires.
    TooWeak {
        field: &'static str,
        got: u32,
        min: u32,
    },
    /// Above the ceiling the policy allows.
    ///
    /// The mirror of [`Self::TooWeak`], and it exists because the record these
    /// parameters come from is stored **on the peer** (SPECS §2.2.2). A floor
    /// stops a hostile peer weakening the KDF; without a ceiling the same peer
    /// hands a recovering client `memory_kib = u32::MAX` and it tries to
    /// allocate four terabytes. That is the four-byte denial of service the
    /// wire decoder is careful about, one layer down — and it costs the
    /// attacker one field of a record it already controls.
    TooStrong {
        field: &'static str,
        got: u32,
        max: u32,
    },
    /// SPECS §2.2.2 fixes `p = 1`. A different lane count is a different KDF
    /// and would silently produce a different key from the same passphrase.
    WrongParallelism {
        got: u32,
    },
    Decode(DecodeError),
    BadWidth {
        got: usize,
    },
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooStrong { field, got, max } => {
                write!(
                    f,
                    "stored {field} is {got}, above the {max} this device will attempt; a \
                     peer-supplied record does not get to choose how much memory recovery uses"
                )
            }
            Self::TooWeak { field, got, min } => {
                write!(
                    f,
                    "argon2 {field} is {got}, below the required minimum {min}"
                )
            }
            Self::WrongParallelism { got } => {
                write!(f, "argon2 parallelism is {got}, SPECS §2.2.2 fixes it at 1")
            }
            Self::Decode(e) => write!(f, "argon2 params encoding: {e:?}"),
            Self::BadWidth { got } => write!(f, "argon2 params field is {got} B, want 4"),
        }
    }
}
impl std::error::Error for ParamError {}
impl From<DecodeError> for ParamError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// Argon2id parameters, as stored in a wrap record.
///
/// Stored rather than assumed, because a client recovering years later must
/// reproduce the *original* derivation. Hard-coding today's parameters would
/// make raising them a data-loss event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// SPECS §2.2.2: m = 256 MiB, t = 3, p = 1.
    pub const SPEC: Self = Self {
        memory_kib: 256 * MIB,
        iterations: 3,
        parallelism: 1,
    };

    /// Deliberately weak, for tests only. Named so it cannot be mistaken.
    pub const WEAK_FOR_TESTS: Self = Self {
        memory_kib: 8 * MIB,
        iterations: 1,
        parallelism: 1,
    };

    pub fn check(&self, policy: &WrapPolicy) -> Result<(), ParamError> {
        if self.parallelism != 1 {
            return Err(ParamError::WrongParallelism {
                got: self.parallelism,
            });
        }
        if self.memory_kib < policy.min_memory_kib {
            return Err(ParamError::TooWeak {
                field: "memory_kib",
                got: self.memory_kib,
                min: policy.min_memory_kib,
            });
        }
        if self.iterations < policy.min_iterations {
            return Err(ParamError::TooWeak {
                field: "iterations",
                got: self.iterations,
                min: policy.min_iterations,
            });
        }
        // Both directions, and the ceiling is the one a hostile peer reaches
        // for: it holds the record, and an unbounded `memory_kib` turns a
        // recovery into an allocation the device cannot survive.
        if self.memory_kib > policy.max_memory_kib {
            return Err(ParamError::TooStrong {
                field: "memory_kib",
                got: self.memory_kib,
                max: policy.max_memory_kib,
            });
        }
        if self.iterations > policy.max_iterations {
            return Err(ParamError::TooStrong {
                field: "iterations",
                got: self.iterations,
                max: policy.max_iterations,
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_fields(&[
            &self.memory_kib.to_le_bytes(),
            &self.iterations.to_le_bytes(),
            &self.parallelism.to_le_bytes(),
        ])
        .expect("fixed-width params always encode")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ParamError> {
        let f = decode_fields(bytes)?;
        if f.len() != 3 {
            return Err(ParamError::BadWidth { got: f.len() });
        }
        let g = |b: &[u8]| -> Result<u32, ParamError> {
            b.try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| ParamError::BadWidth { got: b.len() })
        };
        Ok(Self {
            memory_kib: g(f[0])?,
            iterations: g(f[1])?,
            parallelism: g(f[2])?,
        })
    }

    /// Derive the key-encryption key from a passphrase.
    pub fn derive(&self, passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], ParamError> {
        secure_memory::derive_key_argon2(passphrase, salt, self.memory_kib, self.iterations)
            .map_err(|_| ParamError::TooWeak {
                field: "memory_kib",
                got: self.memory_kib,
                min: 8,
            })
    }
}

/// The floor a caller demands of stored parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapPolicy {
    pub min_memory_kib: u32,
    pub min_iterations: u32,
    /// The most this device will attempt on a **peer-supplied** record.
    ///
    /// Not a statement about what is cryptographically enough — that is the
    /// floor's job — but about what a party we distrust may make us spend. A
    /// deployment that genuinely wants more must say so, which is a visible
    /// line in a diff.
    ///
    /// **It bounds the attack, it does not remove it.** The default ceiling is
    /// 4 GiB, chosen to leave room above the floor for a deployment that has
    /// hardened its own parameters — and a device with less memory than that
    /// can still be pushed into an out-of-memory kill by a peer-supplied
    /// record. This library cannot know how much memory the device has, so a
    /// constrained one should lower this rather than assume the default is
    /// safe for it. (The fuzz target hit exactly that: honouring the shipped
    /// ceiling under a 2 GiB limit produced an OOM.)
    pub max_memory_kib: u32,
    pub max_iterations: u32,
}

impl WrapPolicy {
    /// SPECS §2.2.2's floor: m ≥ 256 MiB, t ≥ 3.
    pub const SPEC: Self = Self {
        min_memory_kib: 256 * MIB,
        min_iterations: 3,
        // Sixteen times the floor, and twenty-one times it. Generous against
        // any real configuration and still bounded: the point is that a
        // hostile record cannot cost orders of magnitude more than an honest
        // one, not that these are the largest sensible parameters.
        max_memory_kib: 4096 * MIB,
        max_iterations: 64,
    };
    /// For tests. Using this in production is a visible line in a diff.
    pub const FAST: Self = Self {
        min_memory_kib: 8 * MIB,
        min_iterations: 1,
        max_memory_kib: 4096 * MIB,
        max_iterations: 64,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spec_policy_matches_the_specification() {
        // If §2.2.2's floor is ever edited, this is the test that notices.
        assert_eq!(WrapPolicy::SPEC.min_memory_kib, 256 * 1024);
        assert_eq!(WrapPolicy::SPEC.min_iterations, 3);
        assert_eq!(Argon2Params::SPEC.memory_kib, 256 * 1024);
        assert_eq!(Argon2Params::SPEC.iterations, 3);
        assert_eq!(Argon2Params::SPEC.parallelism, 1);
        Argon2Params::SPEC.check(&WrapPolicy::SPEC).unwrap();
    }

    #[test]
    fn absurdly_strong_stored_parameters_are_refused_too() {
        // The wrap record is stored ON THE PEER (SPECS §2.2.2), so the peer
        // chooses these numbers. A floor alone stops it weakening the KDF and
        // does nothing about the other direction: `memory_kib = u32::MAX` is
        // four terabytes, and a recovering client that honoured it would be
        // denied service by one field of a record the adversary already holds.
        let bomb = Argon2Params {
            memory_kib: u32::MAX,
            iterations: 3,
            parallelism: 1,
        };
        assert!(matches!(
            bomb.check(&WrapPolicy::SPEC),
            Err(ParamError::TooStrong {
                field: "memory_kib",
                ..
            })
        ));

        // Time is linear in `t`, so an unbounded iteration count is the same
        // attack with a different field.
        let slow = Argon2Params {
            memory_kib: 256 * MIB,
            iterations: u32::MAX,
            parallelism: 1,
        };
        assert!(matches!(
            slow.check(&WrapPolicy::SPEC),
            Err(ParamError::TooStrong {
                field: "iterations",
                ..
            })
        ));
    }

    #[test]
    fn the_ceiling_leaves_room_above_the_floor() {
        // A bound that refused anything stronger than the spec default would
        // stop a deployment hardening its own parameters, which is a worse
        // failure than the one it prevents.
        let hardened = Argon2Params {
            memory_kib: 1024 * MIB,
            iterations: 10,
            parallelism: 1,
        };
        hardened.check(&WrapPolicy::SPEC).unwrap();
        // And the boundary itself is inclusive on both sides.
        let at_ceiling = Argon2Params {
            memory_kib: WrapPolicy::SPEC.max_memory_kib,
            iterations: WrapPolicy::SPEC.max_iterations,
            parallelism: 1,
        };
        at_ceiling.check(&WrapPolicy::SPEC).unwrap();
        let at_floor = Argon2Params {
            memory_kib: WrapPolicy::SPEC.min_memory_kib,
            iterations: WrapPolicy::SPEC.min_iterations,
            parallelism: 1,
        };
        at_floor.check(&WrapPolicy::SPEC).unwrap();
    }

    #[test]
    fn every_policy_here_has_a_ceiling() {
        // A policy constructed without one would fail open, and `FAST` exists
        // to be permissive — which is exactly where an unbounded ceiling would
        // be least noticed.
        for p in [WrapPolicy::SPEC, WrapPolicy::FAST] {
            assert!(p.max_memory_kib > p.min_memory_kib);
            assert!(p.max_iterations >= p.min_iterations);
            assert!(p.max_memory_kib < u32::MAX);
            assert!(p.max_iterations < u32::MAX);
        }
    }

    #[test]
    fn weak_parameters_are_refused_under_the_spec_policy() {
        assert!(matches!(
            Argon2Params::WEAK_FOR_TESTS.check(&WrapPolicy::SPEC),
            Err(ParamError::TooWeak {
                field: "memory_kib",
                ..
            })
        ));
        let low_t = Argon2Params {
            iterations: 2,
            ..Argon2Params::SPEC
        };
        assert!(matches!(
            low_t.check(&WrapPolicy::SPEC),
            Err(ParamError::TooWeak {
                field: "iterations",
                ..
            })
        ));
    }

    #[test]
    fn parallelism_other_than_one_is_refused() {
        // A different lane count is a different KDF: the same passphrase would
        // silently produce a different key, and the data would be unopenable.
        let p = Argon2Params {
            parallelism: 4,
            ..Argon2Params::SPEC
        };
        assert_eq!(
            p.check(&WrapPolicy::SPEC),
            Err(ParamError::WrongParallelism { got: 4 })
        );
        assert_eq!(
            p.check(&WrapPolicy::FAST),
            Err(ParamError::WrongParallelism { got: 4 })
        );
    }

    #[test]
    fn params_round_trip() {
        for p in [Argon2Params::SPEC, Argon2Params::WEAK_FOR_TESTS] {
            assert_eq!(Argon2Params::decode(&p.encode()).unwrap(), p);
        }
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 4, 12, 40] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = Argon2Params::decode(&junk);
        }
    }

    #[test]
    fn derivation_is_deterministic_and_salt_separated() {
        let p = Argon2Params::WEAK_FOR_TESTS;
        let a = p
            .derive(b"correct horse battery staple", b"salt-one-8bytes")
            .unwrap();
        let b = p
            .derive(b"correct horse battery staple", b"salt-one-8bytes")
            .unwrap();
        let c = p
            .derive(b"correct horse battery staple", b"salt-two-8bytes")
            .unwrap();
        let d = p
            .derive(b"a different passphrase", b"salt-one-8bytes")
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "salt did not separate");
        assert_ne!(a, d);
    }

    #[test]
    fn different_parameters_give_different_keys() {
        // Which is exactly why the parameters are stored in the wrap record: a
        // client that guessed today's parameters would derive a different KEK
        // and conclude the passphrase was wrong.
        let salt = b"salt-8-bytes!";
        let a = Argon2Params::WEAK_FOR_TESTS.derive(b"pw", salt).unwrap();
        let b = Argon2Params {
            iterations: 2,
            ..Argon2Params::WEAK_FOR_TESTS
        }
        .derive(b"pw", salt)
        .unwrap();
        assert_ne!(a, b);
    }

    /// The real parameters, run once, so "256 MiB, t=3" is a measured cost
    /// rather than a number in a document.
    #[test]
    #[ignore = "allocates 256 MiB and takes ~1s; run with --ignored"]
    fn the_spec_parameters_actually_work() {
        let k = Argon2Params::SPEC
            .derive(b"five diceware words go here", b"a-real-salt-16by")
            .unwrap();
        assert_ne!(k, [0u8; 32]);
    }
}
