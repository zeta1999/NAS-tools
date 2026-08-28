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
}

impl WrapPolicy {
    /// SPECS §2.2.2's floor: m ≥ 256 MiB, t ≥ 3.
    pub const SPEC: Self = Self {
        min_memory_kib: 256 * MIB,
        min_iterations: 3,
    };
    /// For tests. Using this in production is a visible line in a diff.
    pub const FAST: Self = Self {
        min_memory_kib: 8 * MIB,
        min_iterations: 1,
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
