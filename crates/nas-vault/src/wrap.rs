//! The passphrase wrap record (SPECS §2.2.2).
//!
//! ```text
//! WrapRecord { salt, argon2_params, wrapped_DEK, seq,
//!              anchor: (slot_seq, sig_hash), prev, sig }
//! ```
//!
//! # The passphrase wraps a key; it never *is* the key
//!
//! That indirection is what lets a passphrase change re-wrap 32 bytes instead
//! of re-encrypting a terabyte.
//!
//! # Why the record carries a freshness anchor
//!
//! A client recovering from a passphrase alone holds no capability, so it has
//! no anchor — which reopens exactly the bootstrapping rollback hole §5.3(1)
//! exists to close: with no floor, any validly signed historical record is
//! acceptable, and a rollback is indistinguishable from a first sync.
//!
//! So **the wrap record is the capability for this mode.** Unwrapping it yields
//! both the key material and the `(seq, sig_hash)` floor beneath which nothing
//! will be accepted.
//!
//! # What binds what
//!
//! The AEAD's associated data is the whole record *except* the wrapped key and
//! the signature. So a peer that edits the anchor, the sequence number, the
//! salt or the parameters makes the unwrap fail rather than succeed with a
//! lowered floor — the attack that would otherwise be free, since the peer
//! stores this record and the client has nothing else to compare it against.
//!
//! The signature exists in addition because the **peer** must be able to verify
//! a wrap record it cannot unwrap. It verifies against the namespace's slot
//! verifying key, which it already holds to check slot records.

use crate::argon::{Argon2Params, ParamError, WrapPolicy};
use crate::derive::NamespaceSecrets;
use nas_core::{decode_fields, encode_fields, DecodeError};
use nas_crypto::{
    open, random, seal, verify, wrapping_key, CryptoError, SigContext, SignError, SIGNATURE_LEN,
};
use nas_slots::Anchor;
use zeroize::Zeroize;

/// Minimum salt length. Argon2 requires 8; 16 is the usual floor and costs
/// nothing, so there is no reason to sit at the minimum.
pub const MIN_SALT: usize = 16;

/// Domain string for the wrap chain hash.
const CHAIN_DOMAIN: &[u8] = b"nas-tools/wrap-chain/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    Decode(DecodeError),
    Param(ParamError),
    Sign(SignError),
    /// Wrong passphrase, or a tampered record. **Deliberately one error**: the
    /// two are indistinguishable to an attacker probing with guesses, and
    /// telling them apart would say which half of the record to attack.
    Unwrap,
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    SaltTooShort {
        got: usize,
    },
    GenesisMismatch {
        seq: u64,
    },
    BadSignature,
    Io(String),
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "wrap encoding: {e:?}"),
            Self::Param(e) => write!(f, "{e}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::Unwrap => write!(f, "could not unwrap: wrong passphrase or altered record"),
            Self::BadWidth { field, want, got } => write!(f, "{field} is {got} B, want {want} B"),
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::SaltTooShort { got } => write!(f, "salt is {got} B, want at least {MIN_SALT}"),
            Self::GenesisMismatch { seq } => {
                write!(f, "seq {seq}: only seq 0 may have an empty predecessor")
            }
            Self::BadSignature => write!(f, "wrap record signature does not verify"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for WrapError {}
impl From<DecodeError> for WrapError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<ParamError> for WrapError {
    fn from(e: ParamError) -> Self {
        Self::Param(e)
    }
}
impl From<SignError> for WrapError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}
impl From<CryptoError> for WrapError {
    fn from(_: CryptoError) -> Self {
        Self::Unwrap
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WrapRecord {
    pub salt: Vec<u8>,
    pub params: Argon2Params,
    /// `nonce ‖ ciphertext ‖ tag` over the DEK.
    pub wrapped_dek: Vec<u8>,
    pub seq: u64,
    pub anchor: Anchor,
    pub prev: [u8; 32],
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for WrapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapRecord")
            .field("seq", &self.seq)
            .field("anchor_seq", &self.anchor.seq)
            .field("params", &self.params)
            .finish()
    }
}

/// Everything the AEAD authenticates and the signature covers, except the
/// wrapped key itself.
fn aad(salt: &[u8], params: &Argon2Params, seq: u64, anchor: &Anchor, prev: &[u8; 32]) -> Vec<u8> {
    encode_fields(&[
        salt,
        &params.encode(),
        &seq.to_le_bytes(),
        &anchor.seq.to_le_bytes(),
        &anchor.sig_hash,
        prev,
    ])
    .expect("wrap aad always encodes")
}

fn check_genesis(seq: u64, prev: &[u8; 32]) -> Result<(), WrapError> {
    let zero = prev.iter().all(|&b| b == 0);
    if (seq == 0) != zero {
        return Err(WrapError::GenesisMismatch { seq });
    }
    Ok(())
}

impl WrapRecord {
    /// Wrap `dek` under `passphrase` and sign the result.
    ///
    /// The signing identity is derived from the DEK itself, so only someone who
    /// knows the passphrase can produce a record that verifies — the peer
    /// cannot substitute one of its own with a lowered anchor.
    pub fn create(
        passphrase: &[u8],
        dek: &[u8; 32],
        params: Argon2Params,
        policy: &WrapPolicy,
        seq: u64,
        anchor: Anchor,
        prev: [u8; 32],
    ) -> Result<Self, WrapError> {
        params.check(policy)?;
        check_genesis(seq, &prev)?;

        let salt: [u8; 32] = random::array().map_err(|e| WrapError::Io(e.to_string()))?;
        let mut kek = params.derive(passphrase, &salt)?;
        let key = wrapping_key(kek);
        kek.zeroize();

        let a = aad(&salt, &params, seq, &anchor, &prev);
        let wrapped_dek = seal(&key, dek, &a)?;

        let secrets = NamespaceSecrets::from_dek(dek);
        let identity = secrets.slot_identity()?;
        let body = encode_fields(&[&a, &wrapped_dek]).expect("wrap body always encodes");
        let sig = identity.sign(SigContext::Wrap, &body)?;

        Ok(Self {
            salt: salt.to_vec(),
            params,
            wrapped_dek,
            seq,
            anchor,
            prev,
            sig,
        })
    }

    /// Recover the DEK. Returns the namespace secrets and the anchor together,
    /// because in this mode they *are* the capability and separating them would
    /// let a caller take the keys and forget the floor.
    pub fn unwrap(
        &self,
        passphrase: &[u8],
        policy: &WrapPolicy,
    ) -> Result<(NamespaceSecrets, Anchor), WrapError> {
        self.params.check(policy)?;
        check_genesis(self.seq, &self.prev)?;
        if self.salt.len() < MIN_SALT {
            return Err(WrapError::SaltTooShort {
                got: self.salt.len(),
            });
        }

        let mut kek = self.params.derive(passphrase, &self.salt)?;
        let key = wrapping_key(kek);
        kek.zeroize();

        let a = aad(&self.salt, &self.params, self.seq, &self.anchor, &self.prev);
        let mut dek_bytes = open(&key, &self.wrapped_dek, &a)?;
        if dek_bytes.len() != 32 {
            dek_bytes.zeroize();
            return Err(WrapError::Unwrap);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        dek_bytes.zeroize();

        let secrets = NamespaceSecrets::from_dek(&dek);
        dek.zeroize();

        // Belt and braces: the AEAD already bound the anchor, and this proves
        // the record was authored by a DEK holder rather than merely opened.
        self.verify_with(&secrets)?;
        Ok((secrets, self.anchor))
    }

    /// Verify the signature using secrets already recovered.
    pub fn verify_with(&self, secrets: &NamespaceSecrets) -> Result<(), WrapError> {
        let identity = secrets.slot_identity()?;
        self.verify_pk(identity.verifying_key())
    }

    /// Verify against a known verifying key — what the **peer** does, since it
    /// stores this record and cannot unwrap it.
    pub fn verify_pk(&self, verifying_key: &[u8]) -> Result<(), WrapError> {
        check_genesis(self.seq, &self.prev)?;
        let a = aad(&self.salt, &self.params, self.seq, &self.anchor, &self.prev);
        let body = encode_fields(&[&a, &self.wrapped_dek]).expect("wrap body always encodes");
        verify(verifying_key, SigContext::Wrap, &body, &self.sig)
            .map_err(|_| WrapError::BadSignature)
    }

    pub fn chain_hash(&self) -> [u8; 32] {
        let a = aad(&self.salt, &self.params, self.seq, &self.anchor, &self.prev);
        let mut h = blake3::Hasher::new();
        h.update(CHAIN_DOMAIN);
        h.update(&(a.len() as u64).to_le_bytes());
        h.update(&a);
        h.update(&self.wrapped_dek);
        h.update(&self.sig);
        *h.finalize().as_bytes()
    }

    pub fn encode(&self) -> Result<Vec<u8>, WrapError> {
        Ok(encode_fields(&[
            &self.salt,
            &self.params.encode(),
            &self.wrapped_dek,
            &self.seq.to_le_bytes(),
            &self.anchor.seq.to_le_bytes(),
            &self.anchor.sig_hash,
            &self.prev,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WrapError> {
        let f = decode_fields(bytes)?;
        if f.len() != 8 {
            return Err(WrapError::FieldCount {
                want: 8,
                got: f.len(),
            });
        }
        if f[0].len() < MIN_SALT {
            return Err(WrapError::SaltTooShort { got: f[0].len() });
        }
        if f[7].len() != SIGNATURE_LEN {
            return Err(WrapError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[7].len(),
            });
        }
        let seq = u64::from_le_bytes(fixed::<8>("seq", f[3])?);
        let prev = fixed::<32>("prev", f[6])?;
        check_genesis(seq, &prev)?;
        Ok(Self {
            salt: f[0].to_vec(),
            params: Argon2Params::decode(f[1])?,
            wrapped_dek: f[2].to_vec(),
            seq,
            anchor: Anchor {
                seq: u64::from_le_bytes(fixed::<8>("anchor_seq", f[4])?),
                sig_hash: fixed::<32>("anchor_sig_hash", f[5])?,
            },
            prev,
            sig: f[7].to_vec(),
        })
    }
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], WrapError> {
    b.try_into().map_err(|_| WrapError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"five diceware words go right here";
    const DEK: [u8; 32] = [0x5C; 32];

    fn anchor(seq: u64) -> Anchor {
        Anchor {
            seq,
            sig_hash: [seq as u8; 32],
        }
    }

    fn make(seq: u64, prev: [u8; 32], a: Anchor) -> WrapRecord {
        WrapRecord::create(
            PW,
            &DEK,
            Argon2Params::WEAK_FOR_TESTS,
            &WrapPolicy::FAST,
            seq,
            a,
            prev,
        )
        .unwrap()
    }

    #[test]
    fn wrap_then_unwrap_recovers_the_secrets_and_the_anchor() {
        let w = make(0, [0u8; 32], anchor(7));
        let (secrets, got) = w.unwrap(PW, &WrapPolicy::FAST).unwrap();
        assert_eq!(got, anchor(7));
        assert_eq!(secrets, NamespaceSecrets::from_dek(&DEK));
    }

    #[test]
    fn the_wrong_passphrase_fails() {
        let w = make(0, [0u8; 32], anchor(7));
        assert_eq!(
            w.unwrap(b"not the passphrase", &WrapPolicy::FAST),
            Err(WrapError::Unwrap)
        );
    }

    #[test]
    fn a_lowered_anchor_makes_the_unwrap_fail() {
        // The attack this record exists to stop: a peer that could edit the
        // anchor would hand a recovering client a floor of zero, and every
        // rollback below it would then look like a first sync.
        let mut w = make(0, [0u8; 32], anchor(9));
        w.anchor = anchor(0);
        assert_eq!(w.unwrap(PW, &WrapPolicy::FAST), Err(WrapError::Unwrap));
    }

    #[test]
    fn editing_any_bound_field_makes_the_unwrap_fail() {
        let base = make(1, [3u8; 32], anchor(9));
        for m in 0..5 {
            let mut w = base.clone();
            match m {
                0 => w.salt = vec![9u8; 32],
                1 => {
                    w.params = Argon2Params {
                        iterations: 2,
                        ..Argon2Params::WEAK_FOR_TESTS
                    }
                }
                2 => w.seq = 2,
                3 => w.anchor.sig_hash = [0xFF; 32],
                _ => w.prev = [4u8; 32],
            }
            assert_eq!(
                w.unwrap(PW, &WrapPolicy::FAST),
                Err(WrapError::Unwrap),
                "mutation {m}"
            );
        }
    }

    #[test]
    fn the_peer_can_verify_without_unwrapping() {
        // The peer stores this record and holds the namespace slot key, but
        // never the passphrase.
        let w = make(0, [0u8; 32], anchor(4));
        let secrets = NamespaceSecrets::from_dek(&DEK);
        let vk = secrets.slot_identity().unwrap();
        w.verify_pk(vk.verifying_key()).unwrap();
    }

    #[test]
    fn a_peer_cannot_forge_a_record_it_can_verify() {
        // Substituting a record with a lowered anchor requires signing it, and
        // the signing key derives from the DEK the peer does not have.
        let w = make(0, [0u8; 32], anchor(9));
        let mut forged = w.clone();
        forged.anchor = anchor(0);
        let secrets = NamespaceSecrets::from_dek(&DEK);
        let vk = secrets.slot_identity().unwrap();
        assert_eq!(
            forged.verify_pk(vk.verifying_key()),
            Err(WrapError::BadSignature)
        );
    }

    #[test]
    fn weak_parameters_are_refused_under_the_spec_policy() {
        // A record written with cheap parameters must not be silently accepted
        // by a client that thinks it is running the specified policy.
        let w = make(0, [0u8; 32], anchor(1));
        assert!(matches!(
            w.unwrap(PW, &WrapPolicy::SPEC),
            Err(WrapError::Param(ParamError::TooWeak { .. }))
        ));
    }

    #[test]
    fn round_trips_through_its_encoding() {
        let w = make(2, [7u8; 32], anchor(5));
        let back = WrapRecord::decode(&w.encode().unwrap()).unwrap();
        assert_eq!(back, w);
        let (_, a) = back.unwrap(PW, &WrapPolicy::FAST).unwrap();
        assert_eq!(a, anchor(5));
    }

    #[test]
    fn a_short_salt_is_refused() {
        let mut w = make(0, [0u8; 32], anchor(1));
        w.salt = vec![1u8; 8];
        assert_eq!(
            w.unwrap(PW, &WrapPolicy::FAST),
            Err(WrapError::SaltTooShort { got: 8 })
        );
        let framed = encode_fields(&[
            &w.salt,
            &w.params.encode(),
            &w.wrapped_dek,
            &w.seq.to_le_bytes(),
            &w.anchor.seq.to_le_bytes(),
            &w.anchor.sig_hash,
            &w.prev,
            &w.sig,
        ])
        .unwrap();
        assert_eq!(
            WrapRecord::decode(&framed),
            Err(WrapError::SaltTooShort { got: 8 })
        );
    }

    #[test]
    fn two_wraps_of_one_dek_differ_but_open_to_the_same_secrets() {
        // A passphrase change re-wraps 32 bytes rather than re-encrypting a
        // terabyte, and a fresh salt and nonce mean the two records share no
        // bytes an observer could correlate.
        let a = make(0, [0u8; 32], anchor(1));
        let b = WrapRecord::create(
            b"a new passphrase entirely",
            &DEK,
            Argon2Params::WEAK_FOR_TESTS,
            &WrapPolicy::FAST,
            1,
            anchor(1),
            a.chain_hash(),
        )
        .unwrap();
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
        assert_ne!(a.salt, b.salt);

        let (sa, _) = a.unwrap(PW, &WrapPolicy::FAST).unwrap();
        let (sb, _) = b
            .unwrap(b"a new passphrase entirely", &WrapPolicy::FAST)
            .unwrap();
        assert_eq!(sa, sb, "re-wrapping changed the namespace secrets");
    }

    #[test]
    fn the_old_passphrase_still_opens_the_old_record() {
        // SPECS §2.2.2, stated so nobody is surprised: a superseded wrap
        // remains a brute-force target against the OLD passphrase, and against
        // a hostile peer deleting it is best-effort. Changing a passphrase
        // protects future writes; it does not un-expose what was copied.
        let a = make(0, [0u8; 32], anchor(1));
        assert!(a.unwrap(PW, &WrapPolicy::FAST).is_ok());
    }

    #[test]
    fn only_seq_zero_may_be_genesis() {
        assert!(matches!(
            WrapRecord::create(
                PW,
                &DEK,
                Argon2Params::WEAK_FOR_TESTS,
                &WrapPolicy::FAST,
                3,
                anchor(1),
                [0u8; 32]
            ),
            Err(WrapError::GenesisMismatch { seq: 3 })
        ));
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 8, 100, 3400, 5000] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = WrapRecord::decode(&junk);
        }
    }
}
