//! The root manifest — what a slot record points at (SPECS §3.1 `rk_v`, §5).
//!
//! Not the root *directory* manifest. That is one sealed blob among many,
//! under a key derived from its path, and rewritten whenever the tree
//! changes. This is the small object that says *which* directory manifest is
//! the root at a given slot sequence, plus what a reader needs to know before
//! descending: the convergence-secret generation writes were made under.
//!
//! It is sealed under `rk_seq`, a key that exists for this one sequence
//! ([`nas_crypto::root_key`]), with a nonce the slot record carries under the
//! writer's signature. Until it existed, `SlotRecord.root` pointed straight at
//! the directory manifest and `root_nonce` was random bytes that sealed
//! nothing — a field the frozen peer-facing format had reserved for exactly
//! this and the client had never filled.
//!
//! In `transit-only` it is stored unsealed like every other manifest, so the
//! peer can browse from the slot down (SPECS §2.2.3).

use nas_core::{decode_fields, encode_fields, Addr, DecodeError, ADDR_LEN};

/// AAD prefix for a sealed root manifest; see [`root_aad`].
pub const ROOT_AAD: &[u8] = b"nas-tools/aad/root/v1";

/// Format version byte, first field of the encoding.
const VERSION: u8 = 1;

/// One version of a namespace's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootManifest {
    /// Address of the root directory manifest at this version.
    pub tree: Addr,
    /// The convergence-secret generation new writes used (SPECS §3.9c), so a
    /// reader knows which `CS` opens the chunks beneath before it fetches one.
    pub generation: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RootError {
    Decode(DecodeError),
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    BadVersion {
        value: u8,
    },
}

impl std::fmt::Display for RootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "root manifest: {e:?}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "root manifest: {field} is {got} bytes, want {want}")
            }
            Self::FieldCount { want, got } => {
                write!(f, "root manifest: {got} fields, want {want}")
            }
            Self::BadVersion { value } => write!(f, "root manifest: unknown version {value}"),
        }
    }
}
impl std::error::Error for RootError {}

impl From<DecodeError> for RootError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], RootError> {
    b.try_into().map_err(|_| RootError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

impl RootManifest {
    pub fn encode(&self) -> Result<Vec<u8>, RootError> {
        Ok(encode_fields(&[
            &[VERSION],
            self.tree.as_bytes(),
            &self.generation.to_le_bytes(),
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RootError> {
        let f = decode_fields(bytes)?;
        if f.len() != 3 {
            return Err(RootError::FieldCount {
                want: 3,
                got: f.len(),
            });
        }
        let version = fixed::<1>("version", f[0])?[0];
        if version != VERSION {
            return Err(RootError::BadVersion { value: version });
        }
        Ok(Self {
            tree: Addr::from_bytes(fixed::<ADDR_LEN>("tree", f[1])?),
            generation: u32::from_le_bytes(fixed::<4>("generation", f[2])?),
        })
    }
}

/// The AAD a root manifest is sealed under: the slot and the sequence whose
/// record carries its nonce.
///
/// The key already differs per sequence; the AAD additionally binds the slot,
/// so a namespace with several slots (git refs, SPECS §7.3) cannot have one
/// slot's root served as another's at the same sequence.
pub fn root_aad(slot_id: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(ROOT_AAD.len() + 32 + 8);
    v.extend_from_slice(ROOT_AAD);
    v.extend_from_slice(slot_id);
    v.extend_from_slice(&seq.to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> RootManifest {
        RootManifest {
            tree: Addr::of_ciphertext(b"the root directory manifest"),
            generation: 3,
        }
    }

    #[test]
    fn round_trips() {
        let r = root();
        assert_eq!(RootManifest::decode(&r.encode().unwrap()).unwrap(), r);
    }

    #[test]
    fn an_unknown_version_is_refused_before_anything_is_read_from_it() {
        // Built field by field rather than by patching a good encoding: the
        // version field is one byte long, so its length prefix is *also*
        // 0x01, and a byte search for VERSION lands on the prefix. The other
        // two fields are deliberately malformed — a version we do not know
        // must be refused before their widths are ever looked at.
        let bytes = encode_fields(&[&[2u8], &[0u8; 31], &[]]).unwrap();
        assert_eq!(
            RootManifest::decode(&bytes),
            Err(RootError::BadVersion { value: 2 })
        );
    }

    #[test]
    fn a_trailing_field_is_refused() {
        let mut bytes = root().encode().unwrap();
        bytes.extend_from_slice(&encode_fields(&[b"extra"]).unwrap());
        assert_eq!(
            RootManifest::decode(&bytes),
            Err(RootError::FieldCount { want: 3, got: 4 })
        );
    }

    #[test]
    fn a_short_address_is_refused() {
        let bytes = encode_fields(&[&[VERSION], &[0u8; 31], &3u32.to_le_bytes()]).unwrap();
        assert_eq!(
            RootManifest::decode(&bytes),
            Err(RootError::BadWidth {
                field: "tree",
                want: ADDR_LEN,
                got: 31
            })
        );
    }

    #[test]
    fn aad_binds_both_slot_and_sequence() {
        let a = root_aad(&[1u8; 32], 5);
        assert_ne!(a, root_aad(&[2u8; 32], 5));
        assert_ne!(a, root_aad(&[1u8; 32], 6));
        assert!(a.starts_with(ROOT_AAD));
    }
}
