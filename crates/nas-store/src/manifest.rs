//! Manifests (SPECS §4.3).
//!
//! ```text
//! { name_enc, kind: file|dir, size, chunks: [ { addr, ck, pt_hash, len } ], meta }
//! ```
//!
//! # A manifest is key material
//!
//! `ck` must be stored: a reader holds no plaintext and cannot re-derive it
//! (SPECS §4.3). So a decoded manifest carries one live chunk key per chunk,
//! and leaking it is equivalent to leaking the file. Hence [`ChunkRef`] and
//! [`Manifest`] zeroize on drop and redact in `Debug`, and a manifest is only
//! ever written to a peer through [`nas_crypto::seal`].
//!
//! # Why the chunk table is fixed-width
//!
//! Every field of a [`ChunkRef`] has a fixed width, so the canonical
//! length-prefixed encoder — whose injectivity is the Lean theorem
//! `encFields_inj` — would spend sixteen bytes per chunk restating lengths that
//! cannot vary. Concatenating fixed-width records is injective for the same
//! reason and costs nothing, so the table is `n × RECORD` bytes and a length
//! that is not a multiple of `RECORD` is a decode error.

use nas_core::{
    decode_fields, encode_fields, Addr, DecodeError, KeyScheme, PaddingProfile, ADDR_LEN,
    MANIFEST_VERSION,
};
use nas_crypto::KEY_LEN;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Distinguishes a manifest from any other blob before parsing it.
pub const MAGIC: &[u8; 4] = b"NASM";

/// Bytes per chunk record: addr ‖ ck ‖ pt_hash ‖ le32(len).
pub const RECORD: usize = ADDR_LEN + KEY_LEN + 32 + 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    File = 0,
    Dir = 1,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ManifestError {
    Decode(DecodeError),
    /// Not a manifest at all.
    BadMagic,
    /// Written by a newer implementation. Refusing beats guessing: a manifest
    /// misread is a file silently reconstructed wrong.
    UnknownVersion {
        found: u16,
    },
    /// A discriminant byte outside the enum.
    BadDiscriminant {
        field: &'static str,
        value: u8,
    },
    /// Wrong number of top-level fields.
    FieldCount {
        want: usize,
        got: usize,
    },
    /// A fixed-width field arrived at the wrong width.
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    /// The chunk table is not a whole number of records.
    RaggedChunkTable {
        bytes: usize,
    },
    /// The chunk lengths do not add up to the declared size — a manifest that
    /// would reconstruct a file of the wrong length without any error.
    SizeMismatch {
        declared: u64,
        chunks: u64,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "manifest encoding: {e:?}"),
            Self::BadMagic => write!(f, "not a manifest"),
            Self::UnknownVersion { found } => write!(
                f,
                "manifest version {found}, this build understands {MANIFEST_VERSION}"
            ),
            Self::BadDiscriminant { field, value } => {
                write!(f, "unknown {field} discriminant {value}")
            }
            Self::FieldCount { want, got } => write!(f, "manifest has {got} fields, want {want}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "{field} is {got} B, want {want} B")
            }
            Self::RaggedChunkTable { bytes } => {
                write!(
                    f,
                    "chunk table of {bytes} B is not a multiple of {RECORD} B"
                )
            }
            Self::SizeMismatch { declared, chunks } => {
                write!(
                    f,
                    "manifest declares {declared} B but its chunks total {chunks} B"
                )
            }
        }
    }
}
impl std::error::Error for ManifestError {}
impl From<DecodeError> for ManifestError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// One chunk of a file.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ChunkRef {
    /// `BLAKE3(ciphertext)` — where the blob is filed.
    #[zeroize(skip)]
    pub addr: Addr,
    /// The convergent chunk key. **Secret.**
    pub ck: [u8; KEY_LEN],
    /// `BLAKE3(plaintext)`, so a decryption can be checked against what was
    /// meant to be there rather than merely against the AEAD tag.
    #[zeroize(skip)]
    pub pt_hash: [u8; 32],
    /// Plaintext length, before padding.
    #[zeroize(skip)]
    pub len: u32,
}

impl std::fmt::Debug for ChunkRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkRef")
            .field("addr", &self.addr)
            .field("ck", &"<redacted>")
            .field("len", &self.len)
            .finish()
    }
}

/// A file or directory manifest.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Manifest {
    #[zeroize(skip)]
    pub version: u16,
    #[zeroize(skip)]
    pub key_scheme: KeyScheme,
    #[zeroize(skip)]
    pub padding_profile: PaddingProfile,
    #[zeroize(skip)]
    pub kind: Kind,
    /// The encrypted path segment. Segments are encrypted individually so a
    /// listing resolves locally without a server-side prefix scan (SPECS §4.4).
    #[zeroize(skip)]
    pub name_enc: Vec<u8>,
    #[zeroize(skip)]
    pub size: u64,
    pub chunks: Vec<ChunkRef>,
    #[zeroize(skip)]
    pub meta: Vec<u8>,
}

impl std::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manifest")
            .field("version", &self.version)
            .field("key_scheme", &self.key_scheme)
            .field("padding_profile", &self.padding_profile)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl Manifest {
    pub fn new(kind: Kind, key_scheme: KeyScheme, padding_profile: PaddingProfile) -> Self {
        Self {
            version: MANIFEST_VERSION,
            key_scheme,
            padding_profile,
            kind,
            name_enc: Vec::new(),
            size: 0,
            chunks: Vec::new(),
            meta: Vec::new(),
        }
    }

    /// Sum of the chunk lengths.
    pub fn chunk_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| u64::from(c.len)).sum()
    }

    /// Reject a manifest whose parts disagree with each other.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != MANIFEST_VERSION {
            return Err(ManifestError::UnknownVersion {
                found: self.version,
            });
        }
        let total = self.chunk_bytes();
        if total != self.size {
            return Err(ManifestError::SizeMismatch {
                declared: self.size,
                chunks: total,
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut table = Vec::with_capacity(self.chunks.len() * RECORD);
        for c in &self.chunks {
            table.extend_from_slice(c.addr.as_bytes());
            table.extend_from_slice(&c.ck);
            table.extend_from_slice(&c.pt_hash);
            table.extend_from_slice(&c.len.to_le_bytes());
        }
        let out = encode_fields(&[
            MAGIC,
            &self.version.to_le_bytes(),
            &[self.key_scheme as u8],
            &[self.padding_profile as u8],
            &[self.kind as u8],
            &self.name_enc,
            &self.size.to_le_bytes(),
            &table,
            &self.meta,
        ])?;
        table.zeroize();
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let f = decode_fields(bytes)?;
        if f.len() != 9 {
            return Err(ManifestError::FieldCount {
                want: 9,
                got: f.len(),
            });
        }
        if f[0] != MAGIC {
            return Err(ManifestError::BadMagic);
        }
        let version = u16::from_le_bytes(fixed::<2>("version", f[1])?);
        // Checked before anything else is interpreted: a newer layout read
        // under this build's assumptions is a file reconstructed wrong.
        if version != MANIFEST_VERSION {
            return Err(ManifestError::UnknownVersion { found: version });
        }

        let key_scheme = match one("key_scheme", f[2])? {
            0 => KeyScheme::Convergent,
            1 => KeyScheme::IndexedRandom,
            v => {
                return Err(ManifestError::BadDiscriminant {
                    field: "key_scheme",
                    value: v,
                })
            }
        };
        let padding_profile = match one("padding_profile", f[3])? {
            0 => PaddingProfile::None,
            1 => PaddingProfile::Classes,
            2 => PaddingProfile::Fixed,
            v => {
                return Err(ManifestError::BadDiscriminant {
                    field: "padding_profile",
                    value: v,
                })
            }
        };
        let kind = match one("kind", f[4])? {
            0 => Kind::File,
            1 => Kind::Dir,
            v => {
                return Err(ManifestError::BadDiscriminant {
                    field: "kind",
                    value: v,
                })
            }
        };

        let size = u64::from_le_bytes(fixed::<8>("size", f[6])?);

        let table = f[7];
        if !table.len().is_multiple_of(RECORD) {
            return Err(ManifestError::RaggedChunkTable { bytes: table.len() });
        }
        let mut chunks = Vec::with_capacity(table.len() / RECORD);
        for r in table.chunks_exact(RECORD) {
            let mut addr = [0u8; ADDR_LEN];
            addr.copy_from_slice(&r[..ADDR_LEN]);
            let mut ck = [0u8; KEY_LEN];
            ck.copy_from_slice(&r[ADDR_LEN..ADDR_LEN + KEY_LEN]);
            let mut pt_hash = [0u8; 32];
            pt_hash.copy_from_slice(&r[ADDR_LEN + KEY_LEN..ADDR_LEN + KEY_LEN + 32]);
            let len = u32::from_le_bytes(
                r[RECORD - 4..]
                    .try_into()
                    .expect("RECORD ends in four bytes"),
            );
            chunks.push(ChunkRef {
                addr: Addr::from_bytes(addr),
                ck,
                pt_hash,
                len,
            });
        }

        let m = Self {
            version,
            key_scheme,
            padding_profile,
            kind,
            name_enc: f[5].to_vec(),
            size,
            chunks,
            meta: f[8].to_vec(),
        };
        m.validate()?;
        Ok(m)
    }
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], ManifestError> {
    b.try_into().map_err(|_| ManifestError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

fn one(field: &'static str, b: &[u8]) -> Result<u8, ManifestError> {
    Ok(fixed::<1>(field, b)?[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn chunk(n: u8, len: u32) -> ChunkRef {
        ChunkRef {
            addr: Addr::of_ciphertext(&[n; 8]),
            ck: [n; KEY_LEN],
            pt_hash: [n ^ 0xFF; 32],
            len,
        }
    }

    fn sample() -> Manifest {
        let mut m = Manifest::new(Kind::File, KeyScheme::Convergent, PaddingProfile::Classes);
        m.name_enc = b"encrypted-segment".to_vec();
        m.meta = b"{\"mode\":\"0644\"}".to_vec();
        m.chunks = vec![chunk(1, 1000), chunk(2, 2500), chunk(3, 7)];
        m.size = m.chunk_bytes();
        m
    }

    #[test]
    fn roundtrips() {
        let m = sample();
        assert_eq!(Manifest::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn an_empty_file_roundtrips() {
        let m = Manifest::new(Kind::File, KeyScheme::Convergent, PaddingProfile::None);
        assert_eq!(Manifest::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn the_padding_profile_survives_the_round_trip() {
        // SPECS §4.2.1: written from M0 regardless of the default, so turning
        // padding on later is configuration and never a format break.
        for p in [
            PaddingProfile::None,
            PaddingProfile::Classes,
            PaddingProfile::Fixed,
        ] {
            let mut m = sample();
            m.padding_profile = p;
            assert_eq!(
                Manifest::decode(&m.encode().unwrap())
                    .unwrap()
                    .padding_profile,
                p
            );
        }
    }

    #[test]
    fn the_key_scheme_survives_the_round_trip() {
        // SPECS §20.3: the convergent-vs-indexed decision stays revisable on
        // disk rather than welded into the format.
        for k in [KeyScheme::Convergent, KeyScheme::IndexedRandom] {
            let mut m = sample();
            m.key_scheme = k;
            assert_eq!(
                Manifest::decode(&m.encode().unwrap()).unwrap().key_scheme,
                k
            );
        }
    }

    #[test]
    fn a_future_version_is_refused_not_guessed_at() {
        let mut b = sample().encode().unwrap();
        // Field 1 sits after MAGIC: 4 B len + 4 B magic + 4 B len.
        let off = 4 + MAGIC.len() + 4;
        b[off..off + 2].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            Manifest::decode(&b),
            Err(ManifestError::UnknownVersion { found: 99 })
        );
    }

    #[test]
    fn a_non_manifest_blob_is_rejected_by_magic() {
        let b =
            encode_fields(&[b"XXXX", &[1, 0], &[0], &[0], &[0], b"", &[0u8; 8], b"", b""]).unwrap();
        assert_eq!(Manifest::decode(&b), Err(ManifestError::BadMagic));
    }

    #[test]
    fn a_size_that_disagrees_with_the_chunks_is_rejected() {
        // Otherwise the file reconstructs at the wrong length, silently.
        let mut m = sample();
        m.size += 1;
        let declared = m.size;
        let chunks = m.chunk_bytes();
        assert_eq!(
            Manifest::decode(&m.encode().unwrap()),
            Err(ManifestError::SizeMismatch { declared, chunks })
        );
    }

    #[test]
    fn a_ragged_chunk_table_is_rejected() {
        let m = sample();
        let mut b = m.encode().unwrap();
        // Chop one byte off the table and fix up its length prefix, so the
        // canonical encoder is happy and only the record arithmetic objects.
        let tail = b.len() - m.meta.len() - 4;
        let table_len_at = tail - m.chunks.len() * RECORD - 4;
        let new_len = (m.chunks.len() * RECORD - 1) as u32;
        b[table_len_at..table_len_at + 4].copy_from_slice(&new_len.to_le_bytes());
        b.remove(tail - 1);
        assert_eq!(
            Manifest::decode(&b),
            Err(ManifestError::RaggedChunkTable {
                bytes: new_len as usize
            })
        );
    }

    #[test]
    fn an_unknown_discriminant_is_rejected() {
        let mut b = sample().encode().unwrap();
        let off = 4 + MAGIC.len() + 4 + 2 + 4; // key_scheme's single byte
        b[off] = 7;
        assert_eq!(
            Manifest::decode(&b),
            Err(ManifestError::BadDiscriminant {
                field: "key_scheme",
                value: 7
            })
        );
    }

    #[test]
    fn debug_never_prints_a_chunk_key() {
        let m = sample();
        let s = format!("{m:?} {:?}", m.chunks[0]);
        assert!(
            !s.contains("0101010101"),
            "chunk key leaked into Debug: {s}"
        );
        assert!(s.contains("redacted"));
    }

    proptest! {
        #[test]
        fn decode_never_panics(junk in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = Manifest::decode(&junk);
        }

        #[test]
        fn roundtrip_any_chunk_count(n in 0usize..64) {
            let mut m = Manifest::new(Kind::File, KeyScheme::Convergent, PaddingProfile::None);
            m.chunks = (0..n).map(|i| chunk(i as u8, (i as u32 + 1) * 13)).collect();
            m.size = m.chunk_bytes();
            prop_assert_eq!(Manifest::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }
}
