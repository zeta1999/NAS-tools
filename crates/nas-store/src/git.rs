//! Git object index (SPECS §7.3).
//!
//! Git addresses by SHA-1 of the *inflated* object; we address by BLAKE3 of
//! the ciphertext. The `git_oid → addr` table is therefore a confirmation
//! oracle for every public repository if it ever leaves the encrypted
//! manifest. It is sealed under the directory key, same as a bucket.

use crate::blobs::{BlobStore, StoreError};
use crate::object::Sealer;
use nas_core::{decode_fields, encode_fields, Addr, DecodeError, ADDR_LEN};
use nas_crypto::{manifest_key, open, seal, DirSecret};
use std::collections::BTreeMap;

pub const GIT_MAGIC: &[u8; 4] = b"NASG";
pub const GIT_AAD: &[u8] = b"nas-tools/aad/git-oidmap/v1";
pub const GIT_OID_LEN: usize = 20;
const VERSION: u8 = 1;

pub type GitOid = [u8; GIT_OID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum GitKind {
    Blob = 1,
    Tree = 2,
    Commit = 3,
    Tag = 4,
}

impl GitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "blob" => Some(Self::Blob),
            "tree" => Some(Self::Tree),
            "commit" => Some(Self::Commit),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Blob),
            2 => Some(Self::Tree),
            3 => Some(Self::Commit),
            4 => Some(Self::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidEntry {
    pub addr: Addr,
    pub kind: GitKind,
    pub size: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OidMap {
    pub entries: BTreeMap<GitOid, OidEntry>,
}

#[derive(Debug)]
pub enum GitError {
    Store(StoreError),
    Crypto(nas_crypto::CryptoError),
    Decode(DecodeError),
    BadMagic,
    BadVersion {
        value: u8,
    },
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    Ragged {
        fields: usize,
    },
    BadKind {
        value: u8,
    },
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "encoding: {e:?}"),
            Self::BadMagic => write!(f, "not a git oid map"),
            Self::BadVersion { value } => write!(f, "git oid map version {value}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "git {field} is {got} B, want {want} B")
            }
            Self::Ragged { fields } => write!(f, "{fields} git fields is not a multiple of 4"),
            Self::BadKind { value } => write!(f, "unknown git object kind {value}"),
            Self::NonCanonical { reason } => write!(f, "non-canonical git oid map: {reason}"),
        }
    }
}
impl std::error::Error for GitError {}
impl From<StoreError> for GitError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<nas_crypto::CryptoError> for GitError {
    fn from(e: nas_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<DecodeError> for GitError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

pub fn oid_to_hex(oid: &GitOid) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(40);
    for b in oid {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

pub fn oid_from_hex(s: &str) -> Option<GitOid> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; GIT_OID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], GitError> {
    b.try_into().map_err(|_| GitError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

impl OidMap {
    pub fn get(&self, oid: &GitOid) -> Option<&OidEntry> {
        self.entries.get(oid)
    }

    pub fn insert(&mut self, oid: GitOid, entry: OidEntry) {
        self.entries.insert(oid, entry);
    }

    pub fn encode(&self) -> Result<Vec<u8>, GitError> {
        let mut fields: Vec<Vec<u8>> = vec![GIT_MAGIC.to_vec(), vec![VERSION]];
        for (oid, e) in &self.entries {
            fields.push(oid.to_vec());
            fields.push(e.addr.as_bytes().to_vec());
            fields.push(vec![e.kind as u8]);
            fields.push(e.size.to_le_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
        Ok(encode_fields(&refs)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GitError> {
        let f = decode_fields(bytes)?;
        if f.first() != Some(&&GIT_MAGIC[..]) {
            return Err(GitError::BadMagic);
        }
        if f.len() < 2 {
            return Err(GitError::Ragged { fields: f.len() });
        }
        let version = fixed::<1>("version", f[1])?[0];
        if version != VERSION {
            return Err(GitError::BadVersion { value: version });
        }
        let body = f.len() - 2;
        if !body.is_multiple_of(4) {
            return Err(GitError::Ragged { fields: body });
        }
        let mut entries = BTreeMap::new();
        let mut prev: Option<GitOid> = None;
        let mut i = 2;
        while i + 3 < f.len() {
            let oid: GitOid = fixed("oid", f[i])?;
            if let Some(p) = prev {
                if oid <= p {
                    return Err(GitError::NonCanonical {
                        reason: "oids are not in ascending order",
                    });
                }
            }
            prev = Some(oid);
            let addr_bytes: [u8; ADDR_LEN] = fixed("addr", f[i + 1])?;
            let kind_b = fixed::<1>("kind", f[i + 2])?[0];
            let kind = GitKind::from_u8(kind_b).ok_or(GitError::BadKind { value: kind_b })?;
            let size = u32::from_le_bytes(fixed("size", f[i + 3])?);
            if entries
                .insert(
                    oid,
                    OidEntry {
                        addr: Addr::from_bytes(addr_bytes),
                        kind,
                        size,
                    },
                )
                .is_some()
            {
                return Err(GitError::NonCanonical {
                    reason: "duplicate oid",
                });
            }
            i += 4;
        }
        Ok(Self { entries })
    }
}

pub struct GitStore<'a> {
    pub blobs: &'a BlobStore,
    pub sealer: Sealer<'a>,
}

impl<'a> GitStore<'a> {
    pub fn new(blobs: &'a BlobStore, sealer: Sealer<'a>) -> Self {
        Self { blobs, sealer }
    }

    pub fn store_map(&self, dir: &DirSecret, map: &OidMap) -> Result<Addr, GitError> {
        let plain = map.encode()?;
        match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                let sealed = seal(&key, &plain, GIT_AAD)?;
                Ok(self.blobs.put(&sealed)?)
            }
            Sealer::Plaintext { .. } => Ok(self.blobs.put(&plain)?),
        }
    }

    pub fn load_map(&self, dir: &DirSecret, addr: &Addr) -> Result<OidMap, GitError> {
        let stored = self.blobs.get(addr)?;
        let plain = match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                open(&key, &stored, GIT_AAD)?
            }
            Sealer::Plaintext { .. } => stored,
        };
        OidMap::decode(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::BlobStore;
    use nas_crypto::{ConvergenceSecret, KEY_LEN};
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("nas-git-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn hex_round_trips() {
        let oid = oid_from_hex("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(oid_to_hex(&oid), "0123456789abcdef0123456789abcdef01234567");
        assert!(oid_from_hex("abc").is_none());
    }

    #[test]
    fn map_round_trips_and_stays_sealed() {
        let dir = scratch("map");
        let blobs = BlobStore::open(&dir).unwrap();
        let cs = ConvergenceSecret::from_bytes([9u8; KEY_LEN]);
        let store = GitStore::new(&blobs, Sealer::Convergent(&cs));
        let dsec = nas_crypto::DirSecret::root(&[3u8; KEY_LEN]);
        let mut map = OidMap::default();
        let oid = oid_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        map.insert(
            oid,
            OidEntry {
                addr: Addr::of_ciphertext(&[1u8; 8]),
                kind: GitKind::Commit,
                size: 12,
            },
        );
        let addr = store.store_map(&dsec, &map).unwrap();
        let back = store.load_map(&dsec, &addr).unwrap();
        assert_eq!(back, map);
        let stored = blobs.get(&addr).unwrap();
        let marker = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(
            !stored.windows(marker.len()).any(|w| w == marker),
            "oid hex leaked into the sealed map"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scrambled_map_is_refused() {
        let mut map = OidMap::default();
        map.insert(
            [2u8; 20],
            OidEntry {
                addr: Addr::of_ciphertext(&[1]),
                kind: GitKind::Blob,
                size: 1,
            },
        );
        let mut bytes = map.encode().unwrap();
        bytes[0] ^= 0xff;
        assert!(matches!(
            OidMap::decode(&bytes),
            Err(GitError::BadMagic) | Err(GitError::Decode(_))
        ));
    }
}
