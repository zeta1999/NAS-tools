//! Encrypted chunk cache (SPECS §8.3).
//!
//! `state/cache/` holds recently read plaintext chunks so a ranged GET does
//! not refetch. Entries are sealed under `cache_k`: 32 B from the CSPRNG
//! **per boot**, random nonce per entry. A stolen disk yields nothing, and a
//! previous boot's files do not open under this one.

use nas_core::Addr;
use nas_crypto::{open, random, seal, wrapping_key, Key, KEY_LEN};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const CACHE_AAD: &[u8] = b"nas-tools/aad/cache/v1";

/// Default cap: enough for a working set, small enough that a laptop
/// cache cannot grow without bound.
pub const DEFAULT_CAP: usize = 64;

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    Crypto(nas_crypto::CryptoError),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CacheError {}
impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<nas_crypto::CryptoError> for CacheError {
    fn from(e: nas_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Bounded LRU of sealed chunk plaintexts. The key never leaves this process.
pub struct ChunkCache {
    dir: PathBuf,
    key: Key,
    cap: usize,
    order: Mutex<VecDeque<Addr>>,
}

impl ChunkCache {
    /// Open (or create) `dir` with a fresh per-boot key. Existing files from
    /// a previous boot cannot open and are swept.
    pub fn open(dir: impl AsRef<Path>, cap: usize) -> Result<Self, CacheError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let bytes: [u8; KEY_LEN] = random::array()?;
        // Random-nonce key: many chunks under one boot key, which is the
        // case §3.1 forbids a deterministic nonce for.
        let key = wrapping_key(bytes);
        let cache = Self {
            dir,
            key,
            cap: cap.max(1),
            order: Mutex::new(VecDeque::new()),
        };
        cache.sweep_unreadable()?;
        Ok(cache)
    }

    fn path(&self, addr: &Addr) -> PathBuf {
        self.dir.join(addr.to_hex())
    }

    fn sweep_unreadable(&self) -> Result<(), CacheError> {
        let rd = match fs::read_dir(&self.dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(bytes) = fs::read(&p) else { continue };
            if open(&self.key, &bytes, CACHE_AAD).is_err() {
                let _ = fs::remove_file(p);
            }
        }
        Ok(())
    }

    pub fn get(&self, addr: &Addr) -> Option<Vec<u8>> {
        let bytes = fs::read(self.path(addr)).ok()?;
        let plain = open(&self.key, &bytes, CACHE_AAD).ok()?;
        if let Ok(mut g) = self.order.lock() {
            g.retain(|a| a != addr);
            g.push_back(*addr);
        }
        Some(plain)
    }

    pub fn put(&self, addr: &Addr, plain: &[u8]) -> Result<(), CacheError> {
        let sealed = seal(&self.key, plain, CACHE_AAD)?;
        let path = self.path(addr);
        fs::write(&path, sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let mut g = self.order.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|a| a != addr);
        g.push_back(*addr);
        while g.len() > self.cap {
            if let Some(old) = g.pop_front() {
                let _ = fs::remove_file(self.path(&old));
            }
        }
        Ok(())
    }

    /// On-disk files. Used by the stolen-disk drill: none of them may contain
    /// the plaintext marker.
    pub fn files(&self) -> Result<Vec<PathBuf>, CacheError> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                out.push(e.path());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("nas-cache-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn round_trip_and_lru_evicts() {
        let dir = scratch("lru");
        let c = ChunkCache::open(&dir, 2).unwrap();
        let a = Addr::of_ciphertext(&[1u8; 32]);
        let b = Addr::of_ciphertext(&[2u8; 32]);
        let d = Addr::of_ciphertext(&[3u8; 32]);
        c.put(&a, b"one").unwrap();
        c.put(&b, b"two").unwrap();
        c.put(&d, b"three").unwrap();
        assert_eq!(c.get(&b).as_deref(), Some(&b"two"[..]));
        assert_eq!(c.get(&d).as_deref(), Some(&b"three"[..]));
        assert!(c.get(&a).is_none(), "oldest entry must be evicted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stolen_file_is_not_plaintext() {
        let dir = scratch("steal");
        let c = ChunkCache::open(&dir, 4).unwrap();
        let a = Addr::of_ciphertext(&[9u8; 32]);
        let marker = b"CACHE-PLAINTEXT-MARKER";
        c.put(&a, marker).unwrap();
        let stored = fs::read(c.path(&a)).unwrap();
        assert!(
            !stored.windows(marker.len()).any(|w| w == marker),
            "cache file contained the plaintext"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_boot_cannot_read_the_old_cache() {
        let dir = scratch("boot");
        let a = Addr::of_ciphertext(&[4u8; 32]);
        {
            let c = ChunkCache::open(&dir, 4).unwrap();
            c.put(&a, b"secret").unwrap();
        }
        let c2 = ChunkCache::open(&dir, 4).unwrap();
        assert!(c2.get(&a).is_none(), "previous boot's key must not open");
        let _ = fs::remove_dir_all(&dir);
    }
}
