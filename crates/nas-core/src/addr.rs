//! Content addresses.
//!
//! An address is `BLAKE3(ciphertext)` — never of the plaintext. Addressing the
//! ciphertext is what lets an untrusted peer verify and repair its own blobs by
//! recomputing a hash, with no capability granted and nothing revealed. Tahoe's
//! separate verify-cap is unnecessary as a result (SPECS §3.4).

use core::fmt;

pub const ADDR_LEN: usize = 32;

/// A content address: BLAKE3 over the **ciphertext**.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr([u8; ADDR_LEN]);

#[derive(Debug, PartialEq, Eq)]
pub enum AddrError {
    BadLength(usize),
    NotHex,
}

impl Addr {
    /// Compute the address of a sealed blob.
    ///
    /// Takes ciphertext by construction of the name: passing plaintext here
    /// would leak a confirmation oracle to anyone holding a candidate file.
    pub fn of_ciphertext(ciphertext: &[u8]) -> Self {
        Self(*blake3::hash(ciphertext).as_bytes())
    }

    pub fn from_bytes(b: [u8; ADDR_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; ADDR_LEN] {
        &self.0
    }

    /// Verify a blob against this address. Constant-time is unnecessary — the
    /// address is public — but a mismatch must be a hard error at every call
    /// site, so this returns `bool` rather than being easy to ignore.
    #[must_use]
    pub fn verifies(&self, ciphertext: &[u8]) -> bool {
        Self::of_ciphertext(ciphertext) == *self
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(ADDR_LEN * 2);
        for b in self.0 {
            use fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn from_hex(s: &str) -> Result<Self, AddrError> {
        if s.len() != ADDR_LEN * 2 {
            return Err(AddrError::BadLength(s.len()));
        }
        let mut out = [0u8; ADDR_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| AddrError::NotHex)?;
        }
        Ok(Self(out))
    }

    /// Shard path components: `blobs/<ab>/<cdef…>` (SPECS §4).
    ///
    /// Two hex characters gives 256 directories, which keeps directory sizes
    /// workable on filesystems that degrade with very large directories.
    pub fn shard(self) -> (String, String) {
        let hex = self.to_hex();
        let (a, b) = hex.split_at(2);
        (a.to_string(), b.to_string())
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form: addresses are public, but full hashes make logs unreadable.
        write!(f, "Addr({}…)", &self.to_hex()[..12])
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_over_ciphertext_and_verifies() {
        let a = Addr::of_ciphertext(b"sealed bytes");
        assert!(a.verifies(b"sealed bytes"));
        assert!(!a.verifies(b"sealed byteS"));
    }

    #[test]
    fn hex_roundtrip_and_shard() {
        let a = Addr::of_ciphertext(b"x");
        assert_eq!(Addr::from_hex(&a.to_hex()).unwrap(), a);
        let (dir, rest) = a.shard();
        assert_eq!(dir.len(), 2);
        assert_eq!(dir.len() + rest.len(), ADDR_LEN * 2);
    }

    #[test]
    fn malformed_hex_is_an_error_not_a_panic() {
        assert_eq!(Addr::from_hex("").unwrap_err(), AddrError::BadLength(0));
        assert_eq!(
            Addr::from_hex(&"z".repeat(64)).unwrap_err(),
            AddrError::NotHex
        );
    }

    #[test]
    fn debug_is_abbreviated() {
        let rendered = format!("{:?}", Addr::of_ciphertext(b"x"));
        assert!(rendered.contains('…'), "{rendered}");
    }
}
