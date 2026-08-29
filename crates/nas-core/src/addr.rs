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

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::BadLength(n) => write!(f, "address must be {ADDR_LEN} bytes, got {n}"),
            AddrError::NotHex => f.write_str("address is not valid hex"),
        }
    }
}

impl std::error::Error for AddrError {}

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

    /// Parse a 64-character hex address.
    ///
    /// # Why this works on bytes rather than on `&str` slices
    ///
    /// `s.len()` is a count of **bytes**, and `&s[i*2..i*2+2]` panics if either
    /// index falls inside a multibyte character. A 64-*byte* string of 33
    /// characters therefore passed the length check and then panicked on the
    /// first slice — and that path is reachable from untrusted input:
    /// `BlobStore::addrs` builds this string from **peer-controlled** blob
    /// directory names and relies on the `Err` branch to skip junk. The panic
    /// fires before any `Result` exists, so a peer could crash the lease sweep
    /// by dropping in one well-chosen filename.
    ///
    /// Parsing the byte slice removes the char-boundary question entirely, and
    /// any non-ASCII byte simply fails the hex check.
    pub fn from_hex(s: &str) -> Result<Self, AddrError> {
        let b = s.as_bytes();
        if b.len() != ADDR_LEN * 2 {
            return Err(AddrError::BadLength(b.len()));
        }
        let mut out = [0u8; ADDR_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_val(b[i * 2]).ok_or(AddrError::NotHex)?;
            let lo = hex_val(b[i * 2 + 1]).ok_or(AddrError::NotHex)?;
            *byte = (hi << 4) | lo;
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

/// One hex digit, or `None`. Lower case only: `to_hex` emits lower case, so
/// accepting upper case would make two spellings of one address and give the
/// blob store two paths for the same content.
const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
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
    fn a_64_byte_multibyte_string_is_an_error_not_a_panic() {
        // Reachable from untrusted input: BlobStore::addrs builds this string
        // from peer-controlled directory entries and relies on the Err branch
        // to skip junk. Before this test, the slice panicked before any Result
        // existed and a peer could crash the lease sweep with one filename.
        let s = format!("a{}a", "\u{e9}".repeat(31));
        assert_eq!(s.len(), 64, "the probe must pass the byte-length check");
        assert_ne!(s.chars().count(), 64, "and must not be 64 characters");
        assert_eq!(Addr::from_hex(&s), Err(AddrError::NotHex));
    }

    #[test]
    fn uppercase_hex_is_refused_so_one_address_has_one_spelling() {
        let a = Addr::of_ciphertext(b"x");
        let lower = a.to_hex();
        assert_eq!(Addr::from_hex(&lower).unwrap(), a);
        assert_eq!(
            Addr::from_hex(&lower.to_uppercase()),
            Err(AddrError::NotHex)
        );
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

    proptest::proptest! {
        /// Arbitrary text, including multibyte. There was no proptest here
        /// before and the two hand-written cases were both ASCII, which is
        /// exactly why the char-boundary panic survived.
        #[test]
        fn from_hex_never_panics(s in ".*") {
            let _ = Addr::from_hex(&s);
        }

        /// Arbitrary bytes rendered as hex always parse back.
        #[test]
        fn hex_round_trips(b in proptest::array::uniform32(proptest::num::u8::ANY)) {
            let a = Addr::from_bytes(b);
            proptest::prop_assert_eq!(Addr::from_hex(&a.to_hex()).unwrap(), a);
        }
    }
}
