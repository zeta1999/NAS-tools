//! HMAC-SHA256. SigV4 cannot use BLAKE3: AWS specifies SHA-256.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Constant-time equality. Length mismatch is not secret; the bytes are.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_1() {
        // key = 20 × 0x0b, data = "Hi There"
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex_encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn ct_eq_does_not_short_circuit_on_the_first_difference() {
        // Behaviour, not timing: a length mismatch is an immediate no, and
        // equal-length unequal buffers compare every byte (the fold).
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(ct_eq(b"abc", b"abc"));
    }
}
