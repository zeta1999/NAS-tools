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

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64. Used for WebDAV Basic (SPECS §2.1), not for ciphertext.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(B64[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let v0 = b64_val(raw[i])?;
        let v1 = b64_val(raw[i + 1])?;
        let v2 = if raw[i + 2] == b'=' {
            0
        } else {
            b64_val(raw[i + 2])?
        };
        let v3 = if raw[i + 3] == b'=' {
            0
        } else {
            b64_val(raw[i + 3])?
        };
        out.push((v0 << 2) | (v1 >> 4));
        if raw[i + 2] != b'=' {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if raw[i + 3] != b'=' {
            out.push((v2 << 6) | v3);
        }
        i += 4;
    }
    Some(out)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
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

    #[test]
    fn b64_round_trips() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(b64_decode("Zm8=").as_deref(), Some(&b"fo"[..]));
        assert_eq!(b64_decode("Zm9v").as_deref(), Some(&b"foo"[..]));
        let long = b"access:secret-with-padding";
        assert_eq!(b64_decode(&b64_encode(long)).as_deref(), Some(&long[..]));
    }
}
