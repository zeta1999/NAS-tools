//! The one place randomness enters the system.
//!
//! Read straight from the kernel CSPRNG. Centralised rather than scattered so
//! there is a single answer to "where does this key's entropy come from", and
//! so an all-zero read — the failure mode that silently produces a key everyone
//! can guess — is checked once rather than in each caller.

use std::fs::File;
use std::io::{self, Read};

/// Fill `out` with cryptographically secure random bytes.
///
/// # Errors
///
/// A short read or an all-zero result is an error, never a partial success. A
/// caller that got half a key and no error would produce something that looks
/// like a key and is not one.
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(out)?;
    if out.iter().all(|&b| b == 0) {
        return Err(io::Error::other("CSPRNG returned all zeros"));
    }
    Ok(())
}

/// A fresh random array.
pub fn array<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successive_reads_differ() {
        // Not a randomness test -- a wiring test. If this ever fails, the
        // source is stuck, which is the failure that matters.
        let a: [u8; 32] = array().unwrap();
        let b: [u8; 32] = array().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn an_empty_request_is_fine() {
        fill(&mut []).unwrap();
    }

    #[test]
    fn various_sizes_are_filled() {
        for n in [1usize, 7, 24, 32, 64, 1024] {
            let mut v = vec![0u8; n];
            fill(&mut v).unwrap();
            assert!(v.iter().any(|&b| b != 0), "{n} bytes came back all zero");
        }
    }
}
