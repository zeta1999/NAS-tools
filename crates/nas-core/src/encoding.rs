//! Canonical length-prefixed encoding.
//!
//! Every signed object in this system is signed over a concatenation of fields.
//! The security of that rests on one property: **the encoding must be
//! injective**. If two different field sequences could produce the same bytes, a
//! signature over one could be reinterpreted as a signature over the other —
//! `("AB", "C")` colliding with `("A", "BC")`.
//!
//! This is the Rust counterpart of `formal/lean/NasVerify/Transcript.lean`,
//! which proves injectivity for the abstract scheme. The proof constrains the
//! design; the property tests below constrain *this code*, which is where the
//! two can drift apart — see `MANUAL-TESTING.md` on why that gap is not
//! theoretical.

/// Width of the length prefix. The injectivity argument does not depend on the
/// width, only on it being fixed and recoverable.
const LEN_PREFIX: usize = 4;

/// Largest field this encoding can represent.
pub const MAX_FIELD: usize = u32::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended in the middle of a length prefix or a field body.
    Truncated,
    /// A length prefix promised more bytes than the input holds. This is the
    /// shape a malicious peer reaches for first, so it is a named error rather
    /// than a panic.
    LengthOverrun { want: usize, have: usize },
    /// Field exceeds what a u32 prefix can express.
    FieldTooLarge(usize),
}

/// Append one length-prefixed field.
///
/// The prefix is what makes the encoding unambiguous: without it, two different
/// field splits can produce identical bytes.
pub fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), DecodeError> {
    if field.len() > MAX_FIELD {
        return Err(DecodeError::FieldTooLarge(field.len()));
    }
    out.extend_from_slice(&(field.len() as u32).to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Encode a sequence of fields.
pub fn encode_fields(fields: &[&[u8]]) -> Result<Vec<u8>, DecodeError> {
    let cap = fields.iter().map(|f| f.len() + LEN_PREFIX).sum();
    let mut out = Vec::with_capacity(cap);
    for f in fields {
        push_field(&mut out, f)?;
    }
    Ok(out)
}

/// Decode one field, returning it and the unconsumed remainder.
///
/// Returning the remainder is what makes the encoding self-delimiting: a reader
/// never has to guess where a field ends. This mirrors `decField_encField` in
/// the Lean development.
pub fn decode_field(input: &[u8]) -> Result<(&[u8], &[u8]), DecodeError> {
    if input.len() < LEN_PREFIX {
        return Err(DecodeError::Truncated);
    }
    let (prefix, rest) = input.split_at(LEN_PREFIX);
    let want = u32::from_le_bytes(prefix.try_into().expect("split_at guarantees 4")) as usize;
    if rest.len() < want {
        return Err(DecodeError::LengthOverrun {
            want,
            have: rest.len(),
        });
    }
    Ok(rest.split_at(want))
}

/// Decode a complete field sequence. Trailing bytes are an error, not a
/// tolerated remainder — accepting them would break injectivity at the tail.
pub fn decode_fields(mut input: &[u8]) -> Result<Vec<&[u8]>, DecodeError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (field, rest) = decode_field(input)?;
        out.push(field);
        input = rest;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn different_splits_do_not_collide() {
        // The concrete case the length prefix exists to prevent.
        let a = encode_fields(&[b"AB", b"C"]).unwrap();
        let b = encode_fields(&[b"A", b"BC"]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_fields_are_distinguishable() {
        assert_ne!(
            encode_fields(&[b"", b""]).unwrap(),
            encode_fields(&[b""]).unwrap()
        );
        assert_ne!(encode_fields(&[b""]).unwrap(), encode_fields(&[]).unwrap());
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        assert_eq!(decode_field(&[0, 0, 0]), Err(DecodeError::Truncated));
        // A prefix claiming 16 bytes with none following: the first thing a
        // hostile peer tries.
        let mut evil = 16u32.to_le_bytes().to_vec();
        evil.extend_from_slice(b"short");
        assert!(matches!(
            decode_field(&evil),
            Err(DecodeError::LengthOverrun { want: 16, have: 5 })
        ));
    }

    proptest! {
        /// Round-trip. This is the operational form of `decField_encField`.
        #[test]
        fn roundtrip(fields in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..12)) {
            let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
            let encoded = encode_fields(&refs).unwrap();
            prop_assert_eq!(decode_fields(&encoded).unwrap(), refs);
        }

        /// Injectivity, the property `encFields_inj` proves abstractly: distinct
        /// field sequences never encode alike.
        #[test]
        fn injective(
            a in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..24), 0..6),
            b in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..24), 0..6),
        ) {
            let ra: Vec<&[u8]> = a.iter().map(|f| f.as_slice()).collect();
            let rb: Vec<&[u8]> = b.iter().map(|f| f.as_slice()).collect();
            let ea = encode_fields(&ra).unwrap();
            let eb = encode_fields(&rb).unwrap();
            prop_assert_eq!(a == b, ea == eb);
        }

        /// Never panics on adversarial input. `nas-peer` is assumed hostile, so
        /// everything it hands us reaches this function.
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode_fields(&bytes);
        }
    }
}
