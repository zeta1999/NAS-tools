//! Chunk padding (SPECS §4.2.1).
//!
//! ```text
//! padded = le32(len) ‖ plaintext ‖ 0x00 × (class − 4 − len)
//! ```
//!
//! # The bug this module is written around
//!
//! The Lean model (`formal/lean/NasVerify/Transcript.lean`) proves
//! `unpad (pad cls x) = some x` **unconditionally** — but over `Nat`, whose
//! subtraction truncates at zero. Written literally in Rust, `class - 4 - len`
//! is `usize` arithmetic: when `len > class - 4` it underflows to a value near
//! 2⁶⁴ — a panic in debug, and in release a `Vec` resize request for 16
//! exabytes. The proof erases precisely the failure mode most likely to occur.
//!
//! So the fill is never computed by subtracting the length twice. A class is
//! *selected* by `class >= len + HEADER`, and only then is `class - need`
//! evaluated, where the selection has already established the inequality. When
//! no class fits, the result is [`PadError::TooLarge`] rather than a wrap.
//!
//! # Why unpadding validates
//!
//! The AEAD tag already catches tampering, so validating the padding looks
//! redundant. It is not. Everything a writer controls that a reader does not
//! check is a channel, and padding hands a writer two of them:
//!
//! 1. **The fill bytes.** They sit inside the authenticated blob and carry no
//!    information of their own, so a malicious writer can smuggle data through
//!    them while every reader's signature check still passes. Rejecting
//!    non-zero fill closes it for one scan of bytes already in cache.
//! 2. **The choice of class.** This one is larger and was missed at first. A
//!    five-byte payload fits the 32 KiB class, but nothing stopped a writer
//!    padding it into the 256 KiB class instead — so the class index encodes
//!    log2(ladder) bits per chunk, invisible to every reader. Worse, it defeats
//!    the length-hiding the profile exists for: a writer that always picks the
//!    class matching the true size range leaks exactly what padding was meant
//!    to hide. Requiring the **minimal** class closes it.
//!
//! Note what these two have in common: both are attacks by a *writer* against
//! a *reader*, which the AEAD cannot address at all — it authenticates that the
//! writer said this, not that what they said was well-formed.

use nas_core::PaddingProfile;
use std::borrow::Cow;

/// Bytes of length prefix ahead of the plaintext.
pub const HEADER: usize = 4;

/// Default size-class ladder (SPECS §4.2.1). A 64 KiB CDC average lands mostly
/// in the first two classes.
pub const LADDER: [usize; 4] = [32 << 10, 64 << 10, 128 << 10, 256 << 10];

/// The single class used by [`PaddingProfile::Fixed`].
pub const FIXED_CLASS: usize = 64 << 10;

/// Largest plaintext that [`PaddingProfile::Fixed`] can frame into one class.
///
/// The chunker uses this as its fixed cut size so the framed result is exactly
/// [`FIXED_CLASS`] — a 64 KiB cut would need 65540 bytes of frame and overflow
/// the class by four.
pub const FIXED_CHUNK: usize = FIXED_CLASS - HEADER;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PadError {
    /// No class in the profile is large enough to frame this plaintext. The
    /// error the Lean model cannot express.
    TooLarge { len: usize, largest_class: usize },
    /// Fewer bytes than the length prefix itself.
    Truncated { have: usize },
    /// The declared length runs past the end of the padded buffer.
    LengthOverrun { want: usize, have: usize },
    /// The padded buffer is not a valid size for its profile — a length leak
    /// that would otherwise pass silently.
    NotAClass { len: usize },
    /// Fill bytes were not all zero: a covert channel, or corruption the AEAD
    /// would not have caught because the writer authenticated it.
    DirtyFill { offset: usize },
    /// The payload was padded into a larger class than it needed. The *choice*
    /// of class is itself a channel, and a bigger one than the fill: see the
    /// module docs.
    NonMinimalClass { got: usize, minimal: usize },
}

impl std::fmt::Display for PadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len, largest_class } => {
                write!(
                    f,
                    "chunk of {len} B exceeds the largest class ({largest_class} B)"
                )
            }
            Self::Truncated { have } => {
                write!(f, "padded chunk is {have} B, shorter than its header")
            }
            Self::LengthOverrun { want, have } => {
                write!(f, "declared length {want} B exceeds the {have} B available")
            }
            Self::NotAClass { len } => write!(f, "padded chunk of {len} B is not a size class"),
            Self::DirtyFill { offset } => write!(f, "non-zero padding at offset {offset}"),
            Self::NonMinimalClass { got, minimal } => {
                write!(f, "padded to the {got} B class when {minimal} B would fit")
            }
        }
    }
}
impl std::error::Error for PadError {}

/// The class a payload of `len` bytes must be padded into.
///
/// The *only* admissible class, not merely a valid one — see the module docs.
pub fn minimal_class(profile: PaddingProfile, len: usize) -> Option<usize> {
    let need = len.checked_add(HEADER)?;
    classes(profile).iter().copied().find(|&c| c >= need)
}

/// Largest plaintext a profile can frame, or `None` when the profile does not
/// pad and so has no limit of its own.
///
/// This is load-bearing at a module boundary: the default chunker maximum is
/// 256 KiB and the top size class is also 256 KiB, so a full-size chunk needs
/// 262148 bytes of frame and does not fit. A chunker and a padding profile
/// chosen independently are therefore *not* compatible by default, which is
/// why [`ChunkerConfig::for_profile`](crate::ChunkerConfig::for_profile)
/// exists and why the object writer refuses a mismatched pair up front rather
/// than failing on whichever chunk first happens to be large.
pub fn max_plaintext(profile: PaddingProfile) -> Option<usize> {
    let cls = classes(profile);
    cls.last().map(|c| c - HEADER)
}

/// The size classes a profile admits, in ascending order.
fn classes(profile: PaddingProfile) -> &'static [usize] {
    match profile {
        PaddingProfile::None => &[],
        PaddingProfile::Classes => &LADDER,
        PaddingProfile::Fixed => &[FIXED_CLASS],
    }
}

/// Frame and pad a chunk.
///
/// [`PaddingProfile::None`] borrows: no framing, no copy, no overhead.
///
/// Padding is **deterministic** — identical plaintext must yield identical
/// bytes, or convergent encryption silently stops deduplicating (SPECS §4.2.1).
pub fn pad(profile: PaddingProfile, plaintext: &[u8]) -> Result<Cow<'_, [u8]>, PadError> {
    let cls = classes(profile);
    if cls.is_empty() {
        return Ok(Cow::Borrowed(plaintext));
    }

    // `need` cannot overflow in practice, but a checked add costs nothing and
    // keeps the comparison below meaningful for any input.
    let len = plaintext.len();
    let need = len.checked_add(HEADER).ok_or(PadError::TooLarge {
        len,
        largest_class: cls[cls.len() - 1],
    })?;

    // SELECT a class, never subtract to find one.
    let class = *cls.iter().find(|&&c| c >= need).ok_or(PadError::TooLarge {
        len,
        largest_class: cls[cls.len() - 1],
    })?;

    // Only now is subtraction safe, and it is safe *because* of the predicate
    // that selected `class` — not because a comment says so.
    debug_assert!(class >= need);
    let mut out = Vec::with_capacity(class);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(class, 0);
    Ok(Cow::Owned(out))
}

/// Recover the plaintext from a padded chunk, validating the frame.
pub fn unpad(profile: PaddingProfile, padded: &[u8]) -> Result<&[u8], PadError> {
    let cls = classes(profile);
    if cls.is_empty() {
        return Ok(padded);
    }
    if !cls.contains(&padded.len()) {
        return Err(PadError::NotAClass { len: padded.len() });
    }
    if padded.len() < HEADER {
        return Err(PadError::Truncated { have: padded.len() });
    }

    let mut le = [0u8; HEADER];
    le.copy_from_slice(&padded[..HEADER]);
    let want = u32::from_le_bytes(le) as usize;

    let end = want.checked_add(HEADER).ok_or(PadError::LengthOverrun {
        want,
        have: padded.len() - HEADER,
    })?;
    if end > padded.len() {
        return Err(PadError::LengthOverrun {
            want,
            have: padded.len() - HEADER,
        });
    }

    if let Some(i) = padded[end..].iter().position(|&b| b != 0) {
        return Err(PadError::DirtyFill { offset: end + i });
    }
    // The class must be the smallest one that fits, not merely one that does.
    match minimal_class(profile, want) {
        Some(m) if m == padded.len() => {}
        Some(m) => {
            return Err(PadError::NonMinimalClass {
                got: padded.len(),
                minimal: m,
            })
        }
        // `want` cannot be framed at all, yet arrived inside a class: the
        // length prefix is lying about a payload this buffer cannot hold.
        None => {
            return Err(PadError::LengthOverrun {
                want,
                have: padded.len() - HEADER,
            })
        }
    }
    Ok(&padded[HEADER..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const P: PaddingProfile = PaddingProfile::Classes;

    #[test]
    fn the_underflow_the_lean_proof_cannot_see() {
        // `class - 4 - len` for the largest class and a plaintext four bytes
        // too long. In Lean this truncates to 0 and the theorem still holds.
        // Here it must be an error, not a panic and not a 2⁶⁴ allocation.
        let largest = LADDER[LADDER.len() - 1];
        let too_big = vec![0xAAu8; largest - HEADER + 1];
        assert_eq!(
            pad(P, &too_big),
            Err(PadError::TooLarge {
                len: largest - HEADER + 1,
                largest_class: largest
            })
        );
    }

    #[test]
    fn boundaries_of_every_class() {
        for (i, &class) in LADDER.iter().enumerate() {
            // Exactly fills the class: fill length zero, the case that
            // underflows one byte later.
            let exact = vec![1u8; class - HEADER];
            let p = pad(P, &exact).unwrap();
            assert_eq!(p.len(), class, "class {class}: exact fit");
            assert_eq!(unpad(P, &p).unwrap(), &exact[..]);

            // One byte more must land in the NEXT class, or be refused if
            // there is no next class.
            let over = vec![1u8; class - HEADER + 1];
            match pad(P, &over) {
                Ok(p) => {
                    assert_eq!(p.len(), LADDER[i + 1], "class {class}: +1 promotes");
                    assert_eq!(unpad(P, &p).unwrap(), &over[..]);
                }
                Err(e) => {
                    assert_eq!(i, LADDER.len() - 1, "only the top class may refuse");
                    assert!(matches!(e, PadError::TooLarge { .. }));
                }
            }
        }
    }

    #[test]
    fn empty_and_one_byte_chunks() {
        for n in [0usize, 1, 2] {
            let pt = vec![9u8; n];
            let p = pad(P, &pt).unwrap();
            assert_eq!(p.len(), LADDER[0]);
            assert_eq!(unpad(P, &p).unwrap(), &pt[..]);
        }
    }

    #[test]
    fn the_default_chunk_maximum_does_not_fit_the_top_class() {
        // The boundary bug this constant exists to make visible: 256 KiB of
        // plaintext needs 256 KiB + 4 of frame, and there is no larger class.
        assert_eq!(max_plaintext(P), Some((256 << 10) - HEADER));
        assert!(pad(P, &vec![0u8; 256 << 10]).is_err());
        assert_eq!(max_plaintext(PaddingProfile::None), None);
        assert_eq!(max_plaintext(PaddingProfile::Fixed), Some(FIXED_CHUNK));
    }

    #[test]
    fn padding_is_deterministic() {
        // If this fails, dedup degrades to zero silently rather than loudly.
        let pt = b"identical plaintext".repeat(100);
        assert_eq!(pad(P, &pt).unwrap(), pad(P, &pt).unwrap());
    }

    #[test]
    fn none_is_identity_and_free() {
        let pt = b"unpadded";
        let p = pad(PaddingProfile::None, pt).unwrap();
        assert!(matches!(p, Cow::Borrowed(_)), "None must not copy");
        assert_eq!(&p[..], pt);
        assert_eq!(unpad(PaddingProfile::None, pt).unwrap(), pt);
    }

    #[test]
    fn fixed_chunk_size_frames_to_exactly_one_class() {
        let pt = vec![3u8; FIXED_CHUNK];
        let p = pad(PaddingProfile::Fixed, &pt).unwrap();
        assert_eq!(p.len(), FIXED_CLASS);
        assert_eq!(unpad(PaddingProfile::Fixed, &p).unwrap(), &pt[..]);
        // One more byte has no larger class to be promoted into.
        assert!(pad(PaddingProfile::Fixed, &vec![3u8; FIXED_CHUNK + 1]).is_err());
    }

    #[test]
    fn a_covert_channel_in_the_fill_is_rejected() {
        let mut p = pad(P, b"short").unwrap().into_owned();
        let last = p.len() - 1;
        p[last] = 0x01; // a bit of smuggled data the AEAD would authenticate
        assert_eq!(unpad(P, &p), Err(PadError::DirtyFill { offset: last }));
    }

    #[test]
    fn a_lying_length_prefix_is_rejected_not_trusted() {
        let mut p = pad(P, b"short").unwrap().into_owned();
        p[..HEADER].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(unpad(P, &p), Err(PadError::LengthOverrun { .. })));
    }

    #[test]
    fn a_covert_channel_in_the_class_choice_is_rejected() {
        // The larger of the two writer-side channels: ~2 bits per chunk with
        // this ladder, and a direct defeat of the length hiding that is the
        // whole purpose of padding.
        let payload = b"short";
        let minimal = pad(P, payload).unwrap();
        assert_eq!(minimal.len(), LADDER[0]);

        for &bigger in &LADDER[1..] {
            let mut hand = Vec::with_capacity(bigger);
            hand.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            hand.extend_from_slice(payload);
            hand.resize(bigger, 0);
            // Every check except minimality passes: it is a valid class, the
            // length prefix is honest, and the fill is all zeros.
            assert_eq!(
                unpad(P, &hand),
                Err(PadError::NonMinimalClass {
                    got: bigger,
                    minimal: LADDER[0]
                }),
                "class {bigger} accepted for a {} B payload",
                payload.len()
            );
        }
    }

    #[test]
    fn every_legitimately_padded_chunk_still_passes_the_strict_check() {
        // The check must not reject the writer's own output. Boundaries first,
        // since those are where a minimality check is most likely to be wrong.
        for &class in LADDER.iter() {
            for len in [0usize, 1, class - HEADER - 1, class - HEADER] {
                let pt = vec![7u8; len];
                let Ok(p) = pad(P, &pt) else { continue };
                assert_eq!(unpad(P, &p).unwrap(), &pt[..], "len {len}, class {class}");
            }
        }
    }

    #[test]
    fn a_non_class_size_is_rejected() {
        // Otherwise a writer could leak the true length by picking its own size.
        let p = vec![0u8; LADDER[0] + 1];
        assert_eq!(
            unpad(P, &p),
            Err(PadError::NotAClass { len: LADDER[0] + 1 })
        );
        assert_eq!(unpad(P, &[]), Err(PadError::NotAClass { len: 0 }));
    }

    proptest! {
        #[test]
        fn roundtrip(pt in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let p = pad(P, &pt).unwrap();
            prop_assert_eq!(unpad(P, &p).unwrap(), &pt[..]);
        }

        #[test]
        fn unpad_never_panics(junk in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = unpad(P, &junk);
            let _ = unpad(PaddingProfile::Fixed, &junk);
            let _ = unpad(PaddingProfile::None, &junk);
        }

        #[test]
        fn padded_length_is_always_a_class(pt in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let p = pad(P, &pt).unwrap();
            prop_assert!(LADDER.contains(&p.len()));
            prop_assert!(p.len() >= pt.len() + HEADER);
        }
    }
}
