#![no_main]
//! Padding is written by whoever holds the write capability and read by
//! everyone else, so `unpad` is a reader's defence against a *writer* — a class
//! of attack the AEAD cannot address at all, since it authenticates that the
//! writer said this, not that what they said was well-formed.
use libfuzzer_sys::fuzz_target;
use nas_core::PaddingProfile;
use nas_store::padding::{pad, unpad};

fuzz_target!(|data: &[u8]| {
    for profile in [PaddingProfile::None, PaddingProfile::Classes, PaddingProfile::Fixed] {
        // Anything accepted must round-trip back to itself.
        if let Ok(p) = unpad(profile, data) {
            let owned = p.to_vec();
            let repadded = pad(profile, &owned).expect("an accepted payload must be paddable");
            assert_eq!(&repadded[..], data, "unpad accepted a non-canonical encoding");
        }
        // And anything the padder produces must be accepted.
        if let Ok(p) = pad(profile, data) {
            assert_eq!(unpad(profile, &p).unwrap(), data, "honest output rejected");
        }
    }
});
