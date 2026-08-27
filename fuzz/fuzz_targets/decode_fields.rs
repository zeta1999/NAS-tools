#![no_main]
//! The canonical length-prefixed decoder — the parser every other one sits on.
//!
//! Two properties: it must not panic, and it must be injective. Injectivity is
//! the Lean theorem `encFields_inj`; this checks the implementation agrees, by
//! re-encoding whatever was decoded and requiring the bytes back.
use libfuzzer_sys::fuzz_target;
use nas_core::{decode_fields, encode_fields};

fuzz_target!(|data: &[u8]| {
    if let Ok(fields) = decode_fields(data) {
        let round = encode_fields(&fields).expect("decoded fields must re-encode");
        assert_eq!(round, data, "decode/encode is not injective");
    }
});
