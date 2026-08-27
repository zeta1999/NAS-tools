#![no_main]
//! The decoder that panicked on a truncated final entry and silently dropped
//! trailing fields (MANUAL-TESTING.md §7b, §7c).
//!
//! Both bugs lived past the magic check, where the old proptest never reached.
//! This target spends most of its budget there, and additionally asserts tail
//! injectivity: appending anything must change the decode result.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_store::DirManifest;

fuzz_target!(|data: &[u8]| {
    let _ = DirManifest::decode(data);

    if data.is_empty() {
        return;
    }
    let n = (data[0] % 16) as usize;
    let body = &data[1..];
    let step = body.len() / n.max(1);
    let mut fields: Vec<&[u8]> = vec![b"NASD"];
    for i in 0..n {
        let lo = (i * step).min(body.len());
        let hi = ((i + 1) * step).min(body.len());
        fields.push(&body[lo..hi]);
    }
    let Ok(framed) = encode_fields(&fields) else { return };

    if let Ok(dm) = DirManifest::decode(&framed) {
        // What it accepted must be exactly what it would emit.
        let re = dm.encode().expect("a decoded manifest must re-encode");
        assert_eq!(re, framed, "decode accepted a non-canonical encoding");

        // Tail injectivity: the bug was that trailing fields were dropped.
        let mut longer = framed.clone();
        longer.extend_from_slice(&encode_fields(&[b"tail"]).unwrap());
        assert!(
            DirManifest::decode(&longer).is_err(),
            "trailing fields silently dropped"
        );
    }
});
