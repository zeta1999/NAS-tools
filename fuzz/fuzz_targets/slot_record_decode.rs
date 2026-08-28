#![no_main]
//! A peer-facing record format. SPECS §20 lists the peer's plaintext record
//! types as **format-breaking to change once written**, so they get fuzzed
//! while they are still cheap to fix rather than after M1 freezes them.
//!
//! Half the budget goes to structured input, because a slot record is 3502
//! bytes of mostly fixed-width fields and raw mutation almost never produces a
//! decodable one — the same reason a proptest missed two live panics in the
//! directory decoder.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_slots::SlotRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = SlotRecord::decode(data) {
        // Canonical form: whatever decode accepts must re-encode identically.
        assert_eq!(r.encode().unwrap(), data, "decode accepted a non-canonical record");
        // record_hash must not panic on anything decode accepted.
        let _ = r.record_hash();
        let _ = r.sig_hash();
    }

    if data.len() < 8 {
        return;
    }
    // Structured: fixed-width fields taken from the input, so the decoder is
    // reached past its width checks.
    let take = |o: usize, n: usize| -> Vec<u8> {
        (0..n).map(|i| data[(o + i) % data.len()]).collect()
    };
    let framed = encode_fields(&[
        &take(0, 32),
        &take(32, 8),
        &take(40, 32),
        &take(72, 24),
        &take(96, 32),
        &take(128, 32),
        &take(160, 1),
        &take(161, 3309),
    ])
    .unwrap();
    if let Ok(r) = SlotRecord::decode(&framed) {
        assert_eq!(r.encode().unwrap(), framed);
    }
});
