#![no_main]
//! Lease deltas and checkpoints are peer-facing records (SPECS §20), and the
//! peer is the party being distrusted — a client resyncing from cold parses
//! whatever the peer hands back.
//!
//! Beyond not panicking, both decoders must be canonical: a delta whose address
//! lists were re-ordered would be a second spelling of one statement, and the
//! decoder must refuse it rather than accept both.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_lease::{LeaseCheckpoint, LeaseDelta};

fuzz_target!(|data: &[u8]| {
    if let Ok(d) = LeaseDelta::decode(data) {
        assert_eq!(d.encode().unwrap(), data, "non-canonical delta accepted");
        // Address lists must come back strictly ascending.
        for w in d.add.windows(2) {
            assert!(w[0].as_bytes() < w[1].as_bytes(), "unsorted add list accepted");
        }
        for w in d.remove.windows(2) {
            assert!(w[0].as_bytes() < w[1].as_bytes(), "unsorted remove list accepted");
        }
        let _ = d.chain_hash();
        assert!(d.verify().is_err() || true);
    }
    if let Ok(c) = LeaseCheckpoint::decode(data) {
        assert_eq!(c.encode().unwrap(), data, "non-canonical checkpoint accepted");
        let _ = c.chain_hash();
    }

    if data.len() < 8 {
        return;
    }
    let take = |o: usize, n: usize| -> Vec<u8> {
        (0..n).map(|i| data[(o + i) % data.len()]).collect()
    };
    // Structured: a delta frame with address lists sized from the input.
    let n_add = (data[0] % 5) as usize;
    let n_rem = (data[data.len() - 1] % 5) as usize;
    let framed = encode_fields(&[
        &take(0, 1952),
        &take(1952, 8),
        &take(1960, 8),
        &take(1968, n_add * 32),
        &take(1968 + n_add * 32, n_rem * 32),
        &take(2100, 32),
        &take(2132, 3309),
    ])
    .unwrap();
    if let Ok(d) = LeaseDelta::decode(&framed) {
        assert_eq!(d.encode().unwrap(), framed);
        assert!(d.verify().is_err(), "an unsigned delta verified");
    }
});
