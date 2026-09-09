#![no_main]
//! Witnesses arrive **relayed by the untrusted peer** (SPECS §5.3), so this
//! decoder sees hostile bytes by design. It is also the one place where a
//! parser bug would be worst: a witness is the input to fork detection, and a
//! peer that could crash or confuse it would silence the alarm.
//!
//! v2 witnesses carry a `prev`, so the decoder now also enforces the genesis
//! rule and a `ForkProof` may carry a link the recipient re-walks. Both are
//! exercised here: the walk runs over bytes the peer chose.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_slots::{ForkProof, Witness};

fuzz_target!(|data: &[u8]| {
    if let Ok(w) = Witness::decode(data) {
        assert_eq!(w.encode().unwrap(), data, "decode accepted a non-canonical witness");
        // A witness the peer supplied must not verify unless it was signed.
        // (It may legitimately verify if the fuzzer found a real signature,
        //  which is a break of ML-DSA rather than of this code.)
        let _ = w.verify();
        // A witness cannot conflict with itself, in either shape.
        assert!(ForkProof::try_new(&w, &w).is_none(), "a witness forked against itself");
        assert!(
            ForkProof::try_linked(&w, &w, vec![]).is_none(),
            "a witness linked against itself"
        );
        assert!(
            ForkProof::try_linked(&w, &w, vec![w.clone()]).is_none(),
            "a witness linked against itself through itself"
        );
    }

    if data.len() < 8 {
        return;
    }
    let take = |o: usize, n: usize| -> Vec<u8> {
        (0..n).map(|i| data[(o + i) % data.len()]).collect()
    };
    // A well-framed v2 witness with hostile field contents: 1952 pk, 32 slot,
    // 8 seq, 32 record_hash, 32 prev, 8 logical_time, 3309 sig.
    let framed = encode_fields(&[
        &take(0, 1952),
        &take(1952, 32),
        &take(1984, 8),
        &take(1992, 32),
        &take(2024, 32),
        &take(2056, 8),
        &take(2064, 3309),
    ])
    .unwrap();
    if let Ok(w) = Witness::decode(&framed) {
        assert_eq!(w.encode().unwrap(), framed);
        assert!(w.verify().is_err(), "an unsigned witness verified");
        // The genesis rule holds on everything that got through the door.
        assert_eq!(
            w.seq == 0,
            w.prev.iter().all(|&b| b == 0),
            "decode admitted a witness that breaks the genesis rule"
        );
    }

    // The same bytes as a v1 witness — six fields — must be refused with the
    // version error rather than decoded as something it is not.
    let v1 = encode_fields(&[
        &take(0, 1952),
        &take(1952, 32),
        &take(1984, 8),
        &take(1992, 32),
        &take(2024, 8),
        &take(2032, 3309),
    ])
    .unwrap();
    assert!(Witness::decode(&v1).is_err(), "a v1 witness decoded as v2");
});
