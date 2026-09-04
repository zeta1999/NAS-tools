#![no_main]
//! `SlotHandoff` (SPECS §5.1) arrives from the **untrusted peer**: a client
//! walking a chain across an ownership change asks for the handoffs and is
//! handed whatever the peer likes.
//!
//! A parser bug here is worse than in most places, because this record is the
//! single thing standing between a handover and a takeover. A decoder that
//! could be crashed would deny the walk; one that could be confused into
//! producing a record whose fields differ from the signed bytes would let a
//! takeover pass as authorised.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_slots::{SlotHandoff, SlotId, WriterId};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = SlotHandoff::decode(data) {
        assert_eq!(
            h.encode().unwrap(),
            data,
            "decode accepted a non-canonical handoff"
        );
        // Whatever came off the wire, it is not authority unless it verifies.
        // (It may legitimately verify if the fuzzer found a real ML-DSA
        //  signature, which would be a break of the signature scheme rather
        //  than of this code.)
        if h.verify().is_err() {
            assert!(
                !h.authorises(h.slot_id, h.at_seq, h.from(), h.to),
                "an unverifiable handoff authorised a writer change"
            );
        }
        // A handoff to the writer that already holds the slot says nothing,
        // and must never decode into one that does.
        if h.from() == h.to {
            assert!(h.verify().is_err(), "a self-handoff verified");
        }
    }

    // Well-framed but arbitrary: gets past `decode_fields` so the width and
    // genesis checks are actually reached rather than short-circuited.
    if data.len() < 8 {
        return;
    }
    let take = |o: usize, n: usize| -> Vec<u8> { (0..n).map(|i| data[(o + i) % data.len()]).collect() };
    let framed = encode_fields(&[
        &take(0, 32),
        &take(32, 8),
        &take(40, 1952),
        &take(1992, 32),
        &take(2024, 3309),
    ])
    .unwrap();
    if let Ok(h) = SlotHandoff::decode(&framed) {
        assert_eq!(h.encode().unwrap(), framed);
        assert!(h.verify().is_err(), "an unsigned handoff verified");
        // And it authorises nothing, for any slot or sequence the bytes
        // happen to name.
        assert!(!h.authorises(h.slot_id, h.at_seq, h.from(), h.to));
        assert!(!h.authorises(SlotId::new(b"ns", b"other"), 0, h.from(), h.to));
        assert!(!h.authorises(h.slot_id, h.at_seq, h.from(), WriterId::from_bytes([0u8; 32])));
    }
});
