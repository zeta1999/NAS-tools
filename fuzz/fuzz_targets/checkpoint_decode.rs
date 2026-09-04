#![no_main]
//! `Checkpoint` (SPECS §5.5) is served by the **untrusted peer** to a client
//! that is too far behind to walk every record, which makes it the input to
//! the one path that deliberately verifies *less*.
//!
//! Two invariants matter beyond not crashing. The genesis rule — only the rung
//! at seq 0 may carry a zero back-link — is what stops a writer declaring a new
//! beginning halfway up and cutting the ladder. And `prev_seq` must be below
//! `seq`, or a verifier following the links would not terminate.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_slots::{verify_skip_chain, Checkpoint, Roster};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Checkpoint::decode(data) {
        assert_eq!(
            c.encode().unwrap(),
            data,
            "decode accepted a non-canonical checkpoint"
        );
        // The structural rules hold on anything that decoded, whether or not
        // the signature is real.
        assert_eq!(
            c.prev_hash == [0u8; 32],
            c.seq == 0,
            "a zero back-link away from genesis, or genesis with a back-link"
        );
        if c.seq != 0 {
            assert!(c.prev_seq < c.seq, "a checkpoint links forward or to itself");
        }
        let _ = c.verify_self();

        // An empty roster knows no writer, so no ladder built from peer bytes
        // can ever verify against it. This is the walk refusing rather than
        // the decoder, and it must refuse for every input.
        assert!(
            verify_skip_chain(
                std::slice::from_ref(&c),
                &[],
                c.slot_id,
                &Roster::new(),
                None,
                &[]
            )
            .is_err(),
            "a ladder verified against a roster naming nobody"
        );
    }

    if data.len() < 8 {
        return;
    }
    let take = |o: usize, n: usize| -> Vec<u8> { (0..n).map(|i| data[(o + i) % data.len()]).collect() };
    let framed = encode_fields(&[
        &take(0, 32),
        &take(32, 8),
        &take(40, 32),
        &take(72, 8),
        &take(80, 32),
        &take(112, 1952),
        &take(2064, 3309),
    ])
    .unwrap();
    if let Ok(c) = Checkpoint::decode(&framed) {
        assert_eq!(c.encode().unwrap(), framed);
        assert!(c.verify_self().is_err(), "an unsigned checkpoint verified");
    }
});
