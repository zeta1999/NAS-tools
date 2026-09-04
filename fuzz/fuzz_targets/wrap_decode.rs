#![no_main]
//! The wrap record is stored **on the peer** (SPECS §2.2.2), so this decoder
//! reads bytes the adversary holds. It is also the most sensitive one in the
//! system: the record *is* the capability for passphrase mode, carrying both the
//! wrapped key and the freshness anchor beneath which nothing is accepted.
//!
//! A decoder bug here would be a way to hand a recovering client a lowered
//! floor, which is the exact rollback §5.3(1) exists to close.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_vault::{Argon2Params, WrapPolicy, WrapRecord};

/// Bytes laid out as the decoder's field widths expect.
///
/// Without this the target barely reaches the decoder: a signature is 3309
/// bytes, so raw fuzzer input essentially never satisfies the width check and
/// runs bail immediately. It sat at coverage 61 on four million runs — a green
/// target that was measuring how fast garbage is rejected.
fn framed(data: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let _ = data;
    encode_fields(parts).unwrap()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(w) = WrapRecord::decode(data) {
        assert_eq!(w.encode().unwrap(), data, "non-canonical wrap record accepted");
        let _ = w.chain_hash();
        // Unwrapping with an arbitrary passphrase must fail, not panic. Weak
        // stored parameters must be refused before any derivation is attempted,
        // so this cannot become an accidental Argon2 bomb.
        let _ = w.unwrap(b"not the passphrase", &WrapPolicy::SPEC);
        // Verification against a wrong-length key must be refused, not crash.
        assert!(w.verify_pk(&[0u8; 16]).is_err());
    }

    if data.is_empty() {
        return;
    }
    let take = |o: usize, n: usize| -> Vec<u8> {
        (0..n).map(|i| data[(o + i) % data.len()]).collect()
    };

    // Argon2 parameters the fuzzer chose, which is the point: the wrap record
    // lives on the peer (SPECS §2.2.2), so these numbers are the adversary's.
    // `check` must bound them in BOTH directions before any derivation is
    // attempted -- a floor alone leaves `memory_kib = u32::MAX` as a four
    // terabyte allocation the peer can ask for in one field.
    let params = Argon2Params {
        memory_kib: u32::from_le_bytes(take(0, 4).try_into().unwrap()),
        iterations: u32::from_le_bytes(take(4, 4).try_into().unwrap()),
        parallelism: u32::from_le_bytes(take(8, 4).try_into().unwrap()),
    };
    let bounded = params.check(&WrapPolicy::SPEC).is_ok();
    if bounded {
        assert!(params.memory_kib <= WrapPolicy::SPEC.max_memory_kib);
        assert!(params.iterations <= WrapPolicy::SPEC.max_iterations);
        assert_eq!(params.parallelism, 1);
    }

    let record = framed(
        data,
        &[
            &take(12, 32),          // salt
            &params.encode(),       // params, nested
            &take(44, 48),          // wrapped dek
            &take(92, 8),           // seq
            &take(100, 8),          // anchor seq
            &take(108, 32),         // anchor sig hash
            &take(140, 32),         // prev
            &take(172, 3309),       // sig
        ],
    );
    if let Ok(w) = WrapRecord::decode(&record) {
        assert_eq!(w.encode().unwrap(), record, "non-canonical wrap record accepted");
        let _ = w.chain_hash();
        // A derivation is only attempted under a budget this process can
        // actually afford. `WrapPolicy::SPEC`'s ceiling is 4 GiB -- generous
        // on purpose, because it bounds what a hostile peer may demand rather
        // than describing what a fuzzer can survive -- and libFuzzer runs
        // under a 2 GiB rss limit, so honouring the shipped policy here found
        // an OOM in this target rather than in the product. Guard with a
        // budget instead.
        const FUZZ_BUDGET: WrapPolicy = WrapPolicy {
            min_memory_kib: 8,
            min_iterations: 1,
            max_memory_kib: 64 * 1024,
            max_iterations: 4,
        };
        if w.params.check(&FUZZ_BUDGET).is_ok() {
            let _ = w.unwrap(b"not the passphrase", &FUZZ_BUDGET);
        }
        assert!(w.verify_pk(&[0u8; 16]).is_err());
    }
});
