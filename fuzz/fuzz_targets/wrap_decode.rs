#![no_main]
//! The wrap record is stored **on the peer** (SPECS §2.2.2), so this decoder
//! reads bytes the adversary holds. It is also the most sensitive one in the
//! system: the record *is* the capability for passphrase mode, carrying both the
//! wrapped key and the freshness anchor beneath which nothing is accepted.
//!
//! A decoder bug here would be a way to hand a recovering client a lowered
//! floor, which is the exact rollback §5.3(1) exists to close.
use libfuzzer_sys::fuzz_target;
use nas_vault::{WrapPolicy, WrapRecord};

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
});
