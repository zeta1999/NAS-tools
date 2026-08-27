#![no_main]
//! Every blob a peer serves reaches `open` before anything else looks at it.
//!
//! There is nothing to assert beyond "does not panic and does not accept" — a
//! successful open on attacker-chosen bytes under a key they do not hold would
//! be a forgery, which the assertion below states explicitly rather than
//! trusting the AEAD's reputation.
use libfuzzer_sys::fuzz_target;
use nas_crypto::{chunk_key, chunk_key_from_stored, open, open_chunk, ConvergenceSecret, KEY_LEN};

fuzz_target!(|data: &[u8]| {
    let cs = ConvergenceSecret::from_bytes([0x5A; KEY_LEN]);
    let key = chunk_key(&cs, b"a plaintext the fuzzer does not know");
    // A forgery would be a break of XChaCha20-Poly1305, not of our code -- but
    // if our framing ever let one through, this is where it shows up.
    assert!(open(&key, data, b"nas-tools/aad/chunk/v1").is_err(), "forged open");

    let rk = chunk_key_from_stored([0x11; KEY_LEN]);
    assert!(open_chunk(&rk, data, b"").is_err(), "forged open_chunk");
});
