#![no_main]
//! File manifests arrive sealed, but the writer is only semi-trusted (SPECS
//! §3.3) and local corruption can decrypt to garbage.
//!
//! Half the inputs are wrapped into a well-formed field frame with the right
//! magic, because raw random bytes almost never get past the magic check — that
//! is exactly how a proptest missed two live panics in the sibling decoder.
use libfuzzer_sys::fuzz_target;
use nas_core::encode_fields;
use nas_store::Manifest;

fuzz_target!(|data: &[u8]| {
    let _ = Manifest::decode(data);

    if data.is_empty() {
        return;
    }
    // Structured: split the input into n fields behind the real magic.
    let n = (data[0] % 12) as usize;
    let body = &data[1..];
    let step = body.len() / n.max(1);
    let mut fields: Vec<&[u8]> = vec![b"NASM"];
    for i in 0..n {
        let lo = (i * step).min(body.len());
        let hi = ((i + 1) * step).min(body.len());
        fields.push(&body[lo..hi]);
    }
    if let Ok(framed) = encode_fields(&fields) {
        let _ = Manifest::decode(&framed);
    }
});
