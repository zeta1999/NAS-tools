#![no_main]
//! The most exposed parser in the system: every byte a peer sends arrives here
//! first. A bug in it is reachable by anything that can complete a handshake.
//!
//! Beyond not panicking, the properties that matter are canonical re-encoding
//! and the size bounds actually holding — a decoder that accepted an oversized
//! frame would reinstate the four-byte denial of service the limit exists to
//! stop.
use libfuzzer_sys::fuzz_target;
use nas_transfer::wire::{Request, Response, MAX_FRAME, MAX_RECORDS};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Request::decode(data) {
        let re = r.encode().expect("a decoded request must re-encode");
        assert_eq!(re, data, "decode accepted a non-canonical request");
        assert!(re.len() <= MAX_FRAME);
    }
    if let Ok(r) = Response::decode(data) {
        let re = r.encode().expect("a decoded response must re-encode");
        assert_eq!(re, data, "decode accepted a non-canonical response");
        assert!(re.len() <= MAX_FRAME);
        if let Response::Records(rs) = &r {
            assert!(rs.len() <= MAX_RECORDS, "record bound not enforced on decode");
        }
    }
});
