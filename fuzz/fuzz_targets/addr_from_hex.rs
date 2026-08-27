#![no_main]
//! Reachable from an untrusted peer: `BlobStore::addrs` builds this string from
//! peer-controlled directory names and relies on the `Err` branch to skip junk.
//!
//! A char-boundary panic here halted the lease sweep (MANUAL-TESTING.md §7a).
//! The two hand-written tests that existed were both ASCII, which is why it
//! survived — so this target feeds arbitrary bytes interpreted as text.
use libfuzzer_sys::fuzz_target;
use nas_core::Addr;

fuzz_target!(|data: &[u8]| {
    // Both the lossy view (what a filesystem listing produces) and any valid
    // UTF-8 prefix, so multibyte boundaries are exercised.
    let lossy = String::from_utf8_lossy(data);
    if let Ok(a) = Addr::from_hex(&lossy) {
        assert_eq!(a.to_hex(), lossy, "from_hex accepted a spelling to_hex would not emit");
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Addr::from_hex(s);
    }
});
