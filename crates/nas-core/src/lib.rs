//! Core types shared across NAS-tools.
//!
//! Deliberately holds no policy and no I/O: formats and invariants only, so the
//! daemon, the CLI and the untrusted peer can all depend on it without any of
//! them inheriting the others' assumptions.

pub mod encoding;

pub use encoding::{decode_field, decode_fields, encode_fields, push_field, DecodeError};
