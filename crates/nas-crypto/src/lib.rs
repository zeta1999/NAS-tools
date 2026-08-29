//! Key schedule and domain separation for NAS-tools (SPECS §3).
//!
//! Reuses `rust-secure-memory` for the AEAD and zeroizing storage; this crate
//! contributes the *discipline* around it — which key may use which nonce
//! policy, and which context every signature carries.

pub mod context;
pub mod keys;
pub mod random;
pub mod sign;

pub use context::SigContext;
pub use keys::{
    chunk_key, chunk_key_from_stored, manifest_key, open, open_chunk, seal, seal_chunk,
    wrapping_key, ChunkReadKey, ConvergenceSecret, CryptoError, DirSecret, Key, KEY_LEN, NONCE_LEN,
};
pub use sign::{key_id, verify, Identity, Role, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN};
