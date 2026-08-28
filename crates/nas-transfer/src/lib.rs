//! Talking to a peer over `simple-network`'s PQC transport (SPECS §14).

pub mod server;
pub mod session;
pub mod wire;

pub use server::{handle, serve};
pub use session::{Channel, SessionError};
pub use wire::{Request, Response, WireError, MAX_FRAME, MAX_RECORDS};
