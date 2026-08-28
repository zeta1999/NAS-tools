//! The vault (SPECS §2.2.2, §3.1, §3.9): identities, namespace secrets, and
//! the passphrase wrap.

pub mod argon;
pub mod derive;
pub mod vault;
pub mod wrap;

pub use argon::{Argon2Params, ParamError, WrapPolicy};
pub use derive::NamespaceSecrets;
pub use vault::{Generation, PinnedPeer, Vault, VaultError};
pub use wrap::{WrapError, WrapRecord};
