//! The peer (SPECS §10, §15) — **built hostile from day one**.
//!
//! PLAN moved the `--hostile` modes into M1 rather than M2 for a specific
//! reason: the peer's plaintext record formats freeze during M1 and are
//! format-breaking to change afterwards (§20). Adding hostility later means
//! those formats never feel adversarial pressure while they are still cheap to
//! change — which is exactly when a crafted record that slips past a check
//! would be worth finding.

pub mod acl;
pub mod hostile;
pub mod peer;

pub use acl::{Acl, AclError, Decision, Right};
pub use hostile::Hostility;
pub use peer::{Peer, PeerError, MAX_WITNESSES_PER_SLOT};
