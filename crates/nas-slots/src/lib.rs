//! Slot consistency (SPECS §5): signed, chained heads for every mutable pointer.

pub mod chain;
pub mod client;
pub mod handoff;
pub mod id;
pub mod record;
pub mod roster;
pub mod witness;

pub use chain::{verify_chain, verify_chain_with_handoffs, ChainError, Walk};
pub use client::{Anchor, Pin, Reject, SlotClient, Verdict};
pub use handoff::{HandoffError, SlotHandoff};
pub use id::{SlotId, WriterId};
pub use record::{RecordError, Regime, SlotRecord, ROOT_NONCE_LEN};
pub use roster::{Roster, RosterError};
pub use witness::{ForkProof, Witness, WitnessError};
