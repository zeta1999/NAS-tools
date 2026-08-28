//! Garbage collection by lease (SPECS §6).
//!
//! A peer cannot mark-and-sweep an encrypted DAG: it cannot read the pointers.
//! Leaking them so it could traverse was considered and rejected, since that
//! hands an adversary the shape of the tree. Instead holders *declare* what they
//! still want, incrementally and signed.

pub mod merkle;
pub mod record;
pub mod set;
pub mod sweep;

pub use record::{canonicalise, LeaseCheckpoint, LeaseDelta, LeaseError};
pub use set::{replay, ApplyError, LeaseSet};
pub use sweep::{plan_sweep, BlobInfo, GcPolicy, Holder, HolderStatus, Keep, SweepPlan};
