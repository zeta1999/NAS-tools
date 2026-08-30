//! The deletion approval loop (SPECS §16.2).
//!
//! ```text
//! DeleteRequest   { scope, reason, requested_by, nonce, sig }
//! DeleteApproval  { request_hash, approver_pk, sig }
//! DeleteExecution { request_hash, approvals, sig }
//! ```
//!
//! All of it append-only, so the audit trail cannot be edited either.
//!
//! # What actually defeats ransomware here
//!
//! **Key separation**, not the cooling-off period. SPECS §16.2 corrected an
//! earlier claim on exactly this point, and the correction is load-bearing:
//! there is no trusted time source anywhere in this design. The peer's clock is
//! adversarial by assumption and a request's timestamp is signed by a requester
//! who may be compromised, so *nothing in the protocol can enforce a delay*.
//! Cooling-off is a convention enforced by approver devices against their own
//! local clocks — valuable because it gives a human time to notice, not because
//! it compels anything. [`Approver::may_sign`] is where that lives, and it is
//! deliberately a client-side decision rather than a check the peer performs.
//!
//! What the peer *can* check is arithmetic over signatures: m distinct
//! approvers, each binding the request hash. That is [`decide`].
//!
//! # Decomposition is the attack that per-request quorum misses
//!
//! With `object: 1`, one stolen approval token deletes an entire namespace as N
//! single-object requests, never once tripping the namespace quorum of 3. So
//! quorum is also aggregated over a rolling window: past the threshold, every
//! further request demands the namespace quorum whatever its scope. Volume is
//! what correlates with harm, not the label on any single request.

pub mod policy;
pub mod record;

pub use policy::{decide, Decision, Executed, QuorumPolicy, Refusal, RollingPolicy};
pub use record::{Approver, DeleteApproval, DeleteError, DeleteExecution, DeleteRequest, Scope};
