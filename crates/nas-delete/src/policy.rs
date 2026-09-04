//! Quorum, and the rolling window that survives decomposition (SPECS §16.2).
//!
//! # Counting is not the control
//!
//! An earlier version of [`decide`] counted *distinct* approvers and stopped
//! there. That is not a quorum, it is a headcount: whoever held the requesting
//! laptop could generate three keypairs, sign three approvals with them, and
//! satisfy the namespace threshold of 3. It made §16.1's central claim —
//! "ransomware on the laptop cannot delete, because the authority is not there
//! to steal" — false as implemented, because nothing established what the
//! authority *was*.
//!
//! [`Authority`] is that missing set: the public keys of the offline deletion
//! authority, which by §16.1 are deliberately not on the everyday device. An
//! approval from outside it does not count, and is refused rather than
//! silently ignored — an unrecognised approval is evidence, and a report of
//! "1 of 3 distinct" that quietly dropped two is a worse answer than a
//! refusal that names what happened.

use crate::record::{DeleteExecution, DeleteRequest, Scope};
use nas_core::Timestamp;
use nas_crypto::key_id;
use std::collections::BTreeSet;

/// The offline deletion authority: whose approvals may count (SPECS §16.1).
///
/// Held by the verifier, never carried in the records it judges — a set the
/// records themselves supplied would be a quorum the requester chose.
///
/// An **empty** authority approves nothing. That is deliberate and is the safe
/// direction: a deployment that has not yet named its authority cannot delete,
/// rather than being able to delete with any keys at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authority {
    ids: BTreeSet<[u8; 32]>,
}

impl Authority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit an approver by its full verifying key, returning its id.
    pub fn add(&mut self, verifying_key: &[u8]) -> [u8; 32] {
        let id = key_id(verifying_key);
        self.ids.insert(id);
        id
    }

    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.ids.contains(id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.ids.iter()
    }
}

/// Approvals owed, by blast radius. SPECS §16.2's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumPolicy {
    pub object: usize,
    pub prefix: usize,
    pub namespace: usize,
    pub rolling: RollingPolicy,
}

/// Aggregation over recent history.
///
/// Per-request quorum alone is defeated by decomposition: with `object: 1`, one
/// stolen approval deletes a namespace as N single-object requests and never
/// trips the namespace quorum. Past `objects` requests inside `window`, every
/// further request owes `escalate_to` whatever its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollingPolicy {
    pub window: u64,
    pub objects: usize,
    pub escalate_to: usize,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            object: 1,
            prefix: 2,
            namespace: 3,
            rolling: RollingPolicy {
                window: 30 * 86_400,
                objects: 10,
                escalate_to: 3,
            },
        }
    }
}

impl QuorumPolicy {
    /// What this scope owes on its own, before any escalation.
    pub fn base(&self, scope: &Scope) -> usize {
        match scope {
            Scope::Object(_) => self.object,
            Scope::Prefix(_) => self.prefix,
            Scope::Namespace => self.namespace,
        }
    }
}

/// One previously executed deletion, as the peer recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Executed {
    pub at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Quorum met and every approval verified. Nothing has been deleted yet:
    /// the caller still has to act on it.
    Execute {
        required: usize,
        distinct: usize,
    },
    Refused(Refusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not enough distinct approvers.
    ShortOfQuorum {
        required: usize,
        distinct: usize,
        /// True when `required` rose because of the rolling window.
        escalated: bool,
    },
    /// An approval that does not verify, or that names a different request.
    BadApproval(String),
    /// The request itself does not verify.
    BadRequest(String),
    /// The execution record does not verify.
    BadExecution(String),
    /// An approval signed by a key that is not in the deletion authority.
    ///
    /// Refused rather than ignored: this is what an attacker who has the
    /// laptop and can make keypairs produces, and dropping it from the count
    /// would report a confusing shortfall instead of naming the attempt.
    NotAnApprover { id: [u8; 32] },
    /// The verifier holds no deletion authority, so no approval can count.
    ///
    /// A distinct refusal from [`Self::ShortOfQuorum`] because the fix is
    /// different: this is a deployment that has never named its authority, not
    /// one that is short of signatures.
    NoAuthority,
    /// The requester approved its own request.
    ///
    /// Not a spec rule, and deliberately so: it is here because the whole point
    /// of §16.1 is that the deleting authority is *not* the key on the laptop.
    /// An execution where requester and approver coincide re-collapses the two
    /// roles the design separates.
    SelfApproved,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortOfQuorum {
                required,
                distinct,
                escalated,
            } => write!(
                f,
                "{distinct} distinct approver(s), {required} required{}",
                if *escalated {
                    " (escalated by the rolling window: recent volume, not this request's scope)"
                } else {
                    ""
                }
            ),
            Self::NotAnApprover { id } => write!(
                f,
                "approval from {} is not in the deletion authority; §16.1 puts that key \
                 deliberately off the everyday device",
                id.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            Self::NoAuthority => f.write_str(
                "no deletion authority is configured, so nothing can be approved (SPECS §16.1)",
            ),
            Self::BadApproval(m) => write!(f, "approval rejected: {m}"),
            Self::BadRequest(m) => write!(f, "request rejected: {m}"),
            Self::BadExecution(m) => write!(f, "execution rejected: {m}"),
            Self::SelfApproved => f.write_str(
                "the requester approved its own request; §16.1 separates those keys on purpose",
            ),
        }
    }
}

/// Decide whether an execution may proceed.
///
/// **Pure.** It reads records and returns a verdict; deleting is the caller's
/// job. That separation is the same one `plan_sweep` makes, and for the same
/// reason: the only data-destroying operations in the system should be
/// inspectable before they run.
///
/// `authority` is whose approvals may count (SPECS §16.1). It is a parameter
/// rather than something read out of the records because a set the records
/// supplied would be a quorum the requester chose.
///
/// `recent` is every deletion already executed for this namespace, and is what
/// makes decomposition expensive: the count inside the window escalates the
/// requirement regardless of how small each individual request looks.
pub fn decide(
    request: &DeleteRequest,
    execution: &DeleteExecution,
    recent: &[Executed],
    policy: &QuorumPolicy,
    authority: &Authority,
    now: Timestamp,
) -> Decision {
    if let Err(e) = request.verify() {
        return Decision::Refused(Refusal::BadRequest(e.to_string()));
    }
    if let Err(e) = execution.verify() {
        return Decision::Refused(Refusal::BadExecution(e.to_string()));
    }
    if execution.request_hash != request.request_hash() {
        return Decision::Refused(Refusal::BadExecution(
            "execution names a different request".into(),
        ));
    }

    // No authority, no approvals. Checked before the loop so a deployment
    // that never named one gets the accurate answer rather than a shortfall.
    if authority.is_empty() {
        return Decision::Refused(Refusal::NoAuthority);
    }

    // Distinct approvers **from the authority**, by key id. Two approvals from
    // one holder are one holder ("× m, from distinct holders", §16.2), and an
    // approval from outside the authority is not a holder at all — without
    // that second half this counts keypairs, which anyone can make.
    let mut ids = BTreeSet::new();
    for a in &execution.approvals {
        if let Err(e) = a.verify() {
            return Decision::Refused(Refusal::BadApproval(e.to_string()));
        }
        if a.approver_id() == request.requester_id() {
            return Decision::Refused(Refusal::SelfApproved);
        }
        if !authority.contains(&a.approver_id()) {
            return Decision::Refused(Refusal::NotAnApprover {
                id: a.approver_id(),
            });
        }
        ids.insert(a.approver_id());
    }

    let in_window = recent
        .iter()
        .filter(|e| now.saturating_since(e.at) < policy.rolling.window)
        .count();
    let escalated = in_window >= policy.rolling.objects;
    let required = if escalated {
        policy.base(&request.scope).max(policy.rolling.escalate_to)
    } else {
        policy.base(&request.scope)
    };

    if ids.len() < required {
        return Decision::Refused(Refusal::ShortOfQuorum {
            required,
            distinct: ids.len(),
            escalated,
        });
    }
    Decision::Execute {
        required,
        distinct: ids.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Approver, DeleteApproval, Scope};
    use nas_crypto::{Identity, Role};

    fn id(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Lease).unwrap()
    }

    fn request(scope: Scope) -> DeleteRequest {
        DeleteRequest::sign(&id(1), scope, "spring cleaning", [7u8; 32]).unwrap()
    }

    /// An execution signed by the requester, approved by `approvers`.
    fn execution(r: &DeleteRequest, approvers: &[u8]) -> DeleteExecution {
        let approvals: Vec<DeleteApproval> = approvers
            .iter()
            .map(|s| DeleteApproval::sign(&id(*s), r.request_hash()).unwrap())
            .collect();
        DeleteExecution::sign(&id(1), r, &approvals).unwrap()
    }

    /// Comfortably past a rolling window, so "a year ago" is representable.
    fn now() -> Timestamp {
        Timestamp(100_000_000)
    }

    /// The offline deletion authority these tests judge against: seeds 2..=5.
    /// Seed 1 is the requesting laptop and is deliberately not in it.
    fn authority() -> Authority {
        let mut a = Authority::new();
        for s in 2..=5u8 {
            a.add(id(s).verifying_key());
        }
        a
    }

    #[test]
    fn one_approver_deletes_one_object() {
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[2]);
        assert_eq!(
            decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()),
            Decision::Execute {
                required: 1,
                distinct: 1
            }
        );
    }

    #[test]
    fn one_approver_cannot_delete_a_namespace() {
        let r = request(Scope::Namespace);
        let e = execution(&r, &[2]);
        match decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()) {
            Decision::Refused(Refusal::ShortOfQuorum {
                required, distinct, ..
            }) => assert_eq!((required, distinct), (3, 1)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn two_approvals_from_one_holder_are_one_holder() {
        // "× m, from distinct holders". Counting signatures rather than
        // holders would make the quorum one stolen key deep.
        let r = request(Scope::Prefix("2024/".into()));
        let a = DeleteApproval::sign(&id(2), r.request_hash()).unwrap();
        let e = DeleteExecution::sign(&id(1), &r, &[a.clone(), a]).unwrap();
        match decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()) {
            Decision::Refused(Refusal::ShortOfQuorum {
                required, distinct, ..
            }) => assert_eq!((required, distinct), (2, 1)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_approval_cannot_be_replayed_against_another_request() {
        // The reason DeleteApproval binds the request hash at all.
        let first = request(Scope::Object("a.pdf".into()));
        let second =
            DeleteRequest::sign(&id(1), Scope::Object("b.pdf".into()), "other", [9u8; 32]).unwrap();
        assert_ne!(first.request_hash(), second.request_hash());

        let stolen = DeleteApproval::sign(&id(2), first.request_hash()).unwrap();
        // It cannot even be packaged.
        assert!(matches!(
            DeleteExecution::sign(&id(1), &second, std::slice::from_ref(&stolen)),
            Err(crate::DeleteError::WrongRequest { .. })
        ));
        // And a hand-built execution carrying it is refused.
        let mut forged = execution(&second, &[2]);
        forged.approvals = vec![stolen];
        match decide(
            &second,
            &forged,
            &[],
            &QuorumPolicy::default(),
            &authority(),
            now(),
        ) {
            Decision::Refused(Refusal::BadExecution(_)) => {}
            other => panic!("a replayed approval was accepted: {other:?}"),
        }
    }

    #[test]
    fn the_requester_may_not_approve_its_own_request() {
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[1]);
        assert_eq!(
            decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()),
            Decision::Refused(Refusal::SelfApproved)
        );
    }

    #[test]
    fn keys_invented_on_the_laptop_do_not_make_a_quorum() {
        // The defect this parameter exists to close. Counting distinct
        // approvers and stopping there is a headcount, not a quorum: whoever
        // held the requesting laptop could generate three keypairs, sign three
        // approvals, and satisfy the namespace threshold of 3 — making §16.1's
        // claim ("ransomware on the laptop cannot delete, because the
        // authority is not there to steal") false as implemented.
        let r = request(Scope::Namespace);
        // Three keys nobody admitted, distinct and validly signed.
        let approvals: Vec<DeleteApproval> = [200u8, 201, 202]
            .iter()
            .map(|s| DeleteApproval::sign(&id(*s), r.request_hash()).unwrap())
            .collect();
        let e = DeleteExecution::sign(&id(1), &r, &approvals).unwrap();

        // Every signature verifies and all three holders are distinct, so the
        // old headcount said yes.
        assert_eq!(
            approvals
                .iter()
                .map(|a| a.approver_id())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        match decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()) {
            Decision::Refused(Refusal::NotAnApprover { .. }) => {}
            other => panic!("invented keys satisfied the quorum: {other:?}"),
        }
    }

    #[test]
    fn one_stranger_spoils_an_otherwise_sufficient_quorum() {
        // Refused, not silently ignored. Dropping the stranger from the count
        // would report "2 of 3 distinct" and hide the fact that someone
        // presented an approval from a key nobody admitted.
        let r = request(Scope::Namespace);
        let mut approvals: Vec<DeleteApproval> = [2u8, 3, 4]
            .iter()
            .map(|s| DeleteApproval::sign(&id(*s), r.request_hash()).unwrap())
            .collect();
        // Sanity: these three are enough on their own.
        let good = DeleteExecution::sign(&id(1), &r, &approvals).unwrap();
        assert!(matches!(
            decide(
                &r,
                &good,
                &[],
                &QuorumPolicy::default(),
                &authority(),
                now()
            ),
            Decision::Execute { .. }
        ));

        approvals.push(DeleteApproval::sign(&id(200), r.request_hash()).unwrap());
        let e = DeleteExecution::sign(&id(1), &r, &approvals).unwrap();
        match decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()) {
            Decision::Refused(Refusal::NotAnApprover { .. }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_authority_approves_nothing() {
        // The safe direction, and it must be explicit: a deployment that has
        // not named its authority cannot delete, rather than being able to
        // delete with any keys at all. An empty set that meant "no constraint"
        // is how this kind of check usually fails open.
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[2]);
        assert_eq!(
            decide(
                &r,
                &e,
                &[],
                &QuorumPolicy::default(),
                &Authority::new(),
                now()
            ),
            Decision::Refused(Refusal::NoAuthority)
        );
    }

    #[test]
    fn the_authority_is_the_verifiers_not_the_records() {
        // A set read out of the execution would be a quorum the requester
        // chose. `decide` takes it as a parameter for exactly that reason, so
        // the same records get opposite answers under different authorities.
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[2]);

        let mut theirs = Authority::new();
        theirs.add(id(2).verifying_key());
        assert!(matches!(
            decide(&r, &e, &[], &QuorumPolicy::default(), &theirs, now()),
            Decision::Execute { .. }
        ));

        let mut other = Authority::new();
        other.add(id(9).verifying_key());
        assert!(matches!(
            decide(&r, &e, &[], &QuorumPolicy::default(), &other, now()),
            Decision::Refused(Refusal::NotAnApprover { .. })
        ));
    }

    #[test]
    fn membership_is_by_key_not_by_name() {
        // `add` keys on the verifying key's id, so re-admitting the same key
        // does not inflate the authority and cannot inflate a quorum.
        let mut a = Authority::new();
        let first = a.add(id(2).verifying_key());
        let again = a.add(id(2).verifying_key());
        assert_eq!(first, again);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn decomposition_escalates_to_the_namespace_quorum() {
        // The attack: N single-object deletes, each owing 1, adding up to a
        // namespace wipe that never asks for 3.
        let p = QuorumPolicy::default();
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[2]);

        // Under the threshold: one approver is enough, as designed.
        let nine = vec![Executed { at: now() }; 9];
        assert!(matches!(
            decide(&r, &e, &nine, &p, &authority(), now()),
            Decision::Execute { required: 1, .. }
        ));

        // At it: the same single-object request now owes the namespace quorum.
        let ten = vec![Executed { at: now() }; 10];
        match decide(&r, &e, &ten, &p, &authority(), now()) {
            Decision::Refused(Refusal::ShortOfQuorum {
                required,
                distinct,
                escalated,
            }) => {
                assert_eq!((required, distinct), (3, 1));
                assert!(escalated, "the refusal must say why it escalated");
            }
            other => panic!("decomposition was not caught: {other:?}"),
        }
        // Three distinct approvers still get through — escalation raises the
        // price, it does not deadlock the namespace.
        assert!(matches!(
            decide(
                &r,
                &execution(&r, &[2, 3, 4]),
                &ten,
                &p,
                &authority(),
                now()
            ),
            Decision::Execute { required: 3, .. }
        ));
    }

    #[test]
    fn the_rolling_window_forgets() {
        // Ten deletes a year ago must not escalate today, or the namespace
        // becomes permanently frozen by its own history.
        let p = QuorumPolicy::default();
        let r = request(Scope::Object("a.pdf".into()));
        let e = execution(&r, &[2]);
        let old = vec![
            Executed {
                at: Timestamp(now().0 - p.rolling.window - 1)
            };
            10
        ];
        assert!(matches!(
            decide(&r, &e, &old, &p, &authority(), now()),
            Decision::Execute { required: 1, .. }
        ));
    }

    #[test]
    fn cooling_off_is_the_approvers_own_clock() {
        // SPECS §16.2: no trusted time source. The approver refuses early and
        // signs later, against its own clock; nothing in the protocol compels
        // either answer.
        let a = Approver::default();
        let r = request(Scope::Namespace);
        let seen = Timestamp(1_000);

        assert!(!a.may_sign(seen, Timestamp(1_000 + a.cooling_off - 1)));
        assert!(a
            .approve(&id(2), &r, seen, Timestamp(1_000 + a.cooling_off - 1))
            .unwrap()
            .is_none());

        let signed = a
            .approve(&id(2), &r, seen, Timestamp(1_000 + a.cooling_off))
            .unwrap()
            .expect("past the cooling-off the approver signs");
        signed.verify().unwrap();
        assert_eq!(signed.request_hash, r.request_hash());
    }

    #[test]
    fn records_round_trip() {
        let r = request(Scope::Prefix("2024/".into()));
        assert_eq!(DeleteRequest::decode(&r.encode().unwrap()).unwrap(), r);
        let a = DeleteApproval::sign(&id(2), r.request_hash()).unwrap();
        assert_eq!(DeleteApproval::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn a_tampered_request_does_not_verify() {
        let mut r = request(Scope::Object("a.pdf".into()));
        r.scope = Scope::Namespace;
        assert!(r.verify().is_err());
        let e = execution(&request(Scope::Object("a.pdf".into())), &[2]);
        match decide(&r, &e, &[], &QuorumPolicy::default(), &authority(), now()) {
            Decision::Refused(Refusal::BadRequest(_)) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_scope_path_is_refused_rather_than_interpreted() {
        assert!(matches!(
            DeleteRequest::sign(&id(1), Scope::Object(String::new()), "x", [0u8; 32]),
            Err(crate::DeleteError::BadScopePath)
        ));
    }
}
