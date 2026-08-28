//! Access control the peer evaluates (SPECS §15.3, §15.4).
//!
//! # The answer depends on the mode, and pretending otherwise is the bug
//!
//! §15.3 draws the line plainly:
//!
//! | | `e2ee` / `passphrase` | `transit-only` |
//! |---|---|---|
//! | Mechanism | possession of a capability | ACL evaluated by the peer |
//! | Enforced by | mathematics | the peer's cooperation |
//! | If the peer is hostile | still safe | **no read control whatsoever** |
//!
//! So "does this subject have read?" has *three* answers, not two, and
//! [`Decision::NotEnforceable`] is the third. In an encrypted mode the peer
//! cannot enforce a read ACL at all — possession of a capability is the only
//! access control there is — and answering `Allowed` or `Denied` would describe
//! a control that does not exist. A UI that showed a tidy allow/deny table for
//! an `e2ee` namespace would be telling the user something false about their own
//! security, which is exactly the confusion §15 opens by warning about.
//!
//! **Write is different.** Authenticity does not require readability: the peer
//! checks a slot update against the signed roster, so write policy is
//! enforceable in every mode (§15.4).

use nas_core::{decode_fields, encode_fields, DecodeError, Mode};
use std::collections::{BTreeMap, BTreeSet};

/// The rights vocabulary of SPECS §15.4.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum Right {
    /// Decrypt / fetch.
    Read = 0,
    /// Create, overwrite, delete within the namespace.
    Write = 1,
    /// Create **new** keys only — no overwrite, no delete (§16).
    ///
    /// `append` plus withholding every `delete-*` from day-to-day devices is
    /// the whole of the ransomware defence in §16.
    Append = 2,
    /// May open a deletion request, may not execute one.
    DeleteRequest = 3,
    /// May sign approvals toward a quorum.
    DeleteApprove = 4,
    /// May push to an external mirror (§7.6).
    Publish = 5,
    /// Roster and policy changes.
    Admin = 6,
}

impl Right {
    pub const ALL: [Right; 7] = [
        Self::Read,
        Self::Write,
        Self::Append,
        Self::DeleteRequest,
        Self::DeleteApprove,
        Self::Publish,
        Self::Admin,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Append => "append",
            Self::DeleteRequest => "delete-request",
            Self::DeleteApprove => "delete-approve",
            Self::Publish => "publish",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| *r as u8 == v)
    }

    /// Whether the peer can enforce this right in `mode` (SPECS §15.3, §15.4).
    ///
    /// Only [`Read`](Self::Read) varies. Everything else is about *authenticity*,
    /// which the peer checks against the roster without reading anything.
    pub fn enforceable_in(self, mode: Mode) -> bool {
        match self {
            Self::Read => mode.peer_can_enforce_read_acl(),
            _ => true,
        }
    }
}

/// What the peer can honestly say about a request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allowed,
    /// The subject is known and does not hold this right.
    Denied,
    /// The subject is not in the ACL at all. Distinct from `Denied` because the
    /// remedy differs — add them, versus grant them — and because a peer that
    /// reported "denied" for an unknown subject would make a typo in a name
    /// look like a policy decision.
    UnknownSubject,
    /// This mode has no peer-enforced control of this kind. See the module docs.
    NotEnforceable {
        mode: Mode,
        right: Right,
    },
}

impl Decision {
    /// Whether the operation may proceed.
    ///
    /// `NotEnforceable` is **not** permission. It means the peer is not the
    /// thing standing in the way — in an encrypted mode a capability is — so a
    /// caller that treated it as `Allowed` would be enforcing nothing while
    /// believing it enforced something.
    pub fn permits(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied => write!(f, "denied"),
            Self::UnknownSubject => write!(f, "unknown subject"),
            Self::NotEnforceable { mode, right } => write!(
                f,
                "{mode:?} has no peer-enforced {} control: possession of a capability is \
                 the only access control, and the peer cannot evaluate it",
                right.as_str()
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    Decode(DecodeError),
    UnknownRight {
        value: u8,
    },
    BadSubject,
    /// Not one magic plus a whole number of two-field entries.
    RaggedEntries {
        fields: usize,
    },
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "acl encoding: {e:?}"),
            Self::UnknownRight { value } => write!(f, "unknown right {value}"),
            Self::BadSubject => write!(f, "malformed subject"),
            Self::RaggedEntries { fields } => {
                write!(f, "{fields} acl fields is not a multiple of 2")
            }
            Self::NonCanonical { reason } => write!(f, "non-canonical acl: {reason}"),
        }
    }
}
impl std::error::Error for AclError {}
impl From<DecodeError> for AclError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

const ACL_MAGIC: &[u8; 4] = b"NASA";

/// Subject → rights.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acl {
    entries: BTreeMap<String, BTreeSet<Right>>,
}

impl Acl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, subject: &str, rights: &[Right]) {
        let e = self.entries.entry(subject.to_string()).or_default();
        for r in rights {
            e.insert(*r);
        }
    }

    /// Remove a right. SPECS §15.3: in `transit-only` this is revocation, and
    /// it is instant — which is the advantage that mode buys.
    pub fn revoke(&mut self, subject: &str, right: Right) -> bool {
        self.entries
            .get_mut(subject)
            .is_some_and(|s| s.remove(&right))
    }

    pub fn remove_subject(&mut self, subject: &str) -> bool {
        self.entries.remove(subject).is_some()
    }

    pub fn subjects(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    pub fn rights_of(&self, subject: &str) -> Option<&BTreeSet<Right>> {
        self.entries.get(subject)
    }

    /// Evaluate a request. See [`Decision`] on why there are four outcomes.
    pub fn check(&self, subject: &str, right: Right, mode: Mode) -> Decision {
        if !right.enforceable_in(mode) {
            return Decision::NotEnforceable { mode, right };
        }
        match self.entries.get(subject) {
            None => Decision::UnknownSubject,
            Some(rights) if rights.contains(&right) => Decision::Allowed,
            Some(_) => Decision::Denied,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, AclError> {
        let mut fields: Vec<Vec<u8>> = vec![ACL_MAGIC.to_vec()];
        for (subject, rights) in &self.entries {
            fields.push(subject.as_bytes().to_vec());
            // Ascending and de-duplicated by construction (BTreeSet), which is
            // the canonical form the decoder demands back.
            fields.push(rights.iter().map(|r| *r as u8).collect());
        }
        let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
        Ok(encode_fields(&refs)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AclError> {
        let f = decode_fields(bytes)?;
        if f.first() != Some(&&ACL_MAGIC[..]) {
            return Err(AclError::BadSubject);
        }
        let body = f.len() - 1;
        if !body.is_multiple_of(2) {
            return Err(AclError::RaggedEntries { fields: body });
        }
        let mut entries: BTreeMap<String, BTreeSet<Right>> = BTreeMap::new();
        let mut prev: Option<&[u8]> = None;
        let mut i = 1;
        while i + 1 < f.len() {
            let subject = std::str::from_utf8(f[i]).map_err(|_| AclError::BadSubject)?;
            if subject.is_empty() {
                return Err(AclError::BadSubject);
            }
            // Same canonical rule as every other decoder here: reject anything
            // the encoder would not emit, or the encoding stops being injective
            // and the difference becomes a covert channel.
            if let Some(p) = prev {
                if f[i] <= p {
                    return Err(AclError::NonCanonical {
                        reason: "subjects are not in ascending order",
                    });
                }
            }
            prev = Some(f[i]);

            let mut rights = BTreeSet::new();
            let mut last: Option<u8> = None;
            for b in f[i + 1] {
                if let Some(l) = last {
                    if *b <= l {
                        return Err(AclError::NonCanonical {
                            reason: "rights are not in ascending order",
                        });
                    }
                }
                last = Some(*b);
                rights.insert(Right::from_u8(*b).ok_or(AclError::UnknownRight { value: *b })?);
            }
            entries.insert(subject.to_string(), rights);
            i += 2;
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family_acl() -> Acl {
        let mut a = Acl::new();
        a.grant("family", &[Right::Read]);
        a.grant("laptop", &[Right::Read, Right::Write, Right::Append]);
        a
    }

    #[test]
    fn transit_only_read_is_a_real_allow_or_deny() {
        let a = family_acl();
        assert_eq!(
            a.check("family", Right::Read, Mode::TransitOnly),
            Decision::Allowed
        );
        assert_eq!(
            a.check("family", Right::Write, Mode::TransitOnly),
            Decision::Denied
        );
    }

    #[test]
    fn an_encrypted_mode_has_no_peer_enforced_read_control() {
        // The dishonest answer would be Denied -- it would describe a control
        // the peer does not have, and a UI showing a tidy allow/deny table for
        // an e2ee namespace would be telling the user something false.
        for mode in [Mode::E2ee, Mode::Passphrase] {
            let d = family_acl().check("family", Right::Read, mode);
            assert_eq!(
                d,
                Decision::NotEnforceable {
                    mode,
                    right: Right::Read
                }
            );
            assert!(!d.permits(), "NotEnforceable must never read as permission");
            // Even for a subject that IS granted read.
            assert!(!family_acl().check("laptop", Right::Read, mode).permits());
        }
    }

    #[test]
    fn write_is_enforceable_in_every_mode() {
        // SPECS §15.4: authenticity does not require readability.
        for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
            assert_eq!(
                family_acl().check("laptop", Right::Write, mode),
                Decision::Allowed
            );
            assert_eq!(
                family_acl().check("family", Right::Write, mode),
                Decision::Denied
            );
        }
    }

    #[test]
    fn every_right_but_read_is_enforceable_everywhere() {
        for r in Right::ALL {
            for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
                let expect = r != Right::Read || mode == Mode::TransitOnly;
                assert_eq!(r.enforceable_in(mode), expect, "{r:?} in {mode:?}");
            }
        }
    }

    #[test]
    fn an_unknown_subject_is_not_the_same_as_a_denial() {
        // A typo in a name must not look like a policy decision.
        assert_eq!(
            family_acl().check("famly", Right::Read, Mode::TransitOnly),
            Decision::UnknownSubject
        );
    }

    #[test]
    fn revocation_is_immediate() {
        // The advantage transit-only buys: revocation without re-keying.
        let mut a = family_acl();
        assert!(a.revoke("family", Right::Read));
        assert_eq!(
            a.check("family", Right::Read, Mode::TransitOnly),
            Decision::Denied
        );
        assert!(
            !a.revoke("family", Right::Read),
            "revoking twice must report nothing"
        );
    }

    #[test]
    fn append_without_delete_is_expressible() {
        // The whole of the §16 ransomware defence: append, and no delete-*.
        let mut a = Acl::new();
        a.grant("backup-agent", &[Right::Append]);
        assert_eq!(
            a.check("backup-agent", Right::Append, Mode::E2ee),
            Decision::Allowed
        );
        for r in [Right::Write, Right::DeleteRequest, Right::DeleteApprove] {
            assert_eq!(
                a.check("backup-agent", r, Mode::E2ee),
                Decision::Denied,
                "{r:?}"
            );
        }
    }

    #[test]
    fn round_trips_through_its_encoding() {
        let a = family_acl();
        assert_eq!(Acl::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn an_empty_acl_round_trips() {
        let a = Acl::new();
        assert_eq!(Acl::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn whatever_decode_accepts_re_encodes_identically() {
        let bytes = family_acl().encode().unwrap();
        assert_eq!(Acl::decode(&bytes).unwrap().encode().unwrap(), bytes);
    }

    #[test]
    fn out_of_order_subjects_are_refused() {
        let framed = encode_fields(&[&ACL_MAGIC[..], b"zeta", &[0u8], b"alpha", &[0u8]]).unwrap();
        assert!(matches!(
            Acl::decode(&framed),
            Err(AclError::NonCanonical { .. })
        ));
    }

    #[test]
    fn out_of_order_rights_are_refused() {
        let framed = encode_fields(&[&ACL_MAGIC[..], b"a", &[1u8, 0u8]]).unwrap();
        assert!(matches!(
            Acl::decode(&framed),
            Err(AclError::NonCanonical { .. })
        ));
    }

    #[test]
    fn an_unknown_right_is_refused() {
        let framed = encode_fields(&[&ACL_MAGIC[..], b"a", &[99u8]]).unwrap();
        assert_eq!(
            Acl::decode(&framed),
            Err(AclError::UnknownRight { value: 99 })
        );
    }

    #[test]
    fn a_ragged_entry_list_is_refused() {
        let framed = encode_fields(&[&ACL_MAGIC[..], b"a"]).unwrap();
        assert_eq!(
            Acl::decode(&framed),
            Err(AclError::RaggedEntries { fields: 1 })
        );
    }

    #[test]
    fn right_names_round_trip() {
        for r in Right::ALL {
            assert_eq!(Right::parse(r.as_str()), Some(r));
        }
        assert_eq!(Right::parse("sudo"), None);
    }

    #[test]
    fn decode_never_panics() {
        for n in [0usize, 1, 4, 9, 40, 300] {
            let junk: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let _ = Acl::decode(&junk);
        }
    }
}
