//! The three signed records of the loop, and the approver's local clock gate.

use nas_core::{decode_fields, encode_fields, DecodeError, Timestamp};
use nas_crypto::{
    key_id, verify, Identity, SigContext, SignError, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteError {
    Decode(DecodeError),
    Sign(SignError),
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    FieldCount {
        want: usize,
        got: usize,
    },
    BadSignature,
    /// A scope discriminant that is not one of the three.
    BadScope {
        tag: u8,
    },
    /// A scope whose path is empty, or a namespace scope carrying one.
    ///
    /// `Object("")` would name everything or nothing depending on the reader,
    /// and the quorum owed depends on which — so it is refused rather than
    /// interpreted.
    BadScopePath,
    /// An approval that names a request this execution does not carry.
    ///
    /// This is the replay guard (SPECS §16.2): binding the request hash is what
    /// stops an approval being reused against a different request.
    WrongRequest {
        expected: [u8; 32],
        got: [u8; 32],
    },
}

impl std::fmt::Display for DeleteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e:?}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "{field} is {got} B, want {want} B")
            }
            Self::FieldCount { want, got } => write!(f, "{got} fields, want {want}"),
            Self::BadSignature => f.write_str("signature does not verify"),
            Self::BadScope { tag } => write!(f, "unknown scope discriminant {tag}"),
            Self::BadScopePath => f.write_str(
                "an object or prefix scope needs a path, and a namespace scope may not carry one",
            ),
            Self::WrongRequest { expected, got } => write!(
                f,
                "approval is for request {}, not {}",
                hex6(got),
                hex6(expected)
            ),
        }
    }
}
impl std::error::Error for DeleteError {}
impl From<DecodeError> for DeleteError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<SignError> for DeleteError {
    fn from(e: SignError) -> Self {
        Self::Sign(e)
    }
}

fn hex6(b: &[u8]) -> String {
    b.iter()
        .take(6)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

/// What a request covers. Quorum scales with blast radius (SPECS §16.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Object(String),
    Prefix(String),
    Namespace,
}

impl Scope {
    fn tag(&self) -> u8 {
        match self {
            Self::Object(_) => 0,
            Self::Prefix(_) => 1,
            Self::Namespace => 2,
        }
    }

    fn path(&self) -> &str {
        match self {
            Self::Object(p) | Self::Prefix(p) => p,
            Self::Namespace => "",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Object(p) => format!("object {p}"),
            Self::Prefix(p) => format!("prefix {p}"),
            Self::Namespace => "the whole namespace".into(),
        }
    }

    fn check(&self) -> Result<(), DeleteError> {
        match self {
            Self::Object(p) | Self::Prefix(p) if p.is_empty() => Err(DeleteError::BadScopePath),
            Self::Namespace => Ok(()),
            _ => Ok(()),
        }
    }

    fn decode(tag: u8, path: &[u8]) -> Result<Self, DeleteError> {
        let path = String::from_utf8(path.to_vec()).map_err(|_| DeleteError::BadScopePath)?;
        let s = match tag {
            0 => Self::Object(path),
            1 => Self::Prefix(path),
            2 => {
                if !path.is_empty() {
                    return Err(DeleteError::BadScopePath);
                }
                Self::Namespace
            }
            other => return Err(DeleteError::BadScope { tag: other }),
        };
        s.check()?;
        Ok(s)
    }
}

fn request_body(scope: &Scope, reason: &str, nonce: &[u8; 32]) -> Vec<u8> {
    encode_fields(&[
        &[scope.tag()],
        scope.path().as_bytes(),
        reason.as_bytes(),
        nonce,
    ])
    .expect("request body always encodes")
}

/// Step 1 of the loop: a signed statement of intent. Deletes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteRequest {
    pub scope: Scope,
    pub reason: String,
    pub requested_by: Vec<u8>,
    /// Makes two otherwise identical requests distinct records, so an approval
    /// for one cannot be counted toward the other.
    pub nonce: [u8; 32],
    pub sig: Vec<u8>,
}

impl DeleteRequest {
    pub fn sign(
        identity: &Identity,
        scope: Scope,
        reason: &str,
        nonce: [u8; 32],
    ) -> Result<Self, DeleteError> {
        scope.check()?;
        let b = request_body(&scope, reason, &nonce);
        let sig = identity.sign(SigContext::DeleteRequest, &b)?;
        Ok(Self {
            scope,
            reason: reason.to_string(),
            requested_by: identity.verifying_key().to_vec(),
            nonce,
            sig,
        })
    }

    pub fn verify(&self) -> Result<(), DeleteError> {
        self.scope.check()?;
        let b = request_body(&self.scope, &self.reason, &self.nonce);
        verify(&self.requested_by, SigContext::DeleteRequest, &b, &self.sig)
            .map_err(|_| DeleteError::BadSignature)
    }

    /// What an approval binds itself to.
    ///
    /// Over the body **and** the signature, so that two requests differing only
    /// in who signed them hash differently.
    pub fn request_hash(&self) -> [u8; 32] {
        let mut v = request_body(&self.scope, &self.reason, &self.nonce);
        v.extend_from_slice(&self.requested_by);
        v.extend_from_slice(&self.sig);
        *blake3::hash(&v).as_bytes()
    }

    pub fn requester_id(&self) -> [u8; 32] {
        key_id(&self.requested_by)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DeleteError> {
        Ok(encode_fields(&[
            &[self.scope.tag()],
            self.scope.path().as_bytes(),
            self.reason.as_bytes(),
            &self.requested_by,
            &self.nonce,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DeleteError> {
        let f = decode_fields(bytes)?;
        if f.len() != 6 {
            return Err(DeleteError::FieldCount {
                want: 6,
                got: f.len(),
            });
        }
        if f[0].len() != 1 {
            return Err(DeleteError::BadWidth {
                field: "scope_tag",
                want: 1,
                got: f[0].len(),
            });
        }
        if f[3].len() != VERIFYING_KEY_LEN {
            return Err(DeleteError::BadWidth {
                field: "requested_by",
                want: VERIFYING_KEY_LEN,
                got: f[3].len(),
            });
        }
        if f[5].len() != SIGNATURE_LEN {
            return Err(DeleteError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[5].len(),
            });
        }
        Ok(Self {
            scope: Scope::decode(f[0][0], f[1])?,
            reason: String::from_utf8(f[2].to_vec()).map_err(|_| DeleteError::BadScopePath)?,
            requested_by: f[3].to_vec(),
            nonce: fixed32("nonce", f[4])?,
            sig: f[5].to_vec(),
        })
    }
}

fn fixed32(field: &'static str, b: &[u8]) -> Result<[u8; 32], DeleteError> {
    b.try_into().map_err(|_| DeleteError::BadWidth {
        field,
        want: 32,
        got: b.len(),
    })
}

/// Step 3: one holder's approval, bound to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteApproval {
    pub request_hash: [u8; 32],
    pub approver_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl DeleteApproval {
    pub fn sign(identity: &Identity, request_hash: [u8; 32]) -> Result<Self, DeleteError> {
        let sig = identity.sign(SigContext::DeleteApproval, &request_hash)?;
        Ok(Self {
            request_hash,
            approver_pk: identity.verifying_key().to_vec(),
            sig,
        })
    }

    pub fn verify(&self) -> Result<(), DeleteError> {
        verify(
            &self.approver_pk,
            SigContext::DeleteApproval,
            &self.request_hash,
            &self.sig,
        )
        .map_err(|_| DeleteError::BadSignature)
    }

    pub fn approver_id(&self) -> [u8; 32] {
        key_id(&self.approver_pk)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DeleteError> {
        Ok(encode_fields(&[
            &self.request_hash,
            &self.approver_pk,
            &self.sig,
        ])?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DeleteError> {
        let f = decode_fields(bytes)?;
        if f.len() != 3 {
            return Err(DeleteError::FieldCount {
                want: 3,
                got: f.len(),
            });
        }
        if f[1].len() != VERIFYING_KEY_LEN {
            return Err(DeleteError::BadWidth {
                field: "approver_pk",
                want: VERIFYING_KEY_LEN,
                got: f[1].len(),
            });
        }
        if f[2].len() != SIGNATURE_LEN {
            return Err(DeleteError::BadWidth {
                field: "sig",
                want: SIGNATURE_LEN,
                got: f[2].len(),
            });
        }
        Ok(Self {
            request_hash: fixed32("request_hash", f[0])?,
            approver_pk: f[1].to_vec(),
            sig: f[2].to_vec(),
        })
    }
}

/// Step 4: published only on quorum. Leases are dropped after this, never before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteExecution {
    pub request_hash: [u8; 32],
    pub approvals: Vec<DeleteApproval>,
    pub executed_by: Vec<u8>,
    pub sig: Vec<u8>,
}

impl DeleteExecution {
    pub fn sign(
        identity: &Identity,
        request: &DeleteRequest,
        approvals: &[DeleteApproval],
    ) -> Result<Self, DeleteError> {
        let request_hash = request.request_hash();
        // Refuse to *build* an execution that carries an approval for another
        // request. The verifier checks this too; catching it here means a
        // replayed approval cannot be packaged in the first place.
        for a in approvals {
            if a.request_hash != request_hash {
                return Err(DeleteError::WrongRequest {
                    expected: request_hash,
                    got: a.request_hash,
                });
            }
        }
        let sig = identity.sign(SigContext::DeleteExecution, &request_hash)?;
        Ok(Self {
            request_hash,
            approvals: approvals.to_vec(),
            executed_by: identity.verifying_key().to_vec(),
            sig,
        })
    }

    /// Every approval verifies, binds this request, and the execution itself is
    /// signed. Says nothing about *quorum* — that is [`crate::decide`], which
    /// needs the policy and the recent history.
    pub fn verify(&self) -> Result<(), DeleteError> {
        for a in &self.approvals {
            a.verify()?;
            if a.request_hash != self.request_hash {
                return Err(DeleteError::WrongRequest {
                    expected: self.request_hash,
                    got: a.request_hash,
                });
            }
        }
        verify(
            &self.executed_by,
            SigContext::DeleteExecution,
            &self.request_hash,
            &self.sig,
        )
        .map_err(|_| DeleteError::BadSignature)
    }
}

/// An approver device, and its own local clock (SPECS §16.2).
///
/// The cooling-off period lives here rather than in any verifier because there
/// is no trusted time source in this design: the peer's clock is adversarial by
/// assumption, and the requester signs its own timestamp. An approver refusing
/// to sign early is the whole of the mechanism, and it is a convention — it
/// buys a human time to notice, and compels nothing.
#[derive(Debug, Clone, Copy)]
pub struct Approver {
    /// Default 7 days (SPECS §16.2).
    pub cooling_off: u64,
}

impl Default for Approver {
    fn default() -> Self {
        Self {
            cooling_off: 7 * 86_400,
        }
    }
}

impl Approver {
    /// May this device sign yet? `first_seen` is when *this* approver learned
    /// of the request, by its own clock — not a time any other party asserted.
    pub fn may_sign(&self, first_seen: Timestamp, now: Timestamp) -> bool {
        now.saturating_since(first_seen) >= self.cooling_off
    }

    /// Sign, or refuse because the cooling-off has not elapsed.
    pub fn approve(
        &self,
        identity: &Identity,
        request: &DeleteRequest,
        first_seen: Timestamp,
        now: Timestamp,
    ) -> Result<Option<DeleteApproval>, DeleteError> {
        if !self.may_sign(first_seen, now) {
            return Ok(None);
        }
        DeleteApproval::sign(identity, request.request_hash()).map(Some)
    }
}
