//! Per-document CRDT op-log (SPECS §7, §7.2).
//!
//! Each document is a set of insert/delete operations. Merge is set-union
//! (commutative, associative, idempotent). Concurrent inserts after the same
//! atom both survive; order is `OpId` descending, RGA-style. Compaction
//! drops tombstones and rewrites the live atoms as a linear chain.
//!
//! The log is sealed under the directory key. Exposed, every edit is a
//! confirmation oracle for the document's contents.

use crate::blobs::{BlobStore, StoreError};
use crate::object::Sealer;
use nas_core::{decode_fields, encode_fields, Addr, DecodeError};
use nas_crypto::{manifest_key, open, seal, DirSecret};
use std::collections::{BTreeMap, BTreeSet};

pub const DOC_MAGIC: &[u8; 4] = b"NASO";
pub const DOC_AAD: &[u8] = b"nas-tools/aad/doc-oplog/v1";
const VERSION: u8 = 1;
const WRITER_LEN: usize = 32;

/// Sub-second while a document is being edited (SPECS §7.2).
pub const POLL_ACTIVE_MS: u64 = 250;
/// Minutes when idle.
pub const POLL_IDLE_MS: u64 = 180_000;
const ACTIVE_WINDOW_MS: u64 = 2_000;
const SETTLING_MS: u64 = 2_000;
const SETTLING_WINDOW_MS: u64 = 30_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OpId {
    pub writer: [u8; WRITER_LEN],
    pub counter: u64,
}

pub const ROOT: OpId = OpId {
    writer: [0; WRITER_LEN],
    counter: 0,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpKind {
    Insert { after: OpId, ch: u32 },
    Delete { target: OpId },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocLog {
    pub ops: BTreeMap<OpId, OpKind>,
    pub clock: BTreeMap<[u8; WRITER_LEN], u64>,
}

#[derive(Debug)]
pub enum DocError {
    Store(StoreError),
    Crypto(nas_crypto::CryptoError),
    Decode(DecodeError),
    BadMagic,
    BadVersion {
        value: u8,
    },
    BadWidth {
        field: &'static str,
        want: usize,
        got: usize,
    },
    Ragged {
        fields: usize,
    },
    BadKind {
        value: u8,
    },
    BadChar(u32),
    Range,
    NonCanonical {
        reason: &'static str,
    },
}

impl std::fmt::Display for DocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "encoding: {e:?}"),
            Self::BadMagic => write!(f, "not a doc op-log"),
            Self::BadVersion { value } => write!(f, "doc op-log version {value}"),
            Self::BadWidth { field, want, got } => {
                write!(f, "doc {field} is {got} B, want {want} B")
            }
            Self::Ragged { fields } => write!(f, "{fields} doc fields is not a multiple of 6"),
            Self::BadKind { value } => write!(f, "unknown doc op {value}"),
            Self::BadChar(c) => write!(f, "not a unicode scalar: {c}"),
            Self::Range => write!(f, "position is outside the document"),
            Self::NonCanonical { reason } => write!(f, "non-canonical doc op-log: {reason}"),
        }
    }
}
impl std::error::Error for DocError {}
impl From<StoreError> for DocError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<nas_crypto::CryptoError> for DocError {
    fn from(e: nas_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<DecodeError> for DocError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

fn fixed<const N: usize>(field: &'static str, b: &[u8]) -> Result<[u8; N], DocError> {
    b.try_into().map_err(|_| DocError::BadWidth {
        field,
        want: N,
        got: b.len(),
    })
}

impl DocLog {
    fn next_id(&mut self, writer: [u8; WRITER_LEN]) -> OpId {
        let n = self.clock.get(&writer).copied().unwrap_or(0) + 1;
        self.clock.insert(writer, n);
        OpId { writer, counter: n }
    }

    pub fn insert_ch(&mut self, writer: [u8; WRITER_LEN], after: OpId, ch: char) -> OpId {
        let id = self.next_id(writer);
        self.ops.insert(
            id,
            OpKind::Insert {
                after,
                ch: ch as u32,
            },
        );
        id
    }

    pub fn delete_id(&mut self, writer: [u8; WRITER_LEN], target: OpId) -> OpId {
        let id = self.next_id(writer);
        self.ops.insert(id, OpKind::Delete { target });
        id
    }

    /// Visible atoms in document order.
    pub fn atoms(&self) -> Result<Vec<(OpId, char)>, DocError> {
        let mut deleted = BTreeSet::new();
        let mut kids: BTreeMap<OpId, Vec<(OpId, u32)>> = BTreeMap::new();
        for (id, kind) in &self.ops {
            match kind {
                OpKind::Insert { after, ch } => {
                    kids.entry(*after).or_default().push((*id, *ch));
                }
                OpKind::Delete { target } => {
                    deleted.insert(*target);
                }
            }
        }
        for v in kids.values_mut() {
            v.sort_by_key(|b| std::cmp::Reverse(b.0));
        }
        let mut out = Vec::new();
        walk(ROOT, &kids, &deleted, &mut out)?;
        Ok(out)
    }

    pub fn text(&self) -> Result<String, DocError> {
        let mut s = String::new();
        for (_, ch) in self.atoms()? {
            s.push(ch);
        }
        Ok(s)
    }

    pub fn insert_text(
        &mut self,
        writer: [u8; WRITER_LEN],
        at: usize,
        text: &str,
    ) -> Result<(), DocError> {
        let atoms = self.atoms()?;
        if at > atoms.len() {
            return Err(DocError::Range);
        }
        let mut after = if at == 0 { ROOT } else { atoms[at - 1].0 };
        for ch in text.chars() {
            after = self.insert_ch(writer, after, ch);
        }
        Ok(())
    }

    pub fn delete_range(
        &mut self,
        writer: [u8; WRITER_LEN],
        at: usize,
        count: usize,
    ) -> Result<(), DocError> {
        let atoms = self.atoms()?;
        if at.saturating_add(count) > atoms.len() {
            return Err(DocError::Range);
        }
        for (id, _) in atoms.iter().skip(at).take(count) {
            self.delete_id(writer, *id);
        }
        Ok(())
    }

    /// Set-union. Clocks take the per-writer max.
    pub fn merge(&mut self, other: &DocLog) {
        for (id, kind) in &other.ops {
            self.ops.entry(*id).or_insert(*kind);
        }
        for (w, n) in &other.clock {
            let e = self.clock.entry(*w).or_insert(0);
            if *n > *e {
                *e = *n;
            }
        }
    }

    /// Drop tombstones; keep live atoms as a linear insert chain.
    pub fn compact(&self) -> Result<DocLog, DocError> {
        let atoms = self.atoms()?;
        let mut out = DocLog {
            ops: BTreeMap::new(),
            clock: self.clock.clone(),
        };
        let mut prev = ROOT;
        for (id, ch) in atoms {
            out.ops.insert(
                id,
                OpKind::Insert {
                    after: prev,
                    ch: ch as u32,
                },
            );
            prev = id;
        }
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DocError> {
        let mut fields: Vec<Vec<u8>> = vec![
            DOC_MAGIC.to_vec(),
            vec![VERSION],
            (self.clock.len() as u64).to_le_bytes().to_vec(),
        ];
        for (w, n) in &self.clock {
            fields.push(w.to_vec());
            fields.push(n.to_le_bytes().to_vec());
        }
        for (id, kind) in &self.ops {
            fields.push(id.writer.to_vec());
            fields.push(id.counter.to_le_bytes().to_vec());
            match kind {
                OpKind::Insert { after, ch } => {
                    fields.push(vec![1]);
                    fields.push(after.writer.to_vec());
                    fields.push(after.counter.to_le_bytes().to_vec());
                    fields.push(ch.to_le_bytes().to_vec());
                }
                OpKind::Delete { target } => {
                    fields.push(vec![2]);
                    fields.push(target.writer.to_vec());
                    fields.push(target.counter.to_le_bytes().to_vec());
                    fields.push(Vec::new());
                }
            }
        }
        let refs: Vec<&[u8]> = fields.iter().map(|v| v.as_slice()).collect();
        Ok(encode_fields(&refs)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DocError> {
        let f = decode_fields(bytes)?;
        if f.first() != Some(&&DOC_MAGIC[..]) {
            return Err(DocError::BadMagic);
        }
        if f.len() < 3 {
            return Err(DocError::Ragged { fields: f.len() });
        }
        let version = fixed::<1>("version", f[1])?[0];
        if version != VERSION {
            return Err(DocError::BadVersion { value: version });
        }
        let n_clock = u64::from_le_bytes(fixed("clock-count", f[2])?) as usize;
        let clock_end = 3 + n_clock * 2;
        if f.len() < clock_end {
            return Err(DocError::Ragged { fields: f.len() });
        }
        let mut clock = BTreeMap::new();
        let mut i = 3;
        while i + 1 < clock_end {
            let w: [u8; WRITER_LEN] = fixed("clock-writer", f[i])?;
            let n = u64::from_le_bytes(fixed("clock-n", f[i + 1])?);
            if clock.insert(w, n).is_some() {
                return Err(DocError::NonCanonical {
                    reason: "duplicate clock writer",
                });
            }
            i += 2;
        }
        let body = f.len() - clock_end;
        if !body.is_multiple_of(6) {
            return Err(DocError::Ragged { fields: body });
        }
        let mut ops = BTreeMap::new();
        let mut prev: Option<OpId> = None;
        i = clock_end;
        while i + 5 < f.len() {
            let writer: [u8; WRITER_LEN] = fixed("writer", f[i])?;
            let counter = u64::from_le_bytes(fixed("counter", f[i + 1])?);
            let id = OpId { writer, counter };
            if let Some(p) = prev {
                if id <= p {
                    return Err(DocError::NonCanonical {
                        reason: "ops are not in ascending id order",
                    });
                }
            }
            prev = Some(id);
            let kind_b = fixed::<1>("kind", f[i + 2])?[0];
            let aw: [u8; WRITER_LEN] = fixed("ref-writer", f[i + 3])?;
            let ac = u64::from_le_bytes(fixed("ref-counter", f[i + 4])?);
            let ref_id = OpId {
                writer: aw,
                counter: ac,
            };
            let kind = match kind_b {
                1 => {
                    let ch = u32::from_le_bytes(fixed("ch", f[i + 5])?);
                    if char::from_u32(ch).is_none() {
                        return Err(DocError::BadChar(ch));
                    }
                    OpKind::Insert { after: ref_id, ch }
                }
                2 => {
                    if !f[i + 5].is_empty() {
                        return Err(DocError::NonCanonical {
                            reason: "delete carries a character",
                        });
                    }
                    OpKind::Delete { target: ref_id }
                }
                v => return Err(DocError::BadKind { value: v }),
            };
            if ops.insert(id, kind).is_some() {
                return Err(DocError::NonCanonical {
                    reason: "duplicate op id",
                });
            }
            i += 6;
        }
        Ok(Self { ops, clock })
    }
}

fn walk(
    id: OpId,
    kids: &BTreeMap<OpId, Vec<(OpId, u32)>>,
    deleted: &BTreeSet<OpId>,
    out: &mut Vec<(OpId, char)>,
) -> Result<(), DocError> {
    if id != ROOT && !deleted.contains(&id) {
        let ch = kids
            .values()
            .flatten()
            .find(|(cid, _)| *cid == id)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let ch = char::from_u32(ch).ok_or(DocError::BadChar(ch))?;
        out.push((id, ch));
    }
    if let Some(children) = kids.get(&id) {
        for (cid, _) in children {
            walk(*cid, kids, deleted, out)?;
        }
    }
    Ok(())
}

/// Adaptive poll interval (SPECS §7.2). Sub-second while editing, minutes idle.
pub fn poll_interval_ms(last_edit_ago_ms: u64) -> u64 {
    if last_edit_ago_ms < ACTIVE_WINDOW_MS {
        POLL_ACTIVE_MS
    } else if last_edit_ago_ms < SETTLING_WINDOW_MS {
        SETTLING_MS
    } else {
        POLL_IDLE_MS
    }
}

pub struct DocStore<'a> {
    pub blobs: &'a BlobStore,
    pub sealer: Sealer<'a>,
}

impl<'a> DocStore<'a> {
    pub fn new(blobs: &'a BlobStore, sealer: Sealer<'a>) -> Self {
        Self { blobs, sealer }
    }

    pub fn store(&self, dir: &DirSecret, log: &DocLog) -> Result<Addr, DocError> {
        let plain = log.encode()?;
        match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                let sealed = seal(&key, &plain, DOC_AAD)?;
                Ok(self.blobs.put(&sealed)?)
            }
            Sealer::Plaintext { .. } => Ok(self.blobs.put(&plain)?),
        }
    }

    pub fn load(&self, dir: &DirSecret, addr: &Addr) -> Result<DocLog, DocError> {
        let stored = self.blobs.get(addr)?;
        let plain = match self.sealer {
            Sealer::Convergent(_) => {
                let key = manifest_key(dir);
                open(&key, &stored, DOC_AAD)?
            }
            Sealer::Plaintext { .. } => stored,
        };
        DocLog::decode(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];

    #[test]
    fn insert_delete_round_trip() {
        let mut d = DocLog::default();
        d.insert_text(A, 0, "hello").unwrap();
        assert_eq!(d.text().unwrap(), "hello");
        d.delete_range(A, 1, 2).unwrap();
        assert_eq!(d.text().unwrap(), "hlo");
    }

    #[test]
    fn concurrent_inserts_both_survive() {
        let mut base = DocLog::default();
        base.insert_text(A, 0, "xy").unwrap();
        let mut left = base.clone();
        let mut right = base.clone();
        left.insert_text(A, 1, "A").unwrap();
        right.insert_text(B, 1, "B").unwrap();
        let mut ab = left.clone();
        ab.merge(&right);
        let mut ba = right.clone();
        ba.merge(&left);
        assert_eq!(ab.text().unwrap(), ba.text().unwrap());
        let t = ab.text().unwrap();
        assert!(t.contains('A') && t.contains('B') && t.contains('x') && t.contains('y'));
        assert_eq!(ab, ba);
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = DocLog::default();
        a.insert_text(A, 0, "hi").unwrap();
        let mut b = a.clone();
        b.merge(&a);
        assert_eq!(a, b);
    }

    #[test]
    fn compact_drops_tombstones_and_keeps_text() {
        let mut d = DocLog::default();
        d.insert_text(A, 0, "abcdef").unwrap();
        d.delete_range(A, 1, 3).unwrap();
        let before = d.ops.len();
        let c = d.compact().unwrap();
        assert_eq!(c.text().unwrap(), "aef");
        assert!(c.ops.len() < before);
        assert!(c.ops.values().all(|k| matches!(k, OpKind::Insert { .. })));
    }

    #[test]
    fn encode_decode_is_identity() {
        let mut d = DocLog::default();
        d.insert_text(A, 0, "café").unwrap();
        d.delete_range(A, 1, 1).unwrap();
        let again = DocLog::decode(&d.encode().unwrap()).unwrap();
        assert_eq!(d, again);
    }

    #[test]
    fn poll_is_subsecond_active_and_minutes_idle() {
        assert!(poll_interval_ms(0) < 1_000);
        assert!(poll_interval_ms(60_000) >= 60_000);
    }
}
