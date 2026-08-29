//! The peer's storage and its enforcement (SPECS §4, §5, §10).
//!
//! What the peer is trusted with is **availability and ordering**, and nothing
//! else. It cannot read encrypted namespaces, cannot forge a signature, and
//! cannot invent a witness. What it *can* do is lie about what it holds, serve
//! an old head, or drop things — and each of those has a specific client-side
//! answer rather than a general assurance.
//!
//! Every hostile behaviour is a branch inside the honest function, not a
//! separate mock. See [`crate::hostile`].

use crate::acl::{Acl, Decision, Right};
use crate::hostile::Hostility;
use nas_core::{Addr, Mode};
use nas_slots::{Regime, Roster, SlotId, SlotRecord};
use nas_store::{Addressing, BlobStore, StoreError};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum PeerError {
    Store(StoreError),
    Io(std::io::Error),
    Slot(nas_slots::RecordError),
    /// The writer is not on the roster (SPECS §15.4). Enforceable in **every**
    /// mode: authenticity does not require readability.
    NotRostered,
    /// The subject lacks the right for this operation.
    Refused {
        decision: Decision,
    },
    /// A slot update whose `seq` is not exactly one past the head.
    ///
    /// SPECS §5.2: a rejected CAS is a **normal retry**, not a fork alarm. The
    /// client re-reads, re-merges and tries again. Conflating the two is what
    /// made revision 1's alarm worthless.
    CasConflict {
        head: u64,
        offered: u64,
    },
    /// A slot update that does not chain to the head it claims to extend.
    BrokenChain {
        seq: u64,
    },
    /// Under `single-writer`, a second writer without an explicit handoff.
    ConcurrentWriter {
        seq: u64,
    },
    /// Retention protects this blob (SPECS §16).
    RetentionHold {
        addr: Addr,
    },
    Missing {
        addr: Addr,
    },
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::NotRostered => write!(f, "writer is not on the roster"),
            Self::Refused { decision } => write!(f, "refused: {decision}"),
            Self::CasConflict { head, offered } => write!(
                f,
                "compare-and-swap lost: head is at seq {head}, offered seq {offered} \
                 (re-read and retry; this is not a fork)"
            ),
            Self::BrokenChain { seq } => write!(f, "slot record {seq} does not chain to the head"),
            Self::ConcurrentWriter { seq } => {
                write!(
                    f,
                    "record {seq}: single-writer slot written by a second writer"
                )
            }
            Self::RetentionHold { addr } => {
                write!(f, "{} is protected by retention", addr.to_hex())
            }
            Self::Missing { addr } => write!(f, "no blob {}", addr.to_hex()),
        }
    }
}
impl std::error::Error for PeerError {}
impl From<StoreError> for PeerError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<std::io::Error> for PeerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// One namespace as the peer sees it.
pub struct Peer {
    root: PathBuf,
    pub mode: Mode,
    blobs: BlobStore,
    /// Slot histories, `slot_id -> seq -> record`. Retained rather than
    /// head-only: revision 1 stored only the head, which made its own chain
    /// check impossible to perform (SPECS §5.3).
    slots: BTreeMap<SlotId, BTreeMap<u64, SlotRecord>>,
    /// The second branch a forking peer keeps (SPECS §5.3).
    ///
    /// A peer holds no writer key, so it **cannot fabricate** a divergent
    /// history out of nothing — every record it serves must be one a
    /// legitimate writer signed. What it can do is accept two conflicting
    /// writes that an honest peer would have rejected by compare-and-swap, keep
    /// both, and show each client a different one. That is what equivocation
    /// actually looks like, and it is what this branch stores.
    forks: BTreeMap<SlotId, BTreeMap<u64, SlotRecord>>,
    /// Which branch this connection sees. A forking peer answers differently
    /// per client; an honest one ignores it entirely.
    view: u8,
    pub roster: Roster,
    pub acl: Acl,
    /// Addresses that may not be swept (SPECS §16). Extend-only in the honest
    /// peer: shrinking it is what `ignore_retention` models.
    retention: std::collections::BTreeSet<[u8; 32]>,
    pub hostility: Hostility,
}

impl Peer {
    pub fn open(
        root: impl Into<PathBuf>,
        mode: Mode,
        addressing: Addressing,
        hostility: Hostility,
    ) -> Result<Self, PeerError> {
        let root = root.into();
        fs::create_dir_all(root.join("slots"))?;
        Ok(Self {
            blobs: BlobStore::open_with(&root, addressing)?,
            root,
            mode,
            slots: BTreeMap::new(),
            forks: BTreeMap::new(),
            view: 0,
            roster: Roster::new(),
            acl: Acl::new(),
            retention: std::collections::BTreeSet::new(),
            hostility,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Choose which branch this connection is served (SPECS §5.3).
    ///
    /// Set per connection by the server loop, so two clients talking to one
    /// forking peer see different histories — which is the only way a fork
    /// becomes observable at all.
    pub fn set_view(&mut self, view: u8) {
        self.view = view;
    }

    /// The branch this connection sees, honouring `fork`.
    fn branch(&self, slot: &SlotId) -> Option<&BTreeMap<u64, SlotRecord>> {
        if self.hostility.fork && self.view != 0 {
            if let Some(alt) = self.forks.get(slot) {
                return Some(alt);
            }
        }
        self.slots.get(slot)
    }

    // ── Blobs ───────────────────────────────────────────────────────────

    pub fn put_blob(&self, bytes: &[u8]) -> Result<Addr, PeerError> {
        Ok(self.blobs.put(bytes)?)
    }

    /// Serve a blob.
    ///
    /// `tamper` flips a byte on the way out; the client catches it by hashing
    /// what it received (SPECS §3.4). `withhold` claims the blob is missing,
    /// which **cryptography cannot catch** — withholding is indistinguishable
    /// from having lost it, and the answer is leases and replication rather
    /// than a check.
    pub fn get_blob(&self, addr: &Addr) -> Result<Vec<u8>, PeerError> {
        if self.hostility.withhold {
            return Err(PeerError::Missing { addr: *addr });
        }
        let mut bytes = self.blobs.get(addr)?;
        if self.hostility.tamper && !bytes.is_empty() {
            let n = bytes.len() / 2;
            bytes[n] ^= 0xFF;
        }
        Ok(bytes)
    }

    /// Does the peer already hold this address? (SPECS §4.5)
    ///
    /// A `true` here persuades a client to skip an upload, so a lying peer
    /// converts dedup into silent deletion — discovered only at a future read,
    /// when the plaintext is long gone. That is why a client must never act on
    /// this without a proof-of-possession challenge.
    pub fn has_blob(&self, addr: &Addr) -> bool {
        if self.hostility.dedup_lie {
            return true;
        }
        self.blobs.has(addr)
    }

    /// Answer a proof-of-possession challenge: `BLAKE3(nonce ‖ ciphertext)`.
    ///
    /// Only a peer actually holding the bytes can answer. A `dedup_lie` peer
    /// claimed to have it and now cannot produce this, which is the whole point
    /// of the challenge.
    pub fn prove(&self, addr: &Addr, nonce: &[u8; 32]) -> Result<[u8; 32], PeerError> {
        Ok(self.blobs.prove(addr, nonce)?)
    }

    // ── Slots ───────────────────────────────────────────────────────────

    /// Accept a slot update, enforcing roster membership, write rights,
    /// compare-and-swap and chaining (SPECS §5.1, §5.2, §15.4).
    pub fn publish_slot(&mut self, subject: &str, rec: SlotRecord) -> Result<(), PeerError> {
        // Write policy is enforceable in every mode: the peer checks
        // authenticity, which needs no readability (SPECS §15.4).
        let d = self.acl.check(subject, Right::Write, self.mode);
        if !d.permits() {
            return Err(PeerError::Refused { decision: d });
        }
        let Some(vk) = self.roster.get(&rec.writer_id) else {
            return Err(PeerError::NotRostered);
        };
        rec.verify(vk).map_err(PeerError::Slot)?;

        // Read the head first rather than holding a mutable borrow across the
        // decision: the forking branch below needs to touch a second map.
        let head = self
            .slots
            .get(&rec.slot_id)
            .and_then(|h| h.keys().next_back().copied());

        match head {
            None => {
                if rec.seq != 0 {
                    return Err(PeerError::CasConflict {
                        head: 0,
                        offered: rec.seq,
                    });
                }
            }
            Some(head) => {
                if rec.seq != head + 1 {
                    // An honest peer refuses here and the client retries
                    // (SPECS §5.2). A forking one KEEPS the loser as a second
                    // branch and later serves it to a different client. Note it
                    // forges nothing: the losing record is genuinely signed by a
                    // rostered writer, which is precisely why neither client can
                    // tell from its own view.
                    if self.hostility.fork {
                        let prefix: Vec<(u64, SlotRecord)> = self
                            .slots
                            .get(&rec.slot_id)
                            .map(|h| h.range(..rec.seq).map(|(k, v)| (*k, v.clone())).collect())
                            .unwrap_or_default();
                        let alt = self.forks.entry(rec.slot_id).or_default();
                        if !alt.contains_key(&rec.seq) {
                            // Seed the branch with the shared prefix so the
                            // history it serves verifies end to end.
                            if alt.is_empty() {
                                alt.extend(prefix);
                            }
                            alt.insert(rec.seq, rec);
                            return Ok(());
                        }
                    }
                    return Err(PeerError::CasConflict {
                        head,
                        offered: rec.seq,
                    });
                }
                let prior = &self.slots[&rec.slot_id][&head];
                if rec.prev != prior.record_hash() {
                    return Err(PeerError::BrokenChain { seq: rec.seq });
                }
                if prior.regime == Regime::SingleWriter && prior.writer_id != rec.writer_id {
                    return Err(PeerError::ConcurrentWriter { seq: rec.seq });
                }
            }
        }
        self.slots
            .entry(rec.slot_id)
            .or_default()
            .insert(rec.seq, rec);
        Ok(())
    }

    /// The current head, or what a rolling-back peer claims is the head.
    pub fn slot_head(&self, slot: &SlotId) -> Option<&SlotRecord> {
        let history = self.branch(slot)?;
        if self.hostility.rollback && history.len() > 1 {
            // Serve the record before the head. Signed, chained, and a lie by
            // omission -- caught by the client's pin, not by any signature.
            let keys: Vec<u64> = history.keys().copied().collect();
            return history.get(&keys[keys.len() - 2]);
        }
        history.values().next_back()
    }

    /// The retained history for a chain walk (SPECS §5.3).
    pub fn slot_history(&self, slot: &SlotId, from: u64) -> Vec<SlotRecord> {
        let Some(h) = self.branch(slot) else {
            return Vec::new();
        };
        let upper = self.slot_head(slot).map(|r| r.seq).unwrap_or(u64::MAX);
        h.range(from..=upper).map(|(_, r)| r.clone()).collect()
    }

    pub fn slot_len(&self, slot: &SlotId) -> usize {
        self.slots.get(slot).map(|h| h.len()).unwrap_or(0)
    }

    // ── Retention (SPECS §16) ───────────────────────────────────────────

    /// Add to the retention set. **Extend-only** in the honest peer: a client
    /// verifies the new set is a superset of the old, so a peer that quietly
    /// dropped an entry would be caught by comparison rather than by trust.
    pub fn extend_retention(&mut self, addrs: &[Addr]) {
        for a in addrs {
            self.retention.insert(*a.as_bytes());
        }
    }

    pub fn retains(&self, addr: &Addr) -> bool {
        self.retention.contains(addr.as_bytes())
    }

    pub fn retention_len(&self) -> usize {
        self.retention.len()
    }

    /// Delete a blob, honouring retention.
    ///
    /// `ignore_retention` is the hostile branch: it deletes anyway. Nothing in
    /// the peer stops it — that is the point. §16's defence is that the client
    /// re-checks the superset and notices, not that the peer is well behaved.
    pub fn delete_blob(&self, addr: &Addr) -> Result<(), PeerError> {
        if self.retains(addr) && !self.hostility.ignore_retention {
            return Err(PeerError::RetentionHold { addr: *addr });
        }
        Ok(self.blobs.remove(addr)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::{Identity, Role};
    use nas_slots::ROOT_NONCE_LEN;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-peer-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn peer(tag: &str, h: Hostility) -> (Scratch, Peer, Identity) {
        let s = Scratch::new(tag);
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, h).unwrap();
        let id = ident(1);
        p.roster.add(id.verifying_key()).unwrap();
        p.acl.grant("laptop", &[Right::Write, Right::Append]);
        p.acl.grant("guest", &[Right::Read]);
        (s, p, id)
    }

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"bucket")
    }

    fn record(id: &Identity, seq: u64, prev: [u8; 32], tag: &str) -> SlotRecord {
        SlotRecord::sign(
            id,
            slot(),
            seq,
            Addr::of_ciphertext(tag.as_bytes()),
            [1u8; ROOT_NONCE_LEN],
            prev,
            Regime::CasMerge,
        )
        .unwrap()
    }

    /// Publish `n` chained records.
    fn publish_chain(p: &mut Peer, id: &Identity, n: u64) -> Vec<SlotRecord> {
        let mut out = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = record(id, seq, prev, &format!("root-{seq}"));
            prev = r.record_hash();
            p.publish_slot("laptop", r.clone()).unwrap();
            out.push(r);
        }
        out
    }

    #[test]
    fn an_honest_peer_stores_and_serves() {
        let (_s, p, _) = peer("honest", Hostility::HONEST);
        let a = p.put_blob(b"some ciphertext").unwrap();
        assert_eq!(p.get_blob(&a).unwrap(), b"some ciphertext");
        assert!(p.has_blob(&a));
    }

    #[test]
    fn a_tampering_peer_is_caught_by_the_address() {
        // SPECS §3.4: verifying a blob needs no key, so the client catches this
        // by hashing what it received.
        let (_s, p, _) = peer(
            "tamper",
            Hostility {
                tamper: true,
                ..Hostility::HONEST
            },
        );
        let a = p.put_blob(b"some ciphertext").unwrap();
        let served = p.get_blob(&a).unwrap();
        assert_ne!(served, b"some ciphertext");
        assert!(!a.verifies(&served), "tampering was not detectable");
    }

    #[test]
    fn a_withholding_peer_cannot_be_caught_by_cryptography() {
        // Stated as a test so the limit is recorded rather than assumed:
        // withholding is indistinguishable from loss. The answer is leases and
        // replication, not a check.
        let (_s, p, _) = peer(
            "withhold",
            Hostility {
                withhold: true,
                ..Hostility::HONEST
            },
        );
        let a = p.put_blob(b"present but denied").unwrap();
        assert!(matches!(p.get_blob(&a), Err(PeerError::Missing { .. })));
        // The bytes really are there; only the answer is a lie.
        assert!(p.blobs().has(&a));
    }

    #[test]
    fn a_dedup_lie_is_caught_by_proof_of_possession() {
        // SPECS §4.5: the peer claims to hold it so the client skips the
        // upload -- a silent deletion found at a future read. The challenge is
        // what makes the claim checkable.
        let (_s, p, _) = peer(
            "dedup",
            Hostility {
                dedup_lie: true,
                ..Hostility::HONEST
            },
        );
        let ct = b"a blob the peer does not actually hold";
        let a = Addr::of_ciphertext(ct);
        assert!(p.has_blob(&a), "the lie is the premise of this test");

        let nonce = [7u8; 32];
        assert!(
            p.prove(&a, &nonce).is_err(),
            "a peer without the bytes answered the challenge"
        );

        // And an honest peer that really holds it does answer, correctly.
        let (_s2, q, _) = peer("dedup-honest", Hostility::HONEST);
        q.put_blob(ct).unwrap();
        let answer = q.prove(&a, &nonce).unwrap();
        assert!(BlobStore::check_proof(ct, &nonce, &answer));
    }

    #[test]
    fn a_rolling_back_peer_serves_a_signed_but_stale_head() {
        // Every signature verifies. Only the client's pin notices (SPECS §5.3).
        let (_s, mut p, id) = peer(
            "rollback",
            Hostility {
                rollback: true,
                ..Hostility::HONEST
            },
        );
        let chain = publish_chain(&mut p, &id, 4);
        let head = p.slot_head(&slot()).unwrap();
        assert_eq!(head.seq, 2, "expected the record before the head");
        assert!(
            head.verify(id.verifying_key()).is_ok(),
            "the stale record is validly signed"
        );
        assert_eq!(chain[3].seq, 3, "the peer really does hold seq 3");
        assert_eq!(p.slot_len(&slot()), 4);
    }

    #[test]
    fn cas_rejects_a_stale_publish_as_a_retry_not_an_alarm() {
        // SPECS §5.2: conflating an honest concurrent write with a malicious
        // rollback is what made revision 1's alarm worthless.
        let (_s, mut p, id) = peer("cas", Hostility::HONEST);
        let chain = publish_chain(&mut p, &id, 3);
        let stale = record(&id, 2, chain[1].record_hash(), "a concurrent write");
        match p.publish_slot("laptop", stale) {
            Err(PeerError::CasConflict {
                head: 2,
                offered: 2,
            }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_record_that_does_not_chain_is_refused() {
        let (_s, mut p, id) = peer("chain", Hostility::HONEST);
        publish_chain(&mut p, &id, 2);
        let bad = record(&id, 2, [0xAB; 32], "unchained");
        assert!(matches!(
            p.publish_slot("laptop", bad),
            Err(PeerError::BrokenChain { seq: 2 })
        ));
    }

    #[test]
    fn an_unrostered_writer_is_refused_in_every_mode() {
        // SPECS §15.4: authenticity does not require readability, so this holds
        // even where the peer can read nothing.
        for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
            let s = Scratch::new(&format!("roster-{mode:?}"));
            let mut p = Peer::open(&s.0, mode, Addressing::Content, Hostility::HONEST).unwrap();
            p.acl.grant("laptop", &[Right::Write]);
            let stranger = ident(9);
            let r = record(&stranger, 0, [0u8; 32], "x");
            assert!(matches!(
                p.publish_slot("laptop", r),
                Err(PeerError::NotRostered)
            ));
        }
    }

    #[test]
    fn a_subject_without_write_is_refused_in_every_mode() {
        for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
            let s = Scratch::new(&format!("acl-{mode:?}"));
            let mut p = Peer::open(&s.0, mode, Addressing::Content, Hostility::HONEST).unwrap();
            let id = ident(1);
            p.roster.add(id.verifying_key()).unwrap();
            p.acl.grant("guest", &[Right::Read]);
            let r = record(&id, 0, [0u8; 32], "x");
            match p.publish_slot("guest", r) {
                Err(PeerError::Refused {
                    decision: Decision::Denied,
                }) => {}
                other => panic!("{mode:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn single_writer_refuses_a_second_writer() {
        let s = Scratch::new("single");
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        let (a, b) = (ident(1), ident(2));
        p.roster.add(a.verifying_key()).unwrap();
        p.roster.add(b.verifying_key()).unwrap();
        p.acl.grant("laptop", &[Right::Write]);

        let mk = |id: &Identity, seq, prev, tag: &str| {
            SlotRecord::sign(
                id,
                slot(),
                seq,
                Addr::of_ciphertext(tag.as_bytes()),
                [1u8; ROOT_NONCE_LEN],
                prev,
                Regime::SingleWriter,
            )
            .unwrap()
        };
        let first = mk(&a, 0, [0u8; 32], "a0");
        let h = first.record_hash();
        p.publish_slot("laptop", first).unwrap();
        assert!(matches!(
            p.publish_slot("laptop", mk(&b, 1, h, "b1")),
            Err(PeerError::ConcurrentWriter { seq: 1 })
        ));
    }

    #[test]
    fn retention_blocks_deletion_and_ignore_retention_does_not() {
        // SPECS §16. The honest peer refuses; the hostile one deletes anyway,
        // and nothing here stops it -- the defence is the client noticing.
        let (_s, mut p, _) = peer("retention", Hostility::HONEST);
        let a = p.put_blob(b"legal record").unwrap();
        p.extend_retention(&[a]);
        assert!(matches!(
            p.delete_blob(&a),
            Err(PeerError::RetentionHold { .. })
        ));
        assert!(p.blobs().has(&a));

        let (_s2, mut q, _) = peer(
            "retention-hostile",
            Hostility {
                ignore_retention: true,
                ..Hostility::HONEST
            },
        );
        let b = q.put_blob(b"legal record").unwrap();
        q.extend_retention(&[b]);
        q.delete_blob(&b).unwrap();
        assert!(
            !q.blobs().has(&b),
            "the hostile peer should have deleted it"
        );
    }

    #[test]
    fn retention_is_extend_only_for_the_honest_peer() {
        let (_s, mut p, _) = peer("extend", Hostility::HONEST);
        let a = p.put_blob(b"one").unwrap();
        let b = p.put_blob(b"two").unwrap();
        p.extend_retention(&[a]);
        assert_eq!(p.retention_len(), 1);
        p.extend_retention(&[b]);
        assert_eq!(
            p.retention_len(),
            2,
            "extending must not drop earlier entries"
        );
        assert!(p.retains(&a) && p.retains(&b));
    }

    #[test]
    fn history_is_retained_so_a_client_can_walk_it() {
        // Revision 1 stored only the head, which made its own chain check
        // impossible to perform (SPECS §5.3).
        let (_s, mut p, id) = peer("history", Hostility::HONEST);
        publish_chain(&mut p, &id, 6);
        let walk = p.slot_history(&slot(), 2);
        assert_eq!(walk.len(), 4);
        assert_eq!(walk[0].seq, 2);
        assert!(walk.iter().all(|r| r.verify(id.verifying_key()).is_ok()));
    }

    #[test]
    fn a_rolling_back_peer_serves_a_self_consistent_short_history() {
        // The nasty part: the walk it offers verifies. Detection needs the
        // client's pin or a witness, not a better signature check.
        let (_s, mut p, id) = peer(
            "rollback-walk",
            Hostility {
                rollback: true,
                ..Hostility::HONEST
            },
        );
        publish_chain(&mut p, &id, 5);
        let walk = p.slot_history(&slot(), 0);
        assert_eq!(walk.last().unwrap().seq, 3, "head withheld");
        let mut roster = Roster::new();
        roster.add(id.verifying_key()).unwrap();
        assert!(
            nas_slots::verify_chain(&walk, slot(), &roster, None).is_ok(),
            "the short history must be internally valid -- that is what makes it dangerous"
        );
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    use nas_crypto::{Identity, Role};
    use nas_slots::ROOT_NONCE_LEN;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }
    fn slot() -> SlotId {
        SlotId::new(b"ns", b"forked")
    }
    fn rec(id: &Identity, seq: u64, prev: [u8; 32], tag: &str) -> SlotRecord {
        SlotRecord::sign(
            id,
            slot(),
            seq,
            Addr::of_ciphertext(tag.as_bytes()),
            [1u8; ROOT_NONCE_LEN],
            prev,
            Regime::CasMerge,
        )
        .unwrap()
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(t: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-fork-{}-{t}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Two writers race; the peer keeps both and shows each client its own.
    fn forked_peer(tag: &str) -> (Scratch, Peer, Identity, Identity) {
        let s = Scratch::new(tag);
        let mut p = Peer::open(
            &s.0,
            Mode::E2ee,
            Addressing::Content,
            Hostility {
                fork: true,
                ..Hostility::HONEST
            },
        )
        .unwrap();
        let (a, b) = (ident(1), ident(2));
        p.roster.add(a.verifying_key()).unwrap();
        p.roster.add(b.verifying_key()).unwrap();
        p.acl.grant("laptop", &[Right::Write]);

        let g = rec(&a, 0, [0u8; 32], "genesis");
        let h = g.record_hash();
        p.publish_slot("laptop", g).unwrap();
        // Both writers publish seq 1 against the same predecessor. An honest
        // peer refuses the second; this one keeps it.
        p.publish_slot("laptop", rec(&a, 1, h, "branch-a")).unwrap();
        p.publish_slot("laptop", rec(&b, 1, h, "branch-b")).unwrap();
        (s, p, a, b)
    }

    #[test]
    fn a_forking_peer_serves_two_clients_two_histories() {
        let (_s, mut p, _, _) = forked_peer("two-views");
        p.set_view(0);
        let a = p.slot_head(&slot()).unwrap().clone();
        p.set_view(1);
        let b = p.slot_head(&slot()).unwrap().clone();

        assert_eq!(a.seq, b.seq, "a fork is two records at ONE sequence");
        assert_ne!(
            a.record_hash(),
            b.record_hash(),
            "the peer served one history twice"
        );
    }

    #[test]
    fn each_branch_verifies_on_its_own_which_is_what_makes_it_dangerous() {
        // Neither client can tell from its own view. Every record is genuinely
        // signed -- the peer forged nothing, it merely kept a loser.
        let (_s, mut p, a, b) = forked_peer("both-verify");
        let mut roster = Roster::new();
        roster.add(a.verifying_key()).unwrap();
        roster.add(b.verifying_key()).unwrap();

        for view in [0u8, 1] {
            p.set_view(view);
            let walk = p.slot_history(&slot(), 0);
            assert_eq!(walk.len(), 2, "view {view}");
            nas_slots::verify_chain(&walk, slot(), &roster, None)
                .unwrap_or_else(|e| panic!("view {view} did not verify: {e}"));
        }
    }

    #[test]
    fn an_honest_peer_refuses_the_second_write_instead_of_forking() {
        let s = Scratch::new("honest-cas");
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        let (a, b) = (ident(1), ident(2));
        p.roster.add(a.verifying_key()).unwrap();
        p.roster.add(b.verifying_key()).unwrap();
        p.acl.grant("laptop", &[Right::Write]);
        let g = rec(&a, 0, [0u8; 32], "genesis");
        let h = g.record_hash();
        p.publish_slot("laptop", g).unwrap();
        p.publish_slot("laptop", rec(&a, 1, h, "branch-a")).unwrap();
        assert!(matches!(
            p.publish_slot("laptop", rec(&b, 1, h, "branch-b")),
            Err(PeerError::CasConflict { .. })
        ));
        // And the view makes no difference to an honest peer.
        p.set_view(1);
        assert_eq!(p.slot_head(&slot()).unwrap().seq, 1);
        assert_eq!(p.slot_history(&slot(), 0).len(), 2);
    }

    #[test]
    fn the_two_branches_yield_a_real_fork_proof() {
        // The end-to-end point: two clients observing one forking peer produce
        // witnesses that combine into a publishable proof. Before this flag was
        // wired, ForkProof was only ever fed hand-built witnesses.
        use nas_slots::Witness;
        let (_s, mut p, _, _) = forked_peer("proof");
        let wa_id = Identity::derive(&[10u8; 32], Role::Witness).unwrap();
        let wb_id = Identity::derive(&[11u8; 32], Role::Witness).unwrap();

        p.set_view(0);
        let head_a = p.slot_head(&slot()).unwrap().clone();
        p.set_view(1);
        let head_b = p.slot_head(&slot()).unwrap().clone();

        let wa = Witness::sign(&wa_id, slot(), head_a.seq, head_a.sig_hash(), 0).unwrap();
        let wb = Witness::sign(&wb_id, slot(), head_b.seq, head_b.sig_hash(), 0).unwrap();
        let proof = nas_slots::ForkProof::try_new(&wa, &wb)
            .expect("two clients on a forking peer must be able to prove it");
        assert!(proof.verify());
        assert_eq!(proof.seq, 1);
    }
}
