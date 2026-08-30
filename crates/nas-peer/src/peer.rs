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
use nas_core::{Addr, Mode, Timestamp};
use nas_lease::{plan_sweep, BlobInfo, GcPolicy, Holder, SweepPlan};
use nas_slots::{Regime, Roster, SlotId, SlotRecord, Witness, WitnessError};
use nas_store::{Addressing, BlobStore, StoreError};

/// Witnesses retained per slot. A relay is append-only by design (SPECS
/// §5.3), and an append-only store with no bound is an invitation to fill the
/// peer's disk one signed observation at a time. Well above what a device
/// population produces; a full slot refuses, it does not evict — evicting is
/// how a relay would quietly become a withholding one.
pub const MAX_WITNESSES_PER_SLOT: usize = 1024;
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
    /// A witness that does not verify against the key it carries. Refused at
    /// the relay so a client never has to wonder whether what it fetched was
    /// checked: it re-verifies anyway (`ForkProof::try_new` insists), but a
    /// relay that stores garbage is a relay that can be filled with garbage.
    Witness(WitnessError),
    /// The slot holds [`MAX_WITNESSES_PER_SLOT`] already.
    WitnessesFull {
        slot: SlotId,
    },
    /// A witness-only node (SPECS §5.3): it relays witnesses and does nothing
    /// else, so it can hold no blobs and no capabilities to lose.
    WitnessOnly,
    /// A retention publish that would drop an address (SPECS §16.3).
    ///
    /// The everyday write key may only ever *extend* the set. Shrinking it, or
    /// pulling in the expiry, needs the offline delete authority and a §16.2
    /// quorum — which is what stops ransomware holding the laptop's key from
    /// clearing the protection before it deletes.
    RetentionShrink {
        dropped: Addr,
        had: usize,
        offered: usize,
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
            Self::Witness(e) => write!(f, "witness rejected: {e}"),
            Self::WitnessesFull { slot } => write!(
                f,
                "slot {} already holds {MAX_WITNESSES_PER_SLOT} witnesses",
                slot.to_hex()
            ),
            Self::WitnessOnly => write!(
                f,
                "witness-only node: relays witnesses and holds no blobs, slots or caps (SPECS §5.3)"
            ),
            Self::RetentionShrink {
                dropped,
                had,
                offered,
            } => write!(
                f,
                "retention may only be extended under the everyday key: \
                 offered {offered} addresses, held {had}, dropping {} \
                 (shrinking needs the offline delete authority, SPECS §16.3)",
                dropped.to_hex()
            ),
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
    /// Verifying key → ACL subject.
    ///
    /// The subject used to be a string the caller passed to `serve`, bound to
    /// nothing — so whoever the server wired was the subject for every client,
    /// whichever key had actually completed the handshake. An ACL evaluated
    /// against an unbound string is decorative.
    subjects: BTreeMap<Vec<u8>, String>,
    /// Addresses that may not be swept (SPECS §16). Extend-only in the honest
    /// peer: shrinking it is what `ignore_retention` models.
    retention: std::collections::BTreeSet<[u8; 32]>,
    /// Relayed witness observations, `slot -> (witness id, seq) -> witness`
    /// (SPECS §5.3). One per observer per sequence: a witness re-observing
    /// the same head replaces its earlier note rather than accumulating.
    witnesses: BTreeMap<SlotId, BTreeMap<([u8; 32], u64), Witness>>,
    /// Serve the witness relay and refuse everything else (SPECS §5.3, "a
    /// witness-only node holds no blobs and no caps"). Enforced at the
    /// dispatch, where every request passes; a flag the store consulted
    /// per method would be one forgotten method away from holding a blob.
    pub witness_only: bool,
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
        let mut peer = Self {
            blobs: BlobStore::open_with(&root, addressing)?,
            root,
            mode,
            slots: BTreeMap::new(),
            forks: BTreeMap::new(),
            view: 0,
            roster: Roster::new(),
            acl: Acl::new(),
            subjects: BTreeMap::new(),
            retention: std::collections::BTreeSet::new(),
            witnesses: BTreeMap::new(),
            witness_only: false,
            hostility,
        };
        peer.load()?;
        Ok(peer)
    }

    /// Read slot histories and the retention set back from disk.
    ///
    /// Both were in-memory only for the whole of M1. `open` created `slots/`
    /// and wrote nothing into it, and `retention` was a fresh `BTreeSet` on
    /// every start — so a review reproduced this: retain a blob, confirm
    /// `delete_blob` refuses, restart the peer, and the blob deletes cleanly.
    /// **Object Lock that dies on `kill -9` is not Object Lock** (SPECS §16).
    fn load(&mut self) -> Result<(), PeerError> {
        let slots_dir = self.root.join("slots");
        if let Ok(rd) = fs::read_dir(&slots_dir) {
            for e in rd.flatten() {
                if !e.path().is_dir() {
                    continue;
                }
                let Ok(records) = fs::read_dir(e.path()) else {
                    continue;
                };
                for f in records.flatten() {
                    let Ok(bytes) = fs::read(f.path()) else {
                        continue;
                    };
                    // A record that will not decode is skipped rather than
                    // fatal: the peer must still come up and serve what it can.
                    // It is unverifiable here anyway -- the roster is client
                    // state, and every record is re-verified on the read path.
                    if let Ok(rec) = SlotRecord::decode(&bytes) {
                        self.slots
                            .entry(rec.slot_id)
                            .or_default()
                            .insert(rec.seq, rec);
                    }
                }
            }
        }
        if let Ok(bytes) = fs::read(self.root.join("retention")) {
            for chunk in bytes.chunks_exact(32) {
                let mut a = [0u8; 32];
                a.copy_from_slice(chunk);
                self.retention.insert(a);
            }
        }
        // Witnesses come back the same way slots do, and are re-verified on
        // the way in: a file someone edited on disk is dropped, not relayed.
        if let Ok(rd) = fs::read_dir(self.root.join("witnesses")) {
            for e in rd.flatten() {
                let Ok(files) = fs::read_dir(e.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let Ok(bytes) = fs::read(f.path()) else {
                        continue;
                    };
                    if let Ok(w) = Witness::decode(&bytes) {
                        if w.verify().is_ok() {
                            self.witnesses
                                .entry(w.slot_id)
                                .or_default()
                                .insert((w.witness_id(), w.seq), w);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn slot_dir(&self, slot: &SlotId) -> PathBuf {
        self.root.join("slots").join(slot.to_hex())
    }

    fn persist_witness(&self, w: &Witness) -> Result<(), PeerError> {
        let dir = self.root.join("witnesses").join(w.slot_id.to_hex());
        fs::create_dir_all(&dir)?;
        let bytes = w.encode().map_err(PeerError::Witness)?;
        let name = format!(
            "{}-{}",
            w.witness_id()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            w.seq
        );
        let tmp = dir.join(format!("{name}.tmp"));
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, dir.join(name))?;
        Ok(())
    }

    // ── Witness relay (SPECS §5.3) ──────────────────────────────────────

    /// Accept a signed observation for relay.
    ///
    /// No ACL right gates this: a witness carries its own key and proves its
    /// own authenticity, and the roster that decides whether it is *believed*
    /// lives in the client (`nas_slots::client`), not here. What the relay
    /// enforces is that it holds only things that verify, and only so many.
    pub fn publish_witness(&mut self, w: Witness) -> Result<(), PeerError> {
        w.verify().map_err(PeerError::Witness)?;
        let key = (w.witness_id(), w.seq);
        let held = self.witnesses.get(&w.slot_id);
        if held.map(|m| !m.contains_key(&key) && m.len() >= MAX_WITNESSES_PER_SLOT) == Some(true) {
            return Err(PeerError::WitnessesFull { slot: w.slot_id });
        }
        // Persisted before it is acknowledged, like a slot record: a client
        // told its observation was relayed must find it there after a restart.
        self.persist_witness(&w)?;
        self.witnesses.entry(w.slot_id).or_default().insert(key, w);
        Ok(())
    }

    /// Everything observed for a slot, or nothing at all from a peer that
    /// withholds witnesses.
    ///
    /// Withholding here is the attack SPECS §5.4 proves undetectable from a
    /// single peer: the client sees an empty relay, which is what an honest
    /// peer nobody has talked to also looks like. Only a second relay reveals
    /// the difference, which is why the witness-only node exists.
    pub fn witnesses(&self, slot: &SlotId) -> Vec<Witness> {
        if self.hostility.withhold_witnesses {
            return Vec::new();
        }
        self.witnesses
            .get(slot)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Persist one record. Written before it is acknowledged, so a crash
    /// between accepting and storing cannot lose a write the client believes
    /// succeeded.
    fn persist_slot(&self, rec: &SlotRecord) -> Result<(), PeerError> {
        let dir = self.slot_dir(&rec.slot_id);
        fs::create_dir_all(&dir)?;
        let bytes = rec.encode().map_err(PeerError::Slot)?;
        let tmp = dir.join(format!("{}.tmp", rec.seq));
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, dir.join(rec.seq.to_string()))?;
        Ok(())
    }

    fn persist_retention(&self) -> Result<(), PeerError> {
        let mut out = Vec::with_capacity(self.retention.len() * 32);
        for a in &self.retention {
            out.extend_from_slice(a);
        }
        let tmp = self.root.join("retention.tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, self.root.join("retention"))?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Bind a transport verifying key to an ACL subject.
    pub fn bind_subject(&mut self, verifying_key: &[u8], subject: &str) {
        self.subjects
            .insert(verifying_key.to_vec(), subject.to_string());
    }

    /// The subject a connection authenticates as, or `None` for a key this
    /// peer has never been told about. `None` must deny, never default.
    pub fn subject_for(&self, verifying_key: &[u8]) -> Option<&str> {
        self.subjects.get(verifying_key).map(|s| s.as_str())
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
        //
        // `append` also permits publishing. It previously did not, so a subject
        // holding only `Append` could store nothing at all -- which made the
        // §16 ransomware posture ("append, and withhold every delete-*")
        // expressible in the ACL table and nowhere in behaviour.
        let write = self.acl.check(subject, Right::Write, self.mode);
        let append = self.acl.check(subject, Right::Append, self.mode);
        if !write.permits() && !append.permits() {
            return Err(PeerError::Refused { decision: write });
        }

        // What `append` cannot buy, stated where it matters rather than in a
        // manual. SPECS §2.2: in an encrypted mode a slot update is an opaque
        // root address, so "added a key" and "deleted every key" are
        // indistinguishable to the peer -- `Mode::peer_can_enforce_append_only`
        // is true only for `transit-only`. An append-only device therefore gets
        // its protection from the retention set (§16), which the peer CAN check
        // because retention is addresses rather than semantics, not from this
        // right. Granting append and believing the peer polices additivity
        // would be believing in a control that does not exist.
        if !write.permits() && !self.mode.peer_can_enforce_append_only() {
            // Permitted, and deliberately not silent about what it is not.
            debug_assert!(append.permits());
        }
        let Some(vk) = self.roster.get(&rec.writer_id) else {
            return Err(PeerError::NotRostered);
        };
        rec.verify(vk).map_err(PeerError::Slot)?;

        // A forking peer keeps a private branch for the connections it chose
        // to equivocate to (`view != 0`): their writes land there and never
        // on the branch everyone else is shown. Nothing is forged — the record
        // is signed by a rostered writer — which is exactly why the writer
        // cannot tell from its own view (SPECS §5.3).
        if self.hostility.fork && self.view != 0 {
            return self.publish_on_fork(rec);
        }

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
        // Persisted BEFORE acknowledgement: a crash in between would otherwise
        // lose a write the client was told had succeeded.
        self.persist_slot(&rec)?;
        self.slots
            .entry(rec.slot_id)
            .or_default()
            .insert(rec.seq, rec);
        Ok(())
    }

    /// `fork`, from the branch nobody else is shown (SPECS §5.3).
    ///
    /// Seeded with the shared prefix of the main history so a walk of it
    /// verifies end to end, then chained and compare-and-swapped exactly as
    /// the honest branch is: a forking peer is not a broken peer, it is a
    /// consistent one twice over. In memory only — this adversary forgets its
    /// second branch on restart, which no drill needs it to survive.
    fn publish_on_fork(&mut self, rec: SlotRecord) -> Result<(), PeerError> {
        let prefix: Vec<(u64, SlotRecord)> = self
            .slots
            .get(&rec.slot_id)
            .map(|h| h.range(..rec.seq).map(|(k, v)| (*k, v.clone())).collect())
            .unwrap_or_default();
        let alt = self.forks.entry(rec.slot_id).or_default();
        if alt.is_empty() {
            alt.extend(prefix);
        }
        match alt.keys().next_back().copied() {
            None if rec.seq != 0 => {
                return Err(PeerError::CasConflict {
                    head: 0,
                    offered: rec.seq,
                })
            }
            Some(head) if rec.seq != head + 1 => {
                return Err(PeerError::CasConflict {
                    head,
                    offered: rec.seq,
                })
            }
            Some(head) if rec.prev != alt[&head].record_hash() => {
                return Err(PeerError::BrokenChain { seq: rec.seq })
            }
            _ => {}
        }
        alt.insert(rec.seq, rec);
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
    pub fn extend_retention(&mut self, addrs: &[Addr]) -> Result<(), PeerError> {
        for a in addrs {
            self.retention.insert(*a.as_bytes());
        }
        self.persist_retention()
    }

    /// Publish a **complete** retention set (SPECS §16.3).
    ///
    /// Unlike [`extend_retention`](Self::extend_retention), which can only add
    /// and so makes a shrink unrepresentable, this takes the whole proposed set
    /// — the shape a client actually publishes — and enforces `new ⊇ old`. The
    /// check is a plaintext set comparison, which is precisely why the peer can
    /// perform it in an encrypted mode: it needs to understand addresses, not
    /// manifests (SPECS §2.2).
    ///
    /// A peer running `--hostile ignore-retention` accepts the shrink. Nothing
    /// here stops it, and §16.3 does not pretend otherwise: the client's defence
    /// is re-reading the set and noticing, plus pairing the namespace with a
    /// second peer, not the hope that this one behaves.
    pub fn publish_retention(&mut self, proposed: &[Addr]) -> Result<(), PeerError> {
        let offered: std::collections::BTreeSet<[u8; 32]> =
            proposed.iter().map(|a| *a.as_bytes()).collect();
        if !self.hostility.ignore_retention {
            if let Some(dropped) = self.retention.difference(&offered).next() {
                return Err(PeerError::RetentionShrink {
                    dropped: Addr::from_bytes(*dropped),
                    had: self.retention.len(),
                    offered: offered.len(),
                });
            }
        }
        self.retention = offered;
        self.persist_retention()
    }

    pub fn retains(&self, addr: &Addr) -> bool {
        self.retention.contains(addr.as_bytes())
    }

    /// The retention set as addresses, so a client can re-read what the peer
    /// claims to be protecting and compare it against what it published.
    pub fn retention_set(&self) -> Vec<Addr> {
        self.retention
            .iter()
            .map(|a| Addr::from_bytes(*a))
            .collect()
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

    // ── Garbage collection (SPECS §6) ───────────────────────────────────

    /// Every blob with the size and upload time a sweep decision needs.
    ///
    /// `uploaded_at` is the file's mtime. That is the peer's own record of
    /// when it received the bytes, not a client claim — which matters, because
    /// §6.2's grace period exists to protect a blob whose lease has not
    /// arrived yet, and a client-supplied time would let that same client
    /// extend its own immunity.
    pub fn inventory(&self) -> Result<Vec<BlobInfo>, PeerError> {
        let mut out = Vec::new();
        for addr in self.blobs.addrs()? {
            let m = fs::metadata(self.blobs.path(&addr))?;
            let uploaded_at = Timestamp(
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            out.push(BlobInfo {
                addr,
                size: m.len(),
                uploaded_at,
            });
        }
        Ok(out)
    }

    /// Plan a sweep, and carry it out unless `dry_run` (SPECS §6, §16.3).
    ///
    /// The plan is returned whether or not anything was deleted, so a caller
    /// can show it before acting — for the only data-destroying operation in
    /// the system, the difference between a bug and an incident.
    ///
    /// Retention is applied **twice on purpose**: once as the floor handed to
    /// [`plan_sweep`], and again by [`delete_blob`] on the way out. An honest
    /// peer therefore cannot sweep a retained blob even if the planner were
    /// wrong. A peer running `--hostile ignore-retention` hands the planner an
    /// empty floor, and its `delete_blob` does not object either: that is the
    /// go-silent attack of §16.3, where the client's protection is noticing,
    /// not the peer's restraint.
    pub fn sweep(
        &mut self,
        holders: &[Holder],
        policy: &GcPolicy,
        now: Timestamp,
        dry_run: bool,
    ) -> Result<SweepPlan, PeerError> {
        let floor = if self.hostility.ignore_retention {
            std::collections::BTreeSet::new()
        } else {
            self.retention.clone()
        };
        let plan = plan_sweep(&self.inventory()?, holders, &floor, policy, now);
        if !dry_run {
            for addr in &plan.delete {
                self.delete_blob(addr)?;
            }
        }
        Ok(plan)
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
        p.extend_retention(&[a]).unwrap();
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
        q.extend_retention(&[b]).unwrap();
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
        p.extend_retention(&[a]).unwrap();
        assert_eq!(p.retention_len(), 1);
        p.extend_retention(&[b]).unwrap();
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

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use nas_crypto::{Identity, Role};
    use nas_slots::ROOT_NONCE_LEN;

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }
    fn slot() -> SlotId {
        SlotId::new(b"ns", b"durable")
    }

    /// A scratch dir that is NOT removed between opens, so a restart is a
    /// restart rather than a fresh peer.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(t: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-persist-{}-{t}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(root: &PathBuf) -> Peer {
        Peer::open(root, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap()
    }

    #[test]
    fn retention_survives_a_restart() {
        // The review's reproduction, now a regression test. Object Lock that
        // dies on kill -9 is not Object Lock (SPECS §16).
        let s = Scratch::new("retention");
        let addr;
        {
            let mut p = open(&s.0);
            addr = p.put_blob(b"a legal record under retention").unwrap();
            p.extend_retention(&[addr]).unwrap();
            assert!(matches!(
                p.delete_blob(&addr),
                Err(PeerError::RetentionHold { .. })
            ));
        }
        // Restart.
        let p = open(&s.0);
        assert!(p.retains(&addr), "retention was lost across a restart");
        assert!(matches!(
            p.delete_blob(&addr),
            Err(PeerError::RetentionHold { .. })
        ));
        assert!(p.blobs().has(&addr));
    }

    #[test]
    fn slot_history_survives_a_restart() {
        // Without this a client's chain walk silently loses its history every
        // time the peer is restarted, and §5.5's retain-N guarantee is void.
        let s = Scratch::new("slots");
        let id = ident(1);
        {
            let mut p = open(&s.0);
            p.roster.add(id.verifying_key()).unwrap();
            p.acl.grant("laptop", &[Right::Write]);
            let mut prev = [0u8; 32];
            for seq in 0..5 {
                let r = SlotRecord::sign(
                    &id,
                    slot(),
                    seq,
                    Addr::of_ciphertext(format!("root-{seq}").as_bytes()),
                    [1u8; ROOT_NONCE_LEN],
                    prev,
                    Regime::CasMerge,
                )
                .unwrap();
                prev = r.record_hash();
                p.publish_slot("laptop", r).unwrap();
            }
            assert_eq!(p.slot_len(&slot()), 5);
        }
        let p = open(&s.0);
        assert_eq!(
            p.slot_len(&slot()),
            5,
            "slot history was lost across a restart"
        );
        assert_eq!(p.slot_head(&slot()).unwrap().seq, 4);

        // And the reloaded history still verifies end to end.
        let mut roster = Roster::new();
        roster.add(id.verifying_key()).unwrap();
        let walk = p.slot_history(&slot(), 0);
        nas_slots::verify_chain(&walk, slot(), &roster, None).unwrap();
    }

    #[test]
    fn a_restarted_peer_still_enforces_cas() {
        // The head must be recovered, not reset -- otherwise a restart lets a
        // client re-publish seq 0 and silently truncate the history.
        let s = Scratch::new("cas");
        let id = ident(1);
        let genesis = SlotRecord::sign(
            &id,
            slot(),
            0,
            Addr::of_ciphertext(b"root-0"),
            [1u8; ROOT_NONCE_LEN],
            [0u8; 32],
            Regime::CasMerge,
        )
        .unwrap();
        {
            let mut p = open(&s.0);
            p.roster.add(id.verifying_key()).unwrap();
            p.acl.grant("laptop", &[Right::Write]);
            p.publish_slot("laptop", genesis.clone()).unwrap();
        }
        let mut p = open(&s.0);
        p.roster.add(id.verifying_key()).unwrap();
        p.acl.grant("laptop", &[Right::Write]);
        assert!(matches!(
            p.publish_slot("laptop", genesis),
            Err(PeerError::CasConflict {
                head: 0,
                offered: 0
            })
        ));
    }

    #[test]
    fn junk_in_the_slots_directory_does_not_stop_the_peer_starting() {
        // A peer must come up and serve what it can. Records are re-verified
        // on the read path anyway, so a corrupt file is skipped, not fatal.
        let s = Scratch::new("junk");
        {
            let _ = open(&s.0);
        }
        let d = s.0.join("slots").join("not-a-slot-id");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("0"), b"not a slot record").unwrap();
        let p = open(&s.0);
        assert_eq!(p.slot_len(&SlotId::from_bytes([0u8; 32])), 0);
    }
}

#[cfg(test)]
mod append_tests {
    use super::*;
    use nas_crypto::{Identity, Role};
    use nas_slots::ROOT_NONCE_LEN;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(t: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-append-{}-{t}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn genesis(id: &Identity, slot: SlotId) -> SlotRecord {
        SlotRecord::sign(
            id,
            slot,
            0,
            Addr::of_ciphertext(b"root"),
            [1u8; ROOT_NONCE_LEN],
            [0u8; 32],
            Regime::CasMerge,
        )
        .unwrap()
    }

    #[test]
    fn an_append_only_subject_can_publish() {
        // Before this, `Append` granted nothing and the §16 safe configuration
        // -- a backup agent that may add but never destroy -- could not store
        // anything at all.
        for mode in [Mode::E2ee, Mode::Passphrase, Mode::TransitOnly] {
            let s = Scratch::new(&format!("append-{mode:?}"));
            let mut p = Peer::open(&s.0, mode, Addressing::Content, Hostility::HONEST).unwrap();
            let id = Identity::derive(&[1u8; 32], Role::Slot).unwrap();
            p.roster.add(id.verifying_key()).unwrap();
            p.acl.grant("backup-agent", &[Right::Append]);
            let slot = SlotId::new(b"ns", b"s");
            p.publish_slot("backup-agent", genesis(&id, slot))
                .unwrap_or_else(|e| panic!("{mode:?}: append-only subject refused: {e}"));
        }
    }

    #[test]
    fn a_subject_with_neither_write_nor_append_is_still_refused() {
        let s = Scratch::new("neither");
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        let id = Identity::derive(&[1u8; 32], Role::Slot).unwrap();
        p.roster.add(id.verifying_key()).unwrap();
        p.acl.grant("guest", &[Right::Read]);
        let slot = SlotId::new(b"ns", b"s");
        assert!(matches!(
            p.publish_slot("guest", genesis(&id, slot)),
            Err(PeerError::Refused { .. })
        ));
    }

    #[test]
    fn append_does_not_imply_the_peer_polices_additivity() {
        // SPECS §2.2, asserted rather than left in a manual: in an encrypted
        // mode a slot update is an opaque root address, so the peer cannot tell
        // "added a key" from "deleted every key". An append-only device's real
        // protection is the retention set, not this right.
        assert!(!Mode::E2ee.peer_can_enforce_append_only());
        assert!(!Mode::Passphrase.peer_can_enforce_append_only());
        assert!(Mode::TransitOnly.peer_can_enforce_append_only());
    }

    // ---- witness relay (SPECS §5.3) ------------------------------------

    fn slot() -> SlotId {
        SlotId::new(b"ns", b"witnessed")
    }

    fn witness(observer: &Identity, seq: u64, sig_hash: [u8; 32]) -> Witness {
        Witness::sign(observer, slot(), seq, sig_hash, seq).unwrap()
    }

    #[test]
    fn a_witness_is_relayed_and_survives_restart() {
        let s = Scratch::new("witness-relay");
        let observer = Identity::derive(&[7; 32], Role::Witness).unwrap();
        let w = witness(&observer, 3, [9; 32]);
        {
            let mut p =
                Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
            // No roster, no ACL: the relay holds anything that verifies.
            p.publish_witness(w.clone()).unwrap();
            assert_eq!(p.witnesses(&slot()), vec![w.clone()]);
            // Idempotent: the same observation twice is one entry.
            p.publish_witness(w.clone()).unwrap();
            assert_eq!(p.witnesses(&slot()).len(), 1);
        }
        let p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        assert_eq!(
            p.witnesses(&slot()),
            vec![w],
            "acknowledged witness must be there after a restart"
        );
        assert!(p.witnesses(&SlotId::new(b"ns", b"other")).is_empty());
    }

    #[test]
    fn a_tampered_witness_is_refused_before_it_is_stored() {
        let s = Scratch::new("witness-tamper");
        let observer = Identity::derive(&[7; 32], Role::Witness).unwrap();
        let mut w = witness(&observer, 3, [9; 32]);
        w.seq = 4;
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        assert!(matches!(p.publish_witness(w), Err(PeerError::Witness(_))));
        assert!(p.witnesses(&slot()).is_empty());
        assert!(
            !s.0.join("witnesses").exists()
                || fs::read_dir(s.0.join("witnesses"))
                    .unwrap()
                    .next()
                    .is_none(),
            "nothing may reach disk for a witness that does not verify"
        );
    }

    #[test]
    fn the_per_slot_witness_cap_is_a_refusal_not_an_eviction() {
        let s = Scratch::new("witness-cap");
        let observer = Identity::derive(&[7; 32], Role::Witness).unwrap();
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        for seq in 0..MAX_WITNESSES_PER_SLOT as u64 {
            p.publish_witness(witness(&observer, seq, [1; 32])).unwrap();
        }
        let first = witness(&observer, 0, [1; 32]);
        let extra = witness(&observer, MAX_WITNESSES_PER_SLOT as u64, [1; 32]);
        assert!(matches!(
            p.publish_witness(extra),
            Err(PeerError::WitnessesFull { .. })
        ));
        // A re-publish of something already held is not "one more".
        p.publish_witness(first.clone()).unwrap();
        let held = p.witnesses(&slot());
        assert_eq!(held.len(), MAX_WITNESSES_PER_SLOT);
        assert!(
            held.contains(&first),
            "a full slot keeps what it has; it does not evict"
        );
    }

    #[test]
    fn a_withholding_peer_serves_an_empty_relay() {
        let s = Scratch::new("witness-withhold");
        let observer = Identity::derive(&[7; 32], Role::Witness).unwrap();
        let h = Hostility {
            withhold_witnesses: true,
            ..Hostility::HONEST
        };
        let mut p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, h).unwrap();
        p.publish_witness(witness(&observer, 1, [2; 32])).unwrap();
        // Indistinguishable from a peer nobody has talked to (SPECS §5.4).
        assert!(p.witnesses(&slot()).is_empty());
        // ...but the bytes are on disk: an honest restart of the same store
        // would serve them, which is exactly what makes this withholding
        // rather than loss.
        let p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        assert_eq!(p.witnesses(&slot()).len(), 1);
    }
}

#[cfg(test)]
mod worm_tests {
    //! SPECS §16.3: retention overrides leases, and the everyday key may only
    //! ever extend it.
    use super::*;
    use nas_lease::{sweep::DAY, LeaseSet};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("nas-worm-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn peer(tag: &str, h: Hostility) -> (Scratch, Peer) {
        let s = Scratch::new(tag);
        let p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, h).unwrap();
        (s, p)
    }

    /// Three stored blobs, returned in the order written.
    fn seed(p: &Peer, n: usize) -> Vec<Addr> {
        (0..n)
            .map(|i| p.put_blob(format!("blob-{i}").as_bytes()).unwrap())
            .collect()
    }

    /// Wall clock, because `inventory` reads the blob's mtime: a sweep test
    /// with an invented epoch would classify every blob as young and pass
    /// while sweeping nothing.
    fn real_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Far enough after the blobs were written that the young-blob grace has
    /// lapsed for all of them.
    fn later() -> Timestamp {
        Timestamp(real_now() + 200 * DAY)
    }

    fn holder(id: u8, leases: &[Addr], last_seen: u64) -> Holder {
        Holder {
            id: [id; 32],
            set: LeaseSet::from_addrs(leases),
            last_seen: Timestamp(last_seen),
        }
    }

    #[test]
    fn retention_may_be_extended_but_not_shrunk() {
        let (_s, mut p) = peer("extend", Hostility::HONEST);
        let a = seed(&p, 3);

        p.publish_retention(&a[..2]).unwrap();
        assert_eq!(p.retention_set().len(), 2);
        // Extending: the whole set, plus one more.
        p.publish_retention(&a).unwrap();
        assert_eq!(p.retention_set().len(), 3);

        // Dropping a[0] is a shrink, whatever else it adds.
        match p.publish_retention(&a[1..]) {
            Err(PeerError::RetentionShrink {
                dropped,
                had,
                offered,
            }) => {
                assert_eq!(dropped, a[0]);
                assert_eq!((had, offered), (3, 2));
            }
            other => panic!("a shrink was not refused: {other:?}"),
        }
        assert_eq!(
            p.retention_set().len(),
            3,
            "a refused publish must not apply"
        );
        assert!(a.iter().all(|x| p.retains(x)));
    }

    #[test]
    fn a_peer_ignoring_retention_accepts_the_shrink() {
        // The adversary §16.3 names. Its existence is why the client re-reads
        // the set instead of trusting the peer's acknowledgement.
        let (_s, mut p) = peer(
            "shrink-hostile",
            Hostility {
                ignore_retention: true,
                ..Hostility::HONEST
            },
        );
        let a = seed(&p, 2);
        p.publish_retention(&a).unwrap();
        p.publish_retention(&[]).unwrap();
        assert_eq!(p.retention_set().len(), 0, "the hostile peer dropped it");
    }

    #[test]
    fn going_silent_does_not_destroy_retained_data() {
        // §16.3's central claim: GC is lease-driven, so a client that simply
        // stops renewing would otherwise be able to delete a WORM namespace by
        // saying nothing at all.
        let (_s, mut p) = peer("go-silent", Hostility::HONEST);
        let a = seed(&p, 3);
        p.publish_retention(&a[..2]).unwrap();

        // One holder, long expired, leasing everything. Blobs are old enough
        // that the young-blob grace does not carry them either.
        let now = later();
        let h = holder(9, &a, real_now());
        let plan = p.sweep(&[h], &GcPolicy::default(), now, false).unwrap();

        assert_eq!(plan.delete, vec![a[2]], "only the unretained blob may go");
        assert!(
            p.has_blob(&a[0]) && p.has_blob(&a[1]),
            "retained data survived"
        );
        assert!(
            !p.has_blob(&a[2]),
            "the sweep must actually delete something"
        );
        // ...and the holder is told what it lost (§6.3).
        assert_eq!(plan.warnings.get(&[9u8; 32]), Some(&vec![a[2]]));
    }

    #[test]
    fn a_peer_ignoring_retention_sweeps_it_anyway() {
        let (_s, mut p) = peer(
            "sweep-hostile",
            Hostility {
                ignore_retention: true,
                ..Hostility::HONEST
            },
        );
        let a = seed(&p, 2);
        p.publish_retention(&a).unwrap();
        let plan = p.sweep(&[], &GcPolicy::default(), later(), false).unwrap();
        assert_eq!(plan.delete.len(), 2);
        assert!(a.iter().all(|x| !p.has_blob(x)), "retention was ignored");
    }

    #[test]
    fn a_dry_run_deletes_nothing() {
        let (_s, mut p) = peer("dry", Hostility::HONEST);
        let a = seed(&p, 2);
        let plan = p.sweep(&[], &GcPolicy::default(), later(), true).unwrap();
        assert_eq!(plan.delete.len(), 2, "the plan still names them");
        assert!(a.iter().all(|x| p.has_blob(x)), "a dry run must not delete");
    }

    #[test]
    fn a_young_blob_survives_with_no_lease_at_all() {
        // §6.2: the race between upload and lease publication.
        let (_s, mut p) = peer("young", Hostility::HONEST);
        let a = seed(&p, 1);
        let plan = p
            .sweep(&[], &GcPolicy::default(), Timestamp(real_now()), true)
            .unwrap();
        assert!(plan.delete.is_empty());
        assert_eq!(plan.keep, vec![(a[0], nas_lease::Keep::YoungBlob)]);
    }

    #[test]
    fn an_expiring_holder_still_protects_and_is_warned() {
        // §6.3's window: past expiry, inside grace. Nothing is deleted, and
        // the returning client is the one that needs telling.
        let (_s, mut p) = peer("expiring", Hostility::HONEST);
        let a = seed(&p, 1);
        let policy = GcPolicy::default();
        let now = later();
        let last = now.0 - policy.lease_expiry - policy.grace / 2;
        let plan = p.sweep(&[holder(7, &a, last)], &policy, now, true).unwrap();
        assert!(plan.delete.is_empty(), "inside grace, nothing may be swept");
        assert_eq!(plan.keep, vec![(a[0], nas_lease::Keep::LeasedByExpiring)]);
    }

    #[test]
    fn the_retention_set_survives_a_restart() {
        let s = Scratch::new("persist");
        let a = {
            let mut p =
                Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
            let a = seed(&p, 2);
            p.publish_retention(&a).unwrap();
            a
        };
        let p = Peer::open(&s.0, Mode::E2ee, Addressing::Content, Hostility::HONEST).unwrap();
        assert!(
            a.iter().all(|x| p.retains(x)),
            "Object Lock that dies on restart is not Object Lock"
        );
    }

    #[test]
    fn quota_is_reported_never_enforced_by_deleting() {
        // §6.4: a quota breach is an accounting dispute. Resolving it by
        // destroying data would turn it into data loss.
        let (_s, mut p) = peer("quota", Hostility::HONEST);
        let a = seed(&p, 2);
        let policy = GcPolicy {
            max_leased_bytes: 1,
            ..GcPolicy::default()
        };
        let plan = p
            .sweep(&[holder(3, &a, later().0)], &policy, later(), false)
            .unwrap();
        assert!(
            plan.over_quota.contains_key(&[3u8; 32]),
            "the breach is reported"
        );
        assert!(plan.delete.is_empty(), "and nothing is deleted for it");
        assert!(a.iter().all(|x| p.has_blob(x)));
    }
}
