//! `nas peer …` — running the untrusted peer, and syncing a namespace to one
//! (SPECS §10, §14).
//!
//! # What a peer directory holds
//!
//! ```text
//! <dir>/transport.seed   32 B, 0600 — the peer's own transport identity
//! <dir>/transport.pub    its verifying key; what clients pin
//! <dir>/clients/<subject>.pub   transport keys allowed to connect, by subject
//! <dir>/roster/<id>.pub  slot-writer keys whose records the peer will store
//! <dir>/acl              the peer-evaluated ACL (`Acl::encode`)
//! <dir>/data/            blobs, slot histories, retention (`Peer::open`)
//! ```
//!
//! The peer holds **no client secret** (SPECS §10): its one private file is
//! its own transport seed, which authenticates the peer to clients and
//! nothing else. Everything a client is trusted with — which subject a key
//! is, what that subject may do, whose slot records are accepted — is a
//! public key or a name, put there by the operator with `allow`, `writer`
//! and `grant`.
//!
//! # Sync
//!
//! `nas peer sync` pushes what the namespace has and publishes its `HEAD` as
//! the next slot record. Three client-side checks run against the wire, the
//! same ones the `nas-transfer` socket tests exercise (SPECS §4.5, §5.2):
//!
//! - a blob the peer *says* it already has is challenged for proof of
//!   possession before the upload is skipped — a dedup lie is caught here;
//! - a stored address must equal the one computed locally — a peer that
//!   stores under a different address is not storing our bytes;
//! - the served head must not be *older* than the last one this client
//!   published — a rolled-back head is caught by the local pin.
//!
//! Each of those is a refusal (exit 2), not an error: the client is declining
//! to continue with a peer it has just caught, and the harness distinguishes
//! that from a broken binary.

use crate::exit;
use crate::repo::{self, Repo};
use nas_core::{Addr, Mode};
use nas_crypto::{Identity, Role};
use nas_peer::{Acl, Hostility, Peer, Right, MAX_CHECKPOINTS_PER_SLOT};
use nas_slots::{
    is_checkpoint_seq, plan_walk, verify_chain_with_handoffs, verify_skip_chain, Checkpoint,
    Regime, Roster, SlotHandoff, SlotId, SlotRecord, Walk, WalkPlan, Witness, RETAIN_N,
    ROOT_NONCE_LEN,
};
use nas_store::{Addressing, BlobStore};
use nas_transfer::{transport_identity, Channel, Request, Response};
use std::collections::BTreeMap;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn refused(msg: impl std::fmt::Display) -> i32 {
    eprintln!("refused: {msg}");
    exit::REFUSED
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Short, stable name for a key: the first 16 hex digits of `BLAKE3(vk)`,
/// which is also the prefix of the writer id a roster maps it to.
fn fingerprint(vk: &[u8]) -> String {
    hex(&blake3::hash(vk).as_bytes()[..8])
}

// ── Peer directory ─────────────────────────────────────────────────────────

struct PeerDir(PathBuf);

impl PeerDir {
    fn new(dir: &str) -> Self {
        Self(PathBuf::from(dir))
    }
    fn seed(&self) -> PathBuf {
        self.0.join("transport.seed")
    }
    fn public(&self) -> PathBuf {
        self.0.join("transport.pub")
    }
    fn clients(&self) -> PathBuf {
        self.0.join("clients")
    }
    fn roster(&self) -> PathBuf {
        self.0.join("roster")
    }
    fn acl(&self) -> PathBuf {
        self.0.join("acl")
    }
    fn data(&self) -> PathBuf {
        self.0.join("data")
    }

    fn exists(&self) -> bool {
        self.seed().exists()
    }

    fn require(&self) -> Result<(), String> {
        if self.exists() {
            Ok(())
        } else {
            Err(format!(
                "{} is not a peer directory (run `nas peer init` first)",
                self.0.display()
            ))
        }
    }

    fn identity(&self) -> Result<Identity, String> {
        let bytes = fs::read(self.seed()).map_err(|e| format!("transport.seed: {e}"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "transport.seed is not 32 bytes".to_string())?;
        Identity::derive(&seed, Role::Transport).map_err(|e| e.to_string())
    }

    /// `subject -> transport verifying key`, from `clients/`.
    fn client_keys(&self) -> Result<BTreeMap<String, Vec<u8>>, String> {
        let mut out = BTreeMap::new();
        for (name, bytes) in read_pub_dir(&self.clients())? {
            out.insert(name, bytes);
        }
        Ok(out)
    }

    fn writer_keys(&self) -> Result<Vec<Vec<u8>>, String> {
        Ok(read_pub_dir(&self.roster())?
            .into_iter()
            .map(|(_, b)| b)
            .collect())
    }

    fn load_acl(&self) -> Result<Acl, String> {
        match fs::read(self.acl()) {
            Ok(b) => Acl::decode(&b).map_err(|e| format!("acl: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Acl::new()),
            Err(e) => Err(format!("acl: {e}")),
        }
    }

    fn store_acl(&self, acl: &Acl) -> Result<(), String> {
        let bytes = acl.encode().map_err(|e| e.to_string())?;
        let tmp = self.0.join("acl.tmp");
        fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        fs::rename(&tmp, self.acl()).map_err(|e| e.to_string())
    }
}

/// Every `*.pub` in `dir` as `(stem, bytes)`; a missing directory is empty.
fn read_pub_dir(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("pub") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let bytes = fs::read(&p).map_err(|err| format!("{}: {err}", p.display()))?;
        out.push((stem.to_string(), bytes));
    }
    out.sort();
    Ok(out)
}

/// `nas peer init <dir>`
pub fn init(dir: &str) -> i32 {
    let pd = PeerDir::new(dir);
    if pd.exists() {
        return err(format!("{dir} is already a peer directory"));
    }
    for d in [pd.0.clone(), pd.clients(), pd.roster(), pd.data()] {
        if let Err(e) = fs::create_dir_all(&d) {
            return err(format!("{}: {e}", d.display()));
        }
    }
    let seed = match repo::random_secret() {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let id = match Identity::derive(&seed, Role::Transport) {
        Ok(i) => i,
        Err(e) => return err(e),
    };
    if let Err(e) = repo::write_private_pub(&pd.seed(), &seed) {
        return err(e);
    }
    if let Err(e) = fs::write(pd.public(), id.verifying_key()) {
        return err(e);
    }
    println!("initialised peer at {dir}");
    println!("  transport key {}", fingerprint(id.verifying_key()));
    println!("  clients pin {}", pd.public().display());
    println!("  the peer holds no client secret: only its own transport seed (SPECS §10)");
    exit::OK
}

/// `nas peer allow <dir> <subject> <transport.pub>`
pub fn allow(dir: &str, subject: &str, pub_file: &str) -> i32 {
    let pd = PeerDir::new(dir);
    if let Err(e) = pd.require() {
        return err(e);
    }
    if subject.is_empty() || subject.contains(['/', '.']) {
        return err(format!("subject {subject:?} must be a plain name"));
    }
    let vk = match fs::read(pub_file) {
        Ok(b) => b,
        Err(e) => return err(format!("{pub_file}: {e}")),
    };
    if let Err(e) = fs::write(pd.clients().join(format!("{subject}.pub")), &vk) {
        return err(e);
    }
    println!(
        "{subject} may connect with transport key {}",
        fingerprint(&vk)
    );
    exit::OK
}

/// `nas peer writer <dir> <slot.pub>`
pub fn writer(dir: &str, pub_file: &str) -> i32 {
    let pd = PeerDir::new(dir);
    if let Err(e) = pd.require() {
        return err(e);
    }
    let vk = match fs::read(pub_file) {
        Ok(b) => b,
        Err(e) => return err(format!("{pub_file}: {e}")),
    };
    // Validate by trying to roster it: a key of the wrong length is refused
    // here rather than at serve time.
    if let Err(e) = nas_slots::Roster::new().add(&vk) {
        return err(format!("{pub_file}: {e}"));
    }
    let fp = fingerprint(&vk);
    if let Err(e) = fs::write(pd.roster().join(format!("{fp}.pub")), &vk) {
        return err(e);
    }
    println!("slot records signed by writer {fp} will be stored");
    exit::OK
}

/// `nas peer grant <dir> <subject> <right>`
pub fn grant(dir: &str, subject: &str, right: &str) -> i32 {
    let pd = PeerDir::new(dir);
    if let Err(e) = pd.require() {
        return err(e);
    }
    let Some(r) = Right::parse(right) else {
        return err(format!("unknown right {right:?}"));
    };
    let mut acl = match pd.load_acl() {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    acl.grant(subject, &[r]);
    if let Err(e) = pd.store_acl(&acl) {
        return err(e);
    }
    println!("{subject}: +{right}");
    exit::OK
}

/// `nas peer show <dir>`
pub fn show(dir: &str) -> i32 {
    let pd = PeerDir::new(dir);
    if let Err(e) = pd.require() {
        return err(e);
    }
    match pd.identity() {
        Ok(id) => println!("transport key {}", fingerprint(id.verifying_key())),
        Err(e) => return err(e),
    }
    match pd.client_keys() {
        Ok(c) => {
            println!("clients ({}):", c.len());
            for (s, vk) in &c {
                println!("  {s}\t{}", fingerprint(vk));
            }
        }
        Err(e) => return err(e),
    }
    match pd.writer_keys() {
        Ok(w) => {
            println!("writers ({}):", w.len());
            for vk in &w {
                println!("  {}", fingerprint(vk));
            }
        }
        Err(e) => return err(e),
    }
    match pd.load_acl() {
        Ok(acl) => {
            println!("acl:");
            for s in acl.subjects() {
                let rights: Vec<String> = acl
                    .rights_of(s)
                    .map(|rs| rs.iter().map(|r| format!("{r:?}").to_lowercase()).collect())
                    .unwrap_or_default();
                println!("  {s}\t{}", rights.join(","));
            }
        }
        Err(e) => return err(e),
    }
    exit::OK
}

/// What `nas peer serve` needs beyond the directory.
pub struct ServeOpts<'a> {
    pub listen: &'a str,
    pub hostile: Option<&'a str>,
    pub mode: Option<&'a str>,
    pub salt_file: Option<&'a str>,
    /// Serve one connection and exit. For tests and scripts; a real peer
    /// runs until killed.
    pub once: bool,
    /// Relay witnesses and refuse everything else (SPECS §5.3): "a
    /// witness-only node holds no blobs and no caps".
    pub witness: bool,
}

/// `nas peer serve <dir> --listen <addr> [--hostile <spec>] [--once]`
pub fn serve(dir: &str, o: ServeOpts<'_>) -> i32 {
    let pd = PeerDir::new(dir);
    if let Err(e) = pd.require() {
        return err(e);
    }
    let hostility = match o.hostile {
        None => Hostility::HONEST,
        Some(spec) => match Hostility::parse(spec) {
            Ok(h) => h,
            Err(e) => return err(e),
        },
    };
    let mode = match o.mode {
        None => Mode::E2ee,
        Some(m) => match repo::parse_mode(m) {
            Some(m) => m,
            None => return err(format!("unknown mode {m:?}")),
        },
    };
    // A transit-only tenant addresses blobs under its salt (SPECS §2.2.3); the
    // peer must use the same one or every put looks like a mismatch.
    let addressing = match o.salt_file {
        None => Addressing::Content,
        Some(f) => match fs::read(f) {
            Ok(s) => Addressing::Salted(s),
            Err(e) => return err(format!("{f}: {e}")),
        },
    };
    let id = match pd
        .identity()
        .and_then(|i| transport_identity(&i).map_err(|e| e.to_string()))
    {
        Ok(i) => i,
        Err(e) => return err(e),
    };
    let clients = match pd.client_keys() {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let writers = match pd.writer_keys() {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let acl = match pd.load_acl() {
        Ok(a) => a,
        Err(e) => return err(e),
    };

    let mut peer = match Peer::open(pd.data(), mode, addressing, hostility) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    for vk in &writers {
        if let Err(e) = peer.roster.add(vk) {
            return err(format!("roster: {e}"));
        }
    }
    peer.acl = acl;
    // Enforced at the dispatch (`nas_transfer::handle`), where every request
    // passes, not per store method.
    peer.witness_only = o.witness;
    for (subject, vk) in &clients {
        peer.bind_subject(vk, subject);
    }

    let listener = match TcpListener::bind(o.listen) {
        Ok(l) => l,
        Err(e) => return err(format!("listen {}: {e}", o.listen)),
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| o.listen.to_string());
    // Printed before the first accept so a script can wait on this line.
    println!(
        "peer {dir} listening on {local} ({}{}, {} clients, {} writers, {:?})",
        if o.witness { "witness-only, " } else { "" },
        hostility.describe(),
        clients.len(),
        writers.len(),
        mode
    );

    let mut conns: u64 = 0;
    loop {
        let (sock, from) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("  accept: {e}");
                continue;
            }
        };
        // Connections are served one at a time. The peer is one mutable
        // state and a fork is per *connection* (`set_view`); until the peer
        // is behind a lock, a thread per client would race the slot store.
        let mut ch = match Channel::accept_from(sock, &id, |vk| clients.values().any(|k| k == vk)) {
            Ok(ch) => ch,
            Err(e) => {
                eprintln!("  {from}: handshake refused: {e}");
                if o.once {
                    // A refused stranger does not count as the one connection.
                    continue;
                }
                continue;
            }
        };
        let subject = peer
            .subject_for(ch.peer_identity())
            .unwrap_or("?")
            .to_string();
        // Which branch this connection is shown (SPECS §5.3). A forking peer
        // cannot tell one device of a namespace from another — they share the
        // transport key — so it equivocates blindly: alternate connections
        // are served alternate branches. An honest peer ignores the view.
        let view = (conns % 2) as u8;
        conns += 1;
        peer.set_view(view);
        let tag = if peer.hostility.fork {
            format!(" (view {view})")
        } else {
            String::new()
        };
        match nas_transfer::serve(&mut peer, &mut ch) {
            Ok(n) => println!("  {from} as {subject}{tag}: {n} requests"),
            Err(e) => eprintln!("  {from} as {subject}{tag}: {e}"),
        }
        if o.once {
            return exit::OK;
        }
    }
}

// ── Client side ────────────────────────────────────────────────────────────

/// `nas ns export-pub <ns> <out-dir>` — the public keys a peer operator needs
/// to admit this namespace: its transport key (for `nas peer allow`) and its
/// slot-writer key (for `nas peer writer`). A transit-only namespace also
/// writes its tenant salt, which the peer needs to address its blobs.
pub fn export_pub(ns: &str, out: &str, passphrase: Option<Vec<u8>>) -> i32 {
    let repo = match Repo::open_with(ns, passphrase) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let out = Path::new(out);
    if let Err(e) = fs::create_dir_all(out) {
        return err(format!("{}: {e}", out.display()));
    }
    for (role, file) in [(Role::Transport, "transport.pub"), (Role::Slot, "slot.pub")] {
        let id = match repo.identity(role) {
            Ok(i) => i,
            Err(e) => return err(format!("{role:?} identity: {e}")),
        };
        if let Err(e) = fs::write(out.join(file), id.verifying_key()) {
            return err(e);
        }
        println!("{file}\t{}", fingerprint(id.verifying_key()));
    }
    let salt = repo.tenant_salt();
    if !salt.is_empty() {
        if let Err(e) = fs::write(out.join("tenant.salt"), salt) {
            return err(e);
        }
        println!("tenant.salt\t{} B (not secret; SPECS §2.2.3)", salt.len());
    }
    exit::OK
}

pub struct SyncOpts<'a> {
    pub peer: &'a str,
    pub peer_pub: &'a str,
    pub passphrase: Option<Vec<u8>>,
    /// A second node — typically `nas peer serve --witness` — that relays
    /// observations of slot heads (SPECS §5.3). Consulted before the head is
    /// trusted, told about it after.
    pub witness: Option<&'a str>,
    pub witness_pub: Option<&'a str>,
}

/// Connect to `addr` and complete the handshake with the key in `pub_path`
/// pinned: whoever answers must be that key, or the handshake fails before a
/// byte of ours is sent. The failure is already reported; the `Err` is the
/// exit code to return.
fn dial(repo: &Repo, addr: &str, pub_path: &str) -> Result<Channel, i32> {
    let vk = fs::read(pub_path).map_err(|e| err(format!("{pub_path}: {e}")))?;
    let tid = repo
        .identity(Role::Transport)
        .map_err(|e| e.to_string())
        .and_then(|i| transport_identity(&i).map_err(|e| e.to_string()))
        .map_err(|e| err(format!("transport identity: {e}")))?;
    let sock = TcpStream::connect(addr).map_err(|e| err(format!("connect {addr}: {e}")))?;
    let ch = Channel::connect(sock, &tid, vk.clone())
        .map_err(|e| refused(format!("handshake with {addr}: {e}")))?;
    println!("connected to {addr} (peer key {})", fingerprint(&vk));
    Ok(ch)
}

/// Where the last head this client published to a peer is pinned.
fn pin_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/peer-seq")
}

/// What this device last saw served or published: a specific record, not a
/// height (SPECS §5.3). A pin written before the hash was recorded (`seq`
/// only) still bounds rollback and is upgraded on the next accepted head.
#[derive(Clone, Copy)]
struct Pin {
    seq: u64,
    record_hash: Option<[u8; 32]>,
}

/// A device that joined by copying `config` + `wraps/` has no `state/` yet;
/// the pin must still land, since it is that device's only memory of what it
/// has seen served.
fn write_pin(repo: &Repo, seq: u64, record_hash: [u8; 32]) -> Result<(), String> {
    let p = pin_path(repo);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("pin: {e}"))?;
    }
    fs::write(p, format!("{seq} {}\n", hex(&record_hash))).map_err(|e| format!("pin: {e}"))
}

/// The top rung of the ladder this device has seen (SPECS §5.5).
///
/// Kept separately from the record pin because it answers a different
/// question: the record pin says which *record* was at a sequence, this says
/// which *ladder* the peer was serving. A peer can roll one back without the
/// other.
fn cp_pin_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/peer-checkpoint")
}

fn write_cp_pin(repo: &Repo, seq: u64, hash: [u8; 32]) -> Result<(), String> {
    let p = cp_pin_path(repo);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("checkpoint pin: {e}"))?;
    }
    fs::write(p, format!("{seq} {}\n", hex(&hash))).map_err(|e| format!("checkpoint pin: {e}"))
}

fn read_cp_pin(repo: &Repo) -> Option<(u64, [u8; 32])> {
    let s = fs::read_to_string(cp_pin_path(repo)).ok()?;
    let mut it = s.split_whitespace();
    let seq: u64 = it.next()?.parse().ok()?;
    let h = it.next()?;
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some((seq, out))
}

fn read_pin(repo: &Repo) -> Option<Pin> {
    let s = fs::read_to_string(pin_path(repo)).ok()?;
    let mut it = s.split_whitespace();
    let seq = it.next()?.parse().ok()?;
    let record_hash = it.next().and_then(|h| {
        if h.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    });
    Some(Pin { seq, record_hash })
}

/// `nas peer sync <ns> --peer <host:port> --peer-pub <file>`
pub fn sync(ns: &str, o: SyncOpts<'_>) -> i32 {
    let repo = match Repo::open_with(ns, o.passphrase) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let mut ch = match dial(&repo, o.peer, o.peer_pub) {
        Ok(c) => c,
        Err(code) => return code,
    };

    // ── Blobs ──
    let addrs = match blobs.addrs() {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let (mut pushed, mut present, mut bytes_sent) = (0usize, 0usize, 0usize);
    for addr in &addrs {
        let ct = match blobs.get(addr) {
            Ok(b) => b,
            Err(e) => return err(format!("{}: {e}", addr.to_hex())),
        };
        match call(&mut ch, &Request::HasBlob(*addr)) {
            Ok(Response::Bool(true)) => {
                // SPECS §4.5: "I have it" is a claim. Make the peer prove it
                // before trusting the claim enough to skip the upload.
                let nonce: [u8; 32] = match nas_crypto::random::array() {
                    Ok(n) => n,
                    Err(e) => return err(e),
                };
                match call(&mut ch, &Request::Prove { addr: *addr, nonce }) {
                    Ok(Response::Proof(p)) if BlobStore::check_proof(&ct, &nonce, &p) => {
                        present += 1;
                    }
                    Ok(Response::Proof(_)) | Ok(Response::Error(_)) => {
                        return refused(format!(
                            "peer claims to hold {} but cannot prove it (dedup lie, SPECS §4.5)",
                            addr.to_hex()
                        ));
                    }
                    Ok(other) => return err(format!("unexpected reply to Prove: {other:?}")),
                    Err(e) => return err(e),
                }
            }
            Ok(Response::Bool(false)) => match call(&mut ch, &Request::PutBlob(ct.clone())) {
                Ok(Response::Stored(a)) if a == *addr => {
                    pushed += 1;
                    bytes_sent += ct.len();
                }
                Ok(Response::Stored(a)) => {
                    return refused(format!(
                        "peer stored {} under {} — not our bytes",
                        addr.to_hex(),
                        a.to_hex()
                    ));
                }
                Ok(Response::Error(m)) => return refused(format!("put {}: {m}", addr.to_hex())),
                Ok(other) => return err(format!("unexpected reply to PutBlob: {other:?}")),
                Err(e) => return err(e),
            },
            Ok(Response::Error(m)) => return refused(format!("has {}: {m}", addr.to_hex())),
            Ok(other) => return err(format!("unexpected reply to HasBlob: {other:?}")),
            Err(e) => return err(e),
        }
    }
    println!(
        "blobs: {pushed} pushed ({bytes_sent} B), {present} already held and proven, {} total",
        addrs.len()
    );

    // ── Head ──
    //
    // No local HEAD does not mean nothing to do: a second device of this
    // namespace has no HEAD and no pin, and is exactly the client a rolled-back
    // or withholding peer fools (SPECS §5.3). It still asks for the served head
    // and checks it against the witness node before believing anything.
    let root = match repo.head() {
        None => None,
        Some(h) => match Addr::from_hex(&h) {
            Ok(a) => Some(a),
            Err(e) => return err(format!("state/HEAD: {e}")),
        },
    };
    let writer = match repo.identity(Role::Slot) {
        Ok(i) => i,
        Err(e) => return err(format!("slot identity: {e}")),
    };
    let slot = SlotId::new(writer.verifying_key(), ns.as_bytes());
    let pinned = read_pin(&repo);

    let served = match call(&mut ch, &Request::SlotHead(slot)) {
        Ok(Response::Record(r)) => r,
        Ok(Response::Error(m)) => return refused(format!("head: {m}")),
        Ok(other) => return err(format!("unexpected reply to SlotHead: {other:?}")),
        Err(e) => return err(e),
    };
    let served = match served {
        None => None,
        Some(bytes) => match SlotRecord::decode(&bytes) {
            Ok(r) => Some(r),
            Err(e) => return refused(format!("peer served an undecodable head: {e}")),
        },
    };

    // The local pin is this device's memory of what it has already seen
    // served or published: a specific record, not merely a height (SPECS
    // §5.3). A peer serving anything older, or nothing at all when there was
    // something, is rolling back (SPECS §5.2). A peer serving a *different*
    // record at the pinned sequence is forking — and since the pin is one
    // point, the chain from it to the served head is walked below so that
    // nothing between them was swapped either.
    let mut roster = Roster::new();
    if let Err(e) = roster.add(writer.verifying_key()) {
        return err(format!("roster: {e}"));
    }
    match (&served, pinned) {
        (None, Some(p)) => {
            return refused(format!(
                "peer serves no head, but seq {} was seen here before (rollback or withholding)",
                p.seq
            ));
        }
        (None, None) => {}
        (Some(h), pin) => {
            if h.slot_id != slot {
                return refused("peer served a record for a different slot");
            }
            if let Err(e) = h.verify(writer.verifying_key()) {
                return refused(format!(
                    "peer served a head this namespace did not sign: {e}"
                ));
            }
            if let Some(p) = pin {
                if h.seq < p.seq {
                    return refused(format!(
                        "peer serves seq {}, but seq {} was seen here before (rollback)",
                        h.seq, p.seq
                    ));
                }
            }
        }
    }

    // ── Witness node (SPECS §5.3) ──
    //
    // The pin above is one device's memory. A second device of the same
    // namespace has no pin, and a peer that rolled back after the first device
    // published would look honest to it — unless someone else remembers. That
    // is the witness node: before trusting the served head, ask it what this
    // namespace observed before; after settling on a head, tell it.
    //
    // The roster is this namespace's own `Role::Witness` key. Every device of
    // the namespace derives the same one from the seed, so an observation from
    // one device is believed on another (UC07). Believing *other* observers is
    // an M2 roster, and is where a witness node run by a stranger becomes
    // useful rather than merely honest.
    let witness_node = match (o.witness, o.witness_pub) {
        (Some(addr), Some(pub_path)) => {
            let wid = match repo.identity(Role::Witness) {
                Ok(i) => i,
                Err(e) => return err(format!("witness identity: {e}")),
            };
            let mut wch = match dial(&repo, addr, pub_path) {
                Ok(c) => c,
                Err(code) => return code,
            };
            let held = match call(&mut wch, &Request::Witnesses(slot)) {
                Ok(Response::Records(rs)) => rs,
                Ok(Response::Error(m)) => return refused(format!("witness node: {m}")),
                Ok(other) => return err(format!("unexpected reply to Witnesses: {other:?}")),
                Err(e) => return err(e),
            };
            let mut ours = Vec::new();
            for bytes in &held {
                let w = match Witness::decode(bytes) {
                    Ok(w) => w,
                    Err(e) => {
                        return refused(format!("witness node relayed an undecodable witness: {e}"))
                    }
                };
                if w.witness_pk != wid.verifying_key() || w.slot_id != slot || w.verify().is_err() {
                    continue;
                }
                ours.push(w);
            }
            Some((wch, wid, addr, held.len(), ours))
        }
        (None, None) => None,
        _ => return err("--witness and --witness-pub go together"),
    };
    let witnessed: &[Witness] = witness_node.as_ref().map(|w| w.4.as_slice()).unwrap_or(&[]);

    // A witness ahead of the served head is a rollback (or withholding) that
    // no pin here can see: the observation was another device's.
    for w in witnessed {
        match &served {
            None => {
                return refused(format!(
                    "peer serves no head, but seq {} was witnessed (rollback or withholding)",
                    w.seq
                ))
            }
            Some(h) if w.seq > h.seq => {
                return refused(format!(
                    "peer serves seq {}, but seq {} was witnessed (rollback)",
                    h.seq, w.seq
                ))
            }
            _ => {}
        }
    }

    // ── Ownership handoffs (SPECS §5.1) ──
    //
    // Under `single-writer` a change of writer is an alarm unless the
    // *outgoing* writer signed it away. The client cannot judge that without
    // the signed record, so it asks for what the peer holds and hands it to
    // the walk. Only the signature is trusted: an unverifiable handoff, or
    // one for another slot, is dropped here rather than left for the walk to
    // trip over.
    //
    // The roster is deliberately **not** extended from what comes back. A
    // handoff carries the outgoing writer's key in full, so it is tempting to
    // add it — and that would let the peer decide who may have written this
    // namespace's history, which is the one thing the roster exists to say.
    // A chain by a writer this device does not know still refuses.
    //
    // Today every device of a namespace derives the same `Role::Slot` key, so
    // there is only ever one writer and this changes no outcome. It is here
    // so that a chain which does cross an authorised change is refused for a
    // reason, rather than because nobody asked.
    let handoffs = match call(&mut ch, &Request::Handoffs(slot)) {
        Ok(Response::Records(rs)) => rs,
        Ok(Response::Error(m)) => return refused(format!("handoffs: {m}")),
        Ok(other) => return err(format!("unexpected reply to Handoffs: {other:?}")),
        Err(e) => return err(e),
    };
    let mut authorisations = Vec::new();
    for bytes in &handoffs {
        let Ok(h) = SlotHandoff::decode(bytes) else {
            return refused("peer served an undecodable handoff".to_string());
        };
        if h.slot_id == slot && h.verify().is_ok() {
            authorisations.push(h);
        }
    }
    // Someone asserting this namespace signed its own slot away is worth a
    // human's attention: either it is a forgery, or this device's writer key
    // is not only this device's any more.
    //
    // Reported, not refused. Any admitted client can publish a handoff — the
    // signature is what makes one authority, not the right to send it — so
    // refusing on the mere existence of one would hand every client a way to
    // wedge the namespace.
    for h in &authorisations {
        if h.from_pk == writer.verifying_key() {
            println!(
                "  !! a handoff claims this namespace signed seq {} over to {}; \
                 if that was not done here, the slot key is compromised (SPECS §5.1)",
                h.at_seq,
                h.to.to_hex()
            );
        }
    }
    if !authorisations.is_empty() {
        println!(
            "handoffs: {} of {} served verify for this slot",
            authorisations.len(),
            handoffs.len()
        );
    }

    // ── Skip-chain ladder (SPECS §5.5) ──
    //
    // The rungs are asked for and verified before the head is believed,
    // because the ladder answers a question the record walk cannot: this
    // device pins the top rung it has seen, so a peer serving a *different*
    // ladder — one that does not contain that rung — is caught the way a
    // different record at a pinned sequence is.
    //
    // Anchored at the pin when there is one, which also means the peer may
    // prune rungs below it; anchored at genesis otherwise, because a ladder
    // that starts wherever the peer likes is not evidence of anything.
    let cp_pin = read_cp_pin(&repo);
    let (cp_from, cp_anchor) = match cp_pin {
        Some((seq, hash)) => (seq, Some(hash)),
        None => (0, None),
    };
    // Paged, for the same reason the history walk is: one response carries
    // what fits in `MAX_FRAME`, about 74 rungs, which at an interval of 256 is
    // only 19 000 records of ladder. Asking once would truncate at the
    // *bottom* — losing exactly the high rungs a far-behind client climbs to,
    // and turning a good ladder into `Unreachable`.
    //
    // Bounded by `MAX_CHECKPOINTS_PER_SLOT`, which is what the peer will hold,
    // so a peer that keeps answering cannot keep this loop going.
    let mut rungs: Vec<Checkpoint> = Vec::new();
    {
        let mut next = cp_from;
        loop {
            let page = match call(&mut ch, &Request::Checkpoints { slot, from: next }) {
                Ok(Response::Records(rs)) => rs,
                Ok(Response::Error(m)) => return refused(format!("checkpoints: {m}")),
                Ok(other) => return err(format!("unexpected reply to Checkpoints: {other:?}")),
                Err(e) => return err(e),
            };
            if page.is_empty() {
                break;
            }
            for b in &page {
                match Checkpoint::decode(b) {
                    Ok(c) => rungs.push(c),
                    Err(e) => {
                        return refused(format!("peer served an undecodable checkpoint: {e}"))
                    }
                }
            }
            let last = rungs.last().map(|c| c.seq).unwrap_or(next);
            // A peer that stops advancing ends the loop rather than driving
            // it: the party being distrusted does not get to decide how long
            // this runs.
            if rungs.len() >= MAX_CHECKPOINTS_PER_SLOT || last < next {
                break;
            }
            next = last + 1;
        }
    }
    let top: Option<Checkpoint> = if rungs.is_empty() {
        if let Some((seq, _)) = cp_pin {
            return refused(format!(
                "peer serves no checkpoint at or above seq {seq}, which was pinned here (SPECS §5.5)"
            ));
        }
        None
    } else {
        // An empty tail verifies the ladder on its own: links, signatures,
        // roster and the anchor. The records it stands for are the chain walk
        // below, and keeping the two separate is what lets each be reported
        // for what it is.
        match verify_skip_chain(&rungs, &[], slot, &roster, cp_anchor, &authorisations) {
            Ok(w) => {
                println!(
                    "ladder: {} rung{} verified, seq {}..{}, {}",
                    w.checkpoints,
                    if w.checkpoints == 1 { "" } else { "s" },
                    w.from_seq,
                    w.head_seq,
                    if cp_anchor.is_some() {
                        "continuing the rung pinned here"
                    } else {
                        "from genesis"
                    }
                );
                let top = rungs.last().cloned();
                // A ladder this device verified is now its floor too, exactly
                // as an accepted head becomes the record pin: what was *seen*
                // here bounds a rollback, not only what was published here. A
                // device that verified a ladder to seq 512 and did not pin it
                // would accept the same peer dropping back to genesis
                // tomorrow.
                if let Some(c) = &top {
                    if cp_pin.is_none_or(|(seq, _)| c.seq > seq) {
                        if let Err(e) = write_cp_pin(&repo, c.seq, c.checkpoint_hash()) {
                            return err(e);
                        }
                    }
                }
                top
            }
            Err(e) => return refused(format!("peer's checkpoint ladder does not verify: {e}")),
        }
    };

    // ── Chain walk (SPECS §5.3, mechanism 2) ──
    //
    // Everything at or below the served head that this namespace has a
    // memory of — this device's pin, every witness its devices published —
    // must lie on the chain the peer serves *now*. A forking peer keeps two
    // consistent histories and shows each client one; every record on both
    // is genuinely signed, so no signature check can tell. Comparing what was
    // seen before against what is served now, at the same sequence, can.
    //
    // A witness *below* the head is the case `SlotClient::forked` cannot
    // check on its own — a witness carries no ancestry — and the usual shape
    // of a real fork, since each device witnesses its own head. With the
    // peer's retained history it is checkable, and checked here.
    if let Some(h) = &served {
        let from = witnessed
            .iter()
            .map(|w| w.seq)
            .chain(pinned.map(|p| p.seq))
            .min()
            .unwrap_or(h.seq)
            .min(h.seq);

        // Which walk can reach the head (SPECS §5.5).
        //
        // The full walk is preferred whenever it arrives: it proves the peer
        // served a contiguous history, which no ladder does. Climbing is what
        // a client too far behind for one response does instead of giving up
        // — which is what it used to do here, refusing however good the
        // ladder was.
        //
        // A history longer than one response is **paged**, not given up on.
        // One response carries whatever fits in `MAX_FRAME` — about 74 records
        // at ~3.5 KB each, well below the count ceiling of 256 — and the
        // checkpoint interval is 256, so without paging no rung could ever
        // leave a walkable tail and the ladder would be decorative.
        //
        // What bounds the linear part is therefore patience, not framing:
        // `RETAIN_N` records, the peer's own retention window. Past that the
        // client climbs.
        let fetch = |ch: &mut Channel, from: u64, budget: usize| -> Result<Vec<SlotRecord>, i32> {
            let mut out: Vec<SlotRecord> = Vec::new();
            let mut next = from;
            loop {
                let raw = match call(ch, &Request::SlotHistory { slot, from: next }) {
                    Ok(Response::Records(rs)) => rs,
                    Ok(Response::Error(m)) => return Err(refused(format!("history: {m}"))),
                    Ok(other) => {
                        return Err(err(format!("unexpected reply to SlotHistory: {other:?}")))
                    }
                    Err(e) => return Err(err(e)),
                };
                if raw.is_empty() {
                    break;
                }
                for bytes in &raw {
                    match SlotRecord::decode(bytes) {
                        Ok(r) => out.push(r),
                        Err(e) => {
                            return Err(refused(format!(
                                "peer served an undecodable history record: {e}"
                            )))
                        }
                    }
                }
                let last = out.last().map(|r| r.seq).unwrap_or(next);
                // Stop on arrival, on budget, or on a peer that is not
                // advancing — the last of which would otherwise be a loop
                // driven by the party being distrusted.
                if last >= h.seq || out.len() >= budget || last < next {
                    break;
                }
                next = last + 1;
            }
            Ok(out)
        };

        let offered = match fetch(&mut ch, from, RETAIN_N) {
            Ok(c) => c,
            Err(code) => return code,
        };
        let arrived = offered.last().is_some_and(|r| r.seq == h.seq);
        let rung_seqs: Vec<u64> = rungs.iter().map(|c| c.seq).collect();
        let (walk_from, skipped, chain) = if arrived {
            (from, 0u64, offered)
        } else {
            match plan_walk(from, h.seq, &rung_seqs, RETAIN_N as u64) {
                WalkPlan::Full { .. } => {
                    // The peer stopped short of the head inside its own
                    // capacity: it is not serving the history it claims.
                    return refused(format!(
                        "peer serves seq {} but its history from seq {from} stops at seq {}",
                        h.seq,
                        offered.last().map(|r| r.seq).unwrap_or(from)
                    ));
                }
                WalkPlan::Skip { top_seq, skipped, .. } => match fetch(&mut ch, top_seq, RETAIN_N) {
                    Ok(c) => (top_seq, skipped, c),
                    Err(code) => return code,
                },
                WalkPlan::Unreachable { span, best_rung } => {
                    return refused(format!(
                        "peer serves seq {}, {span} above the lowest sequence this device \
                         remembers, and this client walks at most {} records linearly. {} \
                         (SPECS §5.5)",
                        h.seq,
                        RETAIN_N,
                        match best_rung {
                            Some(r) => format!(
                                "Its highest checkpoint is at seq {r}, too far below the head to climb to"
                            ),
                            None => "It serves no checkpoint to climb".to_string(),
                        }
                    ))
                }
            }
        };

        let walk = if skipped == 0 {
            // The first link is open unless the walk starts at genesis: a walk
            // from a witnessed sequence has no memory of that record's
            // predecessor. Contiguity and every later link are verified.
            let expect_prev = chain.first().filter(|f| f.seq > 0).map(|f| f.prev);
            match verify_chain_with_handoffs(&chain, slot, &roster, expect_prev, &authorisations) {
                Ok(w) => w,
                Err(e) => {
                    return refused(format!(
                        "peer's history from seq {walk_from} does not verify: {e}"
                    ))
                }
            }
        } else {
            // Climbing: the ladder is re-verified together with the tail, so
            // the record the top rung names has to be the one the tail starts
            // with. The rungs above `walk_from` are not part of this walk.
            let climbed: Vec<Checkpoint> = rungs
                .iter()
                .filter(|c| c.seq <= walk_from)
                .cloned()
                .collect();
            match verify_skip_chain(&climbed, &chain, slot, &roster, cp_anchor, &authorisations) {
                Ok(w) => Walk {
                    slot_id: w.slot_id,
                    regime: chain.first().map(|r| r.regime).unwrap_or(Regime::CasMerge),
                    first_seq: w.from_seq,
                    head_seq: w.head_seq,
                    head_hash: w.head_hash,
                },
                Err(e) => {
                    return refused(format!(
                        "peer's ladder and history from seq {walk_from} do not verify: {e}"
                    ))
                }
            }
        };
        if walk.head_seq != h.seq || walk.head_hash != h.record_hash() {
            return refused(format!(
                "peer serves seq {} but the history it offered from seq {walk_from} reaches seq {} (SPECS §5.5)",
                h.seq, walk.head_seq,
            ));
        }

        // Every memory this device has must lie on what was served. A memory
        // the walk did not cover is NOT a pass: it is counted and reported,
        // because "the pin lies on it" said of a sequence nobody looked at is
        // exactly the overclaim SPECS §5.4 is about.
        let at = |seq: u64| chain.iter().find(|r| r.seq == seq);
        let rung_at = |seq: u64| rungs.iter().find(|c| c.seq == seq);
        let mut unchecked = 0usize;
        if let Some(p) = pinned {
            match (p.record_hash, at(p.seq), rung_at(p.seq)) {
                (Some(want), Some(r), _) if r.record_hash() != want => {
                    return refused(format!(
                        "fork: the peer serves a different record at seq {} than the one seen here before (SPECS §5.3)",
                        p.seq
                    ))
                }
                // Skipped, but a rung names that very record — the ladder
                // carries a record hash, so the pin is still checkable there.
                (Some(want), None, Some(c)) if c.record_hash != want => {
                    return refused(format!(
                        "fork: the peer's checkpoint at seq {} names a different record than the one seen here before (SPECS §5.3)",
                        p.seq
                    ))
                }
                (Some(_), None, None) => unchecked += 1,
                _ => {}
            }
        }
        for w in witnessed {
            match at(w.seq) {
                Some(r) if r.sig_hash() != w.sig_hash => {
                    return refused(format!(
                        "fork: the witness saw a different record at seq {} than the chain the peer now serves (SPECS §5.3)",
                        w.seq
                    ))
                }
                Some(_) => {}
                // A witness carries a signature hash and a rung carries a
                // record hash, so a rung cannot stand in for one. A witness
                // below the skipped span simply was not checked.
                None => unchecked += 1,
            }
        }

        let memories = usize::from(pinned.is_some()) + witnessed.len();
        if skipped == 0 {
            println!(
                "chain: walked seq {walk_from}..{}; {} of {memories} memories checked, none contradicted",
                h.seq,
                memories - unchecked
            );
        } else {
            println!(
                "chain: climbed {} rungs over seq {from}..{walk_from} then walked {walk_from}..{}; \
                 {skipped} records taken on the writer's word, {} of {memories} memories checked",
                rungs.iter().filter(|c| c.seq <= walk_from).count(),
                h.seq,
                memories - unchecked
            );
            if unchecked > 0 {
                println!(
                    "  !! {unchecked} of them fall in the skipped span and were NOT checked (SPECS §5.4)"
                );
            }
        }
    }
    if let Some((_, _, addr, total, ours)) = &witness_node {
        println!(
            "witnesses: {} of {total} relayed by {addr} are this namespace's; none contradict the served head",
            ours.len()
        );
    }

    // `None` means there is nothing to publish (the peer already serves this
    // HEAD, or there is no local HEAD); `Some` is the next record to publish.
    let next = match &served {
        None => root.map(|r| (0, [0u8; 32], r)),
        Some(h) => match root {
            Some(r) if h.root == r => {
                println!(
                    "head: seq {} already points at {}; up to date",
                    h.seq,
                    r.to_hex()
                );
                None
            }
            Some(r) => Some((h.seq + 1, h.record_hash(), r)),
            None => {
                println!(
                    "head: peer serves seq {} -> {}; nothing local to publish",
                    h.seq,
                    h.root.to_hex()
                );
                None
            }
        },
    };

    let (seq, sig_hash) = match next {
        None => {
            let Some(h) = served.as_ref() else {
                // Nothing served, nothing local, and (if asked) no witness
                // contradicting that. Genuinely empty.
                println!("peer serves no head and nothing is published here yet");
                return exit::OK;
            };
            // A served head this device accepted is now its floor too: the
            // pin is what was *seen* here, not only what was published here,
            // so a later rollback is caught even by a device that never wrote.
            if pinned.is_none_or(|p| h.seq > p.seq || p.record_hash.is_none()) {
                if let Err(e) = write_pin(&repo, h.seq, h.record_hash()) {
                    return err(e);
                }
            }
            (h.seq, h.sig_hash())
        }
        Some((seq, prev, root)) => {
            let nonce: [u8; ROOT_NONCE_LEN] = match nas_crypto::random::array() {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            let rec =
                match SlotRecord::sign(&writer, slot, seq, root, nonce, prev, Regime::CasMerge) {
                    Ok(r) => r,
                    Err(e) => return err(format!("sign: {e}")),
                };
            let bytes = match rec.encode() {
                Ok(b) => b,
                Err(e) => return err(format!("encode: {e}")),
            };
            match call(&mut ch, &Request::PublishSlot(bytes)) {
                Ok(Response::Ok) => {}
                Ok(Response::Error(m)) => return refused(format!("publish seq {seq}: {m}")),
                Ok(other) => return err(format!("unexpected reply to PublishSlot: {other:?}")),
                Err(e) => return err(e),
            }
            if let Err(e) = write_pin(&repo, seq, rec.record_hash()) {
                return err(e);
            }
            println!(
                "head: published seq {seq} -> {} to slot {}",
                root.to_hex(),
                slot.to_hex()
            );

            // A rung every `CHECKPOINT_INTERVAL` records (SPECS §5.5), chained
            // to the top of the ladder just verified. Chaining to the verified
            // ladder rather than to whatever the peer last offered is the
            // point: a rung is this device's own statement about its history,
            // and it must not be built on something it did not check.
            //
            // A device that has never seen the ladder and is not at genesis
            // does not start a second one. Two rungs at one sequence signed by
            // the same key is equivocation — the exact evidence the peer keeps
            // both of — and producing it by accident would be worse than
            // skipping a rung.
            if is_checkpoint_seq(seq) {
                match (&top, seq) {
                    (None, s) if s > 0 => println!(
                        "  checkpoint at seq {s} skipped: no ladder is known here to extend"
                    ),
                    (prev, _) => {
                        let c = match Checkpoint::of_record(&writer, &rec, prev.as_ref()) {
                            Ok(c) => c,
                            Err(e) => return err(format!("checkpoint sign: {e}")),
                        };
                        let bytes = match c.encode() {
                            Ok(b) => b,
                            Err(e) => return err(format!("checkpoint encode: {e}")),
                        };
                        match call(&mut ch, &Request::PublishCheckpoint(bytes)) {
                            Ok(Response::Ok) => {}
                            Ok(Response::Error(m)) => {
                                return refused(format!("publish checkpoint {seq}: {m}"))
                            }
                            Ok(other) => {
                                return err(format!(
                                    "unexpected reply to PublishCheckpoint: {other:?}"
                                ))
                            }
                            Err(e) => return err(e),
                        }
                        if let Err(e) = write_cp_pin(&repo, seq, c.checkpoint_hash()) {
                            return err(e);
                        }
                        println!("  checkpointed seq {seq} (SPECS §5.5)");
                    }
                }
            }
            (seq, rec.sig_hash())
        }
    };

    if let Some((mut wch, wid, addr, _, _)) = witness_node {
        // `logical_time` is this observer's own counter, not a clock; the slot
        // sequence is monotone for one namespace's observations of its own slot.
        let w = match Witness::sign(&wid, slot, seq, sig_hash, seq) {
            Ok(w) => w,
            Err(e) => return err(format!("witness sign: {e}")),
        };
        let bytes = match w.encode() {
            Ok(b) => b,
            Err(e) => return err(format!("witness encode: {e}")),
        };
        match call(&mut wch, &Request::PublishWitness(bytes)) {
            Ok(Response::Ok) => println!("witnessed seq {seq} at {addr}"),
            Ok(Response::Error(m)) => {
                return refused(format!("witness node refused the observation: {m}"))
            }
            Ok(other) => return err(format!("unexpected reply to PublishWitness: {other:?}")),
            Err(e) => return err(e),
        }
    }
    exit::OK
}

fn call(ch: &mut Channel, r: &Request) -> Result<Response, String> {
    ch.call(r).map_err(|e| format!("peer: {e}"))
}
