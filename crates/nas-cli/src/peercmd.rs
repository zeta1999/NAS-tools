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
use nas_peer::{Acl, Hostility, Peer, Right};
use nas_slots::{Regime, SlotId, SlotRecord, ROOT_NONCE_LEN};
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
        match nas_transfer::serve(&mut peer, &mut ch) {
            Ok(n) => println!("  {from} as {subject}: {n} requests"),
            Err(e) => eprintln!("  {from} as {subject}: {e}"),
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
}

/// Where the last head this client published to a peer is pinned.
fn pin_path(repo: &Repo) -> PathBuf {
    repo.root.join("state/peer-seq")
}

fn read_pin(repo: &Repo) -> Option<u64> {
    fs::read_to_string(pin_path(repo))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// `nas peer sync <ns> --peer <host:port> --peer-pub <file>`
pub fn sync(ns: &str, o: SyncOpts<'_>) -> i32 {
    let repo = match Repo::open_with(ns, o.passphrase) {
        Ok(r) => r,
        Err(e) => return err(format!("namespace {ns}: {e}")),
    };
    let peer_vk = match fs::read(o.peer_pub) {
        Ok(b) => b,
        Err(e) => return err(format!("{}: {e}", o.peer_pub)),
    };
    let tid = match repo
        .identity(Role::Transport)
        .map_err(|e| e.to_string())
        .and_then(|i| transport_identity(&i).map_err(|e| e.to_string()))
    {
        Ok(i) => i,
        Err(e) => return err(format!("transport identity: {e}")),
    };
    let blobs = match repo.blobs() {
        Ok(b) => b,
        Err(e) => return err(e),
    };

    let sock = match TcpStream::connect(o.peer) {
        Ok(s) => s,
        Err(e) => return err(format!("connect {}: {e}", o.peer)),
    };
    // The peer key is pinned by `connect`: whoever answers must be the key in
    // `--peer-pub`, or the handshake fails before a byte of ours is sent.
    let mut ch = match Channel::connect(sock, &tid, peer_vk.clone()) {
        Ok(c) => c,
        Err(e) => return refused(format!("handshake with {}: {e}", o.peer)),
    };
    println!(
        "connected to {} (peer key {})",
        o.peer,
        fingerprint(&peer_vk)
    );

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
    let Some(head_hex) = repo.head() else {
        println!("no HEAD yet; nothing to publish");
        return exit::OK;
    };
    let root = match Addr::from_hex(&head_hex) {
        Ok(a) => a,
        Err(e) => return err(format!("state/HEAD: {e}")),
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

    // The local pin is the client's memory of what it has already published.
    // A peer serving anything older, or nothing at all when there was
    // something, is rolling back (SPECS §5.2) — the defence the socket tests
    // exercise, now on the CLI path.
    let (seq, prev) = match (&served, pinned) {
        (None, Some(p)) => {
            return refused(format!(
                "peer serves no head, but seq {p} was published here before (rollback or withholding)"
            ));
        }
        (None, None) => (0, [0u8; 32]),
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
                if h.seq < p {
                    return refused(format!(
                        "peer serves seq {}, but seq {p} was published here before (rollback)",
                        h.seq
                    ));
                }
            }
            if h.root == root {
                println!(
                    "head: seq {} already points at {}; up to date",
                    h.seq,
                    root.to_hex()
                );
                return exit::OK;
            }
            (h.seq + 1, h.record_hash())
        }
    };

    let nonce: [u8; ROOT_NONCE_LEN] = match nas_crypto::random::array() {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    let rec = match SlotRecord::sign(&writer, slot, seq, root, nonce, prev, Regime::CasMerge) {
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
    if let Err(e) = fs::write(pin_path(&repo), format!("{seq}\n")) {
        return err(format!("pin: {e}"));
    }
    println!(
        "head: published seq {seq} -> {} to slot {}",
        root.to_hex(),
        slot.to_hex()
    );
    exit::OK
}

fn call(ch: &mut Channel, r: &Request) -> Result<Response, String> {
    ch.call(r).map_err(|e| format!("peer: {e}"))
}
