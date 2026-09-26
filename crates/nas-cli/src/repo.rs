//! Local namespace state (SPECS §4).
//!
//! ```text
//! $NAS_HOME/<ns>/config           mode, key_scheme, padding_profile, version
//! $NAS_HOME/<ns>/vault            convergence secret + namespace root secret
//! $NAS_HOME/<ns>/blobs/…          the blob store
//! $NAS_HOME/<ns>/state/HEAD       the root directory manifest address
//! ```
//!
//! # The vault
//!
//! `vault.bin` is a sealed [`nas_vault::Vault`] (SPECS §3.1): one 32-byte seed
//! from which every role identity derives, plus the convergence-secret
//! generations and the pinned peers. Sealed with XChaCha20-Poly1305 under a
//! **vault key**, and written 0600 as well — the file permission is a second
//! line, not the only one.
//!
//! Where the vault key comes from is the mode's business (SPECS §2.2). `e2ee`
//! takes a high-entropy key the user holds; `passphrase` derives one with
//! Argon2id. Vault-backed modes store the key in the OS keychain when a helper
//! is available (`security` / `secret-tool`); otherwise they still write
//! `vault.key` beside the vault (0600). That file fallback relocates the secret
//! rather than protecting it, and is stated in [`VAULT_WARNING`]. Passphrase
//! mode already has no `vault.key` — leave it alone.
//!
//! What *has* changed since M0 is that the convergence secret and the namespace
//! root are no longer on disk in the clear, the identity is derived from a seed
//! rather than absent, and the container is versioned and authenticated.
//!
//! `state/` is local-only and never shipped to a peer (SPECS §4).

use nas_core::{KeyScheme, Mode, PaddingProfile};
use nas_crypto::{
    random, ConvergenceSecret, DirSecret, Identity, Role, RootKey, KEY_LEN, NONCE_LEN,
};
use nas_slots::Anchor;
use nas_store::{root_aad, RootManifest};
use nas_vault::{Argon2Params, NamespaceSecrets, Vault, WrapPolicy, WrapRecord};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VAULT_WARNING: &str = "the vault is sealed; its key is in the OS keychain when \
     available, else vault.key (0600) as a file fallback. The file relocates \
     the secret rather than protecting it — Linux CI without Secret Service \
     uses that fallback.";

/// Where a namespace's secrets come from.
///
/// The two modes differ in exactly this and nothing else: `e2ee` holds a vault
/// on disk, `passphrase` reconstructs its secrets from a passphrase and a wrap
/// record and keeps **nothing** locally that would let anyone else do the same.
/// That is what "recoverable from memory alone" has to mean to be true.
enum Secrets {
    Vault(Box<Vault>),
    Passphrase(Box<NamespaceSecrets>, Anchor),
}

pub struct Repo {
    pub root: PathBuf,
    pub mode: Mode,
    pub key_scheme: KeyScheme,
    pub padding: PaddingProfile,
    secrets: Secrets,
    /// Materialised once at open, so [`sealer`](Self::sealer) can hand out a
    /// borrow rather than every caller re-deriving it.
    cs_holder: ConvergenceSecret,
    /// `transit-only` only (SPECS §2.2.3). **Not secret** — it only has to be
    /// unshared, which is why it lives in the plaintext config rather than in
    /// the vault. Its job is to keep two tenants on one peer out of a shared
    /// dedup pool, not to hide anything.
    tenant_salt: Vec<u8>,
}

/// Where wrap records live. Named per sequence so a superseded one can be
/// deleted and its absence noticed (SPECS §2.2.2).
pub fn wrap_path(root: &Path, seq: u64) -> PathBuf {
    root.join("wraps").join(format!("{seq}.bin"))
}

/// The passphrase, from `--passphrase` or `$NAS_PASSPHRASE`.
///
/// Non-interactive on purpose, and it stays that way: this is the function the
/// `nas test` substrate calls, and that runs under a harness with no tty.
/// `None` here means "nobody supplied one", not "there is none to be had".
///
/// Asking a person is [`crate::prompt`]'s job, and it happens one layer up —
/// at `ns create` (which must resolve the passphrase before any directory
/// exists) and inside [`Repo::open_with`] (which only knows the namespace is
/// passphrase-mode after reading its config). Both prompt only when stdin is a
/// terminal; everywhere else the refusal stands, because a prompt that
/// silently fell back to a default would be worse than none.
pub fn passphrase_from(explicit: Option<&str>) -> Option<Vec<u8>> {
    explicit
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| std::env::var("NAS_PASSPHRASE").ok().map(String::into_bytes))
}

pub fn nas_home() -> PathBuf {
    home()
}

fn home() -> PathBuf {
    if let Ok(h) = std::env::var("NAS_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".local/share/nas")
}

pub fn path_of(ns: &str) -> PathBuf {
    home().join(ns)
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::E2ee => "e2ee",
        Mode::Passphrase => "passphrase",
        Mode::TransitOnly => "transit-only",
    }
}

pub fn parse_mode(s: &str) -> Option<Mode> {
    match s {
        "e2ee" => Some(Mode::E2ee),
        "passphrase" => Some(Mode::Passphrase),
        "transit-only" => Some(Mode::TransitOnly),
        _ => None,
    }
}

fn key_scheme_str(k: KeyScheme) -> &'static str {
    match k {
        KeyScheme::Convergent => "convergent",
        KeyScheme::IndexedRandom => "indexed-random",
        KeyScheme::Plaintext => "plaintext",
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn padding_str(p: PaddingProfile) -> &'static str {
    match p {
        PaddingProfile::None => "none",
        PaddingProfile::Classes => "classes",
        PaddingProfile::Fixed => "fixed",
    }
}

/// Object Lock mode (SPECS §16.1). Recorded at creation; what each mode
/// *costs* to loosen is the §16.2 quorum, which is not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLock {
    /// The owner may shorten retention, with the delete authority's signature.
    Governance,
    /// Nobody may shorten it before expiry — not even the owner.
    Compliance,
    /// An indefinite hold, orthogonal to any expiry.
    LegalHold,
}

impl ObjectLock {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Compliance => "compliance",
            Self::LegalHold => "legal-hold",
        }
    }
}

pub fn parse_object_lock(s: &str) -> Option<ObjectLock> {
    match s {
        "governance" => Some(ObjectLock::Governance),
        "compliance" => Some(ObjectLock::Compliance),
        "legal-hold" | "legal_hold" => Some(ObjectLock::LegalHold),
        _ => None,
    }
}

/// `7y`, `90d`, `24h`, or bare seconds. Returns seconds.
///
/// Years are 365 days: a retention period is a policy horizon, not a calendar,
/// and pretending otherwise would invite a leap-year argument over an archive.
pub fn parse_retention(s: &str) -> Option<u64> {
    let (digits, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = digits.parse().ok()?;
    let secs = match unit {
        "" | "s" => 1,
        "h" => 3_600,
        "d" => 86_400,
        "y" => 365 * 86_400,
        _ => return None,
    };
    n.checked_mul(secs)
}

pub fn parse_padding(s: &str) -> Option<PaddingProfile> {
    match s {
        "none" => Some(PaddingProfile::None),
        "classes" => Some(PaddingProfile::Classes),
        "fixed" => Some(PaddingProfile::Fixed),
        _ => None,
    }
}

/// 32 bytes from the OS CSPRNG.
///
/// Delegates to `nas_crypto::random`, which is the single place entropy enters
/// the system — including the all-zero check, so it exists once rather than in
/// each caller that remembers to write it.
pub fn random_secret() -> io::Result<[u8; KEY_LEN]> {
    random::array()
}

/// Exposed so sibling modules can write wrap records with the same care.
pub fn write_private_pub(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_private(path, bytes)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

/// Create a new `0600` file. Fails if `path` already exists, including when
/// the last component is a symlink: `O_EXCL` does not follow one.
fn open_exclusive(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// New file only. `O_EXCL` is the refusal: a path that already exists,
/// symlink included, is not opened and not followed. `.mode` is applied
/// only when the inode is created, so this is also what makes the file 0600.
fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = open_exclusive(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination exists; refusing to overwrite a vault key",
            )
        } else {
            e
        }
    })?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Sibling used to replace `path`. Same directory, so the rename is atomic.
/// The name is stable — `vault.bin` becomes `.vault.bin.tmp` — and tests
/// occupy that exact name to simulate a replace that must not start.
fn replace_tmp(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Replace `path` by writing a sibling, fsyncing it, and renaming over the
/// target. Returns the parent directory, which the caller still has to fsync.
///
/// `Err` means `path` was not replaced: the previous inode is still that name.
///
/// This is for `vault.bin` only. That file is the only copy of every
/// convergence-secret generation, the identity seed, and the pinned peers.
/// [`write_private`] truncates in place, so a crash or `ENOSPC` between the
/// truncate and the write leaves it empty or torn and every stored chunk
/// underivable. The other callers of `write_private` create a path that did
/// not hold history (`vault.key` and wrap `0` at create, a peer seed, a
/// roster file) or write `gateway.json` only when it is absent. None of them
/// replaces the sole record of secrets a rotation replaces. Export is the
/// other exception, and it must fail with `O_EXCL` rather than replace.
fn write_vault_replace(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use std::io::Write;
    let tmp = replace_tmp(path);
    {
        let mut file = open_exclusive(&tmp)?;
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(parent_dir(path).to_path_buf())
}

/// What a namespace declares about itself, readable **without any secret**.
///
/// Listing namespaces must not require unlocking them: a passphrase namespace
/// would otherwise have to be opened — and its Argon2id derivation run — just to
/// print its name, which is both slow and wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub mode: Mode,
    pub key_scheme: KeyScheme,
    pub padding: PaddingProfile,
    /// SPECS §16.1. `None` for a namespace created without Object Lock.
    pub object_lock: Option<ObjectLock>,
    /// Retention period in seconds, if one was set.
    pub retention_secs: Option<u64>,
    /// Everyday device named at create (`--device`). The honest client
    /// enforces append-only against this subject; the peer cannot, in an
    /// encrypted mode (SPECS §2.2).
    pub device: Option<String>,
}

impl Repo {
    /// Read the config alone. No secrets are touched.
    pub fn describe(ns: &str) -> io::Result<Description> {
        let cfg = fs::read_to_string(path_of(ns).join("config"))?;
        let mut d = Description {
            mode: Mode::E2ee,
            key_scheme: KeyScheme::Convergent,
            padding: PaddingProfile::None,
            object_lock: None,
            retention_secs: None,
            device: None,
        };
        for line in cfg.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some("mode"), Some(v)) => {
                    d.mode = parse_mode(v).ok_or_else(|| io::Error::other("bad mode"))?
                }
                (Some("padding_profile"), Some(v)) => {
                    d.padding = parse_padding(v).ok_or_else(|| io::Error::other("bad padding"))?
                }
                (Some("key_scheme"), Some("indexed-random")) => {
                    d.key_scheme = KeyScheme::IndexedRandom
                }
                (Some("object_lock"), Some(v)) => {
                    d.object_lock = Some(
                        parse_object_lock(v).ok_or_else(|| io::Error::other("bad object_lock"))?,
                    )
                }
                (Some("retention_secs"), Some(v)) => {
                    d.retention_secs = Some(
                        v.parse()
                            .map_err(|_| io::Error::other("bad retention_secs"))?,
                    )
                }
                (Some("device"), Some(v)) => d.device = Some(v.to_string()),
                _ => {}
            }
        }
        Ok(d)
    }

    pub fn exists(ns: &str) -> bool {
        path_of(ns).join("config").exists()
    }

    pub fn create(
        ns: &str,
        mode: Mode,
        key_scheme: KeyScheme,
        padding: PaddingProfile,
        passphrase: Option<Vec<u8>>,
        lock: Option<(ObjectLock, u64)>,
        device: Option<&str>,
    ) -> io::Result<Self> {
        let root = path_of(ns);
        fs::create_dir_all(root.join("state"))?;
        fs::create_dir_all(root.join("wraps"))?;
        // Fresh per namespace. Not secret, so it goes in the plaintext config.
        let tenant_salt = random_secret()?.to_vec();
        // The key scheme follows the mode: transit-only has no chunk keys at
        // all (SPECS §2.2.3), so recording "convergent" there would make every
        // manifest claim a protection the blobs do not have.
        let key_scheme = match mode {
            Mode::TransitOnly => KeyScheme::Plaintext,
            Mode::E2ee | Mode::Passphrase => key_scheme,
        };

        // Object Lock is recorded in the plaintext config on purpose: the
        // peer must be able to read the policy without reading the data, and
        // §16.3's enforcement is a set comparison over addresses, not a
        // decision that needs the manifest (SPECS §2.2).
        let lock_lines = match lock {
            Some((l, secs)) => format!("object_lock {}\nretention_secs {secs}\n", l.as_str()),
            None => String::new(),
        };
        // Named at create so `nas put` / `nas rm` know which ACL subject they
        // are. Inventing one at first write would make the grant decorative.
        let device_line = match device {
            Some(d) if !d.is_empty() => format!("device {d}\n"),
            _ => String::new(),
        };
        fs::write(
            root.join("config"),
            format!(
                "version 1\nmode {}\nkey_scheme {}\npadding_profile {}\ntenant_salt {}\n{lock_lines}{device_line}",
                mode_str(mode),
                key_scheme_str(key_scheme),
                padding_str(padding),
                hex(&tenant_salt),
            ),
        )?;

        let secrets = match mode {
            Mode::Passphrase => {
                // No prompt here, unlike `open_with`: the directories above
                // already exist by this point, so the CLI resolves the
                // passphrase — prompting if it can — before calling in. This
                // is the invariant, not the user-facing refusal.
                let pw = passphrase.ok_or_else(|| io::Error::other(crate::prompt::NO_TERMINAL))?;
                let dek = random_secret()?;
                // At creation there is no slot history, so the floor is
                // genuinely zero -- there is nothing to be rolled back to. It
                // rises with the first published record; the wrap chain exists
                // for exactly that.
                let anchor = Anchor {
                    seq: 0,
                    sig_hash: [0u8; 32],
                };
                let w = WrapRecord::create(
                    &pw,
                    &dek,
                    Argon2Params::SPEC,
                    &WrapPolicy::SPEC,
                    0,
                    anchor,
                    [0u8; 32],
                )
                .map_err(|e| io::Error::other(e.to_string()))?;
                write_private(
                    &wrap_path(&root, 0),
                    &w.encode().map_err(|e| io::Error::other(e.to_string()))?,
                )?;
                Secrets::Passphrase(Box::new(NamespaceSecrets::from_dek(&dek)), anchor)
            }
            Mode::E2ee | Mode::TransitOnly => {
                let vault = Vault::create().map_err(|e| io::Error::other(e.to_string()))?;
                let vault_key = random_secret()?;
                let sealed = vault
                    .seal_with(vault_key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                write_private(&root.join("vault.bin"), &sealed)?;
                // Keychain first. A successful write is the only reason we
                // skip vault.key on a *new* namespace. Migration of an
                // existing vault.key is open_with's job.
                if crate::keychain::store(ns, &vault_key).is_err() {
                    write_private(&root.join("vault.key"), &vault_key)?;
                }
                Secrets::Vault(Box::new(vault))
            }
        };

        let cs_holder = secrets_convergence(&secrets);
        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            secrets,
            cs_holder,
            tenant_salt,
        })
    }

    /// The highest wrap sequence present on disk.
    pub fn latest_wrap_seq(root: &Path) -> io::Result<u64> {
        let mut best: Option<u64> = None;
        for e in fs::read_dir(root.join("wraps"))? {
            let name = e?.file_name().to_string_lossy().into_owned();
            if let Some(n) = name
                .strip_suffix(".bin")
                .and_then(|n| n.parse::<u64>().ok())
            {
                best = Some(best.map_or(n, |b: u64| b.max(n)));
            }
        }
        best.ok_or_else(|| io::Error::other("no wrap record"))
    }

    pub fn load_wrap(root: &Path, seq: u64) -> io::Result<WrapRecord> {
        let bytes = fs::read(wrap_path(root, seq))?;
        WrapRecord::decode(&bytes).map_err(|e| io::Error::other(e.to_string()))
    }

    // There is deliberately no `open(ns)` without a passphrase argument: the
    // three `nas test` commands that used one silently dropped
    // `$NAS_PASSPHRASE` and failed on every passphrase-mode namespace.
    //
    // The terminal prompt below does not walk that back. It is not a second
    // source every caller now shares: it fires only when the caller passed
    // nothing *and* stdin is a terminal, which the harness never is. A caller
    // that has a passphrase must still hand it over.
    pub fn open_with(ns: &str, passphrase: Option<Vec<u8>>) -> io::Result<Self> {
        let root = path_of(ns);
        let cfg = fs::read_to_string(root.join("config"))?;
        let mut mode = Mode::E2ee;
        let mut key_scheme = KeyScheme::Convergent;
        let mut padding = PaddingProfile::None;
        let mut tenant_salt: Vec<u8> = Vec::new();
        for line in cfg.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some("mode"), Some(v)) => {
                    mode = parse_mode(v).ok_or_else(|| io::Error::other("bad mode"))?
                }
                (Some("padding_profile"), Some(v)) => {
                    padding = parse_padding(v).ok_or_else(|| io::Error::other("bad padding"))?
                }
                (Some("key_scheme"), Some("indexed-random")) => {
                    key_scheme = KeyScheme::IndexedRandom
                }
                (Some("key_scheme"), Some("plaintext")) => key_scheme = KeyScheme::Plaintext,
                (Some("tenant_salt"), Some(v)) => {
                    tenant_salt =
                        unhex(v).ok_or_else(|| io::Error::other("malformed tenant_salt"))?
                }
                _ => {}
            }
        }
        // A transit-only namespace with no salt would put every tenant on the
        // peer into one dedup pool -- the confirmation oracle SPECS §2.2.3
        // closes. Refuse rather than silently defaulting to empty.
        if mode == Mode::TransitOnly && tenant_salt.is_empty() {
            return Err(io::Error::other(
                "transit-only namespace has no tenant_salt in its config",
            ));
        }

        let secrets = match mode {
            Mode::Passphrase => {
                // Only now is it known that this namespace needs one at all —
                // which is why the prompt lives here and not at the call
                // sites. Opening an e2ee namespace must never ask.
                let pw = match passphrase {
                    Some(pw) => pw,
                    None => crate::prompt::passphrase(crate::prompt::Ask::Once)
                        .map_err(|e| io::Error::other(e.to_string()))?
                        .ok_or_else(|| io::Error::other(crate::prompt::NO_TERMINAL))?,
                };
                let seq = Self::latest_wrap_seq(&root)?;
                let w = Self::load_wrap(&root, seq)?;
                let (ns, anchor) = w
                    .unwrap(&pw, &WrapPolicy::SPEC)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Secrets::Passphrase(Box::new(ns), anchor)
            }
            Mode::E2ee | Mode::TransitOnly => {
                let sealed = fs::read(root.join("vault.bin"))?;
                let vault_key = Self::load_vault_key(ns, &root)?;
                let vault = Vault::open_with(&sealed, vault_key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Secrets::Vault(Box::new(vault))
            }
        };
        let cs_holder = secrets_convergence(&secrets);
        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            secrets,
            cs_holder,
            tenant_salt,
        })
    }

    /// Keychain first, then `vault.key` for migration. A successful keychain
    /// write after a file read does not delete the file — that is the
    /// operator's copy until they choose to remove it.
    fn load_vault_key(ns: &str, root: &Path) -> io::Result<[u8; KEY_LEN]> {
        if let Ok(Some(k)) = crate::keychain::load(ns) {
            return Ok(k);
        }
        let key_bytes = fs::read(root.join("vault.key"))?;
        let vault_key: [u8; KEY_LEN] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::other("vault.key is not 32 bytes"))?;
        let _ = crate::keychain::store(ns, &vault_key);
        Ok(vault_key)
    }

    /// The freshness anchor a passphrase recovery yields (SPECS §2.2.2).
    ///
    /// `None` for vault-backed modes, where the capability carries it instead.
    pub fn recovered_anchor(&self) -> Option<Anchor> {
        match &self.secrets {
            Secrets::Passphrase(_, a) => Some(*a),
            Secrets::Vault(_) => None,
        }
    }

    /// A role identity (SPECS §3.1).
    pub fn identity(&self, role: Role) -> io::Result<Identity> {
        match &self.secrets {
            Secrets::Vault(v) => v
                .identity(role)
                .map_err(|e| io::Error::other(e.to_string())),
            // A passphrase namespace has one seed and no vault, so both roles
            // derive from it -- still distinct keypairs, by role separation.
            Secrets::Passphrase(ns, _) => match role {
                Role::Lease => ns.lease_identity(),
                Role::Transport => ns.transport_identity(),
                // Previously folded into the slot key, so a passphrase
                // namespace's witness was its own writer. An observer that can
                // write what it observes is not an observer.
                Role::Witness => ns.witness_identity(),
                _ => ns.slot_identity(),
            }
            .map_err(|e| io::Error::other(e.to_string())),
        }
    }

    /// The convergence-secret generation new writes use (SPECS §3.9c).
    ///
    /// Passphrase namespaces have no generation table: rotating `CS` there
    /// would mean changing the DEK, which is a re-encryption rather than a
    /// vault edit (§3.9c), so the answer is always 0.
    pub fn generation(&self) -> u32 {
        match &self.secrets {
            Secrets::Vault(v) => v.current_generation().number,
            Secrets::Passphrase(..) => 0,
        }
    }

    /// Append a convergence-secret generation and seal the vault again
    /// (SPECS §3.9c). Does not rewrite existing chunks. Passphrase mode has
    /// no generation table.
    pub fn rotate_convergence(&mut self) -> io::Result<u32> {
        let Secrets::Vault(v) = &mut self.secrets else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "passphrase mode has no convergence generation to rotate",
            ));
        };
        // Snapshot before the append. `load_vault_key` fails when the key
        // file is gone and the keychain has no item; `seal_with` fails when
        // the container cannot be sealed; the replace fails when the sibling
        // temp cannot be created. Any of those is reachable, and any of them
        // would leave an unpersisted generation in `v` while `cs_holder`
        // still holds the old secret: `generation()` and `sealer()` would
        // disagree, and a retry would skip a number.
        let prior = v.clone();
        let number = match v.rotate_convergence() {
            Ok(n) => n,
            Err(e) => return Err(io::Error::other(e.to_string())),
        };
        let Some(ns) = self.root.file_name().and_then(|s| s.to_str()) else {
            *v = prior;
            return Err(io::Error::other("namespace path has no name"));
        };
        let vault_key = match Self::load_vault_key(ns, &self.root) {
            Ok(k) => k,
            Err(e) => {
                *v = prior;
                return Err(e);
            }
        };
        let sealed = match v.seal_with(vault_key) {
            Ok(s) => s,
            Err(e) => {
                *v = prior;
                return Err(io::Error::other(e.to_string()));
            }
        };
        let dir = match write_vault_replace(&self.root.join("vault.bin"), &sealed) {
            Ok(dir) => dir,
            Err(e) => {
                *v = prior;
                return Err(e);
            }
        };
        // The rename is the commit. Point `cs_holder` at the new generation
        // before the directory fsync: a failure there must not roll `v` back,
        // because the file already contains this generation and rolling back
        // would describe a `vault.bin` that is gone.
        self.cs_holder = v.current_generation().convergence_secret();
        sync_dir(&dir)?;
        Ok(number)
    }

    /// Write the 32-byte vault key to a new `0600` file. Never prints it.
    /// Refuses if `dest` already exists. Passphrase mode has no such key.
    ///
    /// The refusal is `O_EXCL`, not a prior `exists` check. Between the check
    /// and the open a symlink can be planted at `dest`, and a pre-created
    /// `0644` file keeps its mode because `.mode` applies only at creation.
    pub fn export_vault_key(&self, dest: &Path) -> io::Result<()> {
        if self.mode == Mode::Passphrase {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "passphrase mode has no vault key to export",
            ));
        }
        let ns = self
            .root
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("namespace path has no name"))?;
        // Zeroize on every return, including the write failing. The rest of
        // the vault path does this; leaving the exported copy on the stack
        // was the exception.
        let key = zeroize::Zeroizing::new(Self::load_vault_key(ns, &self.root)?);
        write_private_new(dest, &*key)
    }

    /// A hash of the convergence secret, for comparing two namespaces without
    /// exposing the secret itself.
    pub fn convergence_secret_fingerprint(&self) -> [u8; 32] {
        // `seal_chunk`, not `chunk_key` + `seal`: the latter now refuses a
        // derived key, and the old code swallowed that with `unwrap_or_default`
        // -- so every namespace fingerprinted as `blake3(&[])` and the one
        // assertion that compares two fingerprints started passing vacuously.
        // A comparison whose inputs are constant is not a comparison, so this
        // panics rather than degrading: an infallible operation that fails is a
        // bug here, not a condition to tolerate.
        let probe = b"nas-tools/fingerprint-probe/v1";
        let (sealed, _) = nas_crypto::seal_chunk(&self.convergence_secret(), probe, b"")
            .expect("sealing a fixed probe under a derived key is infallible");
        *blake3::hash(&sealed).as_bytes()
    }

    pub fn convergence_secret(&self) -> ConvergenceSecret {
        self.cs_holder.clone()
    }

    /// A convergence secret that is **not** this namespace's — for modelling an
    /// attacker who lacks it (SPECS §3.2, §12.5).
    pub fn foreign_secret(tag: &[u8]) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(blake3::derive_key("nas-tools/test/foreign-cs/v1", tag))
    }

    /// How this namespace protects chunks at rest.
    pub fn sealer(&self) -> nas_store::Sealer<'_> {
        match self.mode {
            Mode::TransitOnly => nas_store::Sealer::Plaintext {
                tenant_salt: &self.tenant_salt,
            },
            Mode::E2ee | Mode::Passphrase => nas_store::Sealer::Convergent(&self.cs_holder),
        }
    }

    /// The blob store, opened with the addressing this mode requires.
    pub fn blobs(&self) -> Result<nas_store::BlobStore, io::Error> {
        let addressing = match self.mode {
            Mode::TransitOnly => nas_store::Addressing::Salted(self.tenant_salt.clone()),
            Mode::E2ee | Mode::Passphrase => nas_store::Addressing::Content,
        };
        nas_store::BlobStore::open_with(self.blobs_root(), addressing)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Root of the per-directory key chain (SPECS §3.1, §15.3).
    pub fn dir_root(&self) -> DirSecret {
        match &self.secrets {
            Secrets::Vault(v) => v.dir_root(),
            Secrets::Passphrase(ns, _) => ns.dir_root(),
        }
    }

    /// `rk_seq`: the key one version of the root manifest is sealed under
    /// (SPECS §3.1). Per sequence, so no two roots share a key.
    pub fn root_key(&self, seq: u64) -> RootKey {
        match &self.secrets {
            Secrets::Vault(v) => v.root_key(seq),
            Secrets::Passphrase(ns, _) => ns.root_key(seq),
        }
    }

    /// Seal a root manifest for publication at `seq` in `slot_id`. Returns
    /// the blob to store and the nonce the slot record must carry.
    ///
    /// `transit-only` stores it as it stores every manifest — unsealed, so
    /// the peer can browse from the slot down (SPECS §2.2.3) — and the
    /// record's nonce is all zero: nothing was sealed, so there is no nonce.
    pub fn seal_root(
        &self,
        slot_id: &[u8; 32],
        seq: u64,
        root: &RootManifest,
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN]), String> {
        let plain = root.encode().map_err(|e| e.to_string())?;
        match self.mode {
            Mode::TransitOnly => Ok((plain, [0u8; NONCE_LEN])),
            Mode::E2ee | Mode::Passphrase => {
                nas_crypto::seal_root(&self.root_key(seq), &plain, &root_aad(slot_id, seq))
                    .map_err(|e| format!("seal root manifest: {e}"))
            }
        }
    }

    /// Open the root manifest a verified slot record points at, with the
    /// nonce that record carries.
    pub fn open_root(
        &self,
        slot_id: &[u8; 32],
        seq: u64,
        nonce: &[u8; NONCE_LEN],
        blob: &[u8],
    ) -> Result<RootManifest, String> {
        let plain = match self.mode {
            Mode::TransitOnly => blob.to_vec(),
            Mode::E2ee | Mode::Passphrase => {
                nas_crypto::open_root(&self.root_key(seq), nonce, blob, &root_aad(slot_id, seq))
                    .map_err(|_| {
                        format!(
                            "root manifest at seq {seq} does not open under this namespace's \
                             key for this slot (wrong namespace, wrong nonce, or a blob that \
                             is not the one the record was signed over)"
                        )
                    })?
            }
        };
        RootManifest::decode(&plain).map_err(|e| e.to_string())
    }

    pub fn blobs_root(&self) -> PathBuf {
        self.root.clone()
    }

    /// The `transit-only` tenant salt; empty for the other modes. Not secret
    /// (see the field), and a peer serving this tenant needs it to address
    /// blobs the same way the client does.
    pub fn tenant_salt(&self) -> &[u8] {
        &self.tenant_salt
    }

    pub fn head(&self) -> Option<String> {
        fs::read_to_string(self.root.join("state/HEAD"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn set_head(&self, addr: &str) -> io::Result<()> {
        // A device joins a namespace by copying `config` and `wraps` alone
        // (MANUAL-TESTING.md §10); `state/` is this device's own memory and
        // may not exist yet if the first thing it does is write.
        fs::create_dir_all(self.root.join("state"))?;
        fs::write(self.root.join("state/HEAD"), format!("{addr}\n"))
    }
}

/// SPECS §2.2.2: per-namespace convergence, not tenant-wide. Otherwise a
/// passphrase namespace would need a vault secret in order to write, and
/// "recoverable from memory alone" would be false.
fn secrets_convergence(s: &Secrets) -> ConvergenceSecret {
    match s {
        Secrets::Vault(v) => v.current_generation().convergence_secret(),
        Secrets::Passphrase(ns, _) => ns.convergence_secret(),
    }
}

/// Serialize tests that mutate `$NAS_HOME`. The process has one env.
#[cfg(test)]
pub(crate) fn with_temp_home<R>(f: impl FnOnce(&Path) -> R) -> R {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = std::env::temp_dir().join(format!(
        "nas-home-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let prev = std::env::var_os("NAS_HOME");
    std::env::set_var("NAS_HOME", &home);
    let out = f(&home);
    match prev {
        Some(p) => std::env::set_var("NAS_HOME", p),
        None => std::env::remove_var("NAS_HOME"),
    }
    let _ = fs::remove_dir_all(&home);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fingerprint's whole job is to differ when the secret differs.
    ///
    /// It silently stopped doing that -- `seal` began refusing derived keys and
    /// an `unwrap_or_default` turned the refusal into an empty ciphertext, so
    /// every namespace hashed to the same value. Nothing failed: the only
    /// assertion that used it compares two fingerprints for *equality*, which a
    /// constant satisfies. This test fails on that, which the acceptance suite
    /// structurally could not.
    #[test]
    fn the_fingerprint_distinguishes_two_secrets() {
        let a = Repo::foreign_secret(b"one");
        let b = Repo::foreign_secret(b"two");
        let fp = |cs: &ConvergenceSecret| {
            let probe = b"nas-tools/fingerprint-probe/v1";
            let (sealed, _) = nas_crypto::seal_chunk(cs, probe, b"").unwrap();
            *blake3::hash(&sealed).as_bytes()
        };
        assert_ne!(fp(&a), fp(&b), "the fingerprint is not secret-dependent");
        assert_eq!(fp(&a), fp(&a), "the fingerprint is not deterministic");
        assert_ne!(
            fp(&a),
            *blake3::hash(b"").as_bytes(),
            "degraded to a constant"
        );
    }

    #[test]
    fn new_e2ee_skips_vault_key_when_keychain_holds_it() {
        with_temp_home(|_| {
            let ns = "kc-e2ee";
            crate::keychain::delete(ns);
            let repo = Repo::create(
                ns,
                Mode::E2ee,
                KeyScheme::Convergent,
                PaddingProfile::None,
                None,
                None,
                None,
            )
            .expect("create e2ee");
            let key_file = repo.root.join("vault.key");
            if crate::keychain::available() && crate::keychain::load(ns).ok().flatten().is_some() {
                assert!(
                    !key_file.exists(),
                    "keychain held the key; vault.key must not be created on a new namespace"
                );
                Repo::open_with(ns, None).expect("open from keychain");
            } else {
                assert!(
                    key_file.exists(),
                    "no Secret Service / keychain: file fallback is the documented CI path"
                );
                Repo::open_with(ns, None).expect("open from vault.key");
            }
            crate::keychain::delete(ns);
        });
    }

    #[test]
    fn rotate_keeps_the_old_generation_and_export_refuses_to_clobber() {
        with_temp_home(|_| {
            let ns = "rot-e2ee";
            crate::keychain::delete(ns);
            let mut repo = Repo::create(
                ns,
                Mode::E2ee,
                KeyScheme::Convergent,
                PaddingProfile::None,
                None,
                None,
                None,
            )
            .expect("create");
            assert_eq!(repo.generation(), 0);
            let next = repo.rotate_convergence().expect("rotate");
            assert_eq!(next, 1);
            let again = Repo::open_with(ns, None).expect("reopen");
            assert_eq!(again.generation(), 1);
            let dest = again.root.join("exported.key");
            again.export_vault_key(&dest).expect("export");
            assert_eq!(fs::read(&dest).unwrap().len(), 32);
            let err = again.export_vault_key(&dest).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            crate::keychain::delete(ns);
        });
    }

    /// A path that already exists is not a place the vault key may be written,
    /// and a path this call creates is mode 0600.
    ///
    /// The pre-created file is the obvious case. The dangling symlink is the
    /// one `exists` misses: it reports false, and `create` without `O_EXCL`
    /// follows the link and writes the 32-byte key wherever it points. A
    /// pre-created 0644 file would also keep that mode, because `.mode` does
    /// not change an existing inode.
    #[cfg(unix)]
    #[test]
    fn export_refuses_an_existing_path_and_creates_mode_0600() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        with_temp_home(|_| {
            let ns = "export-excl";
            crate::keychain::delete(ns);
            let repo = Repo::create(
                ns,
                Mode::E2ee,
                KeyScheme::Convergent,
                PaddingProfile::None,
                None,
                None,
                None,
            )
            .expect("create");

            let dest = repo.root.join("preexisting.key");
            fs::write(&dest, b"not-the-key").unwrap();
            let mut perms = fs::metadata(&dest).unwrap().permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&dest, perms).unwrap();
            let err = repo.export_vault_key(&dest).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("destination exists"), "{err}");
            assert_eq!(fs::read(&dest).unwrap(), b"not-the-key");
            assert_eq!(
                fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o644,
                "a refused export changed the existing file's mode"
            );

            let target = repo.root.join("leaked.key");
            let link = repo.root.join("via-symlink.key");
            symlink(&target, &link).unwrap();
            let err = repo.export_vault_key(&link).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                !target.exists(),
                "export followed a dangling symlink and wrote the vault key"
            );

            let fresh = repo.root.join("fresh.key");
            repo.export_vault_key(&fresh).expect("export");
            let mode = fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "exported vault key mode is {mode:o}");
            assert_eq!(fs::read(&fresh).unwrap().len(), 32);
            crate::keychain::delete(ns);
        });
    }

    /// A rotation that cannot persist must leave the previous `vault.bin`
    /// byte-for-byte, and must not consume a generation number.
    ///
    /// Two injections, both before the rename. Pointing `root` at a directory
    /// that has no vault key makes `load_vault_key` fail after the in-memory
    /// append. Occupying `.vault.bin.tmp` (the sibling `write_vault_replace`
    /// creates with `O_EXCL`) makes the replace fail the same way. An in-place
    /// truncate ignores that sibling and destroys the only copy; a missing
    /// rollback leaves `generation()` ahead of the file, so the rotate that
    /// then succeeds returns 2 or 3 rather than 1.
    #[test]
    fn a_failed_rotate_keeps_vault_bin_and_does_not_skip_a_generation() {
        with_temp_home(|_| {
            let ns = "rot-durable";
            crate::keychain::delete(ns);
            let mut repo = Repo::create(
                ns,
                Mode::E2ee,
                KeyScheme::Convergent,
                PaddingProfile::None,
                None,
                None,
                None,
            )
            .expect("create");
            let root = repo.root.clone();
            let vault = root.join("vault.bin");
            let original = fs::read(&vault).expect("vault.bin");
            let fp = repo.convergence_secret_fingerprint();

            let unique = format!("no-key-{}", std::process::id());
            repo.root = root.join(&unique);
            let err = repo.rotate_convergence().expect_err("no key to seal with");
            assert_eq!(
                err.kind(),
                io::ErrorKind::NotFound,
                "load_vault_key must be what failed, not a later replace"
            );
            repo.root = root.clone();
            assert_eq!(repo.generation(), 0, "unpersisted generation was kept");
            assert_eq!(
                repo.convergence_secret_fingerprint(),
                fp,
                "sealer() moved while generation() did not, or the reverse"
            );
            assert_eq!(
                fs::read(&vault).expect("vault.bin after a failed seal"),
                original,
                "a failed seal rewrote vault.bin"
            );

            // The sibling name `write_vault_replace` uses for `vault.bin`.
            let tmp = root.join(".vault.bin.tmp");
            fs::write(&tmp, b"occupied").unwrap();
            let err = repo
                .rotate_convergence()
                .expect_err("replace must refuse an occupied sibling");
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(fs::read(&tmp).unwrap(), b"occupied");
            assert_eq!(fs::read(&vault).unwrap(), original);
            assert_eq!(repo.generation(), 0);
            assert_eq!(repo.convergence_secret_fingerprint(), fp);
            let opened = Repo::open_with(ns, None).expect("original vault.bin still opens");
            assert_eq!(opened.generation(), 0);

            fs::remove_file(&tmp).unwrap();
            let n = repo.rotate_convergence().expect("rotate");
            assert_eq!(n, 1, "the two failures consumed a generation number");
            assert_eq!(repo.generation(), 1);
            assert_ne!(fs::read(&vault).unwrap(), original);
            assert!(
                !tmp.exists(),
                "the sibling temp survived a successful replace"
            );
            let leftovers: Vec<String> = fs::read_dir(&root)
                .unwrap()
                .filter_map(|e| {
                    let name = e.ok()?.file_name().to_string_lossy().into_owned();
                    name.contains(".tmp").then_some(name)
                })
                .collect();
            assert!(
                leftovers.is_empty(),
                "temp survived a successful replace: {leftovers:?}"
            );
            let again = Repo::open_with(ns, None).expect("replaced vault.bin opens");
            assert_eq!(again.generation(), 1);
            crate::keychain::delete(ns);
        });
    }
}
