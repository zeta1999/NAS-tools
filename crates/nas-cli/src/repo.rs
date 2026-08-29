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
//! Argon2id. M1 stores the `e2ee` key in `vault.key` beside the vault, which is
//! **not yet meaningful protection** — it moves the secret rather than
//! protecting it — and that is stated in [`VAULT_WARNING`] rather than left to
//! be discovered. An OS keychain or a passphrase-derived key is what makes it
//! real, and both are recorded in TODO.md.
//!
//! What *has* changed since M0 is that the convergence secret and the namespace
//! root are no longer on disk in the clear, the identity is derived from a seed
//! rather than absent, and the container is versioned and authenticated.
//!
//! `state/` is local-only and never shipped to a peer (SPECS §4).

use nas_core::{KeyScheme, Mode, PaddingProfile};
use nas_crypto::{random, ConvergenceSecret, DirSecret, Identity, Role, KEY_LEN};
use nas_slots::Anchor;
use nas_vault::{Argon2Params, NamespaceSecrets, Vault, WrapPolicy, WrapRecord};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VAULT_WARNING: &str = "M1: the vault is sealed, but its key sits beside it in vault.key \
     (0600). That relocates the secret rather than protecting it — an OS keychain \
     or a passphrase-derived key is what makes it real.";

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
/// No interactive prompt yet: this runs under a harness with no tty, and a
/// prompt that silently fell back to a default would be worse than none.
pub fn passphrase_from(explicit: Option<&str>) -> Option<Vec<u8>> {
    explicit
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| std::env::var("NAS_PASSPHRASE").ok().map(String::into_bytes))
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

/// What a namespace declares about itself, readable **without any secret**.
///
/// Listing namespaces must not require unlocking them: a passphrase namespace
/// would otherwise have to be opened — and its Argon2id derivation run — just to
/// print its name, which is both slow and wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    pub mode: Mode,
    pub key_scheme: KeyScheme,
    pub padding: PaddingProfile,
}

impl Repo {
    /// Read the config alone. No secrets are touched.
    pub fn describe(ns: &str) -> io::Result<Description> {
        let cfg = fs::read_to_string(path_of(ns).join("config"))?;
        let mut d = Description {
            mode: Mode::E2ee,
            key_scheme: KeyScheme::Convergent,
            padding: PaddingProfile::None,
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

        fs::write(
            root.join("config"),
            format!(
                "version 1\nmode {}\nkey_scheme {}\npadding_profile {}\ntenant_salt {}\n",
                mode_str(mode),
                key_scheme_str(key_scheme),
                padding_str(padding),
                hex(&tenant_salt),
            ),
        )?;

        let secrets = match mode {
            Mode::Passphrase => {
                let pw = passphrase.ok_or_else(|| {
                    io::Error::other("passphrase mode needs --passphrase or $NAS_PASSPHRASE")
                })?;
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
                write_private(&root.join("vault.key"), &vault_key)?;
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

    pub fn open(ns: &str) -> io::Result<Self> {
        Self::open_with(ns, None)
    }

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
                let pw = passphrase.ok_or_else(|| {
                    io::Error::other("passphrase mode needs --passphrase or $NAS_PASSPHRASE")
                })?;
                let seq = Self::latest_wrap_seq(&root)?;
                let w = Self::load_wrap(&root, seq)?;
                let (ns, anchor) = w
                    .unwrap(&pw, &WrapPolicy::SPEC)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Secrets::Passphrase(Box::new(ns), anchor)
            }
            Mode::E2ee | Mode::TransitOnly => {
                let sealed = fs::read(root.join("vault.bin"))?;
                let key_bytes = fs::read(root.join("vault.key"))?;
                let vault_key: [u8; KEY_LEN] = key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| io::Error::other("vault.key is not 32 bytes"))?;
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

    pub fn blobs_root(&self) -> PathBuf {
        self.root.clone()
    }

    pub fn head(&self) -> Option<String> {
        fs::read_to_string(self.root.join("state/HEAD"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn set_head(&self, addr: &str) -> io::Result<()> {
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
}
