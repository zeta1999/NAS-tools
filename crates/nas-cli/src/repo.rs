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
use nas_vault::Vault;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VAULT_WARNING: &str = "M1: the vault is sealed, but its key sits beside it in vault.key \
     (0600). That relocates the secret rather than protecting it — an OS keychain \
     or a passphrase-derived key is what makes it real.";

pub struct Repo {
    pub root: PathBuf,
    pub mode: Mode,
    pub key_scheme: KeyScheme,
    pub padding: PaddingProfile,
    vault: Vault,
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

impl Repo {
    pub fn exists(ns: &str) -> bool {
        path_of(ns).join("config").exists()
    }

    pub fn create(
        ns: &str,
        mode: Mode,
        key_scheme: KeyScheme,
        padding: PaddingProfile,
    ) -> io::Result<Self> {
        let root = path_of(ns);
        fs::create_dir_all(root.join("state"))?;
        let vault = Vault::create().map_err(|e| io::Error::other(e.to_string()))?;
        let vault_key = random_secret()?;

        fs::write(
            root.join("config"),
            format!(
                "version 1\nmode {}\nkey_scheme {}\npadding_profile {}\n",
                mode_str(mode),
                match key_scheme {
                    KeyScheme::Convergent => "convergent",
                    KeyScheme::IndexedRandom => "indexed-random",
                },
                padding_str(padding),
            ),
        )?;

        let sealed = vault
            .seal_with(vault_key)
            .map_err(|e| io::Error::other(e.to_string()))?;
        write_private(&root.join("vault.bin"), &sealed)?;
        write_private(&root.join("vault.key"), &vault_key)?;

        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            vault,
        })
    }

    pub fn open(ns: &str) -> io::Result<Self> {
        let root = path_of(ns);
        let cfg = fs::read_to_string(root.join("config"))?;
        let mut mode = Mode::E2ee;
        let mut key_scheme = KeyScheme::Convergent;
        let mut padding = PaddingProfile::None;
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
                _ => {}
            }
        }

        let sealed = fs::read(root.join("vault.bin"))?;
        let key_bytes = fs::read(root.join("vault.key"))?;
        let vault_key: [u8; KEY_LEN] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::other("vault.key is not 32 bytes"))?;
        let vault =
            Vault::open_with(&sealed, vault_key).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            vault,
        })
    }

    /// A role identity from the vault seed (SPECS §3.1).
    pub fn identity(&self, role: Role) -> io::Result<Identity> {
        self.vault
            .identity(role)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// The convergence-secret generation new writes use (SPECS §3.9c).
    pub fn generation(&self) -> u32 {
        self.vault.current_generation().number
    }

    pub fn convergence_secret(&self) -> ConvergenceSecret {
        self.vault.current_generation().convergence_secret()
    }

    /// A convergence secret that is **not** this namespace's — for modelling an
    /// attacker who lacks it (SPECS §3.2, §12.5).
    pub fn foreign_secret(tag: &[u8]) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(blake3::derive_key("nas-tools/test/foreign-cs/v1", tag))
    }

    /// Root of the per-directory key chain (SPECS §3.1, §15.3).
    pub fn dir_root(&self) -> DirSecret {
        self.vault.dir_root()
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
