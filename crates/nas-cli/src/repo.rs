//! Local namespace state (SPECS §4).
//!
//! ```text
//! $NAS_HOME/<ns>/config           mode, key_scheme, padding_profile, version
//! $NAS_HOME/<ns>/vault            convergence secret + namespace root secret
//! $NAS_HOME/<ns>/blobs/…          the blob store
//! $NAS_HOME/<ns>/state/HEAD       the root directory manifest address
//! ```
//!
//! # The vault is not a vault yet
//!
//! SPECS §3.1 puts `CS` and the identity keys in `vault.bin`, held by `nasd`
//! and never written in the clear. At M0 there is no daemon and no key
//! derivation from a passphrase, so this file stores the secrets **unencrypted
//! at 0600**. That is a real weakness and it is written here rather than
//! discovered later: `nas-vault` is M1 step 7, and until it lands a namespace
//! is only as safe as the local disk.
//!
//! `state/` is local-only and never shipped to a peer (SPECS §4).

use nas_core::{KeyScheme, Mode, PaddingProfile};
use nas_crypto::{ConvergenceSecret, DirSecret, KEY_LEN};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const VAULT_WARNING: &str =
    "M0: secrets are stored UNENCRYPTED at 0600. nas-vault (M1) replaces this.";

pub struct Repo {
    pub root: PathBuf,
    pub mode: Mode,
    pub key_scheme: KeyScheme,
    pub padding: PaddingProfile,
    cs: [u8; KEY_LEN],
    ns_root: [u8; KEY_LEN],
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
/// Read straight from `/dev/urandom` rather than through a crate. This is the
/// one place M0 needs randomness and the requirement is exactly "the kernel's
/// CSPRNG"; a short read is a hard error, never silently padded with zeros.
pub fn random_secret() -> io::Result<[u8; KEY_LEN]> {
    use io::Read;
    let mut f = fs::File::open("/dev/urandom")?;
    let mut b = [0u8; KEY_LEN];
    f.read_exact(&mut b)?;
    if b == [0u8; KEY_LEN] {
        return Err(io::Error::other("CSPRNG returned all zeros"));
    }
    Ok(b)
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
        let cs = random_secret()?;
        let ns_root = random_secret()?;

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

        let mut vault = Vec::with_capacity(64 + VAULT_WARNING.len());
        vault.extend_from_slice(VAULT_WARNING.as_bytes());
        vault.push(b'\n');
        vault.extend_from_slice(&cs);
        vault.extend_from_slice(&ns_root);
        write_private(&root.join("vault"), &vault)?;

        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            cs,
            ns_root,
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

        let vault = fs::read(root.join("vault"))?;
        let nl = vault
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| io::Error::other("malformed vault"))?;
        let secrets = &vault[nl + 1..];
        if secrets.len() < KEY_LEN * 2 {
            return Err(io::Error::other("truncated vault"));
        }
        let mut cs = [0u8; KEY_LEN];
        let mut ns_root = [0u8; KEY_LEN];
        cs.copy_from_slice(&secrets[..KEY_LEN]);
        ns_root.copy_from_slice(&secrets[KEY_LEN..KEY_LEN * 2]);
        Ok(Self {
            root,
            mode,
            key_scheme,
            padding,
            cs,
            ns_root,
        })
    }

    pub fn convergence_secret(&self) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(self.cs)
    }

    /// A convergence secret that is **not** this namespace's — for modelling an
    /// attacker who lacks it (SPECS §3.2, §12.5).
    pub fn foreign_secret(tag: &[u8]) -> ConvergenceSecret {
        ConvergenceSecret::from_bytes(blake3::derive_key("nas-tools/test/foreign-cs/v1", tag))
    }

    pub fn dir_root(&self) -> DirSecret {
        DirSecret::root(&self.ns_root)
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
