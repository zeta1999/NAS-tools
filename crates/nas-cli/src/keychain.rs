//! OS keychain for the vault key (post-M6 leftover).
//!
//! Thin CLI wrapper — `security` on macOS, `secret-tool` (Secret Service) on
//! Linux — so NAS-tools stays sync and dependency-light. A missing helper or
//! a failed write is not fatal: [`crate::repo`] falls back to `vault.key`.

use nas_crypto::KEY_LEN;
use std::process::{Command, Stdio};

const SERVICE: &str = "nas-tools.vault";

fn account(ns: &str) -> String {
    format!("ns:{ns}")
}

fn hex_key(key: &[u8; KEY_LEN]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex_key(s: &str) -> Option<[u8; KEY_LEN]> {
    let s = s.trim();
    if s.len() != KEY_LEN * 2 {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("-h")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success() || s.code().is_some())
        .unwrap_or(false)
        || Command::new("which")
            .arg(bin)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

/// Whether a keychain helper is on PATH. Linux CI usually is not.
#[cfg(test)]
pub fn available() -> bool {
    if cfg!(target_os = "macos") {
        have("security")
    } else {
        have("secret-tool")
    }
}

/// Store `key` under this namespace. Overwrites an existing item.
pub fn store(ns: &str, key: &[u8; KEY_LEN]) -> Result<(), String> {
    let hex = hex_key(key);
    let acct = account(ns);
    if cfg!(target_os = "macos") {
        let st = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-a",
                &acct,
                "-s",
                SERVICE,
                "-w",
                &hex,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("security add-generic-password exited {st}"))
        }
    } else {
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--label",
                &format!("NAS-tools vault {ns}"),
                "service",
                SERVICE,
                "account",
                &acct,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(hex.as_bytes()).map_err(|e| e.to_string())?;
        }
        let st = child.wait().map_err(|e| e.to_string())?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("secret-tool store exited {st}"))
        }
    }
}

/// Load the vault key, or `None` if the item is absent.
pub fn load(ns: &str) -> Result<Option<[u8; KEY_LEN]>, String> {
    let acct = account(ns);
    let out = if cfg!(target_os = "macos") {
        Command::new("security")
            .args(["find-generic-password", "-a", &acct, "-s", SERVICE, "-w"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?
    } else {
        Command::new("secret-tool")
            .args(["lookup", "service", SERVICE, "account", &acct])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?
    };
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    match unhex_key(&text) {
        Some(k) => Ok(Some(k)),
        None => Err("keychain item is not 32 hex bytes".into()),
    }
}

/// Best-effort delete (tests). Failure is ignored.
#[cfg(test)]
pub fn delete(ns: &str) {
    let acct = account(ns);
    if cfg!(target_os = "macos") {
        let _ = Command::new("security")
            .args(["delete-generic-password", "-a", &acct, "-s", SERVICE])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    } else {
        let _ = Command::new("secret-tool")
            .args(["clear", "service", SERVICE, "account", &acct])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let k = [0xABu8; KEY_LEN];
        assert_eq!(unhex_key(&hex_key(&k)), Some(k));
        assert!(unhex_key("zz").is_none());
        assert!(unhex_key("ab").is_none());
    }
}
