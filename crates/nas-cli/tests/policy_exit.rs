//! Exit 2 is a policy refusal, and these two commands must make that
//! decision before they open the namespace.
//!
//! `Repo::open_with` on a passphrase namespace prompts, and with no terminal
//! that prompt fails as an ordinary error (exit 1). MANUAL §4.3 and §4.4 say
//! `nas ns rotate` and `nas ns export-key` exit 2. The mode is in the config;
//! reading it does not need a secret. An OS `EACCES` is not that refusal.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

struct Home(std::path::PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nas-policy-exit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        // The EACCES case removes the owner's search bit. Put it back or
        // this directory cannot be deleted.
        if let Ok(rd) = fs::read_dir(&self.0) {
            for ent in rd.flatten() {
                let _ = fs::set_permissions(ent.path(), fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_ns(home: &Path, name: &str, mode: &str) {
    let dir = home.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("config"),
        format!("version 1\nmode {mode}\nkey_scheme convergent\npadding_profile none\n"),
    )
    .unwrap();
}

fn nas(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nas"))
        .args(args)
        .env("NAS_HOME", home)
        .env_remove("NAS_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .expect("spawn nas")
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn passphrase_rotate_and_export_key_exit_2_with_no_tty() {
    let home = Home::new();
    write_ns(&home.0, "docs", "passphrase");

    for args in [
        &["ns", "rotate", "docs"][..],
        &["ns", "export-key", "docs", "docs.key"][..],
    ] {
        let out = nas(&home.0, args);
        let err = stderr(&out);
        assert_eq!(code(&out), 2, "{args:?} exited {} ({err})", code(&out));
        assert!(
            err.contains("refused:"),
            "{args:?} did not report a policy refusal: {err}"
        );
        assert!(
            !err.contains("not a terminal"),
            "{args:?} opened the namespace before refusing: {err}"
        );
    }
}

#[test]
fn os_eacces_is_not_exit_2() {
    let home = Home::new();
    write_ns(&home.0, "locked", "e2ee");
    let dir = home.0.join("locked");
    let mut perms = fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&dir, perms).unwrap();

    for args in [
        &["ns", "rotate", "locked"][..],
        &["ns", "export-key", "locked", "locked.key"][..],
    ] {
        let out = nas(&home.0, args);
        let err = stderr(&out);
        assert_eq!(
            code(&out),
            1,
            "{args:?} treated an OS EACCES as a policy refusal ({err})"
        );
        assert!(
            !err.contains("refused:"),
            "{args:?} used the policy wording for an OS error: {err}"
        );
    }
}
