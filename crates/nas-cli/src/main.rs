//! `nas` — the command line face.
//!
//! Argument parsing is hand-rolled. The surface is small and fixed by
//! `tests/usecases/`, and the one thing that genuinely matters here is the exit
//! code contract (see [`exit`]), which is easier to hold exactly with a parser
//! that has no opinions of its own.

mod aclcmd;
mod exit;
mod repo;
mod testcmds;

use nas_core::{KeyScheme, Mode, PaddingProfile};
use repo::Repo;

const USAGE: &str = "\
nas — NAS-tools command line

  nas ns create <name> [--mode e2ee|passphrase|transit-only]
                       [--padding none|classes|fixed]
  nas ns list
  nas acl grant|revoke|check <ns> --subject <s> --right <r>
  nas acl list <ns>
  nas test roundtrip <ns> <path>
  nas test dedup-ratio <ns> --shared <pct> --max-transfer <pct>
  nas test confirmation-attack <ns> --with-cs|--without-cs

Exit codes: 0 ok, 1 error, 2 refused by policy, 3 unimplemented.
";

/// Value of `--name`, or `None`.
fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Positional arguments: everything that is not a `--flag` or its value.
fn positional(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(rest) = args[i].strip_prefix("--") {
            // Value-taking options consume the next argument.
            if matches!(
                rest,
                "mode"
                    | "padding"
                    | "shared"
                    | "max-transfer"
                    | "passphrase"
                    | "object-lock"
                    | "retention"
                    | "subject"
                    | "right"
                    | "min-mem"
                    | "agents"
                    | "rows"
                    | "key"
                    | "approvers"
                    | "scope"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        out.push(args[i].as_str());
        i += 1;
    }
    out
}

fn pct(args: &[String], name: &str, default: u32) -> Result<u32, String> {
    match opt(args, name) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| format!("{name} takes a number, got {v:?}")),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&argv));
}

fn run(argv: &[String]) -> i32 {
    let Some(cmd) = argv.first().map(String::as_str) else {
        eprint!("{USAGE}");
        return exit::ERROR;
    };
    let rest = &argv[1..];

    match cmd {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            exit::OK
        }
        "ns" => ns(rest),
        "test" => test(rest),
        // Recognised in SPECS, not built. Never REFUSED — see exit.rs.
        "acl" => acl(rest),
        "peer" => testcmds::unimplemented("peer", "M1 (§10)"),
        "gateway" => testcmds::unimplemented("gateway", "M3 (§2.1)"),
        "mirror" => testcmds::unimplemented("mirror", "M5 (§7.6)"),
        "put" | "rm" | "delete-request" => testcmds::unimplemented(cmd, "M2 (§16)"),
        other => {
            eprintln!("unknown command {other:?}\n");
            eprint!("{USAGE}");
            exit::ERROR
        }
    }
}

fn acl(args: &[String]) -> i32 {
    let pos = positional(args);
    let right = || match opt(args, "--right") {
        Some(r) => nas_peer::Right::parse(r).ok_or_else(|| format!("unknown right {r:?}")),
        None => Err("missing --right".to_string()),
    };
    let subject = || opt(args, "--subject").ok_or_else(|| "missing --subject".to_string());

    let (Some(verb), Some(ns)) = (pos.first().copied(), pos.get(1).copied()) else {
        eprintln!("usage: nas acl grant|revoke|check|list <ns> [--subject <s>] [--right <r>]");
        return exit::ERROR;
    };
    match verb {
        "list" => aclcmd::list(ns),
        "grant" | "revoke" | "check" => match (subject(), right()) {
            (Ok(s), Ok(r)) => match verb {
                "grant" => aclcmd::grant(ns, s, r),
                "revoke" => aclcmd::revoke(ns, s, r),
                _ => aclcmd::check(ns, s, r),
            },
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("{e}");
                exit::ERROR
            }
        },
        other => {
            eprintln!("unknown acl verb {other:?}");
            exit::ERROR
        }
    }
}

fn ns(args: &[String]) -> i32 {
    let pos = positional(args);
    match pos.first().copied() {
        Some("create") => {
            let Some(name) = pos.get(1) else {
                eprintln!("usage: nas ns create <name> [--mode …] [--padding …]");
                return exit::ERROR;
            };
            let mode = match opt(args, "--mode") {
                None => Mode::E2ee,
                Some(m) => match repo::parse_mode(m) {
                    Some(m) => m,
                    None => {
                        eprintln!("unknown mode {m:?}");
                        return exit::ERROR;
                    }
                },
            };
            let padding = match opt(args, "--padding") {
                None => PaddingProfile::default(),
                Some(p) => match repo::parse_padding(p) {
                    Some(p) => p,
                    None => {
                        eprintln!("unknown padding profile {p:?}");
                        return exit::ERROR;
                    }
                },
            };
            for unsupported in ["--object-lock", "--retention"] {
                if opt(args, unsupported).is_some() {
                    return testcmds::unimplemented(unsupported, "M2 (§16)");
                }
            }
            if Repo::exists(name) {
                eprintln!("namespace {name} already exists");
                return exit::ERROR;
            }
            let passphrase = repo::passphrase_from(opt(args, "--passphrase"));
            if mode == Mode::Passphrase && passphrase.is_none() {
                eprintln!("passphrase mode needs --passphrase or $NAS_PASSPHRASE");
                return exit::ERROR;
            }
            match Repo::create(name, mode, KeyScheme::Convergent, padding, passphrase) {
                Ok(r) => {
                    println!("created {name} at {}", r.root.display());
                    println!(
                        "  mode {}, padding {:?}, generation {}",
                        opt(args, "--mode").unwrap_or("e2ee"),
                        padding,
                        r.generation()
                    );
                    // The writer id is what goes on a roster, so print it at
                    // creation rather than making the user derive it later.
                    match r.identity(nas_crypto::Role::Slot) {
                        Ok(id) => println!(
                            "  slot writer id {}",
                            id.id()
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        ),
                        Err(e) => eprintln!("  warning: could not derive identity: {e}"),
                    }
                    // Only vault-backed modes have a key file to warn about.
                    // A passphrase namespace stores nothing that opens it.
                    if mode == Mode::Passphrase {
                        println!(
                            "  no key material on disk: this namespace opens only from the \
                             passphrase. Losing it loses the data (SPECS §2.2.2)."
                        );
                    } else {
                        println!("  {}", repo::VAULT_WARNING);
                    }
                    exit::OK
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    exit::ERROR
                }
            }
        }
        Some("list") => {
            let base = repo::path_of("");
            match std::fs::read_dir(&base) {
                Ok(rd) => {
                    let mut names: Vec<String> = rd
                        .flatten()
                        .filter(|e| e.path().join("config").exists())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    for n in names {
                        // describe() reads the config only: listing must not
                        // require unlocking, or naming a passphrase namespace
                        // would mean running Argon2id over 256 MiB first.
                        match Repo::describe(&n) {
                            Ok(d) => println!(
                                "{n}\tmode={:?}\tkey_scheme={:?}\tpadding={:?}",
                                d.mode, d.key_scheme, d.padding
                            ),
                            Err(e) => println!("{n}\tUNREADABLE: {e}"),
                        }
                    }
                    exit::OK
                }
                Err(_) => exit::OK, // no namespaces yet is not an error
            }
        }
        Some("open") => {
            let Some(name) = pos.get(1) else {
                eprintln!("usage: nas ns open <name> [--passphrase <pw>]");
                return exit::ERROR;
            };
            let pw = repo::passphrase_from(opt(args, "--passphrase"));
            match Repo::open_with(name, pw) {
                Ok(r) => {
                    println!("opened {name} (mode {:?})", r.mode);
                    if let Some(a) = r.recovered_anchor() {
                        println!("  freshness anchor: seq {}", a.seq);
                    }
                    exit::OK
                }
                // A wrong passphrase is a POLICY refusal, not a breakage: the
                // harness distinguishes exit 2 from every other non-zero code
                // precisely so a broken binary cannot pass this assertion.
                Err(e) => {
                    eprintln!("refused: {e}");
                    exit::REFUSED
                }
            }
        }
        _ => {
            eprintln!("usage: nas ns create|list");
            exit::ERROR
        }
    }
}

/// Every `nas test <check> <ns>` command has the same shape.
fn one_ns(pos: &[&str], f: impl Fn(&str) -> i32) -> i32 {
    match pos.get(1) {
        Some(ns) => f(ns),
        None => {
            eprintln!("usage: nas test {} <ns>", pos.first().unwrap_or(&"<check>"));
            exit::ERROR
        }
    }
}

fn test(args: &[String]) -> i32 {
    let pos = positional(args);
    match pos.first().copied() {
        Some("roundtrip") => {
            let (Some(ns), Some(path)) = (pos.get(1), pos.get(2)) else {
                eprintln!("usage: nas test roundtrip <ns> <path>");
                return exit::ERROR;
            };
            testcmds::roundtrip(ns, path)
        }
        Some("dedup-ratio") => {
            let Some(ns) = pos.get(1) else {
                eprintln!("usage: nas test dedup-ratio <ns> --shared <pct> --max-transfer <pct>");
                return exit::ERROR;
            };
            let shared = match pct(args, "--shared", 90) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return exit::ERROR;
                }
            };
            let budget = match pct(args, "--max-transfer", 15) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return exit::ERROR;
                }
            };
            testcmds::dedup_ratio(ns, shared, budget)
        }
        Some("confirmation-attack") => {
            let Some(ns) = pos.get(1) else {
                eprintln!("usage: nas test confirmation-attack <ns> --with-cs|--without-cs");
                return exit::ERROR;
            };
            let with = flag(args, "--with-cs");
            let without = flag(args, "--without-cs");
            if with == without {
                eprintln!("pass exactly one of --with-cs / --without-cs");
                return exit::ERROR;
            }
            testcmds::confirmation_attack(ns, with)
        }
        Some("argon2-params") => {
            let Some(ns) = pos.get(1) else {
                eprintln!("usage: nas test argon2-params <ns> --min-mem 256MiB --min-time 3");
                return exit::ERROR;
            };
            let min_mem = opt(args, "--min-mem").unwrap_or("256MiB");
            let min_time = match pct(args, "--min-time", 3) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return exit::ERROR;
                }
            };
            testcmds::argon2_params(ns, min_mem, min_time)
        }
        Some("peer-no-plaintext") => match pos.get(1) {
            Some(ns) => testcmds::peer_no_plaintext(ns),
            None => {
                eprintln!("usage: nas test peer-no-plaintext <ns>");
                exit::ERROR
            }
        },
        Some("open-with-passphrase") => match pos.get(1) {
            Some(ns) => testcmds::open_with_passphrase(ns),
            None => {
                eprintln!("usage: nas test open-with-passphrase <ns>");
                exit::ERROR
            }
        },
        Some("recovery-has-freshness-anchor") => match pos.get(1) {
            Some(ns) => testcmds::recovery_has_freshness_anchor(ns),
            None => {
                eprintln!("usage: nas test recovery-has-freshness-anchor <ns>");
                exit::ERROR
            }
        },
        Some("passphrase-change-is-rewrap") => match pos.get(1) {
            Some(ns) => testcmds::passphrase_change(ns, false),
            None => {
                eprintln!("usage: nas test passphrase-change-is-rewrap <ns>");
                exit::ERROR
            }
        },
        Some("no-reencrypt-on-passphrase-change") => match pos.get(1) {
            Some(ns) => testcmds::passphrase_change(ns, true),
            None => {
                eprintln!("usage: nas test no-reencrypt-on-passphrase-change <ns>");
                exit::ERROR
            }
        },
        Some("old-wrap-deleted") => match pos.get(1) {
            Some(ns) => testcmds::old_wrap_deleted(ns),
            None => {
                eprintln!("usage: nas test old-wrap-deleted <ns>");
                exit::ERROR
            }
        },
        Some("peer-holds-plaintext") => one_ns(&pos, testcmds::peer_holds_plaintext),
        Some("peer-names-visible") => one_ns(&pos, |n| testcmds::peer_names(n, true)),
        Some("peer-names-encrypted") => one_ns(&pos, |n| testcmds::peer_names(n, false)),
        Some("listing-is-local") => one_ns(&pos, testcmds::listing_is_local),
        Some("slot-signed") => one_ns(&pos, testcmds::slot_signed),
        Some("recover-without-vault") => one_ns(&pos, testcmds::recover_without_vault),
        Some("cross-tenant-dedup") => match (pos.get(1), pos.get(2)) {
            (Some(ns), Some(other)) => testcmds::cross_tenant_dedup(ns, other),
            _ => {
                eprintln!("usage: nas test cross-tenant-dedup <ns> <other>");
                exit::ERROR
            }
        },
        Some(other) => testcmds::unimplemented(&format!("test {other}"), "a later milestone"),
        None => {
            eprintln!("usage: nas test <check> …");
            exit::ERROR
        }
    }
}
