//! `nas` — the command line face.
//!
//! Argument parsing is hand-rolled. The surface is small and fixed by
//! `tests/usecases/`, and the one thing that genuinely matters here is the exit
//! code contract (see [`exit`]), which is easier to hold exactly with a parser
//! that has no opinions of its own.

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
        "acl" => testcmds::unimplemented("acl", "M1 (§15)"),
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
            // SPECS §2.2.2: the passphrase mode needs Argon2id KEK wrapping and
            // a WrapRecord. Creating one without them would produce a namespace
            // whose config claims a protection it does not have.
            if mode == Mode::Passphrase {
                return testcmds::unimplemented("--mode passphrase", "M1 (§2.2.2, nas-vault)");
            }
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
            match Repo::create(name, mode, KeyScheme::Convergent, padding) {
                Ok(r) => {
                    println!("created {name} at {}", r.root.display());
                    println!(
                        "  mode {}, padding {:?}",
                        opt(args, "--mode").unwrap_or("e2ee"),
                        padding
                    );
                    println!("  {}", repo::VAULT_WARNING);
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
                        match Repo::open(&n) {
                            Ok(r) => println!(
                                "{n}\tmode={:?}\tkey_scheme={:?}\tpadding={:?}",
                                r.mode, r.key_scheme, r.padding
                            ),
                            Err(e) => println!("{n}\tUNREADABLE: {e}"),
                        }
                    }
                    exit::OK
                }
                Err(_) => exit::OK, // no namespaces yet is not an error
            }
        }
        Some("open") => testcmds::unimplemented("ns open", "M1 (§2.2.2)"),
        _ => {
            eprintln!("usage: nas ns create|list");
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
        Some(other) => testcmds::unimplemented(&format!("test {other}"), "a later milestone"),
        None => {
            eprintln!("usage: nas test <check> …");
            exit::ERROR
        }
    }
}
