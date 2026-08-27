//! Exit codes — a contract, not a convention.
//!
//! `tests/usecases/lib.sh` distinguishes "correctly refused" from "broken" by
//! exit code, and that distinction is the only thing standing between a real
//! security assertion and a stub binary that errors on everything and thereby
//! passes all fourteen of them.
//!
//! So: **`REFUSED` (2) means a policy decision was made and went against the
//! caller.** Nothing else may use it. In particular an unimplemented subcommand
//! must exit [`UNIMPLEMENTED`], never `REFUSED`, or the harness would score
//! unwritten code as a passing security control.

/// The operation succeeded.
pub const OK: i32 = 0;
/// Something went wrong: bad arguments, I/O failure, corrupt data.
pub const ERROR: i32 = 1;
/// Refused by policy. Reserved. See the module docs.
pub const REFUSED: i32 = 2;
/// Recognised, specified, and not built yet.
pub const UNIMPLEMENTED: i32 = 3;
