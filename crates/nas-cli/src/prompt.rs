//! Asking a human for a passphrase (SPECS §2.2.2).
//!
//! The rule this module exists to keep is a negative one: a passphrase comes
//! from `--passphrase`, from `$NAS_PASSPHRASE`, or from a person at a
//! terminal, and from nowhere else. No default, no empty passphrase, no
//! best-effort fallback when stdin is a pipe. A prompt that invented one would
//! be worse than the refusal it replaced, because the namespace it created
//! would look protected and would not be.
//!
//! So the prompt is used only when *both* hold: nothing was passed on the
//! command line or in the environment, **and** stdin is a terminal. Otherwise
//! the caller keeps the refusal it always had.
//!
//! # What this deliberately does not do
//!
//! Echo is turned off with `tcsetattr` and put back by [`EchoOff`]'s `Drop`,
//! which covers every ordinary return path — including `?` returning early and
//! a panic unwinding past. It does **not** cover Ctrl-C: SIGINT's default
//! disposition kills the process outright, no destructor runs, and the
//! terminal is left with echo off until the shell or `stty sane` puts it back.
//! Covering that needs a signal handler, which is a bigger and more delicate
//! change than a passphrase prompt should smuggle in. The gap is stated here
//! rather than left to be discovered.

use std::io::{self, BufRead, IsTerminal, Write};
use std::os::fd::{AsRawFd, RawFd};
use zeroize::Zeroizing;

/// What to say when no passphrase was supplied and there is no terminal to ask
/// on. Shared so the two refusal sites cannot drift apart.
pub const NO_TERMINAL: &str = "passphrase mode needs --passphrase or $NAS_PASSPHRASE; \
     stdin is not a terminal, so there was nothing to prompt on";

/// How many times to ask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ask {
    /// Opening an existing namespace: once. A typo fails to unwrap the wrap
    /// record, which is answer enough and costs one Argon2id pass.
    Once,
    /// Creating one: twice, and the two must agree. Nothing later will ever be
    /// able to tell the operator they mistyped the only copy of the secret
    /// that opens the namespace.
    Twice,
}

/// Why a prompt yielded no passphrase.
#[derive(Debug)]
pub enum Error {
    /// The person answered and the answer is unusable: nothing typed, or the
    /// two entries differed. A decision that went against the caller, not a
    /// malfunction.
    Refused(&'static str),
    /// The terminal itself failed.
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(why) => f.write_str(why),
            Error::Io(e) => write!(f, "could not read from the terminal: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Ask on the controlling terminal, if there is one.
///
/// `Ok(None)` means stdin is not a terminal and nothing was asked — the caller
/// keeps whatever refusal it had before a prompt existed at all.
pub fn passphrase(ask: Ask) -> Result<Option<Vec<u8>>, Error> {
    from_terminal(ask, io::stdin().is_terminal())
}

/// [`passphrase`], with the one thing a unit test cannot arrange — whether the
/// test harness's own stdin happens to be a terminal — passed in instead.
fn from_terminal(ask: Ask, is_terminal: bool) -> Result<Option<Vec<u8>>, Error> {
    if !is_terminal {
        return Ok(None);
    }
    let stdin = io::stdin();
    let _echo_off = EchoOff::acquire(stdin.as_raw_fd())?;
    // The prompt goes to stderr: stdout carries results a caller may be
    // capturing, and a passphrase prompt is not a result.
    ask_on(ask, &mut stdin.lock(), &mut io::stderr()).map(Some)
}

/// The half of prompting that has nothing to do with terminals.
///
/// Split out so the rules that actually matter — one line ending comes off and
/// nothing else, empty is refused, a create's two entries must match — are
/// exercised against an ordinary reader rather than a pty.
fn ask_on(ask: Ask, src: &mut impl BufRead, out: &mut impl Write) -> Result<Vec<u8>, Error> {
    write!(out, "Passphrase: ")?;
    out.flush()?;
    let first = read_line_wiped(src)?;
    // Echo is off, so the Enter that ended the line left nothing on screen.
    writeln!(out)?;
    if first.is_empty() {
        return Err(Error::Refused("no passphrase typed"));
    }
    if ask == Ask::Twice {
        write!(out, "Confirm passphrase: ")?;
        out.flush()?;
        let again = read_line_wiped(src)?;
        writeln!(out)?;
        if *first != *again {
            return Err(Error::Refused("the two passphrases do not match"));
        }
    }
    Ok(first.as_bytes().to_vec())
}

/// One line, minus its ending, in a buffer that is wiped when it drops.
///
/// EOF with nothing typed (Ctrl-D at the prompt) yields the empty string,
/// which [`ask_on`] refuses — the same answer as pressing Enter on an empty
/// line, which is what it means.
///
/// Honest limit: `read_line` grows the string as it reads, and a reallocation
/// leaves the old bytes in freed memory that `Zeroizing` will never reach.
/// Reserving up front makes that unlikely for anything a person types; it is
/// not a proof that no copy survives.
fn read_line_wiped(src: &mut impl BufRead) -> io::Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(String::with_capacity(512));
    src.read_line(&mut buf)?;
    strip_eol(&mut buf);
    Ok(buf)
}

/// Remove one trailing `\r\n` or `\n`, and nothing else.
///
/// Not `trim`: a passphrase may legitimately begin or end with a space, and
/// silently changing what someone typed would produce a namespace they cannot
/// reopen by typing the same thing again.
fn strip_eol(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

/// Echo off for as long as this lives, and the terminal's own settings back
/// the moment it stops. See the module docs for the one case it cannot cover.
struct EchoOff {
    fd: RawFd,
    saved: libc::termios,
}

impl EchoOff {
    fn acquire(fd: RawFd) -> io::Result<Self> {
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is stdin, open for the life of the process, and
        // `tcgetattr` only writes a `termios` through the pointer given it.
        if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned 0, so it initialised the struct.
        let saved = unsafe { saved.assume_init() };
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        // TCSAFLUSH, not TCSANOW: apply once the output has drained and throw
        // away anything typed ahead. Type-ahead entered before the prompt
        // appeared was not meant as part of the passphrase, and it was typed
        // with echo still on.
        // SAFETY: the same fd, and a `termios` we own.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // A failure here has nowhere useful to go: we are leaving the prompt
        // either way, and reporting it would bury the reason we are leaving.
        // TCSANOW rather than TCSAFLUSH so restoring echo does not discard
        // whatever the caller types next.
        // SAFETY: the same fd, and the settings this guard read from it.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ask(kind: Ask, typed: &str) -> Result<Vec<u8>, Error> {
        ask_on(kind, &mut Cursor::new(typed.as_bytes()), &mut Vec::new())
    }

    fn refusal(r: Result<Vec<u8>, Error>) -> String {
        match r {
            Err(Error::Refused(why)) => why.to_string(),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The line ending goes; everything else the person typed stays. Trimming
    /// would quietly produce a passphrase that is not the one they chose.
    #[test]
    fn only_the_line_ending_comes_off() {
        assert_eq!(ask(Ask::Once, "hunter2\n").unwrap(), b"hunter2");
        assert_eq!(ask(Ask::Once, "hunter2\r\n").unwrap(), b"hunter2");
        assert_eq!(ask(Ask::Once, " two words \n").unwrap(), b" two words ");
        assert_eq!(ask(Ask::Once, "tab\there\n").unwrap(), b"tab\there");
        // No ending at all: EOF closed the line.
        assert_eq!(ask(Ask::Once, "hunter2").unwrap(), b"hunter2");
        // One ending, not two: a passphrase may itself end in a newline when
        // it arrives from somewhere that is not a keyboard.
        assert_eq!(ask(Ask::Once, "a\n\n").unwrap(), b"a");
    }

    /// Nothing typed is a refusal, never a default. This is the whole reason
    /// the prompt was allowed to exist.
    #[test]
    fn an_empty_answer_is_refused() {
        assert_eq!(refusal(ask(Ask::Once, "\n")), "no passphrase typed");
        assert_eq!(refusal(ask(Ask::Once, "\r\n")), "no passphrase typed");
        // Ctrl-D at the prompt: EOF with nothing read.
        assert_eq!(refusal(ask(Ask::Once, "")), "no passphrase typed");
        assert_eq!(refusal(ask(Ask::Twice, "\n\n")), "no passphrase typed");
    }

    /// On create there is no second chance: a mistyped passphrase is a
    /// namespace nobody can open, so the two entries must agree.
    #[test]
    fn create_refuses_two_that_differ() {
        assert_eq!(
            refusal(ask(Ask::Twice, "one\ntwo\n")),
            "the two passphrases do not match"
        );
        assert_eq!(ask(Ask::Twice, "same\nsame\n").unwrap(), b"same");
        // Compared after stripping, so two different line endings still match.
        assert_eq!(ask(Ask::Twice, "same\r\nsame\n").unwrap(), b"same");
        // ...and a trailing space is part of the passphrase, so it does not.
        assert_eq!(
            refusal(ask(Ask::Twice, "same\nsame \n")),
            "the two passphrases do not match"
        );
    }

    /// A confirmation that is only asked for on create.
    #[test]
    fn open_asks_once_and_create_twice() {
        let seen = |kind| {
            let mut out = Vec::new();
            let _ = ask_on(kind, &mut Cursor::new(&b"pw\npw\n"[..]), &mut out);
            String::from_utf8(out).unwrap()
        };
        assert_eq!(seen(Ask::Once), "Passphrase: \n");
        assert_eq!(seen(Ask::Twice), "Passphrase: \nConfirm passphrase: \n");
    }

    /// No terminal, no prompt, and — just as important — no read of stdin: the
    /// caller is handed back its own refusal instead of being blocked on a
    /// pipe that will never carry a passphrase.
    #[test]
    fn without_a_terminal_nothing_is_asked() {
        assert!(from_terminal(Ask::Once, false).unwrap().is_none());
        assert!(from_terminal(Ask::Twice, false).unwrap().is_none());
    }

    /// The refusal has to name both of the ways a passphrase can be supplied
    /// without a terminal, or it tells the operator nothing they can act on.
    #[test]
    fn the_refusal_says_what_to_do_instead() {
        assert!(NO_TERMINAL.contains("--passphrase"));
        assert!(NO_TERMINAL.contains("$NAS_PASSPHRASE"));
        assert!(NO_TERMINAL.contains("not a terminal"));
    }
}
