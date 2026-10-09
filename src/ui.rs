//! User-facing CLI output, separate from diagnostic tracing.
//!
//! `tracing::*` is for debug/diagnostic logs (default level WARN, lifted
//! by `-v` / `-vv`). Anything the user is expected to read during normal
//! operation goes through this module: no `INFO:` prefix, no timestamp,
//! no module path — just plain prose with optional colour glyphs on a
//! TTY.
//!
//! All output goes to stderr (CLI convention: stdout is reserved for
//! the structured payload of a command, like JSON or piped text).

use std::io::{BufRead, IsTerminal as _, Write};
use std::sync::OnceLock;

use crate::exit::{Exit, Failure};

static COLOR: OnceLock<bool> = OnceLock::new();

/// Set once at startup from `main`. Subsequent calls are ignored.
pub fn init_color(enabled: bool) {
    if COLOR.set(enabled).is_err() {
        tracing::debug!("colour was already decided; keeping the first");
    }
}

fn coloured() -> bool {
    *COLOR.get().unwrap_or(&false)
}

/// Neutral status line, no glyph. Used for "created default profile", etc.
pub fn say(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

/// Success-tinted line with a `✓` glyph.
pub fn ok(msg: impl AsRef<str>) {
    if coloured() {
        eprintln!("\x1b[32m✓\x1b[0m {}", msg.as_ref());
    } else {
        eprintln!("✓ {}", msg.as_ref());
    }
}

/// Warning-tinted line with a `!` glyph.
pub fn warn(msg: impl AsRef<str>) {
    if coloured() {
        eprintln!("\x1b[33m!\x1b[0m {}", msg.as_ref());
    } else {
        eprintln!("! {}", msg.as_ref());
    }
}

/// Informational line with a `→` glyph, dim-styled on a TTY.
/// SPEC-043 — used to surface ambient context resolution
/// (`→ acting on alice (source: profile-default)`). Lives between
/// `say()` (neutral status) and `ok()` (success) — informational,
/// not load-bearing.
pub fn note(msg: impl AsRef<str>) {
    if coloured() {
        eprintln!("\x1b[2m→ {}\x1b[0m", msg.as_ref());
    } else {
        eprintln!("→ {}", msg.as_ref());
    }
}

/// How a command may get a yes: whether `-y`/`--yes` was given, whether it
/// runs under `--output json`, and whether a person is at stdin.
///
/// Built with [`Confirm::new`], which reads the terminal; a test builds the
/// struct itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirm {
    /// `-y` / `--yes` was given.
    pub yes: bool,
    /// `--output json`: never prompts.
    pub json: bool,
    /// stdin is a terminal.
    pub stdin_is_terminal: bool,
    /// Whether a flag may give the yes at all. `false` for the one
    /// confirmation only a person at the machine may give (`shell host
    /// trust`), where the refusal says so instead of naming `--yes`.
    pub yes_allowed: bool,
}

impl Confirm {
    /// For a command that takes `-y`/`--yes`.
    pub fn new(yes: bool, json: bool) -> Self {
        Self {
            yes,
            json,
            stdin_is_terminal: std::io::stdin().is_terminal(),
            yes_allowed: true,
        }
    }

    /// For a confirmation only a person at a terminal may give: no flag
    /// answers it.
    pub fn person_only(json: bool) -> Self {
        Self {
            yes: false,
            json,
            stdin_is_terminal: std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            yes_allowed: false,
        }
    }
}

/// The one confirmation prompt (rust guide CLI-4).
///
/// - `-y`/`--yes`: `Ok` without asking.
/// - No terminal on stdin, or `--output json`: never asks; a
///   `confirmation_required` failure (exit 7) naming `--yes`.
/// - Otherwise asks `question [y/N]` on stderr. Default **No**: anything but
///   `y`/`yes` (any case), including an empty line or end of input, is a
///   decline, `confirmation_declined` (exit 3).
pub fn confirm(question: &str, how: Confirm) -> Result<(), Failure> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    confirm_with(question, how, &mut input, &mut std::io::stderr())
}

/// [`confirm`] over any input and prompt output.
pub fn confirm_with(
    question: &str,
    how: Confirm,
    input: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> Result<(), Failure> {
    if how.yes && how.yes_allowed {
        return Ok(());
    }
    if how.json || !how.stdin_is_terminal {
        let why = if how.json {
            "--output json never prompts"
        } else {
            "stdin is not a terminal"
        };
        let question = question.trim_end();
        let mut f = Failure::new(
            Exit::ConfirmationRequired,
            "confirmation_required",
            format!("{question} needs an answer, and {why}"),
        );
        if how.yes_allowed {
            f = f.with_hint("pass `--yes` (`-y`) to confirm");
            f.extra.insert("flag".to_owned(), "--yes".into());
        } else {
            f = f.with_hint("only a person at this machine's terminal can confirm this");
        }
        return Err(f);
    }
    let declined = || {
        Failure::new(
            Exit::Refused,
            "confirmation_declined",
            "declined: nothing was changed",
        )
    };
    if write!(prompt, "{} [y/N] ", question.trim_end())
        .and_then(|()| prompt.flush())
        .is_err()
    {
        return Err(declined());
    }
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(_) if is_yes(&line) => Ok(()),
        _ => Err(declined()),
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn how(yes: bool, json: bool, tty: bool) -> Confirm {
        Confirm {
            yes,
            json,
            stdin_is_terminal: tty,
            yes_allowed: true,
        }
    }

    fn ask(c: Confirm, answer: &str) -> (Result<(), Failure>, String) {
        let mut out = Vec::new();
        let r = confirm_with("Delete it?", c, &mut answer.as_bytes(), &mut out);
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn yes_never_asks() {
        for (json, tty) in [(false, false), (true, true), (false, true)] {
            let (r, prompt) = ask(how(true, json, tty), "");
            assert!(r.is_ok());
            assert!(prompt.is_empty());
        }
    }

    #[test]
    fn no_terminal_is_confirmation_required_naming_the_flag() {
        let (r, prompt) = ask(how(false, false, false), "y\n");
        let f = r.unwrap_err();
        assert_eq!(f.exit, Exit::ConfirmationRequired);
        assert_eq!(f.code, "confirmation_required");
        assert!(f.hint.unwrap().contains("--yes"));
        assert_eq!(f.extra["flag"], "--yes");
        assert!(prompt.is_empty(), "never asked");
    }

    #[test]
    fn json_mode_never_prompts_even_at_a_terminal() {
        let (r, prompt) = ask(how(false, true, true), "y\n");
        assert_eq!(r.unwrap_err().exit, Exit::ConfirmationRequired);
        assert!(prompt.is_empty());
    }

    #[test]
    fn a_terminal_is_asked_and_the_default_is_no() {
        let (r, prompt) = ask(how(false, false, true), "Y\n");
        assert!(r.is_ok());
        assert_eq!(prompt, "Delete it? [y/N] ");
        for no in ["\n", "", "n\n", "yes please\n"] {
            let f = ask(how(false, false, true), no).0.unwrap_err();
            assert_eq!(
                (f.exit, f.code.as_str()),
                (Exit::Refused, "confirmation_declined")
            );
        }
    }

    #[test]
    fn only_an_explicit_yes_confirms() {
        for a in ["y", "Y", "yes", " YES \n"] {
            assert!(is_yes(a), "{a:?}");
        }
        for a in ["", "\n", "n", "no", "yep", "sure"] {
            assert!(!is_yes(a), "{a:?}");
        }
    }

    #[test]
    fn a_person_only_confirmation_ignores_yes() {
        let c = Confirm {
            yes: true,
            json: false,
            stdin_is_terminal: false,
            yes_allowed: false,
        };
        let f = ask(c, "").0.unwrap_err();
        assert_eq!(f.exit, Exit::ConfirmationRequired);
        assert!(!f.hint.unwrap().contains("--yes"));
    }

    #[test]
    fn coloured_defaults_false() {
        // OnceLock keeps state across tests in the same binary, but the
        // initial state is empty → false.
        assert!(!coloured() || COLOR.get().is_some());
    }
}
