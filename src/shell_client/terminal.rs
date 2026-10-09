//! The local terminal: the TTY check, raw mode, the window size, and the
//! escape key.
//!
//! **The TTY check (FR-C2).** `airdress shell` refuses to open or attach
//! unless both stdin and stdout are terminals. It is a speed bump, not a
//! boundary: a process of the same user that opens a pseudo-terminal of its
//! own passes it (requirements T-10, accepted under D-30).
//!
//! **The escape key** is `Ctrl-]`, then a letter (design §10.2):
//!
//! | Keys | What |
//! |---|---|
//! | `Ctrl-]` `d` | detach; the session keeps running |
//! | `Ctrl-]` `q` | close the session, after a confirmation |
//! | `Ctrl-]` `i` | take input back on this device |
//! | `Ctrl-]` `?` | show these keys |
//! | `Ctrl-]` `Ctrl-]` | send one `Ctrl-]` to the program |
//!
//! Any other key after `Ctrl-]` is sent as typed, `Ctrl-]` included.

use std::io::IsTerminal as _;

/// `Ctrl-]`.
pub const ESCAPE: u8 = 0x1d;

/// What the escape parser makes of a key sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// Bytes for the program.
    Input(Vec<u8>),
    /// `Ctrl-]` `d`.
    Detach,
    /// `Ctrl-]` `q`.
    Close,
    /// `Ctrl-]` `i`.
    TakeInput,
    /// `Ctrl-]` `?`.
    Help,
}

/// Splits typed bytes into input and escape commands. Holds a trailing
/// `Ctrl-]` until the next key arrives.
#[derive(Debug, Default)]
pub struct EscapeParser {
    armed: bool,
}

impl EscapeParser {
    /// Feed what was read from the terminal.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Key> {
        let mut out = Vec::new();
        let mut run = Vec::new();
        for &b in bytes {
            if self.armed {
                self.armed = false;
                let cmd = match b {
                    b'd' | b'D' => Some(Key::Detach),
                    b'q' | b'Q' => Some(Key::Close),
                    b'i' | b'I' => Some(Key::TakeInput),
                    b'?' => Some(Key::Help),
                    ESCAPE => {
                        run.push(ESCAPE);
                        None
                    }
                    other => {
                        run.push(ESCAPE);
                        run.push(other);
                        None
                    }
                };
                if let Some(cmd) = cmd {
                    if !run.is_empty() {
                        out.push(Key::Input(std::mem::take(&mut run)));
                    }
                    out.push(cmd);
                }
            } else if b == ESCAPE {
                self.armed = true;
            } else {
                run.push(b);
            }
        }
        if !run.is_empty() {
            out.push(Key::Input(run));
        }
        out
    }
}

/// The help line the escape key prints.
pub const ESCAPE_HELP: &str =
    "Ctrl-] then: d detach · q close the session · i take input · Ctrl-] send Ctrl-]";

/// Whether stdin and stdout are both terminals (FR-C2).
pub fn both_are_terminals() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The terminal's size as (cols, rows), or 80×24 when it cannot be read.
pub fn size() -> (u16, u16) {
    #[cfg(unix)]
    {
        // SAFETY: `winsize` is a C struct of integers, for which all zero
        // bytes is a valid value.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes one `winsize` into the pointer, which
        // points at a live, properly aligned local.
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return (ws.ws_col, ws.ws_row);
        }
    }
    (80, 24)
}

/// Raw mode on stdin while this lives; the previous mode comes back on
/// drop, including on an error path.
pub struct RawMode {
    #[cfg(unix)]
    saved: libc::termios,
}

impl std::fmt::Debug for RawMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawMode").finish_non_exhaustive()
    }
}

impl RawMode {
    /// Put stdin in raw mode: no echo, no line discipline, no signals from
    /// keys (`Ctrl-C` goes to the program on the host, as a local keyboard
    /// would send it), no output post-processing.
    pub fn enter() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            // SAFETY: `termios` is a C struct of integers and arrays of
            // them, for which all zero bytes is a valid value.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: tcgetattr fills the termios struct for a valid fd.
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let saved = t;
            // SAFETY: cfmakeraw only edits the struct it is given.
            unsafe { libc::cfmakeraw(&mut t) };
            // SAFETY: tcsetattr reads the struct; the fd is valid.
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { saved })
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "raw terminal mode needs a Unix terminal",
            ))
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: restores the struct read in `enter` on the same fd.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
        }
    }
}

/// A notice inside a raw-mode session: on its own line, dimmed, and ending
/// with a carriage return so the next line starts at column zero.
pub fn notice(text: &str) -> Vec<u8> {
    format!("\r\n\x1b[2m[airdress] {text}\x1b[0m\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes_pass_through() {
        let mut p = EscapeParser::default();
        assert_eq!(p.feed(b"ls -l\r"), vec![Key::Input(b"ls -l\r".to_vec())]);
    }

    #[test]
    fn escape_commands_are_recognised_across_reads() {
        let mut p = EscapeParser::default();
        assert_eq!(p.feed(b"ab\x1d"), vec![Key::Input(b"ab".to_vec())]);
        assert_eq!(p.feed(b"d"), vec![Key::Detach]);
        assert_eq!(p.feed(b"\x1dq"), vec![Key::Close]);
        assert_eq!(p.feed(b"\x1di"), vec![Key::TakeInput]);
        assert_eq!(p.feed(b"\x1d?"), vec![Key::Help]);
    }

    #[test]
    fn a_doubled_escape_sends_one_and_an_unknown_key_sends_both() {
        let mut p = EscapeParser::default();
        assert_eq!(p.feed(b"\x1d\x1d"), vec![Key::Input(vec![ESCAPE])]);
        assert_eq!(p.feed(b"\x1dx"), vec![Key::Input(vec![ESCAPE, b'x'])]);
    }

    #[test]
    fn ctrl_c_is_input_for_the_program() {
        let mut p = EscapeParser::default();
        assert_eq!(p.feed(&[0x03]), vec![Key::Input(vec![0x03])]);
    }
}
