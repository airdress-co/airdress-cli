//! A session's process on a pseudo-terminal, inside the host process
//! (design §7.1–§7.3, D-15, D-17, FR-P8).
//!
//! `openpty`, then the profile's program with its argv built element by
//! element — never through a shell — as a new session leader with the PTY
//! as its controlling terminal (`setsid`, `TIOCSCTTY`). The child runs as
//! the user who runs the host: there is no `setuid`, `setgid` or
//! `initgroups` anywhere in this crate, and no helper process.
//!
//! The host reads the master continuously, with a 2 ms coalescing window
//! so an echo and the cursor move after it travel together (design §8.4),
//! and never blocks on a viewer.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use airdress_shell_proto::inner::SignalKind;
use anyhow::{Context, Result};
use rustix::pty::OpenptFlags;
use rustix::termios::{SpecialCodeIndex, Winsize};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};

use crate::environment::SessionEnv;
use crate::log_err::LogErr as _;
use crate::profiles::ProcessSpec;

/// How long the reader waits for more output before it sends what it has.
pub const COALESCE: Duration = Duration::from_millis(2);
/// The most the reader sends at once.
pub const READ_BATCH: usize = 32 * 1024;
/// How many chunks of input wait for a program that is not reading
/// (R-ASY-5). A chunk is one `in` message, so at most one record's budget
/// (under 64 KiB): with this bound a stopped program holds at most about
/// 1 MiB of a person's paste on the host, beyond the kernel's own terminal
/// buffer. Past it, [`Pty::try_write`] hands the chunk back and the caller
/// waits ([`Pty::input`]): the host stops reading its link, and the sender
/// slows. Input is never dropped here and never buffered without bound.
pub const INPUT_QUEUE: usize = 16;

/// What a session's PTY tasks report.
#[derive(Debug)]
pub enum PtyEvent {
    /// Output.
    Output(Vec<u8>),
    /// The program exited: its code, or the signal that ended it.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// From the session's structured adapter (design §9).
    Structured(crate::structured::AdapterOut),
    /// A hook call on the host's event socket, for this session (§9.4).
    Hook(crate::structured::events::HookCall),
}

/// The program's stdin and stdout, for an adapter whose protocol is the
/// program's stdio (design §9.1: `acp`, `codex-app-server`). Its stderr is
/// still the terminal, so the session's terminal shows the harness's log.
#[derive(Debug)]
pub struct Stdio {
    pub stdin: tokio::process::ChildStdin,
    pub stdout: tokio::process::ChildStdout,
}

/// The host's end of one session's terminal.
///
/// It owns the session's reader, writer and waiter (R-ASY-1): dropping it
/// aborts all three. The child is not killed by that (the session's own
/// hangup and kill do it); tokio reaps a child whose waiter went away.
pub struct Pty {
    master: Arc<AsyncFd<OwnedFd>>,
    pid: rustix::process::Pid,
    input: mpsc::Sender<Vec<u8>>,
    _tasks: tokio::task::JoinSet<()>,
}

impl std::fmt::Debug for Pty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pty")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

fn winsize(cols: u16, rows: u16) -> Winsize {
    Winsize {
        ws_row: rows.max(1),
        ws_col: cols.max(1),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn open_pair() -> Result<(OwnedFd, OwnedFd)> {
    let master = open_master()?;
    rustix::pty::grantpt(&master).context("grantpt")?;
    rustix::pty::unlockpt(&master).context("unlockpt")?;
    let name = rustix::pty::ptsname(&master, Vec::new()).context("ptsname")?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context("open the terminal's slave end")?;
    Ok((master, slave))
}

/// The terminal's master end, close-on-exec so no session's program
/// inherits another session's terminal.
#[cfg(target_os = "linux")]
fn open_master() -> Result<OwnedFd> {
    rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
        .context("openpt")
}

/// The terminal's master end, close-on-exec so no session's program
/// inherits another session's terminal. `posix_openpt` takes no
/// `O_CLOEXEC` outside Linux (macOS among them), so the flag is set
/// straight after. A child forked by another thread inside that window
/// would inherit the descriptor; Linux, where the host ships today, has no
/// such window.
#[cfg(not(target_os = "linux"))]
fn open_master() -> Result<OwnedFd> {
    let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).context("openpt")?;
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)
        .context("set close-on-exec on the terminal's master end")?;
    Ok(master)
}

/// Start `spec` on a new `cols`×`rows` terminal with exactly `env`.
/// Events (output, then the exit) go to `events`.
pub fn spawn(
    spec: &ProcessSpec,
    env: &SessionEnv,
    cols: u16,
    rows: u16,
    events: mpsc::Sender<PtyEvent>,
) -> Result<Pty> {
    spawn_with(spec, env, cols, rows, events, false).map(|(p, _)| p)
}

/// [`spawn`], or with `stdio` the program's stdin and stdout as pipes for
/// an adapter, and only its stderr on the terminal (which is still its
/// controlling terminal, so hangup and the process group work the same).
pub fn spawn_with(
    spec: &ProcessSpec,
    env: &SessionEnv,
    cols: u16,
    rows: u16,
    events: mpsc::Sender<PtyEvent>,
    stdio: bool,
) -> Result<(Pty, Option<Stdio>)> {
    let (master, slave) = open_pair()?;
    rustix::termios::tcsetwinsize(&master, winsize(cols, rows)).context("set the window size")?;
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(&env.vars)
        .current_dir(&spec.cwd)
        .kill_on_drop(false);
    if stdio {
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::from(slave.try_clone()?))
            .stdout(std::process::Stdio::from(slave.try_clone()?));
    }
    cmd.stderr(std::process::Stdio::from(slave));
    // SAFETY: the closure runs in the child between fork and exec, and calls
    // only `setsid` and the `TIOCSCTTY` ioctl, both async-signal-safe raw
    // system calls; it allocates nothing and takes no lock. The terminal is
    // taken through stderr, which is the terminal in both modes.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid().map_err(std::io::Error::from)?;
            rustix::process::ioctl_tiocsctty(rustix::stdio::stderr())
                .map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not start {}", spec.program.display()))?;
    let pipes = if stdio {
        match (child.stdin.take(), child.stdout.take()) {
            (Some(stdin), Some(stdout)) => Some(Stdio { stdin, stdout }),
            _ => anyhow::bail!("the program's stdio could not be taken"),
        }
    } else {
        None
    };
    let pid = child
        .id()
        .and_then(|p| rustix::process::Pid::from_raw(p as i32))
        .context("the child has no pid")?;
    drop(cmd);
    set_nonblocking(&master)?;
    let master = Arc::new(AsyncFd::new(master).context("register the terminal")?);
    let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
    let (read_done_tx, read_done_rx) = oneshot::channel();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(read_loop(Arc::clone(&master), events.clone(), read_done_tx));
    tasks.spawn(write_loop(Arc::clone(&master), input_rx));
    tasks.spawn(async move {
        let status = child.wait().await;
        // Let the reader drain what the program wrote before it exited.
        // Elapsed: the reader is still going; the exit is reported anyway.
        let _drained = tokio::time::timeout(Duration::from_millis(250), read_done_rx)
            .await
            .is_ok();
        let (code, signal) = match status {
            Ok(s) => {
                use std::os::unix::process::ExitStatusExt as _;
                (s.code(), s.signal())
            }
            Err(_) => (None, None),
        };
        events
            .send(PtyEvent::Exited { code, signal })
            .await
            .log_debug("reporting the program's exit");
    });
    Ok((
        Pty {
            master,
            pid,
            input,
            _tasks: tasks,
        },
        pipes,
    ))
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

fn read_some(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    rustix::io::read(fd.get_ref(), buf).map_err(std::io::Error::from)
}

async fn read_loop(
    fd: Arc<AsyncFd<OwnedFd>>,
    events: mpsc::Sender<PtyEvent>,
    done: oneshot::Sender<()>,
) {
    let mut buf = vec![0u8; READ_BATCH];
    'outer: loop {
        let mut batch: Vec<u8> = Vec::new();
        // Wait for the first byte, then coalesce for COALESCE.
        loop {
            let Ok(mut guard) = fd.readable().await else {
                break 'outer;
            };
            match guard.try_io(|inner| read_some(inner, &mut buf)) {
                Ok(Ok(0)) | Ok(Err(_)) => break 'outer,
                Ok(Ok(n)) => {
                    batch.extend_from_slice(&buf[..n]);
                    break;
                }
                Err(_would_block) => continue,
            }
        }
        let deadline = tokio::time::Instant::now() + COALESCE;
        while batch.len() < READ_BATCH {
            let ready = tokio::time::timeout_at(deadline, fd.readable()).await;
            let Ok(Ok(mut guard)) = ready else { break };
            let room = READ_BATCH - batch.len();
            match guard.try_io(|inner| read_some(inner, &mut buf[..room])) {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    events
                        .send(PtyEvent::Output(batch))
                        .await
                        .log_debug("handing on the last output");
                    break 'outer;
                }
                Ok(Ok(n)) => batch.extend_from_slice(&buf[..n]),
                Err(_would_block) => continue,
            }
        }
        if events.send(PtyEvent::Output(batch)).await.is_err() {
            break;
        }
    }
    // Nobody waiting: the exit was reported without the drain.
    if done.send(()).is_err() {
        tracing::debug!("the reader finished after the exit was reported");
    }
}

async fn write_loop(fd: Arc<AsyncFd<OwnedFd>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        let mut at = 0;
        while at < data.len() {
            let Ok(mut guard) = fd.writable().await else {
                return;
            };
            match guard.try_io(|inner| {
                rustix::io::write(inner.get_ref(), &data[at..]).map_err(std::io::Error::from)
            }) {
                Ok(Ok(n)) => at += n,
                Ok(Err(_)) => return,
                Err(_would_block) => continue,
            }
        }
    }
}

impl Pty {
    /// The session leader's pid, which is also its process group.
    pub fn pid(&self) -> i32 {
        self.pid.as_raw_nonzero().get()
    }

    /// Type into the program, in order, without waiting. `Err` hands the
    /// chunk back when [`INPUT_QUEUE`] chunks are already waiting for a
    /// program that is not reading: the caller waits for room on
    /// [`Pty::input`] and does not take more input meanwhile. A program
    /// that has exited takes nothing; its exit is reported instead.
    pub fn try_write(&self, data: Vec<u8>) -> Result<(), Vec<u8>> {
        match self.input.try_send(data) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Full(data)) => Err(data),
        }
    }

    /// Type into the program, in order, waiting while it is not reading.
    pub async fn write(&self, data: Vec<u8>) {
        // Closed: the program has exited, and its exit is reported.
        self.input
            .send(data)
            .await
            .log_debug("queueing input for the program");
    }

    /// The input queue, to wait for room on it.
    pub fn input(&self) -> mpsc::Sender<Vec<u8>> {
        self.input.clone()
    }

    /// Set the terminal size; the kernel sends `SIGWINCH`.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        rustix::termios::tcsetwinsize(self.master.get_ref().as_fd(), winsize(cols, rows))?;
        Ok(())
    }

    /// The character the terminal's current settings map `signal` to, from
    /// `termios` `c_cc` (FR-S8). `None` when it is disabled.
    pub fn control_char(&self, signal: SignalKind) -> Result<Option<u8>> {
        let t = rustix::termios::tcgetattr(self.master.get_ref().as_fd())?;
        let idx = match signal {
            SignalKind::Interrupt => SpecialCodeIndex::VINTR,
            SignalKind::Suspend => SpecialCodeIndex::VSUSP,
            SignalKind::Quit => SpecialCodeIndex::VQUIT,
            SignalKind::Eof => SpecialCodeIndex::VEOF,
        };
        let c = t.special_codes[idx];
        // _POSIX_VDISABLE is 0 on Linux.
        Ok((c != 0).then_some(c))
    }

    /// `SIGHUP` to the session's process group.
    pub fn hangup(&self) {
        // ESRCH: the group has already gone.
        rustix::process::kill_process_group(self.pid, rustix::process::Signal::HUP)
            .log_debug("SIGHUP to the session's process group");
    }

    /// `SIGKILL` to the session's process group.
    pub fn kill(&self) {
        rustix::process::kill_process_group(self.pid, rustix::process::Signal::KILL)
            .log_debug("SIGKILL to the session's process group");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn spec(program: &str, args: &[&str]) -> ProcessSpec {
        ProcessSpec {
            program: PathBuf::from(program),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: PathBuf::from("/"),
            env_allow: vec![],
            env_set: BTreeMap::new(),
        }
    }

    async fn collect_until(
        rx: &mut mpsc::Receiver<PtyEvent>,
        needle: &str,
    ) -> (String, Option<(Option<i32>, Option<i32>)>) {
        let mut out = String::new();
        let mut exit = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            match ev {
                PtyEvent::Output(b) => out.push_str(&String::from_utf8_lossy(&b)),
                PtyEvent::Exited { code, signal } => {
                    exit = Some((code, signal));
                    break;
                }
                PtyEvent::Structured(_) | PtyEvent::Hook(_) => {}
            }
            if !needle.is_empty() && out.contains(needle) {
                break;
            }
        }
        (out, exit)
    }

    #[tokio::test]
    async fn the_program_runs_on_its_own_terminal_with_exactly_its_environment() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut env = SessionEnv::default();
        env.vars.insert("ONLY".into(), "this".into());
        let pty = spawn(&spec("/usr/bin/env", &[]), &env, 80, 24, tx).unwrap();
        let (out, exit) = collect_until(&mut rx, "").await;
        assert_eq!(out.trim(), "ONLY=this", "{out:?}");
        assert_eq!(exit, Some((Some(0), None)));
        assert!(pty.pid() > 0);
    }

    #[tokio::test]
    async fn the_child_leads_its_own_session_on_the_terminal() {
        let (tx, mut rx) = mpsc::channel(64);
        // `ps -o` is not everywhere; /proc is, on Linux.
        let pty = spawn(
            &spec("/bin/sh", &["-c", "tty; cat /proc/$$/stat"]),
            &SessionEnv::default(),
            80,
            24,
            tx,
        )
        .unwrap();
        let (out, _) = collect_until(&mut rx, "").await;
        assert!(out.contains("/dev/pts/"), "{out}");
        let stat = out.lines().nth(1).unwrap_or_default();
        let fields: Vec<&str> = stat
            .rsplit(')')
            .next()
            .unwrap()
            .split_whitespace()
            .collect();
        // pid, then after the command: state ppid pgrp session tty_nr
        let pgrp: i32 = fields[2].parse().unwrap();
        let session: i32 = fields[3].parse().unwrap();
        let tty_nr: i32 = fields[4].parse().unwrap();
        assert_eq!(pgrp, pty.pid());
        assert_eq!(session, pty.pid());
        assert_ne!(tty_nr, 0, "a controlling terminal");
    }

    #[tokio::test]
    async fn input_echoes_and_the_size_and_signals_follow_termios() {
        let (tx, mut rx) = mpsc::channel(64);
        let pty = spawn(&spec("/bin/cat", &[]), &SessionEnv::default(), 80, 24, tx).unwrap();
        pty.write(b"hello\n".to_vec()).await;
        let (out, _) = collect_until(&mut rx, "hello\r\nhello").await;
        assert!(out.contains("hello"), "{out}");
        assert_eq!(pty.control_char(SignalKind::Interrupt).unwrap(), Some(3));
        assert_eq!(pty.control_char(SignalKind::Eof).unwrap(), Some(4));
        pty.resize(100, 40).unwrap();
        let ws = rustix::termios::tcgetwinsize(pty.master.get_ref().as_fd()).unwrap();
        assert_eq!((ws.ws_col, ws.ws_row), (100, 40));
        pty.write(vec![pty
            .control_char(SignalKind::Interrupt)
            .unwrap()
            .unwrap()])
            .await;
        let (_, exit) = collect_until(&mut rx, "\u{0}never").await;
        assert_eq!(exit, Some((None, Some(2))), "cat died of SIGINT from ^C");
    }

    fn state_of(pid: i32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit(')')
            .next()?
            .split_whitespace()
            .next()?
            .chars()
            .next()
    }

    /// R-ASY-5: a program that does not read, and a large paste. The host
    /// holds at most [`INPUT_QUEUE`] chunks plus what the kernel's terminal
    /// buffer takes; then the writer is refused and an awaited write
    /// stalls, which is what stops the host reading the link. When the
    /// program reads again, everything goes through, nothing dropped.
    #[tokio::test]
    async fn a_stopped_program_and_a_large_paste_keep_the_queue_bounded() {
        let (tx, mut rx) = mpsc::channel(64);
        // The shell stops itself before it reads, then counts what it is
        // given.
        let pty = spawn(
            &spec("/bin/sh", &["-c", "kill -STOP $$; exec wc -c"]),
            &SessionEnv::default(),
            80,
            24,
            tx,
        )
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while state_of(pty.pid()) != Some('T') {
            assert!(tokio::time::Instant::now() < deadline, "never stopped");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // No echo, so the terminal's output side never fills.
        let fd = pty.master.get_ref().as_fd();
        let mut t = rustix::termios::tcgetattr(fd).unwrap();
        t.local_modes.remove(rustix::termios::LocalModes::ECHO);
        rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &t).unwrap();
        let mut line = vec![b'x'; 79];
        line.push(b'\n');
        let chunk: Vec<u8> = line.repeat(51); // 4080 bytes, whole lines
        let paste = 8 << 20; // 8 MiB offered
        let mut accepted = 0usize;
        let mut refused = false;
        while accepted < paste {
            match pty.try_write(chunk.clone()) {
                Ok(()) => accepted += chunk.len(),
                Err(back) => {
                    assert_eq!(back, chunk, "the refused chunk comes back whole");
                    refused = true;
                    break;
                }
            }
            // Let the writer move what the kernel will take.
            tokio::task::yield_now().await;
        }
        assert!(
            refused,
            "8 MiB went into a stopped program without a refusal"
        );
        // The queue, the one chunk in the writer's hands, and the kernel's
        // terminal buffer (a flip-buffer limit of 640 KiB plus the line
        // discipline's 4 KiB on Linux): with headroom, under 1.1 MiB of the
        // 8 MiB offered.
        let bound = (INPUT_QUEUE + 1) * chunk.len() + (1 << 20);
        assert!(
            accepted <= bound,
            "{accepted} bytes held for a stopped program (bound {bound})"
        );
        // An awaited write stalls while the program is stopped.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), pty.write(chunk.clone()))
                .await
                .is_err(),
            "a write to a stopped program completed"
        );
        // The program reads again: the stalled write completes, then EOF.
        rustix::process::kill_process(pty.pid, rustix::process::Signal::CONT).unwrap();
        tokio::time::timeout(Duration::from_secs(10), pty.write(chunk.clone()))
            .await
            .expect("the write completes once the program reads");
        // Only this one: the timed-out `send` was cancelled before it had
        // room, so it took nothing. `send` is not cancel-safe, which is
        // why the host waits for room with `reserve` instead (run.rs).
        accepted += chunk.len();
        pty.write(vec![4]).await; // ^D on an empty line
        let mut out = String::new();
        let mut exit = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            match ev {
                PtyEvent::Output(b) => out.push_str(&String::from_utf8_lossy(&b)),
                PtyEvent::Exited { code, .. } => {
                    exit = Some(code);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(exit, Some(Some(0)), "{out:?}");
        assert_eq!(
            out.trim(),
            accepted.to_string(),
            "every byte arrived, none twice"
        );
    }

    #[tokio::test]
    async fn hangup_ends_the_process_group() {
        let (tx, mut rx) = mpsc::channel(64);
        let pty = spawn(
            &spec("/bin/sh", &["-c", "sleep 30 & sleep 30"]),
            &SessionEnv::default(),
            80,
            24,
            tx,
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        pty.hangup();
        let (_, exit) = collect_until(&mut rx, "\u{0}never").await;
        assert_eq!(exit.unwrap().1, Some(1), "SIGHUP");
    }
}
