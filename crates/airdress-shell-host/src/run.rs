//! `airdress shell host`: the foreground host (design §5.4, §7.1, §7.3).
//!
//! Started by the person, it takes the single-instance lock, enrolls on its
//! first run, prints what it is bound to, and then holds one channel to its
//! operator while it serves its sessions. Ctrl-C or `SIGTERM` stops it:
//! every attached client and the operator are told, every session is hung
//! up and killed after 10 seconds, and the channel is closed (FR-S14).
//! Nothing of it keeps running afterwards (D-17).

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;

use crate::binding::{Authorization, Binding};
use crate::channel::{self, hints::HintFile, LinkConfig, LinkEvent, LinkTimings};
use crate::host::{HostCore, HostFacts, Timings};
use crate::log_err::LogErr as _;
use crate::paths::Paths;

/// How to run the host.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub paths: Paths,
    /// The operator to enroll with on first run (`https://<fqdn>`).
    pub operator: Option<String>,
    /// The name this machine enrolls as (default: its hostname).
    pub name: Option<String>,
    /// A private CA to trust as well as the system's.
    pub ca_file: Option<PathBuf>,
    pub host_version: String,
    pub timings: Timings,
    pub link: LinkTimings,
}

/// The process's exit code when the operator revoked or unlinked the host.
pub const EXIT_REVOKED: i32 = 3;

/// Connecting to the operator.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// One ordinary request to the operator (the roster read), as opposed to
/// the channel's held long-poll.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// An HTTP client for the operator: rustls, a private CA if given, and no
/// request timeout on purpose: the long-poll holds a response open, and the
/// channel's own `idle` timing (`channel::Timing`) bounds a silent one. An
/// ordinary request sets [`REQUEST_TIMEOUT`] on itself.
pub fn http_client(ca_file: Option<&std::path::Path>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(concat!("airdress-shell-host/", env!("CARGO_PKG_VERSION")));
    if let Some(p) = ca_file {
        let pem = std::fs::read(p).with_context(|| format!("could not read {}", p.display()))?;
        for c in reqwest::Certificate::from_pem_bundle(&pem)? {
            b = b.add_root_certificate(c);
        }
    }
    Ok(b.build()?)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "shell host".into())
}

/// Run the host in the foreground until Ctrl-C or `SIGTERM` (a second
/// Ctrl-C kills what is left at once). Returns the exit code.
pub async fn run(opts: RunOptions) -> Result<i32> {
    use tokio::signal::unix::{signal, SignalKind};
    let (stop_tx, stop_rx) = mpsc::channel(4);
    // Made once, outside the loop: a `Signal` counts what arrives between
    // two `recv`s, where a `ctrl_c()` made afresh each pass would miss a
    // second Ctrl-C that came while the first was being handed on.
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    // Owned here (R-ASY-1): it ends when `run_until` returns.
    let mut signals = tokio::task::JoinSet::new();
    signals.spawn(async move {
        loop {
            tokio::select! {
                // cancel-safe: `Signal::recv` (tokio documents it so); a
                // signal that arrives meanwhile is kept for the next pass.
                r = int.recv() => if r.is_none() { break },
                // cancel-safe: as above.
                r = term.recv() => if r.is_none() { break },
            }
            if stop_tx.send(()).await.is_err() {
                break;
            }
        }
    });
    run_until(opts, stop_rx).await
}

/// Run the host until `stop` says so: the first message stops it in order,
/// a second ends what is left at once.
pub async fn run_until(opts: RunOptions, mut stop: mpsc::Receiver<()>) -> Result<i32> {
    let paths = opts.paths.clone();
    let root = crate::root::runs_as_root();
    if root {
        eprintln!("{}", crate::root::banner());
    }
    let profiles = crate::profiles::load(&paths).context(
        "the profile file was refused; nothing would be offered, so the host does not start",
    )?;
    let http = http_client(opts.ca_file.as_deref())?;
    let (binding, _lock) = match Binding::load(&paths)? {
        Some(b) => {
            if let Some(o) = &opts.operator {
                if o.trim_end_matches('/') != b.operator {
                    bail!(
                        "this host is bound to {}; binding it to another operator is a fresh \
                         enrollment (move {} aside first)",
                        b.operator,
                        paths.host_dir().display()
                    );
                }
            }
            let lock = crate::binding::lock(&paths, &b.airdress)?;
            (b, lock)
        }
        None => {
            let operator = opts.operator.clone().context(
                "this machine is not a shell host yet: run `airdress shell host --operator \
                 https://<your airdress>` to enroll it",
            )?;
            let lock = crate::binding::lock(&paths, &crate::binding::airdress_of(&operator)?)?;
            let name = opts.name.clone().unwrap_or_else(hostname);
            let mut err = std::io::stderr();
            let b = crate::enroll::enroll(&paths, &http, &operator, &name, &mut err).await?;
            (b, lock)
        }
    };
    if let Some(w) = Authorization::load(&paths).warning(std::time::SystemTime::now()) {
        eprintln!("{w}");
    }
    let shell = crate::binding::load_shell_key(&paths)?;
    eprintln!("{}", binding.describe(shell.public()));
    report_profiles(&profiles);
    // First-device trust (design §6.3): the person's devices, as the
    // operator lists them, wait here to be confirmed by fingerprint.
    match crate::roster::refresh(&paths, &http, &binding).await {
        Ok(_) => {
            if let Some(hint) = crate::trust::DeviceStore::load(&paths)
                .ok()
                .as_ref()
                .and_then(crate::roster::first_device_hint)
            {
                eprintln!("{hint}");
            }
        }
        Err(e) => eprintln!(
            "Could not read your devices from the operator ({e:#}); a device that connects is \
             listed instead."
        ),
    }

    let (out_tx, out_rx) = mpsc::channel(crate::host::OUT_QUEUE);
    let (pty_tx, mut pty_rx) = mpsc::channel(256);
    let events_tx = pty_tx.clone();
    let (probe_tx, mut probe_rx) = mpsc::channel(PROBE_QUEUE);
    let (link_tx, mut link_rx) = mpsc::channel(1024);
    let mut core = HostCore::new(
        paths.clone(),
        binding.clone(),
        profiles,
        out_tx,
        pty_tx,
        HostFacts {
            host_version: opts.host_version.clone(),
            autostart: crate::install::autostart_kind(),
            runs_as_root: root,
        },
        opts.timings.clone(),
    )?;
    core.probe_tx = Some(probe_tx);
    // The event socket for hooks inside terminal-driven harnesses (design
    // §9.4); without it their structured view is unavailable, nothing else.
    // The socket's guard owns its accept loop and connections (R-ASY-1);
    // it is dropped when this function returns.
    let events_socket = crate::structured::events::listen(&paths.host_dir(), events_tx);
    core.events_socket = events_socket.as_ref().map(|s| s.path.clone());
    // Spill from a previous run can never be read again (its key died with
    // that process); remove it.
    if let Err(e) = std::fs::remove_dir_all(paths.spill_dir()) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "removing the previous run's spill");
        }
    }
    let tls = if binding.operator.starts_with("https://") {
        Some(channel::tls_config(opts.ca_file.as_deref())?)
    } else {
        None
    };
    // The channel task, owned here (R-ASY-1) and joined within a bound at
    // the end; a panic in it is this function's error, not a ghost host.
    let mut link = tokio::task::JoinSet::new();
    link.spawn(channel::run(
        LinkConfig {
            origin: binding.operator.clone(),
            signer: Arc::new(binding.signer(&paths)?),
            operator_key: binding.operator_verifying_key()?,
            pref: core.profiles.host.transport,
            hints: HintFile::at(paths.hints()),
            http,
            tls,
            timings: opts.link.clone(),
        },
        out_rx,
        link_tx,
    ));

    let mut tick = tokio::time::interval(core.timings.tick);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_refusal: Option<String> = None;
    let mut code = 0;
    let mut warned_at = std::time::Instant::now();
    loop {
        // A program that is not reading holds its input here; until it
        // takes it the link is not read, so the operator, and the device
        // behind it, slow down (R-ASY-5). Bounded by `input_stall`.
        let stalled = core.stalled_input();
        let room = async {
            match &stalled {
                Some((_, input, _)) => input.reserve().await.ok(),
                None => std::future::pending().await,
            }
        };
        let give_up = async {
            match &stalled {
                Some((_, _, at)) => tokio::time::sleep_until(*at).await,
                None => std::future::pending().await,
            }
        };
        // What the channel has no room for waits in the outbox; until it
        // has gone, the sessions' output and the probes are not read, so
        // a slow link slows the programs (R-ASY-5). The link is still
        // read: the channel waits on that queue too.
        let backlogged = core.out.backlogged();
        let out_room = core.out.sender();
        let room_out = async {
            if backlogged {
                out_room.reserve().await.ok()
            } else {
                std::future::pending().await
            }
        };
        tokio::select! {
            // cancel-safe: `mpsc::Receiver::recv`. Not polled while a
            // session's input is stalled: that is what slows the sender.
            ev = link_rx.recv(), if stalled.is_none() => match ev {
                Some(LinkEvent::Up(t)) => {
                    eprintln!("Connected to {} ({}).", binding.airdress, t.as_str());
                    last_refusal = None;
                    core.on_connected();
                }
                Some(LinkEvent::Frame(f)) => core.on_frame(*f),
                Some(LinkEvent::Data { session, leg, record }) => core.on_data(session, leg, &record),
                Some(LinkEvent::Down { code: c, reason }) => {
                    tracing::info!(code = ?c, reason, "the channel ended; dialling again");
                    core.on_disconnected();
                }
                Some(LinkEvent::Refused(why)) => {
                    if last_refusal.as_deref() != Some(&why) {
                        eprintln!("The operator refused this host: {why}.{}", hint_for(&why));
                        last_refusal = Some(why);
                    }
                }
                Some(LinkEvent::Gone { code: c, reason }) => {
                    eprintln!("The operator ended this host ({c} {reason}): it was revoked or unlinked. Stopping.");
                    code = EXIT_REVOKED;
                    core.begin_stop();
                }
                None => break,
            },
            // cancel-safe: `Sender::reserve` takes nothing from the session's
            // queue; losing the race only loses the place in line. (A
            // `send(data)` here would drop `data` when another arm won.)
            permit = room, if stalled.is_some() => {
                if let Some((id, _, _)) = &stalled {
                    core.on_input_room(*id, permit);
                }
            }
            // cancel-safe: a sleep, made afresh from the stored deadline.
            () = give_up, if stalled.is_some() => {
                if let Some((id, _, _)) = &stalled {
                    core.on_input_stalled(*id);
                }
            }
            // cancel-safe: `Sender::reserve` takes nothing from the outbox;
            // the message moves only once the permit is in hand.
            permit = room_out, if backlogged => {
                // `None`: the channel is gone, and the link arm sees it end.
                if let Some(permit) = permit {
                    core.out.on_room(permit);
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`. Not polled while the
            // outbox is backlogged.
            Some((id, ev)) = pty_rx.recv(), if !backlogged => core.on_pty(id, ev),
            // cancel-safe: `mpsc::Receiver::recv`. As above.
            Some((id, hash, report)) = probe_rx.recv(), if !backlogged => core.on_probe(id, hash, report),
            // cancel-safe: `Interval::tick` (tokio's list).
            _ = tick.tick() => {
                core.tick();
                if warned_at.elapsed() >= Duration::from_secs(86_400) {
                    warned_at = std::time::Instant::now();
                    if let Some(w) = Authorization::load(&paths).warning(std::time::SystemTime::now()) {
                        eprintln!("{w}");
                    }
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`.
            Some(()) = stop.recv() => {
                if core.stopping() {
                    eprintln!("Stopping now.");
                    core.force_stop();
                    break;
                }
                eprintln!("Stopping: every session is told, hung up, and killed after {} s.", core.timings.kill_after.as_secs());
                core.begin_stop();
            }
        }
        if core.stopping() && core.stop_finished() {
            break;
        }
    }
    core.begin_stop();
    while !core.stop_finished() {
        let backlogged = core.out.backlogged();
        let out_room = core.out.sender();
        tokio::select! {
            // cancel-safe: `Sender::reserve`, as in the loop above.
            permit = out_room.reserve(), if backlogged => {
                if let Ok(permit) = permit {
                    core.out.on_room(permit);
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`.
            Some((id, ev)) = pty_rx.recv(), if !backlogged => core.on_pty(id, ev),
            // cancel-safe: a sleep.
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
    // The clients' last words, then the close, within the drain bound.
    core.close_channel();
    core.out.flush(LINK_DRAIN).await;
    drop(core);
    drop(events_socket);
    // The channel ends on the close; it is joined within a bound, then
    // aborted (dropping the set). A panic in it is an error.
    let joined = tokio::time::timeout(LINK_DRAIN, link.join_next()).await;
    // The last lines are best effort: nothing is left to tell if they fail.
    std::io::stderr().flush().log_debug("flushing stderr");
    if let Ok(Some(Err(e))) = joined {
        if e.is_panic() {
            bail!("the operator channel failed: {e}");
        }
    }
    Ok(code)
}

/// Harness probe reports waiting to be read (R-ASY-5): one per profile
/// being probed at most, and a probe waits for room past it.
pub const PROBE_QUEUE: usize = 16;

/// How long a stopping host waits for its channel to close in order.
pub const LINK_DRAIN: Duration = Duration::from_secs(3);

fn hint_for(code: &str) -> &'static str {
    match code {
        "machine_authorization_expired" => {
            " Run `airdress shell host reauth` and approve it again."
        }
        "not_enabled" => " Shells are switched off on this operator.",
        "shell_host_disabled" => " The host is disabled; its owner can enable it again.",
        _ => "",
    }
}

fn report_profiles(p: &crate::profiles::ProfileFile) {
    if p.profiles.is_empty() {
        eprintln!(
            "No profiles yet: add one with `airdress shell profile add --id <id> --program <path>`."
        );
        return;
    }
    eprintln!(
        "Profiles this host offers (at most {} sessions at once):",
        p.host.max_sessions
    );
    for prof in &p.profiles {
        eprintln!("  {:<20} {:<30} {}", prof.id, prof.label, prof.state_text());
    }
}
