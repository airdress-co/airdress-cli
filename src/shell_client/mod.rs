//! `airdress shell` — the client half of shells: a terminal on your own
//! machine from this one, through your airdress, end to end (SPEC-137,
//! design §5.2, §6, §10.2).
//!
//! * [`device`] — the CLI as a delegation-only human device (task D.1);
//! * [`store`] — where its keys live (the Secret Service, else 0600 files);
//! * [`api`] — the operator's shell routes;
//! * [`leg`] — one leg's transport;
//! * [`session`] — the end-to-end channel of one session, without I/O;
//! * [`run`] — one attached session: raw passthrough, take-over, detach,
//!   close and resume (tasks D.3, D.4);
//! * [`pins`] — the host key, shown at first use and pinned (D-34);
//! * [`terminal`] — raw mode, the window size, the escape key;
//! * [`recordings`] — `recordings ls|play` (task D.5).
//!
//! **No step-up on Linux (D-30).** An enrolled CLI opens, reattaches and
//! resumes without a prompt, like an SSH key without a passphrase; the
//! accepted risk is written in `docs/shells.md`. What stays is the terminal
//! check (FR-C2): no open or attach unless stdin and stdout are terminals.

pub mod api;
pub mod device;
pub mod leg;
pub mod pins;
pub mod recordings;
pub mod run;
pub mod session;
pub mod store;
pub mod terminal;

use std::io::{BufRead as _, Write as _};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use serde_json::json;
use tokio::sync::mpsc;

use airdress_shell_proto::keys::fingerprint;

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::log_err::LogErr as _;
use crate::profile::storage;
use crate::ui;

use api::{HostView, ShellApi};
use pins::{PinCheck, Pins};
use run::{Command, Conn, Front, Outcome};
use session::{ClientSession, Target};
use store::{CliDevice, Store};

/// `airdress shell [profile] [--machine <name>]`, and its verbs.
#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ShellArgs {
    #[command(subcommand)]
    pub command: Option<ShellCommands>,
    /// The profile to open, as the host lists it (`airdress shell ls`).
    /// Without one: the running sessions and the profiles, to pick from.
    pub profile: Option<String>,
    /// The shell host to use, by name. Needed only when you have several.
    #[arg(long, short = 'm', value_name = "NAME")]
    pub machine: Option<String>,
    /// Speak the session's messages as JSON lines on stdin and stdout, for
    /// the editor. Not for people.
    #[arg(long)]
    pub json_proto: bool,
}

#[derive(Subcommand, Debug)]
pub enum ShellCommands {
    /// Your shell hosts, their profiles, and the sessions running on them.
    Ls,
    /// Attach to a running session and take input (the other device
    /// becomes a viewer and is told).
    Attach {
        /// The session id (`airdress shell ls`).
        session: String,
        /// Watch without taking input.
        #[arg(long)]
        view: bool,
        /// JSON lines on stdio, for the editor.
        #[arg(long)]
        json_proto: bool,
    },
    /// Close a session: its program is sent SIGHUP, then SIGKILL.
    Close {
        /// The session id.
        session: String,
        /// Do not ask.
        #[arg(short, long)]
        yes: bool,
    },
    /// Recordings of your sessions, sealed to your devices.
    Recordings {
        #[command(subcommand)]
        command: RecordingsCommands,
    },
    /// This CLI as a device of your airdress.
    Device {
        #[command(subcommand)]
        command: DeviceCommands,
    },
    /// Run this machine as one of your shell hosts, in the foreground
    /// (`--install` for a user unit). Enrolls it on first run.
    Host(crate::shell_host::HostArgs),
    /// The profiles this machine offers, in ~/.config/airdress/shells.toml.
    /// Run on the host itself; nothing over the network can change them.
    Profile {
        #[command(subcommand)]
        command: crate::shell_host::ProfileCommands,
    },
    /// For an editor plugin's hooks: hand one hook's JSON (on stdin) to this
    /// machine's shell host. Does nothing outside a shell session. Not for
    /// people.
    #[command(hide = true)]
    Events,
    /// Pin a host's new key, with the fingerprint `airdress shell host`
    /// printed on that machine. Only after a "HOST KEY CHANGED" stop.
    Repin {
        /// The host's name.
        host: String,
        /// `SHA256:…`, as the host printed it.
        fingerprint: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RecordingsCommands {
    /// List a host's recordings (through a running session on it).
    Ls {
        /// The shell host, by name. Needed only when you have several.
        #[arg(long, short = 'm', value_name = "NAME")]
        machine: Option<String>,
        /// The running session to go through (default: the first).
        #[arg(long)]
        session: Option<String>,
    },
    /// Replay a recording here, at its own pace.
    Play {
        /// The recording (a session id), as `recordings ls` prints it.
        recording: Option<String>,
        /// The shell host, by name. Needed only when you have several.
        #[arg(long, short = 'm', value_name = "NAME")]
        machine: Option<String>,
        /// The running session to go through (default: the first).
        #[arg(long)]
        session: Option<String>,
        /// Read a segment file on this machine instead (on the host).
        #[arg(long, value_name = "PATH", conflicts_with = "recording")]
        file: Option<std::path::PathBuf>,
        /// Playback speed.
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Longest pause, in seconds.
        #[arg(long, default_value_t = 2.0)]
        max_idle: f64,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeviceCommands {
    /// Ask to join your airdress as a CLI device; approve it on a phone.
    Join {
        /// What the phone is shown (default "airdress CLI on <host>").
        #[arg(long)]
        label: Option<String>,
        /// Minutes to wait for the approval.
        #[arg(long, default_value_t = 10)]
        wait_minutes: u64,
    },
    /// Whether this CLI is a device, and where its keys are.
    Status,
    /// Forget this CLI's device here. Revoke it from a phone as well.
    Forget {
        #[arg(short, long)]
        yes: bool,
    },
}

/// What every verb shares.
#[derive(Debug)]
pub struct RunArgs<'a> {
    pub auth_profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

#[derive(Debug)]
struct Ctx {
    hub: HubClient,
    fqdn: String,
    base: String,
    store: Store,
}

async fn context(args: &RunArgs<'_>) -> Result<Ctx> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.auth_profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }
    let fqdn = hub.resolve_fqdn(&resolved.name).await?;
    let base = match args.operator_url {
        Some(u) => u.trim_end_matches('/').to_owned(),
        None => format!("https://{}", fqdn.trim_matches('/')),
    };
    let store = Store::for_airdress(paths, &fqdn)?;
    Ok(Ctx {
        hub,
        fqdn,
        base,
        store,
    })
}

fn ask(question: &str) -> Result<String> {
    eprint!("{question} ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// A question asked inside an interactive shell flow, whose callers have
/// already required a terminal: only a person answers it.
fn at_terminal() -> ui::Confirm {
    ui::Confirm {
        yes: false,
        json: false,
        stdin_is_terminal: true,
        yes_allowed: false,
    }
}

fn say(text: &str) {
    eprintln!("{text}");
}

/// The CLI's device for this airdress, joining first when it has none and a
/// person is at the terminal (FR-C2).
async fn device(ctx: &Ctx, interactive: bool) -> Result<CliDevice> {
    if let Some(mut dev) = ctx.store.load()? {
        device::register_keys(&ctx.store, &mut dev, &ctx.base).await?;
        return Ok(dev);
    }
    if !interactive {
        return Err(crate::exit::Failure::new(
            crate::exit::Exit::ConfirmationRequired,
            "confirmation_required",
            format!("this CLI is not a device of {} yet", ctx.fqdn),
        )
        .with_hint("run `airdress shell device join` in a terminal")
        .into());
    }
    ui::confirm(
        &format!(
            "This CLI is not a device of {} yet. Ask to join (a phone approves it)?",
            ctx.fqdn
        ),
        at_terminal(),
    )?;
    join(ctx, device::default_label(), Duration::from_secs(600)).await
}

async fn join(ctx: &Ctx, label: String, wait: Duration) -> Result<CliDevice> {
    let dev = device::join(
        &ctx.store,
        device::JoinPlan {
            operator: &ctx.base,
            airdress: &ctx.fqdn,
            hub: ctx.hub.endpoint(),
            account_bearer: ctx.hub.bearer(),
            label,
            wait,
        },
        &say,
    )
    .await?;
    say(&format!(
        "Joined. This CLI is device {} of {}.",
        dev.record.enrollment_id, ctx.fqdn
    ));
    Ok(dev)
}

fn pick_host<'a>(hosts: &'a [HostView], name: Option<&str>) -> Result<&'a HostView> {
    if let Some(n) = name {
        return hosts
            .iter()
            .find(|h| h.name == n)
            .with_context(|| format!("no shell host named {n:?} (`airdress shell ls`)"));
    }
    match hosts {
        [] => bail!(
            "you have no shell hosts. Start one on your machine with `airdress shell host`, \
             and approve it"
        ),
        [one] => Ok(one),
        many => {
            let ready: Vec<&HostView> = many.iter().filter(|h| h.ready).collect();
            if let [one] = ready.as_slice() {
                return Ok(one);
            }
            bail!(
                "you have several shell hosts; name one with --machine: {}",
                many.iter()
                    .map(|h| h.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// The pinned key of `host`, asking at first use (D-34). `interactive`
/// false refuses a first use rather than pin silently.
fn pinned_key(ctx: &Ctx, host: &HostView, interactive: bool) -> Result<[u8; 32]> {
    let reported = host
        .shell_key_public
        .as_deref()
        .and_then(pins::decode_key)
        .with_context(|| {
            format!(
                "{} has not reported its host key yet (is `airdress shell host` running?)",
                host.name
            )
        })?;
    let machine = host.machine.as_deref().unwrap_or_default();
    let mut pins = Pins::load(&ctx.store.pins_path())?;
    match pins.check(&host.name, &reported)? {
        PinCheck::Pinned(k) => Ok(k),
        PinCheck::Changed { pinned, reported } => {
            bail!(
                "{}",
                pins::changed_key_message(&host.name, &pinned, &reported)
            )
        }
        PinCheck::FirstUse { key, fingerprint } => {
            if let Some(claimed) = host.shell_key.as_deref() {
                if claimed != fingerprint {
                    bail!(
                        "{} reports a fingerprint ({claimed}) that is not its key's ({fingerprint}); \
                         not connecting",
                        host.name
                    );
                }
            }
            if !interactive {
                bail!(
                    "first connection to {}: its host key must be confirmed in a terminal \
                     first (`airdress shell --machine {}`)",
                    host.name,
                    host.name
                );
            }
            say(&pins::first_use_message(&host.name, &fingerprint));
            // Only a person comparing fingerprints answers this; no flag does.
            ui::confirm("Does it match?", at_terminal())?;
            pins.pin(&host.name, machine, &key);
            pins.save()?;
            Ok(key)
        }
    }
}

fn target(
    ctx: &Ctx,
    dev: &CliDevice,
    host: &HostView,
    key: [u8; 32],
    profile: &str,
) -> Result<Target> {
    let machine = host.machine.clone().with_context(|| {
        format!(
            "the operator does not report {}'s machine id, which the end-to-end handshake binds; \
             it needs a newer operator",
            host.name
        )
    })?;
    Ok(Target {
        airdress: ctx.fqdn.clone(),
        machine,
        host_static: key,
        profile: profile.to_owned(),
        device: dev.record.enrollment_id.clone(),
    })
}

#[derive(Debug)]
enum Choice {
    Open(String),
    Attach(String, String),
}

fn choose(host: &HostView, profile: Option<&str>, interactive: bool) -> Result<Choice> {
    if let Some(p) = profile {
        if !host.profiles.iter().any(|x| x.id == p) {
            bail!(
                "{} has no profile {p:?}; it has: {}",
                host.name,
                host.profiles
                    .iter()
                    .map(|p| p.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(Choice::Open(p.to_owned()));
    }
    let ready: Vec<_> = host
        .profiles
        .iter()
        .filter(|p| p.state == "ready")
        .collect();
    if host.sessions.is_empty() {
        if let [one] = ready.as_slice() {
            return Ok(Choice::Open(one.id.clone()));
        }
    }
    if !interactive {
        bail!("name a profile, or a session with `airdress shell attach <session>`");
    }
    let mut items: Vec<(String, Choice)> = Vec::new();
    for s in &host.sessions {
        items.push((
            format!(
                "attach  {}  ({}, {}, {} attached)",
                s.id, s.profile, s.state, s.attached
            ),
            Choice::Attach(s.id.clone(), s.profile.clone()),
        ));
    }
    for p in &ready {
        items.push((
            format!("open    {}  ({})", p.id, p.label),
            Choice::Open(p.id.clone()),
        ));
    }
    if items.is_empty() {
        bail!("{} has no ready profile and no running session", host.name);
    }
    eprintln!("{}:", host.name);
    for (i, (label, _)) in items.iter().enumerate() {
        eprintln!("  {}. {label}", i + 1);
    }
    let n: usize = ask("Which? [1]")?.parse().unwrap_or(1);
    if n == 0 || n > items.len() {
        bail!("no such choice");
    }
    Ok(items.swap_remove(n - 1).1)
}

fn root_warning(host: &HostView) {
    if host.runs_as_root {
        say(&format!(
            "WARNING: {} runs its sessions as root. Anything typed there runs as root.",
            host.name
        ));
    }
}

/// Run `airdress shell …`. Returns the process exit code.
pub async fn run(args: ShellArgs, run_args: RunArgs<'_>) -> Result<i32> {
    match args.command {
        // The host's own commands: local to this machine, no sign-in.
        Some(ShellCommands::Host(h)) => crate::shell_host::run_host(h).await,
        Some(ShellCommands::Profile { command }) => crate::shell_host::run_profile(command),
        // Local, silent, and never in the way: a hook of ours exits 0.
        Some(ShellCommands::Events) => Ok(airdress_shell_host::structured::events::hook_main(
            &mut std::io::stdin(),
            &mut std::io::stdout(),
            &|k| std::env::var(k).ok(),
        )),
        None => {
            let interactive = terminal::both_are_terminals();
            if !args.json_proto && !interactive {
                bail!("`airdress shell` needs a terminal on stdin and stdout");
            }
            let ctx = context(&run_args).await?;
            let dev = device(&ctx, interactive && !args.json_proto).await?;
            let api = ShellApi::new(&ctx.base, &dev.token)?;
            let hosts = api.overview().await?;
            let host = pick_host(&hosts, args.machine.as_deref())?;
            let key = pinned_key(&ctx, host, interactive && !args.json_proto)?;
            let choice = choose(
                host,
                args.profile.as_deref(),
                interactive && !args.json_proto,
            )?;
            root_warning(host);
            let size = terminal::size();
            let conn = match choice {
                Choice::Open(profile) => {
                    let cs = ClientSession::new(
                        target(&ctx, &dev, host, key, &profile)?,
                        dev.shell.clone(),
                        &uuid::Uuid::new_v4().to_string(),
                    );
                    Conn::open(api, &host.name, cs, size).await?
                }
                Choice::Attach(session, profile) => {
                    let cs = ClientSession::new(
                        target(&ctx, &dev, host, key, &profile)?,
                        dev.shell.clone(),
                        &session,
                    );
                    Conn::attach(api, &host.name, cs, size, true).await?
                }
            };
            drive(conn, args.json_proto).await
        }
        Some(ShellCommands::Attach {
            session,
            view,
            json_proto,
        }) => {
            let interactive = terminal::both_are_terminals();
            if !json_proto && !interactive {
                bail!("`airdress shell attach` needs a terminal on stdin and stdout");
            }
            let ctx = context(&run_args).await?;
            let dev = device(&ctx, interactive && !json_proto).await?;
            let api = ShellApi::new(&ctx.base, &dev.token)?;
            let hosts = api.overview().await?;
            let (host, s) = hosts
                .iter()
                .find_map(|h| h.sessions.iter().find(|s| s.id == session).map(|s| (h, s)))
                .with_context(|| format!("no running session {session} on your hosts"))?;
            let key = pinned_key(&ctx, host, interactive && !json_proto)?;
            root_warning(host);
            let cs = ClientSession::new(
                target(&ctx, &dev, host, key, &s.profile)?,
                dev.shell.clone(),
                &session,
            );
            let conn = Conn::attach(api, &host.name, cs, terminal::size(), !view).await?;
            drive(conn, json_proto).await
        }
        Some(ShellCommands::Ls) => {
            let ctx = context(&run_args).await?;
            let dev = device(&ctx, false).await?;
            let hosts = ShellApi::new(&ctx.base, &dev.token)?.overview().await?;
            if run_args.json {
                let pins = Pins::load(&ctx.store.pins_path())?;
                let v: Vec<_> = hosts
                    .iter()
                    .map(|h| {
                        json!({
                            "name": h.name, "ready": h.ready, "connected": h.connected,
                            "runsAsRoot": h.runs_as_root, "shellKey": h.shell_key,
                            "pinned": pins.get(&h.name).map(|p| p.fingerprint.clone()),
                            "profiles": h.profiles.iter().map(|p| json!({
                                "id": p.id, "label": p.label, "kind": p.kind, "state": p.state,
                                "record": p.record})).collect::<Vec<_>>(),
                            "sessions": h.sessions.iter().map(|s| json!({
                                "id": s.id, "profile": s.profile, "state": s.state,
                                "attached": s.attached, "typist": s.typist,
                                "openedAt": s.opened_at})).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json!({ "hosts": v }))?);
            } else if hosts.is_empty() {
                ui::say("no shell hosts — start `airdress shell host` on your machine");
            } else {
                for h in &hosts {
                    let state = if h.ready {
                        "ready"
                    } else if h.connected {
                        "connected"
                    } else {
                        "offline"
                    };
                    println!(
                        "{}  {state}{}",
                        h.name,
                        if h.runs_as_root {
                            "  (runs as root)"
                        } else {
                            ""
                        }
                    );
                    for p in &h.profiles {
                        println!("  profile  {:<16} {:<10} {}", p.id, p.state, p.label);
                    }
                    for s in &h.sessions {
                        println!(
                            "  session  {}  {:<12} {:<9} {} attached",
                            s.id, s.profile, s.state, s.attached
                        );
                    }
                }
            }
            Ok(0)
        }
        Some(ShellCommands::Close { session, yes: y }) => {
            let ctx = context(&run_args).await?;
            let dev = device(&ctx, false).await?;
            ui::confirm(
                &format!("Close session {session}? Its program is ended."),
                ui::Confirm::new(y, run_args.json),
            )?;
            ShellApi::new(&ctx.base, &dev.token)?
                .close(&session)
                .await?;
            ui::ok(format!("closing {session}"));
            Ok(0)
        }
        Some(ShellCommands::Repin { host, fingerprint }) => {
            let ctx = context(&run_args).await?;
            let dev = device(&ctx, false).await?;
            let hosts = ShellApi::new(&ctx.base, &dev.token)?.overview().await?;
            let h = pick_host(&hosts, Some(&host))?;
            let reported = h
                .shell_key_public
                .as_deref()
                .and_then(pins::decode_key)
                .context("that host reports no key")?;
            let mut pins = Pins::load(&ctx.store.pins_path())?;
            pins.repin(
                &host,
                h.machine.as_deref().unwrap_or_default(),
                &reported,
                &fingerprint,
            )?;
            pins.save()?;
            ui::ok(format!("pinned {host} at {fingerprint}"));
            Ok(0)
        }
        Some(ShellCommands::Device { command }) => {
            let ctx = context(&run_args).await?;
            match command {
                DeviceCommands::Join {
                    label,
                    wait_minutes,
                } => {
                    if ctx.store.load()?.is_some() {
                        bail!(
                            "this CLI is already a device of {}; `airdress shell device forget` first",
                            ctx.fqdn
                        );
                    }
                    join(
                        &ctx,
                        label.unwrap_or_else(device::default_label),
                        Duration::from_secs(wait_minutes.max(1) * 60),
                    )
                    .await?;
                }
                DeviceCommands::Status => match ctx.store.load()? {
                    None => ui::say(format!("not a device of {}", ctx.fqdn)),
                    Some(d) => {
                        let shell = d.shell.public();
                        if run_args.json {
                            println!(
                                "{}",
                                json!({
                                    "airdress": ctx.fqdn, "device": d.record.enrollment_id,
                                    "label": d.record.label, "kind": device::DEVICE_KIND,
                                    "presenceAlg": "none",
                                    "shellKey": fingerprint(shell),
                                    "keysRegistered": d.record.keys_registered,
                                    "secretsAt": d.record.secrets_at,
                                })
                            );
                        } else {
                            println!("device      {}", d.record.enrollment_id);
                            println!("label       {}", d.record.label);
                            println!("kind        cli, no presence key (Linux)");
                            println!("shell key   {}", fingerprint(shell));
                            println!(
                                "registered  {}",
                                if d.record.keys_registered {
                                    "yes"
                                } else {
                                    "no"
                                }
                            );
                            println!(
                                "keys in     {}",
                                match d.record.secrets_at {
                                    store::SecretsAt::Keyring => "the Secret Service".to_owned(),
                                    store::SecretsAt::File =>
                                        format!("{} (0600)", ctx.store.dir().display()),
                                }
                            );
                        }
                    }
                },
                DeviceCommands::Forget { yes: y } => {
                    ui::confirm(
                        "Forget this CLI's device here? Revoke it from a phone too.",
                        ui::Confirm::new(y, run_args.json),
                    )?;
                    if ctx.store.forget()? {
                        ui::ok("forgotten here; revoke the device from a phone as well");
                    } else {
                        ui::say("this CLI was not a device here");
                    }
                }
            }
            Ok(0)
        }
        Some(ShellCommands::Recordings { command }) => recordings_cmd(command, &run_args).await,
    }
}

async fn recordings_cmd(command: RecordingsCommands, run_args: &RunArgs<'_>) -> Result<i32> {
    let (machine, session, play) = match command {
        RecordingsCommands::Ls { machine, session } => (machine, session, None),
        RecordingsCommands::Play {
            recording,
            machine,
            session,
            file,
            speed,
            max_idle,
        } => {
            let max_idle = Duration::from_secs_f64(max_idle.max(0.0));
            if let Some(path) = file {
                let ctx = context(run_args).await?;
                let dev = ctx
                    .store
                    .load()?
                    .context("this CLI is not a device here; it cannot open recordings")?;
                let bytes =
                    std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
                let (data, complete) =
                    recordings::open_file(&bytes, &dev.record.enrollment_id, dev.shell.secret())?;
                let frames = recordings::parse_cast(&data)?;
                recordings::play(&frames, &mut std::io::stdout(), speed, max_idle).await?;
                if !complete {
                    say("(the segment ends early: it was cut short, or is still being written)");
                }
                return Ok(0);
            }
            let rec = recording.context("name a recording (`recordings ls`) or --file")?;
            (machine, session, Some((rec, speed, max_idle)))
        }
    };
    let ctx = context(run_args).await?;
    let dev = device(&ctx, false).await?;
    let api = ShellApi::new(&ctx.base, &dev.token)?;
    let hosts = api.overview().await?;
    let host = pick_host(&hosts, machine.as_deref())?;
    let key = pinned_key(&ctx, host, false)?;
    let s = match session {
        Some(id) => host.sessions.iter().find(|s| s.id == id),
        None => host.sessions.first(),
    }
    .with_context(|| {
        format!(
            "recordings are fetched through a running session on {}, and it has none; \
             open one with `airdress shell --machine {}`",
            host.name, host.name
        )
    })?;
    let cs = ClientSession::new(
        target(&ctx, &dev, host, key, &s.profile)?,
        dev.shell.clone(),
        &s.id,
    );
    let mut conn = Conn::attach(api, &host.name, cs, (80, 24), false).await?;
    let listing = recordings::list(&mut conn).await?;
    match play {
        None => {
            if run_args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "recordings": listing }))?
                );
            } else if listing.is_empty() {
                ui::say(format!("no recordings on {}", host.name));
            } else {
                for r in &listing {
                    println!(
                        "{}  {:<12} {}  {} segment(s)",
                        r.recording, r.profile, r.started_at, r.segments
                    );
                }
            }
        }
        Some((rec, speed, max_idle)) => {
            let info = listing
                .iter()
                .find(|r| r.recording == rec)
                .with_context(|| format!("{} has no recording {rec}", host.name))?;
            let (data, complete) = recordings::fetch(
                &mut conn,
                &rec,
                info.segments,
                &dev.record.enrollment_id,
                dev.shell.secret(),
            )
            .await?;
            drop(conn);
            let frames = recordings::parse_cast(&data)?;
            recordings::play(&frames, &mut std::io::stdout(), speed, max_idle).await?;
            if !complete {
                say("(the recording ends early: cut short, or still being written)");
            }
        }
    }
    Ok(0)
}

/// How many `--json-proto` input errors wait to be written (R-ASY-5); past
/// it the reading thread waits for the writer.
const JSON_ERROR_QUEUE: usize = 64;
/// How long the helper tasks of one session get to finish once it ends.
const DRIVE_DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// Raw mode, the readers and the signals around one session. The helper
/// tasks (signal watchers, the error writer) are owned here (R-ASY-1) and
/// ended when the session loop returns; one that panicked is an error.
async fn drive(conn: Conn, json_proto: bool) -> Result<i32> {
    let (tx, rx) = mpsc::channel(256);
    let mut tasks = tokio::task::JoinSet::new();
    let mut front = if json_proto {
        let (etx, mut erx) = mpsc::channel::<String>(JSON_ERROR_QUEUE);
        run::spawn_json_reader(tx.clone(), etx);
        tasks.spawn(async move {
            while let Some(e) = erx.recv().await {
                println!(
                    "{}",
                    json!({ "type": "error", "code": "invalid_input", "message": e })
                );
            }
        });
        Front::json(Box::new(std::io::stdout()))
    } else {
        run::spawn_terminal_reader(tx.clone());
        Front::terminal(Box::new(std::io::stdout()))
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let txs = tx.clone();
        tasks.spawn(async move {
            let Ok(mut winch) = signal(SignalKind::window_change()) else {
                return;
            };
            while winch.recv().await.is_some() {
                let (c, r) = terminal::size();
                if txs.send(Command::Resize(c, r)).await.is_err() {
                    return;
                }
            }
        });
        for kind in [SignalKind::terminate(), SignalKind::hangup()] {
            let txs = tx.clone();
            tasks.spawn(async move {
                if let Ok(mut s) = signal(kind) {
                    if s.recv().await.is_some() {
                        txs.send(Command::Detach)
                            .await
                            .log_debug("asking the session to detach");
                    }
                }
            });
        }
    }
    let outcome = drive_session(conn, json_proto, &mut front, rx).await;
    drop(tx);
    // The session is over: end the helpers, then join them within a bound.
    tasks.abort_all();
    let joined = tokio::time::timeout(DRIVE_DRAIN, async {
        let mut panicked = None;
        while let Some(r) = tasks.join_next().await {
            if let Err(e) = r {
                if e.is_panic() {
                    panicked.get_or_insert_with(|| e.to_string());
                }
            }
        }
        panicked
    })
    .await;
    if let Ok(Some(p)) = joined {
        anyhow::bail!("a helper of this session failed: {p}");
    }
    outcome
}

async fn drive_session(
    conn: Conn,
    json_proto: bool,
    front: &mut Front,
    rx: mpsc::Receiver<Command>,
) -> Result<i32> {
    let session = conn.cs.session().to_owned();
    let raw = if json_proto {
        None
    } else {
        Some(terminal::RawMode::enter().context("put the terminal in raw mode")?)
    };
    let outcome = run::run(conn, front, rx).await;
    drop(raw);
    let outcome = outcome?;
    if !json_proto {
        match &outcome {
            Outcome::Detached => say(&format!(
                "\r\ndetached; the session keeps running. Back to it: airdress shell attach {session}"
            )),
            Outcome::Exited { code, signal } => say(&format!(
                "\r\nthe program exited{}",
                match (code, signal) {
                    (Some(c), _) => format!(" with {c}"),
                    (None, Some(s)) => format!(" on signal {s}"),
                    _ => String::new(),
                }
            )),
            Outcome::Ended(why) => say(&format!("\r\nsession ended: {why}")),
        }
    } else {
        println!(
            "{}",
            json!({ "type": "ended", "outcome": format!("{outcome:?}") })
        );
    }
    Ok(outcome.exit_code())
}
