//! `airdress shell host` and `airdress shell profile`: the host role, run on
//! the person's own machine. Thin: everything lives in the
//! `airdress-shell-host` crate, so the host can be reasoned about apart from
//! the client.
//!
//! The host is Unix only (pseudo-terminals, Unix sockets, file modes). The
//! subcommands parse everywhere, so `--help` is the same on every platform,
//! and on Windows they say they are unsupported instead of doing anything.

#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use airdress_shell_host::paths::Paths;
#[cfg(unix)]
use airdress_shell_host::profiles::ProfileEdit;
use anyhow::Result;
use clap::{Args, Subcommand};

/// `airdress shell host`.
#[derive(Args, Debug)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: Option<HostCommands>,
    /// The operator to enroll with on first run: `https://<your airdress>`.
    #[arg(long, value_name = "URL")]
    pub operator: Option<String>,
    /// The name this machine enrolls as (default: its hostname).
    #[arg(long)]
    pub name: Option<String>,
    /// Start the host with your user session: write a systemd user unit and
    /// enable it. Nothing system-wide; `--uninstall` removes it.
    #[arg(long, conflicts_with = "uninstall")]
    pub install: bool,
    /// Stop and remove what `--install` wrote.
    #[arg(long)]
    pub uninstall: bool,
}

#[derive(Subcommand, Debug)]
pub enum HostCommands {
    /// What this host is bound to, its keys, profiles, devices and state.
    Status,
    /// Trust a device that asked before it was introduced, by the
    /// fingerprint this host printed. At this machine's terminal only.
    Trust {
        /// `SHA256:…`, as printed when the device asked.
        fingerprint: String,
        /// The device's kind (`phone`, `cli`); default: what it said it is.
        #[arg(long)]
        kind: Option<String>,
    },
    /// The device keys this host trusts, was introduced to, or revoked.
    Devices,
    /// Recordings kept on this machine.
    Recordings {
        #[command(subcommand)]
        command: HostRecordings,
    },
    /// Renew this host's approval before it lapses.
    Reauth,
}

#[derive(Subcommand, Debug)]
pub enum HostRecordings {
    /// List them.
    List,
    /// Remove those past their retention now.
    Prune,
}

/// The fields `profile add` and `profile edit` set.
#[derive(Args, Debug, Default)]
pub struct ProfileFields {
    /// What a person sees.
    #[arg(long)]
    pub label: Option<String>,
    /// `shell` or `harness:<name>`.
    #[arg(long)]
    pub kind: Option<String>,
    /// The program; a bare name is resolved on PATH once and written back.
    #[arg(long)]
    pub program: Option<String>,
    /// One argument; repeat for more (replaces the list on edit).
    #[arg(long = "arg", value_name = "ARG", allow_hyphen_values = true)]
    pub args: Vec<String>,
    /// The working directory (`~` is your home).
    #[arg(long)]
    pub cwd: Option<String>,
    /// An environment variable to pass through from the host; repeat.
    #[arg(long = "env-allow", value_name = "NAME")]
    pub env_allow: Vec<String>,
    /// A structured adapter: acp, opencode-server, codex-app-server, claude-plugin.
    #[arg(long)]
    pub structured: Option<String>,
    /// End a session nobody is attached to after this long (24h).
    #[arg(long)]
    pub idle_timeout: Option<String>,
    /// End any session after this long (7d).
    #[arg(long)]
    pub max_lifetime: Option<String>,
    /// Record sessions on this machine, sealed to your devices.
    #[arg(long)]
    pub record: Option<bool>,
    /// Push "needs you" and "done".
    #[arg(long)]
    pub notify: Option<bool>,
    /// Push when the terminal rings its bell.
    #[arg(long)]
    pub notify_bell: Option<bool>,
}

#[cfg(unix)]
impl ProfileFields {
    fn edit(&self) -> ProfileEdit {
        ProfileEdit {
            label: self.label.clone(),
            kind: self.kind.clone(),
            program: self.program.clone(),
            args: (!self.args.is_empty()).then(|| self.args.clone()),
            cwd: self.cwd.clone(),
            env_allow: (!self.env_allow.is_empty()).then(|| self.env_allow.clone()),
            structured: self.structured.clone(),
            idle_timeout: self.idle_timeout.clone(),
            max_lifetime: self.max_lifetime.clone(),
            record: self.record,
            notify: self.notify,
            notify_bell: self.notify_bell,
        }
    }
}

/// `airdress shell profile`.
#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// Add a profile.
    Add {
        /// Its id: a-z, 0-9 and -.
        #[arg(long)]
        id: String,
        #[command(flatten)]
        fields: ProfileFields,
    },
    /// Change a profile.
    Edit {
        id: String,
        #[command(flatten)]
        fields: ProfileFields,
    },
    /// Remove a profile.
    Remove { id: String },
    /// List the profiles and whether each can open.
    List,
    /// Show one profile as written.
    Show { id: String },
    /// Validate the file, resolving bare program names once.
    Check,
}

/// Run `airdress shell host …`.
#[cfg(unix)]
pub async fn run_host(h: HostArgs) -> Result<i32> {
    let paths = Paths::from_env()?;
    let ca = crate::http::configured_ca_file();
    let mut out = std::io::stdout();
    match h.command {
        Some(HostCommands::Status) => airdress_shell_host::commands::status(&paths, &mut out)?,
        Some(HostCommands::Trust { fingerprint, kind }) => {
            airdress_shell_host::commands::trust_here(
                &paths,
                &fingerprint,
                kind.as_deref(),
                ca.as_deref(),
                &mut |question| {
                    // Only the person at this machine trusts a device: no
                    // flag answers it, and never under `--output json`.
                    crate::ui::confirm(question, crate::ui::Confirm::person_only(false))?;
                    Ok(())
                },
            )
            .await?;
            crate::ui::ok("Trusted. It can open and attach to this host's sessions now.");
        }
        Some(HostCommands::Devices) => airdress_shell_host::commands::devices(&paths, &mut out)?,
        Some(HostCommands::Recordings {
            command: HostRecordings::List,
        }) => {
            airdress_shell_host::commands::recordings_list(&paths, &mut out)?;
        }
        Some(HostCommands::Recordings {
            command: HostRecordings::Prune,
        }) => {
            airdress_shell_host::commands::recordings_prune(&paths, &mut out)?;
        }
        Some(HostCommands::Reauth) => {
            airdress_shell_host::commands::reauth(&paths, ca.as_deref()).await?
        }
        None if h.install => {
            let exe: PathBuf = std::env::current_exe()?.canonicalize()?;
            airdress_shell_host::install::install(
                &paths,
                &exe,
                &airdress_shell_host::install::UserManager,
                &mut out,
            )?;
        }
        None if h.uninstall => airdress_shell_host::install::uninstall(
            &paths,
            &airdress_shell_host::install::UserManager,
            &mut out,
        )?,
        None => {
            crate::panic_exit::install("shell host");
            return airdress_shell_host::run::run(airdress_shell_host::run::RunOptions {
                paths,
                operator: h.operator,
                name: h.name,
                ca_file: ca,
                host_version: crate::build_version().to_owned(),
                timings: Default::default(),
                link: Default::default(),
            })
            .await;
        }
    }
    Ok(0)
}

/// Run `airdress shell profile …`.
#[cfg(unix)]
pub fn run_profile(command: ProfileCommands) -> Result<i32> {
    use airdress_shell_host::commands as c;
    let paths = Paths::from_env()?;
    let mut out = std::io::stdout();
    match command {
        ProfileCommands::Add { id, fields } => {
            c::profile_add(&paths, &id, &fields.edit(), &mut out)?
        }
        ProfileCommands::Edit { id, fields } => {
            c::profile_edit(&paths, &id, &fields.edit(), &mut out)?
        }
        ProfileCommands::Remove { id } => c::profile_remove(&paths, &id, &mut out)?,
        ProfileCommands::List => c::profile_list(&paths, &mut out)?,
        ProfileCommands::Show { id } => c::profile_show(&paths, &id, &mut out)?,
        ProfileCommands::Check => {
            return Ok(if c::profile_check(&paths, &mut out)? {
                0
            } else {
                1
            })
        }
    }
    Ok(0)
}

/// What the host's subcommands answer where there is no host.
#[cfg(not(unix))]
pub const UNSUPPORTED: &str =
    "`airdress shell host` runs on Linux; it is not supported on this platform. \
     `airdress shell` (the client) works here: open a session on a host elsewhere.";

/// `airdress shell host …` on a platform with no host.
#[cfg(not(unix))]
pub async fn run_host(_h: HostArgs) -> Result<i32> {
    anyhow::bail!(UNSUPPORTED)
}

/// `airdress shell profile …` on a platform with no host.
#[cfg(not(unix))]
pub fn run_profile(_command: ProfileCommands) -> Result<i32> {
    anyhow::bail!(UNSUPPORTED)
}
