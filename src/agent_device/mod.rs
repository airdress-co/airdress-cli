//! This machine as an agent device of an airdress (design §9; behind the
//! `mls` feature).
//!
//! A coding assistant's sessions on one machine share one agent device: a
//! delegation-only device a person approved on their phone, with a
//! thirty-day root-signed delegation and never the root. [`host`] is the
//! one process per machine that holds it; [`join`] asks, enrolls and
//! renews; [`store`] keeps the keys in the OS keychain and the MLS state
//! sealed.
//!
//! ```text
//! airdress-agent device join     ask (a phone approves), and wait
//! airdress-agent device status   the device's standing and expiry
//! airdress-agent device leave    sign it out and delete its keys
//! airdress-agent device serve    run the device host (the editor's server starts it)
//! ```

pub mod chat;
pub mod chat_store;
pub mod host;
pub mod join;
pub mod revocation;
pub mod store;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::airdresses::client::HubClient;
use crate::context;
use crate::profile::storage;

/// `airdress-agent …`.
#[derive(Debug, Subcommand)]
pub enum AgentCommands {
    /// This machine's agent device on the airdress.
    Device {
        #[command(subcommand)]
        command: DeviceCommands,
    },
}

/// `airdress-agent device …`.
#[derive(Debug, Subcommand)]
pub enum DeviceCommands {
    /// Ask to join as an agent device; a phone approves it. Waits.
    Join {
        #[command(flatten)]
        opts: DeviceOpts,
        /// Give up (and withdraw the request) after this many seconds.
        #[arg(long, default_value_t = 600)]
        wait: u64,
    },
    /// The device's standing: approved, renewal due, expired.
    Status {
        #[command(flatten)]
        opts: DeviceOpts,
    },
    /// Sign the device out and delete its keys and sealed state.
    Leave {
        #[command(flatten)]
        opts: DeviceOpts,
    },
    /// Run the device host: hold the device, or wait to take it over.
    Serve {
        #[command(flatten)]
        opts: DeviceOpts,
    },
}

/// Where the device lives and what it is called.
#[derive(Debug, Clone, Args)]
pub struct DeviceOpts {
    /// The directory the device keeps itself in (an editor passes its own
    /// data directory). Default: ~/.local/state/airdress/agent.
    #[arg(long, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,
    /// Which program runs the agent, sent as data (`[a-z][a-z0-9-]{0,31}`).
    #[arg(long, default_value = "agent")]
    pub harness: String,
    /// What the phone is shown; `{host}` is this machine's name.
    #[arg(long, default_value = "Agent on {host}")]
    pub device_label_template: String,
    /// Credential profile for the hub sign-in.
    #[arg(long, value_name = "NAME")]
    pub auth_profile: Option<String>,
    /// Talk to this operator URL directly instead of `https://<fqdn>`.
    #[arg(long, value_name = "URL")]
    pub operator_url: Option<String>,
}

/// What `run` needs from the global flags.
#[derive(Debug)]
pub struct RunArgs<'a> {
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    /// `--airdress`.
    pub explicit_airdress: Option<&'a str>,
    /// `--output json`.
    pub json: bool,
}

#[derive(Debug)]
struct Resolved {
    store: store::AgentStore,
    hub: host::HubAuth,
    identity: host::Identity,
}

async fn resolve(
    paths: &crate::paths::Paths,
    opts: &DeviceOpts,
    explicit: Option<&str>,
    file_only: bool,
) -> Result<Resolved> {
    if !join::valid_harness(&opts.harness) {
        bail!("--harness must match [a-z][a-z0-9-]{{0,31}}");
    }
    let profile = storage::resolve_profile_name(paths, opts.auth_profile.as_deref())?;
    let hub = HubClient::from_profile(paths, &profile).await?;
    let named = context::resolve(paths, &profile, explicit)?;
    let fqdn = hub.resolve_fqdn(&named.name).await?;
    let operator = opts.operator_url.as_deref().map_or_else(
        || format!("https://{fqdn}"),
        |u| u.trim_end_matches('/').to_owned(),
    );
    let dir = match &opts.state_dir {
        Some(d) => d.clone(),
        None => store::default_state_dir(paths),
    };
    let store = if file_only {
        store::AgentStore::file_only(&dir, &fqdn)?.with_runtime_dir(paths.runtime_dir())
    } else {
        store::AgentStore::new(&dir, &fqdn)?.with_runtime_dir(paths.runtime_dir())
    };
    Ok(Resolved {
        store,
        hub: host::HubAuth::Profile {
            paths: paths.clone(),
            name: profile,
        },
        identity: host::Identity {
            operator,
            label: join::label_from(&opts.device_label_template),
            harness: opts.harness.clone(),
        },
    })
}

fn print(v: &serde_json::Value, json_out: bool) {
    if json_out {
        println!("{v}");
    } else if let Some(m) = v["message"].as_str() {
        println!("{m}");
        if let Some(exp) = v["expires_at"].as_str() {
            println!("approval expires {exp}");
        }
    }
}

/// Run `airdress-agent …`.
pub async fn run(cmd: AgentCommands, args: RunArgs<'_>) -> Result<()> {
    let paths = args.paths;
    let AgentCommands::Device { command } = cmd;
    match command {
        DeviceCommands::Serve { opts } => {
            let r = resolve(paths, &opts, args.explicit_airdress, false).await?;
            crate::panic_exit::install("agent device serve");
            let cancel = host::CancellationToken::new();
            // Ctrl-C cancels the holder; it drains its tasks and lets go
            // of the lock (R-ASY-3). Raced here, so nothing is left
            // running when this returns (R-ASY-1).
            let served = host::run(
                r.store,
                r.hub,
                r.identity,
                Duration::from_secs(15),
                cancel.clone(),
            );
            tokio::pin!(served);
            tokio::select! {
                // cancel-safe: the holder future is pinned outside the
                // race and polled again below; nothing is dropped.
                r = &mut served => r,
                // cancel-safe: `ctrl_c` is only made once here.
                signal = tokio::signal::ctrl_c() => {
                    // A handler that could not be installed must not read
                    // as a Ctrl-C: say so and leave the holder running.
                    match signal {
                        Ok(()) => cancel.cancel(),
                        Err(e) => tracing::warn!(error = %e, "could not listen for Ctrl-C"),
                    }
                    served.await
                }
            }
        }
        DeviceCommands::Status { opts } => {
            let r = resolve(paths, &opts, args.explicit_airdress, false).await?;
            let v = match host::call(&r.store, &json!({"op": "device.status"})).await {
                Ok(v) => v,
                // No host running: read the store; nothing is advanced.
                Err(_) => host::status_of(r.store.load()?.as_ref(), r.store.airdress()),
            };
            print(&v, args.json);
            Ok(())
        }
        DeviceCommands::Join { opts, wait } => {
            let r = resolve(paths, &opts, args.explicit_airdress, false).await?;
            if let Ok(v) = host::call(&r.store, &json!({"op": "device.request"})).await {
                // A host holds the device: ask through it and watch.
                print(&v, args.json);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
                loop {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let v = host::call(&r.store, &json!({"op": "device.status"})).await?;
                    if v["pending"] != json!(true) {
                        print(&v, args.json);
                        return Ok(());
                    }
                    if tokio::time::Instant::now() >= deadline {
                        bail!("nobody approved it yet; the device host keeps asking");
                    }
                }
            }
            // No host: hold the device for the join.
            let lock = host::HostLock::try_take(&r.store.lock_path())?
                .context("another process holds this device; try again")?;
            let mut dev = match r.store.load()? {
                Some(d) => d,
                None => {
                    let mut d = join::new_device(
                        r.store.airdress(),
                        &r.identity.operator,
                        r.identity.label.clone(),
                        &r.identity.harness,
                    );
                    if r.store.save(&mut d)? == crate::shell_client::store::SecretsAt::File {
                        eprintln!(
                            "No OS keychain here: this device's keys are in {} (mode 0600).",
                            r.store.dir().display()
                        );
                    }
                    d
                }
            };
            let standing = join::standing(dev.record.expires_at, chrono::Utc::now());
            if !dev.record.enrollment_id.is_empty() && standing == join::Standing::Approved {
                print(&host::status_of(Some(&dev), r.store.airdress()), args.json);
                return Ok(());
            }
            let (base, bearer) = match &r.hub {
                host::HubAuth::Profile { paths, name } => {
                    let h = HubClient::from_profile(paths, name).await?;
                    (h.endpoint().to_owned(), h.bearer().to_owned())
                }
                host::HubAuth::Static { base, bearer } => (base.clone(), bearer.clone()),
            };
            join::ask_and_wait(
                &r.store,
                &mut dev,
                &join::Hub {
                    base: &base,
                    bearer: &bearer,
                },
                Duration::from_secs(wait),
                &|s| eprintln!("{s}"),
            )
            .await?;
            drop(lock);
            print(&host::status_of(Some(&dev), r.store.airdress()), args.json);
            Ok(())
        }
        DeviceCommands::Leave { opts } => {
            let r = resolve(paths, &opts, args.explicit_airdress, false).await?;
            if let Ok(v) = host::call(&r.store, &json!({"op": "device.leave"})).await {
                print(
                    &json!({"message": "signed out; keys deleted"}),
                    args.json && v.is_object(),
                );
                return Ok(());
            }
            let _lock = host::HostLock::try_take(&r.store.lock_path())?
                .context("another process holds this device; try again")?;
            if let Some(dev) = r.store.load()? {
                if !dev.record.enrollment_id.is_empty() {
                    join::AgentApi::new(&dev.record.operator)?
                        .leave(&dev.record, &dev.token)
                        .await?;
                }
            }
            r.store.forget()?;
            print(&json!({"message": "signed out; keys deleted"}), args.json);
            Ok(())
        }
    }
}
