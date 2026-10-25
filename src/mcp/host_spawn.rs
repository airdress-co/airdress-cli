//! Start the device host when nothing serves it (SPEC-166 F.2).
//!
//! On a fresh machine, a person who had joined the agent device still had
//! to keep `airdress-agent device serve` running in a terminal of their
//! own, and it stopped with that terminal. The server now starts it as its
//! child when this machine has joined a device for the airdress, the
//! `airdress-agent` binary is installed, and no host answers.
//! `device serve` holds the device or waits to take it over, so every
//! session on the machine may start one: one serves, the others stand by,
//! and when the serving session ends another takes over.
//!
//! It looks again every few seconds, not only at start-up: a machine that
//! joins while the session runs got its host only after the person
//! reconnected the server, one more step in the onboarding count. And the
//! join itself is started from here ([`start_join`]), with the agent the
//! plugin pinned ([`crate::mcp::agent_install`]), so a person runs neither.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::json;

use crate::agent_bus::socket;
use crate::log_err::LogErr as _;
use crate::mcp::agent_install;
use crate::mcp::session::Session;

/// The binary's name.
const AGENT: &str = "airdress-agent";

/// How often a session looks for a joined device nobody serves.
const WATCH_EVERY: Duration = Duration::from_secs(5);

/// Where to look for `airdress-agent`: the copy the plugin installed, then
/// `PATH`, then `~/.local/bin`.
fn find_agent(state: &Path, home: &Path) -> Option<PathBuf> {
    let on_path = std::env::var_os("PATH").into_iter().flat_map(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(AGENT))
            .collect::<Vec<_>>()
    });
    std::iter::once(agent_install::installed_path(state))
        .chain(on_path)
        .chain(std::iter::once(home.join(".local").join("bin").join(AGENT)))
        .find(|p| p.is_file())
}

/// Whether this machine has joined a device for the airdress in `dir`.
fn joined(device_dir: &Path) -> bool {
    device_dir.join("device.json").is_file()
}

/// `airdress-agent device <verb>` with the arguments this session's device
/// is kept under; `join` and `serve` take the same ones.
fn agent_command(
    session: &Session,
    agent: &Path,
    verb: &str,
    state: &Path,
    fqdn: &str,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(agent);
    cmd.args(["device", verb, "--state-dir"])
        .arg(state)
        .args(["-A", fqdn, "--harness", &session.opts.harness])
        .args([
            "--device-label-template",
            &session.opts.device_label_template,
        ]);
    if let Ok(profile) = session.profile_name() {
        cmd.args(["--auth-profile", &profile]);
    }
    cmd
}

/// Append a child's stderr to `name` in the device directory.
fn log_to(cmd: &mut tokio::process::Command, device_dir: &Path, name: &str) {
    std::fs::create_dir_all(device_dir).log_debug("creating the device directory");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(device_dir.join(name));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log.map_or_else(|_| Stdio::null(), Stdio::from))
        .kill_on_drop(true);
}

/// Start `device serve` for `fqdn` when it is joined here and nobody
/// serves it. The child ends with this process.
pub async fn ensure(session: &Arc<Session>, fqdn: &str) {
    if std::env::var_os("AIRDRESS_MCP_NO_HOST_SPAWN").is_some() {
        return;
    }
    let Ok(state) = crate::mcp::bus::state_dir_of(session) else {
        return;
    };
    let device_dir = socket::device_dir(&state, fqdn);
    if !joined(&device_dir) {
        return;
    }
    let Ok(paths) = session.paths() else { return };
    let sock = socket::socket_path(&device_dir, paths.runtime_dir());
    if socket::call(&sock, &json!({"op": "device.status"}))
        .await
        .is_ok()
    {
        return;
    }
    // A host this session started may still be starting, or waiting to
    // take the device over from another session's: leave it be.
    if let Some(child) = session.host_child.lock().await.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return;
        }
    }
    let Some(agent) = find_agent(&state, paths.home()) else {
        tracing::debug!("no {AGENT} installed; the device host is not started");
        return;
    };
    let mut cmd = agent_command(session, &agent, "serve", &state, fqdn);
    log_to(&mut cmd, &device_dir, "host.log");
    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(agent = %agent.display(), "started the device host");
            *session.host_child.lock().await = Some(child);
        }
        Err(e) => tracing::warn!(error = %e, "could not start the device host"),
    }
}

/// [`ensure`], now and every few seconds, for as long as the session runs.
pub async fn watch(session: Arc<Session>, fqdn: String) {
    loop {
        ensure(&session, &fqdn).await;
        tokio::time::sleep(WATCH_EVERY).await;
    }
}

/// Ask to join `fqdn` as an agent device: install the pinned agent if this
/// machine has none, start `device join`, and return what the person
/// does next. The join waits for the phone in the background; once it is
/// approved, [`watch`] starts the host.
pub async fn start_join(session: &Arc<Session>, fqdn: &str) -> Result<String> {
    let state = crate::mcp::bus::state_dir_of(session)?;
    let device_dir = socket::device_dir(&state, fqdn);
    if joined(&device_dir) {
        return Ok(format!(
            "This machine is already an agent device of {fqdn}; the device host starts by itself."
        ));
    }
    if let Some(child) = session.join_child.lock().await.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(format!(
                "A join for {fqdn} is already waiting: approve it on your phone."
            ));
        }
    }
    let paths = session.paths()?;
    let agent = match find_agent(&state, paths.home()) {
        Some(a) => a,
        None => match agent_install::ensure(&state).await {
            Ok(a) => a,
            Err(e) => bail!(
                "this machine has no airdress-agent, and the plugin could not install one \
                 ({e:#}). Install it from https://github.com/airdress-co/airdress-cli/releases \
                 (the airdress-agent-<platform> asset, checked against its .sha256) and call \
                 this again."
            ),
        },
    };
    let mut cmd = agent_command(session, &agent, "join", &state, fqdn);
    log_to(&mut cmd, &device_dir, "join.log");
    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not start {}: {e}", agent.display()))?;
    *session.join_child.lock().await = Some(child);
    let label = label_from(&session.opts.device_label_template);
    Ok(format!(
        "Asked to join {fqdn} as \"{label}\". Approve it on your phone within 10 minutes \
         (the app shows \"{label} wants to join\"). Once it is approved, this session starts \
         the device host by itself and chat works; nothing needs restarting."
    ))
}

/// What the phone will be shown, as `agent_device::join::label_from` makes
/// it; that module links MLS, which this server does not.
fn label_from(template: &str) -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_owned())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this machine".to_owned());
    let label = template.replace("{host}", &host);
    label.chars().take(80).collect::<String>().trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_is_found_in_local_bin_and_a_device_is_joined_by_its_record() {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state");
        let bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        assert!(find_agent(&state, home.path()).is_none_or(|p| !p.starts_with(home.path())));
        std::fs::write(bin.join(AGENT), b"").unwrap();
        // PATH may hold a real one first; either way one is found.
        assert!(find_agent(&state, home.path()).is_some());

        let dev = home.path().join("device/a.example");
        assert!(!joined(&dev));
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("device.json"), b"{}").unwrap();
        assert!(joined(&dev));
    }

    #[test]
    fn the_plugins_own_agent_comes_first() {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state");
        let own = agent_install::installed_path(&state);
        std::fs::create_dir_all(own.parent().unwrap()).unwrap();
        std::fs::write(&own, b"").unwrap();
        assert_eq!(find_agent(&state, home.path()), Some(own));
    }
}
