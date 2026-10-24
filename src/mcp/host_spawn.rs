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

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use serde_json::json;

use crate::agent_bus::socket;
use crate::mcp::session::Session;

/// The binary's name.
const AGENT: &str = "airdress-agent";

/// Where to look for `airdress-agent`: `PATH`, then `~/.local/bin`.
fn find_agent(home: &Path) -> Option<PathBuf> {
    let on_path = std::env::var_os("PATH").into_iter().flat_map(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(AGENT))
            .collect::<Vec<_>>()
    });
    on_path
        .chain(std::iter::once(home.join(".local").join("bin").join(AGENT)))
        .find(|p| p.is_file())
}

/// Whether this machine has joined a device for the airdress in `dir`.
fn joined(device_dir: &Path) -> bool {
    device_dir.join("device.json").is_file()
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
    let Some(agent) = find_agent(paths.home()) else {
        tracing::debug!("no {AGENT} installed; the device host is not started");
        return;
    };
    let mut cmd = tokio::process::Command::new(&agent);
    cmd.args(["device", "serve", "--state-dir"])
        .arg(&state)
        .args(["-A", fqdn, "--harness", &session.opts.harness])
        .args([
            "--device-label-template",
            &session.opts.device_label_template,
        ]);
    if let Ok(profile) = session.profile_name() {
        cmd.args(["--auth-profile", &profile]);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(device_dir.join("host.log"));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log.map_or_else(|_| Stdio::null(), Stdio::from))
        .kill_on_drop(true);
    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(agent = %agent.display(), "started the device host");
            *session.host_child.lock().await = Some(child);
        }
        Err(e) => tracing::warn!(error = %e, "could not start the device host"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_is_found_in_local_bin_and_a_device_is_joined_by_its_record() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        assert!(find_agent(home.path()).is_none_or(|p| !p.starts_with(home.path())));
        std::fs::write(bin.join(AGENT), b"").unwrap();
        // PATH may hold a real one first; either way one is found.
        assert!(find_agent(home.path()).is_some());

        let dev = home.path().join("device/a.example");
        assert!(!joined(&dev));
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("device.json"), b"{}").unwrap();
        assert!(joined(&dev));
    }
}
