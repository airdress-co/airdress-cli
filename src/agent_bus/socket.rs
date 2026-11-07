//! Where this machine's device host listens, and one question to it.
//!
//! Outside the `mls` feature on purpose: the MCP server asks the device
//! host to sign bus writes and never links the MLS engine itself (the
//! public build carries none). The device host (`agent_device::host`)
//! computes its own socket path with the same function, so the two can
//! never disagree about where it is.
//!
//! The protocol is one JSON object per line each way; `sign` takes a
//! base64 payload and answers `{signature, public_key, enrollment_id}`.
//! No key ever crosses the socket.

use std::path::{Path, PathBuf};

use anyhow::Result;
#[cfg(unix)]
use anyhow::{bail, Context as _};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
#[cfg(unix)]
use serde_json::json;
use serde_json::Value;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

/// The default agent state dir: `~/.local/state/airdress/agent`.
pub fn default_state_dir(paths: &crate::paths::Paths) -> PathBuf {
    paths.state_home().join("airdress").join("agent")
}

/// The device's directory for one airdress under a state dir.
pub fn device_dir(state_dir: &Path, airdress: &str) -> PathBuf {
    state_dir.join("device").join(airdress)
}

/// The socket path: `host.sock` beside the lock, or — when that path is
/// longer than a Unix socket address holds — a short name in the per-user
/// runtime directory (`runtime_dir`, from [`crate::paths::Paths::runtime_dir`];
/// the temporary directory without one), derived from the long one.
pub fn socket_path(device_dir: &Path, runtime_dir: Option<&Path>) -> PathBuf {
    let beside = device_dir.join("host.sock");
    if beside.as_os_str().len() < 100 {
        return beside;
    }
    let digest = sha2::Digest::finalize(sha2::Digest::chain_update(
        <sha2::Sha256 as sha2::Digest>::new(),
        beside.as_os_str().as_encoded_bytes(),
    ));
    let name = format!(
        "airdress-agent-{}.sock",
        &URL_SAFE_NO_PAD.encode(digest)[..16]
    );
    runtime_dir
        .map_or_else(std::env::temp_dir, Path::to_path_buf)
        .join(name)
}

/// Ask the holder one question. Errors when no host is serving, or when
/// it refuses (the refusal's message is the error).
#[cfg(unix)]
pub async fn call(socket: &Path, req: &Value) -> Result<Value> {
    let sock = UnixStream::connect(socket)
        .await
        .with_context(|| format!("no device host is serving {}", socket.display()))?;
    let (r, mut w) = sock.into_split();
    let mut out = serde_json::to_vec(req)?;
    out.push(b'\n');
    w.write_all(&out).await?;
    let mut lines = BufReader::new(r).lines();
    let line = lines
        .next_line()
        .await?
        .context("the device host closed the connection")?;
    let v: Value = serde_json::from_str(&line)?;
    if v["ok"] != json!(true) {
        bail!(
            "{}",
            v["message"].as_str().unwrap_or("the device host refused")
        );
    }
    Ok(v)
}

/// A connection kept open to the device host, telling it which bus
/// session this server holds (`bus.hold`). When this process ends without
/// ending that session (Claude Code stops a session's server ~56 ms after
/// `/exit`, SPEC-166 166-H.6), the connection closes and the host ends
/// the session for it. [`Hold::release`] says the server ended it itself.
#[derive(Debug, Default)]
pub struct Hold {
    #[cfg(unix)]
    conn: Option<(
        tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        tokio::net::unix::OwnedWriteHalf,
    )>,
}

#[cfg(unix)]
impl Hold {
    /// Tell the host at `socket` that this connection holds `session`.
    /// Sent again with every heartbeat, so a host that took over from a
    /// dead one learns it too; a broken connection is opened again once.
    ///
    /// # Errors
    /// No host is serving, or it refused (an older host has no `bus.hold`).
    pub async fn hold(&mut self, socket: &Path, airdress: &str, session: &str) -> Result<()> {
        let req = json!({"op": "bus.hold", "airdress": airdress, "session": session});
        let mut last = None;
        for _ in 0..2 {
            match self.ask(socket, &req).await {
                Ok(v) if v["ok"] == json!(true) => return Ok(()),
                Ok(v) => bail!(
                    "{}",
                    v["message"].as_str().unwrap_or("the device host refused")
                ),
                Err(e) => {
                    self.conn = None;
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("the device host did not answer")))
    }

    /// The session was ended by this server: the host must not end it.
    pub async fn release(&mut self) {
        if self.conn.is_some() {
            if let Err(e) = self.ask_open(&json!({"op": "bus.release"})).await {
                // The connection closes below either way; a host that missed
                // the release may still end a session that is already gone.
                tracing::debug!(error = %format!("{e:#}"), "telling the device host the session ended");
            }
        }
        self.conn = None;
    }

    async fn ask(&mut self, socket: &Path, req: &Value) -> Result<Value> {
        if self.conn.is_none() {
            let sock = UnixStream::connect(socket)
                .await
                .with_context(|| format!("no device host is serving {}", socket.display()))?;
            let (r, w) = sock.into_split();
            self.conn = Some((BufReader::new(r).lines(), w));
        }
        self.ask_open(req).await
    }

    async fn ask_open(&mut self, req: &Value) -> Result<Value> {
        let (lines, w) = self
            .conn
            .as_mut()
            .context("no connection to the device host")?;
        let mut out = serde_json::to_vec(req)?;
        out.push(b'\n');
        w.write_all(&out).await?;
        let line = lines
            .next_line()
            .await?
            .context("the device host closed the connection")?;
        Ok(serde_json::from_str(&line)?)
    }
}

#[cfg(not(unix))]
impl Hold {
    /// No device host on this platform, so nothing to hold.
    ///
    /// # Errors
    /// Always: the device host listens on a Unix socket.
    pub async fn hold(&mut self, socket: &Path, _airdress: &str, _session: &str) -> Result<()> {
        anyhow::bail!("no device host on this platform ({})", socket.display())
    }

    /// Nothing to release.
    pub async fn release(&mut self) {}
}

/// Ask the holder one question. The device host listens on a Unix socket,
/// so on Windows there is none to ask.
#[cfg(not(unix))]
pub async fn call(socket: &Path, _req: &Value) -> Result<Value> {
    anyhow::bail!(
        "no device host on this platform: it listens on a Unix socket ({})",
        socket.display()
    )
}
