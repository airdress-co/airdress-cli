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

/// Ask the holder one question. The device host listens on a Unix socket,
/// so on Windows there is none to ask.
#[cfg(not(unix))]
pub async fn call(socket: &Path, _req: &Value) -> Result<Value> {
    anyhow::bail!(
        "no device host on this platform: it listens on a Unix socket ({})",
        socket.display()
    )
}
