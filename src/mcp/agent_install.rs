//! Install `airdress-agent` from the pins the plugin shipped with (SPEC-166 F.2).
//!
//! A fresh machine had to fetch `airdress-agent` itself: the session
//! downloaded and checked it, and then Claude Code's auto mode refused to
//! install a program from the internet, so it became a `!` line for the
//! person, sometimes two. The plugin's pins file, read from the commit the
//! marketplace pins, now names the agent of the same airdress-cli release
//! as this server, with its SHA-256 per platform; this installs that file
//! into the plugin's data directory and nowhere else. A file whose digest
//! is not the pinned one is never made executable.
//!
//! The server is told where the pins are by `AIRDRESS_AGENT_PINS`, which
//! the plugin sets. Without it nothing is downloaded, and a person installs
//! the agent as before.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The environment variable naming the plugin's pins file.
pub const PINS_ENV: &str = "AIRDRESS_AGENT_PINS";

const AGENT: &str = "airdress-agent";

#[derive(Debug, Deserialize)]
struct Pins {
    agent: Option<AgentPins>,
}

#[derive(Debug, Deserialize)]
struct AgentPins {
    version: String,
    /// Base URLs, tried in order; each ends in `/`.
    origins: Vec<String>,
    /// Keyed by `linux-x86_64`, `linux-aarch64`, `darwin-x86_64`,
    /// `darwin-aarch64`.
    files: BTreeMap<String, PinnedFile>,
}

#[derive(Debug, Deserialize)]
struct PinnedFile {
    name: String,
    sha256: String,
}

/// This machine's key in the pins.
fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        ("macos", "x86_64") => Some("darwin-x86_64"),
        ("macos", "aarch64") => Some("darwin-aarch64"),
        _ => None,
    }
}

/// Where the plugin keeps its own copy of the agent.
pub fn installed_path(state_dir: &Path) -> PathBuf {
    state_dir.join("bin").join(AGENT)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The pinned file for this machine, if the plugin pinned one.
fn pinned(pins_path: &Path) -> Result<(String, Vec<String>, PinnedFile)> {
    let raw = std::fs::read(pins_path)
        .with_context(|| format!("reading the plugin's pins at {}", pins_path.display()))?;
    let pins: Pins = serde_json::from_slice(&raw).context("the plugin's pins are not valid")?;
    let agent = pins
        .agent
        .ok_or_else(|| anyhow!("this plugin release pins no airdress-agent"))?;
    let key = platform().ok_or_else(|| {
        anyhow!(
            "no airdress-agent is built for {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let mut files = agent.files;
    let file = files
        .remove(key)
        .ok_or_else(|| anyhow!("this plugin release pins no airdress-agent for {key}"))?;
    if file.sha256.len() != 64 || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the pinned digest for {key} is not a SHA-256");
    }
    Ok((agent.version, agent.origins, file))
}

/// The installed agent, if one is there and matches the pin.
fn current(path: &Path, sha256: &str) -> bool {
    std::fs::read(path).is_ok_and(|b| sha256_hex(&b).eq_ignore_ascii_case(sha256))
}

/// Install the pinned agent into `state_dir/bin` unless it is there
/// already. Returns its path.
pub async fn ensure(state_dir: &Path) -> Result<PathBuf> {
    let pins = std::env::var_os(PINS_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow!("{PINS_ENV} is not set: this server was not started by the plugin")
        })?;
    ensure_from(state_dir, &pins).await
}

async fn ensure_from(state_dir: &Path, pins: &Path) -> Result<PathBuf> {
    let (version, origins, file) = pinned(pins)?;
    let path = installed_path(state_dir);
    if current(&path, &file.sha256) {
        return Ok(path);
    }
    let client = crate::http::client_builder()
        .build()
        .context("building the HTTP client")?;
    let mut why = Vec::new();
    for origin in &origins {
        let url = format!("{origin}{}", file.name);
        let bytes = match fetch(&client, &url).await {
            Ok(b) => b,
            Err(e) => {
                why.push(format!("{url}: {e:#}"));
                continue;
            }
        };
        let got = sha256_hex(&bytes);
        if !got.eq_ignore_ascii_case(&file.sha256) {
            why.push(format!("{url}: SHA-256 {got}, pinned {}", file.sha256));
            continue;
        }
        write_executable(&path, &bytes)?;
        tracing::info!(%version, path = %path.display(), "installed airdress-agent");
        return Ok(path);
    }
    bail!(
        "could not install airdress-agent {version}: {}",
        why.join("; ")
    )
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?.error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}

/// Write beside the target and rename over it, so a half-written file is
/// never what runs.
fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("the agent's path has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".{AGENT}.{}", std::process::id()));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins_with(dir: &Path, sha: &str, origin: &str) -> PathBuf {
        let key = platform().expect("a supported test platform");
        let p = dir.join("pins.json");
        let json = serde_json::json!({
            "version": "0.1.0",
            "agent": {
                "version": "v9.9.9",
                "origins": [origin],
                "files": { key: { "name": "airdress-agent-test", "sha256": sha } }
            }
        });
        std::fs::write(&p, serde_json::to_vec(&json).unwrap()).unwrap();
        p
    }

    #[tokio::test]
    async fn a_matching_installed_agent_is_kept_without_a_download() {
        let dir = tempfile::tempdir().unwrap();
        let body = b"#!/bin/sh\necho agent\n";
        let path = installed_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        // An origin nothing listens on: reaching it would fail the test.
        let pins = pins_with(dir.path(), &sha256_hex(body), "http://127.0.0.1:9/");
        assert_eq!(ensure_from(dir.path(), &pins).await.unwrap(), path);
    }

    #[tokio::test]
    async fn a_download_whose_digest_is_not_the_pin_is_never_installed() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).expect("the request");
                assert!(n > 0, "an empty request");
                let body = b"not the agent";
                write!(
                    s,
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .expect("the head");
                s.write_all(body).expect("the body");
            }
        });
        let pins = pins_with(
            dir.path(),
            &"0".repeat(64),
            &format!("http://127.0.0.1:{port}/"),
        );
        let err = ensure_from(dir.path(), &pins).await.unwrap_err();
        assert!(format!("{err:#}").contains("pinned"), "{err:#}");
        assert!(!installed_path(dir.path()).exists());
    }

    #[test]
    fn pins_without_an_agent_say_so() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pins.json");
        std::fs::write(&p, br#"{"version":"0.1.11","bundles":{}}"#).unwrap();
        let err = pinned(&p).unwrap_err();
        assert!(
            format!("{err:#}").contains("pins no airdress-agent"),
            "{err:#}"
        );
    }
}
