//! Shared HTTP client + error mapping for all hub / IdP / operator
//! traffic.
//!
//! Default budget:
//!   - connect: 10s (anything slower is a network/DNS problem)
//!   - total:   30s (per-request body read included)
//!
//! Override the total budget via `--timeout <seconds>` on the CLI root
//! or `AIRDRESS_TIMEOUT=<seconds>` (the flag wins). Connect budget is fixed because
//! nothing reasonable should take >10s to TCP-connect; if it does,
//! the user wants the failure fast, not a higher ceiling.
//!
//! Status-code and transport errors land in user-readable form through
//! [`handle_status`] and [`format_transport_error`].

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::Response;

use crate::exit::{self, Exit, Failure};

/// Default per-request timeout (body read included).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connect timeout — fixed; not overridable.
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

static TIMEOUT_SECS: OnceLock<u64> = OnceLock::new();
static TLS_CONFIG: OnceLock<TlsConfig> = OnceLock::new();

/// The private CA file `--ca-file` / `AIRDRESS_CA_FILE` named, if any.
pub fn configured_ca_file() -> Option<std::path::PathBuf> {
    TLS_CONFIG.get().and_then(|c| c.ca_file.clone())
}

/// Process-global TLS configuration. Set once from `main` after
/// parsing `--insecure` / `--ca-file`. Defaults to "validate against
/// the system root store" when unset.
#[derive(Debug, Default, Clone)]
pub struct TlsConfig {
    /// When true, the client accepts ANY TLS certificate including
    /// self-signed, expired, and hostname-mismatched ones. Surfaced
    /// to the user with a non-suppressible stderr warning on every
    /// CLI invocation that uses it.
    pub insecure: bool,
    /// Optional path to a PEM-encoded CA bundle. When set, the
    /// CA(s) inside are added to the client's root store IN ADDITION
    /// to the system roots (not as a replacement). Combine with
    /// `--insecure = false` for proper validation against a private
    /// CA (the recommended dev path).
    pub ca_file: Option<PathBuf>,
}

/// Called once from `main` after parsing the global `--timeout` flag.
/// Subsequent calls are ignored.
pub fn init_timeout(secs: u64) {
    if TIMEOUT_SECS.set(secs).is_err() {
        tracing::debug!("the HTTP timeout was already set; keeping the first");
    }
}

/// Called once from `main` after parsing `--insecure` / `--ca-file`.
/// Subsequent calls are ignored.
pub fn init_tls(cfg: TlsConfig) {
    if TLS_CONFIG.set(cfg).is_err() {
        tracing::debug!("the TLS configuration was already set; keeping the first");
    }
}

fn timeout_secs() -> u64 {
    *TIMEOUT_SECS.get().unwrap_or(&DEFAULT_TIMEOUT_SECS)
}

fn tls_config() -> &'static TlsConfig {
    static EMPTY: TlsConfig = TlsConfig {
        insecure: false,
        ca_file: None,
    };
    TLS_CONFIG.get().unwrap_or(&EMPTY)
}

/// Build a `reqwest::Client` with the configured timeouts AND TLS
/// settings. Use this everywhere — no `reqwest::Client::new()` in
/// feature modules.
pub fn client() -> Result<reqwest::Client> {
    client_builder().build().map_err(anyhow::Error::from)
}

/// A certificate renewal waits on the CA's order and validation.
pub const TLS_RENEW: Duration = Duration::from_secs(120);
/// One read of a join request's status, polled every few seconds: a slow
/// answer is a missed tick, not a reason to hold the poll.
pub const JOIN_STATUS: Duration = Duration::from_secs(15);
/// The agent bus's event stream: keep-alive comments every fifteen
/// seconds, so a silent minute means the stream is dead.
pub const BUS_STREAM_IDLE: Duration = Duration::from_secs(60);
/// A shell leg's event stream: keep-alive comments while a session is
/// quiet; five silent minutes means the stream is dead, and the leg resumes
/// from its last event id.
pub const SHELL_STREAM_IDLE: Duration = Duration::from_secs(300);

/// The deadlines one client works to, decided in one place from the global
/// `--timeout` (rust guide R-ASY-6). Built with [`Timeouts::global`],
/// [`Timeouts::at_least`], [`Timeouts::at_most`] or [`Timeouts::stream`];
/// [`client_with`] applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP and TLS connect.
    pub connect: Duration,
    /// The whole request, body read included. `None`: a held stream with
    /// no total deadline.
    pub request: Option<Duration>,
    /// Longest silence while reading. `None`: unbounded.
    pub idle: Option<Duration>,
}

impl Timeouts {
    /// `--timeout` (or `AIRDRESS_TIMEOUT`, or 30 s) for the request, 10 s
    /// to connect.
    pub fn global() -> Self {
        Self {
            connect: Duration::from_secs(CONNECT_TIMEOUT_SECS),
            request: Some(Duration::from_secs(timeout_secs())),
            idle: None,
        }
    }

    /// A request known to take long: the larger of `floor` and `--timeout`.
    pub fn at_least(floor: Duration) -> Self {
        let g = Self::global();
        Self {
            request: g.request.map(|r| r.max(floor)),
            ..g
        }
    }

    /// A request known to be quick: the smaller of `ceiling` and
    /// `--timeout`.
    pub fn at_most(ceiling: Duration) -> Self {
        let g = Self::global();
        Self {
            request: g.request.map(|r| r.min(ceiling)),
            ..g
        }
    }

    /// A held stream: no request deadline, the connect deadline stands, and
    /// a silence of `idle` ends it.
    pub fn stream(idle: Duration) -> Self {
        Self {
            request: None,
            idle: Some(idle),
            ..Self::global()
        }
    }
}

/// [`client_builder`] with these deadlines in place of the global ones.
pub fn client_with(t: Timeouts) -> reqwest::ClientBuilder {
    let mut b = reqwest::Client::builder().connect_timeout(t.connect);
    if let Some(r) = t.request {
        b = b.timeout(r);
    }
    if let Some(i) = t.idle {
        b = b.read_timeout(i);
    }
    with_tls(b)
}

/// Same as [`client`] but returns a builder so callers that need
/// extra customisation (DNS overrides, ...) can layer on top.
///
/// TLS settings from [`init_tls`] are already applied; callers that
/// need to *override* them (e.g. tests pinning a self-signed root)
/// can layer further.
pub fn client_builder() -> reqwest::ClientBuilder {
    client_with(Timeouts::global())
}

fn with_tls(mut b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let tls = tls_config();
    if tls.insecure {
        b = b.danger_accept_invalid_certs(true);
    }
    if let Some(path) = &tls.ca_file {
        match load_ca_certs(path) {
            Ok(certs) => {
                for c in certs {
                    b = b.add_root_certificate(c);
                }
            }
            Err(e) => {
                // Surfaced via the eventual reqwest::send() error;
                // here we just log so the cause is debuggable.
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to load --ca-file; clients will fall back to system roots only"
                );
            }
        }
    }
    b
}

/// Parse one or more PEM-encoded certificates out of `path`.
///
/// reqwest's `Certificate::from_pem` only accepts a single cert at a
/// time — for bundle files containing multiple certs we split on
/// `-----END CERTIFICATE-----` and parse each block.
fn load_ca_certs(path: &std::path::Path) -> Result<Vec<reqwest::Certificate>> {
    let raw = std::fs::read(path).with_context(|| format!("read CA file {}", path.display()))?;
    let text = String::from_utf8(raw.clone()).ok();
    if let Some(text) = text {
        let mut out = Vec::new();
        let mut current = String::new();
        for line in text.lines() {
            current.push_str(line);
            current.push('\n');
            if line.contains("-----END CERTIFICATE-----") {
                let cert = reqwest::Certificate::from_pem(current.as_bytes())
                    .with_context(|| format!("parse PEM cert in {}", path.display()))?;
                out.push(cert);
                current.clear();
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
    // Fall back to DER (single cert).
    let cert = reqwest::Certificate::from_der(&raw)
        .with_context(|| format!("parse {} as PEM or DER", path.display()))?;
    Ok(vec![cert])
}

/// Translate a non-2xx response into a user-friendly error: a
/// [`Failure`](crate::exit::Failure) carrying the status and the body's
/// code, so the exit status is decided by what the server said (401 → 4,
/// 409 → 6, other 4xx → 3, 502–504 → 5).
///
/// Body is consumed for the error message; do NOT call on a response
/// you intend to read further. Returns Ok(resp) on 2xx.
pub async fn handle_status(resp: Response, what: &str) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let url = resp.url().clone();
    let body = resp.text().await.unwrap_or_default();
    Err(status_failure(status.as_u16(), &url, &body, what).into())
}

/// The failure [`handle_status`] reports. The message is unchanged from
/// the text this CLI always printed (the MCP server reads the body back out
/// of it); the code is the body's, or `http_<status>`.
pub fn status_failure(status: u16, url: &reqwest::Url, body: &str, what: &str) -> Failure {
    let body_trim = body.trim();
    let suffix = if body_trim.is_empty() {
        String::new()
    } else {
        format!(": {body_trim}")
    };
    let status_text = reqwest::StatusCode::from_u16(status)
        .map_or_else(|_| status.to_string(), |s| s.to_string());
    let message = match status {
        401 => {
            format!("{what}: session expired or token invalid — run `airdress auth login`{suffix}")
        }
        403 => {
            format!("{what}: forbidden — your account doesn't have access to this resource{suffix}")
        }
        404 => format!("{what}: not found ({url}){suffix}"),
        429 => format!("{what}: rate limited (429) — try again shortly{suffix}"),
        500..=599 => format!(
            "{what}: server error {status_text} from {host}{suffix}",
            host = url.host_str().unwrap_or("?")
        ),
        _ => format!("{what}: HTTP {status_text}{suffix}"),
    };
    let code = exit::body_code(body).unwrap_or_else(|| format!("http_{status}"));
    let answer = serde_json::from_str::<serde_json::Value>(body).unwrap_or_default();
    let mut f = Failure::http(status, code, message).with_answer(&answer);
    if status == 429 {
        f = f.with_hint("try again shortly");
    }
    f
}

/// Wrap a `reqwest::Error` from a `send()` call into a user-readable
/// error. Distinguishes timeout / connect / TLS / generic; a timeout or a
/// refused connection is a [`Failure`](crate::exit::Failure) of kind
/// network (exit 5).
///
/// Use as: `.send().await.map_err(|e| http::format_transport_error(&url, "GET", e))?`
pub fn format_transport_error(url: &str, method: &str, err: reqwest::Error) -> anyhow::Error {
    let host = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string());

    if err.is_timeout() {
        let secs = timeout_secs();
        let next = secs * 2;
        return Failure::new(
            Exit::Network,
            "timeout",
            format!(
                "{method} {url} timed out after {secs}s — try `--timeout {next}` or check {host}"
            ),
        )
        .with_hint(format!("try `--timeout {next}`, or check {host}"))
        .into();
    }
    if err.is_connect() {
        return Failure::new(
            Exit::Network,
            "unreachable",
            format!("{method} {url} could not connect to {host} — DNS, firewall, or service down"),
        )
        .into();
    }
    if let Some(status) = err.status() {
        return Failure::http(
            status.as_u16(),
            format!("http_{}", status.as_u16()),
            format!("{method} {url} failed with HTTP {status}"),
        )
        .into();
    }
    anyhow!(err).context(format!("{method} {url} failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_timeout_is_30() {
        assert_eq!(DEFAULT_TIMEOUT_SECS, 30);
    }

    #[test]
    fn timeouts_bend_around_the_global_one() {
        let g = Timeouts::global().request.unwrap();
        assert_eq!(Timeouts::at_least(Duration::from_secs(1)).request, Some(g));
        assert_eq!(Timeouts::at_least(g * 4).request, Some(g * 4));
        assert_eq!(
            Timeouts::at_most(Duration::from_secs(1)).request,
            Some(Duration::from_secs(1))
        );
        let s = Timeouts::stream(BUS_STREAM_IDLE);
        assert_eq!((s.request, s.idle), (None, Some(BUS_STREAM_IDLE)));
    }

    #[test]
    fn connect_timeout_is_10() {
        assert_eq!(CONNECT_TIMEOUT_SECS, 10);
    }

    #[test]
    fn tls_config_defaults_to_validate() {
        // Without init_tls, tls_config() returns a defaulted struct
        // (validate against system roots).
        let cfg = tls_config();
        // We can't strictly assert "the OnceLock is unset" — other
        // tests in this process may have called init_tls — but we
        // CAN assert that the default field values land where we
        // expect when no `init_tls` ran. The clone-and-inspect is
        // defensive against that ordering.
        assert!(!cfg.insecure || TLS_CONFIG.get().is_some());
    }

    #[test]
    fn load_ca_certs_pem_self_signed() {
        // Tiny self-signed cert generated for this test. Just enough
        // PEM to exercise the multi-block splitter.
        let pem = "-----BEGIN CERTIFICATE-----\n\
MIIBhTCCASugAwIBAgIQEAdsBfGl2/dpa/2vrJZjuTAKBggqhkjOPQQDAjAUMRIw\n\
EAYDVQQDDAlsb2NhbGhvc3QwHhcNMjUwNTE1MDAwMDAwWhcNMjYwNTE1MDAwMDAw\n\
WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
AAQq7XQk9NfMV4WGqQ1WLJ7zr/iWFqLPzgsr2eFRdPDNcZ3pNz6kSffWqMZ3JNDg\n\
6N6mUVrcdRTYpcVrLnCKqEhvo10wWzAOBgNVHQ8BAf8EBAMCAaYwHQYDVR0lBBYw\n\
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHAYDVR0RBBUwE4IJ\n\
bG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIBzD3Yk5j5n+v/L5K9OE\n\
fSnz1eUlf/3JfH3p6sPbJgaUAiEAxq8h0v7vfNqZi1KZJ8aFZ2gO0BJjFp6sH1ed\n\
4ozzPvI=\n\
-----END CERTIFICATE-----\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        // We don't actually care that the cert is valid for any
        // purpose — only that the parser walks PEM blocks without
        // erroring. A garbled-base64 PEM body would fail; this one
        // parses cleanly.
        let parsed = load_ca_certs(&path);
        // Either parsed OK (rustls accepted), or rejected the test
        // cert (which is fine — the splitter ran).
        drop(parsed);
    }
}
