use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use super::discovery::DeviceFlowConfig;
use crate::http;
use crate::log_err::LogErr as _;
use crate::paths::Paths;
use crate::profile::storage;
use crate::redact::Redacted;

/// Path the pending-login hint is written to. Visible from a parallel
/// shell while the device flow is waiting; deleted on success.
fn write_pending_login(paths: &Paths, url: &str, code: &str) -> Result<()> {
    let path = paths.pending_login_path();
    storage::ensure_dirs(paths)?;
    crate::fsx::write(&path, format!("URL:  {url}\nCODE: {code}\n"))?;
    Ok(())
}

fn clear_pending_login(paths: &Paths) -> Result<()> {
    let path = paths.pending_login_path();
    if path.exists() {
        crate::fsx::remove_file(path)?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct DeviceFlowTokens {
    pub access_token: Redacted<String>,
    pub refresh_token: Redacted<String>,
    pub expires_in: i64,
    pub id_token: Option<Redacted<String>>,
}

/// `device_code` is the credential that redeems this login, so its `Debug`
/// leaves it out.
#[derive(serde::Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri_complete: Option<String>,
    verification_uri: String,
    interval: Option<u64>,
    expires_in: u64,
}

impl std::fmt::Debug for DeviceAuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthResponse")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    #[serde(default, deserialize_with = "crate::redact::persist_opt::deserialize")]
    access_token: Option<Redacted<String>>,
    #[serde(default, deserialize_with = "crate::redact::persist_opt::deserialize")]
    refresh_token: Option<Redacted<String>>,
    expires_in: Option<i64>,
    #[serde(default, deserialize_with = "crate::redact::persist_opt::deserialize")]
    id_token: Option<Redacted<String>>,
    error: Option<String>,
}

#[derive(Debug, Default)]
pub struct DeviceFlowOpts {
    /// Skip the browser-open side effect (CI, headless, when the caller
    /// will handle it). Stderr printing always happens regardless.
    pub no_browser: bool,
    /// Use `verification_uri` (bare URL, user types the code) instead of
    /// `verification_uri_complete` (URL with code prefilled). Defends
    /// against URL leakage via browser history / address-bar surfing at
    /// the cost of one extra step for the user.
    pub bare_url: bool,
}

/// A device authorization that has been requested and not yet granted.
///
/// Split out of the polling loop so a caller with no terminal can hand
/// the URL and the code to whoever does have one, and wait elsewhere —
/// which is what the MCP server's `login` tool does.
#[derive(Debug)]
pub struct DeviceFlowStart {
    /// The code the client redeems. A credential: it is the whole of
    /// the pending grant, so it is never printed or logged.
    pub device_code: Redacted<String>,
    /// The short code the person types.
    pub user_code: String,
    /// The URL to open, with the code prefilled unless `bare_url`.
    pub verification_url: String,
    /// Seconds between polls, as the identity provider asked.
    pub interval: u64,
    /// Seconds until the request expires.
    pub expires_in: u64,
}

/// Ask the identity provider to start a device authorization.
pub async fn begin(
    paths: &Paths,
    cfg: &DeviceFlowConfig,
    scopes: &str,
    bare_url: bool,
) -> Result<DeviceFlowStart> {
    if cfg.device_authorization_endpoint.is_empty() {
        bail!(
            "the sign-in server advertises no device authorization endpoint, so there is no \
             device flow here — sign in with the browser (`airdress auth login` without \
             --device / --no-browser)"
        );
    }
    let client = http::client()?;

    let mut params = HashMap::new();
    params.insert("client_id", cfg.client_id.as_str());
    params.insert("scope", scopes);
    // No `resource` here, deliberately: on the hub's authorization server
    // a request naming none is the CLI's grant over every airdress the
    // person owns (see `DeviceFlowConfig::resource`).

    let resp = client
        .post(&cfg.device_authorization_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&cfg.device_authorization_endpoint, "POST", e))?;
    let resp = http::handle_status(resp, "device authorization").await?;

    let auth: DeviceAuthResponse = resp
        .json()
        .await
        .context("failed to parse device authorization response")?;

    let display_url = if bare_url {
        auth.verification_uri.clone()
    } else {
        auth.verification_uri_complete
            .clone()
            .unwrap_or_else(|| auth.verification_uri.clone())
    };

    // Side-channel hint for non-streaming terminals: write the pending
    // URL/code to a fixed file so the user can `cat` it from another
    // shell if neither stdout nor the browser is reachable.
    // Only a hint: the URL and code are printed as well.
    write_pending_login(paths, &display_url, &auth.user_code)
        .log_debug("writing the pending-login hint");

    Ok(DeviceFlowStart {
        device_code: Redacted::new(auth.device_code),
        user_code: auth.user_code,
        verification_url: display_url,
        interval: auth.interval.unwrap_or(5),
        expires_in: auth.expires_in,
    })
}

/// Poll until the person has granted the request, or it expires.
pub async fn complete(
    paths: &Paths,
    cfg: &DeviceFlowConfig,
    start: &DeviceFlowStart,
) -> Result<DeviceFlowTokens> {
    let client = http::client()?;
    let mut interval = start.interval;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(start.expires_in);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

        if tokio::time::Instant::now() > deadline {
            bail!("device authorization timed out — please try again");
        }

        let mut token_params = HashMap::new();
        token_params.insert("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        token_params.insert("device_code", start.device_code.expose().as_str());
        token_params.insert("client_id", cfg.client_id.as_str());
        if let Some(resource) = cfg.resource.as_deref() {
            token_params.insert("resource", resource);
        }

        // Per RFC 8628 §3.5 the token endpoint returns 200 on success
        // and 400 on `authorization_pending` / `slow_down` / final error
        // — both carry a JSON body we want to parse, so we deliberately
        // do *not* run handle_status here. Transport errors (timeout,
        // connect) still get the friendly mapping.
        let resp = client
            .post(&cfg.token_endpoint)
            .form(&token_params)
            .send()
            .await
            .map_err(|e| http::format_transport_error(&cfg.token_endpoint, "POST", e))?;

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("failed to parse token response")?;

        match token_resp.error.as_deref() {
            Some("authorization_pending") => {
                tracing::debug!("authorization pending, polling again in {interval}s");
                continue;
            }
            Some("slow_down") => {
                interval += 5;
                tracing::debug!("rate limited, backing off to {interval}s");
                continue;
            }
            Some(err) => bail!("authorization failed: {err}"),
            None => {
                let access_token = token_resp
                    .access_token
                    .context("token response missing access_token")?;
                let refresh_token = token_resp.refresh_token.unwrap_or_default();
                let expires_in = token_resp.expires_in.unwrap_or(3600);

                // A stale hint is overwritten by the next login.
                clear_pending_login(paths).log_warn("removing the pending-login hint");

                return Ok(DeviceFlowTokens {
                    access_token,
                    refresh_token,
                    expires_in,
                    id_token: token_resp.id_token,
                });
            }
        }
    }
}

pub async fn run_device_flow_with_opts(
    paths: &Paths,
    cfg: &DeviceFlowConfig,
    scopes: &str,
    opts: DeviceFlowOpts,
) -> Result<DeviceFlowTokens> {
    let start = begin(paths, cfg, scopes, opts.bare_url).await?;
    let display_url = start.verification_url.as_str();

    // Try to open the URL in the user's browser *before* printing — when
    // stdout is captured (CI, agentic harnesses), the OS browser is the
    // only signal the user sees in real time. Failure is silent; the URL
    // is still printed for the TTY case.
    let browser_opened = if opts.no_browser {
        false
    } else {
        match webbrowser::open(display_url) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(error = %e, "could not open browser; printing URL only");
                false
            }
        }
    };

    eprintln!();
    if browser_opened {
        eprintln!("Opened in your browser. If it didn't show up:");
    } else {
        eprintln!("Open this URL in your browser to authenticate:");
    }
    eprintln!();
    eprintln!("  {display_url}");
    eprintln!();
    eprintln!("Enter code: {}", start.user_code);
    eprintln!();
    eprintln!("Waiting for authorization...");

    complete(paths, cfg, &start).await
}
