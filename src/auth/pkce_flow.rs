//! Browser login with an account picker: authorization code + PKCE over a
//! loopback redirect (RFC 6749 §4.1, RFC 7636, RFC 8252 §7.3).
//!
//! Why this exists beside the device flow: the device grant cannot ask the
//! IdP to let the person choose an account. RFC 8628's device authorization
//! request carries `client_id` and `scope` only, and ZITADEL reads nothing
//! else (zitadel/oidc `pkg/oidc/device_authorization.go`,
//! `DeviceAuthorizationRequest{Scopes, ClientID}`). Its `/device` page runs
//! on the legacy login, which builds the auth request without a prompt, and
//! with a prompt-less request a browser holding exactly one active session
//! is signed in as that session without being asked
//! (zitadel `internal/auth/repository/eventsourcing/eventstore/auth_request.go`,
//! `nextStepsUser`). That is how a second profile silently became the
//! first profile's account.
//!
//! The authorization endpoint does honour `prompt=select_account`, so the
//! login goes there. The redirect is `http://localhost:<port>` with no path:
//! the CLI client registers `http://localhost`, and a native client may vary
//! the loopback port but not the path (zitadel/oidc `pkg/op/auth_request.go`,
//! `validateAuthReqRedirectURINative` / `equalURI`).
//!
//! Since SPEC-133 D-36 the same flow runs against the hub's own
//! authorization server: the CLI's pre-registered client there redirects to
//! `http://localhost:<port>/callback`, the code exchange carries an RFC 8707
//! `resource` (the authorization request names none, which is how the CLI
//! gets a grant over every airdress the person owns), and the hub forwards `prompt=select_account` to its ZITADEL
//! login so the picker survives the extra hop.
//!
//! The IdP client must also allow the `authorization_code` grant. When it
//! does not, [`code_grant_allowed`] says so before any browser opens, and the
//! caller falls back to the device flow.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::device_flow::DeviceFlowTokens;
use super::discovery::DeviceFlowConfig;
use crate::http;
use crate::log_err::LogErr as _;
use crate::redact::Redacted;

/// How long the loopback listener waits for the browser to come back.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// The OIDC prompt that makes the IdP show its account chooser (with
/// "use another account") even when the browser already holds a session.
pub const PROMPT_SELECT_ACCOUNT: &str = "select_account";

/// RFC 7636 §4.1 code verifier: 64 characters from the unreserved set.
pub(crate) fn generate_verifier() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// RFC 7636 §4.2 `S256` challenge.
pub(crate) fn challenge_for(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_state() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug)]
pub(crate) struct AuthorizeParams<'a> {
    pub authorization_endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub prompt: Option<&'a str>,
}

pub(crate) fn authorize_url(p: &AuthorizeParams<'_>) -> Result<String> {
    let mut url = reqwest::Url::parse(p.authorization_endpoint).with_context(|| {
        format!(
            "invalid authorization endpoint {}",
            p.authorization_endpoint
        )
    })?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", p.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", p.redirect_uri)
            .append_pair("scope", p.scopes)
            .append_pair("state", p.state)
            .append_pair("code_challenge", p.code_challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(prompt) = p.prompt {
            q.append_pair("prompt", prompt);
        }
    }
    Ok(url.into())
}

/// What the browser brought back to the loopback listener.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Callback {
    Code(String),
    Error {
        error: String,
        description: Option<String>,
    },
    /// Not the redirect (a favicon, a stray probe). Answer and keep waiting.
    Ignore,
}

/// Parse the request line of the loopback callback. `expected_state` guards
/// against a stale or forged redirect (RFC 6749 §10.12).
pub(crate) fn parse_callback(
    request_head: &str,
    expected_path: &str,
    expected_state: &str,
) -> Result<Callback> {
    let line = request_head.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(Callback::Ignore);
    };
    let url = reqwest::Url::parse(&format!("http://localhost{target}"))
        .map_err(|e| anyhow!("unreadable callback request: {e}"))?;
    let want = if expected_path.is_empty() {
        "/"
    } else {
        expected_path
    };
    if url.path() != want {
        return Ok(Callback::Ignore);
    }
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if q.is_empty() {
        return Ok(Callback::Ignore);
    }
    if q.get("state").map(String::as_str) != Some(expected_state) {
        bail!(
            "login callback carried the wrong state — ignoring it; run `airdress auth login` again"
        );
    }
    if let Some(error) = q.get("error") {
        return Ok(Callback::Error {
            error: error.clone(),
            description: q.get("error_description").cloned(),
        });
    }
    match q.get("code") {
        Some(code) if !code.is_empty() => Ok(Callback::Code(code.clone())),
        _ => bail!("login callback carried neither a code nor an error"),
    }
}

/// Ask the token endpoint whether this client may use the code grant, with
/// a code that cannot exist. ZITADEL checks the client's grant types before
/// it looks at the code (zitadel/oidc `pkg/op/server_http.go`, `withClient`:
/// `unauthorized_client` "grant_type … not allowed"), so this costs no
/// browser round trip. Any other answer is treated as "allowed" — an IdP
/// that checks in a different order still fails safely at the real
/// exchange, where [`CodeGrantRefused`] triggers the same fallback.
pub async fn code_grant_allowed(cfg: &DeviceFlowConfig) -> Result<bool> {
    let client = http::client()?;
    let resp = client
        .post(&cfg.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "airdress-cli-grant-probe"),
            ("redirect_uri", "http://localhost"),
            ("client_id", cfg.client_id.as_str()),
            ("code_verifier", &generate_verifier()),
        ])
        .send()
        .await
        .map_err(|e| http::format_transport_error(&cfg.token_endpoint, "POST", e))?;
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    Ok(body.get("error").and_then(|e| e.as_str()) != Some("unauthorized_client"))
}

/// The IdP refused the code grant at exchange time.
#[derive(Debug)]
pub struct CodeGrantRefused(pub String);

impl std::fmt::Display for CodeGrantRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the identity provider refused the code grant: {}",
            self.0
        )
    }
}

impl std::error::Error for CodeGrantRefused {}

/// Bind the loopback listeners. `localhost` may resolve to either family,
/// so bind 127.0.0.1 on an ephemeral port and [::1] on the same port when
/// the host has IPv6 loopback.
async fn bind_loopback() -> Result<(Vec<TcpListener>, u16)> {
    let v4 = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("could not open a local port for the login callback")?;
    let port = v4.local_addr()?.port();
    let mut listeners = vec![v4];
    if let Ok(v6) = TcpListener::bind(("::1", port)).await {
        listeners.push(v6);
    }
    Ok((listeners, port))
}

async fn accept_any(listeners: &[TcpListener]) -> std::io::Result<TcpStream> {
    match listeners {
        [a] => a.accept().await.map(|(s, _)| s),
        [a, b, ..] => tokio::select! {
            // cancel-safe: `TcpListener::accept` (tokio's list); a
            // connection the losing listener had not yet accepted stays in
            // its backlog for the next call.
            r = a.accept() => r.map(|(s, _)| s),
            // cancel-safe: as above.
            r = b.accept() => r.map(|(s, _)| s),
        },
        [] => Err(std::io::Error::other("no listener")),
    }
}

async fn read_head(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>airdress</title>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto\">\
         <p>{body}</p></body>"
    );
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{page}",
        page.len()
    );
    // The browser's page only: the code it carried has already been read,
    // and a browser that hung up first changes nothing.
    stream
        .write_all(resp.as_bytes())
        .await
        .log_debug("answering the browser");
    stream
        .shutdown()
        .await
        .log_debug("closing the browser's connection");
}

async fn wait_for_code(listeners: &[TcpListener], path: &str, state: &str) -> Result<String> {
    loop {
        let mut stream = accept_any(listeners).await?;
        let head = match read_head(&mut stream).await {
            Ok(h) => h,
            Err(_) => continue,
        };
        match parse_callback(&head, path, state) {
            Ok(Callback::Ignore) => respond(&mut stream, "404 Not Found", "Not found.").await,
            Ok(Callback::Code(code)) => {
                respond(
                    &mut stream,
                    "200 OK",
                    "Signed in. You can close this tab and return to the terminal.",
                )
                .await;
                return Ok(code);
            }
            Ok(Callback::Error { error, description }) => {
                respond(
                    &mut stream,
                    "200 OK",
                    "Sign-in did not complete. Return to the terminal for details.",
                )
                .await;
                bail!(
                    "sign-in failed ({error}{})",
                    description.map(|d| format!(": {d}")).unwrap_or_default()
                );
            }
            Err(e) => {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    "This sign-in link is not valid.",
                )
                .await;
                return Err(e);
            }
        }
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
    error_description: Option<String>,
}

/// Run the loopback login. Returns `Ok(None)` when the browser could not be
/// opened — a loopback redirect only works with a browser on this machine,
/// so the caller falls back to the device flow.
pub async fn run(
    cfg: &DeviceFlowConfig,
    authorization_endpoint: &str,
    scopes: &str,
    prompt: Option<&str>,
) -> Result<Option<DeviceFlowTokens>> {
    run_with_opener(
        cfg,
        authorization_endpoint,
        scopes,
        prompt,
        |url| match webbrowser::open(url) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(error = %e, "could not open browser for loopback login");
                false
            }
        },
    )
    .await
}

/// [`run`] with the browser injected: `open` is handed the authorization
/// URL and says whether a browser took it. Tests drive the redirect
/// themselves through it.
pub async fn run_with_opener(
    cfg: &DeviceFlowConfig,
    authorization_endpoint: &str,
    scopes: &str,
    prompt: Option<&str>,
    open: impl FnOnce(&str) -> bool,
) -> Result<Option<DeviceFlowTokens>> {
    let (listeners, port) = bind_loopback().await?;
    let redirect_uri = format!("http://localhost:{port}{}", cfg.loopback_path);
    let verifier = generate_verifier();
    let state = random_state();
    let url = authorize_url(&AuthorizeParams {
        authorization_endpoint,
        client_id: &cfg.client_id,
        redirect_uri: &redirect_uri,
        scopes,
        state: &state,
        code_challenge: &challenge_for(&verifier),
        prompt,
    })?;

    if !open(&url) {
        return Ok(None);
    }
    eprintln!();
    eprintln!("Opened your browser to sign in. Pick the account for this profile.");
    eprintln!("If nothing opened, visit:");
    eprintln!();
    eprintln!("  {url}");
    eprintln!();
    eprintln!("Waiting for the browser...");

    let code = tokio::time::timeout(
        CALLBACK_TIMEOUT,
        wait_for_code(&listeners, &cfg.loopback_path, &state),
    )
    .await
    .map_err(|_| anyhow!("sign-in timed out — please try again"))??;

    let client = http::client()?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    if let Some(resource) = cfg.resource.as_deref() {
        form.push(("resource", resource));
    }
    let resp = client
        .post(&cfg.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&cfg.token_endpoint, "POST", e))?;
    let body: TokenResponse = resp
        .json()
        .await
        .context("failed to parse token response")?;
    if let Some(err) = body.error {
        let desc = body.error_description.unwrap_or_default();
        if err == "unauthorized_client" {
            return Err(CodeGrantRefused(desc).into());
        }
        bail!("token exchange failed ({err}): {desc}");
    }
    Ok(Some(DeviceFlowTokens {
        access_token: body
            .access_token
            .context("token response missing access_token")?,
        refresh_token: body.refresh_token.unwrap_or_default(),
        expires_in: body.expires_in.unwrap_or(3600),
        id_token: body.id_token,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_rfc7636_shaped() {
        let v = generate_verifier();
        assert_eq!(v.len(), 64);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
        assert_ne!(v, generate_verifier());
    }

    #[test]
    fn s256_challenge_matches_rfc7636_appendix_b() {
        // RFC 7636 Appendix B, copied from the RFC's raw text.
        const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // cspell:disable-line
        assert_eq!(
            challenge_for(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorize_url_asks_for_the_account_picker() {
        let url = authorize_url(&AuthorizeParams {
            authorization_endpoint: "https://idp.example/oauth/v2/authorize",
            client_id: "cid",
            redirect_uri: "http://localhost:53682",
            scopes: "openid offline_access",
            state: "st",
            code_challenge: "ch",
            prompt: Some(PROMPT_SELECT_ACCOUNT),
        })
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["prompt"], "select_account");
        assert_eq!(q["redirect_uri"], "http://localhost:53682");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["scope"], "openid offline_access");
    }

    #[test]
    fn authorize_url_without_prompt_omits_it() {
        let url = authorize_url(&AuthorizeParams {
            authorization_endpoint: "https://idp.example/authorize",
            client_id: "cid",
            redirect_uri: "http://localhost:1",
            scopes: "openid",
            state: "st",
            code_challenge: "ch",
            prompt: None,
        })
        .unwrap();
        assert!(!url.contains("prompt="));
    }

    #[test]
    fn hub_callback_is_on_its_path_only() {
        let head = "GET /callback?code=abc&state=s1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_callback(head, "/callback", "s1").unwrap(),
            Callback::Code("abc".into())
        );
        let root = "GET /?code=abc&state=s1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_callback(root, "/callback", "s1").unwrap(),
            Callback::Ignore
        );
    }

    #[test]
    fn callback_with_code_and_matching_state() {
        let head = "GET /?code=abc&state=s1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            parse_callback(head, "", "s1").unwrap(),
            Callback::Code("abc".into())
        );
    }

    #[test]
    fn callback_with_wrong_state_is_refused() {
        let head = "GET /?code=abc&state=other HTTP/1.1\r\n\r\n";
        assert!(parse_callback(head, "", "s1").is_err());
    }

    #[test]
    fn callback_error_is_reported() {
        let head =
            "GET /?error=access_denied&error_description=no%20thanks&state=s1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_callback(head, "", "s1").unwrap(),
            Callback::Error {
                error: "access_denied".into(),
                description: Some("no thanks".into()),
            }
        );
    }

    #[test]
    fn stray_requests_are_ignored() {
        for head in [
            "GET /favicon.ico HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "POST /?code=x&state=s1 HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                parse_callback(head, "", "s1").unwrap(),
                Callback::Ignore,
                "{head}"
            );
        }
    }

    #[tokio::test]
    async fn loopback_listener_hands_back_the_code() {
        let (listeners, port) = bind_loopback().await.unwrap();
        let waiter = tokio::spawn(async move { wait_for_code(&listeners, "", "s1").await });
        // A stray favicon request first: must not end the wait.
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(b"GET /favicon.ico HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut sink = Vec::new();
        s.read_to_end(&mut sink).await.unwrap();
        assert!(String::from_utf8_lossy(&sink).starts_with("HTTP/1.1 404"));

        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(b"GET /?code=the-code&state=s1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        assert_eq!(waiter.await.unwrap().unwrap(), "the-code");
    }
}
