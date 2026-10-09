//! `airdress auth logout`: end the IdP session this profile's login
//! created, revoke its tokens, then forget them locally.
//!
//! Deleting the local copy alone left the refresh token valid at ZITADEL
//! for its whole idle window — "logged out" meant "this file forgot", not
//! "this credential is dead". Two things now die at the IdP:
//!
//! - The login's session, via OIDC RP-initiated logout with the profile's
//!   own ID token as `id_token_hint`. ZITADEL ends the session named in
//!   that token by id, with no browser cookie: a device-flow login's `V1_`
//!   session through `terminateV1Session`, a picker (v2 login) session
//!   through `TerminateSessionWithoutTokenCheck` (zitadel
//!   `internal/api/oidc/auth_request.go`, `TerminateSessionFromRequest`).
//!   An expired ID token is still accepted as a hint (zitadel/oidc
//!   `pkg/op/session.go`, `IDTokenHintExpiredError`). The hub's own
//!   `/logout` cannot do this: its hint names the hub's session, not ours.
//! - The tokens, via RFC 7009 — refresh token first (§2.1: revoking it may
//!   take its access tokens with it), then the access token.
//!
//! A hub sign-in (schema v3) is ended by revoking its refresh token at the
//! hub (RFC 7009), which ends the grant and with it every per-airdress
//! token it issued; the cached access tokens are forgotten locally and
//! lapse within their 15 minutes. The hub's browser session is the hub's,
//! not this profile's, and is left alone.

use anyhow::{bail, Result};

use super::discovery;
use crate::http;
use crate::profile::storage::{self, AuthConfig};
use crate::ui;

/// RFC 7009 revocation for a public client (`client_id` in the body, no
/// secret). The server answers 200 for an unknown or already-revoked token
/// (§2.2), so a non-2xx is a real failure.
async fn revoke(endpoint: &str, client_id: &str, token: &str, hint: &str) -> Result<()> {
    let client = http::client()?;
    let resp = client
        .post(endpoint)
        .form(&[
            ("token", token),
            ("token_type_hint", hint),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|e| http::format_transport_error(endpoint, "POST", e))?;
    http::handle_status(resp, "token revocation").await?;
    Ok(())
}

/// RP-initiated logout without a browser. ZITADEL ends the session and
/// answers with a redirect to its logged-out page; that redirect is the
/// success signal, so it is not followed. A rejected hint is a 400 with an
/// OAuth error body.
async fn end_session(endpoint: &str, client_id: &str, id_token: &str) -> Result<()> {
    let client = http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client
        .post(endpoint)
        .form(&[("id_token_hint", id_token), ("client_id", client_id)])
        .send()
        .await
        .map_err(|e| http::format_transport_error(endpoint, "POST", e))?;
    let status = resp.status();
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let err = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("error");
    let desc = body
        .get("error_description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    bail!("end_session answered {status}: {err} {desc}")
}

/// Which tokens to revoke, in order, with their RFC 7009 type hints.
fn revocable(auth: &AuthConfig) -> Vec<(&str, &'static str)> {
    match auth {
        AuthConfig::DeviceFlow {
            access_token,
            refresh_token,
            ..
        } => [
            (refresh_token.expose().as_str(), "refresh_token"),
            (access_token.expose().as_str(), "access_token"),
        ]
        .into_iter()
        .filter(|(t, _)| !t.is_empty())
        .collect(),
        // Machine credentials are the operator's to rotate; logout only
        // forgets them.
        AuthConfig::Hub { refresh_token, .. } => {
            [(refresh_token.expose().as_str(), "refresh_token")]
                .into_iter()
                .filter(|(t, _)| !t.is_empty())
                .collect()
        }
        AuthConfig::ClientCredentials { .. } | AuthConfig::JwtProfile { .. } => Vec::new(),
    }
}

/// Revoke a legacy (ZITADEL direct) sign-in's tokens at the identity
/// provider, without ending its browser session. Used when a login moves a
/// profile onto the hub's sign-in: the browser session at ZITADEL may be the
/// very one that sign-in just used.
pub async fn revoke_legacy_tokens(endpoint: &str, auth: &AuthConfig) -> Result<()> {
    let tokens = revocable(auth);
    if tokens.is_empty() {
        return Ok(());
    }
    let cfg = discovery::resolve_device_flow_config(endpoint).await?;
    let Some(revocation) = cfg.revocation_endpoint.as_deref() else {
        bail!("the identity provider advertises no revocation endpoint");
    };
    for (token, hint) in tokens {
        revoke(revocation, &cfg.client_id, token, hint).await?;
    }
    Ok(())
}

/// End a hub sign-in: revoke its refresh token (the grant) at the hub.
async fn revoke_hub_grant(endpoint: &str, auth: &AuthConfig) -> Result<()> {
    let AuthConfig::Hub {
        client_id,
        revocation_endpoint,
        ..
    } = auth
    else {
        return Ok(());
    };
    let revocation = match revocation_endpoint {
        Some(r) => r.clone(),
        None => match discovery::resolve_login_server(endpoint).await? {
            discovery::LoginServer::Hub(cfg) => cfg
                .revocation_endpoint
                .ok_or_else(|| anyhow::anyhow!("the hub advertises no revocation endpoint"))?,
            discovery::LoginServer::Legacy(_) => {
                bail!("the hub no longer offers its own sign-in, so there is nowhere to revoke it")
            }
        },
    };
    for (token, hint) in revocable(auth) {
        revoke(&revocation, client_id, token, hint).await?;
    }
    Ok(())
}

pub async fn run(paths: &crate::paths::Paths, profile_name: Option<&str>) -> Result<()> {
    let name = storage::resolve_profile_name(paths, profile_name)?;
    let mut profile = storage::read_profile(paths, &name)?;

    let Some(auth) = profile.auth.take() else {
        ui::warn(format!("no cached tokens to clear (profile: {name})"));
        return Ok(());
    };

    if let AuthConfig::Hub { .. } = &auth {
        let result = revoke_hub_grant(&profile.endpoint, &auth).await;
        storage::write_profile(paths, &name, &profile)?;
        ui::ok(format!("logged out of {name}"));
        match result {
            Ok(()) => ui::note(
                "revoked the sign-in at the hub; every airdress token it issued ends with it \
                 (a cached one lapses within 15 minutes)",
            ),
            Err(e) => {
                ui::warn(format!("could not revoke the sign-in at the hub: {e:#}"));
                ui::warn("its refresh token may stay valid at the hub until it expires");
            }
        }
        return Ok(());
    }

    let AuthConfig::DeviceFlow { id_token, .. } = &auth else {
        // Machine credentials: nothing held at the IdP on our behalf.
        storage::write_profile(paths, &name, &profile)?;
        ui::ok(format!("logged out of {name}"));
        return Ok(());
    };

    let mut session_ended = false;
    let mut revoked = false;
    match discovery::resolve_device_flow_config(&profile.endpoint).await {
        Ok(cfg) => {
            match (
                cfg.end_session_endpoint.as_deref(),
                id_token.as_ref().map(|t| t.expose().as_str()),
            ) {
                (Some(endpoint), Some(idt)) if !idt.is_empty() => {
                    match end_session(endpoint, &cfg.client_id, idt).await {
                        Ok(()) => session_ended = true,
                        Err(e) => ui::warn(format!("could not end the sign-in session: {e:#}")),
                    }
                }
                (None, _) => ui::warn("the identity provider advertises no end_session endpoint"),
                _ => ui::warn(
                    "this profile holds no ID token (it was signed in by an older CLI), \
                     so its sign-in session at the identity provider was left to expire",
                ),
            }
            match cfg.revocation_endpoint.as_deref() {
                Some(endpoint) => {
                    revoked = true;
                    for (token, hint) in revocable(&auth) {
                        if let Err(e) = revoke(endpoint, &cfg.client_id, token, hint).await {
                            revoked = false;
                            ui::warn(format!("could not revoke the {hint}: {e:#}"));
                        }
                    }
                }
                None => ui::warn("the identity provider advertises no revocation endpoint"),
            }
        }
        Err(e) => ui::warn(format!("could not reach the identity provider: {e:#}")),
    }

    // Forget locally either way: a token we could not revoke is still
    // better off not sitting on disk.
    storage::write_profile(paths, &name, &profile)?;
    ui::ok(format!("logged out of {name}"));
    if session_ended {
        ui::note("ended the sign-in session this login created at the identity provider");
    }
    if revoked {
        ui::note("revoked its tokens at the identity provider");
    } else {
        ui::warn("the refresh token may stay valid at the identity provider until it expires");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::storage::IdTokenClaims;

    #[test]
    fn refresh_token_is_revoked_before_access_token() {
        let auth = AuthConfig::DeviceFlow {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            expires_at: String::new(),
            id_token_claims: IdTokenClaims {
                sub: "s".into(),
                email: String::new(),
            },
            id_token: None,
        };
        assert_eq!(
            revocable(&auth),
            vec![("rt", "refresh_token"), ("at", "access_token")]
        );
    }

    #[test]
    fn empty_tokens_are_skipped() {
        let auth = AuthConfig::DeviceFlow {
            access_token: "at".into(),
            refresh_token: String::new().into(),
            expires_at: String::new(),
            id_token_claims: IdTokenClaims {
                sub: "s".into(),
                email: String::new(),
            },
            id_token: None,
        };
        assert_eq!(revocable(&auth), vec![("at", "access_token")]);
    }

    #[test]
    fn machine_credentials_are_not_revoked() {
        let auth = AuthConfig::ClientCredentials {
            client_id: "c".into(),
            client_secret: "s".into(),
        };
        assert!(revocable(&auth).is_empty());
    }

    /// One-shot HTTP server answering `status_line` + `body`.
    async fn serve_once(status_line: &'static str, body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/oidc/v1/end_session", l.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            if let Err(e) = s.read(&mut buf).await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nLocation: /ui/v2/login/logout/done\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(e) = s.write_all(resp.as_bytes()).await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        });
        url
    }

    #[tokio::test]
    async fn end_session_redirect_is_success_and_not_followed() {
        // Following it would hit a second request the server never answers.
        let url = serve_once("302 Found", "").await;
        end_session(&url, "cid", "idt").await.unwrap();
    }

    #[tokio::test]
    async fn end_session_rejection_is_reported() {
        let url = serve_once(
            "400 Bad Request",
            r#"{"error":"invalid_request","error_description":"id_token_hint invalid"}"#,
        )
        .await;
        let err = end_session(&url, "cid", "bad")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("id_token_hint invalid"), "{err}");
    }
}
