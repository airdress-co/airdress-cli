//! Two-step discovery for the device flow.
//!
//! 1. Fetch `{endpoint}/api/cli/oauth-config` from the hub → `{issuer, client_id}`.
//!    The hub names the upstream IdP issuer and the CLI client_id registered there.
//! 2. Fetch `{issuer}/.well-known/openid-configuration` from the IdP → standard
//!    OIDC Discovery 1.0 / RFC 8414 metadata. Read `device_authorization_endpoint`
//!    (RFC 8628 §4) and `token_endpoint`.
//!
//! That is the **legacy** (v1) path: the CLI signs in at ZITADEL directly.
//! Since SPEC-133 D-36 the CLI asks for `?v=2` first ([`resolve_login_server`]):
//! a hub that runs its own authorization server answers with itself as the
//! issuer, and the CLI reads the hub's RFC 8414 metadata instead. A hub that
//! does not yet ignores the query and answers as v1 — the issuer is then
//! not the hub, and the CLI falls back to ZITADEL direct, saying so.
//!
//! This keeps the CLI binary vendor-agnostic — no IdP URL or client ID baked in.
//! When the IdP changes, only the hub's response changes; CLI binaries already
//! deployed pick up the new wiring on next login.

use anyhow::{bail, Context, Result};

use crate::http;

#[derive(Debug, serde::Deserialize)]
struct HubOauthConfig {
    issuer: String,
    client_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct OidcDiscovery {
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceFlowConfig {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    /// RFC 6749 authorization endpoint — the loopback + PKCE login uses
    /// it, because only there can the CLI ask for `prompt=select_account`
    /// (the device grant carries no prompt; see `auth::pkce_flow`).
    pub authorization_endpoint: Option<String>,
    /// RFC 7009 revocation endpoint, used by `auth logout`.
    pub revocation_endpoint: Option<String>,
    /// OIDC RP-initiated logout endpoint. `auth logout` calls it with the
    /// profile's ID token to end the IdP session that login created.
    pub end_session_endpoint: Option<String>,
    /// RFC 8707 resource indicator of the token requests (code exchange,
    /// device code). Set for the hub's authorization server only; ZITADEL
    /// direct sends none.
    ///
    /// Never sent on the authorization or device authorization request:
    /// there the CLI, a first-party client, names no resource, and the hub
    /// answers with a grant over every airdress the person owns plus the
    /// hub API. Naming one would narrow the grant to it.
    pub resource: Option<String>,
    /// Path of the loopback redirect. ZITADEL's CLI client registers
    /// `http://localhost` with no path; the hub's registers `/callback`.
    pub loopback_path: String,
}

/// The CLI's pre-registered client at the hub's authorization server
/// redirects here, on any loopback port.
pub const HUB_LOOPBACK_PATH: &str = "/callback";

/// Where `auth login` signs in.
#[derive(Debug, Clone)]
pub enum LoginServer {
    /// The hub's own authorization server (profile schema v3).
    Hub(HubAsConfig),
    /// ZITADEL direct, because the hub does not serve `oauth-config?v=2`
    /// yet (profile schema v2).
    Legacy(DeviceFlowConfig),
}

/// What the hub's authorization server publishes, as the CLI uses it.
#[derive(Debug, Clone)]
pub struct HubAsConfig {
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub device_authorization_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    /// The resource indicator of the hub's own API.
    pub hub_resource: String,
}

/// The hub API's resource indicator when the hub's `oauth-config` does not
/// name one: `<issuer>/api` (it covers `/api/*` and `/v1/enrollment-tokens`).
pub fn default_hub_resource(issuer: &str) -> String {
    format!("{}/api", issuer.trim_end_matches('/'))
}

impl HubAsConfig {
    /// The flow configuration for a sign-in whose first token is for
    /// `resource`. A missing device endpoint is left empty; the device
    /// flow refuses it with a message rather than posting to nothing.
    pub fn flow(&self, resource: &str) -> DeviceFlowConfig {
        DeviceFlowConfig {
            device_authorization_endpoint: self
                .device_authorization_endpoint
                .clone()
                .unwrap_or_default(),
            token_endpoint: self.token_endpoint.clone(),
            client_id: self.client_id.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            end_session_endpoint: None,
            resource: Some(resource.to_owned()),
            loopback_path: HUB_LOOPBACK_PATH.to_owned(),
        }
    }

    /// The scopes to ask for: a refresh token is what makes one sign-in
    /// last, so `offline_access` always; the identity scopes when the
    /// server lists them (they put an email on the ID token for
    /// `auth status`).
    pub fn scopes(&self) -> String {
        let wanted = ["openid", "profile", "email", "offline_access"];
        match &self.scopes_supported {
            Some(supported) => {
                let picked: Vec<&str> = wanted
                    .iter()
                    .copied()
                    .filter(|w| *w == "offline_access" || supported.iter().any(|s| s == w))
                    .collect();
                picked.join(" ")
            }
            None => "offline_access".to_owned(),
        }
    }
}

/// The v2 answer of `/api/cli/oauth-config`. A v1 hub sends the first two
/// fields only (and the issuer is ZITADEL's).
#[derive(Debug, serde::Deserialize)]
struct HubOauthConfigV2 {
    issuer: String,
    client_id: String,
    /// The hub API's resource indicator, when the hub names one.
    #[serde(default)]
    hub_resource: Option<String>,
}

/// RFC 8414 §2 metadata, the fields the CLI reads.
#[derive(Debug, serde::Deserialize)]
struct AsMetadata {
    issuer: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    token_endpoint: String,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

/// `scheme://host[:port]` of a URL, lowercased, for comparing origins.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    Some(u.origin().ascii_serialization().to_ascii_lowercase())
}

/// The RFC 8414 §3 metadata URL for `issuer`: the well-known segment goes
/// between the host and any path the issuer has.
pub(crate) fn metadata_url(issuer: &str) -> Result<String> {
    let u = reqwest::Url::parse(issuer).with_context(|| format!("invalid issuer {issuer}"))?;
    let origin = u.origin().ascii_serialization();
    let path = u.path().trim_end_matches('/');
    Ok(format!(
        "{origin}/.well-known/oauth-authorization-server{path}"
    ))
}

/// Decide where `auth login` signs in for the hub at `endpoint`.
///
/// The v2 answer counts only when its issuer is the hub itself: a hub that
/// predates the authorization server ignores `?v=2` and answers with
/// ZITADEL's issuer, which is exactly the legacy configuration.
pub async fn resolve_login_server(endpoint: &str) -> Result<LoginServer> {
    let client = http::client()?;
    let url = format!(
        "{}/api/cli/oauth-config?v=2",
        endpoint.trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    let resp = http::handle_status(resp, "hub oauth config").await?;
    let cfg: HubOauthConfigV2 = resp
        .json()
        .await
        .context("failed to parse hub oauth config response")?;

    let hub_origin = origin_of(endpoint);
    if hub_origin.is_none() || origin_of(&cfg.issuer) != hub_origin {
        let oidc = fetch_oidc_discovery(&client, &cfg.issuer).await?;
        return Ok(LoginServer::Legacy(legacy_config(
            HubOauthConfig {
                issuer: cfg.issuer,
                client_id: cfg.client_id,
            },
            oidc,
        )?));
    }

    let meta_url = metadata_url(&cfg.issuer)?;
    let resp = client
        .get(&meta_url)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&meta_url, "GET", e))?;
    let resp = http::handle_status(resp, "authorization server metadata").await?;
    let meta: AsMetadata = resp
        .json()
        .await
        .context("failed to parse authorization server metadata")?;
    // RFC 8414 §3.3: the issuer in the document must be the one asked for.
    if meta.issuer.trim_end_matches('/') != cfg.issuer.trim_end_matches('/') {
        bail!(
            "the hub's authorization server metadata names issuer {} where {} was expected — \
             refusing to sign in against it",
            meta.issuer,
            cfg.issuer
        );
    }
    let issuer = cfg.issuer.trim_end_matches('/').to_owned();
    Ok(LoginServer::Hub(HubAsConfig {
        hub_resource: cfg
            .hub_resource
            .unwrap_or_else(|| default_hub_resource(&issuer)),
        issuer,
        client_id: cfg.client_id,
        authorization_endpoint: meta.authorization_endpoint,
        token_endpoint: meta.token_endpoint,
        device_authorization_endpoint: meta.device_authorization_endpoint,
        revocation_endpoint: meta.revocation_endpoint,
        scopes_supported: meta.scopes_supported,
    }))
}

fn legacy_config(hub_cfg: HubOauthConfig, oidc: OidcDiscovery) -> Result<DeviceFlowConfig> {
    let device_authorization_endpoint = oidc.device_authorization_endpoint.with_context(|| {
        format!(
            "OIDC issuer {} does not advertise device_authorization_endpoint",
            hub_cfg.issuer
        )
    })?;
    Ok(DeviceFlowConfig {
        device_authorization_endpoint,
        token_endpoint: oidc.token_endpoint,
        client_id: hub_cfg.client_id,
        authorization_endpoint: oidc.authorization_endpoint,
        revocation_endpoint: oidc.revocation_endpoint,
        end_session_endpoint: oidc.end_session_endpoint,
        resource: None,
        loopback_path: String::new(),
    })
}

/// The legacy (v1) configuration: ZITADEL direct. Used by profiles signed
/// in that way (refresh, logout) and by hubs without an authorization
/// server.
pub async fn resolve_device_flow_config(endpoint: &str) -> Result<DeviceFlowConfig> {
    let client = http::client()?;
    let hub_cfg = fetch_hub_config(&client, endpoint).await?;
    let oidc = fetch_oidc_discovery(&client, &hub_cfg.issuer).await?;
    legacy_config(hub_cfg, oidc)
}

async fn fetch_hub_config(client: &reqwest::Client, endpoint: &str) -> Result<HubOauthConfig> {
    let url = format!("{}/api/cli/oauth-config", endpoint.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    let resp = http::handle_status(resp, "hub oauth config").await?;
    resp.json::<HubOauthConfig>()
        .await
        .context("failed to parse hub oauth config response")
}

async fn fetch_oidc_discovery(client: &reqwest::Client, issuer: &str) -> Result<OidcDiscovery> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    let resp = http::handle_status(resp, "OIDC discovery").await?;
    resp.json::<OidcDiscovery>()
        .await
        .context("failed to parse OIDC discovery response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_url_puts_the_well_known_segment_before_the_path() {
        assert_eq!(
            metadata_url("https://account.airdress.co").unwrap(),
            "https://account.airdress.co/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            metadata_url("https://as.example/tenant/").unwrap(),
            "https://as.example/.well-known/oauth-authorization-server/tenant"
        );
    }

    #[test]
    fn origins_compare_scheme_host_and_port() {
        assert_eq!(
            origin_of("https://Account.airdress.co/x"),
            origin_of("https://account.airdress.co")
        );
        assert_ne!(
            origin_of("https://account.airdress.co"),
            origin_of("https://auth.airdress.co")
        );
        assert_ne!(
            origin_of("http://127.0.0.1:1"),
            origin_of("http://127.0.0.1:2")
        );
    }

    fn hub_as(scopes: Option<&[&str]>) -> HubAsConfig {
        HubAsConfig {
            issuer: "https://hub.example".into(),
            client_id: "airdress-cli".into(),
            authorization_endpoint: Some("https://hub.example/oauth/authorize".into()),
            token_endpoint: "https://hub.example/oauth/token".into(),
            device_authorization_endpoint: None,
            revocation_endpoint: None,
            scopes_supported: scopes.map(|s| s.iter().map(|x| x.to_string()).collect()),
            hub_resource: default_hub_resource("https://hub.example"),
        }
    }

    #[test]
    fn hub_scopes_always_ask_for_a_refresh_token() {
        assert_eq!(hub_as(None).scopes(), "offline_access");
        assert_eq!(
            hub_as(Some(&["openid", "email", "mcp"])).scopes(),
            "openid email offline_access"
        );
    }

    #[test]
    fn hub_flow_carries_the_resource_and_the_callback_path() {
        let flow = hub_as(None).flow("https://hub.example/api");
        assert_eq!(flow.resource.as_deref(), Some("https://hub.example/api"));
        assert_eq!(flow.loopback_path, "/callback");
        assert!(flow.device_authorization_endpoint.is_empty());
    }

    #[test]
    fn hub_config_deserializes_minimal() {
        let json = r#"{"issuer":"https://idp.example","client_id":"abc"}"#;
        let cfg: HubOauthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.issuer, "https://idp.example");
        assert_eq!(cfg.client_id, "abc");
    }

    #[test]
    fn oidc_discovery_tolerates_missing_device_endpoint() {
        let json = r#"{"token_endpoint":"https://idp.example/token"}"#;
        let disc: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert!(disc.device_authorization_endpoint.is_none());
    }

    #[test]
    fn oidc_discovery_ignores_unknown_fields() {
        let json = r#"{
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
            "device_authorization_endpoint": "https://idp.example/device",
            "jwks_uri": "https://idp.example/jwks"
        }"#;
        let disc: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(disc.token_endpoint, "https://idp.example/token");
        assert_eq!(
            disc.device_authorization_endpoint.as_deref(),
            Some("https://idp.example/device")
        );
        assert_eq!(
            disc.authorization_endpoint.as_deref(),
            Some("https://idp.example/auth")
        );
        assert!(disc.revocation_endpoint.is_none());
    }
}
