//! Hub airdress API client — wraps `GET/POST/DELETE /api/airdresses`
//! and handles bearer auth + pagination.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::auth::tokens::Audience;
use crate::http;
use crate::paths::Paths;
use crate::profile::storage::{AuthConfig, Profile};
use crate::redact::Redacted;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Airdress {
    pub id: String,
    pub name: String,
    pub fqdn: String,
    pub ipv4_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    items: Vec<Airdress>,
    next_cursor: Option<String>,
}

#[derive(Debug)]
pub struct HubClient {
    endpoint: String,
    /// The hub API's bearer. Never send it to an operator: on a hub
    /// sign-in its audience is the hub, and an operator refuses it.
    bearer: Redacted<String>,
    /// The profile it came from, and where that lives, for per-operator
    /// tokens.
    profile: Option<(Paths, String)>,
    http: reqwest::Client,
}

impl HubClient {
    /// Build a client from the active profile. Silently refreshes the
    /// access token first if it's expired or near expiry. Errors with a
    /// pointer to `airdress auth login` when refresh isn't possible
    /// (no token, wrong auth method, refresh token revoked/expired).
    pub async fn from_profile(paths: &Paths, name: &str) -> Result<Self> {
        let profile = crate::profile::storage::read_profile(paths, name)?;
        let bearer = crate::auth::tokens::access_token(paths, name, Audience::Hub).await?;
        Ok(Self {
            endpoint: profile.endpoint,
            bearer,
            profile: Some((paths.clone(), name.to_owned())),
            http: http::client()?,
        })
    }

    /// The hub API's bearer, refreshed by `from_profile`. For calls to the
    /// hub only (`/api/...`, `/v1/enrollment-tokens`); an operator gets
    /// [`HubClient::operator_bearer`].
    pub fn bearer(&self) -> &Redacted<String> {
        &self.bearer
    }

    /// The bearer for one operator, named by FQDN or base URL. On a hub
    /// sign-in it is a token whose audience is that operator alone
    /// (`https://<fqdn>/v1`); on a legacy sign-in it is the one token the
    /// profile holds.
    pub async fn operator_bearer(&self, operator: &str) -> Result<Redacted<String>> {
        match &self.profile {
            Some((paths, name)) => {
                crate::auth::tokens::access_token(paths, name, Audience::Operator(operator)).await
            }
            None => Ok(self.bearer.clone()),
        }
    }

    /// Hub endpoint URL (no trailing slash guarantee — callers should
    /// `.trim_end_matches('/')` if they're concatenating). Used by
    /// `whoami` to build the probe URL outside the HubClient's own
    /// list/get methods.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn from_profile_value(profile: Profile) -> Result<Self> {
        let auth = profile.auth.ok_or_else(|| {
            anyhow::Error::from(crate::exit::Failure::auth(
                "not_signed_in",
                "profile is unauthenticated — run `airdress auth login` first",
            ))
        })?;
        let access_token = match auth {
            AuthConfig::DeviceFlow { access_token, .. } => access_token,
            AuthConfig::Hub { .. } => bail!(
                "a hub sign-in holds a token per resource — build the client with \
                 HubClient::from_profile"
            ),
            other => bail!(
                "profile uses {} auth — only device_flow is supported for hub API calls",
                auth_method_name(&other)
            ),
        };
        Ok(Self {
            endpoint: profile.endpoint,
            bearer: access_token,
            profile: None,
            http: http::client()?,
        })
    }

    /// SPEC-044 — find the FQDN of the named airdress for direct
    /// operator calls. Reuses the existing list pagination; in the
    /// common case (single page, < 100 airdresses) one HTTP round-trip.
    pub async fn resolve_fqdn(&self, name_or_id_or_fqdn: &str) -> Result<String> {
        let items = self.list().await?;
        match match_airdress(&items, name_or_id_or_fqdn) {
            Ok(a) => Ok(a.fqdn.clone()),
            Err(MatchError::NotFound) => bail!(
                "no airdress matching '{name_or_id_or_fqdn}' on this profile — \
                 run `airdress airdress list`"
            ),
            Err(MatchError::Ambiguous(n)) => {
                bail!("ambiguous: {n} airdresses match '{name_or_id_or_fqdn}' — use the id")
            }
        }
    }

    /// Fetch all airdresses owned by the authenticated user, paginating
    /// through `next_cursor` until exhausted.
    pub async fn list(&self) -> Result<Vec<Airdress>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!("{}/api/airdresses", self.endpoint.trim_end_matches('/'));
            if let Some(c) = &cursor {
                url.push_str("?cursor=");
                url.push_str(&urlencoding(c));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(self.bearer.expose())
                .send()
                .await
                .map_err(|e| http::format_transport_error(&url, "GET", e))?;
            let resp = http::handle_status(resp, "list airdresses").await?;
            let page: ListResponse = resp.json().await.context("failed to parse list response")?;
            out.extend(page.items);
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }
}

/// SPEC-043 — match a user-supplied identifier (id, name, or FQDN)
/// against a list of airdresses owned by the user. Shared by probe,
/// `airdress a use`, and any future subcommand that takes an airdress
/// reference.
#[derive(Debug)]
pub enum MatchError {
    NotFound,
    Ambiguous(usize),
}

pub fn match_airdress<'a>(items: &'a [Airdress], input: &str) -> Result<&'a Airdress, MatchError> {
    let matched: Vec<&Airdress> = items
        .iter()
        .filter(|a| a.id == input || a.name == input || a.fqdn == input)
        .collect();
    match matched.as_slice() {
        [] => Err(MatchError::NotFound),
        [a] => Ok(a),
        many => Err(MatchError::Ambiguous(many.len())),
    }
}

fn auth_method_name(cfg: &AuthConfig) -> &'static str {
    match cfg {
        AuthConfig::DeviceFlow { .. } => "device_flow",
        AuthConfig::Hub { .. } => "hub",
        AuthConfig::ClientCredentials { .. } => "client_credentials",
        AuthConfig::JwtProfile { .. } => "jwt_profile",
    }
}

/// Minimal percent-encoding for cursor values. The hub's cursor format
/// is opaque base64-like text but may contain `+`, `/`, `=` — encode the
/// few that break query strings.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_preserves_unreserved() {
        assert_eq!(urlencoding("abc_123-XYZ.~"), "abc_123-XYZ.~");
    }

    #[test]
    fn urlencoding_escapes_reserved() {
        assert_eq!(urlencoding("a+b/c=d&e"), "a%2Bb%2Fc%3Dd%26e");
    }

    #[test]
    fn airdress_deserializes_minimal() {
        let json = r#"{
            "id": "01HXXX",
            "name": "alice",
            "fqdn": "01hxxx.a.airdr.es",
            "ipv4_address": "23.163.148.11",
            "status": "DnsActive",
            "created_at": "2026-05-15T08:00:00Z"
        }"#;
        let a: Airdress = serde_json::from_str(json).unwrap();
        assert_eq!(a.name, "alice");
        assert_eq!(a.status, "DnsActive");
        assert_eq!(a.ipv4_address, "23.163.148.11");
        assert!(a.ipv6_address.is_none());
    }

    #[test]
    fn airdress_deserializes_with_ipv6() {
        let json = r#"{
            "id": "01HXXX",
            "name": "alice",
            "fqdn": "01hxxx.a.airdr.es",
            "ipv4_address": "23.163.148.11",
            "ipv6_address": "2001:db8::1",
            "status": "DnsActive",
            "created_at": "2026-05-15T08:00:00Z"
        }"#;
        let a: Airdress = serde_json::from_str(json).unwrap();
        assert_eq!(a.ipv6_address.as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn airdress_deserializes_with_label_comment() {
        let json = r#"{
            "id": "01HXXX",
            "name": "alice",
            "fqdn": "01hxxx.a.airdr.es",
            "ipv4_address": "23.163.148.11",
            "label": "Home server",
            "comment": "Main box in the closet",
            "status": "DnsActive",
            "created_at": "2026-05-15T08:00:00Z"
        }"#;
        let a: Airdress = serde_json::from_str(json).unwrap();
        assert_eq!(a.label.as_deref(), Some("Home server"));
        assert_eq!(a.comment.as_deref(), Some("Main box in the closet"));
    }
}
