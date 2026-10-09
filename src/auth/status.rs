//! `airdress auth status` — a pure read of the profile.
//!
//! It never refreshes and never writes: asking what the profile holds
//! must not change what it holds. What it owes the user instead is an
//! accurate verdict. A device-flow access token lives ~30 minutes and
//! the refresh token beside it is the credential that actually matters,
//! so "the access token is stale" and "you need a browser" are two
//! different states and are reported as such. The IdP is not consulted
//! to check the refresh token — `refreshable` means "one is on file",
//! and the next hub call (or `airdress auth token`) is what spends it.
//!
//! It names the kind of sign-in (SPEC-133 D-36): `hub` (through the hub's
//! authorization server, profile schema v3, one token per resource) or
//! `zitadel_direct` (the legacy sign-in at the identity provider, schema
//! v2, one token for everything — moved by the next `auth login`).

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::profile::storage::{self, AuthConfig};
use crate::ui;

/// What `auth status` knows about a profile, computed before any
/// rendering so the two output formats cannot drift.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StatusReport {
    pub(crate) profile: String,
    pub(crate) endpoint: String,
    pub(crate) method: &'static str,
    /// `hub`, `zitadel_direct`, `client_credentials`, `jwt_profile` or
    /// `none`.
    pub(crate) kind: &'static str,
    pub(crate) schema_version: u32,
    /// Hub sign-in only: each cached audience-bound token and its expiry.
    pub(crate) resources: Vec<(String, String)>,
    pub(crate) identity: Option<String>,
    pub(crate) sub: Option<String>,
    pub(crate) expires_at: Option<String>,
    pub(crate) status: &'static str,
    /// The cached access token is past its `expires_at` (or that
    /// field is unreadable). Only meaningful for `device_flow`.
    pub(crate) access_token_expired: bool,
    /// A non-empty refresh token is on file, so the next token-bearing
    /// call can renew the access token without a browser.
    pub(crate) refreshable: bool,
}

pub fn run(paths: &crate::paths::Paths, profile_name: Option<&str>, json: bool) -> Result<()> {
    let report = report(paths, profile_name)?;
    render(&report, json)
}

pub(crate) fn report(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
) -> Result<StatusReport> {
    let name = storage::resolve_profile_name(paths, profile_name)?;
    let profile = storage::read_profile(paths, &name)?;

    let kind = profile
        .auth
        .as_ref()
        .map(super::tokens::kind_of)
        .unwrap_or("none");
    let mut resources = Vec::new();
    let (method, identity, sub, expires_at, status, access_token_expired, refreshable) =
        match &profile.auth {
            Some(AuthConfig::Hub {
                refresh_token,
                hub_resource,
                access_tokens,
                id_token_claims,
                ..
            }) => {
                resources = access_tokens
                    .iter()
                    .map(|(r, t)| (r.clone(), t.expires_at.clone()))
                    .collect();
                let hub_exp = access_tokens
                    .get(hub_resource)
                    .map(|t| t.expires_at.clone());
                let expired = hub_exp
                    .as_deref()
                    .map(|e| {
                        DateTime::parse_from_rfc3339(e)
                            .map(|dt| dt < Utc::now())
                            .unwrap_or(true)
                    })
                    .unwrap_or(true);
                let refreshable = !refresh_token.expose().is_empty();
                (
                    "hub",
                    Some(id_token_claims.email.clone()).filter(|e| !e.is_empty()),
                    Some(id_token_claims.sub.clone()),
                    hub_exp,
                    if refreshable {
                        "authenticated"
                    } else {
                        "expired"
                    },
                    expired,
                    refreshable,
                )
            }
            Some(AuthConfig::DeviceFlow {
                refresh_token,
                expires_at,
                id_token_claims,
                ..
            }) => {
                let expired = DateTime::parse_from_rfc3339(expires_at)
                    .map(|dt| dt < Utc::now())
                    .unwrap_or(true);
                let refreshable = !refresh_token.expose().is_empty();
                (
                    "device_flow",
                    Some(id_token_claims.email.clone()),
                    Some(id_token_claims.sub.clone()),
                    Some(expires_at.clone()),
                    // A stale access token beside a refresh token is
                    // still an authenticated profile: the next call
                    // renews it silently. Only a missing refresh token
                    // sends the user back to the browser.
                    if expired && !refreshable {
                        "expired"
                    } else {
                        "authenticated"
                    },
                    expired,
                    refreshable,
                )
            }
            Some(AuthConfig::ClientCredentials { client_id, .. }) => (
                "client_credentials",
                Some(client_id.clone()),
                None,
                None,
                "configured",
                false,
                false,
            ),
            Some(AuthConfig::JwtProfile { key_file }) => (
                "jwt_profile",
                Some(key_file.clone()),
                None,
                None,
                "configured",
                false,
                false,
            ),
            None => ("none", None, None, None, "unauthenticated", false, false),
        };

    Ok(StatusReport {
        profile: name,
        endpoint: profile.endpoint,
        method,
        kind,
        schema_version: profile.schema_version,
        resources,
        identity,
        sub,
        expires_at,
        status,
        access_token_expired,
        refreshable,
    })
}

/// `19:25 UTC` when the instant is today (UTC), otherwise dated.
/// Falls back to the raw string when it does not parse.
fn short_utc(rfc3339: &str) -> String {
    match DateTime::parse_from_rfc3339(rfc3339) {
        Ok(dt) => {
            let dt = dt.with_timezone(&Utc);
            if dt.date_naive() == Utc::now().date_naive() {
                dt.format("%H:%M UTC").to_string()
            } else {
                dt.format("%Y-%m-%d %H:%M UTC").to_string()
            }
        }
        Err(_) => rfc3339.to_string(),
    }
}

fn render(r: &StatusReport, json: bool) -> Result<()> {
    if json {
        let info = serde_json::json!({
            "profile": r.profile,
            "endpoint": r.endpoint,
            "method": r.method,
            "kind": r.kind,
            "schema_version": r.schema_version,
            "tokens": r.resources.iter().map(|(res, exp)| serde_json::json!({
                "resource": res,
                "expires_at": exp,
            })).collect::<Vec<_>>(),
            "identity": r.identity,
            "sub": r.sub,
            "expires_at": r.expires_at,
            "status": r.status,
            "access_token_expired": r.access_token_expired,
            "refreshable": r.refreshable,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Profile:  {}", r.profile);
        println!("Endpoint: {}", r.endpoint);
        match r.kind {
            "hub" => println!(
                "Sign-in:  hub (profile schema v{}; a token per airdress, each accepted only there)",
                r.schema_version
            ),
            "zitadel_direct" => println!(
                "Sign-in:  identity provider direct (legacy, profile schema v{}; one token for \
                 the hub and every airdress)",
                r.schema_version
            ),
            "none" => {}
            other => println!("Sign-in:  {other}"),
        }
        if let Some(id) = &r.identity {
            println!("Identity: {id}");
        }
        if let Some(s) = &r.sub {
            // SPEC-044 — operators need this value in `auth.owner_sub`
            // to accept the user's CLI bearer at owner-protected
            // routes. Surfacing it here saves a JSON-poke + jq pipe.
            println!("Sub:      {s}");
        }
        if let Some(exp) = &r.expires_at {
            println!("Expires:  {exp}");
        }
        if r.status == "authenticated" && r.access_token_expired {
            let when = r.expires_at.as_deref().map(short_utc).unwrap_or_default();
            println!(
                "Status:   authenticated (access token expired {when}, will refresh on next use)"
            );
        } else {
            println!("Status:   {}", r.status);
        }
        for (resource, exp) in &r.resources {
            println!("Token:    {resource} until {}", short_utc(exp));
        }
        if r.kind == "zitadel_direct" {
            ui::note("`airdress auth login` moves this profile to the hub's sign-in when the hub offers it");
        }
        if r.status == "expired" {
            ui::warn("expired — run `airdress auth login` to re-authenticate");
        } else if r.status == "unauthenticated" {
            ui::warn("not authenticated — run `airdress auth login`");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::auth::refresh::test_support::write_device_flow_profile;
    use crate::profile::storage::Profile;

    #[test]
    fn live_token_is_authenticated() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", 600, "rt_1");
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.status, "authenticated");
        assert!(!r.access_token_expired);
        assert!(r.refreshable);
        assert_eq!(r.method, "device_flow");
        assert_eq!(r.identity.as_deref(), Some("test@example.com"));
        assert_eq!(r.sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn stale_token_with_refresh_token_is_still_authenticated() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -60, "rt_1");
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.status, "authenticated");
        assert!(r.access_token_expired);
        assert!(r.refreshable);
    }

    #[test]
    fn stale_token_without_refresh_token_is_expired() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -60, "");
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.status, "expired");
        assert!(r.access_token_expired);
        assert!(!r.refreshable);
    }

    #[test]
    fn live_token_without_refresh_token_is_authenticated_but_not_refreshable() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", 600, "");
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.status, "authenticated");
        assert!(!r.access_token_expired);
        assert!(!r.refreshable);
    }

    #[test]
    fn status_is_a_pure_read() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -60, "rt_1");
        let before = std::fs::read_to_string(paths.profile_path("p")).unwrap();
        report(paths, Some("p")).unwrap();
        let after = std::fs::read_to_string(paths.profile_path("p")).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn unauthenticated_profile() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(
            paths,
            "p",
            &Profile {
                schema_version: storage::SCHEMA_VERSION,
                endpoint: "https://account.airdress.co".into(),
                auth: None,
                active_airdress: None,
            },
        )
        .unwrap();
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.status, "unauthenticated");
        assert_eq!(r.method, "none");
        assert!(!r.access_token_expired);
        assert!(!r.refreshable);
    }

    #[test]
    fn client_credentials_profile_is_configured() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(
            paths,
            "svc",
            &Profile {
                schema_version: storage::SCHEMA_VERSION,
                endpoint: "https://account.airdress.co".into(),
                auth: Some(AuthConfig::ClientCredentials {
                    client_id: "cid".into(),
                    client_secret: "sec".into(),
                }),
                active_airdress: None,
            },
        )
        .unwrap();
        let r = report(paths, Some("svc")).unwrap();
        assert_eq!(r.status, "configured");
        assert_eq!(r.method, "client_credentials");
        assert_eq!(r.identity.as_deref(), Some("cid"));
        assert!(!r.refreshable);
    }

    #[test]
    fn short_utc_formats_today_and_other_days() {
        let today = Utc::now().format("%Y-%m-%dT%H:%M:00Z").to_string();
        let s = short_utc(&today);
        assert!(s.ends_with(" UTC") && s.len() == "19:25 UTC".len(), "{s}");
        assert_eq!(short_utc("2026-01-02T19:25:00Z"), "2026-01-02 19:25 UTC");
        assert_eq!(short_utc("garbage"), "garbage");
    }

    #[test]
    fn a_hub_sign_in_is_named_with_its_tokens() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        let profile = crate::auth::tokens::test_support::hub_profile(
            "rt",
            &[
                ("https://hub.example", 600),
                ("https://vm2.example/v1", 600),
            ],
        );
        storage::write_profile(paths, "p", &profile).unwrap();
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.kind, "hub");
        assert_eq!(r.method, "hub");
        assert_eq!(r.schema_version, storage::HUB_SCHEMA_VERSION);
        assert_eq!(r.status, "authenticated");
        assert!(!r.access_token_expired);
        assert_eq!(r.resources.len(), 2);
        assert_eq!(r.sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn a_legacy_sign_in_is_named_as_such() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", 600, "rt_1");
        let r = report(paths, Some("p")).unwrap();
        assert_eq!(r.kind, "zitadel_direct");
        assert_eq!(r.schema_version, storage::SCHEMA_VERSION);
        assert!(r.resources.is_empty());
    }
}
