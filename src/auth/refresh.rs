//! Silent OAuth refresh-token grant for device-flow profiles.
//!
//! ZITADEL access tokens expire in 15 minutes (per the platform
//! `default_oidc_settings`). Without auto-refresh, the user has to
//! re-run `airdress auth login` every 15 minutes — unacceptable for
//! a CLI that's expected to feel like `gh` or `gcloud`.
//!
//! [`ensure_fresh`] is the entry point. Every code path that's about
//! to use the cached access token (hub API, operator API) should call
//! this first. It's a no-op when the token still has > 60 s of life
//! and otherwise performs an RFC 6749 §6 refresh against the IdP's
//! `token_endpoint`, persisting the rotated `{access_token,
//! refresh_token, expires_at}` to the profile.
//!
//! When the refresh fails (refresh-token revoked, or 90-day idle
//! window hit), the call bails with the existing "run `airdress auth
//! login`" prompt so the user sees one consistent recovery hint.
//!
//! The IdP round-trip sits behind [`TokenRefresher`] so the decision
//! logic (`ensure_fresh_with`) is testable without a network: `auth
//! status` and `auth token` exercise it against a fake.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};

use super::discovery::{self, DeviceFlowConfig};
use crate::exit::Failure;
use crate::http;
use crate::profile::storage::{self, AuthConfig, Profile};
use crate::redact::{self, Redacted};

/// Refresh when fewer than this many seconds remain on the access token.
/// A short positive leeway covers clock skew + the time it takes the
/// hub to validate the token after the CLI sends it.
const REFRESH_LEEWAY_SECS: i64 = 60;

/// Token-endpoint reply to a refresh grant (RFC 6749 §5.1 / §5.2).
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct RefreshResponse {
    #[serde(default, deserialize_with = "redact::persist_opt::deserialize")]
    pub(crate) access_token: Option<Redacted<String>>,
    #[serde(default, deserialize_with = "redact::persist_opt::deserialize")]
    pub(crate) refresh_token: Option<Redacted<String>>,
    pub(crate) expires_in: Option<i64>,
    #[serde(default, deserialize_with = "redact::persist_opt::deserialize")]
    pub(crate) id_token: Option<Redacted<String>>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

/// The one network call in this module, abstracted so callers can be
/// tested with a fake. The real implementation is [`IdpRefresher`].
pub(crate) trait TokenRefresher {
    /// Exchange `refresh_token` for new tokens at the IdP that serves
    /// `endpoint` (the hub URL of the profile).
    async fn refresh(&self, endpoint: &str, refresh_token: &str) -> Result<RefreshResponse>;
}

/// Production refresher: OIDC discovery via the hub, then an RFC 6749
/// §6 grant at the IdP's `token_endpoint`.
#[derive(Debug)]
pub(crate) struct IdpRefresher;

impl TokenRefresher for IdpRefresher {
    async fn refresh(&self, endpoint: &str, refresh_token: &str) -> Result<RefreshResponse> {
        let device_cfg = discovery::resolve_device_flow_config(endpoint).await?;
        do_refresh(&device_cfg, refresh_token).await
    }
}

/// Result of [`ensure_fresh_with`]: the profile as it now stands, and
/// whether this call rotated its tokens.
#[derive(Debug)]
pub(crate) struct Freshness {
    pub(crate) profile: Profile,
    pub(crate) refreshed: bool,
}

/// Ensure the named profile has a fresh access token. Returns the
/// (possibly updated) profile.
///
/// Behaviour:
/// - profile has no `auth` block → bail, point at `auth login`
/// - auth is not `device_flow` (e.g. client_credentials) → pass through
/// - access token still has > REFRESH_LEEWAY_SECS left → pass through
/// - else refresh; on success persist and return; on failure bail
pub async fn ensure_fresh(paths: &crate::paths::Paths, profile_name: &str) -> Result<Profile> {
    ensure_fresh_with(paths, profile_name, &IdpRefresher)
        .await
        .map(|f| f.profile)
}

/// [`ensure_fresh`] with the IdP call injected. Same contract; also
/// reports whether a refresh happened.
pub(crate) async fn ensure_fresh_with<R: TokenRefresher>(
    paths: &crate::paths::Paths,
    profile_name: &str,
    refresher: &R,
) -> Result<Freshness> {
    let profile = storage::read_profile(paths, profile_name)?;

    let (refresh_token, expires_at, id_token_claims, id_token) = match &profile.auth {
        Some(AuthConfig::DeviceFlow {
            refresh_token,
            expires_at,
            id_token_claims,
            id_token,
            ..
        }) => (
            refresh_token.clone(),
            expires_at.clone(),
            id_token_claims.clone(),
            id_token.clone(),
        ),
        // other auth methods don't refresh
        Some(_) => {
            return Ok(Freshness {
                profile,
                refreshed: false,
            })
        }
        None => {
            return Err(Failure::auth(
                "not_signed_in",
                "profile is unauthenticated — run `airdress auth login`",
            )
            .into())
        }
    };

    if !needs_refresh(&expires_at)? {
        return Ok(Freshness {
            profile,
            refreshed: false,
        });
    }
    if refresh_token.expose().is_empty() {
        return Err(Failure::auth(
            "sign_in_expired",
            "access token expired and no refresh token available — run `airdress auth login`",
        )
        .into());
    }

    tracing::debug!(profile = profile_name, "refreshing access token");
    let new_tokens = refresher
        .refresh(&profile.endpoint, refresh_token.expose())
        .await?;

    let new_access = new_tokens
        .access_token
        .ok_or_else(|| anyhow!("refresh response missing access_token"))?;
    // Per RFC 6749 §6 the IdP MAY rotate the refresh token. ZITADEL
    // does. Some others don't — keep the old one when the server
    // doesn't echo a new one.
    let new_refresh = new_tokens
        .refresh_token
        .filter(|s| !s.expose().is_empty())
        .unwrap_or(refresh_token);
    let lifetime = new_tokens.expires_in.unwrap_or(3600);
    let new_expires_at = (Utc::now() + Duration::seconds(lifetime)).to_rfc3339();

    let updated = Profile {
        auth: Some(AuthConfig::DeviceFlow {
            access_token: new_access,
            refresh_token: new_refresh,
            expires_at: new_expires_at,
            // identity claims are stable across refreshes — sub never
            // changes, and we accept the small staleness of email/name
            // until the next interactive login.
            id_token_claims,
            // A refresh may carry a new ID token for the same session;
            // keep the login's one otherwise — logout needs one of them.
            id_token: new_tokens
                .id_token
                .filter(|t| !t.expose().is_empty())
                .or(id_token),
        }),
        ..profile
    };
    storage::write_profile(paths, profile_name, &updated)?;
    Ok(Freshness {
        profile: updated,
        refreshed: true,
    })
}

pub(crate) fn needs_refresh(expires_at: &str) -> Result<bool> {
    let exp: DateTime<Utc> = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|e| anyhow!("invalid expires_at '{expires_at}': {e}"))?
        .with_timezone(&Utc);
    let cutoff = Utc::now() + Duration::seconds(REFRESH_LEEWAY_SECS);
    Ok(exp <= cutoff)
}

async fn do_refresh(cfg: &DeviceFlowConfig, refresh_token: &str) -> Result<RefreshResponse> {
    let client = http::client()?;
    let mut params = HashMap::new();
    params.insert("grant_type", "refresh_token");
    params.insert("refresh_token", refresh_token);
    params.insert("client_id", cfg.client_id.as_str());

    // Same RFC 8628 / OAuth 2.0 token-endpoint convention as the device
    // flow itself: 200 on success, 400 with `{error, error_description}`
    // on a failed refresh. Parse the body either way; map a structured
    // refresh error back at the user with a re-login hint.
    let resp = client
        .post(&cfg.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&cfg.token_endpoint, "POST", e))?;
    let body: RefreshResponse = resp
        .json()
        .await
        .map_err(|e| anyhow!("failed to parse refresh response: {e}"))?;
    if let Some(err) = body.error.as_deref() {
        let desc = body.error_description.as_deref().unwrap_or("");
        return Err(Failure::auth(
            "sign_in_expired",
            format!(
                "refresh failed ({err}{}): run `airdress auth login`",
                if desc.is_empty() {
                    String::new()
                } else {
                    format!(": {desc}")
                }
            ),
        )
        .into());
    }
    Ok(body)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fakes shared by the `auth status` / `auth token` tests.
    use std::cell::Cell;

    use anyhow::Result;
    use chrono::{Duration, Utc};

    use super::{RefreshResponse, TokenRefresher};
    use crate::profile::storage::{self, AuthConfig, IdTokenClaims, Profile};
    use crate::redact::Redacted;

    /// Stands in for the IdP. Answers every call with a clone of
    /// `outcome` and counts how often it was asked.
    #[derive(Debug)]
    pub(crate) struct FakeRefresher {
        outcome: Result<RefreshResponse, String>,
        pub(crate) calls: Cell<u32>,
    }

    impl FakeRefresher {
        pub(crate) fn succeeding(access: &str, refresh: Option<&str>, expires_in: i64) -> Self {
            Self {
                outcome: Ok(RefreshResponse {
                    access_token: Some(access.into()),
                    refresh_token: refresh.map(Redacted::from),
                    expires_in: Some(expires_in),
                    ..Default::default()
                }),
                calls: Cell::new(0),
            }
        }

        pub(crate) fn failing(msg: &str) -> Self {
            Self {
                outcome: Err(msg.into()),
                calls: Cell::new(0),
            }
        }
    }

    impl TokenRefresher for FakeRefresher {
        async fn refresh(&self, _endpoint: &str, _refresh_token: &str) -> Result<RefreshResponse> {
            self.calls.set(self.calls.get() + 1);
            match &self.outcome {
                Ok(r) => Ok(RefreshResponse {
                    access_token: r.access_token.clone(),
                    refresh_token: r.refresh_token.clone(),
                    expires_in: r.expires_in,
                    id_token: r.id_token.clone(),
                    error: None,
                    error_description: None,
                }),
                Err(m) => Err(crate::exit::Failure::auth(
                    "sign_in_expired",
                    format!("refresh failed ({m}): run `airdress auth login`"),
                )
                .into()),
            }
        }
    }

    /// Write a device-flow profile whose access token expires
    /// `secs_from_now` seconds from now (negative = already expired).
    pub(crate) fn write_device_flow_profile(
        paths: &crate::paths::Paths,
        name: &str,
        secs_from_now: i64,
        refresh_token: &str,
    ) {
        let expires_at = (Utc::now() + Duration::seconds(secs_from_now)).to_rfc3339();
        let profile = Profile {
            schema_version: storage::SCHEMA_VERSION,
            endpoint: "https://account.airdress.co".into(),
            auth: Some(AuthConfig::DeviceFlow {
                access_token: "at_old".into(),
                refresh_token: refresh_token.into(),
                expires_at,
                id_token_claims: IdTokenClaims {
                    sub: "user-1".into(),
                    email: "test@example.com".into(),
                },
                id_token: Some("idt_old".into()),
            }),
            active_airdress: None,
        };
        storage::write_profile(paths, name, &profile).unwrap();
    }

    /// Drive a future to completion on a throwaway current-thread
    /// runtime. The tests are plain `#[test]`s because `with_temp_home`
    /// takes a sync closure and `$HOME` must be swapped back before the
    /// next `#[serial(env)]` test runs.
    pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    pub(crate) fn access_token_of(profile: &Profile) -> String {
        match &profile.auth {
            Some(AuthConfig::DeviceFlow { access_token, .. }) => access_token.expose().clone(),
            other => panic!("expected device_flow auth, got {other:?}"),
        }
    }

    pub(crate) fn refresh_token_of(profile: &Profile) -> String {
        match &profile.auth {
            Some(AuthConfig::DeviceFlow { refresh_token, .. }) => refresh_token.expose().clone(),
            other => panic!("expected device_flow auth, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::test_support::*;
    use super::*;

    #[test]
    fn needs_refresh_true_when_expired() {
        let past = (Utc::now() - Duration::seconds(10)).to_rfc3339();
        assert!(needs_refresh(&past).unwrap());
    }

    #[test]
    fn needs_refresh_true_within_leeway() {
        let near = (Utc::now() + Duration::seconds(30)).to_rfc3339();
        assert!(needs_refresh(&near).unwrap());
    }

    #[test]
    fn needs_refresh_false_when_well_in_future() {
        let far = (Utc::now() + Duration::seconds(600)).to_rfc3339();
        assert!(!needs_refresh(&far).unwrap());
    }

    #[test]
    fn needs_refresh_errors_on_garbage() {
        assert!(needs_refresh("not-a-date").is_err());
    }

    #[test]
    fn ensure_fresh_passes_through_when_token_is_live() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", 600, "rt_1");
        let fake = FakeRefresher::failing("must not be called");
        let out = block_on(ensure_fresh_with(paths, "p", &fake));
        let f = out.unwrap();
        assert!(!f.refreshed);
        assert_eq!(fake.calls.get(), 0);
        assert_eq!(access_token_of(&f.profile), "at_old");
    }

    #[test]
    fn ensure_fresh_refreshes_and_persists_when_expired() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -10, "rt_1");
        let fake = FakeRefresher::succeeding("at_new", Some("rt_2"), 1800);
        let f = block_on(ensure_fresh_with(paths, "p", &fake)).unwrap();
        assert!(f.refreshed);
        assert_eq!(fake.calls.get(), 1);
        assert_eq!(access_token_of(&f.profile), "at_new");
        assert_eq!(refresh_token_of(&f.profile), "rt_2");

        // written back — a later read sees the rotated tokens
        let on_disk = storage::read_profile(paths, "p").unwrap();
        assert_eq!(access_token_of(&on_disk), "at_new");
        assert_eq!(refresh_token_of(&on_disk), "rt_2");
        match on_disk.auth {
            Some(AuthConfig::DeviceFlow { expires_at, .. }) => {
                assert!(!needs_refresh(&expires_at).unwrap());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn ensure_fresh_keeps_the_id_token_logout_needs() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -10, "rt_1");
        let fake = FakeRefresher::succeeding("at_new", Some("rt_2"), 1800);
        block_on(ensure_fresh_with(paths, "p", &fake)).unwrap();
        match storage::read_profile(paths, "p").unwrap().auth {
            Some(AuthConfig::DeviceFlow { id_token, .. }) => {
                assert_eq!(
                    id_token.as_ref().map(|t| t.expose().as_str()),
                    Some("idt_old")
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn ensure_fresh_keeps_old_refresh_token_when_idp_omits_it() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -10, "rt_1");
        let fake = FakeRefresher::succeeding("at_new", None, 1800);
        let f = block_on(ensure_fresh_with(paths, "p", &fake)).unwrap();
        assert_eq!(refresh_token_of(&f.profile), "rt_1");
    }

    #[test]
    fn ensure_fresh_fails_and_leaves_profile_alone_when_idp_refuses() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -10, "rt_1");
        let fake = FakeRefresher::failing("invalid_grant");
        let err = block_on(ensure_fresh_with(paths, "p", &fake)).unwrap_err();
        assert!(err.to_string().contains("airdress auth login"), "{err}");
        assert_eq!(
            access_token_of(&storage::read_profile(paths, "p").unwrap()),
            "at_old"
        );
    }

    #[test]
    fn ensure_fresh_fails_without_refresh_token() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -10, "");
        let fake = FakeRefresher::succeeding("at_new", None, 1800);
        let err = block_on(ensure_fresh_with(paths, "p", &fake)).unwrap_err();
        assert!(err.to_string().contains("no refresh token"), "{err}");
        assert_eq!(fake.calls.get(), 0);
    }

    #[test]
    fn ensure_fresh_passes_through_other_auth_methods() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: storage::SCHEMA_VERSION,
            endpoint: "https://account.airdress.co".into(),
            auth: Some(AuthConfig::ClientCredentials {
                client_id: "cid".into(),
                client_secret: "sec".into(),
            }),
            active_airdress: None,
        };
        storage::write_profile(paths, "svc", &profile).unwrap();
        let fake = FakeRefresher::failing("must not be called");
        let f = block_on(ensure_fresh_with(paths, "svc", &fake)).unwrap();
        assert!(!f.refreshed);
        assert_eq!(fake.calls.get(), 0);
    }

    #[test]
    fn ensure_fresh_bails_when_unauthenticated() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: storage::SCHEMA_VERSION,
            endpoint: "https://account.airdress.co".into(),
            auth: None,
            active_airdress: None,
        };
        storage::write_profile(paths, "empty", &profile).unwrap();
        let fake = FakeRefresher::failing("must not be called");
        let err = block_on(ensure_fresh_with(paths, "empty", &fake)).unwrap_err();
        assert!(err.to_string().contains("unauthenticated"), "{err}");
    }
}
