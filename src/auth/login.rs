//! `airdress auth login`.
//!
//! Signs in through the hub's own authorization server when the hub serves
//! `/api/cli/oauth-config?v=2` (SPEC-133 D-36): one grant at the hub, then a
//! token per resource (profile schema v3). A hub without one is signed in
//! to at ZITADEL directly, as before (schema v2), and the CLI says so.
//!
//! A profile is never moved from one kind to the other behind the person's
//! back: the move happens here, on a login they ran, and is printed.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::profile::storage::{self, AuthConfig, IdTokenClaims, Profile, ResourceToken};
use crate::ui;

use super::discovery::{HubAsConfig, LoginServer};
use super::{device_flow, discovery, logout, pkce_flow};

const DEFAULT_SCOPES: &str = "openid profile email offline_access";

/// How `auth login` gets its tokens.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoginOpts {
    /// Don't open a browser. Implies the device flow: a loopback redirect
    /// needs a browser on this machine.
    pub no_browser: bool,
    /// Device flow only: don't prefill the user code in the link.
    pub bare_url: bool,
    /// Use the device flow even when the account picker is available
    /// (signing in from a browser on another machine).
    pub device: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Flow {
    /// Authorization code + PKCE with `prompt=select_account`.
    Picker,
    /// RFC 8628 device flow; the IdP cannot be asked to show a picker.
    Device(DeviceReason),
}

#[derive(Debug, PartialEq, Eq)]
enum DeviceReason {
    Asked,
    NoBrowser,
    NoAuthorizationEndpoint,
}

fn choose_flow(opts: LoginOpts, has_authorization_endpoint: bool) -> Flow {
    if opts.device {
        Flow::Device(DeviceReason::Asked)
    } else if opts.no_browser {
        Flow::Device(DeviceReason::NoBrowser)
    } else if !has_authorization_endpoint {
        Flow::Device(DeviceReason::NoAuthorizationEndpoint)
    } else {
        Flow::Picker
    }
}

/// Load the profile, creating it with the default hub endpoint when it does
/// not exist yet. Returns whether it was created. A profile on another hub
/// still needs `profile create --endpoint`.
fn load_or_create_profile(paths: &crate::paths::Paths, name: &str) -> Result<(Profile, bool)> {
    if paths.profile_path(name).exists() {
        return Ok((storage::read_profile(paths, name)?, false));
    }
    let profile = Profile {
        schema_version: storage::SCHEMA_VERSION,
        endpoint: storage::DEFAULT_ENDPOINT.into(),
        auth: None,
        active_airdress: None,
    };
    storage::write_profile(paths, name, &profile)?;
    if storage::read_active_profile(paths)?.is_none() {
        storage::write_active_profile(paths, name)?;
    }
    Ok((profile, true))
}

/// Other profiles whose stored login is the same subject.
fn profiles_holding_subject(
    paths: &crate::paths::Paths,
    except: &str,
    sub: &str,
) -> Result<Vec<String>> {
    if sub.is_empty() {
        return Ok(Vec::new());
    }
    let mut holders = Vec::new();
    for (other, _) in storage::list_profiles(paths)? {
        if other == except {
            continue;
        }
        let Ok(p) = storage::read_profile(paths, &other) else {
            continue;
        };
        let held = match &p.auth {
            Some(AuthConfig::DeviceFlow {
                id_token_claims, ..
            })
            | Some(AuthConfig::Hub {
                id_token_claims, ..
            }) => id_token_claims.sub == sub,
            _ => false,
        };
        if held {
            holders.push(other);
        }
    }
    Ok(holders)
}

fn device_flow_notice(reason: &DeviceReason) {
    let why = match reason {
        DeviceReason::Asked => "--device",
        DeviceReason::NoBrowser => "--no-browser",
        DeviceReason::NoAuthorizationEndpoint => {
            "the identity provider advertises no authorization endpoint"
        }
    };
    ui::warn(format!(
        "using the device flow ({why}): its page cannot offer an account picker and \
         signs in whichever account that browser already uses"
    ));
    ui::note("for a different account, open the link in a private window");
}

async fn obtain_tokens(
    paths: &crate::paths::Paths,
    cfg: &discovery::DeviceFlowConfig,
    scopes: &str,
    opts: LoginOpts,
) -> Result<device_flow::DeviceFlowTokens> {
    let device_opts = device_flow::DeviceFlowOpts {
        no_browser: opts.no_browser,
        bare_url: opts.bare_url,
    };
    let reason = match choose_flow(opts, cfg.authorization_endpoint.is_some()) {
        Flow::Device(reason) => reason,
        Flow::Picker => {
            let authz = cfg.authorization_endpoint.as_deref().unwrap_or_default();
            // Probe first: when the IdP client lacks the code grant, say so
            // before a browser tab is spent on a login that cannot finish.
            // ZITADEL direct only — the hub's CLI client has the code grant
            // by registration.
            let legacy = cfg.resource.is_none();
            if legacy && !pkce_flow::code_grant_allowed(cfg).await.unwrap_or(true) {
                ui::warn(
                    "the identity provider does not allow the account picker for the CLI yet \
                     (its client lacks the authorization_code grant)",
                );
                device_flow_notice(&DeviceReason::NoAuthorizationEndpoint);
                return device_flow::run_device_flow_with_opts(paths, cfg, scopes, device_opts)
                    .await;
            }
            match pkce_flow::run(cfg, authz, scopes, Some(pkce_flow::PROMPT_SELECT_ACCOUNT)).await {
                Ok(Some(tokens)) => return Ok(tokens),
                Ok(None) => {
                    ui::warn("could not open a browser here");
                    DeviceReason::NoBrowser
                }
                Err(e) if e.is::<pkce_flow::CodeGrantRefused>() => {
                    ui::warn(format!("{e}"));
                    ui::note(
                        "the account you picked is now signed in to the browser; \
                         the device page will offer it",
                    );
                    DeviceReason::NoAuthorizationEndpoint
                }
                Err(e) => return Err(e),
            }
        }
    };
    device_flow_notice(&reason);
    device_flow::run_device_flow_with_opts(paths, cfg, scopes, device_opts).await
}

/// What a login is about to do to the credential a profile already holds,
/// said before it happens. `None` when there is nothing to say (no login
/// yet, or the same kind again).
pub(crate) fn migration_notice(
    name: &str,
    old: Option<&AuthConfig>,
    to_hub: bool,
) -> Option<String> {
    match (old, to_hub) {
        (Some(AuthConfig::DeviceFlow { .. }), true) => Some(format!(
            "profile {name} is signed in directly at the identity provider (profile schema v2). \
             This login moves it to the hub's sign-in (schema v3): one grant at the hub and a \
             separate token for each of your airdresses, each accepted only by that airdress. \
             Once you are signed in, the old tokens are revoked and removed from the profile. \
             A CLI older than this one cannot read a v3 profile."
        )),
        (Some(AuthConfig::Hub { .. }), false) => Some(format!(
            "profile {name} holds a hub sign-in (schema v3), but this hub does not offer one any \
             more; this login replaces it with a sign-in directly at the identity provider \
             (schema v2)"
        )),
        (Some(AuthConfig::ClientCredentials { .. } | AuthConfig::JwtProfile { .. }), _) => {
            Some(format!(
                "profile {name} holds a machine credential; this login replaces it with your \
                 account's sign-in"
            ))
        }
        _ => None,
    }
}

/// The notice when the hub does not serve `oauth-config?v=2` yet.
pub(crate) const LEGACY_FALLBACK_NOTICE: &str =
    "this hub does not offer its own sign-in yet (no /api/cli/oauth-config?v=2), so the CLI \
     signs in directly at the identity provider, as older versions did; the profile stays on \
     schema v2 and one token serves the hub and every airdress";

/// Resolve the sign-in server and the flow to run there.
fn plan(server: &LoginServer) -> (discovery::DeviceFlowConfig, String) {
    match server {
        LoginServer::Hub(as_cfg) => (as_cfg.flow(&as_cfg.hub_resource), as_cfg.scopes()),
        LoginServer::Legacy(cfg) => (cfg.clone(), DEFAULT_SCOPES.to_owned()),
    }
}

pub async fn run_with_opts(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
    opts: LoginOpts,
) -> Result<()> {
    let name = match profile_name {
        Some(n) => n.to_string(),
        None => storage::read_active_profile(paths)?.unwrap_or_else(|| "default".to_string()),
    };

    // A missing profile is created on the default hub — the pointer can
    // also outlive its target, e.g. after wiping a stale profile.
    let (profile, created) = load_or_create_profile(paths, &name)?;
    if created {
        ui::say(format!("created profile {name}"));
    }

    let server = discovery::resolve_login_server(&profile.endpoint).await?;
    let to_hub = matches!(server, LoginServer::Hub(_));
    if !to_hub {
        ui::warn(LEGACY_FALLBACK_NOTICE);
    }
    if let Some(notice) = migration_notice(&name, profile.auth.as_ref(), to_hub) {
        ui::warn(notice);
    }
    let (flow, scopes) = plan(&server);
    let tokens = obtain_tokens(paths, &flow, &scopes, opts).await?;

    let endpoint = profile.endpoint.clone();
    let previous = profile.auth.clone();
    let id_token_claims = store(paths, &name, profile, &server, tokens)?;
    if to_hub {
        if let Some(old @ AuthConfig::DeviceFlow { .. }) = previous.as_ref() {
            match logout::revoke_legacy_tokens(&endpoint, old).await {
                Ok(()) => ui::note(
                    "revoked the profile's old identity-provider tokens; it now holds a hub \
                     sign-in (schema v3)",
                ),
                Err(e) => ui::warn(format!(
                    "the profile now holds a hub sign-in (schema v3), but its old \
                     identity-provider tokens could not be revoked ({e:#}); they expire on \
                     their own"
                )),
            }
        }
    }

    let identity = if id_token_claims.email.is_empty() {
        "unknown".to_string()
    } else {
        id_token_claims.email.clone()
    };
    let sub = if id_token_claims.sub.is_empty() {
        String::new()
    } else {
        format!(", subject {}", id_token_claims.sub)
    };
    let kind = if to_hub {
        "through the hub"
    } else {
        "directly at the identity provider"
    };
    ui::ok(format!(
        "profile {name} is signed in {kind} as {identity}{sub}"
    ));

    let holders = profiles_holding_subject(paths, &name, &id_token_claims.sub)?;
    if !holders.is_empty() {
        ui::warn(format!(
            "the same account is already signed in to profile{} {} — both now act as one identity",
            if holders.len() == 1 { "" } else { "s" },
            holders.join(", ")
        ));
        ui::note(format!(
            "to use another account here: `airdress auth logout --profile {name}`, then \
             `airdress auth login --profile {name}` and choose it in the picker"
        ));
    }
    Ok(())
}

/// Write a finished sign-in into the profile in the shape its server
/// calls for.
fn store(
    paths: &crate::paths::Paths,
    name: &str,
    profile: Profile,
    server: &LoginServer,
    tokens: device_flow::DeviceFlowTokens,
) -> Result<IdTokenClaims> {
    match server {
        LoginServer::Hub(as_cfg) => store_hub_tokens(paths, name, profile, as_cfg, tokens),
        LoginServer::Legacy(_) => store_tokens(paths, name, profile, tokens),
    }
}

/// Schema v3: the grant's refresh token, and the hub API's token as the
/// first cached one. The identity comes from the ID token when the hub
/// sent one, else from the access token's own claims (read for display
/// only — the hub verified them; the CLI does not).
pub(crate) fn store_hub_tokens(
    paths: &crate::paths::Paths,
    name: &str,
    profile: Profile,
    as_cfg: &HubAsConfig,
    tokens: device_flow::DeviceFlowTokens,
) -> Result<IdTokenClaims> {
    let from_id = tokens
        .id_token
        .as_ref()
        .and_then(|t| parse_id_token_claims(t.expose()));
    let from_at = parse_id_token_claims(tokens.access_token.expose());
    let id_token_claims = match (from_id, from_at) {
        (Some(mut id), at) => {
            if id.email.is_empty() {
                id.email = at.map(|a| a.email).unwrap_or_default();
            }
            id
        }
        (None, Some(at)) => at,
        (None, None) => IdTokenClaims {
            sub: String::new(),
            email: String::new(),
        },
    };
    let mut id_token_claims = id_token_claims;
    // The hub's tokens carry a subject and no email. When the profile's
    // previous sign-in was the same person, keep the email it knew, so
    // `auth status` still says who this is.
    if id_token_claims.email.is_empty() {
        if let Some(
            AuthConfig::DeviceFlow {
                id_token_claims: old,
                ..
            }
            | AuthConfig::Hub {
                id_token_claims: old,
                ..
            },
        ) = &profile.auth
        {
            if !old.sub.is_empty() && old.sub == id_token_claims.sub {
                id_token_claims.email = old.email.clone();
            }
        }
    }
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(tokens.expires_in);
    let mut access_tokens = BTreeMap::new();
    access_tokens.insert(
        as_cfg.hub_resource.clone(),
        ResourceToken {
            access_token: tokens.access_token,
            expires_at: expires_at.to_rfc3339(),
        },
    );
    let updated = Profile {
        schema_version: storage::HUB_SCHEMA_VERSION,
        auth: Some(AuthConfig::Hub {
            issuer: as_cfg.issuer.clone(),
            client_id: as_cfg.client_id.clone(),
            token_endpoint: as_cfg.token_endpoint.clone(),
            revocation_endpoint: as_cfg.revocation_endpoint.clone(),
            hub_resource: as_cfg.hub_resource.clone(),
            refresh_token: tokens.refresh_token,
            id_token_claims: id_token_claims.clone(),
            access_tokens,
        }),
        ..profile
    };
    storage::write_profile(paths, name, &updated)?;
    Ok(id_token_claims)
}

/// Write what a finished sign-in produced into the profile, and return
/// the claims it carried.
///
/// Stored as `device_flow` whichever flow produced it: the method names
/// the token shape (access + refresh at the IdP's token endpoint), and
/// refresh is identical for both grants.
fn store_tokens(
    paths: &crate::paths::Paths,
    name: &str,
    profile: Profile,
    tokens: device_flow::DeviceFlowTokens,
) -> Result<IdTokenClaims> {
    let id_token_claims = tokens
        .id_token
        .as_ref()
        .and_then(|t| parse_id_token_claims(t.expose()))
        .unwrap_or(IdTokenClaims {
            sub: String::new(),
            email: String::new(),
        });
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(tokens.expires_in);
    let updated = Profile {
        schema_version: storage::SCHEMA_VERSION,
        auth: Some(AuthConfig::DeviceFlow {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: expires_at.to_rfc3339(),
            id_token_claims: id_token_claims.clone(),
            id_token: tokens.id_token.clone(),
        }),
        ..profile
    };
    storage::write_profile(paths, name, &updated)?;
    Ok(id_token_claims)
}

/// A sign-in that has been started and is waiting for the person.
#[derive(Debug)]
pub struct PendingLogin {
    pub profile: String,
    pub verification_url: String,
    pub user_code: String,
    pub expires_in_seconds: u64,
    /// What this sign-in will do to the profile, for the person to read:
    /// the legacy fallback, a schema move. Never empty-handed silence.
    pub notices: Vec<String>,
}

/// Start a device-flow sign-in and finish it in the background.
///
/// For a caller with no terminal of its own: it gets the URL and the
/// code to pass to whoever is at a keyboard, and the profile is written
/// when the person grants it. The device flow rather than the loopback
/// picker, deliberately — a loopback redirect needs a browser on *this*
/// machine, and the whole point here is that the person may be
/// elsewhere.
///
/// Nothing is printed and no browser is opened: this caller's stdout
/// belongs to a protocol.
pub async fn begin_background(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
) -> Result<PendingLogin> {
    let name = match profile_name {
        Some(n) => n.to_string(),
        None => storage::read_active_profile(paths)?.unwrap_or_else(|| "default".to_string()),
    };
    let (profile, _created) = load_or_create_profile(paths, &name)?;
    let server = discovery::resolve_login_server(&profile.endpoint).await?;
    let to_hub = matches!(server, LoginServer::Hub(_));
    let mut notices = Vec::new();
    if !to_hub {
        notices.push(LEGACY_FALLBACK_NOTICE.to_owned());
    }
    notices.extend(migration_notice(&name, profile.auth.as_ref(), to_hub));
    let (cfg, scopes) = plan(&server);
    let start = device_flow::begin(paths, &cfg, &scopes, false).await?;
    let pending = PendingLogin {
        profile: name.clone(),
        verification_url: start.verification_url.clone(),
        user_code: start.user_code.clone(),
        expires_in_seconds: start.expires_in,
        notices,
    };
    // The sign-in finishes after this returns, so the task holds its own.
    let paths = paths.clone();
    tokio::spawn(async move {
        match device_flow::complete(&paths, &cfg, &start).await {
            Ok(tokens) => {
                let endpoint = profile.endpoint.clone();
                let previous = profile.auth.clone();
                if let Err(e) = store(&paths, &name, profile, &server, tokens) {
                    tracing::warn!(error = %format!("{e:#}"), "sign-in finished but the profile could not be written");
                    return;
                }
                if let (true, Some(old @ AuthConfig::DeviceFlow { .. })) =
                    (to_hub, previous.as_ref())
                {
                    if let Err(e) = logout::revoke_legacy_tokens(&endpoint, old).await {
                        tracing::info!(error = %format!("{e:#}"), "old identity-provider tokens were not revoked");
                    }
                }
            }
            Err(e) => tracing::info!(error = %format!("{e:#}"), "sign-in did not complete"),
        }
    });
    Ok(pending)
}

fn parse_id_token_claims(id_token: &str) -> Option<IdTokenClaims> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    use base64_decode_unpadded as decode;
    let payload = decode(parts[1])?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    Some(IdTokenClaims {
        sub: value.get("sub")?.as_str()?.to_string(),
        email: value
            .get("email")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

fn base64_decode_unpadded(input: &str) -> Option<Vec<u8>> {
    let input = input.replace('-', "+").replace('_', "/");
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input,
    };
    base64_decode_std(&padded)
}

fn base64_decode_std(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        let val = alphabet.iter().position(|&c| c == byte)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::storage::temp_paths;

    #[test]
    fn picker_is_the_default() {
        assert_eq!(choose_flow(LoginOpts::default(), true), Flow::Picker);
    }

    #[test]
    fn device_flow_when_asked_or_headless_or_unsupported() {
        let device = LoginOpts {
            device: true,
            ..Default::default()
        };
        let headless = LoginOpts {
            no_browser: true,
            ..Default::default()
        };
        assert_eq!(choose_flow(device, true), Flow::Device(DeviceReason::Asked));
        assert_eq!(
            choose_flow(headless, true),
            Flow::Device(DeviceReason::NoBrowser)
        );
        assert_eq!(
            choose_flow(LoginOpts::default(), false),
            Flow::Device(DeviceReason::NoAuthorizationEndpoint)
        );
    }

    #[test]
    fn login_creates_a_missing_profile_on_the_default_hub() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let (profile, created) = load_or_create_profile(paths, "qa").unwrap();
        assert!(created);
        assert_eq!(profile.endpoint, storage::DEFAULT_ENDPOINT);
        assert!(profile.auth.is_none());
        assert!(paths.profile_path("qa").exists());
        // First profile on the machine becomes the active one.
        assert_eq!(
            storage::read_active_profile(paths).unwrap().as_deref(),
            Some("qa")
        );

        let (_, created_again) = load_or_create_profile(paths, "qa").unwrap();
        assert!(!created_again);
    }

    #[test]
    fn creating_a_second_profile_leaves_the_active_one_alone() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        load_or_create_profile(paths, "default").unwrap();
        load_or_create_profile(paths, "qa").unwrap();
        assert_eq!(
            storage::read_active_profile(paths).unwrap().as_deref(),
            Some("default")
        );
    }

    fn signed_in(sub: &str) -> Profile {
        Profile {
            schema_version: storage::SCHEMA_VERSION,
            endpoint: storage::DEFAULT_ENDPOINT.into(),
            auth: Some(AuthConfig::DeviceFlow {
                access_token: "at".into(),
                refresh_token: "rt".into(),
                expires_at: "2099-01-01T00:00:00Z".into(),
                id_token_claims: IdTokenClaims {
                    sub: sub.into(),
                    email: format!("{sub}@example.com"),
                },
                id_token: None,
            }),
            active_airdress: None,
        }
    }

    #[test]
    fn moving_a_v2_profile_to_the_hub_is_announced() {
        let legacy = signed_in("u1").auth.unwrap();
        let notice = migration_notice("qa", Some(&legacy), true).unwrap();
        assert!(notice.contains("schema v2"), "{notice}");
        assert!(notice.contains("schema v3"), "{notice}");
        assert!(notice.contains("revoked"), "{notice}");
        // Nothing to announce: a first login, or the same kind again.
        assert!(migration_notice("qa", None, true).is_none());
        assert!(migration_notice("qa", Some(&legacy), false).is_none());
    }

    #[test]
    fn falling_back_from_a_hub_sign_in_is_announced() {
        let hub = crate::auth::tokens::test_support::hub_profile("rt", &[])
            .auth
            .unwrap();
        let notice = migration_notice("qa", Some(&hub), false).unwrap();
        assert!(notice.contains("schema v2"), "{notice}");
        assert!(migration_notice("qa", Some(&hub), true).is_none());
    }

    #[test]
    fn same_subject_in_another_profile_is_found() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        storage::write_profile(paths, "default", &signed_in("u1")).unwrap();
        storage::write_profile(paths, "other", &signed_in("u2")).unwrap();
        storage::write_profile(paths, "qa", &signed_in("u1")).unwrap();
        assert_eq!(
            profiles_holding_subject(paths, "qa", "u1").unwrap(),
            vec!["default".to_string()]
        );
        assert!(profiles_holding_subject(paths, "qa", "u3")
            .unwrap()
            .is_empty());
        assert!(profiles_holding_subject(paths, "qa", "")
            .unwrap()
            .is_empty());
    }
}
