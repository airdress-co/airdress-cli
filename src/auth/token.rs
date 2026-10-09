//! `airdress auth token` — print a fresh access token and nothing else.
//!
//! The one thing scripts need from the profile is the bearer, and the
//! profile file is the wrong place to read it from: the access token
//! there lives ~30 minutes and only the CLI knows how to trade the
//! refresh token for a new one. This command is that trade, exposed.
//!
//! Which token: a hub sign-in (schema v3) holds one per resource. Without
//! `--airdress` this prints the hub API's; with `--airdress X` it prints
//! the one X's operator accepts (audience `https://<fqdn>/v1`), which no
//! other operator will. A legacy profile (schema v2) has one token for
//! everything and prints it either way.
//!
//! stdout carries the token alone (no trailing decoration, one newline)
//! so `TOKEN=$(airdress auth token)` works; every diagnostic goes to
//! stderr via the error path, with a non-zero exit.

use anyhow::{bail, Result};

use super::refresh::{self, IdpRefresher, TokenRefresher};
use super::tokens::{self, Audience};
use crate::airdresses::client::HubClient;
use crate::profile::storage::{self, AuthConfig};
use crate::redact::Redacted;

pub async fn run(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
    airdress: Option<&str>,
) -> Result<()> {
    let name = storage::resolve_profile_name(paths, profile_name)?;
    let profile = storage::read_profile(paths, &name)?;
    let token = match (&profile.auth, airdress) {
        (Some(AuthConfig::Hub { .. }), None) => {
            tokens::access_token(paths, &name, Audience::Hub).await?
        }
        (Some(AuthConfig::Hub { .. }), Some(a)) => {
            let hub = HubClient::from_profile(paths, &name).await?;
            let fqdn = hub.resolve_fqdn(a).await?;
            tokens::access_token(paths, &name, Audience::Operator(&fqdn)).await?
        }
        _ => fresh_token(paths, Some(&name), &IdpRefresher).await?,
    };
    println!("{}", token.expose());
    Ok(())
}

/// Resolve the profile, refresh if needed, and return the access token.
pub(crate) async fn fresh_token<R: TokenRefresher>(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
    refresher: &R,
) -> Result<Redacted<String>> {
    let name = storage::resolve_profile_name(paths, profile_name)?;
    let fresh = refresh::ensure_fresh_with(paths, &name, refresher).await?;
    if fresh.refreshed {
        tracing::debug!(profile = %name, "access token refreshed and written back");
    }
    match fresh.profile.auth {
        Some(AuthConfig::DeviceFlow { access_token, .. }) => Ok(access_token),
        Some(AuthConfig::Hub { .. }) => tokens::access_token(paths, &name, Audience::Hub).await,
        Some(AuthConfig::ClientCredentials { .. }) => {
            bail!(
                "profile '{name}' uses client_credentials auth — it holds no access token to print"
            )
        }
        Some(AuthConfig::JwtProfile { .. }) => {
            bail!("profile '{name}' uses jwt_profile auth — it holds no access token to print")
        }
        None => Err(crate::exit::Failure::auth(
            "not_signed_in",
            format!("profile '{name}' is unauthenticated — run `airdress auth login`"),
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::auth::refresh::test_support::*;
    use crate::profile::storage::Profile;

    #[test]
    fn live_token_is_printed_as_is() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", 600, "rt_1");
        let fake = FakeRefresher::failing("must not be called");
        let t = block_on(fresh_token(paths, Some("p"), &fake)).unwrap();
        assert_eq!(t.expose(), "at_old");
        assert_eq!(fake.calls.get(), 0);
    }

    #[test]
    fn expired_token_is_refreshed_before_printing() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -60, "rt_1");
        let fake = FakeRefresher::succeeding("at_new", Some("rt_2"), 1800);
        let t = block_on(fresh_token(paths, Some("p"), &fake)).unwrap();
        assert_eq!(t.expose(), "at_new");
        assert_eq!(fake.calls.get(), 1);
        assert_eq!(
            refresh_token_of(&storage::read_profile(paths, "p").unwrap()),
            "rt_2"
        );
    }

    #[test]
    fn failed_refresh_is_an_error_pointing_at_login() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        write_device_flow_profile(paths, "p", -60, "rt_1");
        let fake = FakeRefresher::failing("invalid_grant");
        let err = block_on(fresh_token(paths, Some("p"), &fake)).unwrap_err();
        assert!(err.to_string().contains("airdress auth login"), "{err}");
    }

    #[test]
    fn unauthenticated_profile_is_an_error() {
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
        let fake = FakeRefresher::failing("must not be called");
        let err = block_on(fresh_token(paths, Some("p"), &fake)).unwrap_err();
        assert!(err.to_string().contains("unauthenticated"), "{err}");
        assert_eq!(fake.calls.get(), 0);
    }

    #[test]
    fn client_credentials_profile_has_no_token_to_print() {
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
        let fake = FakeRefresher::failing("must not be called");
        let err = block_on(fresh_token(paths, Some("svc"), &fake)).unwrap_err();
        assert!(err.to_string().contains("client_credentials"), "{err}");
    }
}
