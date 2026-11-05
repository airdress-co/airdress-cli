//! The right bearer for each thing the CLI talks to.
//!
//! A profile signed in through the hub's authorization server (schema v3,
//! [`AuthConfig::Hub`]) holds one grant and asks for a separate access token
//! per resource (RFC 8707): the hub API under its own resource indicator,
//! and each operator under `https://<fqdn>/v1`. An operator accepts only a
//! token whose audience is itself, so the token the CLI sends one operator is one another
//! refuses — that is the point of the move (SPEC-133 D-36, design §10.6).
//!
//! The refresh token rotates on every use, and the hub treats a second use
//! of the same one as theft and revokes the whole grant. So a refresh runs
//! under a cross-process lock on the profile ([`storage::ProfileLock`]),
//! re-reads the profile once the lock is held (another process may have
//! rotated it meanwhile), and writes the new refresh token back before the
//! lock is released.
//!
//! That write must happen even when whoever asked for the token stops
//! waiting (AIR-173). The hub rotates the moment it answers; a caller
//! dropped between that answer and the write (a cancelled MCP loop, a
//! process ending) loses the only copy of the new refresh token, and the
//! next refresh presents the spent one, which ends the grant. So the real
//! path runs as its own task ([`shield`]) that finishes without its
//! caller, every binary waits for those tasks before it exits
//! ([`settle`]), and a call that got no answer is asked again at once,
//! inside the hub's 30 s grace, which hands back the successor.
//!
//! A legacy profile (schema v2, ZITADEL direct, [`AuthConfig::DeviceFlow`])
//! keeps working as before: its one token is what every caller gets, until
//! the person signs in again. That fallback is never silent: the first time
//! a process hands a legacy token out, it says so on stderr
//! ([`legacy_notice`]), and the MCP server repeats it to the model
//! (SPEC-133 133-H.16).
//!
//! When such a token runs out and a person is at the terminal, the profile
//! is signed in again through the hub, once, instead of being refreshed at
//! the identity provider (SPEC-142 FR-3): every refresh there is a ZITADEL
//! user-day the hub's sign-in does not cost. Without a person (the MCP
//! server, a script, CI) nobody could finish a sign-in, so it refreshes as
//! before and says so.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Duration, Utc};

use super::refresh::{self, RefreshResponse};
use crate::exit::Failure;
use crate::http;
use crate::profile::storage::{self, AuthConfig, ResourceToken};
use crate::redact::Redacted;

/// Renew a cached token when fewer than this many seconds remain.
const LEEWAY_SECS: i64 = 60;

/// The longest one refresh request may take, whatever `--timeout` says.
///
/// Two attempts must fit inside the hub's 30 s reuse grace
/// (`REUSE_GRACE`): when the first answer is lost after the hub rotated,
/// the retry has to arrive while the hub still hands back the successor.
/// With the general 30 s budget, a first attempt that waited it out would
/// retry just after the grace closed, and that retry revokes the grant.
const REFRESH_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Cached tokens for other resources that expired longer ago than this are
/// dropped when the profile is written, so the file does not grow with
/// every airdress ever touched.
const PRUNE_AFTER_HOURS: i64 = 24;

/// Who a bearer is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience<'a> {
    /// The hub's own API (`/api/...`, `/v1/enrollment-tokens`).
    Hub,
    /// An operator, named by FQDN or by a base URL (`https://<fqdn>[:port]`,
    /// as `--operator-url` gives it).
    Operator(&'a str),
}

/// The RFC 8707 resource indicator of an operator: `https://<fqdn>/v1`.
/// A base URL keeps its scheme and port, so a development override names
/// the server it points at.
pub fn operator_resource(operator: &str) -> String {
    let op = operator.trim().trim_end_matches('/');
    if op.contains("://") {
        if let Some(origin) = super::discovery::origin_of(op) {
            return format!("{origin}/v1");
        }
    }
    format!("https://{}/v1", op.trim_matches('/').to_ascii_lowercase())
}

/// What kind of credential a profile holds, as `auth status` names it.
pub fn kind_of(auth: &AuthConfig) -> &'static str {
    match auth {
        AuthConfig::Hub { .. } => "hub",
        AuthConfig::DeviceFlow { .. } => "zitadel_direct",
        AuthConfig::ClientCredentials { .. } => "client_credentials",
        AuthConfig::JwtProfile { .. } => "jwt_profile",
    }
}

/// What a legacy (schema v2, identity-provider direct) sign-in means for
/// the caller, as one sentence. `None` for any other kind of profile.
///
/// The token such a profile holds is accepted by every airdress on the
/// account alike; that is the property the hub's sign-in removes, and the
/// reason the fallback to it is said out loud rather than taken quietly.
pub fn legacy_notice(profile_name: &str, auth: Option<&AuthConfig>) -> Option<String> {
    matches!(auth, Some(AuthConfig::DeviceFlow { .. })).then(|| {
        format!(
            "profile {profile_name} is still signed in directly at the identity provider \
             (profile schema v2): one token that every one of your airdresses accepts. \
             Run `airdress auth login` to move it to the hub's sign-in, where each \
             airdress gets a token only it accepts."
        )
    })
}

/// Set once this process has said [`legacy_notice`] on stderr.
static LEGACY_NOTICE_SAID: AtomicBool = AtomicBool::new(false);

/// Say [`legacy_notice`] on stderr, once per process. stderr, never stdout:
/// `auth token` prints the token alone there, and for the MCP server stdout
/// is the protocol.
fn say_legacy_once(profile_name: &str, auth: Option<&AuthConfig>) {
    if let Some(notice) = legacy_notice(profile_name, auth) {
        if !LEGACY_NOTICE_SAID.swap(true, Ordering::Relaxed) {
            eprintln!("airdress: notice: {notice}");
        }
    }
}

/// The token-endpoint call, abstracted for tests.
pub(crate) trait ResourceRefresher {
    async fn refresh(
        &self,
        token_endpoint: &str,
        client_id: &str,
        refresh_token: &str,
        resource: &str,
    ) -> Result<RefreshResponse>;
}

/// The real one: RFC 6749 §6 with an RFC 8707 `resource`.
#[derive(Debug)]
pub(crate) struct HubRefresher;

impl ResourceRefresher for HubRefresher {
    async fn refresh(
        &self,
        token_endpoint: &str,
        client_id: &str,
        refresh_token: &str,
        resource: &str,
    ) -> Result<RefreshResponse> {
        let client = http::client()?;
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", client_id);
        params.insert("resource", resource);
        let resp = client
            .post(token_endpoint)
            .timeout(REFRESH_REQUEST_TIMEOUT)
            .form(&params)
            .send()
            .await
            .map_err(|e| http::format_transport_error(token_endpoint, "POST", e))?;
        let status = resp.status();
        let body: RefreshResponse = resp.json().await.map_err(|e| {
            anyhow!("failed to parse the hub's token response (HTTP {status}): {e}")
        })?;
        Ok(body)
    }
}

/// A fresh access token for `audience`, from the named profile.
pub async fn access_token(
    paths: &crate::paths::Paths,
    profile_name: &str,
    audience: Audience<'_>,
) -> Result<Redacted<String>> {
    let paths = paths.clone();
    let profile_name = profile_name.to_owned();
    let operator = match audience {
        Audience::Hub => None,
        Audience::Operator(op) => Some(op.to_owned()),
    };
    shield(async move {
        let audience = operator
            .as_deref()
            .map_or(Audience::Hub, Audience::Operator);
        access_token_moving(&paths, &profile_name, audience, &HubRefresher, &SignInAgain).await
    })
    .await?
}

/// Refreshes started by this process and not finished yet.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
/// Woken each time one finishes.
static FINISHED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Counts one shielded task for as long as it lives, including when the
/// runtime drops it.
struct InFlight;

impl InFlight {
    fn start() -> Self {
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        FINISHED.notify_waiters();
    }
}

/// Run `fut` as its own task and wait for it. Dropping the returned
/// future stops the waiting, never the task: a refresh the hub has
/// already answered still reaches the profile file.
pub(crate) async fn shield<T: Send + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
) -> Result<T> {
    let in_flight = InFlight::start();
    tokio::spawn(async move {
        let _in_flight = in_flight;
        fut.await
    })
    .await
    .map_err(|e| anyhow!("the token refresh task failed: {e}"))
}

/// How long a binary waits at exit for [`shield`]ed refreshes.
///
/// Long enough for a refresh whose answer is on its way (they take well
/// under a second); short enough that a process asked to stop still does.
pub const SETTLE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait, within `bound`, until no [`shield`]ed refresh is running. Every
/// binary calls this before it returns from `main`: the runtime drops
/// unfinished tasks when it shuts down, which is exactly the lost write
/// [`shield`] exists to prevent. Returns whether they all finished.
pub async fn settle(bound: std::time::Duration) -> bool {
    let all_done = async {
        loop {
            let finished = FINISHED.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if IN_FLIGHT.load(Ordering::SeqCst) == 0 {
                return;
            }
            finished.await;
        }
    };
    let settled = tokio::time::timeout(bound, all_done).await.is_ok();
    if !settled {
        tracing::warn!(
            left = IN_FLIGHT.load(Ordering::SeqCst),
            "a token refresh was still running at exit; its sign-in may need `airdress auth login`"
        );
    }
    settled
}

/// Moving a legacy profile to the hub's sign-in, abstracted for tests.
pub(crate) trait LegacyMove {
    /// Whether a person is at the terminal to finish a sign-in.
    fn person_present(&self) -> bool;
    /// Sign the profile in through the hub. `Ok(false)` when the hub
    /// offers no sign-in of its own, so there is nowhere to move to.
    async fn move_to_hub(&self, paths: &crate::paths::Paths, profile_name: &str) -> Result<bool>;
}

/// The real one: `airdress auth login`, as the person would have run it.
#[derive(Debug)]
pub(crate) struct SignInAgain;

impl LegacyMove for SignInAgain {
    fn person_present(&self) -> bool {
        use std::io::IsTerminal as _;
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    async fn move_to_hub(&self, paths: &crate::paths::Paths, profile_name: &str) -> Result<bool> {
        let profile = storage::read_profile(paths, profile_name)?;
        let server = super::discovery::resolve_login_server(&profile.endpoint).await?;
        if !matches!(server, super::discovery::LoginServer::Hub(_)) {
            return Ok(false);
        }
        eprintln!(
            "airdress: notice: profile {profile_name}'s sign-in at the identity provider has run              out; signing it in through the hub instead, once (it will not be asked again)"
        );
        super::login::run_with_opts(paths, Some(profile_name), Default::default()).await?;
        Ok(true)
    }
}

/// Never moves: the second pass after a move, so a profile that is somehow
/// still legacy cannot loop back into another sign-in; and tests.
pub(crate) struct NeverMove;

impl LegacyMove for NeverMove {
    fn person_present(&self) -> bool {
        false
    }
    async fn move_to_hub(&self, _: &crate::paths::Paths, _: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
pub(crate) async fn access_token_with<R: ResourceRefresher>(
    paths: &crate::paths::Paths,
    profile_name: &str,
    audience: Audience<'_>,
    refresher: &R,
) -> Result<Redacted<String>> {
    access_token_moving(paths, profile_name, audience, refresher, &NeverMove).await
}

pub(crate) async fn access_token_moving<R: ResourceRefresher, M: LegacyMove>(
    paths: &crate::paths::Paths,
    profile_name: &str,
    audience: Audience<'_>,
    refresher: &R,
    mover: &M,
) -> Result<Redacted<String>> {
    let profile = storage::read_profile(paths, profile_name)?;
    match &profile.auth {
        Some(AuthConfig::Hub {
            hub_resource,
            access_tokens,
            ..
        }) => {
            let resource = match audience {
                Audience::Hub => hub_resource.clone(),
                Audience::Operator(op) => operator_resource(op),
            };
            if let Some(t) = live(access_tokens.get(&resource)) {
                return Ok(t);
            }
            refresh_resource(paths, profile_name, &resource, refresher).await
        }
        // Legacy: one ZITADEL token, whatever the audience. Said, once.
        Some(auth @ AuthConfig::DeviceFlow { expires_at, .. }) => {
            // Run out, and somebody to sign in: move to the hub rather than
            // refresh at the identity provider. A sign-in that fails or is
            // abandoned leaves the profile as it was, and the refresh below
            // still serves this command.
            if refresh::needs_refresh(expires_at)? && mover.person_present() {
                match mover.move_to_hub(paths, profile_name).await {
                    Ok(true) => {
                        return Box::pin(access_token_moving(
                            paths,
                            profile_name,
                            audience,
                            refresher,
                            &NeverMove,
                        ))
                        .await;
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!(
                        "airdress: warning: signing profile {profile_name} in through the hub                          failed ({e:#}); refreshing its old sign-in instead"
                    ),
                }
            }
            say_legacy_once(profile_name, Some(auth));
            let fresh = refresh::ensure_fresh(paths, profile_name).await?;
            match fresh.auth {
                Some(AuthConfig::DeviceFlow { access_token, .. }) => Ok(access_token),
                _ => bail!("profile '{profile_name}' changed while it was being read; try again"),
            }
        }
        Some(other) => Err(Failure::auth(
            "not_signed_in",
            format!(
                "profile '{profile_name}' uses {} auth — it holds no account token; \
                 run `airdress auth login`",
                kind_of(other)
            ),
        )
        .into()),
        None => Err(Failure::auth(
            "not_signed_in",
            format!("profile '{profile_name}' is unauthenticated — run `airdress auth login`"),
        )
        .into()),
    }
}

fn live(t: Option<&ResourceToken>) -> Option<Redacted<String>> {
    let t = t?;
    let exp = DateTime::parse_from_rfc3339(&t.expires_at).ok()?;
    (exp.with_timezone(&Utc) > Utc::now() + Duration::seconds(LEEWAY_SECS))
        .then(|| t.access_token.clone())
}

async fn refresh_resource<R: ResourceRefresher>(
    paths: &crate::paths::Paths,
    profile_name: &str,
    resource: &str,
    refresher: &R,
) -> Result<Redacted<String>> {
    let _lock = storage::ProfileLock::acquire(paths, profile_name).await?;
    // Under the lock: the profile as it is now, not as it was before we
    // waited — another process may have rotated the refresh token.
    let mut profile = storage::read_profile(paths, profile_name)?;
    let Some(AuthConfig::Hub {
        token_endpoint,
        client_id,
        refresh_token,
        access_tokens,
        ..
    }) = profile.auth.as_mut()
    else {
        bail!("profile '{profile_name}' changed while it was being read; try again");
    };
    if let Some(t) = live(access_tokens.get(resource)) {
        return Ok(t);
    }
    if refresh_token.expose().is_empty() {
        return Err(Failure::auth(
            "not_signed_in",
            format!(
                "profile '{profile_name}' holds no refresh token — run \
                 `airdress auth login --profile {profile_name}`"
            ),
        )
        .into());
    }

    tracing::debug!(
        profile = profile_name,
        resource,
        "requesting an access token"
    );
    let resp = match refresher
        .refresh(token_endpoint, client_id, refresh_token.expose(), resource)
        .await
    {
        Ok(resp) => resp,
        // No answer (a timeout, a dropped connection, a body that did not
        // parse). The hub may have rotated anyway, and then the token on
        // file is spent. Asked again now, inside the hub's 30 s grace, it
        // hands back the successor; if it never rotated, this is simply
        // the refresh. Later, the same token would end the grant.
        Err(first) => {
            tracing::warn!(
                profile = profile_name,
                resource,
                error = %format!("{first:#}"),
                "no answer to a token refresh; asking again at once"
            );
            refresher
                .refresh(token_endpoint, client_id, refresh_token.expose(), resource)
                .await
                .map_err(|again| {
                    again.context(format!(
                        "renewing profile '{profile_name}' got no answer twice (first: {first:#})"
                    ))
                })?
        }
    };
    if let Some(err) = resp.error.as_deref() {
        let desc = resp.error_description.as_deref().unwrap_or("");
        let detail = if desc.is_empty() {
            err.to_owned()
        } else {
            format!("{err}: {desc}")
        };
        if err == "invalid_target" {
            bail!(
                "the hub will not issue a token for {resource} ({detail}) — this account does \
                 not own that airdress, or the hub does not know it yet"
            );
        }
        return Err(Failure::auth(
            "sign_in_expired",
            format!(
                "the hub refused to renew profile '{profile_name}' ({detail}): run \
                 `airdress auth login --profile {profile_name}`"
            ),
        )
        .into());
    }
    let access = resp
        .access_token
        .filter(|t| !t.expose().is_empty())
        .ok_or_else(|| anyhow!("the hub's token response carried no access_token"))?;
    // The hub rotates on every use. A server that does not keep the
    // old one, which stays valid there.
    if let Some(next) = resp.refresh_token.filter(|t| !t.expose().is_empty()) {
        *refresh_token = next;
    }
    let now = Utc::now();
    let lifetime = resp.expires_in.unwrap_or(900);
    access_tokens.retain(|_, t| {
        DateTime::parse_from_rfc3339(&t.expires_at)
            .map(|e| e.with_timezone(&Utc) > now - Duration::hours(PRUNE_AFTER_HOURS))
            .unwrap_or(false)
    });
    access_tokens.insert(
        resource.to_owned(),
        ResourceToken {
            access_token: access.clone(),
            expires_at: (now + Duration::seconds(lifetime)).to_rfc3339(),
        },
    );
    storage::write_profile(paths, profile_name, &profile)?;
    Ok(access)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use anyhow::Result;
    use chrono::{Duration, Utc};

    use super::*;
    use crate::profile::storage::{IdTokenClaims, Profile};

    /// A hub that rotates its refresh token on every use and revokes the
    /// grant when an old one comes back, like the real one (design §10.4).
    #[derive(Debug)]
    pub(crate) struct FakeHub {
        pub(crate) current: Mutex<String>,
        pub(crate) calls: Mutex<Vec<(String, String)>>,
        pub(crate) revoked: Mutex<bool>,
        pub(crate) refuse_target: Option<String>,
    }

    impl FakeHub {
        pub(crate) fn new(refresh: &str) -> Self {
            Self {
                current: Mutex::new(refresh.into()),
                calls: Mutex::new(Vec::new()),
                revoked: Mutex::new(false),
                refuse_target: None,
            }
        }
    }

    impl ResourceRefresher for FakeHub {
        async fn refresh(
            &self,
            _token_endpoint: &str,
            _client_id: &str,
            refresh_token: &str,
            resource: &str,
        ) -> Result<RefreshResponse> {
            self.calls
                .lock()
                .unwrap()
                .push((refresh_token.to_owned(), resource.to_owned()));
            let mut current = self.current.lock().unwrap();
            if *self.revoked.lock().unwrap() || *current != refresh_token {
                *self.revoked.lock().unwrap() = true;
                return Ok(RefreshResponse {
                    error: Some("invalid_grant".into()),
                    ..Default::default()
                });
            }
            if self.refuse_target.as_deref() == Some(resource) {
                return Ok(RefreshResponse {
                    error: Some("invalid_target".into()),
                    ..Default::default()
                });
            }
            let n = self.calls.lock().unwrap().len();
            *current = format!("rt_{n}");
            Ok(RefreshResponse {
                access_token: Some(format!("at[{resource}]#{n}").into()),
                refresh_token: Some(current.clone().into()),
                expires_in: Some(900),
                ..Default::default()
            })
        }
    }

    pub(crate) fn hub_profile(refresh: &str, cached: &[(&str, i64)]) -> Profile {
        let mut access_tokens = BTreeMap::new();
        for (resource, secs) in cached {
            access_tokens.insert(
                resource.to_string(),
                ResourceToken {
                    access_token: format!("cached[{resource}]").into(),
                    expires_at: (Utc::now() + Duration::seconds(*secs)).to_rfc3339(),
                },
            );
        }
        Profile {
            schema_version: storage::HUB_SCHEMA_VERSION,
            endpoint: "https://hub.example".into(),
            auth: Some(AuthConfig::Hub {
                issuer: "https://hub.example".into(),
                client_id: "airdress-cli".into(),
                token_endpoint: "https://hub.example/oauth/token".into(),
                revocation_endpoint: None,
                hub_resource: "https://hub.example".into(),
                refresh_token: refresh.into(),
                id_token_claims: IdTokenClaims {
                    sub: "user-1".into(),
                    email: "ada@example.com".into(),
                },
                access_tokens,
            }),
            active_airdress: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::test_support::*;
    use super::*;
    use crate::auth::refresh::test_support::block_on;

    fn stored_refresh(paths: &crate::paths::Paths, name: &str) -> String {
        match storage::read_profile(paths, name).unwrap().auth {
            Some(AuthConfig::Hub { refresh_token, .. }) => refresh_token.expose().clone(),
            other => panic!("expected hub auth, got {other:?}"),
        }
    }

    #[test]
    fn operator_resource_is_the_v1_root_of_the_fqdn() {
        assert_eq!(
            operator_resource("00000000-0000-7000-8000-000000000002.a.airdr.es"),
            "https://00000000-0000-7000-8000-000000000002.a.airdr.es/v1"
        );
        assert_eq!(
            operator_resource("https://00000000-0000-7000-8000-000000000002.a.airdr.es/"),
            "https://00000000-0000-7000-8000-000000000002.a.airdr.es/v1"
        );
        assert_eq!(
            operator_resource("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/v1"
        );
    }

    #[test]
    fn a_live_cached_token_is_used_without_the_hub() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(
            paths,
            "p",
            &hub_profile("rt_0", &[("https://vm2.example/v1", 600)]),
        )
        .unwrap();
        let hub = FakeHub::new("rt_0");
        let t = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
        ))
        .unwrap();
        assert_eq!(t.expose(), "cached[https://vm2.example/v1]");
        assert!(hub.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn each_operator_gets_its_own_token_and_the_refresh_token_rotates() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(paths, "p", &hub_profile("rt_0", &[])).unwrap();
        let hub = FakeHub::new("rt_0");

        let vm2 = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
        ))
        .unwrap();
        assert_eq!(stored_refresh(paths, "p"), "rt_1");
        let vm3 = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm3.example"),
            &hub,
        ))
        .unwrap();
        assert_eq!(stored_refresh(paths, "p"), "rt_2");
        let hub_api = block_on(access_token_with(paths, "p", Audience::Hub, &hub)).unwrap();

        assert_eq!(vm2.expose(), "at[https://vm2.example/v1]#1");
        assert_eq!(vm3.expose(), "at[https://vm3.example/v1]#2");
        assert_eq!(hub_api.expose(), "at[https://hub.example]#3");
        let calls = hub.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                ("rt_0".into(), "https://vm2.example/v1".into()),
                ("rt_1".into(), "https://vm3.example/v1".into()),
                ("rt_2".into(), "https://hub.example".into()),
            ]
        );
        assert!(!*hub.revoked.lock().unwrap());

        // Cached now: no fourth call.
        let again = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
        ))
        .unwrap();
        assert_eq!(again, vm2);
        assert_eq!(hub.calls.lock().unwrap().len(), 3);
        assert_eq!(
            storage::read_profile(paths, "p").unwrap().schema_version,
            storage::HUB_SCHEMA_VERSION
        );
    }

    #[test]
    fn an_expired_token_is_renewed() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(
            paths,
            "p",
            &hub_profile("rt_0", &[("https://vm2.example/v1", 30)]),
        )
        .unwrap();
        let hub = FakeHub::new("rt_0");
        let t = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
        ))
        .unwrap();
        assert_eq!(t.expose(), "at[https://vm2.example/v1]#1");
    }

    #[test]
    fn a_refused_grant_points_at_login_and_keeps_the_profile() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(paths, "p", &hub_profile("rt_stale", &[])).unwrap();
        let hub = FakeHub::new("rt_other");
        let err = block_on(access_token_with(paths, "p", Audience::Hub, &hub)).unwrap_err();
        // Named: the person may have several profiles, and the plugin's is
        // not the active one (AIR-173).
        assert!(
            err.to_string().contains("airdress auth login --profile p"),
            "{err}"
        );
        assert_eq!(stored_refresh(paths, "p"), "rt_stale");
    }

    #[test]
    fn an_airdress_the_account_does_not_own_is_named() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        storage::write_profile(paths, "p", &hub_profile("rt_0", &[])).unwrap();
        let mut hub = FakeHub::new("rt_0");
        hub.refuse_target = Some("https://not-mine.example/v1".into());
        let err = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("not-mine.example"),
            &hub,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("does not own"), "{err}");
    }

    #[test]
    fn a_legacy_profile_gets_its_one_token_for_every_audience() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "p", 600, "rt_1");
        let hub = FakeHub::new("unused");
        let a = block_on(access_token_with(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
        ))
        .unwrap();
        let b = block_on(access_token_with(paths, "p", Audience::Hub, &hub)).unwrap();
        assert_eq!(a.expose(), "at_old");
        assert_eq!(b.expose(), "at_old");
        assert!(hub.calls.lock().unwrap().is_empty());
        assert!(LEGACY_NOTICE_SAID.load(Ordering::Relaxed));
        // Not migrated behind the person's back.
        assert!(matches!(
            storage::read_profile(paths, "p").unwrap().auth,
            Some(AuthConfig::DeviceFlow { .. })
        ));
    }

    /// A stand-in for `auth login`: writes `after` into the profile and
    /// counts how often it was asked.
    struct FakeMove {
        person: bool,
        after: Option<crate::profile::storage::Profile>,
        calls: std::cell::Cell<usize>,
    }

    impl LegacyMove for FakeMove {
        fn person_present(&self) -> bool {
            self.person
        }
        async fn move_to_hub(&self, paths: &crate::paths::Paths, name: &str) -> Result<bool> {
            self.calls.set(self.calls.get() + 1);
            match &self.after {
                Some(p) => {
                    storage::write_profile(paths, name, p).unwrap();
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    #[test]
    fn a_run_out_legacy_profile_moves_to_the_hub_when_a_person_is_there() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "p", -10, "rt_1");
        let hub = FakeHub::new("rt_0");
        let mover = FakeMove {
            person: true,
            after: Some(hub_profile("rt_0", &[])),
            calls: Default::default(),
        };
        let t = block_on(access_token_moving(
            paths,
            "p",
            Audience::Operator("vm2.example"),
            &hub,
            &mover,
        ))
        .unwrap();
        assert_eq!(mover.calls.get(), 1);
        // The token comes from the hub, for that operator alone.
        assert_eq!(t.expose(), "at[https://vm2.example/v1]#1");
        assert!(matches!(
            storage::read_profile(paths, "p").unwrap().auth,
            Some(AuthConfig::Hub { .. })
        ));
    }

    #[test]
    fn a_live_legacy_token_is_used_without_a_sign_in() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "p", 600, "rt_1");
        let mover = FakeMove {
            person: true,
            after: Some(hub_profile("rt_0", &[])),
            calls: Default::default(),
        };
        let t = block_on(access_token_moving(
            paths,
            "p",
            Audience::Hub,
            &FakeHub::new("unused"),
            &mover,
        ))
        .unwrap();
        assert_eq!(t.expose(), "at_old");
        assert_eq!(mover.calls.get(), 0, "nothing ran out, so nothing is asked");
    }

    #[test]
    fn a_sign_in_that_leaves_the_profile_legacy_is_not_asked_for_twice() {
        let (_home, paths) = storage::temp_paths();
        let paths = &paths;
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "p", -10, "rt_1");
        // The "sign-in" writes a live legacy profile: still not a hub one.
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "live", 600, "rt_2");
        let still_legacy = storage::read_profile(paths, "live").unwrap();
        let mover = FakeMove {
            person: true,
            after: Some(still_legacy),
            calls: Default::default(),
        };
        let t = block_on(access_token_moving(
            paths,
            "p",
            Audience::Hub,
            &FakeHub::new("unused"),
            &mover,
        ))
        .unwrap();
        assert_eq!(mover.calls.get(), 1, "one sign-in, never a loop of them");
        assert_eq!(t.expose(), "at_old");
    }

    #[test]
    fn only_a_legacy_profile_carries_the_notice() {
        let legacy = AuthConfig::DeviceFlow {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            expires_at: Utc::now().to_rfc3339(),
            id_token: None,
            id_token_claims: crate::profile::storage::IdTokenClaims {
                sub: "u1".into(),
                email: "u1@example.test".into(),
            },
        };
        let notice = legacy_notice("qa", Some(&legacy)).unwrap();
        assert!(notice.contains("profile qa"), "{notice}");
        assert!(notice.contains("airdress auth login"), "{notice}");
        let hub = hub_profile("rt", &[]).auth.unwrap();
        assert!(legacy_notice("qa", Some(&hub)).is_none());
        assert!(legacy_notice("qa", None).is_none());
    }

    /// A hub that rotates, then takes `delay` to deliver its answer: the
    /// window in which a caller that stops waiting used to lose the new
    /// refresh token (AIR-173).
    struct AnswersLate {
        hub: FakeHub,
        delay: std::time::Duration,
    }

    impl ResourceRefresher for AnswersLate {
        async fn refresh(&self, e: &str, c: &str, rt: &str, r: &str) -> Result<RefreshResponse> {
            let answer = self.hub.refresh(e, c, rt, r).await;
            tokio::time::sleep(self.delay).await;
            answer
        }
    }

    /// A hub whose first answer never arrives although it rotated, and
    /// which, like the real one, hands the successor back once to the
    /// previous token presented again at once (the 30 s grace).
    struct LosesFirstAnswer {
        hub: FakeHub,
        graced: std::sync::Mutex<Option<String>>,
        lost: AtomicBool,
    }

    impl ResourceRefresher for LosesFirstAnswer {
        async fn refresh(&self, e: &str, c: &str, rt: &str, r: &str) -> Result<RefreshResponse> {
            if self.graced.lock().unwrap().as_deref() == Some(rt) {
                *self.graced.lock().unwrap() = None;
                let successor = "rt_rekeyed".to_owned();
                *self.hub.current.lock().unwrap() = successor.clone();
                return Ok(RefreshResponse {
                    access_token: Some(format!("at[{r}]#graced").into()),
                    refresh_token: Some(successor.into()),
                    expires_in: Some(900),
                    ..Default::default()
                });
            }
            let answer = self.hub.refresh(e, c, rt, r).await;
            if !self.lost.swap(true, Ordering::SeqCst) {
                *self.graced.lock().unwrap() = Some(rt.to_owned());
                return Err(anyhow!("operation timed out"));
            }
            answer
        }
    }

    fn multi_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// The incident itself, as a test: a caller dropped after the hub
    /// rotated and before the write leaves the spent token on file, and
    /// the next refresh ends the grant. This is what [`shield`] prevents.
    #[test]
    fn a_caller_dropped_mid_refresh_without_the_shield_leaves_a_spent_token() {
        let (_home, paths) = storage::temp_paths();
        storage::write_profile(&paths, "p", &hub_profile("rt_0", &[])).unwrap();
        let hub = AnswersLate {
            hub: FakeHub::new("rt_0"),
            delay: std::time::Duration::from_millis(300),
        };
        multi_thread().block_on(async {
            let call = access_token_with(&paths, "p", Audience::Hub, &hub);
            let waited = tokio::time::timeout(std::time::Duration::from_millis(50), call).await;
            assert!(waited.is_err());
        });
        assert_eq!(stored_refresh(&paths, "p"), "rt_0");
        assert_eq!(*hub.hub.current.lock().unwrap(), "rt_1");
        let err = block_on(access_token_with(&paths, "p", Audience::Hub, &hub.hub)).unwrap_err();
        assert!(err.to_string().contains("invalid_grant"), "{err}");
        assert!(*hub.hub.revoked.lock().unwrap());
    }

    #[test]
    fn a_shielded_refresh_is_stored_when_its_caller_stops_waiting() {
        let (_home, paths) = storage::temp_paths();
        storage::write_profile(&paths, "p", &hub_profile("rt_0", &[])).unwrap();
        let hub = std::sync::Arc::new(AnswersLate {
            hub: FakeHub::new("rt_0"),
            delay: std::time::Duration::from_millis(300),
        });
        multi_thread().block_on(async {
            let (p, h) = (paths.clone(), std::sync::Arc::clone(&hub));
            let call = shield(async move { access_token_with(&p, "p", Audience::Hub, &*h).await });
            let waited = tokio::time::timeout(std::time::Duration::from_millis(50), call).await;
            assert!(waited.is_err(), "the caller gave up before the answer");
            assert!(settle(std::time::Duration::from_secs(5)).await);
        });
        assert_eq!(stored_refresh(&paths, "p"), "rt_1");
        // And the next refresh is an ordinary one, not a replay.
        let fresh = block_on(access_token_with(
            &paths,
            "p",
            Audience::Operator("op.example"),
            &hub.hub,
        ))
        .unwrap();
        assert_eq!(fresh.expose(), "at[https://op.example/v1]#2");
        assert!(!*hub.hub.revoked.lock().unwrap());
    }

    #[test]
    fn a_refresh_that_got_no_answer_asks_again_at_once_and_keeps_the_grant() {
        let (_home, paths) = storage::temp_paths();
        storage::write_profile(&paths, "p", &hub_profile("rt_0", &[])).unwrap();
        let hub = LosesFirstAnswer {
            hub: FakeHub::new("rt_0"),
            graced: std::sync::Mutex::new(None),
            lost: AtomicBool::new(false),
        };
        let token = block_on(access_token_with(&paths, "p", Audience::Hub, &hub)).unwrap();
        assert_eq!(token.expose(), "at[https://hub.example]#graced");
        assert_eq!(stored_refresh(&paths, "p"), "rt_rekeyed");
        assert!(!*hub.hub.revoked.lock().unwrap());
    }

    #[test]
    fn settle_returns_at_once_with_nothing_in_flight() {
        let started = std::time::Instant::now();
        // Other tests may have a shielded refresh running; none outlives
        // its own short delay.
        assert!(block_on(settle(std::time::Duration::from_secs(5))));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
