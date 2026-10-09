//! Signing in through the hub's authorization server, against a mock hub
//! over real HTTP (SPEC-133 D-36, tasks 133-H.13 and 133-H.14).
//!
//! - Discovery: `oauth-config?v=2` naming the hub as issuer leads to the
//!   hub's RFC 8414 metadata; a hub that ignores `v=2` (it answers with the
//!   identity provider's issuer) is signed in to directly, as before.
//! - The device flow and the PKCE loopback flow both sign in at the hub,
//!   `prompt=select_account` on the authorization request and no `resource`
//!   there or on the device authorization (that is what makes the hub grant
//!   every airdress the person owns), and the hub API's resource on the
//!   token request.
//! - One grant, several tokens: each operator's token is requested with
//!   `resource=https://<fqdn>/v1`, the refresh token rotates on every use,
//!   and concurrent requests never present one refresh token twice (the
//!   mock, like the hub, revokes the grant when that happens).
//! - A v2 (identity-provider direct) profile is moved to v3 by a login, and
//!   its old tokens are revoked; until then it keeps working as it was.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use airdress::auth::discovery::{self, LoginServer};
use airdress::auth::login::{self, LoginOpts};
use airdress::auth::pkce_flow;
use airdress::auth::tokens::{self, Audience};
use airdress::paths::Paths;
use airdress::profile::storage::{self, AuthConfig, IdTokenClaims, Profile};

/// What the mock hub has seen and holds.
#[derive(Default)]
struct Hub {
    /// Serve the authorization server (`v=2` names the hub), or behave
    /// like a hub that predates it.
    serves_v2: bool,
    /// The one live refresh token of the grant.
    refresh: String,
    /// Set when a refresh token was presented twice.
    family_revoked: bool,
    issued: u32,
    /// `resource` of each refresh grant, in order.
    refresh_resources: Vec<String>,
    /// Form fields of the device authorization request.
    device_request: HashMap<String, String>,
    device_polls: u32,
    /// Query of the authorization request.
    authorize: HashMap<String, String>,
    /// Form fields of the code exchange.
    code_exchange: HashMap<String, String>,
    /// Tokens revoked at the identity provider (legacy).
    legacy_revoked: Vec<(String, String)>,
}

fn jwt(claims: Value) -> String {
    let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"at+jwt"}"#);
    let p = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{h}.{p}.c2ln")
}

fn form(body: &str) -> HashMap<String, String> {
    reqwest::Url::parse(&format!("http://form.invalid/?{body}"))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

fn reply(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nConnection: close\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn issue(hub: &mut Hub, base: &str, resource: &str) -> Value {
    hub.issued += 1;
    hub.refresh = format!("rt_{}", hub.issued);
    json!({
        "access_token": jwt(json!({
            "iss": base, "sub": "user-ada", "aud": resource,
            "n": hub.issued,
        })),
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": hub.refresh,
    })
}

fn handle(hub: &mut Hub, base: &str, method: &str, target: &str, body: &str) -> String {
    let url = reqwest::Url::parse(&format!("{base}{target}")).unwrap();
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let port = url.port().unwrap();
    // A different origin from the hub's: what a v1 answer looks like.
    let idp = format!("http://localhost:{port}/zitadel");
    match (method, url.path()) {
        ("GET", "/api/cli/oauth-config") => {
            let body = if hub.serves_v2 && q.get("v").map(String::as_str) == Some("2") {
                json!({"issuer": base, "client_id": "airdress-cli"})
            } else {
                json!({"issuer": idp, "client_id": "zitadel-cli"})
            };
            reply("200 OK", "", &body.to_string())
        }
        ("GET", "/.well-known/oauth-authorization-server") => reply(
            "200 OK",
            "",
            &json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/oauth/authorize"),
                "token_endpoint": format!("{base}/oauth/token"),
                "device_authorization_endpoint": format!("{base}/oauth/device_authorization"),
                "revocation_endpoint": format!("{base}/oauth/revoke"),
                "scopes_supported": ["mcp.read", "mcp.write", "offline_access"],
                "code_challenge_methods_supported": ["S256"],
            })
            .to_string(),
        ),
        ("POST", "/oauth/device_authorization") => {
            hub.device_request = form(body);
            reply(
                "200 OK",
                "",
                &json!({
                    "device_code": "dc-1", "user_code": "ABCD-EFGH",
                    "verification_uri": format!("{base}/oauth/device"),
                    "interval": 0, "expires_in": 60,
                })
                .to_string(),
            )
        }
        ("GET", "/oauth/authorize") => {
            hub.authorize = q.clone();
            let mut location = reqwest::Url::parse(&q["redirect_uri"]).unwrap();
            location
                .query_pairs_mut()
                .append_pair("code", "code-1")
                .append_pair("state", &q["state"]);
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        }
        ("POST", "/oauth/token") => {
            let f = form(body);
            let hub_api = format!("{base}/api");
            let resource = f.get("resource").cloned().unwrap_or(hub_api.clone());
            // The hub's rule: the hub API, or exactly `https://<name>/v1`.
            let valid = resource == hub_api
                || (resource.starts_with("https://")
                    && resource.ends_with("/v1")
                    && resource == resource.to_ascii_lowercase()
                    && !resource["https://".len()..resource.len() - 3].contains([':', '/']));
            if !valid {
                return reply("400 Bad Request", "", r#"{"error":"invalid_target"}"#);
            }
            match f["grant_type"].as_str() {
                "urn:ietf:params:oauth:grant-type:device_code" => {
                    hub.device_polls += 1;
                    if hub.device_polls == 1 {
                        return reply(
                            "400 Bad Request",
                            "",
                            r#"{"error":"authorization_pending"}"#,
                        );
                    }
                    reply("200 OK", "", &issue(hub, base, &resource).to_string())
                }
                "authorization_code" => {
                    hub.code_exchange = f.clone();
                    let challenge =
                        URL_SAFE_NO_PAD.encode(Sha256::digest(f["code_verifier"].as_bytes()));
                    if f["code"] != "code-1"
                        || challenge != hub.authorize["code_challenge"]
                        || f["redirect_uri"] != hub.authorize["redirect_uri"]
                    {
                        return reply("400 Bad Request", "", r#"{"error":"invalid_grant"}"#);
                    }
                    reply("200 OK", "", &issue(hub, base, &resource).to_string())
                }
                "refresh_token" => {
                    if hub.family_revoked || f["refresh_token"] != hub.refresh {
                        hub.family_revoked = true;
                        return reply("400 Bad Request", "", r#"{"error":"invalid_grant"}"#);
                    }
                    hub.refresh_resources.push(resource.clone());
                    reply("200 OK", "", &issue(hub, base, &resource).to_string())
                }
                _ => reply(
                    "400 Bad Request",
                    "",
                    r#"{"error":"unsupported_grant_type"}"#,
                ),
            }
        }
        ("GET", "/zitadel/.well-known/openid-configuration") => reply(
            "200 OK",
            "",
            &json!({
                "issuer": idp,
                "token_endpoint": format!("{base}/zitadel/token"),
                "device_authorization_endpoint": format!("{base}/zitadel/device"),
                "revocation_endpoint": format!("{base}/zitadel/revoke"),
            })
            .to_string(),
        ),
        ("POST", "/zitadel/revoke") => {
            let f = form(body);
            hub.legacy_revoked
                .push((f["token"].clone(), f["token_type_hint"].clone()));
            reply("200 OK", "", "{}")
        }
        ("POST", "/zitadel/device") => reply(
            "200 OK",
            "",
            &json!({"device_code": "zdc", "user_code": "Z", "verification_uri": idp,
                    "interval": 0, "expires_in": 60})
            .to_string(),
        ),
        ("POST", "/zitadel/token") => reply(
            "200 OK",
            "",
            &json!({"access_token": "zitadel-at", "refresh_token": "zitadel-rt",
                    "expires_in": 900})
            .to_string(),
        ),
        _ => reply("404 Not Found", "", "{}"),
    }
}

async fn mock_hub(serves_v2: bool) -> (String, Arc<Mutex<Hub>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hub = Arc::new(Mutex::new(Hub {
        serves_v2,
        ..Default::default()
    }));
    let state = Arc::clone(&hub);
    let b = base.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&state);
            let base = b.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let end = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < end + 4 + len {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = String::from_utf8_lossy(&buf[end + 4..]).into_owned();
                let mut line = head.lines().next().unwrap_or("").split_whitespace();
                let (method, target) = (line.next().unwrap_or(""), line.next().unwrap_or(""));
                let resp = handle(&mut state.lock().unwrap(), &base, method, target, &body);
                if let Err(e) = sock.write_all(resp.as_bytes()).await {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
                if let Err(e) = sock.shutdown().await {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            });
        }
    });
    (base, hub)
}

/// A fresh home for one test, its own temporary directory. Nothing
/// process-global moves, so these tests run in parallel.
struct Home {
    _dir: tempfile::TempDir,
    paths: Paths,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            paths: Paths::under(dir.path()),
            _dir: dir,
        }
    }
}

fn empty_profile(endpoint: &str) -> Profile {
    Profile {
        schema_version: storage::SCHEMA_VERSION,
        endpoint: endpoint.into(),
        auth: None,
        active_airdress: None,
    }
}

fn claims_of(token: &str) -> Value {
    let p = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

async fn device_login(paths: &Paths, name: &str) {
    login::run_with_opts(
        paths,
        Some(name),
        LoginOpts {
            no_browser: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_finds_the_hub_and_falls_back_when_it_has_none() {
    let (base, _) = mock_hub(true).await;
    match discovery::resolve_login_server(&base).await.unwrap() {
        LoginServer::Hub(cfg) => {
            assert_eq!(cfg.issuer, base);
            assert_eq!(cfg.client_id, "airdress-cli");
            assert_eq!(cfg.token_endpoint, format!("{base}/oauth/token"));
            assert_eq!(cfg.hub_resource, format!("{base}/api"));
            assert_eq!(cfg.scopes(), "offline_access");
        }
        other => panic!("expected the hub, got {other:?}"),
    }

    let (old, _) = mock_hub(false).await;
    match discovery::resolve_login_server(&old).await.unwrap() {
        LoginServer::Legacy(cfg) => {
            assert_eq!(cfg.client_id, "zitadel-cli");
            assert!(cfg.resource.is_none());
        }
        other => panic!("expected the legacy fallback, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_flow_signs_in_at_the_hub_and_writes_a_v3_profile() {
    let home = Home::new();
    let paths = &home.paths;
    let (base, hub) = mock_hub(true).await;
    storage::write_profile(paths, "p", &empty_profile(&base)).unwrap();

    device_login(paths, "p").await;

    let seen = hub.lock().unwrap();
    assert_eq!(seen.device_request["client_id"], "airdress-cli");
    assert!(!seen.device_request.contains_key("resource"));
    assert!(seen.device_request["scope"].contains("offline_access"));
    drop(seen);

    let profile = storage::read_profile(paths, "p").unwrap();
    assert_eq!(profile.schema_version, storage::HUB_SCHEMA_VERSION);
    match profile.auth.unwrap() {
        AuthConfig::Hub {
            issuer,
            refresh_token,
            id_token_claims,
            access_tokens,
            hub_resource,
            ..
        } => {
            assert_eq!(issuer, base);
            assert_eq!(refresh_token.expose(), "rt_1");
            assert_eq!(id_token_claims.sub, "user-ada");
            // The hub's access token carries no email, and no ID token
            // comes with it.
            assert_eq!(id_token_claims.email, "");
            assert_eq!(hub_resource, format!("{base}/api"));
            assert_eq!(
                claims_of(access_tokens[&hub_resource].access_token.expose())["aud"],
                format!("{base}/api")
            );
        }
        other => panic!("expected a hub sign-in, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_loopback_flow_asks_for_the_account_picker_and_proves_its_verifier() {
    let (base, hub) = mock_hub(true).await;
    let LoginServer::Hub(cfg) = discovery::resolve_login_server(&base).await.unwrap() else {
        panic!("expected the hub");
    };
    let flow = cfg.flow(&cfg.hub_resource);

    // The "browser": follow the hub's redirect back to the loopback port.
    let opener = |url: &str| {
        let url = url.to_owned();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let r = client.get(&url).send().await.unwrap();
            let location = r.headers()["location"].to_str().unwrap().to_owned();
            client.get(&location).send().await.unwrap();
        });
        true
    };
    let tokens = pkce_flow::run_with_opener(
        &flow,
        flow.authorization_endpoint.as_deref().unwrap(),
        &cfg.scopes(),
        Some(pkce_flow::PROMPT_SELECT_ACCOUNT),
        opener,
    )
    .await
    .unwrap()
    .unwrap();

    let seen = hub.lock().unwrap();
    assert_eq!(seen.authorize["prompt"], "select_account");
    assert!(!seen.authorize.contains_key("resource"));
    assert_eq!(seen.authorize["code_challenge_method"], "S256");
    assert!(
        seen.authorize["redirect_uri"].starts_with("http://localhost:")
            && seen.authorize["redirect_uri"].ends_with("/callback"),
        "{}",
        seen.authorize["redirect_uri"]
    );
    assert_eq!(seen.code_exchange["resource"], format!("{base}/api"));
    assert_eq!(tokens.refresh_token.expose(), "rt_1");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_grant_gives_each_operator_its_own_token() {
    let home = Home::new();
    let paths = &home.paths;
    let (base, hub) = mock_hub(true).await;
    storage::write_profile(paths, "p", &empty_profile(&base)).unwrap();
    device_login(paths, "p").await;

    let vm2 = tokens::access_token(paths, "p", Audience::Operator("vm2.example"))
        .await
        .unwrap();
    let vm3 = tokens::access_token(paths, "p", Audience::Operator("vm3.example"))
        .await
        .unwrap();
    assert_eq!(claims_of(vm2.expose())["aud"], "https://vm2.example/v1");
    assert_eq!(claims_of(vm3.expose())["aud"], "https://vm3.example/v1");

    // Cached: asking again costs nothing at the hub.
    let again = tokens::access_token(paths, "p", Audience::Operator("vm2.example"))
        .await
        .unwrap();
    assert_eq!(again, vm2);
    let seen = hub.lock().unwrap();
    assert_eq!(
        seen.refresh_resources,
        vec!["https://vm2.example/v1", "https://vm3.example/v1"]
    );
    assert!(!seen.family_revoked);
    match storage::read_profile(paths, "p").unwrap().auth.unwrap() {
        AuthConfig::Hub { refresh_token, .. } => assert_eq!(*refresh_token.expose(), seen.refresh),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_never_present_one_refresh_token_twice() {
    let home = Home::new();
    let paths = &home.paths;
    let (base, hub) = mock_hub(true).await;
    storage::write_profile(paths, "p", &empty_profile(&base)).unwrap();
    device_login(paths, "p").await;

    let mut tasks = Vec::new();
    for i in 0..6 {
        let paths = paths.clone();
        tasks.push(tokio::spawn(async move {
            let fqdn = format!("vm{i}.example");
            tokens::access_token(&paths, "p", Audience::Operator(&fqdn)).await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let seen = hub.lock().unwrap();
    assert!(!seen.family_revoked, "a refresh token was presented twice");
    assert_eq!(seen.refresh_resources.len(), 6);
}

fn legacy_profile(endpoint: &str) -> Profile {
    Profile {
        schema_version: storage::SCHEMA_VERSION,
        endpoint: endpoint.into(),
        auth: Some(AuthConfig::DeviceFlow {
            access_token: "zitadel-old-at".into(),
            refresh_token: "zitadel-old-rt".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            id_token_claims: IdTokenClaims {
                sub: "user-ada".into(),
                email: "ada@example.com".into(),
            },
            id_token: None,
        }),
        active_airdress: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v2_profile_keeps_working_until_a_login_moves_it_to_v3() {
    let home = Home::new();
    let paths = &home.paths;
    let (base, hub) = mock_hub(true).await;
    storage::write_profile(paths, "p", &legacy_profile(&base)).unwrap();

    // Untouched until the person logs in: the one token, for any audience.
    let t = tokens::access_token(paths, "p", Audience::Operator("vm2.example"))
        .await
        .unwrap();
    assert_eq!(t.expose(), "zitadel-old-at");
    assert_eq!(
        storage::read_profile(paths, "p").unwrap().schema_version,
        storage::SCHEMA_VERSION
    );

    device_login(paths, "p").await;

    let profile = storage::read_profile(paths, "p").unwrap();
    assert_eq!(profile.schema_version, storage::HUB_SCHEMA_VERSION);
    match profile.auth {
        // Same person: the email the old sign-in knew is kept.
        Some(AuthConfig::Hub {
            id_token_claims, ..
        }) => assert_eq!(id_token_claims.email, "ada@example.com"),
        other => panic!("expected a hub sign-in, got {other:?}"),
    }
    let seen = hub.lock().unwrap();
    assert_eq!(
        seen.legacy_revoked,
        vec![
            ("zitadel-old-rt".to_string(), "refresh_token".to_string()),
            ("zitadel-old-at".to_string(), "access_token".to_string()),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hub_without_its_own_sign_in_still_signs_in_directly() {
    let home = Home::new();
    let paths = &home.paths;
    let (base, _) = mock_hub(false).await;
    storage::write_profile(paths, "p", &empty_profile(&base)).unwrap();

    device_login(paths, "p").await;

    let profile = storage::read_profile(paths, "p").unwrap();
    assert_eq!(profile.schema_version, storage::SCHEMA_VERSION);
    match profile.auth.unwrap() {
        AuthConfig::DeviceFlow { access_token, .. } => {
            assert_eq!(access_token.expose(), "zitadel-at")
        }
        other => panic!("expected the legacy sign-in, got {other:?}"),
    }
}
