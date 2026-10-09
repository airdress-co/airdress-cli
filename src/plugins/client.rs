//! The operator's owner routes for plugin installs, `/v1/plugins/installs*`.
//!
//! Every call carries the owner's ZITADEL bearer — the one `airdress auth
//! login` holds. The operator accepts nothing else here (SPEC-119 FR-1: these
//! routes replaced the unauthenticated `/api/v1/airdresses/{airdress}/apps*`),
//! so a sign-in that is not the operator's owner gets a 401/403 back.
//!
//! Shapes follow `airdress-operator` `apps_api.rs` and `openapi.yaml`
//! (`PluginInstall`, `PluginInstallRequest`). `{id}` is the install's
//! durable id (a ULID) since SPEC-119 R.1; the operator still accepts the
//! subdomain in its place, so this client treats it as an opaque string.
//!
//! The routes are mounted only on an operator whose plugin runtime is on, and
//! no fleet host has it on yet — so the commonest answer is the operator's
//! `route_not_found`, which is said as that, not as "not installed".

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http;
use crate::redact::Redacted;

/// One install, as `GET /v1/plugins/installs` lists it and `GET …/{id}`
/// reads it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Install {
    /// The install's id on this operator — the `{id}` of its routes.
    pub id: String,
    /// The owner's airdress label the install is held under.
    pub airdress: String,
    /// Subdomain under the airdress.
    pub subdomain: String,
    /// The installed plugin (`forms`, `webdav`, …).
    pub app_type: String,
    /// `cold`, `starting` or `hot`. Absent from the install response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_state: Option<String>,
    /// Seconds since the last served request; `0` if never served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_request_age_seconds: Option<u64>,
    /// The install's plugin-db role, schema and capability — never a
    /// password. Passed through as the operator sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_access: Option<Value>,
    /// The version it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `local` (a definition the operator loaded) or `registry`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The pinned key that verified a registry release (install response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// What the plugin will be able to do, per scope (install response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<Value>,
    /// Who signed a registry release, and the signer set the install pins
    /// (install response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<Value>,
}

/// One member of an install's signer set: a key or an approved machine.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Signer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// Body of `POST /v1/plugins/installs`: a registry release (`plugin`,
/// `version`) or a definition the operator loaded (`app_type`). `subdomain`
/// only when asked for: absent, the plugin's declared subdomain is used.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct InstallBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<&'a str>,
    /// Who may sign what the install runs (SPEC-119 R-8); absent, the
    /// operator proposes the set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signers: Option<Vec<Signer>>,
    /// Offer the plugin's personal scope to the airdress's people, each of
    /// whom then authorizes it for themselves. Absent: not offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_personal: Option<bool>,
}

/// A person's own authorization of a plugin's personal scope, as the
/// operator answers it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// `personal`.
    pub scope: String,
    /// `active`, `needs_reconsent` or `revoked`.
    pub state: String,
    /// The plugin version consented to.
    pub version: String,
    /// Why it was revoked, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    /// On a revocation of one's own: `keep` or `erase`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_revoke: Option<String>,
}

/// Client for the owner's plugin-install routes on one operator.
#[derive(Debug)]
pub struct PluginsClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl PluginsClient {
    pub fn new(fqdn: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        Self::with_base_url(format!("https://{}", fqdn.trim_matches('/')), bearer)
    }

    pub fn with_base_url(base_url: String, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer: bearer.into(),
            http,
        })
    }

    /// `GET /v1/plugins/installs`.
    pub async fn list(&self) -> Result<Vec<Install>> {
        let url = format!("{}/v1/plugins/installs", self.base_url);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "list plugins").await?;
        resp.json().await.context("parse plugin installs")
    }

    /// `GET /v1/plugins/installs/{id}`. `None` when the operator says the id
    /// is not installed.
    pub async fn get(&self, id: &str) -> Result<Option<Install>> {
        let url = format!("{}/v1/plugins/installs/{}", self.base_url, segment(id));
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let body = resp.text().await.unwrap_or_default();
            if is_route_not_found(&body) {
                bail!("read plugin `{id}`: {NO_ROUTES}");
            }
            return Ok(None);
        }
        let resp = checked(resp, "read plugin").await?;
        resp.json().await.map(Some).context("parse plugin install")
    }

    /// `POST /v1/plugins/installs[?dry_run=true]`.
    pub async fn install(&self, body: &InstallBody<'_>, dry_run: bool) -> Result<Install> {
        let mut url = format!("{}/v1/plugins/installs", self.base_url);
        if dry_run {
            url.push_str("?dry_run=true");
        }
        let resp = self
            .send(self.http.post(&url).json(body), &url, "POST")
            .await?;
        let resp = checked(resp, "install").await?;
        resp.json().await.context("parse install")
    }

    /// `DELETE /v1/plugins/installs/{id}?purge=true[&backup=true][&dry_run=true]`.
    ///
    /// `purge=true` is always sent: the operator refuses an uninstall
    /// without it, and the CLI's own confirmation is what stands in front
    /// of it.
    pub async fn uninstall(&self, id: &str, backup: bool, dry_run: bool) -> Result<()> {
        let url = uninstall_url(&self.base_url, id, backup, dry_run);
        let resp = self.send(self.http.delete(&url), &url, "DELETE").await?;
        checked(resp, "uninstall").await?;
        Ok(())
    }

    /// `POST /v1/plugins/installs/{plugin}/authorizations`: authorize the
    /// plugin's personal scope for yourself. The body names nobody: the
    /// operator takes who you are from your sign-in.
    pub async fn authorize(&self, plugin: &str) -> Result<Authorization> {
        let url = format!(
            "{}/v1/plugins/installs/{}/authorizations",
            self.base_url,
            segment(plugin)
        );
        let resp = self.send(self.http.post(&url), &url, "POST").await?;
        let resp = checked(resp, "authorize").await?;
        resp.json().await.context("parse authorization")
    }

    /// `DELETE /v1/plugins/installs/{plugin}/authorizations/me?data=keep|erase`:
    /// revoke your own authorization. `false` when you had none.
    pub async fn deauthorize(&self, plugin: &str, keep: bool) -> Result<bool> {
        let url = format!(
            "{}/v1/plugins/installs/{}/authorizations/me?data={}",
            self.base_url,
            segment(plugin),
            if keep { "keep" } else { "erase" }
        );
        let resp = self.send(self.http.delete(&url), &url, "DELETE").await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let body = resp.text().await.unwrap_or_default();
            if is_route_not_found(&body) {
                bail!("deauthorize `{plugin}`: {NO_ROUTES}");
            }
            if error_parts(&body).1.as_deref() == Some("not_authorized") {
                return Ok(false);
            }
            bail!("deauthorize `{plugin}`: no such plugin installed here");
        }
        checked(resp, "deauthorize").await?;
        Ok(true)
    }

    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        url: &str,
        method: &str,
    ) -> Result<reqwest::Response> {
        req.bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(url, method, e))
    }
}

fn uninstall_url(base: &str, id: &str, backup: bool, dry_run: bool) -> String {
    let mut url = format!("{base}/v1/plugins/installs/{}?purge=true", segment(id));
    if backup {
        url.push_str("&backup=true");
    }
    if dry_run {
        url.push_str("&dry_run=true");
    }
    url
}

/// An install id as one path segment: letters, digits, `-` and `_`. The id is
/// opaque (a ULID, or a subdomain the operator also accepts) but never needs more, and
/// refusing the rest means a `/`, `?` or `..` cannot reach another route.
pub fn valid_id(id: &str) -> Result<&str> {
    if !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Ok(id)
    } else {
        bail!("`{id}` is not an install id — `airdress plugins list` shows them")
    }
}

fn segment(id: &str) -> &str {
    // Callers validate first; this is the belt to that brace.
    debug_assert!(valid_id(id).is_ok());
    id
}

const NO_ROUTES: &str = "this operator does not serve plugin installs — its plugin \
                         runtime is off, or it predates the owner install routes";

fn is_route_not_found(body: &str) -> bool {
    error_parts(body).0.as_deref() == Some("route_not_found")
}

/// The operator's error bodies: `{"error":"<message>","code":…,"step":…,
/// "detail":"…"}` from the install routes, `{"error":{"code","message"}}` from
/// its fallback. An install refusal's code and step are said with it — they
/// are what tells an unsigned release from a tampered one.
fn error_parts(body: &str) -> (Option<String>, Option<String>) {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return (None, None);
    };
    let detail = v.get("detail").and_then(Value::as_str).map(str::to_owned);
    let code = v.get("code").and_then(Value::as_str);
    let step = v.get("step").and_then(Value::as_str);
    let tag = match (code, step) {
        (Some(c), Some(s)) => format!(" [{c} at {s}]"),
        (Some(c), None) => format!(" [{c}]"),
        _ => String::new(),
    };
    match v.get("error") {
        Some(Value::String(message)) => (
            None,
            Some(format!("{}{tag}", join(message, detail.as_deref()))),
        ),
        Some(Value::Object(o)) => (
            o.get("code").and_then(Value::as_str).map(str::to_owned),
            o.get("message").and_then(Value::as_str).map(str::to_owned),
        ),
        // `application/problem+json`: the closed code is the message.
        _ => (None, code.map(str::to_owned)),
    }
}

fn join(message: &str, detail: Option<&str>) -> String {
    match detail {
        Some(d) if !d.is_empty() => format!("{message} ({d})"),
        _ => message.to_owned(),
    }
}

async fn checked(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() || matches!(status.as_u16(), 401 | 403) {
        return http::handle_status(resp, what).await;
    }
    let body = resp.text().await.unwrap_or_default();
    let (code, message) = error_parts(&body);
    let wire = crate::exit::body_code(&body)
        .filter(|c| !c.contains(' '))
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    let text = if code.as_deref() == Some("route_not_found") {
        format!("{what}: {NO_ROUTES}")
    } else {
        let detail = message.or(code).unwrap_or_else(|| body.trim().to_owned());
        if detail.is_empty() {
            format!("{what}: HTTP {status}")
        } else {
            format!("{what}: {detail}")
        }
    };
    Err(crate::exit::Failure::http(status.as_u16(), wire, text).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_route_errors_keep_their_detail() {
        let (code, m) = error_parts(
            r#"{"error":"subdomain `forms` already installed","detail":"installed app is `webdav`, request was `forms`"}"#,
        );
        assert!(code.is_none());
        assert_eq!(
            m.as_deref(),
            Some("subdomain `forms` already installed (installed app is `webdav`, request was `forms`)")
        );
        let (_, m) = error_parts(r#"{"error":"not installed"}"#);
        assert_eq!(m.as_deref(), Some("not installed"));
        let (_, m) = error_parts(
            r#"{"error":"the release is not signed","code":"bundle_unsigned","step":"signature"}"#,
        );
        assert_eq!(
            m.as_deref(),
            Some("the release is not signed [bundle_unsigned at signature]")
        );
    }

    #[test]
    fn the_fallback_is_recognized_as_no_routes() {
        assert!(is_route_not_found(
            r#"{"error":{"code":"route_not_found","message":"No such route on this operator."}}"#
        ));
        assert!(!is_route_not_found(r#"{"error":"not installed"}"#));
        assert!(!is_route_not_found("<html>"));
    }

    #[test]
    fn uninstall_always_purges_and_adds_only_what_was_asked() {
        assert_eq!(
            uninstall_url("http://o", "forms", false, false),
            "http://o/v1/plugins/installs/forms?purge=true"
        );
        assert_eq!(
            uninstall_url("http://o", "forms", true, true),
            "http://o/v1/plugins/installs/forms?purge=true&backup=true&dry_run=true"
        );
    }

    #[test]
    fn an_id_is_one_path_segment_or_refused() {
        for ok in ["forms", "forms-2", "01J9ZK_x"] {
            assert!(valid_id(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", "..", "a/b", "forms?purge=true", "x y", &"a".repeat(129)] {
            assert!(valid_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_install_body_names_a_subdomain_only_when_given() {
        let v = serde_json::to_value(InstallBody {
            app_type: Some("forms"),
            ..InstallBody::default()
        })
        .unwrap();
        assert_eq!(v, serde_json::json!({ "app_type": "forms" }));
        let v = serde_json::to_value(InstallBody {
            plugin: Some("forms"),
            version: Some("0.2.0"),
            subdomain: Some("surveys"),
            ..InstallBody::default()
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "plugin": "forms", "version": "0.2.0", "subdomain": "surveys" })
        );
    }

    #[test]
    fn the_install_response_reads_without_runtime_fields() {
        let i: Install = serde_json::from_str(
            r#"{"id":"forms","app_type":"forms","subdomain":"forms","airdress":"ada.a.airdr.es"}"#,
        )
        .unwrap();
        assert!(i.runtime_state.is_none() && i.db_access.is_none());
    }
}
