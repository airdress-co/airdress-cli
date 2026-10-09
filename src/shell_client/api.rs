//! The operator's shell routes (design §5.1), and the join and enrollment
//! calls that make the CLI a device (design §5.2).
//!
//! Every shell route takes the **device's** bearer: the session token this
//! CLI received when its join was approved. An account's sign-in token is
//! refused there (`shell_caller_not_eligible`): the law needs an enrolled
//! device, not an account.

use std::time::Duration;

use anyhow::{Context as _, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::http;
use crate::redact::Redacted;

/// A refusal from the operator, with its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// HTTP status.
    pub status: u16,
    /// `error.code`, or the status text.
    pub code: String,
    /// `error.message`.
    pub message: String,
    /// `error.reason`, when the operator gives one.
    pub reason: Option<String>,
    /// `Retry-After`, when the operator asks the device to wait
    /// (`429 shell_reconnect_throttled`).
    pub retry_after: Option<Duration>,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", explain(&self.code, &self.message))?;
        if let Some(r) = &self.reason {
            write!(f, " ({r})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusal {}

/// Why a session ended, from the reason code an operator's `410
/// shell_session_ended` carries (the host's `exited` reason).
pub fn ended_because(reason: Option<&str>) -> String {
    let why = match reason.unwrap_or_default() {
        "host_stopped" => "its host stopped",
        "exit" => "its program exited",
        "closed" => "it was closed",
        "idle" => "it was idle too long",
        "lifetime" => "it reached its maximum lifetime",
        "revoked" => "this device was signed out",
        "gone" => "its host no longer has it (the host restarted?)",
        "" => return "the session has ended".to_owned(),
        other => return format!("the session has ended [{other}]"),
    };
    format!("the session has ended: {why}")
}

/// A human sentence for a design §13 code.
pub fn explain(code: &str, message: &str) -> String {
    let known = match code {
        "not_enabled" => "shells are switched off on this airdress",
        "shell_host_not_found" => "no such shell host",
        "shell_caller_not_eligible" => {
            "only an enrolled device can reach a shell; this CLI's device is not one yet \
             (`airdress shell device join`)"
        }
        "shell_host_offline" => "your machine is offline (is `airdress shell host` running?)",
        "shell_host_disabled" => "this shell host is switched off",
        "shell_profile_unknown" => "that host has no such profile",
        "shell_profile_invalid" => "the host reports that profile is not ready",
        "shell_session_limit" => "the host is running as many sessions as it allows",
        "shell_viewer_limit" => "that session has as many devices attached as it allows",
        "rate_limited" => "too many sessions opened this minute; try again shortly",
        "shell_device_keys_missing" => "this device has not registered its shell keys yet",
        "shell_device_not_introduced" => {
            "this device is not introduced on that host yet: confirm it there with \
             `airdress shell host trust <fingerprint>`, or allow it from one of your \
             devices that is"
        }
        "shell_handshake_failed" => {
            "the end-to-end handshake failed (a wrong host key, or a bad delegation)"
        }
        "shell_presence_required" => "the host refused this device without a presence key",
        "shell_presence_none_not_allowed" => {
            "the operator does not record this device as a delegation-only CLI device"
        }
        "shell_resume_expired" => "the resume ticket expired",
        "shell_session_not_found" => "no such session",
        "session_ended" | "shell_session_ended" => "the session has ended",
        "shell_reconnect_throttled" => {
            "this device was refused too often just now; the operator asks it to wait"
        }
        "shell_host_stopping" => "the host is stopping, and its sessions end with it",
        "device_revoked" => "this device was signed out",
        "host_revoked" => "this shell host was removed",
        "unlinked" => "this shell host is no longer linked",
        "shell_leg_not_found" => "the connection to that session is gone",
        "unauthorized" => "this device's credential was refused (revoked?)",
        "sub_user_forbidden" => "that is not available to a sub-user",
        _ => "",
    };
    match (known.is_empty(), message.is_empty()) {
        (false, _) => format!("{known} [{code}]"),
        (true, false) => format!("{message} [{code}]"),
        (true, true) => code.to_owned(),
    }
}

async fn refusal(resp: reqwest::Response) -> Refusal {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let body = resp.text().await.unwrap_or_default();
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let e = if v["error"].is_object() {
        &v["error"]
    } else {
        &v
    };
    Refusal {
        status: status.as_u16(),
        code: e["code"]
            .as_str()
            .or(e["error"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned()),
        message: e["message"].as_str().unwrap_or_default().to_owned(),
        reason: e["reason"].as_str().map(str::to_owned),
        retry_after,
    }
}

/// One profile a host reports (status, never a program).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    /// The id.
    pub id: String,
    /// What a person sees.
    #[serde(default)]
    pub label: String,
    /// `shell` or `harness:<name>`.
    #[serde(default)]
    pub kind: String,
    /// `ready`, or why not.
    #[serde(default)]
    pub state: String,
    /// Recorded on the host.
    #[serde(default)]
    pub record: bool,
}

/// One live session a host reports.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    /// The session id.
    pub id: String,
    /// Its profile.
    pub profile: String,
    /// When it opened.
    #[serde(default)]
    pub opened_at: Option<String>,
    /// Devices attached.
    #[serde(default)]
    pub attached: u32,
    /// The typist (a device id, or `desk`).
    #[serde(default)]
    pub typist: Option<String>,
    /// `working`, `needs_you`, `done` or `idle`.
    #[serde(default)]
    pub state: String,
}

/// One host in the overview.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    /// The `ShellHost` name.
    pub name: String,
    /// The machine id the prologue binds.
    #[serde(default)]
    pub machine: Option<String>,
    /// Switched on.
    #[serde(default)]
    pub enabled: bool,
    /// The host channel is up.
    #[serde(default)]
    pub connected: bool,
    /// Connected, enabled and profiles reported.
    #[serde(default)]
    pub ready: bool,
    /// D-15's warning.
    #[serde(default)]
    pub runs_as_root: bool,
    /// The host key's fingerprint, as the host reports it.
    #[serde(default)]
    pub shell_key: Option<String>,
    /// The host key, base64.
    #[serde(default)]
    pub shell_key_public: Option<String>,
    /// The host's version.
    #[serde(default)]
    pub host_version: Option<String>,
    /// Its profiles.
    #[serde(default)]
    pub profiles: Vec<ProfileView>,
    /// Its live sessions.
    #[serde(default)]
    pub sessions: Vec<SessionView>,
}

/// What an open answers.
#[derive(Debug, Clone, Deserialize)]
pub struct Opened {
    /// The session.
    pub session: String,
    /// The leg.
    pub leg: String,
}

/// The shell routes, as one device.
#[derive(Debug, Clone)]
pub struct ShellApi {
    base: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl ShellApi {
    /// A client for the operator at `base` with this device's bearer.
    pub fn new(base: &str, bearer: &Redacted<String>) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            bearer: bearer.clone(),
            http: http::client_builder()
                .tcp_nodelay(true)
                .build()
                .context("build the HTTP client")?,
        })
    }

    /// The operator's base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The device bearer.
    pub fn bearer(&self) -> &Redacted<String> {
        &self.bearer
    }

    /// The HTTP client (shared with the leg transport).
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, req: reqwest::RequestBuilder, what: &str) -> Result<reqwest::Response> {
        let resp = req
            .bearer_auth(self.bearer.expose())
            .header("accept", "application/json")
            .send()
            .await
            .with_context(|| format!("{what}: the operator is unreachable"))?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(refusal(resp).await.into())
        }
    }

    /// `GET /v1/shells` — the overview.
    pub async fn overview(&self) -> Result<Vec<HostView>> {
        #[derive(Debug, Deserialize)]
        struct O {
            hosts: Vec<HostView>,
        }
        let r = self
            .send(self.http.get(self.url("/v1/shells")), "list shell hosts")
            .await?;
        Ok(r.json::<O>().await.context("read the overview")?.hosts)
    }

    /// `POST /v1/shells/{host}/sessions`.
    ///
    /// `session` is the id this device proposes and its handshake binds
    /// (design §6.5's prologue names the session; the device must know it
    /// before message 1).
    pub async fn open(
        &self,
        host: &str,
        session: &str,
        profile: &str,
        cols: u16,
        rows: u16,
        msg1: &[u8],
    ) -> Result<Opened> {
        let r = self
            .send(
                self.http
                    .post(self.url(&format!("/v1/shells/{}/sessions", seg(host))))
                    .json(&json!({
                        "session": session,
                        "profile": profile,
                        "cols": cols,
                        "rows": rows,
                        "handshake": STANDARD.encode(msg1),
                    })),
                "open a session",
            )
            .await?;
        r.json().await.context("read the open's answer")
    }

    /// `POST /v1/shells/sessions/{id}/legs` with a full handshake.
    pub async fn attach(&self, session: &str, msg1: &[u8]) -> Result<String> {
        self.legs(session, json!({ "handshake": STANDARD.encode(msg1) }))
            .await
    }

    /// `POST /v1/shells/sessions/{id}/legs` with a resume.
    pub async fn resume(&self, session: &str, ticket_id: &str, msg1: &[u8]) -> Result<String> {
        self.legs(
            session,
            json!({ "resume": { "ticketId": ticket_id, "handshake": STANDARD.encode(msg1) } }),
        )
        .await
    }

    async fn legs(&self, session: &str, body: Value) -> Result<String> {
        #[derive(Debug, Deserialize)]
        struct L {
            leg: String,
        }
        let r = self
            .send(
                self.http
                    .post(self.url(&format!("/v1/shells/sessions/{}/legs", seg(session))))
                    .json(&body),
                "attach",
            )
            .await?;
        Ok(r.json::<L>().await.context("read the leg")?.leg)
    }

    /// `POST /v1/shells/sessions/{id}/input` — take input in this session.
    pub async fn take_input(&self, session: &str, leg: &str) -> Result<()> {
        self.send(
            self.http
                .post(self.url(&format!("/v1/shells/sessions/{}/input", seg(session))))
                .json(&json!({ "leg": leg })),
            "take input",
        )
        .await?;
        Ok(())
    }

    /// `DELETE /v1/shells/sessions/{id}`.
    pub async fn close(&self, session: &str) -> Result<()> {
        self.send(
            self.http
                .delete(self.url(&format!("/v1/shells/sessions/{}", seg(session)))),
            "close the session",
        )
        .await?;
        Ok(())
    }

    /// `POST /v1/shells/device-keys`.
    pub async fn register_keys(&self, dh_public: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
        self.send(
            self.http
                .post(self.url("/v1/shells/device-keys"))
                .json(&json!({
                    "dhPublic": STANDARD.encode(dh_public),
                    "presenceAlg": "none",
                    "sig": STANDARD.encode(sig),
                })),
            "register the shell keys",
        )
        .await?;
        Ok(())
    }
}

/// One path segment, percent-encoded where a name could need it.
pub fn seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Joining (design §5.2): unauthenticated until approved.
// ---------------------------------------------------------------------------

/// A join request as the asking device sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinStatus {
    /// `pending`, `approved`, `declined`, `expired`, `unanswerable`,
    /// `withdrawn`.
    pub state: String,
    /// The root-signed delegation, once approved by delegation.
    pub delegation: Option<Value>,
}

/// The join and enrollment calls, and the hub's enrollment token.
#[derive(Debug, Clone)]
pub struct JoinApi {
    operator: String,
    http: reqwest::Client,
}

impl JoinApi {
    /// Against the operator at `base`.
    pub fn new(base: &str) -> Result<Self> {
        Ok(Self {
            operator: base.trim_end_matches('/').to_owned(),
            http: http::client()?,
        })
    }

    /// `POST {hub}/v1/enrollment-tokens` — one enrollment assertion for this
    /// airdress, valid five minutes, single use.
    pub async fn hub_token(
        &self,
        hub: &str,
        account_bearer: &Redacted<String>,
        fqdn: &str,
    ) -> Result<Redacted<String>> {
        let url = format!("{}/v1/enrollment-tokens", hub.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .bearer_auth(account_bearer.expose())
            .json(&json!({ "airdress": fqdn, "operator_fqdn": fqdn }))
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            return Err(refusal(resp).await.into());
        }
        let v: Value = resp.json().await?;
        v["token"]
            .as_str()
            .map(Redacted::from)
            .context("the hub's answer carried no token")
    }

    /// `POST /v1/endpoints/device-join-requests` as a delegation-only human
    /// device of kind `cli`. Returns the request id. `device_public_key` and
    /// `device_id` are what the approving phone's delegation must name.
    pub async fn create(
        &self,
        hub_token: &str,
        ephemeral_public: &[u8; 32],
        identity_public: &[u8; 32],
        device_id: &str,
        label: &str,
    ) -> Result<String> {
        let b = |k: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k);
        let resp = self
            .http
            .post(format!(
                "{}/v1/endpoints/device-join-requests",
                self.operator
            ))
            .json(&json!({
                "hub_token": hub_token,
                "public_key": b(ephemeral_public),
                "device_public_key": b(identity_public),
                "device_id": device_id,
                "device_label": label,
                "device_class": "human",
                "delegation_only": true,
                "device_kind": super::device::DEVICE_KIND,
            }))
            .send()
            .await
            .context("ask to join: the operator is unreachable")?;
        if resp.status() == StatusCode::NOT_FOUND {
            anyhow::bail!("this operator does not take join requests (too old, or no hub trust)");
        }
        if !resp.status().is_success() {
            return Err(refusal(resp).await.into());
        }
        let v: Value = resp.json().await?;
        v["request_id"]
            .as_str()
            .map(str::to_owned)
            .context("the join answer carried no request_id")
    }

    /// `GET /v1/endpoints/device-join-requests/{id}`. `None` for a 404.
    pub async fn read(&self, id: &str) -> Result<Option<JoinStatus>> {
        let resp = self
            .http
            .get(format!(
                "{}/v1/endpoints/device-join-requests/{}",
                self.operator,
                seg(id)
            ))
            .timeout(
                http::Timeouts::at_most(http::JOIN_STATUS)
                    .request
                    .unwrap_or(http::JOIN_STATUS),
            )
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(refusal(resp).await.into());
        }
        let v: Value = resp.json().await?;
        Ok(Some(JoinStatus {
            state: v["state"].as_str().unwrap_or("pending").to_owned(),
            delegation: v.get("delegation").filter(|d| d.is_object()).cloned(),
        }))
    }

    /// `POST /v1/endpoints/device-join-requests/{id}/withdraw`.
    pub async fn withdraw(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/v1/endpoints/device-join-requests/{}/withdraw",
                self.operator,
                seg(id)
            ))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(refusal(resp).await.into());
        }
        Ok(())
    }

    /// `POST /v1/endpoints/enrollments` with the approved delegation.
    /// Returns (enrollment id, session token).
    pub async fn enroll(
        &self,
        hub_token: &str,
        airdress: &str,
        label: &str,
        identity_public: &[u8; 32],
        delegation: &Value,
    ) -> Result<(String, Redacted<String>)> {
        let resp = self
            .http
            .post(format!("{}/v1/endpoints/enrollments", self.operator))
            .json(&json!({
                "airdress": airdress,
                "role": "human_held",
                "key_custody": "client_held",
                "device_label": label,
                "device_session_public_key":
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identity_public),
                "delegation": delegation,
                "delegation_only": true,
                "device_kind": super::device::DEVICE_KIND,
                "transport_profile": "qr",
                "hub_token": hub_token,
            }))
            .send()
            .await
            .context("enroll: the operator is unreachable")?;
        if !resp.status().is_success() {
            return Err(refusal(resp).await.into());
        }
        let v: Value = resp.json().await?;
        Ok((
            v["enrollment_id"]
                .as_str()
                .context("no enrollment_id")?
                .to_owned(),
            Redacted::from(v["token"].as_str().context("no token")?),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_read_as_sentences() {
        assert!(explain("shell_host_offline", "").contains("offline"));
        assert_eq!(explain("zzz", "m"), "m [zzz]");
        assert_eq!(explain("zzz", ""), "zzz");
    }

    #[test]
    fn path_segments_are_escaped() {
        assert_eq!(seg("dev-box"), "dev-box");
        assert_eq!(seg("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn a_host_view_reads_the_operators_shape() {
        let v = serde_json::json!({
            "name": "dev", "enabled": true, "linked": true, "connected": true, "ready": true,
            "runsAsRoot": false, "shellKey": "SHA256:x", "shellKeyPublic": "AAAA",
            "hostVersion": "1", "os": "linux", "limits": {},
            "profiles": [{"id": "sh", "label": "Shell", "kind": "shell", "source": "process",
                          "state": "ready", "record": false, "notify": false}],
            "sessions": [{"id": "s", "profile": "sh", "attached": 1, "state": "working"}],
            "sessionsStale": false, "lastSeen": null
        });
        let h: HostView = serde_json::from_value(v).unwrap();
        assert_eq!(h.profiles[0].id, "sh");
        assert_eq!(h.sessions[0].id, "s");
        assert!(h.machine.is_none());
    }
}
