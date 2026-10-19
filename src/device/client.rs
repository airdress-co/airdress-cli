//! Operator-direct HTTP client for SPEC-044 device pairing.
//!
//! The CLI talks straight to `https://<airdress-fqdn>/v1/endpoints/*`
//! using its existing hub OAuth bearer (a ZITADEL access token). The
//! operator's [`OwnerPrincipal`][op-owner] extractor validates the
//! token via JWKS and asserts `claims.sub == owner_sub`.
//!
//! [op-owner]: https://github.com/airdress-co/airdress-operator/blob/main/crates/airdress-operator/src/enrollment/owner.rs

use std::fmt;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::http;
use crate::redact::Redacted;

/// String wrapper for the pairing code. Custom `Debug` masks the
/// value so the secret never lands in `tracing::debug!` output or
/// the `#[derive(Debug)]` of a containing struct.
///
/// v1 of `device pair` never reads the raw code (the operator returns
/// a ready-to-render `pair_uri` that embeds it). The newtype + masked
/// Debug stays in place so future callers that DO need to expose the
/// code (e.g. a `--show-code` flag) do so explicitly via
/// [`expose`](Self::expose).
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Borrow the underlying string. Caller is responsible for not
    /// logging it; the method name is the explicit opt-in.
    #[must_use]
    #[allow(dead_code)] // reserved for SPEC-044.x (--show-code, scripted consumers)
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(\"***\")")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Body of `POST /v1/endpoints/pairing-codes` on the operator. Field
/// names match SPEC-011 §11.4.
#[derive(Debug, Serialize)]
struct MintRequest<'a> {
    role: &'static str,
    key_custody: &'static str,
    transport_profile: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_label: Option<&'a str>,
    ttl_seconds: u64,
}

/// Operator's response from `POST /v1/endpoints/pairing-codes`.
#[derive(Debug, Deserialize)]
struct MintResponse {
    id: uuid::Uuid,
    code: SecretString,
    expires_at: DateTime<Utc>,
    pair_uri: String,
}

/// Resolved pairing-code mint result exposed to the rest of the CLI.
///
/// The bare `code` is intentionally NOT exposed here — the operator's
/// `pair_uri` field already embeds it in render-ready form, and
/// exposing the raw code on the CLI surface invites accidental logging.
#[derive(Debug)]
pub struct PairingMint {
    /// The **pairing code's** id, which is what the operator returns and
    /// what the completion signal is keyed by.
    ///
    /// This was previously named `enrollment_id` and polled against
    /// `/v1/endpoints/enrollments/{id}` — a different table's primary key,
    /// so the poll 404'd forever and every successful pairing was reported
    /// as a timeout.
    pub pairing_code_id: uuid::Uuid,
    pub expires_at: DateTime<Utc>,
    pub pair_uri: String,
}

/// Outcome of a single poll of `GET /v1/endpoints/pairing-codes/{id}`.
#[derive(Debug)]
pub enum PairingPollResult {
    /// Pairing code hasn't been consumed yet — operator returns 404.
    Pending,
    /// Pairing completed; carries the freshly-enrolled device's metadata.
    Consumed(PairedDevice),
    /// Pairing code expired (5-minute TTL elapsed) before consumption.
    Expired,
}

#[derive(Debug, Deserialize)]
pub struct PairedDevice {
    pub id: uuid::Uuid,
    pub device_label: String,
    pub transport_profile: String,
    pub created_at: DateTime<Utc>,
}

/// The operator's answer to a dry-run revoke.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevokePreview {
    pub enrollment_id: uuid::Uuid,
    pub airdress: String,
    pub device_label: String,
    /// Active enrollments left on that airdress once this one is gone.
    /// Absent on operators that do not report it.
    #[serde(default)]
    pub remaining_active_enrollments: Option<u64>,
}

/// One row of `GET /v1/endpoints/enrollments`, as `device list` reads it.
///
/// Every field an older operator may not send is optional, and "not sent"
/// is kept distinct from `false`: an operator that predates
/// `delegation_only` cannot say whether a `client_held` row is a phone or a
/// terminal, and the list says "unknown" rather than guessing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollmentRow {
    pub id: uuid::Uuid,
    pub device_label: String,
    pub key_custody: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub principal_id: Option<uuid::Uuid>,
    /// `human` or `agent`; absent from an operator that predates agents,
    /// which had none.
    #[serde(default)]
    pub device_class: Option<String>,
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub suspended_at: Option<DateTime<Utc>>,
    /// Holds a root-signed delegation and never the root. `None` when the
    /// operator does not send it.
    #[serde(default)]
    pub delegation_only: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EnrollmentListResponse {
    enrollments: Vec<EnrollmentRow>,
}

#[derive(Debug, Deserialize)]
struct SubUserRow {
    id: uuid::Uuid,
}

/// The operator's pairing-code status (SPEC-049).
#[derive(Debug, Deserialize)]
struct PairingCodeStatus {
    state: String,
    enrollment_id: Option<uuid::Uuid>,
}

/// Operator client scoped to the SPEC-044 enrollment routes.
#[derive(Debug)]
pub struct OperatorEnrollClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl OperatorEnrollClient {
    /// Build a client for the operator at `fqdn`. The scheme is
    /// hard-coded to HTTPS — operators run TLS in production
    /// (SPEC-031). Tests may pass a `https://localhost:NNNN` URL via
    /// [`with_base_url`](Self::with_base_url).
    pub fn new(fqdn: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        let base_url = format!("https://{}", fqdn.trim_matches('/'));
        Self::with_base_url(base_url, bearer)
    }

    /// Build a client with an explicit base URL. Used by tests and by
    /// callers that already hold the full URL (e.g. when the hub
    /// returns a `direct_url` field).
    pub fn with_base_url(base_url: String, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        let http = http::client_builder()
            // The pairing-codes call is fast (no key generation), so
            // the default timeout is fine. The polling client uses a
            // tighter per-request budget — see watcher.rs.
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer: bearer.into(),
            http,
        })
    }

    /// SPEC-044 §3 — mint a pairing code on the operator.
    pub async fn mint_pairing(&self, label: Option<&str>) -> Result<PairingMint> {
        let url = format!("{}/v1/endpoints/pairing-codes", self.base_url);
        let body = MintRequest {
            role: "human_held",
            key_custody: "client_held",
            transport_profile: "qr",
            device_label: label,
            ttl_seconds: 300,
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.bearer.expose())
            .json(&body)
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "POST", e))?;
        let resp = http::handle_status(resp, "mint pairing code").await?;
        let payload: MintResponse = resp.json().await.context("parse mint response")?;
        // payload.code is the raw secret — drop it here. The operator
        // already returned a ready-to-render pair_uri that embeds it.
        drop(payload.code);
        Ok(PairingMint {
            pairing_code_id: payload.id,
            expires_at: payload.expires_at,
            pair_uri: payload.pair_uri,
        })
    }

    /// SPEC-044 §5 — poll the operator for pairing completion. Maps
    /// the operator's HTTP status to a typed outcome:
    ///
    /// - `200 OK` → [`PairingPollResult::Consumed`]
    /// - `404 Not Found` → [`PairingPollResult::Pending`]
    /// - `410 Gone` → [`PairingPollResult::Expired`]
    /// - Anything else → user-readable `anyhow::Error`
    pub async fn poll_pairing_code(&self, code_id: uuid::Uuid) -> Result<PairingPollResult> {
        let url = format!("{}/v1/endpoints/pairing-codes/{code_id}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            // The code is gone or not ours. Treat as pending rather than
            // erroring: the watcher's own deadline is the authority.
            return Ok(PairingPollResult::Pending);
        }
        let resp = http::handle_status(resp, "poll pairing code").await?;
        let status: PairingCodeStatus = resp.json().await.context("parse pairing status")?;

        match status.state.as_str() {
            "expired" => Ok(PairingPollResult::Expired),
            "consumed" => {
                let Some(enrollment_id) = status.enrollment_id else {
                    // Consumed but not yet linked — the operator writes the
                    // link just after minting. A tick later it will be there.
                    return Ok(PairingPollResult::Pending);
                };
                self.get_enrollment(enrollment_id).await
            }
            _ => Ok(PairingPollResult::Pending),
        }
    }

    /// Whether `enrollment_id` is an active enrollment this bearer can see.
    ///
    /// The operator answers 404 for revoked, unknown and out-of-scope ids
    /// alike, and its dry-run revoke does not distinguish a revoked row
    /// (revoking is idempotent), so this is the only way to tell the user
    /// "nothing to revoke" instead of previewing a revoke that changes
    /// nothing.
    pub async fn enrollment_is_active(&self, enrollment_id: uuid::Uuid) -> Result<bool> {
        let url = format!("{}/v1/endpoints/enrollments/{enrollment_id}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        if resp.status().as_u16() == 404 {
            return Ok(false);
        }
        http::handle_status(resp, "read enrollment").await?;
        Ok(true)
    }

    /// Ask the operator what revoking `enrollment_id` would do, without
    /// revoking it (`DELETE …?dry_run=true`).
    ///
    /// The operator runs the same authorization as the real revoke, so a
    /// refusal here (403 / 404) is the refusal the real call would get.
    /// That makes it both the preview and the check.
    pub async fn preview_revoke(&self, enrollment_id: uuid::Uuid) -> Result<RevokePreview> {
        let url = format!(
            "{}/v1/endpoints/enrollments/{enrollment_id}?dry_run=true",
            self.base_url
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "DELETE", e))?;
        let resp = http::handle_status(resp, "preview enrollment revocation").await?;
        let is_dry_run = resp.headers().get("X-Dry-Run").is_some_and(|v| v == "true");
        if !is_dry_run {
            // An operator that ignored `dry_run` has just revoked the
            // enrollment. Say so rather than asking for confirmation of
            // something already done.
            anyhow::bail!(
                "the operator did not honour dry_run — enrollment {enrollment_id} \
                 may already be revoked; check with the operator before retrying"
            );
        }
        resp.json().await.context("parse revocation preview")
    }

    /// Revoke `enrollment_id` (`DELETE /v1/endpoints/enrollments/{id}`).
    pub async fn revoke_enrollment(&self, enrollment_id: uuid::Uuid) -> Result<()> {
        let url = format!("{}/v1/endpoints/enrollments/{enrollment_id}", self.base_url);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "DELETE", e))?;
        http::handle_status(resp, "revoke enrollment").await?;
        Ok(())
    }

    /// Every active enrollment this sign-in may see
    /// (`GET /v1/endpoints/enrollments`). With the owner's sign-in that is
    /// every device on the airdress.
    pub async fn list_enrollments(&self) -> Result<Vec<EnrollmentRow>> {
        let url = format!("{}/v1/endpoints/enrollments", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let resp = http::handle_status(resp, "list enrollments").await?;
        let body: EnrollmentListResponse = resp.json().await.context("parse enrollment list")?;
        Ok(body.enrollments)
    }

    /// The ids of the airdress's active members other than its owner
    /// (`GET /v1/admin/sub-users`), or `None` when the operator will not say
    /// — an older one, or a sign-in that is not the owner's. Only used to
    /// tell a member's device from the owner's, so a refusal is not an error.
    pub async fn sub_user_ids(&self) -> Option<Vec<uuid::Uuid>> {
        let url = format!("{}/v1/admin/sub-users?limit=200", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| tracing::debug!(error = %e, "sub-user list unreachable"))
            .ok()?;
        if !resp.status().is_success() {
            tracing::debug!(status = %resp.status(), "sub-user list refused");
            return None;
        }
        let rows: Vec<SubUserRow> = resp
            .json()
            .await
            .map_err(|e| tracing::debug!(error = %e, "sub-user list unreadable"))
            .ok()?;
        Some(rows.into_iter().map(|r| r.id).collect())
    }

    /// Read the enrollment a redeemed code produced.
    async fn get_enrollment(&self, enrollment_id: uuid::Uuid) -> Result<PairingPollResult> {
        let url = format!("{}/v1/endpoints/enrollments/{enrollment_id}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        if resp.status().as_u16() == 404 {
            return Ok(PairingPollResult::Pending);
        }
        let resp = http::handle_status(resp, "read enrollment").await?;
        let device: PairedDevice = resp.json().await.context("parse enrollment response")?;
        Ok(PairingPollResult::Consumed(device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One canned HTTP response per connection, recording each request's
    /// head so a test can assert what was sent. Enough for a client that
    /// makes one request per connection; no mock-server dependency.
    async fn canned_operator(
        responses: Vec<String>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            for response in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap();
                seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                sock.write_all(response.as_bytes()).await.unwrap();
                sock.shutdown().await.unwrap();
            }
            seen
        });
        (base, handle)
    }

    fn response(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{headers}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn preview_response(dry_run_header: bool) -> String {
        let body = r#"{"enrollment_id":"6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11","airdress":"ada.a.airdr.es","device_label":"dead phone","would_revoke":true,"remaining_active_enrollments":0}"#;
        let headers = if dry_run_header {
            "Content-Type: application/json\r\nX-Dry-Run: true\r\n"
        } else {
            "Content-Type: application/json\r\n"
        };
        response("200 OK", headers, body)
    }

    fn id() -> uuid::Uuid {
        "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11".parse().unwrap()
    }

    #[tokio::test]
    async fn preview_revoke_asks_for_a_dry_run_with_the_owner_bearer() {
        let (base, server) = canned_operator(vec![preview_response(true)]).await;
        let op = OperatorEnrollClient::with_base_url(base, "owner.jwt.token").unwrap();

        let preview = op.preview_revoke(id()).await.unwrap();
        assert_eq!(preview.enrollment_id, id());
        assert_eq!(preview.airdress, "ada.a.airdr.es");
        assert_eq!(preview.device_label, "dead phone");
        assert_eq!(preview.remaining_active_enrollments, Some(0));

        let seen = server.await.unwrap();
        let head = seen[0].to_ascii_lowercase();
        assert!(
            head.starts_with(
                "delete /v1/endpoints/enrollments/6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11?dry_run=true "
            ),
            "{head}"
        );
        assert!(
            head.contains("authorization: bearer owner.jwt.token"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn a_preview_the_operator_did_not_treat_as_dry_run_is_an_error() {
        // Same body, no X-Dry-Run header: the operator ran it for real.
        let (base, server) = canned_operator(vec![preview_response(false)]).await;
        let op = OperatorEnrollClient::with_base_url(base, "t").unwrap();
        let err = op.preview_revoke(id()).await.unwrap_err().to_string();
        assert!(err.contains("did not honour dry_run"), "{err}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_revoked_or_unknown_enrollment_is_not_active() {
        let (base, server) = canned_operator(vec![
            response("404 Not Found", "", ""),
            response("200 OK", "Content-Type: application/json\r\n", "{}"),
        ])
        .await;
        let op = OperatorEnrollClient::with_base_url(base, "t").unwrap();
        assert!(!op.enrollment_is_active(id()).await.unwrap());
        assert!(op.enrollment_is_active(id()).await.unwrap());
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with(
            "GET /v1/endpoints/enrollments/6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11 HTTP/1.1"
        ));
    }

    #[tokio::test]
    async fn revoke_sends_a_plain_delete() {
        let (base, server) = canned_operator(vec![response("204 No Content", "", "")]).await;
        let op = OperatorEnrollClient::with_base_url(base, "owner.jwt.token").unwrap();
        op.revoke_enrollment(id()).await.unwrap();
        let seen = server.await.unwrap();
        let head = seen[0].to_ascii_lowercase();
        assert!(
            head.starts_with(
                "delete /v1/endpoints/enrollments/6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11 http/1.1"
            ),
            "{head}"
        );
        assert!(!head.contains("dry_run"), "{head}");
    }

    #[tokio::test]
    async fn a_refused_revoke_surfaces_the_operator_refusal() {
        let (base, server) = canned_operator(vec![response("403 Forbidden", "", "")]).await;
        let op = OperatorEnrollClient::with_base_url(base, "not-the-owner").unwrap();
        let err = op.preview_revoke(id()).await.unwrap_err().to_string();
        assert!(err.contains("forbidden"), "{err}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn the_list_keeps_an_absent_field_apart_from_false() {
        // One row from a current operator, one from an operator that
        // predates `delegation_only` and `device_class`.
        let body = r#"{"enrollments":[
            {"id":"6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11","device_label":"Galaxy S23",
             "key_custody":"client_held","created_at":"2026-10-01T00:00:00Z",
             "last_seen_at":"2026-10-20T08:00:00Z","device_class":"human",
             "delegation_only":false},
            {"id":"7f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11","device_label":"old row",
             "key_custody":"client_held","created_at":"2026-09-01T00:00:00Z"}]}"#;
        let (base, server) = canned_operator(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            body,
        )])
        .await;
        let op = OperatorEnrollClient::with_base_url(base, "owner.jwt.token").unwrap();
        let rows = op.list_enrollments().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].delegation_only, Some(false));
        assert_eq!(rows[1].delegation_only, None);
        assert_eq!(rows[1].device_class, None);
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("GET /v1/endpoints/enrollments HTTP/1.1"));
    }

    #[tokio::test]
    async fn a_refused_member_list_is_not_an_error() {
        let (base, server) = canned_operator(vec![response("403 Forbidden", "", "")]).await;
        let op = OperatorEnrollClient::with_base_url(base, "t").unwrap();
        assert_eq!(op.sub_user_ids().await, None);
        server.await.unwrap();
    }

    #[test]
    fn secret_string_debug_masks_value() {
        let s = SecretString::from("super-secret-code".to_owned());
        let formatted = format!("{s:?}");
        assert_eq!(formatted, "SecretString(\"***\")");
        assert!(!formatted.contains("super-secret"));
    }

    #[test]
    fn secret_string_expose_returns_raw() {
        let s = SecretString::from("abc".to_owned());
        assert_eq!(s.expose(), "abc");
    }

    #[test]
    fn secret_string_roundtrips_through_json() {
        let json = r#""raw-token-value""#;
        let s: SecretString = serde_json::from_str(json).unwrap();
        assert_eq!(s.expose(), "raw-token-value");
        let back = serde_json::to_string(&s).unwrap();
        assert_eq!(back, json);
    }
}
