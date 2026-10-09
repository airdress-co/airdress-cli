//! Operator-direct HTTP client for SPEC-033 declarative-resource
//! routes. Mirrors `device::client::OperatorEnrollClient` but covers
//! `POST /v1/apply`, `GET /v1/kinds[/...]`, and `DELETE /v1/kinds/...`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// Note: most wire types only deserialise; a few (DeleteResponse,
// ApplyResult, Condition) also need Serialize because they're echoed
// back into JSON envelopes the CLI prints.

use crate::http;
use crate::redact::Redacted;

/// Wire shape returned by every read endpoint that surfaces a single
/// resource. The operator's `ResourceView` (server side) deserialises
/// here byte-for-byte.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceView {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: ResourceMetadata,
    pub spec: serde_json::Value,
    pub status: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceMetadata {
    pub name: String,
    pub generation: i64,
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(rename = "resourceVersion")]
    pub resource_version: String,
    #[serde(default)]
    pub labels: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub last_reconciled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceList {
    pub kind: String,
    pub items: Vec<ResourceView>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KindsList {
    pub kinds: Vec<KindSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KindSummary {
    pub kind: String,
    pub api_version: String,
    #[serde(default)]
    pub summary_condition_types: Vec<String>,
}

/// Response body of `POST /v1/apply` (both dry-run and non-dry-run).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplyResult {
    pub kind: String,
    pub name: String,
    /// `created | configured | unchanged | would_create | would_update`.
    pub action: String,
    pub generation: i64,
    #[serde(default)]
    pub previous_generation: Option<i64>,
    #[serde(default)]
    pub resource_version: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusResponse {
    pub kind: String,
    pub name: String,
    // Wire-shape parity with the operator's `StatusResponse`. The
    // describe verb reads phase + conditions; the rest are kept so
    // future status pollers (watch loop, prompt integrations) deserialise
    // the full response without re-touching this struct.
    #[allow(dead_code)]
    pub generation: i64,
    #[allow(dead_code)]
    #[serde(default)]
    pub observed_generation: Option<i64>,
    pub phase: String,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[allow(dead_code)]
    #[serde(default)]
    pub last_reconciled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    #[serde(rename = "type")]
    pub ty: String,
    pub status: String,
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeleteResponse {
    pub kind: String,
    pub name: String,
    /// `deleted` if the row existed, `noop` if it did not.
    pub action: String,
}

/// Operator client scoped to the SPEC-033 routes.
#[derive(Debug)]
pub struct OperatorResourcesClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl OperatorResourcesClient {
    /// HTTPS to `https://<fqdn>`. The scheme is hard-coded — tests and
    /// dev callers that need a different scheme/port use
    /// [`with_base_url`](Self::with_base_url).
    pub fn new(fqdn: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        let base_url = format!("https://{}", fqdn.trim_matches('/'));
        Self::with_base_url(base_url, bearer)
    }

    /// Explicit base URL. Pair with `--operator-url` for dev work.
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

    /// `POST /v1/apply` (or `?dry-run=true`). The body is one manifest;
    /// callers loop for multi-doc files.
    pub async fn apply(&self, manifest: &serde_json::Value, dry_run: bool) -> Result<ApplyResult> {
        let mut url = format!("{}/v1/apply", self.base_url);
        if dry_run {
            url.push_str("?dry-run=true");
        }
        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.bearer.expose())
            .json(manifest)
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "POST", e))?;
        let resp = http::handle_status(resp, "apply manifest").await?;
        resp.json::<ApplyResult>()
            .await
            .context("parse apply response")
    }

    /// `GET /v1/kinds` — list registered Kinds.
    pub async fn list_kinds(&self) -> Result<KindsList> {
        let url = format!("{}/v1/kinds", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let resp = http::handle_status(resp, "list Kinds").await?;
        resp.json::<KindsList>()
            .await
            .context("parse list-kinds response")
    }

    /// `GET /v1/kinds/{kind}` — list resources of one Kind.
    pub async fn list_resources(&self, kind: &str) -> Result<ResourceList> {
        let url = format!("{}/v1/kinds/{kind}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let resp = http::handle_status(resp, "list resources").await?;
        resp.json::<ResourceList>()
            .await
            .context("parse list-resources response")
    }

    /// `GET /v1/kinds/{kind}/{name}` — read one resource.
    pub async fn get_one(&self, kind: &str, name: &str) -> Result<ResourceView> {
        let url = format!("{}/v1/kinds/{kind}/{name}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let resp = http::handle_status(resp, "read resource").await?;
        resp.json::<ResourceView>()
            .await
            .context("parse read-resource response")
    }

    /// `GET /v1/kinds/{kind}/{name}/status` — light-weight status read.
    pub async fn get_status(&self, kind: &str, name: &str) -> Result<StatusResponse> {
        let url = format!("{}/v1/kinds/{kind}/{name}/status", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "GET", e))?;
        let resp = http::handle_status(resp, "read status").await?;
        resp.json::<StatusResponse>()
            .await
            .context("parse status response")
    }

    /// `DELETE /v1/kinds/{kind}/{name}`.
    pub async fn delete(&self, kind: &str, name: &str) -> Result<DeleteResponse> {
        let url = format!("{}/v1/kinds/{kind}/{name}", self.base_url);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(&url, "DELETE", e))?;
        let resp = http::handle_status(resp, "delete resource").await?;
        resp.json::<DeleteResponse>()
            .await
            .context("parse delete response")
    }
}

/// SPEC-033 §6.5 — `<kind>/<name>` or `<kind>` reference parser.
/// Returns `(kind, Some(name))` for slash-form, `(kind, None)` for
/// bare-kind. Empty either side is an error.
pub fn parse_ref(s: &str) -> Result<(String, Option<String>)> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty resource reference — expected `<Kind>` or `<Kind>/<name>`");
    }
    let mut parts = s.splitn(2, '/');
    let kind = parts.next().unwrap_or_default();
    let name = parts.next();
    if kind.is_empty() {
        anyhow::bail!("missing Kind in reference '{s}'");
    }
    match name {
        None => Ok((kind.to_owned(), None)),
        Some("") => anyhow::bail!("missing name after '/' in reference '{s}'"),
        Some(n) => Ok((kind.to_owned(), Some(n.to_owned()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_kind_only() {
        let (k, n) = parse_ref("InferencePoolMember").unwrap();
        assert_eq!(k, "InferencePoolMember");
        assert!(n.is_none());
    }

    #[test]
    fn parse_ref_kind_and_name() {
        let (k, n) = parse_ref("InferencePoolMember/my-nas").unwrap();
        assert_eq!(k, "InferencePoolMember");
        assert_eq!(n.as_deref(), Some("my-nas"));
    }

    #[test]
    fn parse_ref_rejects_empty() {
        assert!(parse_ref("").is_err());
        assert!(parse_ref("   ").is_err());
    }

    #[test]
    fn parse_ref_rejects_trailing_slash() {
        assert!(parse_ref("InferencePoolMember/").is_err());
    }

    #[test]
    fn parse_ref_rejects_leading_slash() {
        // "" before the slash → empty Kind.
        assert!(parse_ref("/name").is_err());
    }
}
