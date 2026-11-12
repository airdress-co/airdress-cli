//! The two halves `airdress geo …` talks to.
//!
//! - [`GeoClient`]: the geo plugin at `geo.<airdress>` — OGC API Features
//!   (`/collections`, `/collections/{c}/items`), share links
//!   (`/collections/{c}/share-links`) and `/me/usage`. The plugin proxy in
//!   front of it authenticates the same bearer the operator API takes
//!   (SPEC-119 design §5.3), so one sign-in reaches both.
//! - [`GrantsClient`]: the operator's own `/v1/plugin-grants`, where a
//!   person shares a resource they govern (SPEC-117 117-2.1, SPEC-119 S2).
//!   Geo decides nothing about who may read; the airdress does, from these
//!   grants.
//!
//! Every refusal geo sends is `application/problem+json` with a closed
//! `code` (and a `path` into the body when it has one); the operator's grant
//! routes answer the same shape. Both are said as the code and a sentence,
//! never as the raw body.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exit::Failure;
use crate::http;
use crate::redact::Redacted;

/// GeoJSON's media type, which geo answers features with and takes writes in.
pub const GEOJSON: &str = "application/geo+json";

/// What `GET /collections/{c}/items` is asked.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ItemQuery {
    pub limit: Option<u32>,
    pub bbox: Option<String>,
    pub datetime: Option<String>,
    pub filter: Option<String>,
    pub cursor: Option<String>,
}

impl ItemQuery {
    fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        if let Some(l) = self.limit {
            q.push(("limit", l.to_string()));
        }
        for (k, v) in [
            ("bbox", &self.bbox),
            ("datetime", &self.datetime),
            ("filter", &self.filter),
            ("cursor", &self.cursor),
        ] {
            if let Some(v) = v {
                q.push((k, v.clone()));
            }
        }
        q
    }
}

/// An item geo has written: its id (from `Location` on a create) and the
/// new `ETag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Written {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

/// Body of `POST /collections/{c}/share-links`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision_m: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// Client for the geo plugin on one airdress.
#[derive(Debug)]
pub struct GeoClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl GeoClient {
    /// `https://geo.<fqdn>`.
    pub fn new(host: &str, bearer: Redacted<String>) -> Result<Self> {
        Self::with_base_url(format!("https://{}", host.trim_matches('/')), bearer)
    }

    pub fn with_base_url(base_url: String, bearer: Redacted<String>) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build geo HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer,
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
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

    async fn get_json(&self, path: &str, what: &str) -> Result<Value> {
        let url = self.url(path);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, what).await?;
        resp.json().await.with_context(|| format!("parse {what}"))
    }

    /// `GET /collections`.
    pub async fn collections(&self) -> Result<Value> {
        self.get_json("/collections", "list collections").await
    }

    /// `GET /collections/{c}`.
    pub async fn collection(&self, c: &str) -> Result<Value> {
        self.get_json(&format!("/collections/{c}"), "read collection")
            .await
    }

    /// `GET /collections/{c}/items`.
    pub async fn items(&self, c: &str, q: &ItemQuery) -> Result<Value> {
        let url = self.url(&format!("/collections/{c}/items"));
        let resp = self
            .send(self.http.get(&url).query(&q.pairs()), &url, "GET")
            .await?;
        let resp = checked(resp, "list items").await?;
        resp.json().await.context("parse items")
    }

    /// `GET /collections/{c}/items/{id}`: the Feature and its `ETag`.
    pub async fn item(&self, c: &str, id: &str) -> Result<(Value, Option<String>)> {
        let url = self.url(&format!("/collections/{c}/items/{id}"));
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "read item").await?;
        let etag = etag_of(&resp);
        let v = resp.json().await.context("parse item")?;
        Ok((v, etag))
    }

    /// `POST /collections/{c}/items`: a new item; geo names its id.
    pub async fn create(&self, c: &str, feature: &Value) -> Result<Written> {
        let url = self.url(&format!("/collections/{c}/items"));
        let req = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, GEOJSON)
            .body(feature.to_string());
        let resp = self.send(req, &url, "POST").await?;
        let resp = checked(resp, "create item").await?;
        let etag = etag_of(&resp);
        let id = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
            .map(str::to_owned)
            .context("geo created the item but did not say its id (no Location)")?;
        Ok(Written { id, etag })
    }

    /// `PUT /collections/{c}/items/{id}`, with `If-Match` when given.
    pub async fn replace(
        &self,
        c: &str,
        id: &str,
        feature: &Value,
        if_match: Option<&str>,
    ) -> Result<Written> {
        let url = self.url(&format!("/collections/{c}/items/{id}"));
        let mut req = self
            .http
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, GEOJSON)
            .body(feature.to_string());
        if let Some(e) = if_match {
            req = req.header(reqwest::header::IF_MATCH, e);
        }
        let resp = self.send(req, &url, "PUT").await?;
        let resp = checked(resp, "replace item").await?;
        Ok(Written {
            id: id.to_owned(),
            etag: etag_of(&resp),
        })
    }

    /// `DELETE /collections/{c}/items/{id}`, with `If-Match` when given.
    pub async fn delete(&self, c: &str, id: &str, if_match: Option<&str>) -> Result<()> {
        let url = self.url(&format!("/collections/{c}/items/{id}"));
        let mut req = self.http.delete(&url);
        if let Some(e) = if_match {
            req = req.header(reqwest::header::IF_MATCH, e);
        }
        let resp = self.send(req, &url, "DELETE").await?;
        checked(resp, "delete item").await?;
        Ok(())
    }

    /// `GET /me/usage`: what the caller holds and may hold, and who geo
    /// says they are.
    pub async fn usage(&self) -> Result<Value> {
        self.get_json("/me/usage", "read usage").await
    }

    /// `POST /collections/{c}/share-links`.
    pub async fn link_create(&self, c: &str, body: &MintBody) -> Result<Value> {
        let url = self.url(&format!("/collections/{c}/share-links"));
        let resp = self
            .send(self.http.post(&url).json(body), &url, "POST")
            .await?;
        let resp = checked(resp, "create share link").await?;
        resp.json().await.context("parse share link")
    }

    /// `GET /collections/{c}/share-links`: the caller's own, never a token.
    pub async fn links(&self, c: &str) -> Result<Value> {
        self.get_json(&format!("/collections/{c}/share-links"), "list share links")
            .await
    }

    /// `DELETE /collections/{c}/share-links/{rid}`.
    pub async fn link_revoke(&self, c: &str, rid: &str) -> Result<()> {
        let url = self.url(&format!("/collections/{c}/share-links/{rid}"));
        let resp = self.send(self.http.delete(&url), &url, "DELETE").await?;
        checked(resp, "revoke share link").await?;
        Ok(())
    }
}

fn etag_of(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// A grant on a plugin resource, as `/v1/plugin-grants` answers it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub install: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub namespace: String,
    pub resource: String,
    pub principal: String,
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Body of `POST /v1/plugin-grants`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GrantBody<'a> {
    pub install: &'a str,
    #[serde(rename = "type")]
    pub resource_type: &'a str,
    pub namespace: &'a str,
    pub resource: &'a str,
    pub principal: &'a str,
    pub actions: Vec<String>,
}

/// Client for the operator's `/v1/plugin-grants`.
#[derive(Debug)]
pub struct GrantsClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl GrantsClient {
    pub fn with_base_url(base_url: String, bearer: Redacted<String>) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer,
            http,
        })
    }

    /// The operator's base URL, for the installs lookup beside it.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The bearer, for the installs lookup beside it.
    pub fn bearer(&self) -> &Redacted<String> {
        &self.bearer
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

    /// `POST /v1/plugin-grants`.
    pub async fn create(&self, body: &GrantBody<'_>) -> Result<Grant> {
        let url = format!("{}/v1/plugin-grants", self.base_url);
        let resp = self
            .send(self.http.post(&url).json(body), &url, "POST")
            .await?;
        let resp = checked(resp, "grant").await?;
        resp.json().await.context("parse grant")
    }

    /// `GET /v1/plugin-grants?install=<id>`: the grants on what the caller
    /// governs.
    pub async fn list(&self, install: &str) -> Result<Vec<Grant>> {
        #[derive(Deserialize)]
        struct Grants {
            grants: Vec<Grant>,
        }
        let url = format!("{}/v1/plugin-grants", self.base_url);
        let resp = self
            .send(
                self.http.get(&url).query(&[("install", install)]),
                &url,
                "GET",
            )
            .await?;
        let resp = checked(resp, "list grants").await?;
        let g: Grants = resp.json().await.context("parse grants")?;
        Ok(g.grants)
    }

    /// `DELETE /v1/plugin-grants/{id}`.
    pub async fn revoke(&self, id: &str) -> Result<()> {
        if !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') || id.is_empty() {
            bail!("`{id}` is not a grant id");
        }
        let url = format!("{}/v1/plugin-grants/{id}", self.base_url);
        let resp = self.send(self.http.delete(&url), &url, "DELETE").await?;
        checked(resp, "revoke grant").await?;
        Ok(())
    }
}

/// A sentence for the closed codes geo and the grant routes answer with,
/// where the code alone would not tell a person what to do.
fn sentence(code: &str) -> Option<&'static str> {
    Some(match code {
        "not_found" => "not found — no such collection or item, or you may not read it",
        "item_not_found" => "no such item in this collection",
        "precondition_failed" => {
            "the item changed since that ETag was read — read it again (`airdress geo items get`) and retry"
        }
        "quota_exceeded" => "over your geo quota — `airdress geo usage` shows what you hold",
        "sealed_key_unavailable" => {
            "the collection is sealed with its person's own key; only they can open it"
        }
        "share_link_disabled" => "share links are off for this collection or this airdress",
        "share_ttl_too_long" => "that lifetime is longer than the collection allows",
        "precision_unsupported_geometry" => {
            "a collection that may hold lines or polygons is shared exactly or not at all"
        }
        "storage_migration_in_progress" => {
            "the collection is changing storage mode; try again once it is done"
        }
        "not_governor" => {
            "only a collection's person may share it (for a household collection, the airdress owner)"
        }
        "grant_exists" => "a grant to that principal on that collection already exists",
        "grant_not_found" => "no such grant on anything you govern",
        "install_not_found" => "no such plugin install on this airdress",
        "action_not_declared" => "geo does not declare that action",
        "unknown_type" | "scope_not_declared" => {
            "this geo install does not declare collections in that scope"
        }
        "person_required" => "only a person may do this, not a machine",
        "credential_invalid" => "your sign-in was not accepted — run `airdress auth login`",
        _ => return None,
    })
}

/// A non-2xx answer as a [`Failure`]: the body's `code` (problem+json, or
/// the operator's `{"error": …}`), a sentence, and the `path` it names.
pub(crate) async fn checked(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let url = resp.url().clone();
    let body = resp.text().await.unwrap_or_default();
    let v: Value = serde_json::from_str(&body).unwrap_or_default();
    let code = v
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| crate::exit::body_code(&body).filter(|c| !c.contains(' ')));
    let Some(code) = code else {
        return Err(http::status_failure(status.as_u16(), &url, &body, what).into());
    };
    let title = v.get("title").and_then(Value::as_str);
    let mut text = match (sentence(&code), title) {
        (Some(s), _) => format!("{what}: {s} ({code})"),
        (None, Some(t)) => format!("{what}: {t} ({code})"),
        (None, None) => format!("{what}: {code}"),
    };
    if let Some(p) = v.get("path").and_then(Value::as_str) {
        text.push_str(&format!(" at {p}"));
    }
    if code == "route_not_found" {
        text = format!("{what}: this airdress does not serve that route — is geo installed?");
    }
    Err(Failure::http(status.as_u16(), code, text)
        .with_answer(&v)
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_query_sends_only_what_was_asked() {
        assert!(ItemQuery::default().pairs().is_empty());
        let q = ItemQuery {
            limit: Some(10),
            bbox: Some("1,2,3,4".into()),
            cursor: Some("abc".into()),
            ..ItemQuery::default()
        };
        assert_eq!(
            q.pairs(),
            vec![
                ("limit", "10".to_owned()),
                ("bbox", "1,2,3,4".to_owned()),
                ("cursor", "abc".to_owned())
            ]
        );
    }

    #[test]
    fn a_mint_body_is_camel_case_and_sparse() {
        assert_eq!(
            serde_json::to_value(MintBody::default()).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(MintBody {
                precision_m: Some(1000),
                ttl: Some("7d".into())
            })
            .unwrap(),
            serde_json::json!({ "precisionM": 1000, "ttl": "7d" })
        );
    }

    #[test]
    fn a_grant_body_names_the_type_on_the_wire() {
        let v = serde_json::to_value(GrantBody {
            install: "01J",
            resource_type: "GeoCollection",
            namespace: "person:p1",
            resource: "trips",
            principal: "p2",
            actions: vec!["ReadData".into()],
        })
        .unwrap();
        assert_eq!(v["type"], "GeoCollection");
        assert!(v.get("resource_type").is_none());
    }
}
