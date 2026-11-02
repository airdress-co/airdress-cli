//! The operator's `/v1/work/items` routes, over the person's own bearer.

use anyhow::{Context as _, Result};
use serde_json::{json, Map, Value};

use crate::http;
use crate::redact::Redacted;

/// A client for one operator's work routes.
#[derive(Debug)]
pub struct WorkClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl WorkClient {
    /// Explicit base URL (`https://<fqdn>`, or `--operator-url` in dev).
    pub fn with_base_url(base_url: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer: bearer.into(),
            http,
        })
    }

    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        url: &str,
        method: &str,
        what: &str,
    ) -> Result<Value> {
        let resp = req
            .bearer_auth(self.bearer.expose())
            .send()
            .await
            .map_err(|e| http::format_transport_error(url, method, e))?;
        let resp = http::handle_status(resp, what).await?;
        resp.json::<Value>()
            .await
            .with_context(|| format!("parse {what} response"))
    }

    /// `GET /v1/work/items?view=…&limit=…`.
    pub async fn list(&self, view: &str, limit: u32) -> Result<Value> {
        let url = format!("{}/v1/work/items?view={view}&limit={limit}", self.base_url);
        self.send(self.http.get(&url), &url, "GET", "list work items")
            .await
    }

    /// `GET /v1/work/items/{id}`.
    pub async fn get(&self, id: uuid::Uuid) -> Result<Value> {
        let url = format!("{}/v1/work/items/{id}", self.base_url);
        self.send(self.http.get(&url), &url, "GET", "read work item")
            .await
    }

    /// `POST /v1/work/items`.
    pub async fn create(&self, body: &Value) -> Result<Value> {
        let url = format!("{}/v1/work/items", self.base_url);
        self.send(
            self.http.post(&url).json(body),
            &url,
            "POST",
            "create work item",
        )
        .await
    }

    /// `POST /v1/work/items/{id}/status`.
    pub async fn set_status(&self, id: uuid::Uuid, to: &str) -> Result<Value> {
        let url = format!("{}/v1/work/items/{id}/status", self.base_url);
        self.send(
            self.http.post(&url).json(&json!({ "to": to })),
            &url,
            "POST",
            "move work item",
        )
        .await
    }

    /// `POST /v1/work/items/{id}/answer`.
    pub async fn answer(
        &self,
        id: uuid::Uuid,
        text: &str,
        cost: &str,
        schedule: &str,
    ) -> Result<Value> {
        let url = format!("{}/v1/work/items/{id}/answer", self.base_url);
        let body = json!({ "text": text, "costImpact": cost, "scheduleImpact": schedule });
        self.send(self.http.post(&url).json(&body), &url, "POST", "answer RFI")
            .await
    }

    /// `GET /v1/work/items/{id}/history`.
    pub async fn history(&self, id: uuid::Uuid) -> Result<Value> {
        let url = format!("{}/v1/work/items/{id}/history", self.base_url);
        self.send(self.http.get(&url), &url, "GET", "read work item history")
            .await
    }

    /// Turn names and ids into ids. Names are looked up once, in the
    /// airdress's people (`GET /v1/admin/sub-users`, the owner's to read),
    /// and only when a name is given.
    pub async fn resolve_people(&self, who: &[String]) -> Result<Vec<uuid::Uuid>> {
        let mut out = Vec::with_capacity(who.len());
        let mut people: Option<Map<String, Value>> = None;
        for w in who {
            if let Ok(id) = w.parse::<uuid::Uuid>() {
                out.push(id);
                continue;
            }
            if people.is_none() {
                people = Some(self.people().await?);
            }
            out.push(super::match_person(
                w,
                people.as_ref().unwrap_or(&Map::new()),
            )?);
        }
        Ok(out)
    }

    async fn people(&self) -> Result<Map<String, Value>> {
        let url = format!("{}/v1/admin/sub-users?limit=200", self.base_url);
        let rows = self
            .send(
                self.http.get(&url),
                &url,
                "GET",
                "look up people by name (owner only; pass ids otherwise)",
            )
            .await?;
        let mut map = Map::new();
        for r in rows.as_array().into_iter().flatten() {
            if let (Some(name), Some(id)) = (r["display_name"].as_str(), r["id"].as_str()) {
                map.insert(name.to_owned(), json!(id));
            }
        }
        Ok(map)
    }
}
