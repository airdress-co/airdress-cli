//! Operator-direct client for the function authoring routes — the same
//! routes the editor extension uses, and nothing else:
//!
//! - `GET  /v1/functions/templates[/{id}]`
//! - `POST /v1/functions/sources[?dry-run=true]` (the JSON encoding)
//! - `POST /v1/functions/{name}/promote[?dry-run=true]`
//! - `GET  /v1/functions/sources/{version}[/files/{path}]`
//! - `GET  /v1/functions/{name}/versions`
//! - `GET  /v1/functions/{name}/logs`
//!
//! and, for the deploy loop, the three resource-plane calls it needs:
//! `GET /v1/kinds/Function/{name}[/status]` and `POST /v1/apply`.
//!
//! Every request is authenticated one of two ways (SPEC-113 design §9.2):
//! the owner's hub bearer, or — for a CI runner with no hub profile — an
//! enrolled machine's RFC 9421 signature over the exact bytes sent.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde_json::Value;

use super::refusal::{self, Refusal, StaleBase};
use crate::machine::{self, MachineIdentity};
use crate::redact::Redacted;
use crate::ui;
use crate::{http, wire};

/// How a publish (or a dry run) ended.
#[derive(Debug)]
pub enum PublishOutcome {
    /// `200` / `201`: the operator's `SourcePublished` body.
    Published { created: bool, body: Value },
    /// `409 source_base_stale`.
    Stale(StaleBase),
    /// Any other structured refusal: `400`, `409`, `415`, `422`.
    Refused { status: u16, refusal: Refusal },
}

/// How a promote (or its dry run) ended.
#[derive(Debug)]
pub enum PromoteOutcome {
    /// `200`: `{ name, version, previous, generation, changed[, dryRun] }`.
    Promoted(Value),
    /// `409 source_base_stale`: the function runs another version than
    /// the one this promote was based on (`current`, possibly `null`).
    Stale {
        based_on: Option<String>,
        current: Option<String>,
        refusal: Refusal,
    },
    /// Any other structured refusal, verbatim.
    Refused { status: u16, refusal: Refusal },
    /// `404` or `405` with no refusal code: the route does not exist, so
    /// the operator predates promote.
    RouteMissing { status: u16 },
}

/// The one refusal every step turns into the same stop: the machine's
/// approval has lapsed. Returned as an error so any call can raise it.
#[derive(Debug)]
pub struct MachineAuthorizationExpired(pub String);

impl std::fmt::Display for MachineAuthorizationExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} — run `airdress-operator machine reauth`, then have the owner approve it",
            machine::AUTHORIZATION_EXPIRED_CODE,
            self.0
        )
    }
}

impl std::error::Error for MachineAuthorizationExpired {}

/// Who the requests are sent as.
#[derive(Clone)]
pub enum OperatorAuth {
    /// The owner's hub (ZITADEL) access token.
    Bearer(Redacted<String>),
    /// An enrolled machine: every request is signed, no bearer is sent.
    Machine(Arc<MachineIdentity>),
}

impl std::fmt::Debug for OperatorAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(…)"),
            Self::Machine(m) => write!(f, "Machine({})", m.keyid()),
        }
    }
}

#[derive(Debug)]
pub struct OperatorFunctionsClient {
    base_url: String,
    auth: OperatorAuth,
    http: reqwest::Client,
    /// The approval warning is printed once per run, not per request.
    warned: AtomicBool,
}

/// Percent-encode one path segment (a function name, a version, a
/// template id). `sha256:` versions carry a colon, which is legal in a
/// path segment, so only what is not is escaped.
pub(crate) fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A status that carries a structured refusal on the authoring routes.
const fn is_refusal_status(status: u16) -> bool {
    matches!(status, 400 | 403 | 404 | 409 | 415 | 422)
}

impl OperatorFunctionsClient {
    pub fn new(fqdn: &str, auth: OperatorAuth) -> Result<Self> {
        Self::with_base_url(format!("https://{}", fqdn.trim_matches('/')), auth)
    }

    pub fn with_base_url(base_url: String, auth: OperatorAuth) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            auth,
            http,
            warned: AtomicBool::new(false),
        })
    }

    /// The operator's host, for what a person reads.
    pub fn host(&self) -> String {
        reqwest::Url::parse(&self.base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| self.base_url.clone())
    }

    fn url(&self, path: &str, query: &[(&str, String)]) -> Result<String> {
        let base = format!("{}{path}", self.base_url);
        if query.is_empty() {
            return Ok(base);
        }
        Ok(reqwest::Url::parse_with_params(&base, query)
            .with_context(|| format!("`{base}` is not a URL"))?
            .to_string())
    }

    /// Send one request, authenticated as this client is. With a machine
    /// identity the exact URL and body bytes are signed; a `401` is always
    /// the machine's credential and is returned as an error (a lapsed
    /// approval as [`MachineAuthorizationExpired`]).
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        json_body: Option<&Value>,
    ) -> Result<reqwest::Response> {
        let body = json_body.map(serde_json::to_vec).transpose()?;
        let content_type = body.as_ref().map(|_| "application/json");
        let mut req = self.http.request(method.clone(), url);
        match &self.auth {
            OperatorAuth::Bearer(token) => {
                req = req.bearer_auth(token.expose());
                if let Some(ct) = content_type {
                    req = req.header(reqwest::header::CONTENT_TYPE, ct);
                }
            }
            OperatorAuth::Machine(id) => {
                let headers = id
                    .sign(
                        &method,
                        url,
                        content_type,
                        body.as_deref().unwrap_or_default(),
                        SystemTime::now(),
                    )
                    .await?;
                req = req.headers(headers);
            }
        }
        if let Some(bytes) = body {
            req = req.body(bytes);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| http::format_transport_error(url, method.as_str(), e))?;
        if let OperatorAuth::Machine(_) = &self.auth {
            self.note_authorization(&resp);
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                let text = resp.text().await.unwrap_or_default();
                let r = refusal::parse(401, &text);
                if r.error == machine::AUTHORIZATION_EXPIRED_CODE {
                    return Err(MachineAuthorizationExpired(r.message).into());
                }
                return Err(crate::exit::Failure::http(
                    401,
                    r.error.clone(),
                    format!(
                        "{method} {url}: the operator refused the machine's signature ({}: {})",
                        r.error, r.message
                    ),
                )
                .with_hint("check the machine key and its enrollment record")
                .into());
            }
        }
        Ok(resp)
    }

    /// Warn (once) when the answer says the machine's approval lapses soon.
    fn note_authorization(&self, resp: &reqwest::Response) {
        let Some(until) = resp
            .headers()
            .get(machine::AUTHORIZATION_EXPIRES_HEADER)
            .and_then(|v| v.to_str().ok())
        else {
            return;
        };
        if let Some(w) = machine::authorization_warning(until, SystemTime::now()) {
            if !self.warned.swap(true, Ordering::Relaxed) {
                ui::warn(w);
            }
        }
    }

    async fn get_json(&self, path: &str, query: &[(&str, String)], what: &str) -> Result<Value> {
        let url = self.url(path, query)?;
        let resp = self.send(reqwest::Method::GET, &url, None).await?;
        let resp = http::handle_status(resp, what).await?;
        resp.json::<Value>()
            .await
            .with_context(|| format!("parse {what} response"))
    }

    /// `GET /v1/functions/templates`.
    pub async fn templates(&self) -> Result<Value> {
        self.get_json(wire::functions::TEMPLATES, &[], "list function templates")
            .await
    }

    /// `GET /v1/functions/templates/{id}?functionId=…` — the template and
    /// its files, with `function.json` naming the author's function id
    /// instead of the template's placeholder.
    pub async fn template(&self, id: &str, function_id: &str) -> Result<Value> {
        self.get_json(
            &wire::functions::template(&segment(id)),
            &[("functionId", function_id.to_owned())],
            "read function template",
        )
        .await
    }

    /// `GET /v1/functions/sdk` — every Functions SDK version this operator
    /// carries, its status and modules, and `newest`.
    pub async fn sdk_catalogue(&self) -> Result<Value> {
        self.get_json(
            wire::functions::SDK,
            &[],
            "read the Functions SDK catalogue",
        )
        .await
    }

    /// `GET /v1/functions/sdk/{version}` — one version's catalogue entry and
    /// its `files`: every module and `sdk.d.ts`.
    pub async fn sdk_release(&self, version: &str) -> Result<Value> {
        self.get_json(
            &wire::functions::sdk_release(&segment(version)),
            &[],
            "read a Functions SDK version",
        )
        .await
    }

    /// `POST /v1/functions/sources` with the JSON body.
    pub async fn publish(&self, body: &Value, dry_run: bool) -> Result<PublishOutcome> {
        let mut url = format!("{}{}", self.base_url, wire::functions::SOURCES);
        if dry_run {
            url.push_str("?dry-run=true");
        }
        let resp = self.send(reqwest::Method::POST, &url, Some(body)).await?;
        let status = resp.status().as_u16();
        match status {
            200 | 201 => Ok(PublishOutcome::Published {
                created: status == 201,
                body: resp.json().await.context("parse publish response")?,
            }),
            s if is_refusal_status(s) => {
                let text = resp.text().await.unwrap_or_default();
                let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if status == 409 && value["error"] == "source_base_stale" {
                    return Ok(PublishOutcome::Stale(
                        serde_json::from_value(value).context("parse source_base_stale body")?,
                    ));
                }
                Ok(PublishOutcome::Refused {
                    status,
                    refusal: refusal::parse(status, &text),
                })
            }
            _ => {
                http::handle_status(resp, "publish function source").await?;
                anyhow::bail!("publish function source: unexpected HTTP {status}")
            }
        }
    }

    /// `POST /v1/functions/{name}/promote {version, basedOn}` — run another
    /// published version, and change nothing else.
    pub async fn promote(
        &self,
        name: &str,
        version: &str,
        based_on: Option<&str>,
        dry_run: bool,
    ) -> Result<PromoteOutcome> {
        let mut url = format!(
            "{}{}",
            self.base_url,
            wire::functions::of(&segment(name), "promote")
        );
        if dry_run {
            url.push_str("?dry-run=true");
        }
        let mut body = serde_json::json!({ "version": version });
        if let Some(base) = based_on {
            body["basedOn"] = base.into();
        }
        let resp = self.send(reqwest::Method::POST, &url, Some(&body)).await?;
        let status = resp.status().as_u16();
        if status == 200 {
            return Ok(PromoteOutcome::Promoted(
                resp.json().await.context("parse promote response")?,
            ));
        }
        let text = resp.text().await.unwrap_or_default();
        let refusal = refusal::parse(status, &text);
        // A route the operator does not have answers without a code of
        // ours: axum's bare 404, or 405 for a path another method owns.
        if matches!(status, 404 | 405) && refusal.error.starts_with("http_") {
            return Ok(PromoteOutcome::RouteMissing { status });
        }
        if status == 409 && refusal.error == "source_base_stale" {
            let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            return Ok(PromoteOutcome::Stale {
                based_on: value["basedOn"].as_str().map(str::to_owned),
                current: value["current"].as_str().map(str::to_owned),
                refusal,
            });
        }
        if is_refusal_status(status) {
            return Ok(PromoteOutcome::Refused { status, refusal });
        }
        anyhow::bail!("promote {name}: unexpected HTTP {status}: {}", text.trim())
    }

    /// `GET /v1/kinds/Function/{name}` — the applied manifest and its
    /// status, or `None` when there is no such Function.
    pub async fn function(&self, name: &str) -> Result<Option<Value>> {
        let url = format!("{}/v1/kinds/Function/{}", self.base_url, segment(name));
        let resp = self.send(reqwest::Method::GET, &url, None).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = http::handle_status(resp, "read Function").await?;
        resp.json().await.context("parse Function").map(Some)
    }

    /// [`Self::function`], but a `403` (no `Get` on it) is `Err` with the
    /// refusal's code, so a caller that only *may* read can tell.
    pub async fn function_if_readable(&self, name: &str) -> Result<Option<Option<Value>>> {
        let url = format!("{}/v1/kinds/Function/{}", self.base_url, segment(name));
        let resp = self.send(reqwest::Method::GET, &url, None).await?;
        match resp.status().as_u16() {
            403 => Ok(None),
            404 => Ok(Some(None)),
            _ => {
                let resp = http::handle_status(resp, "read Function").await?;
                Ok(Some(Some(resp.json().await.context("parse Function")?)))
            }
        }
    }

    /// `GET /v1/kinds/Function/{name}/status`. `None` on a `404`.
    pub async fn function_status(&self, name: &str) -> Result<Option<Value>> {
        let url = format!(
            "{}/v1/kinds/Function/{}/status",
            self.base_url,
            segment(name)
        );
        let resp = self.send(reqwest::Method::GET, &url, None).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = http::handle_status(resp, "read Function status").await?;
        resp.json().await.context("parse Function status").map(Some)
    }

    /// `POST /v1/apply[?dry-run=true]` with one manifest. A refusal is
    /// returned as `Err((status, refusal))`, verbatim.
    pub async fn apply(
        &self,
        manifest: &Value,
        dry_run: bool,
    ) -> Result<std::result::Result<Value, (u16, Refusal)>> {
        let mut url = format!("{}/v1/apply", self.base_url);
        if dry_run {
            url.push_str("?dry-run=true");
        }
        let resp = self
            .send(reqwest::Method::POST, &url, Some(manifest))
            .await?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(Ok(resp.json().await.context("parse apply response")?));
        }
        let text = resp.text().await.unwrap_or_default();
        Ok(Err((status, refusal::parse(status, &text))))
    }

    /// `GET /v1/functions/{name}/versions`.
    pub async fn versions(&self, name: &str) -> Result<Value> {
        self.get_json(
            &wire::functions::of(&segment(name), "versions"),
            &[],
            "read function versions",
        )
        .await
    }

    /// `GET /v1/functions/sources/{version}` — manifest, file index, signer.
    pub async fn source(&self, version: &str) -> Result<Value> {
        self.get_json(
            &wire::functions::source(&segment(version)),
            &[],
            "read source version",
        )
        .await
    }

    /// `GET /v1/functions/sources/{version}/files/{path}` — one file.
    pub async fn source_file(&self, version: &str, path: &str) -> Result<Vec<u8>> {
        let path = path
            .trim_start_matches('/')
            .split('/')
            .map(segment)
            .collect::<Vec<_>>()
            .join("/");
        let url = format!(
            "{}{}/files/{path}",
            self.base_url,
            wire::functions::source(&segment(version))
        );
        let resp = self.send(reqwest::Method::GET, &url, None).await?;
        let resp = http::handle_status(resp, "read source file").await?;
        Ok(resp
            .bytes()
            .await
            .context("read source file body")?
            .to_vec())
    }

    /// `GET /v1/functions/{name}/logs` — newest first, or with `after`
    /// the rows after that id, oldest first.
    pub async fn logs(&self, name: &str, query: &LogQuery) -> Result<Value> {
        let mut q: Vec<(&str, String)> = vec![("limit", query.limit.to_string())];
        if let Some(since) = &query.since {
            q.push(("since", since.clone()));
        }
        if let Some(inv) = &query.invocation {
            q.push(("invocation", inv.clone()));
        }
        if let Some(after) = query.after {
            q.push(("after", after.to_string()));
        }
        self.get_json(
            &wire::functions::of(&segment(name), "logs"),
            &q,
            "read function log",
        )
        .await
    }
}

/// The log route's query.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// RFC 3339; the route answers rows at or after it.
    pub since: Option<String>,
    pub invocation: Option<String>,
    /// A row id: only the rows after it, oldest first.
    pub after: Option<i64>,
    /// 1–1000; the operator clamps.
    pub limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::functions::test_support::{canned_operator, response};

    fn body() -> Value {
        serde_json::json!({ "name": "hello", "basedOn": "sha256:aaaa", "files": [] })
    }

    #[tokio::test]
    async fn a_stale_base_is_reported_with_both_versions_and_never_retried() {
        let stale = r#"{"error":"source_base_stale","message":"the function has moved since this tree was read","basedOn":"sha256:aaaa","current":"sha256:bbbb","currentPublishedAt":"2026-09-25T10:00:00Z","currentPublishedBy":"owner"}"#;
        // One response only: a second request would find no listener
        // answering and the test would hang or fail.
        let (base, server) = canned_operator(vec![response("409 Conflict", stale)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("owner.jwt".into()))
                .unwrap();
        let out = op.publish(&body(), false).await.unwrap();
        let PublishOutcome::Stale(s) = out else {
            panic!("expected a stale base, got {out:?}");
        };
        assert_eq!(s.based_on.as_deref(), Some("sha256:aaaa"));
        assert_eq!(s.current, "sha256:bbbb");

        let seen = server.await.unwrap();
        assert_eq!(seen.len(), 1);
        let head = seen[0].to_ascii_lowercase();
        assert!(
            head.starts_with("post /v1/functions/sources http/1.1"),
            "{head}"
        );
        assert!(head.contains("authorization: bearer owner.jwt"), "{head}");
        assert!(head.contains("content-type: application/json"), "{head}");
        assert!(
            seen[0].contains(r#""basedOn":"sha256:aaaa""#),
            "{}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn a_managed_externally_conflict_is_a_refusal_not_a_stale_base() {
        let body409 = r#"{"error":"source_managed_externally","message":"served from an import"}"#;
        let (base, server) = canned_operator(vec![response("409 Conflict", body409)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        match op.publish(&body(), false).await.unwrap() {
            PublishOutcome::Refused { status, refusal } => {
                assert_eq!(status, 409);
                assert_eq!(refusal.error, "source_managed_externally");
            }
            other => panic!("{other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_dry_run_asks_with_the_api_spelling_and_reads_locations() {
        let refusal = r#"{"error":"source_import_unresolved","message":"./nope does not resolve","locations":[{"path":"src/main.ts","line":1,"column":20}]}"#;
        let (base, server) =
            canned_operator(vec![response("422 Unprocessable Entity", refusal)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        let PublishOutcome::Refused { refusal, .. } = op.publish(&body(), true).await.unwrap()
        else {
            panic!("expected a refusal");
        };
        assert_eq!(
            super::super::refusal::format(&refusal),
            ["src/main.ts:1:20: SourceImportUnresolved: ./nope does not resolve"]
        );
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("POST /v1/functions/sources?dry-run=true HTTP/1.1"));
    }

    #[tokio::test]
    async fn a_created_version_is_published() {
        let ok = r#"{"version":"sha256:cccc","name":"hello","files":[],"entry":"src/main.ts","unreachable":[],"engineDigest":"x","transpiler":"y","warnings":[],"dryRun":false,"created":true}"#;
        let (base, server) = canned_operator(vec![response("201 Created", ok)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        match op.publish(&body(), false).await.unwrap() {
            PublishOutcome::Published { created, body } => {
                assert!(created);
                assert_eq!(body["version"], "sha256:cccc");
            }
            other => panic!("{other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn logs_pass_since_and_limit_as_the_route_names_them() {
        let (base, server) =
            canned_operator(vec![response("200 OK", r#"{"name":"hello","lines":[]}"#)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        op.logs(
            "hello",
            &LogQuery {
                since: Some("2026-09-25T10:00:00.5Z".into()),
                invocation: None,
                after: None,
                limit: 200,
            },
        )
        .await
        .unwrap();
        let seen = server.await.unwrap();
        assert!(
            seen[0].starts_with(
                "GET /v1/functions/hello/logs?limit=200&since=2026-09-25T10%3A00%3A00.5Z HTTP/1.1"
            ),
            "{}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn following_reverses_the_first_page_then_polls_after_the_last_id() {
        let first = r#"{"name":"hello","lines":[
            {"id":11,"invocation":"i2","at":"2026-09-25T10:00:02Z","level":"info","kind":"log","body":{"message":"b"}},
            {"id":10,"invocation":"i1","at":"2026-09-25T10:00:01Z","level":"info","kind":"log","body":{"message":"a"}}]}"#;
        let second = r#"{"name":"hello","lines":[
            {"id":12,"invocation":"i2","at":"2026-09-25T10:00:02Z","level":"info","kind":"log","body":{"message":"b"}},
            {"id":13,"invocation":"i3","at":"2026-09-25T10:00:03Z","level":"info","kind":"log","body":{"message":"c"}}]}"#;
        let (base, server) =
            canned_operator(vec![response("200 OK", first), response("200 OK", second)]).await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        let mut cursor = super::super::logs::Cursor::default();
        let mut shown = Vec::new();
        for _ in 0..2 {
            let q = LogQuery {
                after: cursor.after,
                limit: 200,
                ..LogQuery::default()
            };
            let page = op.logs("hello", &q).await.unwrap();
            for row in cursor.take(page["lines"].as_array().unwrap()) {
                shown.push(row["body"]["message"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(shown, ["a", "b", "b", "c"]);
        assert_eq!(cursor.after, Some(13));
        let seen = server.await.unwrap();
        assert!(
            seen[0].starts_with("GET /v1/functions/hello/logs?limit=200 HTTP/1.1"),
            "{}",
            seen[0]
        );
        assert!(
            seen[1].starts_with("GET /v1/functions/hello/logs?limit=200&after=11 HTTP/1.1"),
            "{}",
            seen[1]
        );
    }

    #[tokio::test]
    async fn a_template_is_asked_for_with_the_authors_function_id() {
        let (base, server) = canned_operator(vec![response(
            "200 OK",
            r#"{"id":"hello","files":{"function.json":"{\"id\": \"co.example.greeter\"}"}}"#,
        )])
        .await;
        let op =
            OperatorFunctionsClient::with_base_url(base, OperatorAuth::Bearer("t".into())).unwrap();
        let t = op.template("hello", "co.example.greeter").await.unwrap();
        assert!(t["files"]["function.json"]
            .as_str()
            .unwrap()
            .contains("co.example.greeter"));
        let seen = server.await.unwrap();
        assert!(
            seen[0].starts_with(
                "GET /v1/functions/templates/hello?functionId=co.example.greeter HTTP/1.1"
            ),
            "{}",
            seen[0]
        );
    }

    #[test]
    fn segments_keep_versions_readable_and_escape_the_rest() {
        assert_eq!(segment("sha256:ab"), "sha256:ab");
        assert_eq!(segment("a/b c"), "a%2Fb%20c");
    }
}
