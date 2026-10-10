//! The operator's event routes.
//!
//! - `GET  /v1/events/catalog` — every event type the operator can record
//!   and every interception point, `{catalog_version, events[], points[]}`.
//!   Whoever may apply may read it.
//! - `GET  /v1/events/signing-key` — the `whpk_` key a receiver verifies
//!   `v1a` deliveries with. Public: served without authentication.
//! - `POST /v1/event-subscriptions/{name}/redeliver` — `{eventId}` or
//!   `{since}`; answers `202 {requeued}`.
//! - `POST /v1/event-subscriptions/{name}/test` — a synthetic test event to
//!   that subscription only; answers `202 {eventId}`.
//!
//! Redeliver and test are for the subscription's owning person (the owner
//! may also act on a machine's). This client only ever sends a person's
//! hub bearer. A redelivered event is held to the
//! same matcher as a live one, so redelivery never sends what the
//! subscription could not have received.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::functions::client::segment;
use crate::http;
use crate::machine_admin::client::error_code;
use crate::redact::Redacted;

/// What to send again: one event, or everything since an instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redeliver {
    EventId(uuid::Uuid),
    Since(chrono::DateTime<chrono::Utc>),
}

impl Redeliver {
    /// The request body: exactly one of the two fields.
    pub fn body(&self) -> Value {
        match self {
            Self::EventId(id) => json!({ "eventId": id }),
            Self::Since(t) => {
                json!({ "since": t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) })
            }
        }
    }
}

/// Client for the event routes on one operator.
#[derive(Debug)]
pub struct EventsClient {
    base_url: String,
    /// `None` only for the public signing-key read.
    bearer: Option<Redacted<String>>,
    http: reqwest::Client,
}

impl EventsClient {
    pub fn with_base_url(base_url: &str, bearer: Option<Redacted<String>>) -> Result<Self> {
        let http = http::client_builder()
            .build()
            .context("build operator HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer,
            http,
        })
    }

    /// `GET /v1/events/catalog`.
    pub async fn catalog(&self) -> Result<Value> {
        let url = format!("{}/v1/events/catalog", self.base_url);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "read the event catalogue").await?;
        resp.json().await.context("parse the event catalogue")
    }

    /// `GET /v1/events/signing-key` — the `whpk_…` string.
    pub async fn signing_key(&self) -> Result<String> {
        let url = format!("{}/v1/events/signing-key", self.base_url);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "read the operator's webhook signing key").await?;
        let v: Value = resp.json().await.context("parse the signing key")?;
        v["standardWebhooks"]
            .as_str()
            .filter(|k| k.starts_with("whpk_"))
            .map(str::to_owned)
            .context("the operator's signing-key answer carries no whpk_ key")
    }

    /// `POST /v1/event-subscriptions/{name}/redeliver` — how many
    /// deliveries were queued again.
    pub async fn redeliver(&self, subscription: &str, what: &Redeliver) -> Result<u64> {
        let url = format!(
            "{}/v1/event-subscriptions/{}/redeliver",
            self.base_url,
            segment(subscription)
        );
        let resp = self
            .send(self.http.post(&url).json(&what.body()), &url, "POST")
            .await?;
        let resp = checked(resp, &format!("redeliver to {subscription}")).await?;
        let v: Value = resp.json().await.context("parse the redelivery answer")?;
        v["requeued"]
            .as_u64()
            .context("the redelivery answer carries no requeued count")
    }

    /// `POST /v1/event-subscriptions/{name}/test` — the test event's id.
    pub async fn test(&self, subscription: &str) -> Result<uuid::Uuid> {
        let url = format!(
            "{}/v1/event-subscriptions/{}/test",
            self.base_url,
            segment(subscription)
        );
        let resp = self.send(self.http.post(&url), &url, "POST").await?;
        let resp = checked(resp, &format!("send a test event to {subscription}")).await?;
        let v: Value = resp.json().await.context("parse the test answer")?;
        v["eventId"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .context("the test answer carries no event id")
    }

    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        url: &str,
        method: &str,
    ) -> Result<reqwest::Response> {
        let req = match &self.bearer {
            Some(b) => req.bearer_auth(b.expose()),
            None => req,
        };
        req.send()
            .await
            .map_err(|e| http::format_transport_error(url, method, e))
    }
}

/// A refusal the operator named with a code this CLI can say plainly;
/// anything else falls through to the generic status handling.
async fn checked(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() || matches!(status.as_u16(), 401 | 403) {
        return http::handle_status(resp, what).await;
    }
    let body = resp.text().await.unwrap_or_default();
    let (code, message) = error_code(&body);
    let wire = code
        .clone()
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    let text = if let Some(sentence) = code.as_deref().and_then(plain_refusal) {
        format!("{what}: {sentence}")
    } else if status.as_u16() == 404 && code.is_none() {
        format!(
            "{what}: this operator does not serve the event routes (HTTP 404) — it predates \
             event subscriptions, or runs without them"
        )
    } else {
        let detail = message.or(code).unwrap_or_else(|| body.trim().to_owned());
        if detail.is_empty() {
            format!("{what}: HTTP {status}")
        } else {
            format!("{what}: HTTP {status}: {detail}")
        }
    };
    Err(crate::exit::Failure::http(status.as_u16(), wire, text).into())
}

/// The event routes' refusal codes, as sentences.
pub fn plain_refusal(code: &str) -> Option<&'static str> {
    Some(match code {
        "not_found" => {
            "no subscription of yours has that name — `airdress get EventSubscription` \
             lists them"
        }
        "event_not_found" => {
            "no such event for this subscription: it was swept from the log (kept 7 days), \
             or it is not one the subscription receives. Nothing was queued"
        }
        "subscription_disabled" => {
            "the subscription is disabled, so nothing can be queued for it — re-apply it \
             with enabled: true (its queued backlog resumes), then redeliver"
        }
        "signing_unavailable" => {
            "the operator has no webhook signing key, so it cannot sign v1a deliveries \
             either; pass the key with --signing-key once it has one"
        }
        "no_owner_principal" => {
            "this airdress has no owner principal yet, so there is nobody to address a \
             test event to"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};

    #[test]
    fn the_redeliver_body_carries_exactly_one_field() {
        let id = uuid::Uuid::parse_str("0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee").unwrap();
        assert_eq!(
            Redeliver::EventId(id).body(),
            json!({ "eventId": "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee" })
        );
        let t = chrono::DateTime::parse_from_rfc3339("2026-10-04T08:00:00+02:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            Redeliver::Since(t).body(),
            json!({ "since": "2026-10-04T06:00:00Z" })
        );
    }

    #[test]
    fn every_named_refusal_is_a_sentence() {
        for code in [
            "not_found",
            "event_not_found",
            "subscription_disabled",
            "signing_unavailable",
            "no_owner_principal",
        ] {
            let s = plain_refusal(code).unwrap_or_else(|| panic!("{code}"));
            assert!(!s.contains(code), "{code}: a sentence, not the code: {s}");
        }
        assert!(plain_refusal("internal").is_none());
    }

    fn first_line(r: &str) -> &str {
        r.lines().next().unwrap_or_default()
    }

    #[tokio::test]
    async fn catalog_reads_the_document_with_the_bearer() {
        let (base, handle) = canned_operator(vec![response(
            "200 OK",
            r#"{"catalog_version":1,"events":[],"points":[]}"#,
        )])
        .await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("tok"))).unwrap();
        let doc = c.catalog().await.unwrap();
        assert_eq!(doc["catalog_version"], 1);
        let seen = handle.await.unwrap();
        assert_eq!(first_line(&seen[0]), "GET /v1/events/catalog HTTP/1.1");
        assert!(
            seen[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer tok"),
            "{}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn the_signing_key_is_read_without_a_bearer() {
        let (base, handle) = canned_operator(vec![response(
            "200 OK",
            r#"{"standardWebhooks":"whpk_AAAA","alg":"ed25519","kid":"k-1","publicKey":"AAAA"}"#,
        )])
        .await;
        let c = EventsClient::with_base_url(&base, None).unwrap();
        assert_eq!(c.signing_key().await.unwrap(), "whpk_AAAA");
        let seen = handle.await.unwrap();
        assert_eq!(first_line(&seen[0]), "GET /v1/events/signing-key HTTP/1.1");
        assert!(!seen[0].to_ascii_lowercase().contains("authorization:"));
    }

    #[tokio::test]
    async fn redeliver_posts_the_body_and_reads_the_count() {
        let (base, handle) =
            canned_operator(vec![response("202 Accepted", r#"{"requeued":3}"#)]).await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("t"))).unwrap();
        let t = chrono::DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            c.redeliver("home assistant", &Redeliver::Since(t))
                .await
                .unwrap(),
            3
        );
        let seen = handle.await.unwrap();
        assert_eq!(
            first_line(&seen[0]),
            "POST /v1/event-subscriptions/home%20assistant/redeliver HTTP/1.1"
        );
        assert!(
            seen[0].ends_with(r#"{"since":"2026-10-01T00:00:00Z"}"#),
            "{}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn redeliver_of_a_swept_event_says_so() {
        let (base, _h) = canned_operator(vec![response(
            "404 Not Found",
            r#"{"error":{"code":"event_not_found","message":"no such event"}}"#,
        )])
        .await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("t"))).unwrap();
        let id = uuid::Uuid::new_v4();
        let e = format!(
            "{:#}",
            c.redeliver("ha", &Redeliver::EventId(id))
                .await
                .unwrap_err()
        );
        assert!(e.starts_with("redeliver to ha: no such event"), "{e}");
        assert!(e.contains("Nothing was queued"), "{e}");
    }

    #[tokio::test]
    async fn a_disabled_subscription_is_named() {
        let (base, _h) = canned_operator(vec![response(
            "409 Conflict",
            r#"{"error":{"code":"subscription_disabled","message":"x"}}"#,
        )])
        .await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("t"))).unwrap();
        let e = format!("{:#}", c.test("ha").await.unwrap_err());
        assert!(e.contains("the subscription is disabled"), "{e}");
    }

    #[tokio::test]
    async fn an_operator_without_the_routes_is_told_apart_from_a_missing_subscription() {
        let (base, _h) = canned_operator(vec![response("404 Not Found", "")]).await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("t"))).unwrap();
        let e = format!("{:#}", c.catalog().await.unwrap_err());
        assert!(e.contains("does not serve the event routes"), "{e}");
    }

    #[tokio::test]
    async fn test_returns_the_event_id() {
        let (base, handle) = canned_operator(vec![response(
            "202 Accepted",
            r#"{"eventId":"0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"}"#,
        )])
        .await;
        let c = EventsClient::with_base_url(&base, Some(Redacted::from("t"))).unwrap();
        assert_eq!(
            c.test("ha").await.unwrap().to_string(),
            "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
        );
        let seen = handle.await.unwrap();
        assert_eq!(
            first_line(&seen[0]),
            "POST /v1/event-subscriptions/ha/test HTTP/1.1"
        );
    }
}
