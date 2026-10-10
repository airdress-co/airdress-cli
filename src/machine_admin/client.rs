//! The operator's owner routes for machines, `/v1/admin/machines*`.
//!
//! Every call carries the owner's ZITADEL bearer — the one `airdress auth
//! login` holds. The operator refuses anything else on these routes (a
//! device bearer, the owner's own phone included, cannot approve a machine),
//! so a sign-in that is not the operator's owner gets a 401/403 back.
//!
//! Shapes follow `airdress-operator` `machines/admin_routes.rs`. Fields a
//! newer operator adds (`purpose`, `links`) are optional here, and an absent
//! `links` reads as `[]`: an operator that does not advertise a link kind
//! cannot be sent one.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http;
use crate::redact::Redacted;

/// One pending enrollment, as `GET /v1/admin/machines/enrollments` lists it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PendingEnrollment {
    pub user_code: String,
    pub name: String,
    pub fingerprint: String,
    /// `new` or `reauth`.
    #[serde(default)]
    pub kind: Option<String>,
    /// What the machine says it is for (`home-assistant`); absent for a
    /// plain machine and on older operators.
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub confirmation_code: Option<String>,
    pub expires_at: String,
    /// The kinds this enrollment may be linked as at approval on this
    /// operator. Absent on older operators, which means none.
    #[serde(default)]
    pub links: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PendingList {
    enrollments: Vec<PendingEnrollment>,
}

/// What the owner compared against what the machine printed. There is no
/// approval without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    Fingerprint(String),
    ConfirmationCode(String),
}

/// A link made at approval: the machine is also bound as this resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub kind: String,
    pub name: String,
}

/// Body of `POST …/enrollments/{user_code}/approve`. Exactly one comparison;
/// `link` only when asked for, because an older operator refuses unknown
/// fields.
#[derive(Debug, Serialize)]
pub struct ApproveBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<&'a Link>,
}

impl<'a> ApproveBody<'a> {
    pub fn new(comparison: &'a Comparison, link: Option<&'a Link>) -> Self {
        let (fingerprint, confirmation_code) = match comparison {
            Comparison::Fingerprint(f) => (Some(f.as_str()), None),
            Comparison::ConfirmationCode(c) => (None, Some(c.as_str())),
        };
        Self {
            fingerprint,
            confirmation_code,
            link,
        }
    }
}

/// The operator's answer to an approval.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Approved {
    pub machine_id: uuid::Uuid,
    pub name: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub grants: Vec<String>,
    #[serde(default)]
    pub authorization: Option<Value>,
    #[serde(default)]
    pub link: Option<Link>,
}

/// Client for the owner's machine routes on one operator.
#[derive(Debug)]
pub struct MachineAdminClient {
    base_url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl MachineAdminClient {
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

    pub async fn pending(&self) -> Result<Vec<PendingEnrollment>> {
        let url = format!("{}/v1/admin/machines/enrollments", self.base_url);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "list pending enrollments").await?;
        let list: PendingList = resp.json().await.context("parse pending enrollments")?;
        Ok(list.enrollments)
    }

    pub async fn approve(&self, user_code: &str, body: &ApproveBody<'_>) -> Result<Approved> {
        let url = format!(
            "{}/v1/admin/machines/enrollments/{user_code}/approve",
            self.base_url
        );
        let resp = self
            .send(self.http.post(&url).json(body), &url, "POST")
            .await?;
        let resp = checked(resp, "approve").await?;
        resp.json().await.context("parse approval")
    }

    pub async fn deny(&self, user_code: &str) -> Result<()> {
        let url = format!(
            "{}/v1/admin/machines/enrollments/{user_code}/deny",
            self.base_url
        );
        let resp = self.send(self.http.post(&url), &url, "POST").await?;
        checked(resp, "deny").await?;
        Ok(())
    }

    /// `GET /v1/admin/machines` — every machine, revoked ones included.
    pub async fn list(&self) -> Result<Value> {
        let url = format!("{}/v1/admin/machines", self.base_url);
        let resp = self.send(self.http.get(&url), &url, "GET").await?;
        let resp = checked(resp, "list machines").await?;
        resp.json().await.context("parse machine list")
    }

    pub async fn revoke(
        &self,
        machine_id: uuid::Uuid,
        reason: &str,
        source_signing: Option<&str>,
    ) -> Result<Value> {
        let url = format!("{}/v1/admin/machines/{machine_id}/revoke", self.base_url);
        let mut body = serde_json::json!({ "reason": reason });
        if let Some(kind) = source_signing {
            body["source_signing"] = Value::from(kind);
        }
        let resp = self
            .send(self.http.post(&url).json(&body), &url, "POST")
            .await?;
        let resp = checked(resp, "revoke").await?;
        resp.json().await.context("parse revocation")
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

/// A refusal the operator named with a code this CLI can say plainly.
/// Anything else falls through to the generic status handling.
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

/// The operator's error body: `{"error":{"code","message"}}`, or the bare
/// `{"error":"<code>"}` some routes answer with.
pub(crate) fn error_code(body: &str) -> (Option<String>, Option<String>) {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return (None, None);
    };
    match v.get("error") {
        Some(Value::String(code)) => (Some(code.clone()), None),
        Some(Value::Object(o)) => (
            o.get("code").and_then(Value::as_str).map(str::to_owned),
            o.get("message").and_then(Value::as_str).map(str::to_owned),
        ),
        _ => (None, None),
    }
}

/// The operator's refusal codes, as sentences.
pub fn plain_refusal(code: &str) -> Option<&'static str> {
    Some(match code {
        "confirmation_mismatch" => {
            "what you gave does not match what this enrollment holds — compare the \
             fingerprint or code the machine printed again. Nothing was approved"
        }
        "confirmation_required" => {
            "the operator needs the fingerprint or the confirmation code the machine \
             printed. Nothing was approved"
        }
        "no_pending_enrollment" => {
            "no pending enrollment has that user code — it was already decided, or the \
             code is mistyped. `airdress machines pending` lists what is waiting"
        }
        "enrollment_expired" => "that enrollment expired; the machine has to start enrolling again",
        "link_unavailable" => {
            "this operator cannot link that enrollment as a Home. Nothing was approved"
        }
        "no_machine" => "no live machine has that id — `airdress machines list` shows them",
        "source_signing_kind_required" => {
            "this machine holds a key that signs function source; pass --source-signing \
             rotated (what it signed keeps running) or compromised (what it signed is \
             quarantined). Nothing was revoked"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_and_bare_error_bodies_both_give_a_code() {
        let (c, m) = error_code(r#"{"error":{"code":"link_unavailable","message":"no"}}"#);
        assert_eq!(c.as_deref(), Some("link_unavailable"));
        assert_eq!(m.as_deref(), Some("no"));
        let (c, m) = error_code(r#"{"error":"invalid_request"}"#);
        assert_eq!(c.as_deref(), Some("invalid_request"));
        assert!(m.is_none());
        assert_eq!(error_code("not json"), (None, None));
    }

    #[test]
    fn every_named_refusal_has_a_sentence() {
        for code in [
            "confirmation_mismatch",
            "confirmation_required",
            "no_pending_enrollment",
            "enrollment_expired",
            "link_unavailable",
        ] {
            let s = plain_refusal(code).unwrap_or_else(|| panic!("{code}"));
            assert!(!s.contains('_'), "{code}: a sentence, not a code: {s}");
        }
        assert!(plain_refusal("server_error").is_none());
    }

    #[test]
    fn an_absent_links_field_reads_as_none() {
        let e: PendingEnrollment = serde_json::from_str(
            r#"{"user_code":"WDJB-MJHT","name":"n","fingerprint":"SHA256:x",
                "kind":"new","machine_id":null,"preauth_key_id":null,
                "confirmation_code":null,"created_at":"t","expires_at":"t"}"#,
        )
        .unwrap();
        assert!(e.links.is_empty());
        assert!(e.purpose.is_none());
    }

    #[test]
    fn the_body_carries_one_comparison_and_a_link_only_when_asked() {
        let fp = Comparison::Fingerprint("SHA256:abc".into());
        let v = serde_json::to_value(ApproveBody::new(&fp, None)).unwrap();
        assert_eq!(v, serde_json::json!({ "fingerprint": "SHA256:abc" }));
        let code = Comparison::ConfirmationCode("ABCD-EFGH".into());
        let link = Link {
            kind: "Home".into(),
            name: "home".into(),
        };
        let v = serde_json::to_value(ApproveBody::new(&code, Some(&link))).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "confirmation_code": "ABCD-EFGH",
                "link": { "kind": "Home", "name": "home" },
            })
        );
    }
}
