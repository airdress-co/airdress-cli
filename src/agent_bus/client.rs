//! The operator's `/v1/agent-bus` routes, and signing a write.
//!
//! A write is the request body plus an `attestation`: the device host
//! signs `label ‖ 0x1F ‖ JCS({airdress, signed_by, session, enrollment,
//! op, target, body, nonce, time})`, where `body` is the SHA-256 of the
//! canonical body without the attestation. The account bearer says who
//! is asking; the signature says which machine.

use std::path::PathBuf;

use anyhow::{anyhow, Context as _, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::RngCore as _;
use reqwest::Method;
use serde_json::{json, Value};

use super::canon;
use crate::redact::Redacted;

/// The bus routes' prefix.
pub const PREFIX: &str = "/v1/agent-bus";

/// A refusal from the operator, kept whole so a caller can read its code.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub body: Value,
    /// `Retry-After`, in seconds, on a rate-limit refusal.
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body travels in the text: the MCP layer reads a
        // `not_enabled` answer back out of it, as for every other route.
        write!(
            f,
            "{} ({}): {} {}",
            self.code, self.status, self.message, self.body
        )
    }
}

impl std::error::Error for Refusal {}

impl Refusal {
    fn from_body(status: u16, body: Value, retry_after: Option<u64>) -> Self {
        // Two shapes: `{"error": {"code", "message"}}` and the flat
        // `{"error": "not_enabled", "feature", "message"}`.
        let (code, message) = match &body["error"] {
            Value::Object(e) => (
                e.get("code").and_then(Value::as_str).unwrap_or("error"),
                e.get("message").and_then(Value::as_str).unwrap_or(""),
            ),
            Value::String(s) => (s.as_str(), body["message"].as_str().unwrap_or("")),
            _ => ("http_error", ""),
        };
        Self {
            status,
            code: code.to_owned(),
            message: message.to_owned(),
            body: body.clone(),
            retry_after,
        }
    }

    /// An extra field of the error object (`current_token`, …).
    pub fn extra(&self, key: &str) -> Option<&Value> {
        self.body["error"].get(key).or_else(|| self.body.get(key))
    }
}

/// Who signs this machine's writes.
#[derive(Clone)]
pub enum Signer {
    /// The device host on this machine, over its socket.
    Host(PathBuf),
    /// A key held in process — tests, and nothing else in this crate.
    Key {
        key: Box<ed25519_dalek::SigningKey>,
        enrollment: String,
    },
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(p) => f.debug_tuple("Host").field(p).finish(),
            Self::Key { enrollment, .. } => f
                .debug_struct("Key")
                .field("enrollment", enrollment)
                .finish_non_exhaustive(),
        }
    }
}

/// What a signature came back with.
#[derive(Debug, Clone)]
pub struct Signed {
    pub signature: String,
    pub public_key: Vec<u8>,
    pub enrollment: String,
}

impl Signer {
    /// Sign `input`.
    ///
    /// # Errors
    /// No device host is serving, or it refused (not approved, expired).
    pub async fn sign(&self, input: &[u8]) -> Result<Signed> {
        match self {
            Self::Key { key, enrollment } => {
                use ed25519_dalek::Signer as _;
                Ok(Signed {
                    signature: URL_SAFE_NO_PAD.encode(key.sign(input).to_bytes()),
                    public_key: key.verifying_key().to_bytes().to_vec(),
                    enrollment: enrollment.clone(),
                })
            }
            Self::Host(socket) => {
                let v = super::socket::call(
                    socket,
                    &json!({"op": "sign", "payload": STANDARD.encode(input)}),
                )
                .await
                .context("this machine's agent device could not sign")?;
                let public_key = URL_SAFE_NO_PAD
                    .decode(v["public_key"].as_str().unwrap_or_default())
                    .context("the device host answered no public key")?;
                Ok(Signed {
                    signature: v["signature"].as_str().unwrap_or_default().to_owned(),
                    public_key,
                    enrollment: v["enrollment_id"].as_str().unwrap_or_default().to_owned(),
                })
            }
        }
    }

    /// The enrollment this signer signs as (it is inside the signed
    /// bytes, so it is asked before anything is signed).
    ///
    /// # Errors
    /// No device host is serving, or the device is not enrolled yet.
    pub async fn enrollment(&self) -> Result<String> {
        match self {
            Self::Key { enrollment, .. } => Ok(enrollment.clone()),
            Self::Host(socket) => {
                let v = super::socket::call(socket, &json!({"op": "device.status"}))
                    .await
                    .context("no agent device is running on this machine")?;
                v["enrollment_id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        anyhow!(
                            "this machine is not an approved agent device yet: {}",
                            v["message"].as_str().unwrap_or("approve it on your phone")
                        )
                    })
            }
        }
    }
}

/// `now`, as the signing input carries it.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Add the attestation to `body` for `op` on `target` by `session`.
///
/// The enrollment is asked of the signer first (it is inside the signed
/// bytes), so a device that renewed into a new enrollment signs as it.
///
/// # Errors
/// The signer refused, or the body cannot be canonicalized.
pub async fn attest(
    signer: &Signer,
    airdress: &str,
    session: &str,
    enrollment: &str,
    op: &str,
    target: &str,
    body: &mut Value,
) -> Result<()> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let time = now_rfc3339();
    let obj = json!({
        "airdress": airdress,
        "signed_by": "device",
        "session": session,
        "enrollment": enrollment,
        "op": op,
        "target": target,
        "body": canon::body_hash(body)?,
        "nonce": nonce,
        "time": time,
    });
    let signed = signer.sign(&canon::signing_input(&obj)?).await?;
    let map = body
        .as_object_mut()
        .ok_or_else(|| anyhow!("a bus write body is a JSON object"))?;
    map.insert(
        "attestation".into(),
        json!({
            "signed_by": "device",
            "session": session,
            "enrollment": enrollment,
            "key_id": canon::key_id(&signed.public_key),
            "nonce": nonce,
            "time": time,
            "sig": signed.signature,
        }),
    );
    Ok(())
}

/// One operator's bus, with one bearer.
#[derive(Clone)]
pub struct BusClient {
    base: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for BusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BusClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl BusClient {
    /// `base` is the operator's origin (`https://<fqdn>`).
    ///
    /// # Errors
    /// The HTTP client could not be built.
    pub fn new(base: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            bearer: bearer.into(),
            http: crate::http::client()?,
        })
    }

    /// The operator's origin.
    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("/.well-known") {
            format!("{}{path}", self.base)
        } else {
            format!("{}{PREFIX}{path}", self.base)
        }
    }

    /// One request; a non-2xx answer is a [`Refusal`].
    ///
    /// # Errors
    /// Transport failure, or the operator refused.
    pub async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = self.url(path);
        let mut req = self
            .http
            .request(method.clone(), &url)
            .bearer_auth(self.bearer.expose());
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| crate::http::format_transport_error(&url, method.as_str(), e))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let text = resp.text().await.unwrap_or_default();
        let value: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}))
        };
        if (200..300).contains(&status) {
            Ok(value)
        } else {
            Err(Refusal::from_body(status, value, retry_after).into())
        }
    }

    /// GET a bus path.
    ///
    /// # Errors
    /// As [`Self::request`].
    pub async fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, None).await
    }

    /// The event stream for `session`, resuming after `last_event_id`.
    ///
    /// # Errors
    /// Transport failure, or the operator refused.
    pub async fn events(
        &self,
        session: &str,
        last_event_id: Option<i64>,
    ) -> Result<reqwest::Response> {
        let url = self.url(&format!("/sessions/{session}/events"));
        // No overall timeout: the stream is held open; keep-alive comments arrive
        // every fifteen seconds and a silent minute ends it.
        let http =
            crate::http::client_with(crate::http::Timeouts::stream(crate::http::BUS_STREAM_IDLE))
                .build()?;
        let mut req = http
            .get(&url)
            .bearer_auth(self.bearer.expose())
            .header("accept", "text/event-stream");
        if let Some(id) = last_event_id {
            req = req.header("last-event-id", id.to_string());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| crate::http::format_transport_error(&url, "GET", e))?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(resp);
        }
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        Err(Refusal::from_body(status, body, None).into())
    }
}

/// The refusal inside an error, if it is one.
pub fn refusal(e: &anyhow::Error) -> Option<&Refusal> {
    e.downcast_ref::<Refusal>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_attestation_verifies_under_the_signers_key() {
        use ed25519_dalek::Verifier as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let signer = Signer::Key {
            key: Box::new(key.clone()),
            enrollment: "e-1".into(),
        };
        let mut body = json!({"content": "hi"});
        attest(
            &signer,
            "a.example",
            "s-1",
            "e-1",
            "message.post",
            "topic:general",
            &mut body,
        )
        .await
        .unwrap();
        let a = body["attestation"].clone();
        assert_eq!(a["key_id"], canon::key_id(key.verifying_key().as_bytes()));
        let obj = json!({
            "airdress": "a.example", "signed_by": "device", "session": "s-1",
            "enrollment": "e-1", "op": "message.post", "target": "topic:general",
            "body": canon::body_hash(&body).unwrap(), "nonce": a["nonce"], "time": a["time"],
        });
        let sig = URL_SAFE_NO_PAD.decode(a["sig"].as_str().unwrap()).unwrap();
        key.verifying_key()
            .verify(
                &canon::signing_input(&obj).unwrap(),
                &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn both_refusal_shapes_read_their_code() {
        let r = Refusal::from_body(
            409,
            json!({"error": {"code": "fencing_stale", "message": "m", "current_token": 8}}),
            None,
        );
        assert_eq!(r.code, "fencing_stale");
        assert_eq!(r.extra("current_token"), Some(&json!(8)));
        let r = Refusal::from_body(
            403,
            json!({"error": "not_enabled", "feature": "agent_bus", "message": "not enabled on this airdress"}),
            None,
        );
        assert_eq!(r.code, "not_enabled");
        assert!(r.to_string().contains("\"not_enabled\""));
    }
}
