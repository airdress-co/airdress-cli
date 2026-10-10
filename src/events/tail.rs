//! `airdress events tail` — a local receiver for what a subscription
//! delivers.
//!
//! The operator has no route that reads its event log back out (it keeps
//! the log internal: the app gets its own projection over the
//! client stream, and everything else is pushed by an `EventSubscription`).
//! So `tail` is the other end of a subscription: a small HTTP server that
//! takes each delivery, checks its Standard Webhooks `v1a` signature
//! against the operator's published `whpk_` key, prints it, and answers.
//!
//! A verified delivery is answered `204`; anything else `401`, so a forged
//! or stale request shows as a failed attempt on the subscription rather
//! than as a success. Every request is printed either way, with its verdict.
//!
//! The HTTP side is deliberately small: one request per connection,
//! `Content-Length` bodies only (the operator sends nothing else), 1 MiB at
//! most.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::log_err::LogErr as _;

/// Standard Webhooks' default tolerance for `webhook-timestamp`.
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(5 * 60);

/// Largest request head this receiver reads.
const MAX_HEAD: usize = 16 * 1024;
/// Largest body this receiver reads. The operator's events are far smaller.
const MAX_BODY: usize = 1024 * 1024;
/// How long one connection may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// The operator's public key, from its `whpk_<base64>` form.
pub fn parse_whpk(s: &str) -> Result<VerifyingKey> {
    let b64 = s
        .trim()
        .strip_prefix("whpk_")
        .context("a Standard Webhooks public key starts with whpk_")?;
    let raw = STANDARD
        .decode(b64)
        .context("the whpk_ key is not base64")?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("the whpk_ key is not 32 bytes (an Ed25519 public key)"))?;
    VerifyingKey::from_bytes(&raw).context("the whpk_ key is not a valid Ed25519 public key")
}

/// What `tail` concluded about one delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A `v1a` signature verified with the operator's key, inside the
    /// tolerance.
    Verified,
    /// `webhook-id`, `webhook-timestamp` or `webhook-signature` is absent.
    Unsigned,
    /// Signed, but not with `v1a` (the subscription uses `v1` or
    /// `rfc9421`); `tail` checks `v1a` only. The schemes it saw.
    NotV1a(Vec<String>),
    /// No `v1a` signature verified with the key.
    BadSignature,
    /// The signature is good, but the timestamp is outside the tolerance.
    Stale { skew_secs: i64 },
}

impl Verdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// A short word for the output.
    pub fn label(&self) -> String {
        match self {
            Self::Verified => "verified".into(),
            Self::Unsigned => "UNSIGNED".into(),
            Self::NotV1a(schemes) => format!("NOT VERIFIED (signed {})", schemes.join(",")),
            Self::BadSignature => "BAD SIGNATURE".into(),
            Self::Stale { skew_secs } => format!("STALE ({skew_secs}s off)"),
        }
    }
}

/// Verify a Standard Webhooks `v1a` delivery: Ed25519 over
/// `webhook-id.webhook-timestamp.body`, any one of the space-separated
/// `v1a,<base64>` signatures in `webhook-signature`.
pub fn verify(
    key: &VerifyingKey,
    id: Option<&str>,
    timestamp: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
    now_unix: i64,
    tolerance: Duration,
) -> Verdict {
    let (Some(id), Some(ts), Some(sig)) = (id, timestamp, signature) else {
        return Verdict::Unsigned;
    };
    let Ok(ts_n) = ts.trim().parse::<i64>() else {
        return Verdict::Unsigned;
    };
    let mut content = Vec::with_capacity(id.len() + ts.len() + body.len() + 2);
    content.extend_from_slice(id.as_bytes());
    content.push(b'.');
    content.extend_from_slice(ts.trim().as_bytes());
    content.push(b'.');
    content.extend_from_slice(body);

    let mut schemes = Vec::new();
    let mut any_v1a = false;
    let mut good = false;
    for token in sig.split_whitespace() {
        let Some((scheme, value)) = token.split_once(',') else {
            continue;
        };
        if scheme != "v1a" {
            if !schemes.iter().any(|s| s == scheme) {
                schemes.push(scheme.to_owned());
            }
            continue;
        }
        any_v1a = true;
        let Ok(raw) = STANDARD.decode(value) else {
            continue;
        };
        let Ok(s) = Signature::from_slice(&raw) else {
            continue;
        };
        if key.verify(&content, &s).is_ok() {
            good = true;
            break;
        }
    }
    if !any_v1a {
        return if schemes.is_empty() {
            Verdict::Unsigned
        } else {
            Verdict::NotV1a(schemes)
        };
    }
    if !good {
        return Verdict::BadSignature;
    }
    let skew = now_unix - ts_n;
    let limit = i64::try_from(tolerance.as_secs()).unwrap_or(i64::MAX);
    if skew.abs() > limit {
        return Verdict::Stale { skew_secs: skew };
    }
    Verdict::Verified
}

/// One request the receiver took.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub verdict: Verdict,
    pub webhook_id: Option<String>,
    pub timestamp: Option<String>,
    /// The body as JSON, or as a string when it is not JSON.
    pub event: Value,
}

impl Delivery {
    /// One line of `--output json` (NDJSON).
    pub fn to_json(&self) -> Value {
        json!({
            "verified": self.verdict.is_verified(),
            "verdict": self.verdict.label(),
            "webhookId": self.webhook_id,
            "timestamp": self.timestamp,
            "event": self.event,
        })
    }

    /// The human form: a header line, then the event's data, indented.
    pub fn render(&self) -> String {
        let e = &self.event;
        let field = |k: &str| e[k].as_str().unwrap_or("—").to_owned();
        let mut head = format!(
            "{}  {}  id={}",
            field("time"),
            field("type"),
            e["id"]
                .as_str()
                .or(self.webhook_id.as_deref())
                .unwrap_or("—")
        );
        if let Some(s) = e["subject"].as_str() {
            head.push_str(&format!("  subject={s}"));
        }
        head.push_str(&format!("  [{}]", self.verdict.label()));
        let data = match e.get("data") {
            Some(d) => serde_json::to_string(d).unwrap_or_default(),
            None => match e {
                Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            },
        };
        format!("{head}\n  {data}")
    }
}

/// What the receiver needs to judge a request.
#[derive(Clone, Debug)]
pub struct Receiver {
    pub key: VerifyingKey,
    pub tolerance: Duration,
}

/// Serve until `count` requests have been taken (forever when `None`),
/// sending each to `out`.
pub async fn serve(
    listener: TcpListener,
    receiver: Receiver,
    count: Option<usize>,
    out: mpsc::Sender<Delivery>,
) -> Result<()> {
    let mut taken = 0usize;
    loop {
        if count.is_some_and(|n| taken >= n) {
            return Ok(());
        }
        let (sock, _) = listener.accept().await.context("accept a delivery")?;
        taken += 1;
        let r = receiver.clone();
        let out = out.clone();
        let one = tokio::spawn(async move {
            if let Ok(Some(d)) = handle(sock, &r).await {
                out.send(d)
                    .await
                    .log_debug("hand a delivery to the printer");
            }
        });
        // With a count, take them one at a time so the count is exact.
        if count.is_some() {
            one.await.log_debug("take one delivery");
        }
    }
}

struct Request {
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn handle(mut sock: TcpStream, r: &Receiver) -> Result<Option<Delivery>> {
    let req = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut sock)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            respond(&mut sock, "400 Bad Request", &format!("{e:#}")).await;
            return Ok(None);
        }
        Err(_) => {
            respond(&mut sock, "408 Request Timeout", "too slow").await;
            return Ok(None);
        }
    };
    if req.method != "POST" {
        respond(
            &mut sock,
            "405 Method Not Allowed",
            "this receiver takes event deliveries: POST",
        )
        .await;
        return Ok(None);
    }
    let now = chrono::Utc::now().timestamp();
    let verdict = verify(
        &r.key,
        req.header("webhook-id"),
        req.header("webhook-timestamp"),
        req.header("webhook-signature"),
        &req.body,
        now,
        r.tolerance,
    );
    let event = serde_json::from_slice::<Value>(&req.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&req.body).into_owned()));
    if verdict.is_verified() {
        respond(&mut sock, "204 No Content", "").await;
    } else {
        respond(&mut sock, "401 Unauthorized", &verdict.label()).await;
    }
    Ok(Some(Delivery {
        verdict,
        webhook_id: req.header("webhook-id").map(str::to_owned),
        timestamp: req.header("webhook-timestamp").map(str::to_owned),
        event,
    }))
}

async fn read_request(sock: &mut TcpStream) -> Result<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            bail!("request head over {MAX_HEAD} bytes");
        }
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the request head ended");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).context("request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let method = lines
        .next()
        .and_then(|l| l.split(' ').next())
        .unwrap_or_default()
        .to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let get = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    };
    if get("transfer-encoding").is_some() {
        bail!("chunked bodies are not taken; send Content-Length");
    }
    let len: usize = match get("content-length") {
        Some(v) => v.parse().context("Content-Length is not a number")?,
        None => 0,
    };
    if len > MAX_BODY {
        bail!("body over {MAX_BODY} bytes");
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the body ended");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(Request {
        method,
        headers,
        body,
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

async fn respond(sock: &mut TcpStream, status: &str, body: &str) {
    let text = if body.is_empty() {
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    } else {
        format!(
            "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    sock.write_all(text.as_bytes())
        .await
        .log_debug("answer a delivery");
    sock.shutdown()
        .await
        .log_debug("close a delivery's connection");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    // A fixed vector: the operator's own signer test uses this seed, id,
    // timestamp and body (airdress-operator `subscriptions/signing.rs`,
    // `v1a_verifies_with_the_published_public_key_alone`). Ed25519 is
    // deterministic, so the signature below is what that operator sends.
    // Both strings were computed outside this crate (Python `cryptography`),
    // so the test does not merely agree with itself.
    const SEED: [u8; 32] = [9u8; 32];
    const WHPK: &str = "whpk_/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
    const V1A: &str =
        "v1a,4U9ChxTCCGjwks6uO1KeWhcalU0Qm8oShLjTE6MOQN+K7cCtqcBdkCQXlBVWBXkKpbeehr+mjxiLGbd9LQwzAw==";
    const ID: &str = "evt_1";
    const TS: i64 = 1_700_000_000;

    fn key() -> VerifyingKey {
        parse_whpk(WHPK).unwrap()
    }

    #[test]
    fn the_published_key_is_the_seeds_public_key() {
        let derived = ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key();
        assert_eq!(key(), derived);
    }

    #[test]
    fn the_known_v1a_vector_verifies() {
        let v = verify(
            &key(),
            Some(ID),
            Some("1700000000"),
            Some(V1A),
            b"{}",
            TS + 10,
            DEFAULT_TOLERANCE,
        );
        assert_eq!(v, Verdict::Verified);
    }

    #[test]
    fn one_good_signature_among_several_is_enough() {
        let header = format!("v1,c29tZWhtYWM= v1a,AAAA {V1A}");
        let v = verify(
            &key(),
            Some(ID),
            Some("1700000000"),
            Some(&header),
            b"{}",
            TS,
            DEFAULT_TOLERANCE,
        );
        assert_eq!(v, Verdict::Verified);
    }

    #[test]
    fn a_changed_body_id_or_timestamp_fails() {
        let k = key();
        let t = DEFAULT_TOLERANCE;
        let bad = |id: &str, ts: &str, body: &[u8]| {
            verify(&k, Some(id), Some(ts), Some(V1A), body, TS, t)
        };
        assert_eq!(bad(ID, "1700000000", b"{ }"), Verdict::BadSignature);
        assert_eq!(bad("evt_2", "1700000000", b"{}"), Verdict::BadSignature);
        assert_eq!(bad(ID, "1700000001", b"{}"), Verdict::BadSignature);
    }

    #[test]
    fn another_key_fails() {
        let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let v = verify(
            &other,
            Some(ID),
            Some("1700000000"),
            Some(V1A),
            b"{}",
            TS,
            DEFAULT_TOLERANCE,
        );
        assert_eq!(v, Verdict::BadSignature);
    }

    #[test]
    fn a_good_signature_outside_the_tolerance_is_stale() {
        let v = verify(
            &key(),
            Some(ID),
            Some("1700000000"),
            Some(V1A),
            b"{}",
            TS + 301,
            DEFAULT_TOLERANCE,
        );
        assert_eq!(v, Verdict::Stale { skew_secs: 301 });
    }

    #[test]
    fn other_schemes_and_missing_headers_are_said() {
        let k = key();
        let t = DEFAULT_TOLERANCE;
        assert_eq!(
            verify(&k, Some(ID), Some("1"), Some("v1,abc"), b"{}", 1, t),
            Verdict::NotV1a(vec!["v1".into()])
        );
        assert_eq!(
            verify(&k, Some(ID), None, Some(V1A), b"{}", TS, t),
            Verdict::Unsigned
        );
    }

    #[test]
    fn a_malformed_whpk_is_refused() {
        assert!(parse_whpk("whsec_AAAA").is_err());
        assert!(parse_whpk("whpk_!!!").is_err());
        assert!(parse_whpk("whpk_AAAA").is_err(), "3 bytes is not a key");
    }

    #[test]
    fn a_delivery_renders_type_subject_and_data() {
        let d = Delivery {
            verdict: Verdict::Verified,
            webhook_id: Some("w".into()),
            timestamp: Some("1".into()),
            event: json!({
                "id": "0199", "type": "airdress.device_join.requested",
                "time": "2026-10-04T08:00:00Z", "subject": "s1",
                "data": {"label": "Galaxy S23"}
            }),
        };
        assert_eq!(
            d.render(),
            "2026-10-04T08:00:00Z  airdress.device_join.requested  id=0199  subject=s1  \
             [verified]\n  {\"label\":\"Galaxy S23\"}"
        );
        assert_eq!(d.to_json()["verified"], true);
    }

    /// A signed POST, as the operator's delivery worker sends one.
    async fn post(base: &str, body: &str, sign_with: &ed25519_dalek::SigningKey) -> u16 {
        let ts = chrono::Utc::now().timestamp().to_string();
        let content = format!("msg_1.{ts}.{body}");
        let sig = STANDARD.encode(sign_with.sign(content.as_bytes()).to_bytes());
        reqwest::Client::new()
            .post(base)
            .header("content-type", "application/cloudevents+json")
            .header("webhook-id", "msg_1")
            .header("webhook-timestamp", &ts)
            .header("webhook-signature", format!("v1a,{sig}"))
            .body(body.to_owned())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn receiver(count: usize) -> (String, mpsc::Receiver<Delivery>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel(8);
        let r = Receiver {
            key: key(),
            tolerance: DEFAULT_TOLERANCE,
        };
        tokio::spawn(serve(listener, r, Some(count), tx));
        (base, rx)
    }

    #[tokio::test]
    async fn the_receiver_answers_204_to_a_signed_delivery_and_prints_it() {
        let (base, mut rx) = receiver(1).await;
        let body = r#"{"specversion":"1.0","id":"e1","type":"airdress.event_subscription.test.sent","data":{}}"#;
        let status = post(&base, body, &ed25519_dalek::SigningKey::from_bytes(&SEED)).await;
        assert_eq!(status, 204);
        let d = rx.recv().await.unwrap();
        assert_eq!(d.verdict, Verdict::Verified);
        assert_eq!(d.event["type"], "airdress.event_subscription.test.sent");
        assert_eq!(d.webhook_id.as_deref(), Some("msg_1"));
    }

    #[tokio::test]
    async fn the_receiver_answers_401_to_a_forgery_and_still_prints_it() {
        let (base, mut rx) = receiver(1).await;
        let forger = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        assert_eq!(post(&base, r#"{"id":"e2"}"#, &forger).await, 401);
        assert_eq!(rx.recv().await.unwrap().verdict, Verdict::BadSignature);
    }

    #[tokio::test]
    async fn the_receiver_refuses_a_get() {
        let (base, mut rx) = receiver(1).await;
        let s = reqwest::get(&base).await.unwrap().status().as_u16();
        assert_eq!(s, 405);
        assert!(rx.recv().await.is_none(), "a GET is not a delivery");
    }
}
