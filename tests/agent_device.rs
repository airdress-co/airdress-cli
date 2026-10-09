//! The agent device host, end to end against a mock hub and operator over
//! real HTTP (design §6.2, §9.2; tasks F.1 and F.10).
//!
//! - `device.request` asks as `device_class: agent` with its harness and
//!   label, and nothing is enrolled before a phone approves.
//! - The host advances the request itself: it checks the delegation under
//!   the published root, enrolls once, and opens the sealed MLS state.
//! - Inside the last seven days it files the renewal itself, naming the
//!   enrollment it renews; the re-approval renews the same enrollment —
//!   no second enrollment — for thirty days.
//! - It signs for its clients while approved; `device.leave` signs it out
//!   and deletes its keys.

#![cfg(feature = "mls")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use airdress::agent_device::host::{self, CancellationToken as Token, HubAuth, Identity};
use airdress::agent_device::store::AgentStore;

const AIRDRESS: &str = "a.example";
const ENROLLMENT: &str = "0b7f2c1e-5a44-4d8e-9a17-3c2e6d1f8a90";

#[derive(Default)]
struct Seen {
    joins: Vec<Value>,
    enrolls: usize,
    deleted: bool,
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Hub and operator in one. The phone approves each request at once: the
/// first for three days (so a renewal is due immediately), the renewal for
/// thirty.
async fn mock() -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s2 = Arc::clone(&seen);
    tokio::spawn(async move {
        let root = SigningKey::from_bytes(&[0x51; 32]);
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let end = loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(p);
                }
            };
            let Some(end) = end else { continue };
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let headers: HashMap<String, String> = head
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                .collect();
            let len: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = buf[end + 4..].to_vec();
            while body.len() < len {
                let n = sock.read(&mut tmp).await.unwrap();
                body.extend_from_slice(&tmp[..n]);
            }
            let first = head.lines().next().unwrap().to_owned();
            let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let path: Vec<&str> = first.split(' ').take(2).collect();
            let answer = {
                let mut s = s2.lock().unwrap();
                match path.as_slice() {
                    ["POST", "/v1/enrollment-tokens"] => json!({"token": "hub-assertion"}),
                    ["POST", "/v1/endpoints/device-join-requests"] => {
                        s.joins.push(body);
                        json!({"request_id": format!("req-{}", s.joins.len()), "state": "pending"})
                    }
                    ["GET", p] if p.starts_with("/v1/endpoints/device-join-requests/req-") => {
                        let n: usize = p.rsplit('-').next().unwrap().parse().unwrap();
                        let ask = &s.joins[n - 1];
                        let now = chrono::Utc::now();
                        let days = if n == 1 { 3 } else { 30 };
                        let mut d = json!({
                            "airdress": AIRDRESS,
                            "device_class": "agent",
                            "device_id": ask["device_id"],
                            "device_kind": "agent",
                            "device_label": ask["device_label"],
                            "device_session_public_key": ask["device_public_key"],
                            "expires_at": rfc3339(now + chrono::Duration::days(days)),
                            "harness": ask["harness"],
                            "issued_at": rfc3339(now),
                            "role": "human_held",
                        });
                        let sig = root.sign(&serde_json::to_vec(&d).unwrap());
                        d["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
                        json!({"state": "approved", "delegation": d})
                    }
                    ["GET", p] if p.ends_with("/root-key") => json!({
                        "airdress": AIRDRESS,
                        "root_public_key": URL_SAFE_NO_PAD.encode(root.verifying_key().to_bytes()),
                    }),
                    ["POST", "/v1/endpoints/enrollments"] => {
                        s.enrolls += 1;
                        assert_eq!(body["delegation"]["device_class"], "agent");
                        assert_eq!(body["device_kind"], "agent");
                        json!({"enrollment_id": ENROLLMENT, "token": "device-token"})
                    }
                    ["DELETE", p] if p.ends_with(ENROLLMENT) => {
                        assert_eq!(
                            headers.get("authorization").map(String::as_str),
                            Some("Bearer device-token")
                        );
                        s.deleted = true;
                        json!({})
                    }
                    other => panic!("no route {other:?}"),
                }
            };
            let b = answer.to_string();
            if let Err(e) = sock
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{b}",
                        b.len()
                    )
                    .as_bytes(),
                )
                .await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            if let Err(e) = sock.shutdown().await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        }
    });
    (base, seen)
}

async fn until(store: &AgentStore, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..200 {
        if let Ok(v) = host::call(store, &json!({"op": "device.status"})).await {
            if pred(&v) {
                return v;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never {what}");
}

#[tokio::test]
async fn the_host_joins_renews_in_place_signs_and_leaves() {
    let (base, seen) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let store = AgentStore::file_only(dir.path(), AIRDRESS).unwrap();
    let cancel = Token::new();
    let task = tokio::spawn(host::run(
        store.clone(),
        HubAuth::Static {
            base: base.clone(),
            bearer: "account-token".into(),
        },
        Identity {
            operator: base.clone(),
            label: "Agent on desk".into(),
            harness: "test-harness".into(),
        },
        Duration::from_millis(200),
        cancel.clone(),
    ));

    // Ask. The answer is the sentence a person acts on.
    let mut asked = None;
    for _ in 0..100 {
        if let Ok(v) = host::call(&store, &json!({"op": "device.request"})).await {
            asked = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let asked = asked.expect("the host answered");
    assert_eq!(asked["message"], "Approve 'Agent on desk' on your phone.");
    {
        let s = seen.lock().unwrap();
        let j = &s.joins[0];
        assert_eq!(j["device_class"], "agent");
        assert_eq!(j["harness"], "test-harness");
        assert_eq!(j["device_label"], "Agent on desk");
        assert!(j.get("renews").is_none());
    }

    // Approved for three days: enrolled once, and the renewal is filed by
    // the host itself, naming the enrollment; approved again for thirty.
    let v = until(&store, "renewed", |v| {
        v["standing"] == "approved" && v["enrolled"] == true
    })
    .await;
    let exp = chrono::DateTime::parse_from_rfc3339(v["expires_at"].as_str().unwrap()).unwrap();
    assert!(exp.with_timezone(&chrono::Utc) - chrono::Utc::now() > chrono::Duration::days(29));
    assert_eq!(v["enrollment_id"], ENROLLMENT);
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.joins.len(), 2, "one join, one renewal");
        assert_eq!(s.joins[1]["renews"], ENROLLMENT);
        assert_eq!(
            s.joins[1]["device_public_key"], s.joins[0]["device_public_key"],
            "the same key renews"
        );
        assert_eq!(s.enrolls, 1, "a renewal enrolls nothing new");
    }
    assert!(store.mls_dir().is_dir(), "the sealed MLS state exists");

    // It signs for a client, with the key the delegation names.
    let payload = STANDARD.encode(b"bus write");
    let signed = host::call(&store, &json!({"op": "sign", "payload": payload}))
        .await
        .unwrap();
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(signed["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signed["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(b"bus write", &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    {
        let s = seen.lock().unwrap();
        assert_eq!(
            s.joins[0]["device_public_key"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(key)
        );
    }

    // Leave: signed out at the operator, keys and state deleted.
    host::call(&store, &json!({"op": "device.leave"}))
        .await
        .unwrap();
    assert!(seen.lock().unwrap().deleted);
    assert!(store.load().unwrap().is_none());
    assert!(!store.mls_dir().exists());

    cancel.cancel();
    task.await.unwrap().unwrap();
}
