//! The CLI joins an airdress as a delegation-only human device (task D.1),
//! against a mock hub and operator over real HTTP.
//!
//! - The join request says `device_class: human`, `delegation_only: true`,
//!   `device_kind: cli`, and names the identity key and device id the
//!   phone's delegation must bind.
//! - No shell route is called, and no credential exists, before a phone
//!   approves.
//! - The enrollment carries the delegation and the two facts; the shell key
//!   is then registered with `presenceAlg: none`, signed over the operator's
//!   statement layout by the key the delegation names.
//! - A delegation that does not say `cli` is not used: nothing is enrolled
//!   and nothing is stored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use airdress::shell_client::device::{self, device_keys_statement, JoinPlan};
use airdress::shell_client::store::Store;

const ENROLLMENT: &str = "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11";

#[derive(Default)]
struct Seen {
    calls: Vec<String>,
    join: Value,
    enroll: Value,
    keys: Value,
    keys_bearer: String,
}

async fn mock(kind: &'static str) -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s2 = Arc::clone(&seen);
    tokio::spawn(async move {
        let root = SigningKey::from_bytes(&[0x77; 32]);
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let end = loop {
                let n = sock.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p;
                }
            };
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
            let answer = {
                let mut s = s2.lock().unwrap();
                s.calls.push(first.clone());
                match first.split(' ').take(2).collect::<Vec<_>>().as_slice() {
                    ["POST", "/v1/enrollment-tokens"] => json!({"token": "hub-assertion"}),
                    ["POST", "/v1/endpoints/device-join-requests"] => {
                        s.join = body;
                        json!({"request_id": "req-1", "state": "pending"})
                    }
                    ["GET", "/v1/endpoints/device-join-requests/req-1"] => {
                        // The phone mints a root-signed delegation for the
                        // key and device the request names.
                        let mut d = json!({
                            "airdress": "a.example",
                            "device_id": s.join["device_id"],
                            "device_label": s.join["device_label"],
                            "device_session_public_key": s.join["device_public_key"],
                            "expires_at": "2027-01-01T00:00:00Z",
                            "issued_at": "2026-10-04T00:00:00Z",
                            "role": "human_held",
                        });
                        if kind == "cli" {
                            d["device_kind"] = json!("cli");
                        }
                        let sig = root.sign(&serde_json::to_vec(&d).unwrap());
                        d["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
                        json!({"state": "approved", "delegation": d})
                    }
                    ["POST", "/v1/endpoints/enrollments"] => {
                        s.enroll = body;
                        json!({"enrollment_id": ENROLLMENT, "token": "device-token"})
                    }
                    ["POST", "/v1/shells/device-keys"] => {
                        s.keys = body;
                        s.keys_bearer = headers.get("authorization").cloned().unwrap_or_default();
                        json!({"device": ENROLLMENT, "presenceAlg": "none"})
                    }
                    ["POST", "/v1/endpoints/device-join-requests/req-1/withdraw"] => json!({}),
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

#[tokio::test]
async fn a_cli_joins_by_delegation_and_registers_no_presence_key() {
    let (base, seen) = mock("cli").await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::in_dir(dir.path(), "a.example").unwrap();
    let dev = device::join(
        &store,
        JoinPlan {
            operator: &base,
            airdress: "a.example",
            hub: &base,
            account_bearer: &"account-token".into(),
            label: "airdress CLI on desk".into(),
            wait: Duration::from_secs(30),
        },
        &|_| {},
    )
    .await
    .unwrap();

    let s = seen.lock().unwrap();
    // Asked as a delegation-only human CLI device.
    assert_eq!(s.join["device_class"], "human");
    assert_eq!(s.join["delegation_only"], true);
    assert_eq!(s.join["device_kind"], "cli");
    assert_eq!(s.join["device_label"], "airdress CLI on desk");
    // No shell route before the approval.
    let approved = s
        .calls
        .iter()
        .position(|c| c.starts_with("GET /v1/endpoints/device-join-requests/req-1"))
        .unwrap();
    assert!(!s.calls[..approved].iter().any(|c| c.contains("/v1/shells")));
    // The enrollment carries the delegation and the two facts.
    assert_eq!(s.enroll["delegation_only"], true);
    assert_eq!(s.enroll["device_kind"], "cli");
    assert_eq!(s.enroll["delegation"]["device_kind"], "cli");
    assert_eq!(
        s.enroll["device_session_public_key"],
        s.join["device_public_key"]
    );
    // The shell key: registered with the device's bearer, `none`, signed
    // over the operator's statement by the key the delegation names.
    assert_eq!(s.keys_bearer, "Bearer device-token");
    assert_eq!(s.keys["presenceAlg"], "none");
    assert!(s.keys.get("presencePublic").is_none());
    let identity: [u8; 32] = URL_SAFE_NO_PAD
        .decode(s.join["device_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let dh: [u8; 32] = STANDARD
        .decode(s.keys["dhPublic"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig: [u8; 64] = STANDARD
        .decode(s.keys["sig"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let msg = device_keys_statement(&ENROLLMENT.parse().unwrap(), &dh);
    VerifyingKey::from_bytes(&identity)
        .unwrap()
        .verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .expect("the operator would verify it");
    assert_eq!(&dh, dev.shell.public());
    drop(s);

    // Stored, 0600, and registered.
    let back = store.load().unwrap().unwrap();
    assert_eq!(back.token.expose(), "device-token");
    assert!(back.record.keys_registered);
}

#[tokio::test]
async fn a_delegation_that_does_not_say_cli_enrolls_nothing() {
    let (base, seen) = mock("phone").await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::in_dir(dir.path(), "a.example").unwrap();
    let err = device::join(
        &store,
        JoinPlan {
            operator: &base,
            airdress: "a.example",
            hub: &base,
            account_bearer: &"account-token".into(),
            label: "airdress CLI on desk".into(),
            wait: Duration::from_secs(30),
        },
        &|_| {},
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("does not say this is a CLI"));
    let s = seen.lock().unwrap();
    assert!(!s
        .calls
        .iter()
        .any(|c| c.contains("/v1/endpoints/enrollments") || c.contains("/v1/shells")));
    assert!(store.load().unwrap().is_none());
}
