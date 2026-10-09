//! Agent chat in the device host, end to end over real HTTP and real MLS:
//! the own lane with the operator's agent (AC-7, locally).
//!
//! The mock operator holds a second MLS client playing the operator's
//! agent. The device host, once approved:
//!
//! - publishes key packages and asks for its own lane;
//! - on the first `chat.send` fetches the agent's root and key package,
//!   founds the group, and posts the Welcome and the message — which the
//!   agent joins and decrypts, bound to this device's airdress;
//! - receives the agent's reply on its envelope stream, stores it sealed,
//!   acknowledges it, and answers `chat.read` and `chat.wait` with it;
//! - refuses to write into a conversation that is neither its lane nor
//!   assigned to it.

#![cfg(feature = "mls")]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use airdress_mls::credential::test_support::signed_delegation_json_v2;
use airdress_mls::MlsEngine;
use airdress_mls_client::{Client, Event, InboundEnvelope};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use airdress::agent_device::host::{self, CancellationToken as Token, HubAuth, Identity};
use airdress::agent_device::store::AgentStore;

const AIRDRESS: &str = "a.example";
const ENROLLMENT: &str = "0b7f2c1e-5a44-4d8e-9a17-3c2e6d1f8a91";
const LANE: &str = "5c1d1a8e-8a2f-4c55-9d3e-0f0a1b2c3d4e";
const AGENT_LANE_TARGET: &str = "operator.local";

struct Agent {
    client: Client,
    root: [u8; 32],
    _dir: tempfile::TempDir,
}

#[derive(Default)]
struct Op {
    published: usize,
    posted: Vec<Value>,
    heard: Vec<(String, String)>,
    outbox: VecDeque<Value>,
    acked: Vec<String>,
    agent: Option<Agent>,
    /// The revocation route's answer about the operator's agent.
    agent_revocation: Option<(u16, Value)>,
    /// Device ids the device asked the revocation route about.
    revocation_asked: Vec<String>,
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn the_operators_agent() -> Agent {
    let dir = tempfile::tempdir().unwrap();
    let seed = [0x61; 32];
    let root = SigningKey::from_bytes(&[0x62; 32]);
    let session = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let delegation = signed_delegation_json_v2(
        &root,
        AGENT_LANE_TARGET,
        &session,
        "operator-agent",
        "2099-01-01T00:00:00Z",
    );
    let engine = MlsEngine::from_seed(
        AGENT_LANE_TARGET,
        &seed,
        &root.verifying_key().to_bytes(),
        &delegation,
        dir.path().join("mls").to_str().unwrap(),
        &[0x63; 32],
    )
    .unwrap();
    engine.set_v2_cutover();
    // Past the cutover nothing verifies without a revocation lookup; the
    // operator answers its own from its tables.
    engine.set_revocation_lookup(std::sync::Arc::new(|_: &str| {
        Some(airdress_mls::credential::DeviceStatus::Active)
    }));
    let client = Client::open(engine, &dir.path().join("client"), &[0x63; 32]).unwrap();
    Agent {
        client,
        root: root.verifying_key().to_bytes(),
        _dir: dir,
    }
}

/// What the operator's agent does with a posted envelope: join, decrypt,
/// and answer a message with a reply into the same group.
fn agent_receives(op: &mut Op, body: &Value) {
    let env = InboundEnvelope {
        envelope_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: LANE.into(),
        envelope_kind: body["envelope_kind"].as_str().unwrap().to_owned(),
        from_airdress: AIRDRESS.into(),
        ciphertext: STANDARD
            .decode(body["ciphertext"].as_str().unwrap())
            .unwrap(),
        commit_from_epoch: None,
        duration_ms: None,
        received_at: None,
    };
    let agent = op.agent.as_mut().unwrap();
    let processed = agent.client.process(&env);
    if let Event::Message(m) = processed.event {
        let text = m.blocks[0]["text"].as_str().unwrap().to_owned();
        op.heard.push((m.from_airdress.clone(), text.clone()));
        let reply = serde_json::to_vec(&json!({
            "origin": "agent",
            "blocks": [{"type": "text", "text": format!("you said: {text}")}],
        }))
        .unwrap();
        let out = agent
            .client
            .encrypt(LANE, &reply, AGENT_LANE_TARGET)
            .unwrap();
        op.outbox.push_back(json!({
            "envelope_id": uuid::Uuid::new_v4().to_string(),
            "conversation_id": LANE,
            "envelope_kind": "mls_application",
            "from_airdress": AGENT_LANE_TARGET,
            "ciphertext": STANDARD.encode(&out.ciphertext),
            "received_at": rfc3339(chrono::Utc::now()),
        }));
    }
}

async fn mock() -> (String, Arc<Mutex<Op>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let op = Arc::new(Mutex::new(Op {
        agent: Some(the_operators_agent()),
        ..Op::default()
    }));
    let state = Arc::clone(&op);
    tokio::spawn(async move {
        let root = SigningKey::from_bytes(&[0x51; 32]);
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&state);
            let root = root.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let end = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p);
                    }
                };
                let Some(end) = end else { return };
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
                let parts: Vec<&str> = first.split(' ').take(2).collect();
                let (method, path) = (parts[0], parts[1]);

                if method == "GET" && path == "/v1/chat/envelopes/events" {
                    assert_eq!(
                        headers.get("authorization").map(String::as_str),
                        Some("Bearer device-token")
                    );
                    if let Err(e) = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                        .await {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                    for _ in 0..40 {
                        let next = state.lock().unwrap().outbox.pop_front();
                        if let Some(ev) = next {
                            let frame = format!("event: envelope\ndata: {ev}\n\n");
                            if sock.write_all(frame.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    return;
                }

                let (status, answer) = {
                    let mut s = state.lock().unwrap();
                    match (method, path) {
                        ("POST", "/v1/enrollment-tokens") => {
                            (200, json!({"token": "hub-assertion"}))
                        }
                        ("POST", "/v1/endpoints/device-join-requests") => (
                            200,
                            json!({"request_id": "req-1", "state": "pending", "ask": body}),
                        ),
                        ("GET", "/v1/endpoints/device-join-requests/req-1") => {
                            let now = chrono::Utc::now();
                            let mut d = json!({
                                "airdress": AIRDRESS, "device_class": "agent",
                                "device_id": "agent-device-1", "device_kind": "agent",
                                "device_label": "Agent on desk",
                                "expires_at": rfc3339(now + chrono::Duration::days(30)),
                                "harness": "test-harness", "issued_at": rfc3339(now),
                                "role": "human_held",
                            });
                            // The key the device asked with, from its stored ask.
                            d["device_session_public_key"] = json!(s.posted_key());
                            d["device_id"] = json!(s.posted_device());
                            let sig = root.sign(&serde_json::to_vec(&d).unwrap());
                            d["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
                            (200, json!({"state": "approved", "delegation": d}))
                        }
                        ("GET", "/v1/endpoints/airdresses/operator.local/root-key") => (
                            200,
                            json!({"root_public_key": URL_SAFE_NO_PAD.encode(s.agent.as_ref().unwrap().root)}),
                        ),
                        ("GET", p) if p.ends_with("/root-key") => (
                            200,
                            json!({"airdress": AIRDRESS,
                                   "root_public_key": URL_SAFE_NO_PAD.encode(root.verifying_key().to_bytes())}),
                        ),
                        ("POST", "/v1/endpoints/enrollments") => (
                            200,
                            json!({"enrollment_id": ENROLLMENT, "token": "device-token"}),
                        ),
                        ("POST", "/v1/chat/key-packages") => {
                            s.published += body["key_packages"].as_array().map_or(0, Vec::len);
                            (201, json!({"stored": s.published}))
                        }
                        ("POST", "/v1/chat/agent-lane") => (
                            201,
                            json!({"conversation_id": LANE, "target_airdress": AGENT_LANE_TARGET, "created": true}),
                        ),
                        ("GET", "/v1/chat/agent-conversations") => (
                            200,
                            json!({"conversations": [
                                {"conversation_id": LANE, "target_airdress": AGENT_LANE_TARGET,
                                 "title": null, "counterparty_kind": "agent", "lane": "own",
                                 "assignment_id": null, "state": null},
                            ]}),
                        ),
                        ("GET", "/v1/chat/key-packages/operator.local") => {
                            let kp = s.agent.as_ref().unwrap().client.key_packages(1).unwrap();
                            (200, json!({"key_package": STANDARD.encode(&kp[0])}))
                        }
                        ("POST", p) if p == format!("/v1/chat/conversations/{LANE}/envelopes") => {
                            assert_eq!(body["target_airdress"], AGENT_LANE_TARGET);
                            s.posted.push(body.clone());
                            agent_receives(&mut s, &body);
                            (
                                202,
                                json!({"envelope_id": uuid::Uuid::new_v4().to_string()}),
                            )
                        }
                        ("GET", p)
                            if p.starts_with("/v1/mls/members/") && p.ends_with("/revocation") =>
                        {
                            assert_eq!(
                                headers.get("authorization").map(String::as_str),
                                Some("Bearer device-token")
                            );
                            let id = p
                                .trim_start_matches("/v1/mls/members/")
                                .trim_end_matches("/revocation")
                                .to_owned();
                            s.revocation_asked.push(id.clone());
                            if id == "operator-agent" {
                                s.agent_revocation.clone().unwrap_or((
                                    200,
                                    json!({"device_id": id, "revoked": false, "kind": "operator_agent"}),
                                ))
                            } else if json!(id) == s.posted_device() {
                                (
                                    200,
                                    json!({"device_id": id, "revoked": false, "kind": "agent_device"}),
                                )
                            } else {
                                (
                                    404,
                                    json!({"error": {"code": "member_not_found", "message": "no"}}),
                                )
                            }
                        }
                        ("POST", p) if p.ends_with("/ack") => {
                            s.acked.push(p.to_owned());
                            (204, Value::Null)
                        }
                        (m, p) => (
                            404,
                            json!({"error": {"code": "not_found", "message": format!("{m} {p}")}}),
                        ),
                    }
                };
                let b = if answer.is_null() {
                    String::new()
                } else {
                    answer.to_string()
                };
                if let Err(e) = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{b}",
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
            });
        }
    });
    (base, op)
}

impl Op {
    fn posted_key(&self) -> Value {
        ASK.lock().unwrap()["device_public_key"].clone()
    }
    fn posted_device(&self) -> Value {
        ASK.lock().unwrap()["device_id"].clone()
    }
}

/// The device's join request, as it asked (read back by the approval).
static ASK: Mutex<Value> = Mutex::new(Value::Null);
/// One test at a time: [`ASK`] is shared.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ask(store: &AgentStore, req: Value) -> Value {
    for _ in 0..200 {
        if let Ok(v) = host::call(store, &req).await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the host never answered {req}");
}

/// A device host against `base`, asked, approved and enrolled.
async fn approved_host(
    base: &str,
) -> (
    tempfile::TempDir,
    AgentStore,
    Token,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentStore::file_only(dir.path(), AIRDRESS).unwrap();
    let cancel = Token::new();
    let task = tokio::spawn(host::run(
        store.clone(),
        HubAuth::Static {
            base: base.to_owned(),
            bearer: "account-token".into(),
        },
        Identity {
            operator: base.to_owned(),
            label: "Agent on desk".into(),
            harness: "test-harness".into(),
        },
        Duration::from_millis(200),
        cancel.clone(),
    ));

    // Ask, then let the approval land (the mock approves with the key asked).
    ask(&store, json!({"op": "device.request"})).await;
    let record = store.load().unwrap().unwrap().record;
    *ASK.lock().unwrap() = json!({
        "device_public_key": record.identity_public,
        "device_id": record.device_id,
    });
    for _ in 0..200 {
        let v = ask(&store, json!({"op": "device.status"})).await;
        if v["standing"] == "approved" && v["enrolled"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (dir, store, cancel, task)
}

// Multi-threaded: the engine asks the revocation route synchronously from
// inside its calls, as it does in the binary (`#[tokio::main]`), while the
// mock operator answers on another worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_own_lane_round_trips_with_the_operators_agent() {
    let _one = SERIAL.lock().await;
    let (base, op) = mock().await;
    let (_dir, store, cancel, task) = approved_host(&base).await;

    // A conversation that is neither the lane nor assigned is refused.
    let refused = host::call(
        &store,
        &json!({"op": "chat.send", "conversation_id": "someone-elses", "text": "x"}),
    )
    .await;
    assert!(
        format!("{refused:?}").contains("only into its own lane"),
        "{refused:?}"
    );

    let conversations_listed = ask(&store, json!({"op": "chat.conversations"})).await;
    assert_eq!(
        conversations_listed["conversations"][0]["conversation_id"],
        LANE
    );
    assert_eq!(conversations_listed["conversations"][0]["lane"], "own");

    let head = ask(&store, json!({"op": "chat.wait", "after": null})).await["head"]
        .as_i64()
        .unwrap();

    let sent = ask(
        &store,
        json!({"op": "chat.send", "conversation_id": LANE, "text": "hello operator"}),
    )
    .await;
    assert_eq!(sent["ok"], true, "{sent}");
    {
        let s = op.lock().unwrap();
        let kinds: Vec<&str> = s
            .posted
            .iter()
            .map(|p| p["envelope_kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, vec!["mls_welcome", "mls_application"]);
        assert_eq!(
            s.heard,
            vec![(AIRDRESS.to_owned(), "hello operator".to_owned())],
            "the operator's agent joined and decrypted, bound to this airdress"
        );
        assert!(
            s.revocation_asked.iter().any(|d| d == "operator-agent"),
            "the device asked whether the operator's agent is revoked: {:?}",
            s.revocation_asked
        );
    }
    // The pump, once the device is approved, publishes key packages so a
    // phone can add it to an assigned conversation.
    for _ in 0..300 {
        if op.lock().unwrap().published > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        op.lock().unwrap().published > 0,
        "key packages were published"
    );

    // The reply arrives on the stream, is stored and acknowledged.
    let mut got = Value::Null;
    for _ in 0..100 {
        let v = ask(
            &store,
            json!({"op": "chat.wait", "after": head, "timeout_ms": 500}),
        )
        .await;
        if v["messages"]
            .as_array()
            .is_some_and(|m| m.iter().any(|m| m["from"] == "operator"))
        {
            got = v;
            break;
        }
    }
    let reply = got["messages"]
        .as_array()
        .expect("the reply arrived")
        .iter()
        .find(|m| m["from"] == "operator")
        .unwrap()
        .clone();
    assert_eq!(reply["text"], "you said: hello operator");
    assert_eq!(reply["lane"], "own");
    assert_eq!(reply["conversation_id"], LANE);

    let read = ask(&store, json!({"op": "chat.read", "conversation_id": LANE})).await;
    let texts: Vec<&str> = read["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, vec!["hello operator", "you said: hello operator"]);
    for _ in 0..100 {
        if !op.lock().unwrap().acked.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !op.lock().unwrap().acked.is_empty(),
        "the reply was acknowledged"
    );

    // The message store is sealed on disk.
    let raw = std::fs::read(store.dir().join("chat").join("messages.sealed")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("hello operator"));

    cancel.cancel();
    task.await.unwrap().unwrap();
}

/// Past the cutover a member the operator calls revoked, or cannot answer
/// for, is refused: the first send never founds the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_or_unanswerable_operator_agent_is_refused() {
    let _one = SERIAL.lock().await;
    for answer in [
        (
            200,
            json!({"device_id": "operator-agent", "revoked": true,
                   "revoked_at": "2026-10-08T00:00:00Z", "kind": "operator_agent"}),
        ),
        (
            503,
            json!({"error": {"code": "revocation_unavailable", "message": "later"}}),
        ),
        (
            404,
            json!({"error": {"code": "member_not_found", "message": "no"}}),
        ),
    ] {
        let (base, op) = mock().await;
        op.lock().unwrap().agent_revocation = Some(answer.clone());
        let (_dir, store, cancel, task) = approved_host(&base).await;
        let sent = host::call(
            &store,
            &json!({"op": "chat.send", "conversation_id": LANE, "text": "hello operator"}),
        )
        .await;
        let refused = !matches!(&sent, Ok(v) if v["ok"] == true);
        assert!(refused, "{answer:?} -> {sent:?}");
        {
            let s = op.lock().unwrap();
            assert!(s.heard.is_empty(), "{answer:?}: nothing reached the agent");
            assert!(
                s.revocation_asked.iter().any(|d| d == "operator-agent"),
                "{:?}",
                s.revocation_asked
            );
        }
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
