//! The agent bus from inside an editor, end to end: the server joins the
//! bus at start through a device host, pushes what other sessions write as
//! channel events, and loses nothing when those pushes go unseen.
//!
//! Driven the way a harness drives it — JSON-RPC over the binary's stdin
//! and stdout — against a mock hub, a mock operator that checks every
//! write's signature, and a stand-in device host on the real socket path.
//!
//! What it proves (design §6.6, §7.1–7.2; tasks G.2, E.6, D.7):
//!
//! - registration is device-signed, with the session id inside the signed
//!   bytes, and labelled `<host> · <repo>`;
//! - a peer's message arrives as `notifications/claude/channel`, verified
//!   and labelled, with meta keys a client can turn into attributes;
//! - this session's own messages are not pushed back to it;
//! - `bus_read` without a topic returns everything after the cursor —
//!   pushed items marked `already_pushed`, the rest too — and then
//!   nothing twice;
//! - `delivered` is acknowledged once per message, on push or on read;
//! - on EOF the session is ended at the operator.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use airdress::agent_bus::canon;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde_json::{json, Value};

const AIRDRESS: &str = "a.example";
const OUR_ENROLLMENT: &str = "11111111-1111-4111-8111-111111111111";
const PEER_SESSION: &str = "22222222-2222-4222-8222-222222222222";
const PEER_ENROLLMENT: &str = "33333333-3333-4333-8333-333333333333";

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

#[derive(Default)]
struct Bus {
    sse: bool,
    items: Vec<Value>,
    registered: Vec<Value>,
    acks: Vec<(String, Value)>,
    ended: Vec<String>,
    sessions: Vec<Value>,
    /// Direct messages: (to session, body).
    direct: Vec<(String, Value)>,
    /// Refuse the next direct message as `agent_session_expired`, as an
    /// operator does once it has forgotten a session.
    expire_next_write: bool,
    /// A session the operator has forgotten: its event stream is refused
    /// `agent_session_unknown`, so the stream notices too.
    forgotten: Option<String>,
    /// An operator that keeps session names (SPEC-166 phase B): `/info`
    /// says so, a register's `name` is settled here, and posts by name
    /// arrive on `/messages`.
    keeps_names: bool,
    /// Names held: name to session id.
    held: std::collections::BTreeMap<String, String>,
    /// Posts by name: the bodies.
    by_name: Vec<Value>,
    /// Registrations refused for their name.
    refused: Vec<Value>,
}

/// A peer's device-signed message.
fn peer_message(peer: &SigningKey, id: &str, cursor: i64, content: &str) -> Value {
    let body = json!({"content": content});
    let obj = json!({
        "airdress": AIRDRESS, "signed_by": "device", "session": PEER_SESSION,
        "enrollment": PEER_ENROLLMENT, "op": "message.post", "target": "topic:general",
        "body": canon::body_hash(&body).unwrap(), "nonce": "bm9uY2U", "time": "2026-10-05T00:00:00.000Z",
    });
    let sig = peer.sign(&canon::signing_input(&obj).unwrap());
    json!({
        "id": id, "cursor": cursor, "stream": "topic:general", "seq": cursor, "kind": "message",
        "from_session": PEER_SESSION, "from_label": "peer-box · other-repo", "from_principal": "p-1",
        "content": content, "sent_at": "2026-10-05T00:00:00.000Z",
        "attestation": {
            "signed_by": "device", "key_id": canon::key_id(peer.verifying_key().as_bytes()),
            "session": PEER_SESSION, "enrollment": PEER_ENROLLMENT, "op": "message.post",
            "target": "topic:general", "body": obj["body"], "nonce": "bm9uY2U",
            "time": "2026-10-05T00:00:00.000Z", "sig": b64(&sig.to_bytes()),
        }
    })
}

fn session_row(id: &str, enrollment: &str, key: &SigningKey, root: &SigningKey) -> Value {
    let mut d = json!({
        "airdress": AIRDRESS, "device_class": "agent",
        "device_session_public_key": b64(key.verifying_key().as_bytes()),
    });
    let sig = root.sign(canon::jcs(&d).unwrap().as_bytes());
    d["signature"] = json!(b64(&sig.to_bytes()));
    json!({
        "id": id, "label": "x", "attestation": "device", "enrollment_id": enrollment,
        "device_public_key": b64(key.verifying_key().as_bytes()), "delegation": d,
        "root_public_key": b64(root.verifying_key().as_bytes()), "topics": ["general"],
    })
}

/// Check a write's attestation as the operator would.
fn check_write(body: &Value, ours: &SigningKey) {
    let a = &body["attestation"];
    assert_eq!(a["signed_by"], "device");
    assert_eq!(a["enrollment"], OUR_ENROLLMENT);
    assert_eq!(a["key_id"], canon::key_id(ours.verifying_key().as_bytes()));
    let sig = URL_SAFE_NO_PAD.decode(a["sig"].as_str().unwrap()).unwrap();
    assert!(
        a["time"].as_str().unwrap().ends_with('Z'),
        "time is RFC 3339 UTC: {a}"
    );
    let _ = sig;
}

fn verify_signature(op: &str, target: &str, body: &Value, ours: &SigningKey) {
    let a = &body["attestation"];
    let obj = json!({
        "airdress": AIRDRESS, "signed_by": "device", "session": a["session"],
        "enrollment": a["enrollment"], "op": op, "target": target,
        "body": canon::body_hash(body).unwrap(), "nonce": a["nonce"], "time": a["time"],
    });
    let sig = ed25519_dalek::Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(a["sig"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    ours.verifying_key()
        .verify(&canon::signing_input(&obj).unwrap(), &sig)
        .unwrap_or_else(|_| panic!("{op} on {target}: the signature does not verify"));
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Value,
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    })
}

fn respond(stream: &mut std::net::TcpStream, status: u16, body: &Value) {
    let text = body.to_string();
    if let Err(e) = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    ) {
        eprintln!("best effort, the peer may have gone: {e}");
    }
}

fn spawn_operator(bus: Arc<Mutex<Bus>>, ours: SigningKey) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let bus = Arc::clone(&bus);
            let ours = ours.clone();
            std::thread::spawn(move || {
                let Some(req) = read_request(&mut stream) else {
                    return;
                };
                let p = req.path.clone();
                let path = p.split('?').next().unwrap_or_default();
                let query = p.split_once('?').map(|(_, q)| q).unwrap_or("");
                let rest = path.strip_prefix("/v1/agent-bus").unwrap_or("");
                match (req.method.as_str(), path, rest) {
                    ("GET", "/v1/capabilities", _) => respond(
                        &mut stream,
                        200,
                        &json!({"agent_bus": true, "agent_devices": true, "mcp_local": true, "mcp_remote": false}),
                    ),
                    ("GET", "/.well-known/airdress/keys.json", _) => {
                        respond(&mut stream, 200, &json!({"keys": []}));
                    }
                    ("GET", _, "/info") => {
                        let mut info = json!({"protocol": 1, "airdress": AIRDRESS,
                                "limits": {"heartbeat_seconds": 30, "claim_ttl_default_seconds": 300}});
                        if bus.lock().unwrap().keeps_names {
                            info["features"] = json!(["session_names"]);
                        }
                        respond(&mut stream, 200, &info);
                    }
                    ("POST", _, "/sessions") => {
                        check_write(&req.body, &ours);
                        let id = req.body["id"].as_str().unwrap().to_owned();
                        verify_signature("session.register", &id, &req.body, &ours);
                        assert_eq!(req.body["attestation"]["session"], id.as_str());
                        let mut b = bus.lock().unwrap();
                        if let Some(name) = req.body["name"].as_str() {
                            assert!(b.keeps_names, "a name sent to an operator that keeps none");
                            if b.held.get(name).is_some_and(|holder| *holder != id) {
                                b.refused.push(req.body.clone());
                                drop(b);
                                respond(
                                    &mut stream,
                                    409,
                                    &json!({"error": {"code": "session_name_taken", "message": "x",
                                            "name": name, "suggested": format!("{name}-2")}}),
                                );
                                return;
                            }
                            b.held.insert(name.to_owned(), id.clone());
                        }
                        b.registered.push(req.body.clone());
                        respond(&mut stream, 201, &json!({"id": id}));
                    }
                    ("GET", _, "/sessions") => {
                        let rows = bus.lock().unwrap().sessions.clone();
                        respond(&mut stream, 200, &json!({"sessions": rows}));
                    }
                    ("GET", _, r) if r.ends_with("/events") => {
                        let b = bus.lock().unwrap();
                        if b.forgotten.as_deref().is_some_and(|f| r.contains(f)) {
                            drop(b);
                            respond(
                                &mut stream,
                                404,
                                &json!({"error": {"code": "agent_session_unknown", "message": "x"}}),
                            );
                            return;
                        }
                        if !b.sse {
                            drop(b);
                            respond(
                                &mut stream,
                                503,
                                &json!({"error": {"code": "unavailable", "message": "x"}}),
                            );
                            return;
                        }
                        let after: i64 = req
                            .headers
                            .get("last-event-id")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let mut out = String::from(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: hello\n\n",
                        );
                        for i in b
                            .items
                            .iter()
                            .filter(|i| i["cursor"].as_i64().unwrap() > after)
                        {
                            out.push_str(&format!(
                                "id: {}\nevent: {}\ndata: {}\n\n",
                                i["cursor"],
                                i["kind"].as_str().unwrap(),
                                i
                            ));
                        }
                        drop(b);
                        if let Err(e) = stream.write_all(out.as_bytes()) {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                        // Held a moment, then closed: the client reconnects.
                        std::thread::sleep(Duration::from_millis(300));
                    }
                    ("POST", _, r) if r.ends_with("/heartbeat") => {
                        respond(&mut stream, 200, &json!({}));
                    }
                    ("GET", _, "/messages") => {
                        let after: i64 = query
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("after="))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let items: Vec<Value> = bus
                            .lock()
                            .unwrap()
                            .items
                            .iter()
                            .filter(|i| i["cursor"].as_i64().unwrap() > after)
                            .cloned()
                            .collect();
                        let next = items
                            .iter()
                            .filter_map(|i| i["cursor"].as_i64())
                            .max()
                            .unwrap_or(after);
                        respond(
                            &mut stream,
                            200,
                            &json!({"items": items, "next_cursor": next}),
                        );
                    }
                    ("POST", _, r) if r.starts_with("/messages/") && r.ends_with("/acks") => {
                        let id = r
                            .trim_start_matches("/messages/")
                            .trim_end_matches("/acks")
                            .to_owned();
                        check_write(&req.body, &ours);
                        verify_signature("ack", &id, &req.body, &ours);
                        bus.lock().unwrap().acks.push((id, req.body.clone()));
                        respond(&mut stream, 201, &json!({"state": req.body["state"]}));
                    }
                    ("POST", _, "/messages") => {
                        let to = req.body["to_name"].as_str().unwrap().to_owned();
                        check_write(&req.body, &ours);
                        verify_signature("message.post", &format!("name:{to}"), &req.body, &ours);
                        let mut b = bus.lock().unwrap();
                        if b.held.contains_key(&to) {
                            b.by_name.push(req.body.clone());
                            drop(b);
                            respond(&mut stream, 201, &json!({"id": "n-1", "seq": 1}));
                        } else {
                            drop(b);
                            respond(
                                &mut stream,
                                404,
                                &json!({"error": {"code": "no_session_named", "message": "x", "name": to}}),
                            );
                        }
                    }
                    ("POST", _, r) if r.starts_with("/sessions/") && r.ends_with("/messages") => {
                        let to = r
                            .trim_start_matches("/sessions/")
                            .trim_end_matches("/messages")
                            .to_owned();
                        check_write(&req.body, &ours);
                        verify_signature(
                            "message.post",
                            &format!("session:{to}"),
                            &req.body,
                            &ours,
                        );
                        if std::mem::take(&mut bus.lock().unwrap().expire_next_write) {
                            // Answered late, as a write in flight across an
                            // operator restart is: by then the stream has
                            // noticed and registered again.
                            std::thread::sleep(Duration::from_millis(3000));
                            respond(
                                &mut stream,
                                404,
                                &json!({"error": {"code": "agent_session_expired", "message": "x"}}),
                            );
                            return;
                        }
                        bus.lock().unwrap().direct.push((to, req.body.clone()));
                        respond(&mut stream, 201, &json!({"id": "d-1", "seq": 1}));
                    }
                    ("DELETE", _, r) if r.starts_with("/sessions/") => {
                        let id = r.trim_start_matches("/sessions/").to_owned();
                        verify_signature("session.end", &id, &req.body, &ours);
                        bus.lock().unwrap().ended.push(id);
                        respond(&mut stream, 200, &json!({}));
                    }
                    _ => respond(
                        &mut stream,
                        404,
                        &json!({"error": {"code": "not_found", "message": p}}),
                    ),
                }
            });
        }
    });
    port
}

fn spawn_hub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            if read_request(&mut stream).is_none() {
                continue;
            }
            respond(&mut stream, 200, &json!({"items": [], "next_cursor": null}));
        }
    });
    port
}

/// The device host, as far as the server can tell: it answers
/// `device.status` and `sign` on the real socket path.
fn spawn_device_host(socket: &std::path::Path, key: SigningKey) {
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let key = key.clone();
            std::thread::spawn(move || {
                let mut w = stream.try_clone().unwrap();
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    let req: Value = serde_json::from_str(&line).unwrap();
                    let answer = match req["op"].as_str() {
                        Some("device.status") => {
                            json!({"ok": true, "enrollment_id": OUR_ENROLLMENT})
                        }
                        Some("sign") => {
                            let payload =
                                STANDARD.decode(req["payload"].as_str().unwrap()).unwrap();
                            json!({"ok": true, "signature": b64(&key.sign(&payload).to_bytes()),
                                   "public_key": b64(key.verifying_key().as_bytes()),
                                   "enrollment_id": OUR_ENROLLMENT})
                        }
                        _ => json!({"ok": false, "message": "no"}),
                    };
                    writeln!(w, "{answer}").unwrap();
                }
            });
        }
    });
}

fn profile_store(home: &std::path::Path, hub_port: u16, operator_host: &str) {
    let dir = home.join(".airdress/profiles");
    std::fs::create_dir_all(&dir).unwrap();
    let profile = json!({
        "schema_version": 2,
        "endpoint": format!("http://127.0.0.1:{hub_port}"),
        "auth": {
            "method": "device_flow",
            "access_token": "at-bus-test",
            "refresh_token": "rt-bus-test",
            "expires_at": "2999-01-01T00:00:00Z",
            "id_token_claims": {"sub": "user-1", "email": "qa@example.com"},
        },
        "active_airdress": operator_host,
    });
    std::fs::write(dir.join("default.json"), profile.to_string()).unwrap();
    std::fs::write(home.join(".airdress/active-profile"), "default").unwrap();
}

struct Server {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: mpsc::Receiver<Value>,
    notifications: Vec<Value>,
}

impl Server {
    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        loop {
            let v = self
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("a reply in time");
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            self.notifications.push(v);
        }
    }

    /// Wait for a notification matching `pred`.
    fn wait_for(&mut self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(n) = self.notifications.iter().find(|n| pred(n)) {
            return n.clone();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(v) = self.lines.recv_timeout(Duration::from_millis(200)) {
                self.notifications.push(v.clone());
                if pred(&v) {
                    return v;
                }
            }
        }
        panic!("{what} never arrived: {:?}", self.notifications);
    }
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn pushed_items_are_labelled_and_reads_lose_nothing() {
    let home = tempfile::tempdir().unwrap();
    let state = home.path().join("state");
    let ours = SigningKey::from_bytes(&[0x21; 32]);
    let peer = SigningKey::from_bytes(&[0x22; 32]);
    let root = SigningKey::from_bytes(&[0x23; 32]);

    let bus = Arc::new(Mutex::new(Bus {
        sse: true,
        ..Bus::default()
    }));
    bus.lock()
        .unwrap()
        .items
        .push(peer_message(&peer, "m1", 1, "hello from the peer"));
    // The peer already holds the name this session is configured with.
    let mut peer_row = session_row(PEER_SESSION, PEER_ENROLLMENT, &peer, &root);
    peer_row["label"] = json!("@tester · peer-box · other-repo");
    bus.lock().unwrap().sessions.push(peer_row);

    let op_port = spawn_operator(Arc::clone(&bus), ours.clone());
    let hub_port = spawn_hub();
    let operator_host = format!("127.0.0.1:{op_port}");
    profile_store(home.path(), hub_port, &operator_host);
    spawn_device_host(
        &airdress::agent_bus::socket::socket_path(
            &airdress::agent_bus::socket::device_dir(&state, &operator_host),
            // A temporary path is short: the socket sits beside its state.
            None,
        ),
        ours.clone(),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_airdress-mcp"))
        .args([
            "--harness",
            "test-harness",
            "--profile",
            "default",
            "--default-airdress",
            &operator_host,
            "--bus",
            "true",
            "--bus-topics",
            "general",
            "--session-name",
            "tester",
            "--state-dir",
        ])
        .arg(&state)
        .env("HOME", home.path())
        .env_remove("AIRDRESS_SESSION_NAME")
        .env("AIRDRESS_OPERATOR_URL", format!("http://{operator_host}"))
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start airdress-mcp");
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let v: Value =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON: {line} ({e})"));
            if tx.send(v).is_err() {
                break;
            }
        }
    });
    let mut server = Server {
        stdin: child.stdin.take(),
        child,
        lines: rx,
        notifications: Vec::new(),
    };

    let init = server.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    let experimental = &init["result"]["capabilities"]["experimental"];
    assert!(experimental.get("claude/channel").is_some(), "{init}");
    assert!(
        !experimental.to_string().contains("permission"),
        "no permission relay: {experimental}"
    );

    // Registered, device-signed (the mock checked the signature), labelled.
    wait_until("registration", || {
        !bus.lock().unwrap().registered.is_empty()
    });
    let reg = bus.lock().unwrap().registered[0].clone();
    assert_eq!(reg["harness"], "test-harness");
    // The name leads the label, so other sessions can address it; the
    // peer holds `tester`, so this session takes the first free suffix.
    let label = reg["label"].as_str().unwrap();
    assert!(label.starts_with("@tester-2 · "), "{label}");
    assert_eq!(reg["topics"], json!(["general"]));
    let ours_id = reg["id"].as_str().unwrap().to_owned();
    {
        let mut b = bus.lock().unwrap();
        b.sessions
            .push(session_row(&ours_id, OUR_ENROLLMENT, &ours, &root));
        // Our own message: never pushed back to us.
        let mut mine = peer_message(&peer, "m2", 2, "mine");
        mine["from_session"] = json!(ours_id);
        b.items.push(mine);
    }

    // The peer's message arrives as a channel event, verified.
    let pushed = server.wait_for("the channel event for m1", |n| {
        n["method"] == "notifications/claude/channel" && n["params"]["meta"]["message_id"] == "m1"
    });
    let meta = pushed["params"]["meta"].as_object().unwrap();
    for (k, v) in meta {
        assert!(
            !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "meta key {k:?}"
        );
        assert!(v.is_string(), "{k}");
    }
    assert_eq!(pushed["params"]["content"], "hello from the peer");
    assert_eq!(meta["signed_by"], "device");
    assert_eq!(meta["signature"], "valid");
    assert_eq!(meta["topic"], "general");
    assert_eq!(meta["from_session"], PEER_SESSION);

    // Now pushes stop reaching anyone (channels off, or a dropped
    // stream), and another message arrives.
    bus.lock().unwrap().sse = false;
    bus.lock()
        .unwrap()
        .items
        .push(peer_message(&peer, "m3", 3, "second from the peer"));

    // The inbox returns all three, pushed or not, own included.
    let read = server.call(
        10,
        "tools/call",
        json!({"name": "bus_read", "arguments": {}}),
    );
    assert_eq!(read["result"]["isError"], false, "{read}");
    let items = read["result"]["structuredContent"]["items"]
        .as_array()
        .unwrap()
        .clone();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["m1", "m2", "m3"], "nothing lost: {items:?}");
    let by_id = |id: &str| items.iter().find(|i| i["id"] == id).unwrap().clone();
    assert_eq!(by_id("m1")["already_pushed"], true);
    assert_eq!(by_id("m3")["already_pushed"], false);
    assert_eq!(by_id("m3")["signed_by"], "device-signed");
    assert_eq!(by_id("m3")["signature"], "valid");

    // And never twice.
    let again = server.call(
        11,
        "tools/call",
        json!({"name": "bus_read", "arguments": {}}),
    );
    assert_eq!(
        again["result"]["structuredContent"]["items"],
        json!([]),
        "{again}"
    );

    // whoami says how delivery works and that the session is on the bus.
    let who = server.call(12, "tools/call", json!({"name": "whoami", "arguments": {}}));
    let who = &who["result"]["structuredContent"];
    assert!(who["delivery"].as_str().unwrap().contains("bus_read"));
    assert_eq!(who["bus"]["sessions"][0]["registered"], true);
    assert_eq!(who["session_name"], "tester-2", "{who}");
    assert!(
        who["name_note"]
            .as_str()
            .unwrap()
            .contains("tester was taken"),
        "{who}"
    );

    // A direct message by name reaches the session that holds it.
    let direct = server.call(
        13,
        "tools/call",
        json!({"name": "bus_post", "arguments": {"to_session": "@tester", "content": "hi"}}),
    );
    assert_eq!(direct["result"]["isError"], false, "{direct}");
    assert_eq!(bus.lock().unwrap().direct[0].0, PEER_SESSION);
    let listed = server.call(
        14,
        "tools/call",
        json!({"name": "bus_sessions", "arguments": {}}),
    );
    assert_eq!(
        listed["result"]["structuredContent"]["sessions"][0]["name"],
        "tester"
    );
    let unknown = server.call(
        15,
        "tools/call",
        json!({"name": "bus_post", "arguments": {"to_session": "nobody", "content": "hi"}}),
    );
    assert_eq!(unknown["result"]["isError"], true, "{unknown}");
    assert!(
        unknown.to_string().contains("no_session_named"),
        "{unknown}"
    );
    assert!(
        unknown.to_string().contains("named sessions: tester"),
        "{unknown}"
    );

    // A re-registration keeps the name. The operator has forgotten the
    // session while its old row is still listed as `@tester-2`; settling
    // the name again would make it `tester-3`.
    {
        let mut b = bus.lock().unwrap();
        let row = b
            .sessions
            .iter_mut()
            .find(|r| r["id"] == ours_id.as_str())
            .unwrap();
        row["label"] = json!(label);
        b.expire_next_write = true;
        // The stream hears it too, at about the same moment.
        b.forgotten = Some(ours_id.clone());
    }
    let after_expiry = server.call(
        16,
        "tools/call",
        json!({"name": "bus_post", "arguments": {"to_session": "@tester", "content": "again"}}),
    );
    assert_eq!(after_expiry["result"]["isError"], false, "{after_expiry}");
    // Both the write and the stream heard the session was forgotten; one
    // registration answers both, and no duplicate is left behind.
    std::thread::sleep(Duration::from_millis(1500));
    let again = bus.lock().unwrap().registered.clone();
    assert_eq!(again.len(), 2, "registered again, once: {again:?}");
    assert_ne!(
        again[1]["id"], again[0]["id"],
        "a re-registration is a new session"
    );
    assert_eq!(again[1]["label"], again[0]["label"], "and keeps its name");
    assert_eq!(
        bus.lock().unwrap().direct.len(),
        2,
        "the post went through after it"
    );
    let who = server.call(17, "tools/call", json!({"name": "whoami", "arguments": {}}));
    assert_eq!(
        who["result"]["structuredContent"]["session_name"], "tester-2",
        "{who}"
    );

    // Two live sessions under one name (an older server, or a race the
    // operator does not settle until phase B): a post by that name is
    // refused, naming both, rather than sent to either.
    let mut twin = session_row("bbbbbbbb-0000-4000-8000-000000000002", "e-2", &peer, &root);
    twin["label"] = json!("@tester · elsewhere · repo");
    bus.lock().unwrap().sessions.push(twin);
    let ambiguous = server.call(
        18,
        "tools/call",
        json!({"name": "bus_post", "arguments": {"to_session": "tester", "content": "which?"}}),
    );
    assert_eq!(ambiguous["result"]["isError"], true, "{ambiguous}");
    let text = ambiguous.to_string();
    assert!(text.contains("session_name_ambiguous"), "{text}");
    assert!(text.contains(PEER_SESSION), "{text}");
    assert!(
        text.contains("bbbbbbbb-0000-4000-8000-000000000002"),
        "{text}"
    );
    assert_eq!(bus.lock().unwrap().direct.len(), 2, "nothing was sent");

    // Delivered once per peer message: m1 on push, m3 on read; never m2.
    let acked: Vec<String> = bus
        .lock()
        .unwrap()
        .acks
        .iter()
        .map(|(i, _)| i.clone())
        .collect();
    assert!(acked.contains(&"m1".to_string()), "{acked:?}");
    assert!(acked.contains(&"m3".to_string()), "{acked:?}");
    assert!(!acked.contains(&"m2".to_string()), "{acked:?}");
    assert_eq!(acked.iter().filter(|i| *i == "m1").count(), 1, "{acked:?}");

    // Our own message was never pushed.
    assert!(!server
        .notifications
        .iter()
        .any(|n| n["params"]["meta"]["message_id"] == "m2"));

    // EOF ends the session at the operator: the one it re-registered as.
    drop(server.stdin.take());
    wait_until("the session's end", || {
        !bus.lock().unwrap().ended.is_empty()
    });
    let current = bus.lock().unwrap().registered[1]["id"].clone();
    assert_eq!(bus.lock().unwrap().ended[0], current);
    let status = server.child.wait().unwrap();
    assert!(status.success());
}

/// SPEC-166 phase B: against an operator that keeps names, the name is a
/// field of its own, the operator settles a clash, and a post by name goes
/// to it.
#[test]
fn an_operator_that_keeps_names_settles_them() {
    let home = tempfile::tempdir().unwrap();
    let state = home.path().join("state");
    let ours = SigningKey::from_bytes(&[0x21; 32]);
    let peer = SigningKey::from_bytes(&[0x22; 32]);
    let root = SigningKey::from_bytes(&[0x23; 32]);
    let bus = Arc::new(Mutex::new(Bus {
        keeps_names: true,
        ..Bus::default()
    }));
    {
        // The peer holds `tester` on the operator; its label says nothing.
        let mut b = bus.lock().unwrap();
        b.held.insert("tester".into(), PEER_SESSION.into());
        let mut row = session_row(PEER_SESSION, PEER_ENROLLMENT, &peer, &root);
        row["label"] = json!("peer-box · other-repo");
        row["name"] = json!("tester");
        b.sessions.push(row);
    }
    let op_port = spawn_operator(Arc::clone(&bus), ours.clone());
    let hub_port = spawn_hub();
    let operator_host = format!("127.0.0.1:{op_port}");
    profile_store(home.path(), hub_port, &operator_host);
    spawn_device_host(
        &airdress::agent_bus::socket::socket_path(
            &airdress::agent_bus::socket::device_dir(&state, &operator_host),
            None,
        ),
        ours.clone(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_airdress-mcp"))
        .args([
            "--harness",
            "test-harness",
            "--profile",
            "default",
            "--default-airdress",
            &operator_host,
            "--bus",
            "true",
            "--bus-topics",
            "general",
            "--session-name",
            "tester",
            "--state-dir",
        ])
        .arg(&state)
        .env("HOME", home.path())
        .env_remove("AIRDRESS_SESSION_NAME")
        .env("AIRDRESS_OPERATOR_URL", format!("http://{operator_host}"))
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start airdress-mcp");
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                break;
            };
            if tx.send(v).is_err() {
                break;
            }
        }
    });
    let mut server = Server {
        stdin: child.stdin.take(),
        child,
        lines: rx,
        notifications: Vec::new(),
    };
    server.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );

    // The configured name was asked for, pinned, and refused; the
    // suggestion was taken, not pinned, and the label carries no name.
    wait_until("registration", || {
        !bus.lock().unwrap().registered.is_empty()
    });
    let (refused, reg) = {
        let b = bus.lock().unwrap();
        (b.refused.clone(), b.registered[0].clone())
    };
    assert_eq!(refused[0]["name"], "tester");
    assert_eq!(refused[0]["pinned"], true);
    assert_eq!(reg["name"], "tester-2");
    assert_eq!(reg["pinned"], false);
    let label = reg["label"].as_str().unwrap();
    assert!(!label.starts_with('@'), "{label}");
    let who = server.call(2, "tools/call", json!({"name": "whoami", "arguments": {}}));
    let who = &who["result"]["structuredContent"];
    assert_eq!(who["session_name"], "tester-2", "{who}");
    assert!(
        who["name_note"]
            .as_str()
            .unwrap()
            .contains("held by another"),
        "{who}"
    );

    // A post by name is resolved by the operator, signed for the name.
    let sent = server.call(
        3,
        "tools/call",
        json!({"name": "bus_post", "arguments": {"to_session": "@Tester", "content": "hi"}}),
    );
    assert_eq!(sent["result"]["isError"], false, "{sent}");
    assert_eq!(bus.lock().unwrap().by_name[0]["to_name"], "tester");
    assert!(bus.lock().unwrap().direct.is_empty());

    drop(server.stdin.take());
    assert!(server.child.wait().unwrap().success());
}
