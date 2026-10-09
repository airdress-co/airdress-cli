//! `airdress chat assign|unassign|agents` against a mock operator: the
//! routes, the bodies, and that an agent device is named by id or label.

use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use airdress::chat_assign::Operator;
use serde_json::{json, Value};

const AGENT: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const PHONE: &str = "aaaaaaaa-0000-4000-8000-000000000002";

#[derive(Default)]
struct Seen {
    calls: Vec<(String, String, Value, String)>,
    assignments: Vec<Value>,
}

fn serve(seen: Arc<Mutex<Seen>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap().to_owned();
                let path = parts.next().unwrap().to_owned();
                let mut len = 0usize;
                let mut auth = String::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap() == 0 || h.trim().is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                    if k.eq_ignore_ascii_case("authorization") {
                        auth = v.trim().to_owned();
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let mut s = seen.lock().unwrap();
                s.calls
                    .push((method.clone(), path.clone(), body.clone(), auth));
                let (status, answer) = match (method.as_str(), path.as_str()) {
                    ("GET", "/v1/endpoints/enrollments") => (
                        200,
                        json!({"enrollments": [
                            {"id": PHONE, "device_class": "human", "label": "Galaxy S23"},
                            {"id": AGENT, "device_class": "agent", "label": "Agent on box", "suspended_at": null},
                        ]}),
                    ),
                    ("POST", p) if p.ends_with("/agent-assignments") => {
                        let a = json!({"id": "as-1", "enrollment_id": body["enrollment_id"], "state": "pending_add"});
                        s.assignments.push(a.clone());
                        (201, a)
                    }
                    ("GET", p) if p.ends_with("/agent-assignments") => {
                        (200, json!({"assignments": s.assignments}))
                    }
                    ("DELETE", p) if p.ends_with("/agent-assignments/as-1") => {
                        for a in &mut s.assignments {
                            a["state"] = json!("ended");
                        }
                        (204, Value::Null)
                    }
                    _ => (
                        404,
                        json!({"error": {"code": "not_found", "message": path}}),
                    ),
                };
                drop(s);
                let text = if answer.is_null() {
                    String::new()
                } else {
                    answer.to_string()
                };
                if let Err(e) = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                ) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn assign_names_the_agent_by_label_and_unassign_ends_it() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = serve(Arc::clone(&seen));
    let op = Operator::new(format!("http://127.0.0.1:{port}/"), "owner-token").unwrap();

    let agents = op.agents().await.unwrap();
    assert_eq!(agents.len(), 1, "phones are not agents: {agents:?}");
    let agent = op.agent("Agent on box").await.unwrap();
    assert_eq!(agent["id"], AGENT);
    assert!(
        op.agent("Galaxy S23").await.is_err(),
        "a phone was accepted as an agent"
    );

    let a = op.assign("conversation_row-1", AGENT).await.unwrap();
    assert_eq!(a["state"], "pending_add");
    let list = op.assignments("conversation_row-1").await.unwrap();
    assert_eq!(list.len(), 1);
    op.unassign("conversation_row-1", "as-1").await.unwrap();

    let s = seen.lock().unwrap();
    let post = s
        .calls
        .iter()
        .find(|c| c.0 == "POST")
        .expect("an assignment was posted");
    assert_eq!(
        post.1,
        "/v1/chat/conversations/conversation_row-1/agent-assignments"
    );
    assert_eq!(post.2, json!({"enrollment_id": AGENT}));
    assert_eq!(post.3, "Bearer owner-token");
    assert!(s.calls.iter().any(|c| c.0 == "DELETE"
        && c.1 == "/v1/chat/conversations/conversation_row-1/agent-assignments/as-1"));
    assert_eq!(s.assignments[0]["state"], "ended");
}

#[tokio::test]
async fn an_operator_refusal_is_reported_with_its_code() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = serve(seen);
    let op = Operator::new(format!("http://127.0.0.1:{port}"), "t").unwrap();
    let e = op.unassign("conversation_row-1", "nope").await.unwrap_err();
    assert!(format!("{e:#}").contains("not_found"), "{e:#}");
}
