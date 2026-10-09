//! Newline-delimited JSON-RPC over a program's stdio, both ways: the shape
//! ACP (`transports.mdx`: one message per line, no embedded newlines) and
//! the Codex app-server (JSONL, with no `"jsonrpc"` member) share.
//!
//! The peer issues requests and notifications, matches responses to
//! requests by id, and hands everything the program sends unprompted —
//! notifications and the program's own requests — to its adapter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::{mpsc, oneshot};

use crate::log_err::LogErr as _;
use crate::pty::Stdio;

/// The longest line read from the program; a longer one ends the peer.
pub const MAX_LINE: usize = 16 << 20;
/// Messages waiting to be written to the program's stdin (R-ASY-5). A
/// program that stops reading makes its adapter wait here, and the adapter
/// then reads nothing more from it either.
pub const PEER_QUEUE: usize = 64;

/// Something the program sent that is not a response.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A notification.
    Notification { method: String, params: Value },
    /// A request the program expects an answer to.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
}

type Waiters = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, Value>>>>>;

/// Our end of the conversation. Its reader and writer are owned by every
/// clone together (R-ASY-1): the last one dropped aborts both.
#[derive(Debug, Clone)]
pub struct Peer {
    tx: mpsc::Sender<Value>,
    _tasks: Arc<tokio::task::JoinSet<()>>,
    waiting: Waiters,
    next: Arc<AtomicU64>,
    /// Whether messages carry `"jsonrpc": "2.0"` (ACP) or not (Codex).
    version: bool,
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

impl Peer {
    /// Start the reader and writer over `stdio`.
    pub fn start(stdio: Stdio, version: bool) -> (Self, mpsc::Receiver<Incoming>) {
        let (tx, mut rx) = mpsc::channel::<Value>(PEER_QUEUE);
        let (in_tx, in_rx) = mpsc::channel(256);
        let waiting: Waiters = Arc::default();
        let mut stdin = stdio.stdin;
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            while let Some(v) = rx.recv().await {
                let mut line = serde_json::to_vec(&v).expect("a value serializes");
                line.push(b'\n');
                if stdin.write_all(&line).await.is_err() || stdin.flush().await.is_err() {
                    break;
                }
            }
        });
        let w = Arc::clone(&waiting);
        tasks.spawn(async move {
            let mut reader = BufReader::new(stdio.stdout);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match (&mut reader)
                    .take(MAX_LINE as u64)
                    .read_until(b'\n', &mut buf)
                    .await
                {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if buf.last() != Some(&b'\n') && buf.len() >= MAX_LINE {
                    tracing::warn!("a structured harness sent a line past the limit");
                    break;
                }
                let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
                    // Not ours to interpret: some agents print a banner.
                    continue;
                };
                let method = v.get("method").and_then(Value::as_str).map(str::to_owned);
                let id = v.get("id").cloned().filter(|i| !i.is_null());
                match (method, id) {
                    (Some(method), Some(id)) => {
                        let params = v.get("params").cloned().unwrap_or(Value::Null);
                        if in_tx
                            .send(Incoming::Request { id, method, params })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    (Some(method), None) => {
                        let params = v.get("params").cloned().unwrap_or(Value::Null);
                        if in_tx
                            .send(Incoming::Notification { method, params })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    (None, Some(id)) => {
                        let waiter = w.lock().expect("waiters").remove(&id_key(&id));
                        if let Some(waiter) = waiter {
                            let r = match v.get("error") {
                                Some(e) => Err(e.clone()),
                                None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
                            };
                            // Nobody waiting: the request was abandoned.
                            if waiter.send(r).is_err() {
                                tracing::debug!("an answer arrived for an abandoned request");
                            }
                        }
                    }
                    (None, None) => {}
                }
            }
            // Everyone still waiting learns the program is gone.
            w.lock().expect("waiters").clear();
        });
        (
            Self {
                tx,
                _tasks: Arc::new(tasks),
                waiting,
                next: Arc::new(AtomicU64::new(1)),
                version,
            },
            in_rx,
        )
    }

    fn envelope(&self, mut v: Value) -> Value {
        if self.version {
            v["jsonrpc"] = Value::from("2.0");
        }
        v
    }

    /// Ask, and wait for the answer.
    ///
    /// # Errors
    /// The program's JSON-RPC error, or that it went away.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.waiting
            .lock()
            .expect("waiters")
            .insert(id_key(&json!(id)), tx);
        self.tx
            .send(self.envelope(json!({ "id": id, "method": method, "params": params })))
            .await
            .map_err(|_| anyhow!("the harness is gone"))?;
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(anyhow!(
                "{}",
                e.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the harness refused the request")
            )),
            Err(_) => Err(anyhow!("the harness is gone")),
        }
    }

    /// Tell, without an answer.
    pub async fn notify(&self, method: &str, params: Value) {
        let msg = if params.is_null() {
            json!({ "method": method })
        } else {
            json!({ "method": method, "params": params })
        };
        // Closed: the harness is gone, and its reader says so.
        self.tx
            .send(self.envelope(msg))
            .await
            .log_debug("queueing a notification for the program");
    }

    /// Answer one of the program's requests.
    pub async fn respond(&self, id: &Value, result: Value) {
        self.tx
            .send(self.envelope(json!({ "id": id, "result": result })))
            .await
            .log_debug("queueing an answer for the program");
    }

    /// Refuse one of the program's requests.
    pub async fn refuse(&self, id: &Value, code: i64, message: &str) {
        self.tx
            .send(self.envelope(json!({ "id": id, "error": { "code": code, "message": message } })))
            .await
            .log_debug("queueing a refusal for the program");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program that answers every request with its own params, sends a
    /// notification first and a request of its own last.
    fn echo_program() -> (Stdio, tokio::process::Child) {
        let script = r#"
            echo 'not json, a banner'
            echo '{"jsonrpc":"2.0","method":"hello","params":{"n":1}}'
            while IFS= read -r line; do
                id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
                [ -n "$id" ] && echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"got\":$id}}"
                echo '{"jsonrpc":"2.0","id":"x1","method":"ask","params":{}}'
            done
        "#;
        let mut c = tokio::process::Command::new("/bin/sh");
        c.args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = c.spawn().unwrap();
        let s = Stdio {
            stdin: child.stdin.take().unwrap(),
            stdout: child.stdout.take().unwrap(),
        };
        // The caller holds the child; `kill_on_drop` ends it with the test.
        (s, child)
    }

    #[tokio::test]
    async fn requests_meet_their_responses_and_the_rest_reaches_the_adapter() {
        let (stdio, _child) = echo_program();
        let (peer, mut rx) = Peer::start(stdio, true);
        assert_eq!(
            rx.recv().await.unwrap(),
            Incoming::Notification {
                method: "hello".into(),
                params: json!({"n": 1})
            }
        );
        let r = peer.request("ping", json!({})).await.unwrap();
        assert_eq!(r, json!({"got": 1}));
        assert!(matches!(
            rx.recv().await.unwrap(),
            Incoming::Request { method, .. } if method == "ask"
        ));
    }
}
