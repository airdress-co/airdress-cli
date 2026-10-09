//! The opencode server adapter: HTTP and server-sent events on the loopback
//! server the profile's own `serve` starts (design §9.1, §7.5).
//!
//! Verified against opencode 1.18.25, run here: its OpenAPI document at
//! `/doc`, and a live event capture.
//!
//! - basic auth, user `opencode`, the password the host put in the
//!   session's `OPENCODE_SERVER_PASSWORD` (ours, not a vendor credential);
//! - `GET /global/health` until it answers;
//! - `POST /session?directory=<cwd>` → `id`;
//! - `GET /event?directory=<cwd>`: `data: {id, type, properties}` lines;
//!   `message.updated`, `message.part.updated`, `message.part.delta`,
//!   `session.status`, `session.idle`, `session.diff`, `todo.updated`,
//!   `session.error`, `permission.asked` / `permission.v2.asked`,
//!   `permission.replied`, `question.asked`;
//! - `POST /session/{id}/prompt_async {parts: [{type: "text", text}]}`;
//! - `POST /permission/{id}/reply {reply: once|always|reject}` (and the v2
//!   route for a v2 request) — by the human's tap only;
//! - `POST /session/{id}/abort`.
//!
//! The adapter reads the port from the profile's own `--port` and adds
//! nothing to the command line (FR-T5). The terminal beside it is the
//! server's own log.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use airdress_shell_proto::structured::{
    ApprovalOption, ApprovalOutcome, Event, Input, OptionKind, PlanEntry, PlanStatus, Role,
    SessionState, ToolKind, ToolStatus,
};
use futures_util::StreamExt as _;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{summarize, Out};

/// The port `opencode serve` binds when the profile names none (measured
/// on 1.18.25; its help says 0, which it does not do).
pub const DEFAULT_PORT: u16 = 4096;
/// The server's basic-auth user.
pub const USER: &str = "opencode";
/// How long the server has to come up.
pub const STARTUP: Duration = Duration::from_secs(60);
/// One request to the profile's server (not its event stream).
const REQUEST: Duration = Duration::from_secs(30);

/// Where the server is.
#[derive(Debug)]
pub struct Target {
    /// `http://127.0.0.1:<port>`, or why there is none.
    pub base: Result<String, &'static str>,
    pub password: Option<Zeroizing<String>>,
    pub directory: PathBuf,
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let eq = format!("{name}=");
    args.iter().enumerate().find_map(|(i, a)| {
        if a == name {
            args.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix(&eq)
        }
    })
}

impl Target {
    /// From the profile's own arguments. Only a loopback address is
    /// connected to.
    pub fn from_profile(
        args: &[String],
        password: Option<Zeroizing<String>>,
        directory: PathBuf,
    ) -> Self {
        let host = flag(args, "--hostname").unwrap_or("127.0.0.1");
        let base = match flag(args, "--port").map(str::parse::<u16>) {
            _ if !matches!(host, "127.0.0.1" | "localhost" | "::1") => Err("server_not_loopback"),
            Some(Ok(0)) => Err("server_port_unknown"),
            Some(Ok(p)) => Ok(format!("http://127.0.0.1:{p}")),
            Some(Err(_)) => Err("server_port_unknown"),
            None => Ok(format!("http://127.0.0.1:{DEFAULT_PORT}")),
        };
        Self {
            base,
            password,
            directory,
        }
    }
}

/// Map a tool's name onto a kind.
pub fn tool_kind(tool: &str) -> ToolKind {
    match tool {
        "read" | "list" | "ls" => ToolKind::Read,
        "edit" | "write" | "patch" | "multiedit" | "apply_patch" => ToolKind::Edit,
        "bash" | "shell" => ToolKind::Execute,
        "grep" | "glob" | "codesearch" | "search" => ToolKind::Search,
        "webfetch" | "websearch" | "fetch" => ToolKind::Fetch,
        _ => ToolKind::Other,
    }
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The options of an opencode permission request.
pub fn replies() -> Vec<ApprovalOption> {
    vec![
        ApprovalOption {
            id: "once".into(),
            label: "Allow once".into(),
            kind: OptionKind::AllowOnce,
        },
        ApprovalOption {
            id: "always".into(),
            label: "Always allow".into(),
            kind: OptionKind::AllowAlways,
        },
        ApprovalOption {
            id: "reject".into(),
            label: "Deny".into(),
            kind: OptionKind::Deny,
        },
    ]
}

/// A permission request still open, by its own id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    /// Answered on `/permission/{id}/reply`.
    V1,
    /// Answered on `/api/session/{session}/permission/{id}/reply`.
    V2,
}

/// The adapter's state, apart from its connection.
#[derive(Debug, Default)]
pub struct Mapper {
    /// The session of ours on the server.
    pub session: String,
    roles: HashMap<String, Role>,
    /// Part id → (message id, is reasoning).
    parts: HashMap<String, (String, bool)>,
    /// Tool call id → its input summary.
    inputs: HashMap<String, String>,
    pub permissions: HashMap<String, Pending>,
}

impl Mapper {
    fn role(&self, message: &str) -> Role {
        self.roles.get(message).copied().unwrap_or(Role::Assistant)
    }

    /// One bus event (`{type, properties}`), as model events. Events of
    /// another session on the same server are not ours.
    pub fn event(&mut self, ev: &Value) -> Vec<Event> {
        let kind = s(ev, "type").unwrap_or("");
        let p = ev.get("properties").cloned().unwrap_or(Value::Null);
        let session = s(&p, "sessionID")
            .or_else(|| p.get("info").and_then(|i| s(i, "sessionID")))
            .or_else(|| p.get("part").and_then(|i| s(i, "sessionID")));
        if session.is_some_and(|x| x != self.session) {
            return Vec::new();
        }
        match kind {
            "message.updated" => {
                if let Some(info) = p.get("info") {
                    if let (Some(id), Some(role)) = (s(info, "id"), s(info, "role")) {
                        let r = if role == "user" {
                            Role::User
                        } else {
                            Role::Assistant
                        };
                        self.roles.insert(id.to_owned(), r);
                    }
                }
                Vec::new()
            }
            "message.part.updated" => p.get("part").map(|x| self.part(x)).unwrap_or_default(),
            "message.part.delta" => {
                let (Some(part), Some(delta)) = (s(&p, "partID"), s(&p, "delta")) else {
                    return Vec::new();
                };
                if s(&p, "field").is_some_and(|f| f != "text") {
                    return Vec::new();
                }
                let message = s(&p, "messageID").unwrap_or("").to_owned();
                let reasoning = self.parts.get(part).is_some_and(|(_, r)| *r);
                if reasoning {
                    vec![Event::Thought {
                        id: part.to_owned(),
                        text: delta.to_owned(),
                        append: true,
                    }]
                } else {
                    vec![Event::Message {
                        id: part.to_owned(),
                        role: self.role(&message),
                        text: delta.to_owned(),
                        append: true,
                        done: false,
                    }]
                }
            }
            "session.status" => match p.get("status").and_then(|x| s(x, "type")) {
                Some("busy" | "retry") => vec![Event::Status {
                    state: SessionState::Working,
                }],
                Some("idle") => vec![Event::Status {
                    state: SessionState::Idle,
                }],
                _ => Vec::new(),
            },
            "session.idle" => vec![Event::Status {
                state: SessionState::Idle,
            }],
            "session.diff" => p
                .get("diff")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|d| {
                    let path = s(d, "file").or_else(|| s(d, "path"))?;
                    let patch = s(d, "patch")?;
                    Some(Event::Diff {
                        tool_call_id: String::new(),
                        path: path.to_owned(),
                        unified: patch.to_owned(),
                        truncated: false,
                    })
                })
                .collect(),
            "todo.updated" => vec![Event::Plan {
                entries: p
                    .get("todos")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|t| s(t, "status") != Some("cancelled"))
                    .map(|t| PlanEntry {
                        text: s(t, "content").unwrap_or("").to_owned(),
                        status: match s(t, "status") {
                            Some("completed") => PlanStatus::Completed,
                            Some("in_progress") => PlanStatus::InProgress,
                            _ => PlanStatus::Pending,
                        },
                    })
                    .collect(),
            }],
            "session.error" => {
                let e = p.get("error").cloned().unwrap_or(Value::Null);
                if s(&e, "name") == Some("MessageAbortedError") {
                    return Vec::new();
                }
                let text = e
                    .get("data")
                    .and_then(|d| s(d, "message"))
                    .or_else(|| s(&e, "name"))
                    .unwrap_or("The harness reported an error");
                vec![Event::Error {
                    text: text.to_owned(),
                }]
            }
            "permission.asked" | "permission.v2.asked" => {
                let Some(id) = s(&p, "id") else {
                    return Vec::new();
                };
                let v2 = kind == "permission.v2.asked";
                let what = if v2 {
                    s(&p, "action")
                } else {
                    s(&p, "permission")
                }
                .unwrap_or("act");
                let call = if v2 {
                    p.get("source").and_then(|x| s(x, "callID"))
                } else {
                    p.get("tool").and_then(|x| s(x, "callID"))
                };
                let list = if v2 { "resources" } else { "patterns" };
                let patterns: Vec<&str> = p
                    .get(list)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                let detail = call
                    .and_then(|c| self.inputs.get(c).cloned())
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| patterns.join("\n"));
                self.permissions
                    .insert(id.to_owned(), if v2 { Pending::V2 } else { Pending::V1 });
                vec![
                    Event::ApprovalRequest {
                        id: id.to_owned(),
                        title: format!("Allow {what}?"),
                        detail,
                        options: replies(),
                    },
                    Event::Status {
                        state: SessionState::WaitingForApproval,
                    },
                ]
            }
            "permission.replied" | "permission.v2.replied" => {
                let Some(id) = s(&p, "requestID").or_else(|| s(&p, "id")) else {
                    return Vec::new();
                };
                if self.permissions.remove(id).is_none() {
                    return Vec::new();
                }
                vec![
                    Event::ApprovalResolved {
                        id: id.to_owned(),
                        outcome: ApprovalOutcome::Answered,
                    },
                    Event::Status {
                        state: SessionState::Working,
                    },
                ]
            }
            "question.asked" => vec![
                Event::Error {
                    text: "The harness asks a question; answer it in its own interface".into(),
                },
                Event::Status {
                    state: SessionState::WaitingForInput,
                },
            ],
            _ => Vec::new(),
        }
    }

    fn part(&mut self, part: &Value) -> Vec<Event> {
        let Some(id) = s(part, "id") else {
            return Vec::new();
        };
        let message = s(part, "messageID").unwrap_or("").to_owned();
        let done = part
            .get("time")
            .and_then(|t| t.get("end"))
            .is_some_and(|e| !e.is_null());
        match s(part, "type").unwrap_or("") {
            "text" => {
                self.parts.insert(id.to_owned(), (message.clone(), false));
                if part.get("synthetic").and_then(Value::as_bool) == Some(true) {
                    return Vec::new();
                }
                vec![Event::Message {
                    id: id.to_owned(),
                    role: self.role(&message),
                    text: s(part, "text").unwrap_or("").to_owned(),
                    append: false,
                    done: done || self.role(&message) == Role::User,
                }]
            }
            "reasoning" => {
                self.parts.insert(id.to_owned(), (message, true));
                vec![Event::Thought {
                    id: id.to_owned(),
                    text: s(part, "text").unwrap_or("").to_owned(),
                    append: false,
                }]
            }
            "tool" => {
                let call = s(part, "callID").unwrap_or(id).to_owned();
                let tool = s(part, "tool").unwrap_or("tool");
                let state = part.get("state").cloned().unwrap_or(Value::Null);
                let status = match s(&state, "status") {
                    Some("running") => ToolStatus::Running,
                    Some("completed") => ToolStatus::Done,
                    Some("error") => ToolStatus::Failed,
                    _ => ToolStatus::Pending,
                };
                let input = state.get("input").map(summarize).unwrap_or_default();
                self.inputs.insert(call.clone(), input.clone());
                let mut out = vec![Event::ToolCall {
                    id: call.clone(),
                    title: s(&state, "title")
                        .filter(|t| !t.is_empty())
                        .unwrap_or(tool)
                        .to_owned(),
                    kind: tool_kind(tool),
                    status,
                    input,
                }];
                match status {
                    ToolStatus::Done => {
                        out.push(Event::ToolResult {
                            id: call.clone(),
                            text: s(&state, "output").unwrap_or("").to_owned(),
                            exit_code: state
                                .get("metadata")
                                .and_then(|m| m.get("exit"))
                                .and_then(Value::as_i64)
                                .and_then(|c| i32::try_from(c).ok()),
                            truncated: false,
                        });
                        if let Some(diff) = state
                            .get("metadata")
                            .and_then(|m| s(m, "diff"))
                            .filter(|d| !d.is_empty())
                        {
                            let path = state
                                .get("input")
                                .and_then(|i| s(i, "filePath").or_else(|| s(i, "path")))
                                .unwrap_or("")
                                .to_owned();
                            out.push(Event::Diff {
                                tool_call_id: call,
                                path,
                                unified: diff.to_owned(),
                                truncated: false,
                            });
                        }
                    }
                    ToolStatus::Failed => out.push(Event::ToolResult {
                        id: call,
                        text: s(&state, "error").unwrap_or("").to_owned(),
                        exit_code: None,
                        truncated: false,
                    }),
                    _ => {}
                }
                out
            }
            _ => Vec::new(),
        }
    }
}

struct Client {
    http: reqwest::Client,
    /// The same, with no request deadline: the held event stream.
    stream_http: reqwest::Client,
    base: String,
    password: Option<Zeroizing<String>>,
    directory: String,
}

impl Client {
    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .query(&[("directory", self.directory.as_str())]);
        match &self.password {
            Some(p) => r.basic_auth(USER, Some(p.as_str())),
            None => r,
        }
    }

    /// A `GET` on the stream client: no request deadline.
    fn stream_req(&self, path: &str) -> reqwest::RequestBuilder {
        let r = self
            .stream_http
            .get(format!("{}{path}", self.base))
            .query(&[("directory", self.directory.as_str())]);
        match &self.password {
            Some(p) => r.basic_auth(USER, Some(p.as_str())),
            None => r,
        }
    }

    async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        let r = self
            .req(reqwest::Method::POST, path)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let bytes = r.bytes().await?;
        Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
}

/// Run the adapter until the session's server goes away for good.
pub async fn run(target: Target, mut inputs: mpsc::Receiver<Input>, out: Out) {
    let base = match target.base {
        Ok(b) => b,
        Err(why) => {
            return out
                .ended(match why {
                    "server_not_loopback" => {
                        "The profile's server is not on this machine's loopback; the structured view only connects there"
                    }
                    _ => "The profile names no fixed --port, so the structured view cannot find its server",
                })
                .await
        }
    };
    // Two clients for the profile's own server on loopback: requests have
    // REQUEST deadlines; the event stream has none on purpose (a quiet
    // session sends nothing for as long as it is quiet), and ends with the
    // session.
    let (Ok(http), Ok(stream_http)) = (
        reqwest::Client::builder()
            .no_proxy()
            .timeout(REQUEST)
            .build(),
        reqwest::Client::builder().no_proxy().build(),
    ) else {
        return out.ended("No HTTP client").await;
    };
    let c = Client {
        http,
        stream_http,
        base,
        password: target.password,
        directory: target.directory.to_string_lossy().into_owned(),
    };
    // The server starts with the session's process.
    let deadline = tokio::time::Instant::now() + STARTUP;
    loop {
        let ok = c
            .req(reqwest::Method::GET, "/global/health")
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if ok {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return out.ended("The profile's server did not answer").await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let session = match c.post("/session", json!({})).await {
        Ok(v) => match s(&v, "id") {
            Some(id) => id.to_owned(),
            None => return out.ended("The server opened no session").await,
        },
        Err(e) => {
            return out
                .ended(format!("The server opened no session: {e}"))
                .await
        }
    };
    let mut m = Mapper {
        session: session.clone(),
        ..Mapper::default()
    };
    let (ev_tx, mut ev_rx) = mpsc::channel::<Value>(256);
    let events = tokio::spawn(stream_events(c.stream_req("/event"), ev_tx));
    out.event(Event::Status {
        state: SessionState::Idle,
    })
    .await;
    loop {
        tokio::select! {
            // cancel-safe: `mpsc::Receiver::recv`.
            input = inputs.recv() => {
                let Some(input) = input else { break };
                let r = match input {
                    Input::Prompt { text, .. } => c.post(&format!("/session/{session}/prompt_async"), json!({
                        "parts": [{ "type": "text", "text": text }]
                    })).await.map(|_| ()),
                    Input::ApprovalAnswer { id, option } => {
                        // The session checked that `id` is open and offers
                        // `option`; this is the human's tap, forwarded.
                        let path = match m.permissions.get(&id) {
                            Some(Pending::V2) => format!("/api/session/{session}/permission/{id}/reply"),
                            _ => format!("/permission/{id}/reply"),
                        };
                        c.post(&path, json!({ "reply": option })).await.map(|_| ())
                    }
                    Input::Cancel => c.post(&format!("/session/{session}/abort"), json!({})).await.map(|_| ()),
                };
                if let Err(e) = r {
                    out.event(Event::Error { text: format!("The server refused: {e}") }).await;
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`; `stream_events` owns the
            // partial event.
            ev = ev_rx.recv() => {
                let Some(ev) = ev else { break };
                for e in m.event(&ev) {
                    out.event(e).await;
                }
            }
        }
    }
    events.abort();
    out.ended("The profile's server stopped").await;
}

/// Read the event stream into `tx`, one JSON object per `data:` line.
async fn stream_events(req: reqwest::RequestBuilder, tx: mpsc::Sender<Value>) {
    let Ok(resp) = req.header("accept", "text/event-stream").send().await else {
        return;
    };
    if !resp.status().is_success() {
        return;
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(Ok(chunk)) = stream.next().await {
        buf.extend_from_slice(&chunk);
        while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\r', '\n']);
            if let Some(data) = line.strip_prefix("data:") {
                if let Ok(v) = serde_json::from_str::<Value>(data.trim_start()) {
                    if tx.send(v).await.is_err() {
                        return;
                    }
                }
            }
        }
        if buf.len() > super::jsonrpc::MAX_LINE {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper() -> Mapper {
        Mapper {
            session: "ses_1".into(),
            ..Mapper::default()
        }
    }

    #[test]
    fn the_port_is_the_profile_s_and_only_loopback_is_reached() {
        let t = |a: &[&str]| {
            Target::from_profile(
                &a.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>(),
                None,
                "/w".into(),
            )
            .base
        };
        assert_eq!(
            t(&["serve", "--port", "4100"]).unwrap(),
            "http://127.0.0.1:4100"
        );
        assert_eq!(
            t(&["serve", "--port=4101"]).unwrap(),
            "http://127.0.0.1:4101"
        );
        assert_eq!(t(&["serve"]).unwrap(), "http://127.0.0.1:4096");
        assert_eq!(t(&["serve", "--port", "0"]), Err("server_port_unknown"));
        assert_eq!(
            t(&["serve", "--hostname", "0.0.0.0", "--port", "1"]),
            Err("server_not_loopback")
        );
    }

    #[test]
    fn a_live_turn_maps_onto_the_model() {
        let mut m = mapper();
        let ev = |t: &str, p: Value| json!({"id": "evt", "type": t, "properties": p});
        assert!(m
            .event(&ev("message.updated", json!({"sessionID": "ses_1", "info": {"id": "msg_u", "sessionID": "ses_1", "role": "user"}})))
            .is_empty());
        let e = m.event(&ev("message.part.updated", json!({"sessionID": "ses_1", "time": 1,
            "part": {"id": "prt_u", "sessionID": "ses_1", "messageID": "msg_u", "type": "text", "text": "hi"}})));
        assert!(matches!(
            &e[..],
            [Event::Message {
                role: Role::User,
                done: true,
                ..
            }]
        ));
        m.event(&ev("message.updated", json!({"sessionID": "ses_1", "info": {"id": "msg_a", "sessionID": "ses_1", "role": "assistant"}})));
        m.event(&ev("message.part.updated", json!({"sessionID": "ses_1", "time": 1,
            "part": {"id": "prt_a", "sessionID": "ses_1", "messageID": "msg_a", "type": "text", "text": ""}})));
        let e = m.event(&ev("message.part.delta", json!({"sessionID": "ses_1", "messageID": "msg_a", "partID": "prt_a", "field": "text", "delta": "Hello"})));
        assert_eq!(
            e,
            [Event::Message {
                id: "prt_a".into(),
                role: Role::Assistant,
                text: "Hello".into(),
                append: true,
                done: false
            }]
        );
        let e = m.event(&ev("message.part.updated", json!({"sessionID": "ses_1", "time": 2,
            "part": {"id": "prt_t", "sessionID": "ses_1", "messageID": "msg_a", "type": "tool", "callID": "call_1", "tool": "bash",
                     "state": {"status": "completed", "input": {"command": "ls"}, "output": "a\nb", "title": "List files",
                               "metadata": {"exit": 0}, "time": {"start": 1, "end": 2}}}})));
        assert!(
            matches!(&e[0], Event::ToolCall { title, kind: ToolKind::Execute, status: ToolStatus::Done, .. } if title == "List files")
        );
        assert!(
            matches!(&e[1], Event::ToolResult { text, exit_code: Some(0), .. } if text == "a\nb")
        );
        let e = m.event(&ev(
            "session.status",
            json!({"sessionID": "ses_1", "status": {"type": "idle"}}),
        ));
        assert_eq!(
            e,
            [Event::Status {
                state: SessionState::Idle
            }]
        );
        // Another session on the same server is not ours.
        assert!(m
            .event(&ev("session.idle", json!({"sessionID": "ses_2"})))
            .is_empty());
    }

    #[test]
    fn a_permission_is_a_card_until_it_is_replied_to() {
        let mut m = mapper();
        let e = m.event(
            &json!({"type": "permission.asked", "properties": {"id": "per_1", "sessionID": "ses_1",
            "permission": "bash", "patterns": ["rm -rf build"], "metadata": {}, "always": []}}),
        );
        assert!(
            matches!(&e[0], Event::ApprovalRequest { id, detail, options, .. }
            if id == "per_1" && detail == "rm -rf build" && options.len() == 3)
        );
        assert_eq!(
            e[1],
            Event::Status {
                state: SessionState::WaitingForApproval
            }
        );
        let e = m.event(&json!({"type": "permission.replied", "properties": {"sessionID": "ses_1", "requestID": "per_1", "reply": "once"}}));
        assert!(matches!(
            &e[0],
            Event::ApprovalResolved {
                outcome: ApprovalOutcome::Answered,
                ..
            }
        ));
        assert!(m.permissions.is_empty());
    }
}
