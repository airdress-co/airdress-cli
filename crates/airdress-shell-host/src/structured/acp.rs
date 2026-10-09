//! The ACP adapter: the Agent Client Protocol, version 1, over the
//! profile's own stdio (design §9.1).
//!
//! Verified against `agentclientprotocol/agent-client-protocol` tag
//! `v1.10.2` (`schema/v1/schema.json`, `docs/protocol/v1/*.mdx`), and
//! `goose acp` against Goose `v1.53.0` source (`crates/goose-cli/src/cli.rs`):
//!
//! - framing: JSON-RPC 2.0, one message per line;
//! - `initialize {protocolVersion: 1, clientCapabilities, clientInfo}`;
//!   the client declares **no** `fs` and **no** `terminal` capability, so
//!   the agent "MUST NOT attempt to call" those methods, and any it calls
//!   anyway is refused: this host reads and writes nothing for a harness;
//! - `session/new {cwd, mcpServers: []}` → `sessionId`;
//! - `session/prompt {sessionId, prompt: [{type: "text", text}]}` →
//!   `stopReason`;
//! - `session/update` (`agent_message_chunk`, `user_message_chunk`,
//!   `agent_thought_chunk`, `tool_call`, `tool_call_update`, `plan`);
//! - `session/request_permission` → `{outcome: {outcome: "selected",
//!   optionId}}`, or `{outcome: "cancelled"}` once the human cancelled the
//!   turn (the spec requires every pending request be answered so);
//! - `session/cancel {sessionId}`.
//!
//! The terminal beside it shows only the agent's stderr: stdio is the
//! protocol, so the terminal takes no input (design §9.1).

use std::collections::HashMap;
use std::path::PathBuf;

use airdress_shell_proto::structured::{
    ApprovalOption, ApprovalOutcome, Event, Input, OptionKind, PlanEntry, PlanStatus, Role,
    SessionState, ToolKind, ToolStatus,
};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::jsonrpc::{Incoming, Peer};
use super::{summarize, unified::unified, Out};
use crate::log_err::LogErr as _;
use crate::pty::Stdio;

/// The ACP protocol version this adapter speaks.
pub const PROTOCOL_VERSION: u64 = 1;

/// A tool call's fields, kept so an update that names only some of them
/// still renders whole.
#[derive(Debug, Clone)]
struct Tool {
    title: String,
    kind: ToolKind,
    status: ToolStatus,
    input: String,
}

/// Map ACP's tool kind.
pub fn tool_kind(k: Option<&str>) -> ToolKind {
    match k {
        Some("read") => ToolKind::Read,
        Some("edit" | "delete" | "move") => ToolKind::Edit,
        Some("search") => ToolKind::Search,
        Some("execute") => ToolKind::Execute,
        Some("fetch") => ToolKind::Fetch,
        _ => ToolKind::Other,
    }
}

/// Map ACP's tool status.
pub fn tool_status(s: Option<&str>) -> Option<ToolStatus> {
    Some(match s? {
        "pending" => ToolStatus::Pending,
        "in_progress" => ToolStatus::Running,
        "completed" => ToolStatus::Done,
        "failed" => ToolStatus::Failed,
        _ => return None,
    })
}

/// Map ACP's permission option kind. A reject, once or always, is a deny.
pub fn option_kind(k: &str) -> OptionKind {
    match k {
        "allow_once" => OptionKind::AllowOnce,
        "allow_always" => OptionKind::AllowAlways,
        _ => OptionKind::Deny,
    }
}

fn text_of(content: &Value) -> Option<&str> {
    (content.get("type").and_then(Value::as_str) == Some("text"))
        .then(|| content.get("text").and_then(Value::as_str))
        .flatten()
}

/// The adapter's state, apart from its connection.
#[derive(Debug, Default)]
pub struct Mapper {
    tools: HashMap<String, Tool>,
    turn: u64,
    prompts: u64,
}

impl Mapper {
    fn assistant_id(&self, message_id: Option<&str>) -> String {
        message_id.map_or_else(|| format!("assistant-{}", self.turn), str::to_owned)
    }

    /// One `session/update` notification's `update`, as events.
    pub fn update(&mut self, u: &Value) -> Vec<Event> {
        let kind = u.get("sessionUpdate").and_then(Value::as_str).unwrap_or("");
        let message_id = u.get("messageId").and_then(Value::as_str);
        match kind {
            "agent_message_chunk" | "user_message_chunk" | "agent_thought_chunk" => {
                let Some(text) = u.get("content").and_then(text_of) else {
                    return Vec::new();
                };
                match kind {
                    "agent_message_chunk" => vec![Event::Message {
                        id: self.assistant_id(message_id),
                        role: Role::Assistant,
                        text: text.to_owned(),
                        append: true,
                        done: false,
                    }],
                    "user_message_chunk" => vec![Event::Message {
                        id: message_id
                            .map_or_else(|| format!("user-replayed-{}", self.turn), str::to_owned),
                        role: Role::User,
                        text: text.to_owned(),
                        append: true,
                        done: false,
                    }],
                    _ => vec![Event::Thought {
                        id: message_id.map_or_else(
                            || format!("thought-{}", self.turn),
                            |m| format!("thought-{m}"),
                        ),
                        text: text.to_owned(),
                        append: true,
                    }],
                }
            }
            "tool_call" | "tool_call_update" => self.tool(u),
            "plan" => {
                let entries = u
                    .get("entries")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|e| PlanEntry {
                                text: e
                                    .get("content")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_owned(),
                                status: match e.get("status").and_then(Value::as_str) {
                                    Some("completed") => PlanStatus::Completed,
                                    Some("in_progress") => PlanStatus::InProgress,
                                    _ => PlanStatus::Pending,
                                },
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                vec![Event::Plan { entries }]
            }
            _ => Vec::new(),
        }
    }

    fn tool(&mut self, u: &Value) -> Vec<Event> {
        let Some(id) = u.get("toolCallId").and_then(Value::as_str) else {
            return Vec::new();
        };
        let t = self.tools.entry(id.to_owned()).or_insert_with(|| Tool {
            title: String::new(),
            kind: ToolKind::Other,
            status: ToolStatus::Pending,
            input: String::new(),
        });
        if let Some(title) = u.get("title").and_then(Value::as_str) {
            title.clone_into(&mut t.title);
        }
        if let Some(k) = u.get("kind").and_then(Value::as_str) {
            t.kind = tool_kind(Some(k));
        }
        if let Some(s) = tool_status(u.get("status").and_then(Value::as_str)) {
            t.status = s;
        }
        if let Some(raw) = u.get("rawInput") {
            t.input = summarize(raw);
        } else if t.input.is_empty() {
            if let Some(p) = u
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|l| l.first())
                .and_then(|l| l.get("path"))
                .and_then(Value::as_str)
            {
                p.clone_into(&mut t.input);
            }
        }
        let mut out = vec![Event::ToolCall {
            id: id.to_owned(),
            title: if t.title.is_empty() {
                "Tool".to_owned()
            } else {
                t.title.clone()
            },
            kind: t.kind,
            status: t.status,
            input: t.input.clone(),
        }];
        let mut text = String::new();
        for c in u
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match c.get("type").and_then(Value::as_str) {
                Some("diff") => {
                    let path = c.get("path").and_then(Value::as_str).unwrap_or("");
                    let new = c.get("newText").and_then(Value::as_str).unwrap_or("");
                    let old = c.get("oldText").and_then(Value::as_str);
                    out.push(Event::Diff {
                        tool_call_id: id.to_owned(),
                        path: path.to_owned(),
                        unified: unified(path, old, new),
                        truncated: false,
                    });
                }
                Some("content") => {
                    if let Some(t) = c.get("content").and_then(text_of) {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(t);
                    }
                }
                _ => {}
            }
        }
        if !text.is_empty() {
            out.push(Event::ToolResult {
                id: id.to_owned(),
                text,
                exit_code: None,
                truncated: false,
            });
        }
        out
    }

    /// A `session/request_permission`'s params, as the approval card.
    pub fn permission(&mut self, approval: &str, params: &Value) -> Event {
        let call = params.get("toolCall").cloned().unwrap_or(Value::Null);
        // The request carries the tool call as an update: show it too.
        let title = call
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                call.get("toolCallId")
                    .and_then(Value::as_str)
                    .and_then(|i| self.tools.get(i))
                    .map(|t| t.title.clone())
            })
            .unwrap_or_else(|| "The harness asks for permission".to_owned());
        let detail = call
            .get("rawInput")
            .map(summarize)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                call.get("toolCallId")
                    .and_then(Value::as_str)
                    .and_then(|i| self.tools.get(i))
                    .map(|t| t.input.clone())
            })
            .unwrap_or_default();
        let options = params
            .get("options")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|o| {
                        Some(ApprovalOption {
                            id: o.get("optionId")?.as_str()?.to_owned(),
                            label: o
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned(),
                            kind: option_kind(o.get("kind").and_then(Value::as_str).unwrap_or("")),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Event::ApprovalRequest {
            id: approval.to_owned(),
            title,
            detail,
            options,
        }
    }
}

/// Run the adapter until the harness goes away.
pub async fn run(stdio: Stdio, cwd: PathBuf, mut inputs: mpsc::Receiver<Input>, out: Out) {
    let (peer, mut incoming) = Peer::start(stdio, true);
    let init = peer
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "clientCapabilities": {
                    "fs": { "readTextFile": false, "writeTextFile": false },
                    "terminal": false
                },
                "clientInfo": { "name": "airdress-shell-host", "version": env!("CARGO_PKG_VERSION") }
            }),
        )
        .await;
    if let Err(e) = init {
        return out
            .ended(format!("The harness did not start its protocol: {e}"))
            .await;
    }
    let session = match peer
        .request(
            "session/new",
            json!({ "cwd": cwd.to_string_lossy(), "mcpServers": [] }),
        )
        .await
    {
        Ok(v) => match v.get("sessionId").and_then(Value::as_str) {
            Some(s) => s.to_owned(),
            None => return out.ended("The harness opened no session").await,
        },
        Err(e) => {
            return out
                .ended(format!("The harness opened no session: {e}"))
                .await
        }
    };
    let mut m = Mapper::default();
    // Our approval id → the harness's request id, until a human answers.
    let mut open: HashMap<String, Value> = HashMap::new();
    let mut approvals = 0u64;
    // The turn requests in flight, owned by this adapter (R-ASY-1), and
    // their answers. One turn runs at a time, so the bound is never met in
    // practice; a request waits for room past it (R-ASY-5).
    let mut requests = tokio::task::JoinSet::new();
    let (turn_tx, mut turn_rx) = mpsc::channel::<Result<Value, String>>(super::TURN_RESULTS);
    let mut running = false;
    out.event(Event::Status {
        state: SessionState::Idle,
    })
    .await;
    loop {
        tokio::select! {
            // cancel-safe: `mpsc::Receiver::recv`.
            input = inputs.recv() => {
                let Some(input) = input else { break };
                match input {
                    Input::Prompt { text, .. } => {
                        if running {
                            out.event(Event::Error { text: "A turn is running; wait for it or cancel it".into() }).await;
                            continue;
                        }
                        m.prompts += 1;
                        m.turn += 1;
                        running = true;
                        out.event(Event::Message {
                            id: format!("user-{}", m.prompts),
                            role: Role::User,
                            text: text.clone(),
                            append: false,
                            done: true,
                        }).await;
                        out.event(Event::Status { state: SessionState::Working }).await;
                        let p = peer.clone();
                        let tx = turn_tx.clone();
                        let session = session.clone();
                        requests.spawn(async move {
                            let r = p.request("session/prompt", json!({
                                "sessionId": session,
                                "prompt": [{ "type": "text", "text": text }]
                            })).await.map_err(|e| e.to_string());
                            // Closed: the turn was abandoned.
                            tx.send(r)
                                .await
                                .log_debug("handing back a prompt's answer");
                        });
                    }
                    Input::ApprovalAnswer { id, option } => {
                        // The session checked that `id` is open and offers
                        // `option`; this is the human's tap, forwarded.
                        if let Some(rpc) = open.remove(&id) {
                            peer.respond(&rpc, json!({ "outcome": { "outcome": "selected", "optionId": option } })).await;
                            out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Answered }).await;
                            if running {
                                out.event(Event::Status { state: SessionState::Working }).await;
                            }
                        }
                    }
                    Input::Cancel => {
                        peer.notify("session/cancel", json!({ "sessionId": session })).await;
                        // ACP: a client that cancels answers every pending
                        // permission request `cancelled`. The human asked
                        // for the cancel; nothing is approved by it.
                        for (id, rpc) in open.drain() {
                            peer.respond(&rpc, json!({ "outcome": { "outcome": "cancelled" } })).await;
                            out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Withdrawn }).await;
                        }
                    }
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`; the peer's reader owns the
            // partial line.
            msg = incoming.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    Incoming::Notification { method, params } if method == "session/update" => {
                        if let Some(u) = params.get("update") {
                            for e in m.update(u) {
                                out.event(e).await;
                            }
                        }
                    }
                    Incoming::Notification { .. } => {}
                    Incoming::Request { id, method, params } if method == "session/request_permission" => {
                        approvals += 1;
                        let ours = format!("approval-{approvals}");
                        if let Some(call) = params.get("toolCall") {
                            for e in m.update(&{
                                let mut c = call.clone();
                                c["sessionUpdate"] = Value::from("tool_call_update");
                                c
                            }) {
                                out.event(e).await;
                            }
                        }
                        let card = m.permission(&ours, &params);
                        open.insert(ours, id);
                        out.event(card).await;
                        out.event(Event::Status { state: SessionState::WaitingForApproval }).await;
                    }
                    Incoming::Request { id, .. } => {
                        // fs/*, terminal/*, elicitation/*: not declared, not
                        // served. This host neither reads nor writes for a
                        // harness.
                        peer.refuse(&id, -32601, "not offered by this client").await;
                    }
                }
            }
            // cancel-safe: `JoinSet::join_next` (documented cancel-safe);
            // reaps a finished request, whose answer came on `turn_rx`.
            Some(_) = requests.join_next() => {}
            // cancel-safe: `mpsc::Receiver::recv`.
            r = turn_rx.recv() => {
                let Some(r) = r else { continue };
                running = false;
                let id = m.assistant_id(None);
                out.event(Event::Message { id, role: Role::Assistant, text: String::new(), append: true, done: true }).await;
                match r {
                    Ok(v) => {
                        if v.get("stopReason").and_then(Value::as_str) == Some("refusal") {
                            out.event(Event::Error { text: "The model refused this turn".into() }).await;
                        }
                    }
                    Err(e) => { out.event(Event::Error { text: format!("The turn failed: {e}") }).await; }
                }
                for (id, rpc) in open.drain() {
                    peer.respond(&rpc, json!({ "outcome": { "outcome": "cancelled" } })).await;
                    out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Withdrawn }).await;
                }
                out.event(Event::Status { state: SessionState::Idle }).await;
            }
        }
    }
    out.ended("The harness stopped").await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_map_onto_the_model() {
        let mut m = Mapper {
            turn: 1,
            ..Mapper::default()
        };
        let e = m.update(&json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "Hi"}
        }));
        assert_eq!(
            e,
            [Event::Message {
                id: "assistant-1".into(),
                role: Role::Assistant,
                text: "Hi".into(),
                append: true,
                done: false
            }]
        );
        let e = m.update(&json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "t1",
            "title": "Edit main.rs",
            "kind": "edit",
            "status": "pending",
            "rawInput": {"path": "src/main.rs"}
        }));
        assert_eq!(
            e,
            [Event::ToolCall {
                id: "t1".into(),
                title: "Edit main.rs".into(),
                kind: ToolKind::Edit,
                status: ToolStatus::Pending,
                input: "src/main.rs".into()
            }]
        );
        // An update naming only the status keeps the title, and its diff
        // content becomes a diff event.
        let e = m.update(&json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "t1",
            "status": "completed",
            "content": [{"type": "diff", "path": "src/main.rs", "oldText": "a\n", "newText": "b\n"}]
        }));
        assert!(
            matches!(&e[0], Event::ToolCall { title, status: ToolStatus::Done, .. } if title == "Edit main.rs")
        );
        assert!(matches!(&e[1], Event::Diff { unified, .. } if unified.contains("-a\n+b\n")));
        let e = m.update(&json!({
            "sessionUpdate": "plan",
            "entries": [{"content": "Write it", "priority": "high", "status": "in_progress"}]
        }));
        assert_eq!(
            e,
            [Event::Plan {
                entries: vec![PlanEntry {
                    text: "Write it".into(),
                    status: PlanStatus::InProgress
                }]
            }]
        );
    }

    #[test]
    fn a_permission_request_becomes_a_card_with_the_harness_s_own_options() {
        let mut m = Mapper::default();
        let card = m.permission(
            "approval-1",
            &json!({
                "sessionId": "s",
                "toolCall": {"toolCallId": "t9", "title": "Run ls", "rawInput": {"command": "ls -la"}},
                "options": [
                    {"optionId": "ok", "name": "Allow", "kind": "allow_once"},
                    {"optionId": "ok-all", "name": "Always", "kind": "allow_always"},
                    {"optionId": "no", "name": "Reject", "kind": "reject_once"}
                ]
            }),
        );
        let Event::ApprovalRequest {
            id,
            title,
            detail,
            options,
        } = card
        else {
            panic!()
        };
        assert_eq!(
            (id.as_str(), title.as_str(), detail.as_str()),
            ("approval-1", "Run ls", "ls -la")
        );
        assert_eq!(
            options.iter().map(|o| o.kind).collect::<Vec<_>>(),
            [
                OptionKind::AllowOnce,
                OptionKind::AllowAlways,
                OptionKind::Deny
            ]
        );
    }
}
