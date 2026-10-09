//! The Codex app-server adapter: JSON-RPC over the profile's own stdio
//! (design §9.1).
//!
//! Verified against `codex-cli 0.160.1`: the JSON Schema it generates
//! (`codex app-server generate-json-schema`, `ServerNotification.json`,
//! `ServerRequest.json`, `codex_app_server_protocol.v2.schemas.json`), its
//! source (`codex-rs/app-server/src/rpc.rs`: one JSON object per line and
//! no `"jsonrpc"` member) and a live `initialize` / `thread/start` against
//! an empty home with no account. The whole `app-server` command is marked
//! experimental by its authors.
//!
//! - `initialize {clientInfo}`, then the `initialized` notification;
//! - `thread/start {cwd}` → `thread.id` (no approval policy, sandbox or
//!   model of ours: those are the person's own Codex settings, FR-T5);
//! - `turn/start {threadId, input: [{type: "text", text}]}` → `turn.id`;
//!   `turn/interrupt {threadId, turnId}`;
//! - notifications `item/started`, `item/completed`,
//!   `item/agentMessage/delta`, `item/reasoning/summaryTextDelta`,
//!   `turn/plan/updated`, `turn/completed`, `error`,
//!   `serverRequest/resolved`;
//! - requests `item/commandExecution/requestApproval` and
//!   `item/fileChange/requestApproval`, answered `{decision: "accept" |
//!   "acceptForSession" | "decline" | "cancel"}` — by the human's tap only.

use std::collections::HashMap;
use std::path::PathBuf;

use airdress_shell_proto::structured::{
    ApprovalOption, ApprovalOutcome, Event, Input, OptionKind, PlanEntry, PlanStatus, Role,
    SessionState, ToolKind, ToolStatus,
};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::jsonrpc::{Incoming, Peer};
use super::{summarize, Out};
use crate::log_err::LogErr as _;
use crate::pty::Stdio;

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// Map an item's status.
pub fn item_status(s: Option<&str>) -> ToolStatus {
    match s {
        Some("completed") => ToolStatus::Done,
        Some("failed" | "declined") => ToolStatus::Failed,
        _ => ToolStatus::Running,
    }
}

/// The options every Codex approval offers, in its own words' order.
pub fn decisions() -> Vec<ApprovalOption> {
    vec![
        ApprovalOption {
            id: "accept".into(),
            label: "Allow once".into(),
            kind: OptionKind::AllowOnce,
        },
        ApprovalOption {
            id: "acceptForSession".into(),
            label: "Allow for this session".into(),
            kind: OptionKind::AllowAlways,
        },
        ApprovalOption {
            id: "decline".into(),
            label: "Decline".into(),
            kind: OptionKind::Deny,
        },
        ApprovalOption {
            id: "cancel".into(),
            label: "Decline and stop the turn".into(),
            kind: OptionKind::Deny,
        },
    ]
}

/// The adapter's state, apart from its connection.
#[derive(Debug, Default)]
pub struct Mapper {
    /// Paths a file-change item touches, for its approval card.
    paths: HashMap<String, Vec<String>>,
}

impl Mapper {
    /// An item from `item/started` or `item/completed`.
    pub fn item(&mut self, item: &Value, completed: bool) -> Vec<Event> {
        let Some(id) = s(item, "id") else {
            return Vec::new();
        };
        let id = id.to_owned();
        match s(item, "type").unwrap_or("") {
            "agentMessage" => {
                let text = s(item, "text").unwrap_or("").to_owned();
                if !completed && text.is_empty() {
                    return Vec::new();
                }
                vec![Event::Message {
                    id,
                    role: Role::Assistant,
                    text,
                    append: false,
                    done: completed,
                }]
            }
            "reasoning" if completed => {
                let parts: Vec<&str> = item
                    .get("summary")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if parts.is_empty() {
                    return Vec::new();
                }
                vec![Event::Thought {
                    id,
                    text: parts.join("\n\n"),
                    append: false,
                }]
            }
            "commandExecution" => {
                let command = s(item, "command").unwrap_or("").to_owned();
                let status = item_status(s(item, "status"));
                let mut out = vec![Event::ToolCall {
                    id: id.clone(),
                    title: summarize(&Value::from(command.clone())),
                    kind: ToolKind::Execute,
                    status,
                    input: command,
                }];
                if completed {
                    if let Some(text) = s(item, "aggregatedOutput") {
                        out.push(Event::ToolResult {
                            id,
                            text: text.to_owned(),
                            exit_code: item
                                .get("exitCode")
                                .and_then(Value::as_i64)
                                .and_then(|c| i32::try_from(c).ok()),
                            truncated: false,
                        });
                    }
                }
                out
            }
            "fileChange" => {
                let changes = item
                    .get("changes")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let paths: Vec<String> = changes
                    .iter()
                    .filter_map(|c| s(c, "path").map(str::to_owned))
                    .collect();
                self.paths.insert(id.clone(), paths.clone());
                let mut out = vec![Event::ToolCall {
                    id: id.clone(),
                    title: match paths.as_slice() {
                        [one] => format!("Edit {one}"),
                        many => format!("Edit {} files", many.len()),
                    },
                    kind: ToolKind::Edit,
                    status: item_status(s(item, "status")),
                    input: paths.join(" "),
                }];
                for c in &changes {
                    let path = s(c, "path").unwrap_or("").to_owned();
                    let diff = s(c, "diff").unwrap_or("");
                    let unified = if diff.starts_with("--- ") {
                        diff.to_owned()
                    } else {
                        format!("--- a/{path}\n+++ b/{path}\n{diff}")
                    };
                    out.push(Event::Diff {
                        tool_call_id: id.clone(),
                        path,
                        unified,
                        truncated: false,
                    });
                }
                out
            }
            "mcpToolCall" | "dynamicToolCall" => {
                let tool = s(item, "tool").unwrap_or("tool");
                let title = match s(item, "server") {
                    Some(server) => format!("{server}: {tool}"),
                    None => tool.to_owned(),
                };
                vec![Event::ToolCall {
                    id,
                    title,
                    kind: ToolKind::Other,
                    status: item_status(s(item, "status")),
                    input: item.get("arguments").map(summarize).unwrap_or_default(),
                }]
            }
            "webSearch" => vec![Event::ToolCall {
                id,
                title: "Web search".into(),
                kind: ToolKind::Search,
                status: if completed {
                    ToolStatus::Done
                } else {
                    ToolStatus::Running
                },
                input: s(item, "query").unwrap_or("").to_owned(),
            }],
            _ => Vec::new(),
        }
    }

    /// A server request asking for approval, as the card.
    pub fn approval(&self, ours: &str, method: &str, p: &Value) -> Event {
        let (title, detail) = if method == "item/commandExecution/requestApproval" {
            (
                "Run this command?".to_owned(),
                s(p, "command")
                    .map(str::to_owned)
                    .or_else(|| s(p, "reason").map(str::to_owned))
                    .unwrap_or_default(),
            )
        } else {
            let paths = s(p, "itemId")
                .and_then(|i| self.paths.get(i))
                .map(|p| p.join("\n"))
                .unwrap_or_default();
            (
                "Apply these changes?".to_owned(),
                match (paths.is_empty(), s(p, "reason")) {
                    (false, _) => paths,
                    (true, Some(r)) => r.to_owned(),
                    (true, None) => String::new(),
                },
            )
        };
        Event::ApprovalRequest {
            id: ours.to_owned(),
            title,
            detail,
            options: decisions(),
        }
    }
}

/// Run the adapter until the harness goes away.
pub async fn run(stdio: Stdio, cwd: PathBuf, mut inputs: mpsc::Receiver<Input>, out: Out) {
    let (peer, mut incoming) = Peer::start(stdio, false);
    if let Err(e) = peer
        .request(
            "initialize",
            json!({ "clientInfo": {
                "name": "airdress_shell_host",
                "title": "Airdress shell host",
                "version": env!("CARGO_PKG_VERSION")
            }}),
        )
        .await
    {
        return out
            .ended(format!("The harness did not start its protocol: {e}"))
            .await;
    }
    peer.notify("initialized", Value::Null).await;
    let thread = match peer
        .request("thread/start", json!({ "cwd": cwd.to_string_lossy() }))
        .await
    {
        Ok(v) => match v.get("thread").and_then(|t| s(t, "id")) {
            Some(t) => t.to_owned(),
            None => return out.ended("The harness started no thread").await,
        },
        Err(e) => {
            return out
                .ended(format!("The harness started no thread: {e}"))
                .await
        }
    };
    let mut m = Mapper::default();
    let mut turn: Option<String> = None;
    let mut prompts = 0u64;
    let mut approvals = 0u64;
    // Our approval id → the harness's request id, until a human answers.
    let mut open: HashMap<String, Value> = HashMap::new();
    // The turn requests in flight, owned by this adapter (R-ASY-1), and
    // their answers. One turn runs at a time, so the bound is never met in
    // practice; a request waits for room past it (R-ASY-5).
    let mut requests = tokio::task::JoinSet::new();
    let (started_tx, mut started_rx) = mpsc::channel::<Result<Value, String>>(super::TURN_RESULTS);
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
                        if turn.is_some() {
                            out.event(Event::Error { text: "A turn is running; wait for it or cancel it".into() }).await;
                            continue;
                        }
                        prompts += 1;
                        turn = Some(String::new());
                        out.event(Event::Message {
                            id: format!("user-{prompts}"),
                            role: Role::User,
                            text: text.clone(),
                            append: false,
                            done: true,
                        }).await;
                        out.event(Event::Status { state: SessionState::Working }).await;
                        let p = peer.clone();
                        let tx = started_tx.clone();
                        let thread = thread.clone();
                        requests.spawn(async move {
                            let r = p.request("turn/start", json!({
                                "threadId": thread,
                                "input": [{ "type": "text", "text": text }]
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
                            peer.respond(&rpc, json!({ "decision": option })).await;
                            out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Answered }).await;
                            if turn.is_some() {
                                out.event(Event::Status { state: SessionState::Working }).await;
                            }
                        }
                    }
                    Input::Cancel => {
                        if let Some(t) = turn.clone().filter(|t| !t.is_empty()) {
                            let p = peer.clone();
                            let thread = thread.clone();
                            requests.spawn(async move {
                                if let Err(e) = p.request("turn/interrupt", json!({ "threadId": thread, "turnId": t })).await {
                                    tracing::warn!(error = %e, "interrupting the turn");
                                }
                            });
                        }
                    }
                }
            }
            // cancel-safe: `JoinSet::join_next` (documented cancel-safe);
            // reaps a finished request, whose answer came on `started_rx`.
            Some(_) = requests.join_next() => {}
            // cancel-safe: `mpsc::Receiver::recv`.
            r = started_rx.recv() => {
                match r {
                    Some(Ok(v)) => {
                        if let Some(id) = v.get("turn").and_then(|t| s(t, "id")) {
                            if turn.as_deref() == Some("") {
                                turn = Some(id.to_owned());
                            }
                        }
                    }
                    Some(Err(e)) => {
                        turn = None;
                        out.event(Event::Error { text: format!("The turn did not start: {e}") }).await;
                        out.event(Event::Status { state: SessionState::Idle }).await;
                    }
                    None => {}
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`; the peer's reader owns the
            // partial line.
            msg = incoming.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    Incoming::Notification { method, params } => match method.as_str() {
                        "item/started" | "item/completed" => {
                            if let Some(item) = params.get("item") {
                                for e in m.item(item, method == "item/completed") {
                                    out.event(e).await;
                                }
                            }
                        }
                        "item/agentMessage/delta" => {
                            if let (Some(id), Some(d)) = (s(&params, "itemId"), s(&params, "delta")) {
                                out.event(Event::Message { id: id.to_owned(), role: Role::Assistant, text: d.to_owned(), append: true, done: false }).await;
                            }
                        }
                        "item/reasoning/summaryTextDelta" => {
                            if let (Some(id), Some(d)) = (s(&params, "itemId"), s(&params, "delta")) {
                                out.event(Event::Thought { id: id.to_owned(), text: d.to_owned(), append: true }).await;
                            }
                        }
                        "turn/plan/updated" => {
                            let entries = params.get("plan").and_then(Value::as_array).map(|a| a.iter().map(|e| PlanEntry {
                                text: s(e, "step").unwrap_or("").to_owned(),
                                status: match s(e, "status") {
                                    Some("completed") => PlanStatus::Completed,
                                    Some("inProgress") => PlanStatus::InProgress,
                                    _ => PlanStatus::Pending,
                                },
                            }).collect()).unwrap_or_default();
                            out.event(Event::Plan { entries }).await;
                        }
                        "turn/started" => {
                            if let Some(id) = params.get("turn").and_then(|t| s(t, "id")) {
                                turn = Some(id.to_owned());
                            }
                        }
                        "turn/completed" => {
                            turn = None;
                            let t = params.get("turn").cloned().unwrap_or(Value::Null);
                            if s(&t, "status") == Some("failed") {
                                let why = t.get("error").and_then(|e| s(e, "message")).unwrap_or("The turn failed");
                                out.event(Event::Error { text: why.to_owned() }).await;
                            }
                            for (id, _) in open.drain() {
                                out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Withdrawn }).await;
                            }
                            out.event(Event::Status { state: SessionState::Idle }).await;
                        }
                        "error" => {
                            let will_retry = params.get("willRetry").and_then(Value::as_bool).unwrap_or(false);
                            if !will_retry {
                                if let Some(msg) = params.get("error").and_then(|e| s(e, "message")) {
                                    out.event(Event::Error { text: msg.to_owned() }).await;
                                }
                            }
                        }
                        "serverRequest/resolved" => {
                            // Answered or withdrawn by the harness itself
                            // (an interrupted turn): take the buttons away.
                            if let Some(rid) = params.get("requestId") {
                                let ours: Vec<String> = open.iter().filter(|(_, r)| *r == rid).map(|(k, _)| k.clone()).collect();
                                for id in ours {
                                    open.remove(&id);
                                    out.event(Event::ApprovalResolved { id, outcome: ApprovalOutcome::Withdrawn }).await;
                                }
                            }
                        }
                        _ => {}
                    },
                    Incoming::Request { id, method, params } => match method.as_str() {
                        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                            approvals += 1;
                            let ours = format!("approval-{approvals}");
                            let card = m.approval(&ours, &method, &params);
                            open.insert(ours, id);
                            out.event(card).await;
                            out.event(Event::Status { state: SessionState::WaitingForApproval }).await;
                        }
                        _ => {
                            // Questions and permission kinds this view does
                            // not show are refused, never answered for the
                            // person.
                            peer.refuse(&id, -32601, "not offered by this client").await;
                            out.event(Event::Error { text: "The harness asked something this view cannot show; use a terminal profile for it".into() }).await;
                        }
                    },
                }
            }
        }
    }
    out.ended("The harness stopped").await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_map_onto_the_model() {
        let mut m = Mapper::default();
        let e = m.item(
            &json!({"type": "commandExecution", "id": "i1", "command": "cargo test", "cwd": "/w",
                    "status": "completed", "aggregatedOutput": "ok", "exitCode": 0, "commandActions": []}),
            true,
        );
        assert_eq!(
            e,
            [
                Event::ToolCall {
                    id: "i1".into(),
                    title: "cargo test".into(),
                    kind: ToolKind::Execute,
                    status: ToolStatus::Done,
                    input: "cargo test".into()
                },
                Event::ToolResult {
                    id: "i1".into(),
                    text: "ok".into(),
                    exit_code: Some(0),
                    truncated: false
                }
            ]
        );
        let e = m.item(
            &json!({"type": "fileChange", "id": "i2", "status": "inProgress",
                    "changes": [{"path": "a.rs", "kind": {"type": "update"}, "diff": "@@ -1 +1 @@\n-a\n+b\n"}]}),
            false,
        );
        assert!(
            matches!(&e[0], Event::ToolCall { title, kind: ToolKind::Edit, .. } if title == "Edit a.rs")
        );
        assert!(
            matches!(&e[1], Event::Diff { unified, .. } if unified.starts_with("--- a/a.rs\n+++ b/a.rs\n@@"))
        );
        let card = m.approval(
            "approval-1",
            "item/fileChange/requestApproval",
            &json!({"threadId": "t", "turnId": "u", "itemId": "i2", "startedAtMs": 1}),
        );
        assert!(
            matches!(card, Event::ApprovalRequest { ref detail, ref options, .. }
            if detail == "a.rs" && options.len() == 4)
        );
    }

    #[test]
    fn the_decisions_are_the_schema_s_words() {
        let ids: Vec<String> = decisions().into_iter().map(|o| o.id).collect();
        assert_eq!(ids, ["accept", "acceptForSession", "decline", "cancel"]);
    }
}
