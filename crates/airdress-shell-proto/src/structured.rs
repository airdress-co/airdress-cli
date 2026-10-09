//! The structured tier's neutral event model, `airdress.shell.structured.v1`
//! (design §9.3, FR-T3).
//!
//! Every structured adapter on the host maps its harness's own protocol into
//! these events, and every client renders only them. They travel as the body
//! of an inner [`Message::Structured`](crate::inner::Message::Structured),
//! inside the end-to-end channel, so the operator never sees one.
//!
//! A body is a JSON object with exactly one discriminator:
//!
//! - `event` for host → client (`status`, `message`, `thought`, `tool_call`,
//!   `tool_result`, `diff`, `plan`, `approval_request`, `approval_resolved`,
//!   `error`);
//! - `input` for client → host (`prompt`, `approval_answer`, `cancel`).
//!
//! **Items are replaced by id.** `message`, `thought`, `tool_call` and
//! `approval_request` carry an `id`; a client keeps one entry per id, in the
//! order it first saw them, and replaces (or, with `append`, extends) it. A
//! client that attaches mid-session is sent the current state of every item,
//! so replay and live updates are the same thing.
//!
//! **Only a human answers.** No code path of the host or a client produces
//! an [`Input::ApprovalAnswer`] except a human's tap or key on the typist's
//! client (D-31, FR-T4).
//!
//! **Readers ignore unknown fields; writers emit exactly this schema.** A
//! newer host may add a field to an event, and an older client renders what
//! it knows (see the crate's "Wire compatibility"). A new field is `Option`
//! or `#[serde(default)]`, never required. The schema keeps
//! `additionalProperties: false`: it states what a v1 writer emits, not what
//! a reader refuses. An unknown `event` or `input` value, or an unknown
//! enum value, is still malformed: a reader cannot render what it cannot
//! name, and an input it does not understand must not be half-obeyed.
//!
//! The JSON Schema is [`SCHEMA_JSON`] (`schema/structured.v1.json`, shipped
//! with the crate), and `tests/vectors/structured.json` holds the vectors
//! every client decodes.

use serde::{Deserialize, Serialize};

use crate::error::{ProtoError, Result};

/// The schema id.
pub const SCHEMA_ID: &str = "airdress.shell.structured.v1";

/// The JSON Schema of every body (draft 2020-12).
pub const SCHEMA_JSON: &str = include_str!("../schema/structured.v1.json");

/// A tool result's text is cut at this many bytes.
pub const TOOL_RESULT_MAX: usize = 16 * 1024;

/// A diff is cut at this many bytes.
pub const DIFF_MAX: usize = 256 * 1024;

/// What the session is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Waiting for a prompt; the last turn, if any, is over.
    Idle,
    /// A turn is running.
    Working,
    /// The harness asked the human a question.
    WaitingForInput,
    /// The harness asked the human to approve something.
    WaitingForApproval,
    /// The harness is gone.
    Ended,
}

/// Who wrote a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The human.
    User,
    /// The harness's model.
    Assistant,
}

/// What a tool does, coarsely, for an icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    /// Reads files.
    Read,
    /// Changes files.
    Edit,
    /// Runs a command.
    Execute,
    /// Searches.
    Search,
    /// Fetches from the network.
    Fetch,
    /// Anything else.
    Other,
}

/// Where a tool call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Announced, not started (often: waiting for an approval).
    Pending,
    /// Running.
    Running,
    /// Finished.
    Done,
    /// Failed or was refused.
    Failed,
}

/// Where a plan entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// Not started.
    Pending,
    /// Being worked on.
    InProgress,
    /// Done.
    Completed,
}

/// One entry of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanEntry {
    /// What the step is.
    pub text: String,
    /// Where it is.
    pub status: PlanStatus,
}

/// What an approval option does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    /// Allow this once.
    AllowOnce,
    /// Allow this and its like from now on (the harness's own rule).
    AllowAlways,
    /// Refuse.
    Deny,
}

/// One button of an approval card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalOption {
    /// The id the answer names.
    pub id: String,
    /// The button's words.
    pub label: String,
    /// What it does.
    pub kind: OptionKind,
}

/// How an approval ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// A human answered it (on any client, or at the desk).
    Answered,
    /// The harness withdrew it, the turn was cancelled, or it timed out and
    /// the harness's own prompt stands.
    Withdrawn,
}

/// host → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The session's state; drives the status chip and attention.
    Status {
        /// The state.
        state: SessionState,
    },
    /// A message, whole or in part.
    Message {
        /// The item id.
        id: String,
        /// Who wrote it.
        role: Role,
        /// The text: the whole message, or with `append` the next part.
        text: String,
        /// `text` extends the message rather than replacing it.
        #[serde(default, skip_serializing_if = "is_false")]
        append: bool,
        /// The message is complete.
        #[serde(rename = "final", default, skip_serializing_if = "is_false")]
        done: bool,
    },
    /// The model's reasoning, shown collapsed.
    Thought {
        /// The item id.
        id: String,
        /// The text, whole or with `append` the next part.
        text: String,
        /// `text` extends the thought.
        #[serde(default, skip_serializing_if = "is_false")]
        append: bool,
    },
    /// A tool call, announced or updated.
    ToolCall {
        /// The item id.
        id: String,
        /// One line saying what it does.
        title: String,
        /// What kind of tool.
        kind: ToolKind,
        /// Where it is.
        status: ToolStatus,
        /// A summary of its input.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        input: String,
    },
    /// What a tool call returned.
    #[serde(rename_all = "camelCase")]
    ToolResult {
        /// The tool call's id.
        id: String,
        /// Its output, cut at [`TOOL_RESULT_MAX`].
        text: String,
        /// The exit code, for a command.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// `text` was cut.
        #[serde(default, skip_serializing_if = "is_false")]
        truncated: bool,
    },
    /// A change to one file.
    #[serde(rename_all = "camelCase")]
    Diff {
        /// The tool call that made it (may be empty for a turn-level diff).
        tool_call_id: String,
        /// The file, relative to the session's directory where possible.
        path: String,
        /// A unified diff, cut at [`DIFF_MAX`].
        unified: String,
        /// `unified` was cut.
        #[serde(default, skip_serializing_if = "is_false")]
        truncated: bool,
    },
    /// The harness's plan; replaces the previous one.
    Plan {
        /// The steps.
        entries: Vec<PlanEntry>,
    },
    /// The harness asks the human to decide. Answered only by a human tap.
    ApprovalRequest {
        /// The id the answer names.
        id: String,
        /// One line.
        title: String,
        /// What exactly would happen (a command, a path).
        detail: String,
        /// The buttons, in the harness's order.
        options: Vec<ApprovalOption>,
    },
    /// An approval is no longer open; clients take its buttons away.
    ApprovalResolved {
        /// The approval.
        id: String,
        /// How it ended.
        outcome: ApprovalOutcome,
    },
    /// Something went wrong in the harness or the adapter.
    Error {
        /// Words for the human.
        text: String,
    },
}

/// client → host. Only from the typist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "input", rename_all = "snake_case")]
pub enum Input {
    /// A prompt, typed or dictated, sent by a tap.
    Prompt {
        /// The text.
        text: String,
        /// Always empty in v1.
        #[serde(default)]
        attachments: Vec<serde_json::Value>,
    },
    /// The human's answer to an approval. Produced only by a human's tap or
    /// key (D-31).
    ApprovalAnswer {
        /// The approval.
        id: String,
        /// The option chosen.
        option: String,
    },
    /// Stop the current turn.
    Cancel,
}

/// One body, either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// host → client.
    Event(Event),
    /// client → host.
    Input(Input),
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Body {
    /// Read a body from its JSON.
    ///
    /// # Errors
    /// [`ProtoError::InnerMalformed`] for anything that is not exactly one
    /// event or one input of this schema.
    pub fn from_value(v: &serde_json::Value) -> Result<Self> {
        let o = v
            .as_object()
            .ok_or(ProtoError::InnerMalformed("structured body"))?;
        // `event` decides first: a `tool_call` has an `input` field of its
        // own, and on any other event a stray `input` is an unknown field,
        // ignored. A host never acts on an event from a client, so reading
        // such a body as an event cannot turn it into an input.
        if o.contains_key("event") {
            serde_json::from_value(v.clone())
                .map(Body::Event)
                .map_err(|_| ProtoError::InnerMalformed("structured event"))
        } else if o.contains_key("input") {
            serde_json::from_value(v.clone())
                .map(Body::Input)
                .map_err(|_| ProtoError::InnerMalformed("structured input"))
        } else {
            Err(ProtoError::InnerMalformed("structured body"))
        }
    }

    /// Its JSON.
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            Body::Event(e) => e.to_value(),
            Body::Input(i) => serde_json::to_value(i).expect("an input serializes"),
        }
    }
}

impl Event {
    /// Its JSON.
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("an event serializes")
    }

    /// The attention this event raises when it is the session's new state
    /// (design §9.3 "Notifications"): `needs_you` on a question or an
    /// approval, `done` on `idle` after `working`.
    #[must_use]
    pub fn attention(&self, previous: Option<SessionState>) -> Option<&'static str> {
        match self {
            Event::Status { state } => match (previous, state) {
                (Some(p), s) if p == *s => None,
                (_, SessionState::WaitingForApproval | SessionState::WaitingForInput) => {
                    Some("needs_you")
                }
                (Some(SessionState::Working), SessionState::Idle) => Some("done"),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Cut `s` to at most `max` bytes on a character boundary. Returns whether
/// it cut.
pub fn truncate_utf8(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bodies_round_trip_and_tell_events_from_inputs() {
        let e = json!({"event": "message", "id": "m1", "role": "assistant", "text": "hi", "append": true});
        let b = Body::from_value(&e).unwrap();
        assert!(matches!(
            b,
            Body::Event(Event::Message {
                append: true,
                done: false,
                ..
            })
        ));
        assert_eq!(b.to_value(), e);
        let i = json!({"input": "approval_answer", "id": "a1", "option": "allow"});
        assert!(matches!(
            Body::from_value(&i).unwrap(),
            Body::Input(Input::ApprovalAnswer { .. })
        ));
        let c = json!({"input": "cancel"});
        assert_eq!(Body::from_value(&c).unwrap().to_value(), c);
    }

    #[test]
    fn anything_else_is_malformed() {
        for v in [
            json!([]),
            json!({}),
            json!({"event": "status", "state": "sleeping"}),
            json!({"event": "teleport"}),
            json!({"input": "auto_approve"}),
            json!({"input": "approval_answer", "id": "a"}),
        ] {
            assert!(Body::from_value(&v).is_err(), "{v}");
        }
    }

    /// An older reader ignores a field a newer writer added, at the top and
    /// nested, and what it re-emits is the v1 body without it.
    #[test]
    fn an_older_reader_ignores_a_newer_field() {
        let newer = json!({"event": "status", "state": "idle", "since": 12});
        assert_eq!(
            Body::from_value(&newer).unwrap().to_value(),
            json!({"event": "status", "state": "idle"})
        );
        let nested = json!({"event": "approval_request", "id": "a", "title": "t",
            "detail": "d", "options": [{"id": "x", "label": "X", "kind": "deny", "hotkey": "n"}]});
        assert!(matches!(
            Body::from_value(&nested).unwrap(),
            Body::Event(Event::ApprovalRequest { .. })
        ));
        let input = json!({"input": "prompt", "text": "go", "voice": true});
        assert_eq!(
            Body::from_value(&input).unwrap().to_value(),
            json!({"input": "prompt", "text": "go", "attachments": []})
        );
        // A stray `input` on an event is one more unknown field: the body is
        // still the event, never the input.
        let stray = json!({"event": "status", "input": "cancel", "state": "idle"});
        assert!(matches!(
            Body::from_value(&stray).unwrap(),
            Body::Event(Event::Status { .. })
        ));
    }

    #[test]
    fn attention_follows_the_design() {
        let st = |s| Event::Status { state: s };
        use SessionState::*;
        assert_eq!(
            st(WaitingForApproval).attention(Some(Working)),
            Some("needs_you")
        );
        assert_eq!(st(WaitingForInput).attention(None), Some("needs_you"));
        assert_eq!(st(Idle).attention(Some(Working)), Some("done"));
        assert_eq!(st(Idle).attention(Some(Idle)), None);
        assert_eq!(st(Idle).attention(None), None);
        assert_eq!(
            st(WaitingForApproval).attention(Some(WaitingForApproval)),
            None
        );
        assert_eq!(st(Working).attention(Some(Idle)), None);
    }

    #[test]
    fn truncation_keeps_characters_whole() {
        let mut s = "aä".repeat(10);
        assert!(truncate_utf8(&mut s, 4));
        assert_eq!(s, "aäa");
        let mut t = "short".to_owned();
        assert!(!truncate_utf8(&mut t, 10));
    }
}
