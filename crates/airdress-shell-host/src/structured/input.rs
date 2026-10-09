//! The session's side of the structured tier: what a client's `structured`
//! message does, what an adapter's event does, and what a device that
//! attaches is shown.
//!
//! **Who may send** (design §9.3): only the typist. An `approval_answer`
//! reaches an adapter only when it names an approval that is open and an
//! option that approval offered, and only from the typist's client, where
//! only a human's tap or key makes one (D-31). Nothing here makes one.

use std::time::Instant;

use airdress_shell_proto::inner::Message;
use airdress_shell_proto::structured::{ApprovalOutcome, Body, Event, Input, SessionState};
use uuid::Uuid;

use super::transcript::fit;
use super::{Adapter, AdapterOut};
use crate::session::{Send, Session};

fn error(code: &str, message: &str) -> Message {
    Message::Error {
        code: code.into(),
        message: message.into(),
    }
}

/// A client's `structured` message. Returns the replies to that client,
/// and events for the whole session (an approval a human just answered).
pub fn from_client(
    s: &mut Session,
    device: Uuid,
    body: &serde_json::Value,
) -> (Vec<Message>, Vec<Event>) {
    from_client_inner(s, device, body)
}

fn from_client_inner(
    s: &mut Session,
    device: Uuid,
    body: &serde_json::Value,
) -> (Vec<Message>, Vec<Event>) {
    let only = |m: Message| (vec![m], Vec::new());
    let Some(side) = s.structured.as_ref() else {
        return only(error(
            "shell_structured_unavailable",
            "This host offers no structured view of this profile",
        ));
    };
    let input = match Body::from_value(body) {
        Ok(Body::Input(i)) => i,
        Ok(Body::Event(_)) | Err(_) => {
            return only(error(
                "shell_message_malformed",
                "A client sends structured inputs, not events",
            ))
        }
    };
    if !s.is_typist(device) {
        return only(error(
            "shell_input_not_held",
            "Input is on another device; take input first",
        ));
    }
    if let Input::ApprovalAnswer { id, option } = &input {
        if !side.transcript.approval_offers(id, option) {
            return only(error(
                "shell_approval_closed",
                "That question is no longer open",
            ));
        }
    }
    if let Input::Prompt { attachments, .. } = &input {
        if !attachments.is_empty() {
            return only(error(
                "shell_message_malformed",
                "Attachments are not offered in this version",
            ));
        }
    }
    s.last_input = Some(Instant::now());
    if side.adapter == Adapter::TerminalHooks {
        return plugin_input(s, input);
    }
    match side.handle.as_ref().map(|h| h.inputs.try_send(input)) {
        Some(Ok(())) => (Vec::new(), Vec::new()),
        Some(Err(tokio::sync::mpsc::error::TrySendError::Full(_))) => only(error(
            "shell_structured_busy",
            "The harness is not taking input yet; send it again in a moment",
        )),
        _ => only(error(
            "shell_structured_unavailable",
            "The structured view of this session has ended; its terminal is still there",
        )),
    }
}

/// For a harness driven through its own terminal (design §9.4): a prompt is
/// pasted and entered as a person would, a cancel is Esc, and an answer to
/// a permission goes back to the hook that is waiting for it.
fn plugin_input(s: &mut Session, input: Input) -> (Vec<Message>, Vec<Event>) {
    let none = (Vec::new(), Vec::new());
    match input {
        Input::Prompt { text, .. } => {
            if s.pty.is_none() {
                return (
                    vec![error(
                        "shell_structured_unavailable",
                        "The program has exited",
                    )],
                    Vec::new(),
                );
            }
            let mut bytes = b"\x1b[200~".to_vec();
            bytes.extend_from_slice(text.replace('\x1b', "").as_bytes());
            bytes.extend_from_slice(b"\x1b[201~\r");
            s.type_in(bytes, Instant::now());
            none
        }
        Input::Cancel => {
            s.type_in(vec![0x1b], Instant::now());
            none
        }
        Input::ApprovalAnswer { id, option } => {
            // The checks above found `id` open and offering `option`: this
            // is the human's tap, handed to the hook that waits for it.
            let waiting = s
                .structured
                .as_mut()
                .and_then(|side| side.waiting.remove(&id));
            let delivered = waiting
                .is_some_and(|hook| hook.send(serde_json::json!({ "decision": option })).is_ok());
            match delivered {
                true => (
                    Vec::new(),
                    vec![
                        Event::ApprovalResolved {
                            id,
                            outcome: ApprovalOutcome::Answered,
                        },
                        Event::Status {
                            state: SessionState::Working,
                        },
                    ],
                ),
                false => (
                    vec![error(
                        "shell_approval_closed",
                        "That question is no longer open; answer it in the terminal",
                    )],
                    vec![Event::ApprovalResolved {
                        id,
                        outcome: ApprovalOutcome::Withdrawn,
                    }],
                ),
            }
        }
    }
}

fn wrap(e: Event, budget: usize) -> impl Iterator<Item = Message> {
    fit(e, budget)
        .into_iter()
        .map(|e| Message::Structured { body: e.to_value() })
}

/// An adapter's output. Returns what every attached client is sent, and the
/// attention to report (already filtered by the profile's `notify`).
pub fn from_adapter(
    s: &mut Session,
    out: AdapterOut,
    budget: usize,
) -> (Vec<Send>, Option<&'static str>) {
    let Some(side) = s.structured.as_mut() else {
        return (Vec::new(), None);
    };
    let events = match out {
        AdapterOut::Event(e) => vec![e],
        AdapterOut::Ended(why) => {
            side.handle = None;
            let mut v = side.transcript.withdraw_all();
            v.push(Event::Error { text: why });
            v.push(Event::Status {
                state: SessionState::Ended,
            });
            v
        }
    };
    let mut msgs = Vec::new();
    let mut attention = None;
    let mut state = None;
    for e in events {
        let applied = side.transcript.apply(e);
        attention = applied.attention.or(attention);
        state = applied.state.or(state);
        for b in applied.broadcast {
            msgs.extend(wrap(b, budget));
        }
    }
    if let Some(w) = state {
        s.state = w;
    }
    let mut sends = Vec::new();
    for m in msgs {
        sends.extend(s.broadcast(&m));
    }
    (sends, attention.filter(|_| s.profile.notify))
}

/// What a device that (re)attaches is shown of the structured tier.
pub fn replay(s: &Session, leg: Uuid, budget: usize) -> Vec<Send> {
    let Some(side) = s.structured.as_ref() else {
        return Vec::new();
    };
    side.transcript
        .replay()
        .into_iter()
        .flat_map(|e| wrap(e, budget))
        .map(|msg| Send { leg, msg })
        .collect()
}
