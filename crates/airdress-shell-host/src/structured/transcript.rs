//! A structured session's transcript: the current state of every item, in
//! the order the items first appeared, so a device that attaches later is
//! shown the conversation so far (design §9.3, "items are replaced by id").
//!
//! It also holds the session's status (for attention, D-20) and the
//! approvals still open (so an answer to anything else is refused).

use std::collections::{BTreeMap, VecDeque};

use airdress_shell_proto::structured::{
    truncate_utf8, ApprovalOutcome, Event, SessionState, DIFF_MAX, TOOL_RESULT_MAX,
};

/// The most items kept.
pub const MAX_ITEMS: usize = 400;
/// The most text kept across items.
pub const MAX_BYTES: usize = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Message(String),
    Thought(String),
    Tool(String),
    Result(String),
    Diff(String, String),
    Plan,
    Approval(String),
    Error(u64),
}

/// What applying one event did.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Applied {
    /// What every attached client is sent.
    pub broadcast: Vec<Event>,
    /// `needs_you` or `done`, when the status raised it.
    pub attention: Option<&'static str>,
    /// The session's new state word for the overview, when it changed.
    pub state: Option<&'static str>,
}

/// One session's transcript.
#[derive(Debug, Default)]
pub struct Transcript {
    order: VecDeque<Key>,
    items: BTreeMap<Key, Event>,
    status: Option<SessionState>,
    errors: u64,
    bytes: usize,
}

fn size(e: &Event) -> usize {
    match e {
        Event::Message { text, .. } | Event::Thought { text, .. } => text.len(),
        Event::ToolCall { title, input, .. } => title.len() + input.len(),
        Event::ToolResult { text, .. } => text.len(),
        Event::Diff { unified, .. } => unified.len(),
        Event::Plan { entries } => entries.iter().map(|e| e.text.len()).sum(),
        Event::ApprovalRequest { title, detail, .. } => title.len() + detail.len(),
        Event::Error { text } => text.len(),
        Event::Status { .. } | Event::ApprovalResolved { .. } => 0,
    }
}

/// Cut an event's long fields to the model's limits.
pub fn bound(mut e: Event) -> Event {
    match &mut e {
        Event::ToolResult {
            text, truncated, ..
        } => {
            *truncated |= truncate_utf8(text, TOOL_RESULT_MAX);
        }
        Event::Diff {
            unified, truncated, ..
        } => {
            *truncated |= truncate_utf8(unified, DIFF_MAX);
        }
        _ => {}
    }
    e
}

/// The overview's word for a state (design §10.1 state chips).
pub fn state_word(previous: Option<SessionState>, now: SessionState) -> &'static str {
    match now {
        SessionState::Working => "working",
        SessionState::WaitingForInput | SessionState::WaitingForApproval => "needs_you",
        SessionState::Idle if previous == Some(SessionState::Working) => "done",
        SessionState::Idle | SessionState::Ended => "idle",
    }
}

impl Transcript {
    /// Apply one event from the adapter.
    pub fn apply(&mut self, e: Event) -> Applied {
        let e = bound(e);
        let mut out = Applied::default();
        match &e {
            Event::Status { state } => {
                let prev = self.status;
                out.attention = e.attention(prev);
                if prev != Some(*state) {
                    out.state = Some(state_word(prev, *state));
                }
                self.status = Some(*state);
                // A status that did not change says nothing new.
                if prev != Some(*state) {
                    out.broadcast.push(e);
                }
                return out;
            }
            Event::ApprovalResolved { id, .. } => {
                let key = Key::Approval(id.clone());
                if self.items.contains_key(&key) {
                    self.remove(&key);
                    out.broadcast.push(e);
                }
                return out;
            }
            _ => {}
        }
        let key = match &e {
            Event::Message { id, .. } => Key::Message(id.clone()),
            Event::Thought { id, .. } => Key::Thought(id.clone()),
            Event::ToolCall { id, .. } => Key::Tool(id.clone()),
            Event::ToolResult { id, .. } => Key::Result(id.clone()),
            Event::Diff {
                tool_call_id, path, ..
            } => Key::Diff(tool_call_id.clone(), path.clone()),
            Event::Plan { .. } => Key::Plan,
            Event::ApprovalRequest { id, .. } => Key::Approval(id.clone()),
            Event::Error { .. } => {
                self.errors += 1;
                Key::Error(self.errors)
            }
            Event::Status { .. } | Event::ApprovalResolved { .. } => unreachable!(),
        };
        let merged = match (self.items.get(&key), &e) {
            (
                Some(Event::Message { text: old, .. }),
                Event::Message {
                    id,
                    role,
                    text,
                    append: true,
                    done,
                },
            ) => Event::Message {
                id: id.clone(),
                role: *role,
                text: format!("{old}{text}"),
                append: false,
                done: *done,
            },
            (
                Some(Event::Thought { text: old, .. }),
                Event::Thought {
                    id,
                    text,
                    append: true,
                },
            ) => Event::Thought {
                id: id.clone(),
                text: format!("{old}{text}"),
                append: false,
            },
            _ => e.clone(),
        };
        if let Some(old) = self.items.insert(key.clone(), merged.clone()) {
            self.bytes = self.bytes.saturating_sub(size(&old));
        } else {
            self.order.push_back(key);
        }
        self.bytes += size(&merged);
        self.trim();
        out.broadcast.push(e);
        out
    }

    fn remove(&mut self, key: &Key) {
        if let Some(old) = self.items.remove(key) {
            self.bytes = self.bytes.saturating_sub(size(&old));
        }
        self.order.retain(|k| k != key);
    }

    /// Drop the oldest items past the bounds; an open approval is kept.
    fn trim(&mut self) {
        while self.order.len() > MAX_ITEMS || self.bytes > MAX_BYTES {
            let Some(pos) = self
                .order
                .iter()
                .position(|k| !matches!(k, Key::Approval(_)))
            else {
                break;
            };
            let k = self.order.remove(pos).expect("in range");
            if let Some(old) = self.items.remove(&k) {
                self.bytes = self.bytes.saturating_sub(size(&old));
            }
        }
    }

    /// Everything a newly attached device is sent: every item, then the
    /// status.
    pub fn replay(&self) -> Vec<Event> {
        let mut v: Vec<Event> = self
            .order
            .iter()
            .filter_map(|k| self.items.get(k).cloned())
            .collect();
        if let Some(s) = self.status {
            v.push(Event::Status { state: s });
        }
        v
    }

    /// Whether `id` is an open approval offering `option`.
    pub fn approval_offers(&self, id: &str, option: &str) -> bool {
        matches!(
            self.items.get(&Key::Approval(id.to_owned())),
            Some(Event::ApprovalRequest { options, .. }) if options.iter().any(|o| o.id == option)
        )
    }

    /// Close every open approval (the adapter ended): what to broadcast.
    pub fn withdraw_all(&mut self) -> Vec<Event> {
        let open: Vec<Key> = self
            .order
            .iter()
            .filter(|k| matches!(k, Key::Approval(_)))
            .cloned()
            .collect();
        open.into_iter()
            .filter_map(|k| {
                self.remove(&k);
                match k {
                    Key::Approval(id) => Some(Event::ApprovalResolved {
                        id,
                        outcome: ApprovalOutcome::Withdrawn,
                    }),
                    _ => None,
                }
            })
            .collect()
    }

    /// The current status.
    pub fn status(&self) -> Option<SessionState> {
        self.status
    }
}

/// Split or cut `e` so each piece's JSON fits in `budget` bytes: a long
/// message or thought becomes a whole first part and appended rest; any
/// other long field is cut (and marked, where the model has a mark).
pub fn fit(e: Event, budget: usize) -> Vec<Event> {
    let room = budget.saturating_sub(512).max(256);
    if serde_json::to_vec(&e).map_or(0, |b| b.len()) <= room {
        return vec![e];
    }
    let pieces = |text: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = text;
        // JSON escaping can grow text up to six times; leave room for it.
        let step = (room / 6).max(64);
        while !rest.is_empty() {
            let mut end = step.min(rest.len());
            while !rest.is_char_boundary(end) {
                end -= 1;
            }
            out.push(rest[..end].to_owned());
            rest = &rest[end..];
        }
        out
    };
    match e {
        Event::Message {
            id,
            role,
            text,
            append,
            done,
        } => {
            let parts = pieces(&text);
            let n = parts.len();
            parts
                .into_iter()
                .enumerate()
                .map(|(i, t)| Event::Message {
                    id: id.clone(),
                    role,
                    text: t,
                    append: append || i > 0,
                    done: done && i + 1 == n,
                })
                .collect()
        }
        Event::Thought { id, text, append } => pieces(&text)
            .into_iter()
            .enumerate()
            .map(|(i, t)| Event::Thought {
                id: id.clone(),
                text: t,
                append: append || i > 0,
            })
            .collect(),
        Event::ToolResult {
            id,
            mut text,
            exit_code,
            truncated,
        } => {
            let cut = truncate_utf8(&mut text, room / 6);
            vec![Event::ToolResult {
                id,
                text,
                exit_code,
                truncated: truncated || cut,
            }]
        }
        Event::Diff {
            tool_call_id,
            path,
            mut unified,
            truncated,
        } => {
            let cut = truncate_utf8(&mut unified, room / 6);
            vec![Event::Diff {
                tool_call_id,
                path,
                unified,
                truncated: truncated || cut,
            }]
        }
        Event::ToolCall {
            id,
            title,
            kind,
            status,
            mut input,
        } => {
            truncate_utf8(&mut input, room / 12);
            let mut title = title;
            truncate_utf8(&mut title, room / 12);
            vec![Event::ToolCall {
                id,
                title,
                kind,
                status,
                input,
            }]
        }
        Event::ApprovalRequest {
            id,
            mut title,
            mut detail,
            options,
        } => {
            truncate_utf8(&mut title, room / 12);
            truncate_utf8(&mut detail, room / 8);
            vec![Event::ApprovalRequest {
                id,
                title,
                detail,
                options,
            }]
        }
        Event::Error { mut text } => {
            truncate_utf8(&mut text, room / 6);
            vec![Event::Error { text }]
        }
        other => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airdress_shell_proto::structured::{
        ApprovalOption, OptionKind, Role, ToolKind, ToolStatus,
    };

    fn msg(id: &str, text: &str, append: bool) -> Event {
        Event::Message {
            id: id.into(),
            role: Role::Assistant,
            text: text.into(),
            append,
            done: false,
        }
    }

    fn approval(id: &str) -> Event {
        Event::ApprovalRequest {
            id: id.into(),
            title: "Run?".into(),
            detail: "ls".into(),
            options: vec![
                ApprovalOption {
                    id: "y".into(),
                    label: "Allow".into(),
                    kind: OptionKind::AllowOnce,
                },
                ApprovalOption {
                    id: "n".into(),
                    label: "Deny".into(),
                    kind: OptionKind::Deny,
                },
            ],
        }
    }

    #[test]
    fn a_late_device_sees_the_items_whole_in_first_seen_order() {
        let mut t = Transcript::default();
        t.apply(msg("m1", "Hel", false));
        t.apply(Event::ToolCall {
            id: "c1".into(),
            title: "ls".into(),
            kind: ToolKind::Execute,
            status: ToolStatus::Running,
            input: String::new(),
        });
        t.apply(msg("m1", "lo", true));
        t.apply(Event::ToolCall {
            id: "c1".into(),
            title: "ls".into(),
            kind: ToolKind::Execute,
            status: ToolStatus::Done,
            input: String::new(),
        });
        t.apply(Event::Status {
            state: SessionState::Idle,
        });
        let r = t.replay();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], msg("m1", "Hello", false));
        assert!(matches!(
            r[1],
            Event::ToolCall {
                status: ToolStatus::Done,
                ..
            }
        ));
        assert_eq!(
            r[2],
            Event::Status {
                state: SessionState::Idle
            }
        );
    }

    #[test]
    fn attention_and_the_overview_word_follow_the_status() {
        let mut t = Transcript::default();
        let st = |s| Event::Status { state: s };
        let a = t.apply(st(SessionState::Working));
        assert_eq!((a.attention, a.state), (None, Some("working")));
        let a = t.apply(st(SessionState::WaitingForApproval));
        assert_eq!(
            (a.attention, a.state),
            (Some("needs_you"), Some("needs_you"))
        );
        t.apply(st(SessionState::Working));
        let a = t.apply(st(SessionState::Idle));
        assert_eq!((a.attention, a.state), (Some("done"), Some("done")));
        let a = t.apply(st(SessionState::Idle));
        assert_eq!((a.attention, a.state), (None, None));
    }

    #[test]
    fn only_an_open_approval_with_that_option_can_be_answered() {
        let mut t = Transcript::default();
        t.apply(approval("a1"));
        assert!(t.approval_offers("a1", "y"));
        assert!(!t.approval_offers("a1", "always"));
        assert!(!t.approval_offers("a2", "y"));
        let a = t.apply(Event::ApprovalResolved {
            id: "a1".into(),
            outcome: ApprovalOutcome::Answered,
        });
        assert_eq!(a.broadcast.len(), 1);
        assert!(!t.approval_offers("a1", "y"));
        assert!(t.replay().is_empty());
        // Resolving it twice says nothing the second time.
        let a = t.apply(Event::ApprovalResolved {
            id: "a1".into(),
            outcome: ApprovalOutcome::Answered,
        });
        assert!(a.broadcast.is_empty());
    }

    #[test]
    fn bounds_drop_the_oldest_but_never_an_open_approval() {
        let mut t = Transcript::default();
        t.apply(approval("keep"));
        for i in 0..(MAX_ITEMS + 50) {
            t.apply(msg(&format!("m{i}"), "x", false));
        }
        let r = t.replay();
        assert!(r.len() <= MAX_ITEMS);
        assert!(t.approval_offers("keep", "y"));
        assert_eq!(r[0], approval("keep"));
        assert_eq!(t.withdraw_all().len(), 1);
        assert!(!t.approval_offers("keep", "y"));
    }

    #[test]
    fn a_long_message_is_split_into_parts_that_rebuild_it() {
        let text = "äb".repeat(20_000);
        let parts = fit(msg("m", &text, false), 4096);
        assert!(parts.len() > 1);
        let mut t = Transcript::default();
        for p in &parts {
            assert!(serde_json::to_vec(p).unwrap().len() <= 4096);
            t.apply(p.clone());
        }
        assert_eq!(t.replay()[0], msg("m", &text, false));
        let diff = fit(
            Event::Diff {
                tool_call_id: "c".into(),
                path: "p".into(),
                unified: "+".repeat(100_000),
                truncated: false,
            },
            4096,
        );
        assert!(matches!(
            diff[..],
            [Event::Diff {
                truncated: true,
                ..
            }]
        ));
    }
}
