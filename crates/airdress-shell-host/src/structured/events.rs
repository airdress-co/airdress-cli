//! The host's event socket, for a harness driven through its own terminal
//! (design §9.4, D-9, D-31, FR-K).
//!
//! The person runs the unmodified harness binary in a terminal profile and
//! installs the plugin themselves. The plugin's hooks run a small program
//! (`airdress shell events`) which exits at once outside an Airdress shell
//! session, and otherwise writes the hook's JSON here, with the session's id
//! and a per-session token the host put in that session's environment
//! (design §7.5). The host maps it into the neutral event model.
//!
//! What this socket can do, and nothing more:
//!
//! - deliver one hook's input, for one session, with that session's token;
//! - for a permission hook, wait for the human's answer from the typist's
//!   client and return it — `allow` or `deny` — or, after
//!   [`PERMISSION_WAIT`] with no answer, return nothing, so the harness's
//!   own terminal prompt stands.
//!
//! It cannot open, attach or type. It is a Unix socket in the host's
//! private state directory (0700), and a peer of another uid is refused.
//!
//! Verified against Claude Code 2.1.289's hook reference
//! (`code.claude.com/docs/en/hooks.md`, raw): the event names, their input
//! fields (`hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`,
//! `tool_response`, `error`, `prompt`, `notification_type`,
//! `last_assistant_message`), and `PermissionRequest`'s output
//! `{hookSpecificOutput: {hookEventName, decision: {behavior}}}`, which the
//! hook program writes.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airdress_shell_proto::structured::{
    ApprovalOption, Event, OptionKind, Role, SessionState, ToolKind, ToolStatus,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::{summarize, unified::unified};
use crate::log_err::LogErr as _;
use crate::pty::PtyEvent;

/// How long a permission hook waits for the human (FR-K3).
pub const PERMISSION_WAIT: Duration = Duration::from_secs(120);
/// The most one hook message may be.
pub const MAX_MESSAGE: u64 = 1 << 20;

/// One hook call, handed to the session it names.
#[derive(Debug)]
pub struct HookCall {
    pub token: HookToken,
    pub input: Value,
    /// For a permission hook: where the human's answer goes.
    pub reply: Option<oneshot::Sender<Value>>,
}

/// The socket's path under the host's private directory.
pub fn socket_path(host_dir: &Path) -> PathBuf {
    host_dir.join("events.sock")
}

/// The most hook connections served at once (R-ASY-5). A hook program
/// writes one line and, for a permission, waits up to
/// [`PERMISSION_WAIT`]; past this many the socket stops accepting until one
/// finishes, so a runaway plugin cannot grow the host without bound.
pub const MAX_HOOK_CONNECTIONS: usize = 64;

/// The listening socket. It owns its accept loop and every connection it
/// serves (R-ASY-1): dropping it stops them all.
#[derive(Debug)]
pub struct EventSocket {
    pub path: PathBuf,
    _task: tokio::task::JoinSet<()>,
}

/// Listen. Returns the socket, or `None` where none could be made (the
/// structured view of terminal-driven harnesses is then unavailable; the
/// terminal is not affected).
pub fn listen(host_dir: &Path, to_host: mpsc::Sender<(Uuid, PtyEvent)>) -> Option<EventSocket> {
    let path = socket_path(host_dir);
    // A dead host's socket; the bind below fails, naming it, if it stays.
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(error = %e, "removing a stale event socket");
        }
    }
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "the event socket could not be made");
            return None;
        }
    };
    // The directory is private (0700) already; this is the belt to it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .log_warn("restricting the event socket to 0600");
    let mut task = tokio::task::JoinSet::new();
    task.spawn(accept_loop(listener, to_host));
    Some(EventSocket { path, _task: task })
}

async fn accept_loop(listener: tokio::net::UnixListener, to_host: mpsc::Sender<(Uuid, PtyEvent)>) {
    let me = rustix::process::getuid();
    let mut serving = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            // cancel-safe: `UnixListener::accept` (tokio's list). Not polled
            // while MAX_HOOK_CONNECTIONS are being served.
            accepted = listener.accept(), if serving.len() < MAX_HOOK_CONNECTIONS => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                match stream.peer_cred() {
                    Ok(c) if c.uid() == me.as_raw() => {}
                    _ => {
                        tracing::warn!("a peer of another user was refused on the event socket");
                        continue;
                    }
                }
                serving.spawn(serve(stream, to_host.clone()));
            }
            // cancel-safe: `JoinSet::join_next` (documented cancel-safe).
            // Reaps a finished connection; a panicked one is said once.
            Some(done) = serving.join_next() => {
                if let Err(e) = done {
                    if e.is_panic() {
                        tracing::error!(error = %e, "a hook connection panicked");
                    }
                }
            }
        }
    }
}

async fn serve(stream: tokio::net::UnixStream, to_host: mpsc::Sender<(Uuid, PtyEvent)>) {
    let (rd, mut wr) = stream.into_split();
    let mut line = Vec::new();
    let mut rd = BufReader::new(rd.take(MAX_MESSAGE));
    if rd.read_until(b'\n', &mut line).await.is_err() {
        return;
    }
    let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
        return;
    };
    let (Some(session), Some(token), Some(input)) = (
        msg.get("session")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok()),
        msg.get("token").and_then(Value::as_str),
        msg.get("hook").cloned(),
    ) else {
        return;
    };
    let is_permission =
        input.get("hook_event_name").and_then(Value::as_str) == Some("PermissionRequest");
    let (tx, rx) = oneshot::channel();
    let call = HookCall {
        token: HookToken::new(token.to_owned()),
        input,
        reply: is_permission.then_some(tx),
    };
    if to_host.send((session, PtyEvent::Hook(call))).await.is_err() {
        return;
    }
    let answer = if is_permission {
        match tokio::time::timeout(PERMISSION_WAIT, rx).await {
            Ok(Ok(v)) => v,
            // No answer in time, or the session dropped it: nothing, and
            // the harness's own prompt stands.
            _ => json!({}),
        }
    } else {
        json!({})
    };
    let mut out = serde_json::to_vec(&answer).unwrap_or_default();
    out.push(b'\n');
    // The hook gave up waiting; its own timeout decides what it does.
    wr.write_all(&out).await.log_debug("answering a hook");
}

/// The hook program (`airdress shell events`), which the plugin's hooks run
/// with the hook's JSON on stdin. Outside an Airdress shell session — any
/// of the three session variables unset — it does nothing and exits 0, as
/// it does when the host cannot be reached: a hook of ours must never get
/// in the person's way. For a permission hook it prints the decision the
/// human tapped, in the harness's hook output shape, and otherwise nothing.
pub fn hook_main(
    stdin: &mut dyn std::io::Read,
    stdout: &mut dyn std::io::Write,
    var: &dyn Fn(&str) -> Option<String>,
) -> i32 {
    use std::io::{BufRead as _, Read as _, Write as _};
    let (Some(session), Some(sock), Some(token)) = (
        var("AIRDRESS_SHELL_SESSION"),
        var("AIRDRESS_SHELL_SOCKET"),
        var("AIRDRESS_SHELL_EVENTS_TOKEN"),
    ) else {
        return 0;
    };
    let mut raw = Vec::new();
    if stdin.take(MAX_MESSAGE).read_to_end(&mut raw).is_err() {
        return 0;
    }
    let Ok(hook) = serde_json::from_slice::<Value>(&raw) else {
        return 0;
    };
    let permission =
        hook.get("hook_event_name").and_then(Value::as_str) == Some("PermissionRequest");
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&sock) else {
        return 0;
    };
    let wait = if permission {
        PERMISSION_WAIT + Duration::from_secs(5)
    } else {
        Duration::from_secs(5)
    };
    // Without a timeout the hook waits on the host as long as it takes;
    // the harness's own hook timeout still bounds it.
    stream
        .set_read_timeout(Some(wait))
        .log_debug("setting the hook's read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .log_debug("setting the hook's write timeout");
    let mut line = serde_json::to_vec(&json!({ "session": session, "token": token, "hook": hook }))
        .unwrap_or_default();
    line.push(b'\n');
    if stream.write_all(&line).is_err() {
        return 0;
    }
    let mut reply = String::new();
    // No answer means no decision is written below, and the harness goes
    // on as it would without this hook.
    std::io::BufReader::new(stream)
        .read_line(&mut reply)
        .log_debug("reading the host's answer");
    if !permission {
        return 0;
    }
    let behavior = serde_json::from_str::<Value>(&reply)
        .ok()
        .and_then(|v| v.get("decision").and_then(Value::as_str).map(str::to_owned));
    if let Some(b) = behavior.filter(|b| b == "allow" || b == "deny") {
        let out = json!({ "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": { "behavior": b }
        }});
        // The harness reads the decision from stdout; there is nowhere
        // else to say it could not be written.
        writeln!(stdout, "{out}").log_debug("writing the hook's decision");
    }
    0
}

/// Compare two tokens without stopping at the first difference.
/// The token a session's hooks present on the event socket. `Debug` prints
/// a placeholder (a `HookCall` and a session's structured side are both
/// `Debug`), and the bytes are wiped on drop. `expose()` is the way out.
#[derive(Clone, PartialEq, Eq)]
pub struct HookToken(zeroize::Zeroizing<String>);

impl HookToken {
    /// Wrap a token.
    pub fn new(token: String) -> Self {
        Self(zeroize::Zeroizing::new(token))
    }

    /// The token itself, for the comparison and the hook's environment.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for HookToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

pub fn token_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Map a tool's name onto a kind.
pub fn tool_kind(tool: &str) -> ToolKind {
    match tool {
        "Read" | "LS" | "NotebookRead" => ToolKind::Read,
        "Edit" | "MultiEdit" | "Write" | "NotebookEdit" => ToolKind::Edit,
        "Bash" | "BashOutput" | "KillShell" => ToolKind::Execute,
        "Grep" | "Glob" => ToolKind::Search,
        "WebFetch" | "WebSearch" => ToolKind::Fetch,
        _ => ToolKind::Other,
    }
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The diff an edit tool's input describes, without reading the file.
fn diff_of(tool: &str, input: &Value) -> Option<(String, String)> {
    let path = s(input, "file_path")?.to_owned();
    let d = match tool {
        "Edit" => unified(
            &path,
            Some(s(input, "old_string")?),
            s(input, "new_string")?,
        ),
        "Write" => unified(&path, None, s(input, "content")?),
        "MultiEdit" => input
            .get("edits")?
            .as_array()?
            .iter()
            .filter_map(|e| {
                Some(unified(
                    &path,
                    Some(s(e, "old_string")?),
                    s(e, "new_string")?,
                ))
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => return None,
    };
    Some((path, d))
}

/// A session's hook mapper.
#[derive(Debug, Default)]
pub struct Mapper {
    prompts: u64,
    turns: u64,
    approvals: u64,
}

impl Mapper {
    /// One hook's input as events. A permission hook's card id is returned
    /// too, so its answer can find its way back.
    pub fn hook(&mut self, h: &Value) -> (Vec<Event>, Option<String>) {
        let tool = s(h, "tool_name").unwrap_or("");
        let input = h.get("tool_input").cloned().unwrap_or(Value::Null);
        let call = s(h, "tool_use_id").unwrap_or("").to_owned();
        let events = match s(h, "hook_event_name").unwrap_or("") {
            "SessionStart" => vec![Event::Status {
                state: SessionState::Idle,
            }],
            "SessionEnd" => vec![Event::Status {
                state: SessionState::Ended,
            }],
            "UserPromptSubmit" => {
                self.prompts += 1;
                self.turns += 1;
                vec![
                    Event::Message {
                        id: format!("user-{}", self.prompts),
                        role: Role::User,
                        text: s(h, "prompt").unwrap_or("").to_owned(),
                        append: false,
                        done: true,
                    },
                    Event::Status {
                        state: SessionState::Working,
                    },
                ]
            }
            "PreToolUse" if !call.is_empty() => vec![Event::ToolCall {
                id: call,
                title: tool.to_owned(),
                kind: tool_kind(tool),
                status: ToolStatus::Running,
                input: summarize(&input),
            }],
            "PostToolUse" if !call.is_empty() => {
                let mut v = vec![Event::ToolCall {
                    id: call.clone(),
                    title: tool.to_owned(),
                    kind: tool_kind(tool),
                    status: ToolStatus::Done,
                    input: summarize(&input),
                }];
                let text = match h.get("tool_response") {
                    Some(Value::String(t)) => t.clone(),
                    Some(Value::Object(o)) => o
                        .get("stdout")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| Value::Object(o.clone()).to_string()),
                    Some(other) => other.to_string(),
                    None => String::new(),
                };
                if !text.is_empty() {
                    v.push(Event::ToolResult {
                        id: call.clone(),
                        text,
                        exit_code: None,
                        truncated: false,
                    });
                }
                if let Some((path, unified)) = diff_of(tool, &input) {
                    v.push(Event::Diff {
                        tool_call_id: call,
                        path,
                        unified,
                        truncated: false,
                    });
                }
                v
            }
            "PostToolUseFailure" if !call.is_empty() => vec![
                Event::ToolCall {
                    id: call.clone(),
                    title: tool.to_owned(),
                    kind: tool_kind(tool),
                    status: ToolStatus::Failed,
                    input: summarize(&input),
                },
                Event::ToolResult {
                    id: call,
                    text: s(h, "error").unwrap_or("").to_owned(),
                    exit_code: None,
                    truncated: false,
                },
            ],
            "Notification" => match s(h, "notification_type") {
                Some("idle_prompt" | "elicitation_dialog") => vec![Event::Status {
                    state: SessionState::WaitingForInput,
                }],
                _ => Vec::new(),
            },
            "Stop" => {
                let mut v = Vec::new();
                if let Some(t) = s(h, "last_assistant_message").filter(|t| !t.is_empty()) {
                    v.push(Event::Message {
                        id: format!("assistant-{}", self.turns),
                        role: Role::Assistant,
                        text: t.to_owned(),
                        append: false,
                        done: true,
                    });
                }
                v.push(Event::Status {
                    state: SessionState::Idle,
                });
                v
            }
            "PermissionRequest" => {
                self.approvals += 1;
                let id = format!("approval-{}", self.approvals);
                return (
                    vec![
                        Event::ApprovalRequest {
                            id: id.clone(),
                            title: if tool.is_empty() {
                                "Allow this?".to_owned()
                            } else {
                                format!("Allow {tool}?")
                            },
                            detail: summarize(&input),
                            options: vec![
                                ApprovalOption {
                                    id: "allow".into(),
                                    label: "Allow".into(),
                                    kind: OptionKind::AllowOnce,
                                },
                                ApprovalOption {
                                    id: "deny".into(),
                                    label: "Deny".into(),
                                    kind: OptionKind::Deny,
                                },
                            ],
                        },
                        Event::Status {
                            state: SessionState::WaitingForApproval,
                        },
                    ],
                    Some(id),
                );
            }
            _ => Vec::new(),
        };
        (events, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_hook(input: Value, vars: &[(&str, String)]) -> String {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        let mut stdin = std::io::Cursor::new(serde_json::to_vec(&input).unwrap());
        let mut out = Vec::new();
        let code = hook_main(&mut stdin, &mut out, &|k| {
            vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        });
        assert_eq!(code, 0);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_hook_program_is_silent_outside_a_session_and_speaks_only_for_a_permission() {
        // Outside a session: nothing, whatever the input.
        assert_eq!(
            run_hook(json!({"hook_event_name": "PermissionRequest"}), &[]),
            ""
        );
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let seen = std::thread::spawn(move || {
            use std::io::{BufRead as _, Write as _};
            let mut got = Vec::new();
            for answer in [r#"{"decision":"allow"}"#, "{}", "{}"] {
                let (s, _) = listener.accept().unwrap();
                let mut r = std::io::BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                got.push(serde_json::from_str::<Value>(&line).unwrap());
                (&s).write_all(format!("{answer}\n").as_bytes()).unwrap();
            }
            got
        });
        let vars = [
            ("AIRDRESS_SHELL_SESSION", "s-1".to_owned()),
            ("AIRDRESS_SHELL_SOCKET", sock.to_string_lossy().into_owned()),
            ("AIRDRESS_SHELL_EVENTS_TOKEN", "tok".to_owned()),
        ];
        let out = run_hook(
            json!({"hook_event_name": "PermissionRequest", "tool_name": "Bash"}),
            &vars,
        );
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap(),
            json!({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}})
        );
        // No answer: no output, so the harness's own prompt stands.
        assert_eq!(
            run_hook(json!({"hook_event_name": "PermissionRequest"}), &vars),
            ""
        );
        // Any other hook: never any output.
        assert_eq!(run_hook(json!({"hook_event_name": "Stop"}), &vars), "");
        let got = seen.join().unwrap();
        assert_eq!(got[0]["session"], "s-1");
        assert_eq!(got[0]["token"], "tok");
        assert_eq!(got[0]["hook"]["tool_name"], "Bash");
    }

    #[test]
    fn hooks_map_onto_the_model() {
        let mut m = Mapper::default();
        let (e, _) = m.hook(&json!({"hook_event_name": "UserPromptSubmit", "prompt": "fix it"}));
        assert!(matches!(&e[0], Event::Message { role: Role::User, text, .. } if text == "fix it"));
        let (e, _) = m.hook(
            &json!({"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_use_id": "tu1",
            "tool_input": {"file_path": "/w/a.rs", "old_string": "a\n", "new_string": "b\n"},
            "tool_response": {"filePath": "/w/a.rs"}}),
        );
        assert!(matches!(
            &e[0],
            Event::ToolCall {
                kind: ToolKind::Edit,
                status: ToolStatus::Done,
                ..
            }
        ));
        assert!(e
            .iter()
            .any(|x| matches!(x, Event::Diff { unified, .. } if unified.contains("-a\n+b\n"))));
        let (e, id) = m.hook(
            &json!({"hook_event_name": "PermissionRequest", "tool_name": "Bash",
            "tool_input": {"command": "rm -rf build"}}),
        );
        assert_eq!(id.as_deref(), Some("approval-1"));
        assert!(
            matches!(&e[0], Event::ApprovalRequest { detail, options, .. } if detail == "rm -rf build" && options.len() == 2)
        );
        let (e, _) = m.hook(&json!({"hook_event_name": "Stop", "last_assistant_message": "Done."}));
        assert!(
            matches!(&e[0], Event::Message { id, text, done: true, .. } if id == "assistant-1" && text == "Done.")
        );
        assert_eq!(
            e[1],
            Event::Status {
                state: SessionState::Idle
            }
        );
    }
}
