//! The structured tier on the host (design §9, D-9, D-10, D-20, D-31).
//!
//! A profile's `structured` names one adapter from a closed set. The adapter
//! connects to what the profile itself starts — never with an argument or an
//! environment variable of its own beyond design §7.5 (FR-T5) — and maps its
//! harness's protocol into the neutral event model
//! ([`airdress_shell_proto::structured`]). The session keeps a transcript of
//! those events, so a device that attaches later is shown the conversation
//! so far, and derives the session's attention from its status.
//!
//! **Only a human answers.** An adapter answers a harness's approval
//! request only with an [`Input::ApprovalAnswer`] that came from the
//! typist's client, which only a human's tap or key produces. There is no
//! auto-answer anywhere in this module, no timeout that answers, and no
//! rule that matches a request against an earlier answer: a test reads the
//! source and fails if one appears.

pub mod acp;
pub mod app_server;
pub mod events;
pub mod http_server;
pub mod input;
pub mod jsonrpc;
pub mod transcript;
pub mod unified;

use std::path::PathBuf;

use airdress_shell_proto::structured::{Event, Input};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::log_err::LogErr as _;
use crate::pty::{PtyEvent, Stdio};

/// What an adapter tells its session.
#[derive(Debug, Clone, PartialEq)]
pub enum AdapterOut {
    /// One event of the neutral model.
    Event(Event),
    /// The adapter lost its harness; the words say why. The session's
    /// process keeps running (or has exited on its own).
    Ended(String),
}

/// The adapters (design §9.1). Closed: adding one is a spec change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adapter {
    /// JSON-RPC 2.0 over the program's stdio.
    Acp,
    /// The loopback HTTP server the program starts.
    HttpServer,
    /// JSON-RPC over the program's stdio.
    AppServer,
    /// Hooks inside the unmodified binary, over the host's event socket.
    TerminalHooks,
}

impl Adapter {
    /// From a profile's `structured` value.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "acp" => Adapter::Acp,
            "opencode-server" => Adapter::HttpServer,
            "codex-app-server" => Adapter::AppServer,
            "claude-plugin" => Adapter::TerminalHooks,
            _ => return None,
        })
    }

    /// Whether the program's stdio is the protocol (so the terminal shows
    /// only its stderr, and takes no input).
    pub fn uses_stdio(self) -> bool {
        matches!(self, Adapter::Acp | Adapter::AppServer)
    }
}

/// Whether a harness may be offered with an adapter at all
/// (requirements §5, D-10, task 137-F.9). The table is the spec's: a change
/// here is a change to that table first.
///
/// - Claude Code: only through the plugin, inside the interactive binary.
/// - Codex: its app-server.
/// - opencode: its server.
/// - Goose: ACP.
/// - Gemini CLI: none (terminal only) until Google confirms otherwise in
///   writing; Cursor, Amp, Aider, Crush: none in v1; any other harness, and
///   a plain shell: none until an entry is added to the table.
pub fn allowed(kind: &str, adapter: Adapter) -> bool {
    let Some(harness) = kind.strip_prefix("harness:") else {
        return false;
    };
    matches!(
        (harness, adapter),
        ("claude-code", Adapter::TerminalHooks)
            | ("codex", Adapter::AppServer)
            | ("opencode", Adapter::HttpServer)
            | ("goose", Adapter::Acp)
    )
}

/// What an adapter is started with.
#[derive(Debug)]
pub struct Connect {
    pub session: Uuid,
    pub adapter: Adapter,
    /// The program's stdio, for the stdio adapters.
    pub stdio: Option<Stdio>,
    /// The session's working directory.
    pub cwd: PathBuf,
    /// The profile's own arguments (read, never added to: the opencode
    /// server's port is the profile's `--port`).
    pub args: Vec<String>,
    /// The per-session loopback password the host set (design §7.5).
    pub server_password: Option<zeroize::Zeroizing<String>>,
}

/// How many of a person's structured inputs (a prompt, an answer, a
/// cancel) wait for an adapter that is busy talking to its harness
/// (R-ASY-5). Each is one person's tap, so this is far beyond anything a
/// person sends; past it the input is refused out loud, never queued
/// without bound and never dropped silently.
pub const ADAPTER_INPUTS: usize = 32;

/// Answers of an adapter's turn requests waiting to be read (R-ASY-5).
pub const TURN_RESULTS: usize = 4;

/// The session's end of a running adapter. It owns the adapter's task
/// (R-ASY-1): dropping it ends the adapter.
#[derive(Debug)]
pub struct AdapterHandle {
    pub inputs: mpsc::Sender<Input>,
    _task: tokio::task::JoinSet<()>,
}

/// An adapter's way back to its session.
#[derive(Debug, Clone)]
pub struct Out(pub mpsc::Sender<PtyEvent>);

impl Out {
    /// One event.
    pub async fn event(&self, e: Event) -> bool {
        self.0
            .send(PtyEvent::Structured(AdapterOut::Event(e)))
            .await
            .is_ok()
    }

    /// The adapter is done.
    pub async fn ended(&self, why: impl Into<String>) {
        // Closed: the session has already gone.
        self.0
            .send(PtyEvent::Structured(AdapterOut::Ended(why.into())))
            .await
            .log_debug("reporting that the adapter ended");
    }
}

/// Start the adapter for a session. Returns `None` for the plugin adapter,
/// whose events arrive on the host's event socket rather than from a task
/// of ours.
pub fn start(c: Connect, events: mpsc::Sender<PtyEvent>) -> Option<AdapterHandle> {
    let (tx, rx) = mpsc::channel(ADAPTER_INPUTS);
    let out = Out(events);
    let mut task = tokio::task::JoinSet::new();
    match c.adapter {
        Adapter::Acp => {
            let stdio = c.stdio?;
            task.spawn(acp::run(stdio, c.cwd, rx, out));
        }
        Adapter::AppServer => {
            let stdio = c.stdio?;
            task.spawn(app_server::run(stdio, c.cwd, rx, out));
        }
        Adapter::HttpServer => {
            let target = http_server::Target::from_profile(&c.args, c.server_password, c.cwd);
            task.spawn(http_server::run(target, rx, out));
        }
        Adapter::TerminalHooks => return None,
    }
    Some(AdapterHandle {
        inputs: tx,
        _task: task,
    })
}

/// A one-line summary of a JSON value for a tool call's `input`: a command,
/// a path, or the compact JSON, cut at 512 bytes.
pub fn summarize(v: &serde_json::Value) -> String {
    let mut s = match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(o) => {
            let pick = [
                "command",
                "cmd",
                "path",
                "filePath",
                "file_path",
                "pattern",
                "url",
                "query",
            ]
            .iter()
            .find_map(|k| o.get(*k));
            match pick {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Array(a)) => a
                    .iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                _ => v.to_string(),
            }
        }
        other => other.to_string(),
    };
    airdress_shell_proto::structured::truncate_utf8(&mut s, 512);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_terms_table_is_the_spec_s() {
        use Adapter::*;
        assert!(allowed("harness:claude-code", TerminalHooks));
        assert!(allowed("harness:codex", AppServer));
        assert!(allowed("harness:opencode", HttpServer));
        assert!(allowed("harness:goose", Acp));
        // AC-17: Gemini on Google sign-in is terminal only, whatever the
        // profile asks for.
        for a in [Acp, HttpServer, AppServer, TerminalHooks] {
            assert!(!allowed("harness:gemini", a));
            assert!(!allowed("harness:cursor", a));
            assert!(!allowed("harness:amp", a));
            assert!(!allowed("harness:aider", a));
            assert!(!allowed("harness:crush", a));
            assert!(!allowed("shell", a));
            assert!(!allowed("harness:something-new", a));
        }
        assert!(!allowed("harness:claude-code", Acp));
        assert!(!allowed("harness:opencode", Acp));
    }

    /// D-31, FR-T4, task 137-F.9: no adapter or host path answers an
    /// approval for the human. Each adapter builds its harness's answer in
    /// exactly one place, inside the arm that forwards a client's
    /// `approval_answer`; and nothing in the host constructs one.
    #[test]
    fn no_code_path_answers_an_approval_for_the_human() {
        let code = |src: &'static str| src.split("#[cfg(test)]").next().unwrap();
        for (file, src, token) in [
            ("acp.rs", include_str!("acp.rs"), r#""outcome": "selected""#),
            (
                "app_server.rs",
                include_str!("app_server.rs"),
                r#""decision": option"#,
            ),
            (
                "http_server.rs",
                include_str!("http_server.rs"),
                r#""reply": option"#,
            ),
            (
                "input.rs",
                include_str!("input.rs"),
                r#""decision": option"#,
            ),
        ] {
            let c = code(src);
            assert_eq!(c.matches(token).count(), 1, "{file}: one place answers");
            let at = c.find(token).unwrap();
            let arm = c[..at]
                .rfind("Input::ApprovalAnswer { id, option } =>")
                .unwrap_or_else(|| panic!("{file}: the answer is built outside the human's arm"));
            let between = &c[arm..at];
            assert!(
                !between.contains("Input::Prompt") && !between.contains("Input::Cancel"),
                "{file}: the answer is built in another arm"
            );
        }
        for (file, src) in [
            ("mod.rs", include_str!("mod.rs")),
            ("acp.rs", include_str!("acp.rs")),
            ("app_server.rs", include_str!("app_server.rs")),
            ("http_server.rs", include_str!("http_server.rs")),
            ("input.rs", include_str!("input.rs")),
            ("events.rs", include_str!("events.rs")),
            ("transcript.rs", include_str!("transcript.rs")),
            ("jsonrpc.rs", include_str!("jsonrpc.rs")),
            ("host.rs", include_str!("../host.rs")),
            ("session.rs", include_str!("../session.rs")),
        ] {
            let c = code(src);
            for (i, _) in c.match_indices("ApprovalAnswer {") {
                let rest = &c[i..];
                let body = &rest[..rest.find('}').unwrap()];
                assert!(
                    !body.contains(':'),
                    "{file}: an ApprovalAnswer is constructed, not matched: {body}"
                );
            }
        }
    }

    #[test]
    fn summaries_prefer_the_command_or_path() {
        use serde_json::json;
        assert_eq!(
            summarize(&json!({"command": ["cargo", "test"]})),
            "cargo test"
        );
        assert_eq!(
            summarize(&json!({"filePath": "/a/b.rs", "x": 1})),
            "/a/b.rs"
        );
        assert_eq!(summarize(&json!("ls")), "ls");
        assert_eq!(summarize(&json!(null)), "");
        assert!(summarize(&json!({"blob": "x".repeat(2000)})).len() <= 512);
    }
}
