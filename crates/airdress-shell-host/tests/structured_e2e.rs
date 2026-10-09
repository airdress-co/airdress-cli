//! The structured tier end to end (design §9, tasks 137-F.2–F.5, F.9): a
//! real host, enrolled with the mock operator, runs stand-in harnesses that
//! speak each adapter's protocol, and devices drive them over the end-to-end
//! channel.
//!
//! The stand-ins (`tests/fixtures/*.py`) log every message they receive, so
//! the tests can show that a permission is answered only after — and only
//! with — the typist's tap, and never by the host on its own.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use airdress_shell_host::testkit::{Client, Device};
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::structured::{Body, Event, SessionState};
use common::{rig, Rig};
use serde_json::{json, Value};
use uuid::Uuid;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn python() -> &'static str {
    "/usr/bin/python3"
}

/// Every structured event the client has seen, in order.
fn events(c: &Client) -> Vec<Event> {
    c.other
        .iter()
        .filter_map(|m| match m {
            Message::Structured { body } => match Body::from_value(body) {
                Ok(Body::Event(e)) => Some(e),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn has(c: &Client, f: impl Fn(&Event) -> bool) -> bool {
    events(c).iter().any(f)
}

fn input(v: Value) -> Message {
    Message::Structured { body: v }
}

fn log_lines(path: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn profiles(log: &str, port: u16) -> String {
    format!(
        r#"
[[profile]]
id = "agent"
label = "agent"
kind = "harness:goose"
program = "{py}"
args = ["{acp}"]
structured = "acp"
notify = true
env_set = {{ FAKE_LOG = "{log}.acp" }}

[[profile]]
id = "app-server"
label = "app server"
kind = "harness:codex"
program = "{py}"
args = ["{app}"]
structured = "codex-app-server"
notify = true
env_set = {{ FAKE_LOG = "{log}.app" }}

[[profile]]
id = "server"
label = "server"
kind = "harness:opencode"
program = "{py}"
args = ["{srv}", "--port", "{port}"]
structured = "opencode-server"
env_set = {{ FAKE_LOG = "{log}.srv" }}

[[profile]]
id = "term"
label = "terminal harness"
kind = "harness:claude-code"
program = "{py}"
args = ["{term}"]
structured = "claude-plugin"
notify = true

[[profile]]
id = "term-wrong-token"
label = "terminal harness, wrong token"
kind = "harness:claude-code"
program = "{py}"
args = ["{term}"]
structured = "claude-plugin"
env_set = {{ FAKE_IMPOSTOR = "not-the-session-s" }}

[[profile]]
id = "gem"
label = "gemini"
kind = "harness:gemini"
program = "{py}"
args = ["{acp}"]
structured = "acp"

[[profile]]
id = "gem-terminal"
label = "gemini in a terminal"
kind = "harness:gemini"
program = "/bin/cat"
"#,
        py = python(),
        acp = fixture("fake_acp_agent.py"),
        app = fixture("fake_app_server.py"),
        srv = fixture("fake_server.py"),
        term = fixture("fake_terminal_harness.py"),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn setup() -> (Rig, String, u16) {
    let dir = tempfile::tempdir().unwrap().keep();
    let log = dir.join("fake").to_string_lossy().into_owned();
    let port = free_port();
    let r = rig(&profiles(&log, port), true).await;
    (r, log, port)
}

async fn open_typist(r: &mut Rig, profile: &str) -> (Client, Uuid) {
    let cli = Device::cli(4, "laptop");
    let deleg = r.delegation(&cli, "cli");
    let mut c = r.client(cli, profile);
    let leg = r.open(&mut c, profile, Some(deleg)).await;
    assert!(
        r.pump(&mut c, leg, |c| has(c, |e| matches!(
            e,
            Event::Status {
                state: SessionState::Idle
            }
        )))
        .await,
        "the adapter came up: {:?} {:?}",
        events(&c),
        c.errors
    );
    (c, leg)
}

/// AC-17 and F.9: an adapter is offered only where the terms row allows it.
#[tokio::test]
async fn a_harness_whose_terms_allow_no_adapter_is_not_offered_one() {
    let (r, _, _) = setup().await;
    let p = r.profiles["profiles"].as_array().unwrap();
    let get = |id: &str| p.iter().find(|x| x["id"] == id).unwrap().clone();
    assert_eq!(get("gem")["state"], "invalid");
    assert_eq!(get("gem")["reason"], "structured_not_allowed");
    assert_eq!(get("gem-terminal")["state"], "ready");
    assert!(get("gem-terminal").get("structured").is_none());
    for id in ["agent", "app-server", "server", "term"] {
        assert_eq!(get(id)["state"], "ready", "{id}: {}", get(id));
    }
}

/// F.2 and F.5: an ACP agent's prompt, tool call, plan, diff and permission
/// request, the permission answered by the typist's tap and by nothing
/// else, attention raised as `needs_you` then `done` with nothing but the
/// session and the state.
#[tokio::test]
async fn acp_a_permission_is_answered_only_by_the_typist_s_tap() {
    let (mut r, log, _) = setup().await;
    let log = format!("{log}.acp");
    let (mut c, cleg) = open_typist(&mut r, "agent").await;
    let session = c.session;

    // A phone attaches as a viewer.
    let phone = Device::phone(5, "Galaxy");
    let phone_deleg = r.delegation(&phone, "phone");
    let mut p = r.client_for(phone, session, "agent");
    let pleg = r.attach(&mut p, Some(phone_deleg), true).await;
    assert!(r.pump(&mut p, pleg, |p| p.snapshots == 1).await);

    r.say(
        &mut c,
        cleg,
        &[input(json!({"input": "prompt", "text": "list the files"}))],
    );
    assert!(
        r.pump(&mut c, cleg, |c| has(c, |e| matches!(
            e,
            Event::ApprovalRequest { .. }
        )))
        .await,
        "{:?}",
        events(&c)
    );
    let ev = events(&c);
    assert!(ev.iter().any(|e| matches!(e, Event::Message { text, role: airdress_shell_proto::structured::Role::User, .. } if text == "list the files")));
    assert!(ev.iter().any(|e| matches!(e, Event::Plan { .. })));
    let Some(Event::ApprovalRequest {
        id,
        detail,
        options,
        ..
    }) = ev
        .iter()
        .find(|e| matches!(e, Event::ApprovalRequest { .. }))
        .cloned()
    else {
        unreachable!()
    };
    assert_eq!(detail, "ls -la");
    assert_eq!(options.len(), 3);

    // F.5: attention carries the session and the state, and nothing else.
    let att = r.inbox.frame("attention").await.unwrap();
    let mut keys: Vec<&str> = att
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["sessionId", "state", "type"], "{att}");
    assert_eq!(att["state"], "needs_you");
    assert_eq!(att["sessionId"], session.to_string());

    // Nothing has answered the agent: not the host, not a timer.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let answered = |log: &str| {
        log_lines(log)
            .into_iter()
            .find(|m| m["id"] == "perm-1" && m.get("method").is_none())
    };
    assert!(answered(&log).is_none(), "{:?}", log_lines(&log));
    // The host refused the client method it never offered.
    assert!(log_lines(&log)
        .iter()
        .any(|m| m["id"] == "fs-1" && m["error"]["code"] == -32601));

    // The viewer's tap is refused, and reaches nobody.
    r.say(
        &mut p,
        pleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "yes"}),
        )],
    );
    assert!(
        r.pump(&mut p, pleg, |p| p
            .errors
            .contains(&"shell_input_not_held".to_owned()))
            .await
    );
    // An option the request did not offer is refused.
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "everything"}),
        )],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c
            .errors
            .contains(&"shell_approval_closed".to_owned()))
            .await
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(answered(&log).is_none());

    // The typist's tap.
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "yes"}),
        )],
    );
    assert!(
        r.pump(&mut c, cleg, |c| {
            let ev = events(c);
            ev.len() > 2
                && matches!(
                    ev.last(),
                    Some(Event::Status {
                        state: SessionState::Idle
                    })
                )
                && ev.iter().any(|e| matches!(e, Event::Diff { .. }))
        })
        .await,
        "{:?}",
        events(&c)
    );
    let a = answered(&log).expect("the tap reached the agent");
    assert_eq!(
        a["result"],
        json!({"outcome": {"outcome": "selected", "optionId": "yes"}})
    );
    let ev = events(&c);
    assert!(ev
        .iter()
        .any(|e| matches!(e, Event::ApprovalResolved { .. })));
    assert!(ev
        .iter()
        .any(|e| matches!(e, Event::ToolResult { text, .. } if text == "a.txt b.txt")));
    assert!(ev.iter().any(|e| matches!(e, Event::Diff { path, unified, .. } if path == "notes.md" && unified.contains("+two"))));
    let done = r
        .inbox
        .frame_where("attention", |v| v["state"] == "done")
        .await
        .unwrap();
    assert_eq!(done["sessionId"], session.to_string());

    // The viewer saw the same conversation.
    assert!(
        r.pump(&mut p, pleg, |p| has(p, |e| matches!(
            e,
            Event::Diff { .. }
        )))
        .await
    );

    // A device attaching now is shown it whole: the assistant's message as
    // one item, the tool call done, the status.
    let late = Device::phone(6, "Pixel");
    let late_deleg = r.delegation(&late, "phone");
    let mut l = r.client_for(late, session, "agent");
    let lleg = r.attach(&mut l, Some(late_deleg), true).await;
    assert!(
        r.pump(&mut l, lleg, |l| has(l, |e| matches!(
            e,
            Event::Status { .. }
        )))
        .await
    );
    let ev = events(&l);
    assert!(ev.iter().any(|e| matches!(e, Event::Message { text, append: false, .. } if text == "Listing files. Done.")), "{ev:?}");
    assert!(ev.iter().any(|e| matches!(
        e,
        Event::ToolCall {
            status: airdress_shell_proto::structured::ToolStatus::Done,
            ..
        }
    )));
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Event::ApprovalRequest { .. })),
        "an answered approval is gone"
    );

    // The terminal shows the agent's log and takes no input: stdio is the
    // protocol.
    assert!(
        r.pump(&mut c, cleg, |c| c.text().contains("fake agent: ready"))
            .await,
        "{}",
        c.text()
    );
    r.say(
        &mut c,
        cleg,
        &[Message::In {
            data: b"x".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c
            .errors
            .contains(&"shell_terminal_unavailable".to_owned()))
            .await
    );
}

/// F.4: the app-server shape — a prompt, a command approval answered by the
/// typist with the harness's own word, its result and the message.
#[tokio::test]
async fn app_server_an_approval_carries_the_human_s_decision() {
    let (mut r, log, _) = setup().await;
    let log = format!("{log}.app");
    let (mut c, cleg) = open_typist(&mut r, "app-server").await;
    // No "jsonrpc" member, and `initialized` follows `initialize`.
    let sent = log_lines(&log);
    assert!(sent.iter().all(|m| m.get("jsonrpc").is_none()), "{sent:?}");
    assert_eq!(sent[1]["method"], "initialized");
    r.say(
        &mut c,
        cleg,
        &[input(json!({"input": "prompt", "text": "run the tests"}))],
    );
    assert!(
        r.pump(&mut c, cleg, |c| has(c, |e| matches!(
            e,
            Event::ApprovalRequest { .. }
        )))
        .await,
        "{:?}",
        events(&c)
    );
    let Some(Event::ApprovalRequest { id, detail, .. }) = events(&c)
        .into_iter()
        .find(|e| matches!(e, Event::ApprovalRequest { .. }))
    else {
        unreachable!()
    };
    assert_eq!(detail, "cargo test");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !log_lines(&log).iter().any(|m| m["id"] == 900),
        "nobody answered for the human"
    );
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "accept"}),
        )],
    );
    assert!(
        r.pump(&mut c, cleg, |c| matches!(
            events(c).last(),
            Some(Event::Status {
                state: SessionState::Idle
            })
        ) && has(
            c,
            |e| matches!(e, Event::Message { text, .. } if text == "Tests pass.")
        ))
        .await,
        "{:?}",
        events(&c)
    );
    let a = log_lines(&log)
        .into_iter()
        .find(|m| m["id"] == 900)
        .unwrap();
    assert_eq!(a["result"], json!({"decision": "accept"}));
    assert!(has(&c, |e| matches!(
        e,
        Event::ToolResult {
            exit_code: Some(0),
            ..
        }
    )));
    assert!(r
        .inbox
        .frame_where("attention", |v| v["state"] == "done")
        .await
        .is_some());
}

/// F.3 (AC-7's host half against a stand-in): the HTTP + SSE server shape,
/// reached on the profile's own port with the per-session password the
/// host set, a permission answered by the typist's tap, the diff.
#[tokio::test]
async fn server_the_permission_reply_is_the_human_s_and_the_password_the_host_s() {
    let (mut r, log, _port) = setup().await;
    let log = format!("{log}.srv");
    let (mut c, cleg) = open_typist(&mut r, "server").await;
    // The terminal beside it is the server's own log.
    assert!(
        r.pump(&mut c, cleg, |c| c.text().contains("fake server listening"))
            .await
    );
    r.say(
        &mut c,
        cleg,
        &[input(json!({"input": "prompt", "text": "edit a.txt"}))],
    );
    assert!(
        r.pump(&mut c, cleg, |c| has(c, |e| matches!(
            e,
            Event::ApprovalRequest { .. }
        )))
        .await,
        "{:?}",
        events(&c)
    );
    let Some(Event::ApprovalRequest { id, detail, .. }) = events(&c)
        .into_iter()
        .find(|e| matches!(e, Event::ApprovalRequest { .. }))
    else {
        unreachable!()
    };
    assert_eq!(id, "per_1");
    assert_eq!(detail, "/w/a.txt");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replied = |log: &str| {
        log_lines(log).into_iter().find(|m| {
            m["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("/permission/"))
        })
    };
    assert!(replied(&log).is_none());
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "once"}),
        )],
    );
    assert!(
        r.pump(&mut c, cleg, |c| has(c, |e| matches!(
            e,
            Event::Diff { .. }
        )) && matches!(
            events(c).last(),
            Some(Event::Status {
                state: SessionState::Idle
            })
        ))
        .await,
        "{:?}",
        events(&c)
    );
    assert_eq!(replied(&log).unwrap()["body"], json!({"reply": "once"}));
    let lines = log_lines(&log);
    assert!(
        lines.iter().all(|m| m.get("auth").is_none()),
        "every request carried the session's password"
    );
    assert!(lines
        .iter()
        .any(|m| m["path"].as_str().is_some_and(|p| p.contains("directory="))));
    assert!(has(
        &c,
        |e| matches!(e, Event::Message { text, .. } if text == "edit a.txt")
    ));
    assert!(has(
        &c,
        |e| matches!(e, Event::Message { text, .. } if text == "Editing.")
    ));
    // This profile does not set `notify`: no attention reaches the operator.
    assert!(r.inbox.frame_where("attention", |_| true).await.is_none());
}

/// The plugin path (design §9.4, FR-K1–K3): a harness driven through its
/// own terminal reports through hooks on the host's event socket; a prompt
/// from the structured view is typed into its terminal as a paste; a
/// permission hook waits, and gets the typist's tap and nothing else.
#[tokio::test]
async fn terminal_harness_the_permission_hook_gets_the_human_s_answer() {
    let (mut r, _, _) = setup().await;
    let (mut c, cleg) = open_typist(&mut r, "term").await;
    r.say(
        &mut c,
        cleg,
        &[input(json!({"input": "prompt", "text": "build it"}))],
    );
    assert!(
        r.pump(&mut c, cleg, |c| has(c, |e| matches!(
            e,
            Event::ApprovalRequest { .. }
        )))
        .await,
        "{:?} {}",
        events(&c),
        c.text()
    );
    assert!(has(
        &c,
        |e| matches!(e, Event::Message { text, role: airdress_shell_proto::structured::Role::User, .. } if text == "build it")
    ));
    let Some(Event::ApprovalRequest { id, detail, .. }) = events(&c)
        .into_iter()
        .find(|e| matches!(e, Event::ApprovalRequest { .. }))
    else {
        unreachable!()
    };
    assert_eq!(detail, "make");
    assert_eq!(
        r.inbox.frame("attention").await.unwrap()["state"],
        "needs_you"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    r.pump(&mut c, cleg, |_| false).await;
    assert!(
        !c.text().contains("permission answer"),
        "the hook is still waiting: {}",
        c.text()
    );
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "approval_answer", "id": id, "option": "allow"}),
        )],
    );
    assert!(
        r.pump(&mut c, cleg, |c| matches!(
            events(c).last(),
            Some(Event::Status {
                state: SessionState::Idle
            })
        ) && has(
            c,
            |e| matches!(e, Event::Message { text, .. } if text == "Answered build it")
        ))
        .await,
        "{:?}",
        events(&c)
    );
    assert!(
        r.pump(&mut c, cleg, |c| c
            .text()
            .contains(r#"permission answer: {"decision": "allow"}"#))
            .await,
        "{}",
        c.text()
    );
    assert!(has(
        &c,
        |e| matches!(e, Event::ToolResult { text, .. } if text == "built")
    ));
    // The terminal is the session: it takes input as ever.
    r.say(
        &mut c,
        cleg,
        &[Message::In {
            data: b"\n".to_vec(),
        }],
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!c.errors.contains(&"shell_terminal_unavailable".to_owned()));
}

/// A hook call without the session's own token is not heard: no event, and
/// a permission hook is answered with nothing at once.
#[tokio::test]
async fn terminal_harness_a_hook_with_another_token_is_not_heard() {
    let (mut r, _, _) = setup().await;
    let cli = Device::cli(4, "laptop");
    let deleg = r.delegation(&cli, "cli");
    let mut c = r.client(cli, "term-wrong-token");
    let cleg = r.open(&mut c, "term-wrong-token", Some(deleg)).await;
    assert!(
        r.pump(&mut c, cleg, |c| c.text().contains("harness ready"))
            .await
    );
    r.say(
        &mut c,
        cleg,
        &[input(json!({"input": "prompt", "text": "x"}))],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c.text().contains("permission answer: {}"))
            .await,
        "{}",
        c.text()
    );
    assert!(events(&c).is_empty(), "{:?}", events(&c));
}

/// The real `opencode serve`, when `AIRDRESS_LIVE_HTTP_SERVER` names its
/// binary: the adapter against the server itself, not a stand-in. It sends
/// one harmless prompt to whatever model that opencode is configured for
/// (with none configured, opencode's own free default). Not in CI.
#[tokio::test]
#[ignore = "needs a real opencode; run by hand with AIRDRESS_LIVE_HTTP_SERVER=<path>"]
async fn live_http_server_a_turn_through_the_real_server() {
    let Ok(bin) = std::env::var("AIRDRESS_LIVE_HTTP_SERVER") else {
        return;
    };
    let port = free_port();
    let work = tempfile::tempdir().unwrap();
    let profiles = format!(
        r#"
[[profile]]
id = "oc"
label = "opencode"
kind = "harness:opencode"
program = "{bin}"
args = ["serve", "--hostname", "127.0.0.1", "--port", "{port}"]
cwd = "{cwd}"
structured = "opencode-server"
notify = true
env_allow = ["PATH", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]
"#,
        cwd = work.path().display()
    );
    let mut r = rig(&profiles, true).await;
    let cli = Device::cli(4, "laptop");
    let deleg = r.delegation(&cli, "cli");
    let mut c = r.client(cli, "oc");
    let cleg = r.open(&mut c, "oc", Some(deleg)).await;
    // A real server takes a while to come up the first time.
    let mut up = false;
    for _ in 0..9 {
        up = r
            .pump(&mut c, cleg, |c| {
                has(c, |e| matches!(e, Event::Status { .. }))
            })
            .await;
        if up {
            break;
        }
    }
    assert!(up, "the adapter came up: {:?}\n{}", events(&c), c.text());
    r.say(
        &mut c,
        cleg,
        &[input(
            json!({"input": "prompt", "text": "Reply with the single word: ok"}),
        )],
    );
    let mut ok = false;
    for _ in 0..12 {
        ok = r
            .pump(&mut c, cleg, |c| {
                has(c, |e| {
                    matches!(
                        e,
                        Event::Status {
                            state: SessionState::Working
                        }
                    )
                }) && matches!(
                    events(c).last(),
                    Some(Event::Status {
                        state: SessionState::Idle
                    })
                )
            })
            .await;
        if ok {
            break;
        }
    }
    for e in events(&c) {
        eprintln!("{}", serde_json::to_string(&e).unwrap());
    }
    assert!(ok, "a whole turn");
    assert!(has(&c, |e| matches!(
        e,
        Event::Message {
            role: airdress_shell_proto::structured::Role::Assistant,
            ..
        }
    )));
    assert_eq!(
        r.inbox
            .frame_where("attention", |v| v["state"] == "done")
            .await
            .unwrap()["state"],
        "done"
    );
}
