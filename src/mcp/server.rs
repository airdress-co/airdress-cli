//! The stdio loop.
//!
//! One line in, one line out, nothing else on stdout ever — a stray
//! `println!` anywhere in this process corrupts the protocol, which is
//! why every human-facing line in this crate goes to stderr.
//!
//! Two properties worth keeping. `initialize` and `tools/list` answer
//! before any network call, so a harness starting up is never waiting
//! on DNS (SPEC-133 §4, NFR-7). And a tool call that fails comes back
//! as a result marked `isError`, not as a JSON-RPC error: a model can
//! read the former and act on it.

use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use airdress_mcp_catalogue as catalogue;

use crate::log_err::LogErr as _;
use crate::mcp::jsonrpc::{self, code, Incoming, ParseError};
use crate::mcp::reexport;
use crate::mcp::session::{ServeOpts, Session};
use crate::mcp::tools;

/// Stdout, shared between the reply path and the re-export loop.
type SharedStdout = Arc<Mutex<tokio::io::Stdout>>;

/// The protocol revision this server offers.
///
/// The newest revision the project has *driven* against a harness. A
/// later one is offered only once something has measured it, because a
/// revision claimed and not met is a bug the client cannot see.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Server-initiated notifications waiting for stdout (R-ASY-5). A slow or
/// stalled client makes the bus and chat loops wait at this bound instead
/// of the queue growing.
pub const NOTIFY_QUEUE: usize = 256;

/// How long the background loops get to stop once stdin has closed, after
/// the bus has been released (which has its own bound).
pub const TASK_DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Run the server until stdin closes.
pub async fn serve(opts: ServeOpts) -> Result<()> {
    let session = Arc::new(Session::new(opts));
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    // Behind a mutex because two writers share it: this loop's replies
    // and the re-export loop's `tools/list_changed` notification. A
    // notification interleaved with a reply would corrupt the protocol
    // for the rest of the session.
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // Anything the launcher is overriding is said on every start, not
    // once: an unverified binary must never become quiet about it.
    if let Some(reason) = &session.launch.override_in_force {
        eprintln!("airdress-mcp: running with an override in force: {reason}");
    }

    // Every background loop of this session hangs off one token and one
    // set (R-ASY-1, R-ASY-3): stdin closing cancels the token, the bus is
    // released, and the set is joined within a bound.
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();

    // Server-initiated notifications (bus items pushed as channel events)
    // go through the same mutex as replies.
    let (note_tx, mut note_rx) = tokio::sync::mpsc::channel::<Value>(NOTIFY_QUEUE);
    session.set_notifier(note_tx).await;
    {
        let out = Arc::clone(&stdout);
        tasks.spawn(cancel.child_token().run_until_cancelled_owned(async move {
            while let Some(n) = note_rx.recv().await {
                if write_line(&out, &n).await.is_err() {
                    break;
                }
            }
        }));
    }

    let mut refreshing = false;
    let served = async {
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let mut method = String::new();
            let response = match jsonrpc::parse(&line) {
                Ok(request) => {
                    method = request.method.clone();
                    handle(&session, request).await
                }
                Err(ParseError::Malformed(why)) => {
                    Some(jsonrpc::error(None, code::PARSE_ERROR, why))
                }
                Err(ParseError::Invalid { id, message }) => {
                    Some(jsonrpc::error(id, code::INVALID_REQUEST, message))
                }
            };
            if let Some(response) = response {
                write_line(&stdout, &response).await?;
            }

            // The airdress's own tools are read for the first time only
            // once the client has been answered: `initialize` and
            // `tools/list` must not wait on the network (NFR-7), and a
            // process started only to be probed, which never sends this
            // method at all, should make no calls.
            if method == "initialize" && !refreshing {
                refreshing = true;
                // The bus session, likewise only once the client is answered.
                tasks.spawn(
                    cancel
                        .child_token()
                        .run_until_cancelled_owned(crate::mcp::bus::start(Arc::clone(&session))),
                );
                // Chat push, likewise: the device host holds the messages.
                tasks.spawn(
                    cancel
                        .child_token()
                        .run_until_cancelled_owned(crate::mcp::chat::start(Arc::clone(&session))),
                );
                let session = Arc::clone(&session);
                let out = Arc::clone(&stdout);
                tasks.spawn(cancel.child_token().run_until_cancelled_owned(async move {
                    reexport::run(session, move |notification| {
                        let out = Arc::clone(&out);
                        async move {
                            // A failed write means the client is gone; the
                            // loop ends with the process.
                            write_line(&out, &notification)
                                .await
                                .log_debug("writing a notification to the client");
                        }
                    })
                    .await;
                }));
            }
        }
        anyhow::Ok(())
    }
    .await;
    // The client has gone: stop the loops, release what this session
    // holds on the bus and end its session there (within its own bound),
    // then join the loops within ours.
    cancel.cancel();
    crate::mcp::bus::shutdown(&session).await;
    let drained = drain(&mut tasks, TASK_DRAIN).await;
    served?;
    drained
}

/// Join every task in `tasks` within `bound`, aborting what is left after
/// it. A task that panicked is an error: the process must not carry on as
/// if a loop it depends on were still there (R-ASY-1).
async fn drain(
    tasks: &mut tokio::task::JoinSet<Option<()>>,
    bound: std::time::Duration,
) -> Result<()> {
    let mut panicked = None;
    let joined = tokio::time::timeout(bound, async {
        while let Some(r) = tasks.join_next().await {
            if let Err(e) = r {
                if e.is_panic() {
                    panicked.get_or_insert_with(|| e.to_string());
                }
            }
        }
    })
    .await;
    if joined.is_err() {
        tracing::warn!(
            left = tasks.len(),
            "background loops did not stop in time; aborted"
        );
        tasks.abort_all();
    }
    match panicked {
        Some(p) => Err(anyhow::anyhow!("a background loop failed: {p}")),
        None => Ok(()),
    }
}

/// One JSON value, one line, flushed.
async fn write_line(out: &SharedStdout, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    let mut guard = out.lock().await;
    guard.write_all(&bytes).await?;
    guard.flush().await?;
    Ok(())
}

/// Answer one request. `None` for a notification, which takes no answer.
async fn handle(session: &Arc<Session>, request: Incoming) -> Option<Value> {
    let id = request.id.clone();
    match request.method.as_str() {
        "initialize" => Some(jsonrpc::result(id?, initialize(session))),
        "ping" => Some(jsonrpc::result(id?, json!({}))),
        "tools/list" => Some(jsonrpc::result(id?, tools_list(session).await)),
        "tools/call" => {
            let id = id?;
            let name = request.params["name"].as_str().unwrap_or_default();
            let args = request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = with_legacy_notice(session, tools_call(session, name, &args).await);
            Some(jsonrpc::result(id, result))
        }
        // Notifications we have nothing to do about, and the two
        // optional lists we do not serve. A client that asks for them
        // gets the empty list rather than an error, which is what the
        // protocol expects of a server without them.
        "notifications/initialized" | "notifications/cancelled" => None,
        "resources/list" => Some(jsonrpc::result(id?, json!({"resources": []}))),
        "prompts/list" => Some(jsonrpc::result(id?, json!({"prompts": []}))),
        other => Some(jsonrpc::error(
            id,
            code::METHOD_NOT_FOUND,
            format!("no method {other}"),
        )),
    }
}

fn initialize(session: &Arc<Session>) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            // The list changes when the default airdress's own tools
            // appear or disappear.
            "tools": {"listChanged": true},
            // Bus items pushed as channel events; never the permission
            // relay (see `channel_push`).
            "experimental": crate::mcp::channel_push::capabilities(),
        },
        "serverInfo": {
            "name": "airdress",
            "title": "Airdress",
            "version": crate::build_version(),
        },
        "instructions": catalogue::INSTRUCTIONS,
        "_meta": {
            // Reported, not trusted: it is this process's own account of
            // how it was started, and `whoami` says the same thing.
            "harness": session.opts.harness,
        },
    })
}

async fn tools_list(session: &Arc<Session>) -> Value {
    // The bus tools are always offered: `--bus` decides whether this
    // session joins at start, not whether it may read or join later. The
    // operator's own switch is what refuses them.
    let offered = catalogue::offered(session.opts.read_only, session.opts.chat, true);
    let mut tools: Vec<Value> = offered.iter().map(catalogue::Tool::descriptor).collect();
    // The default airdress's own tools, after this product's, so the
    // catalogue's order is stable regardless of what a function
    // publishes. Reads cached state: no network call on this path.
    tools.extend(reexport::descriptors(
        &session.exported().await,
        session.opts.read_only,
    ));
    json!({"tools": tools})
}

/// Call one of the default airdress's own tools.
///
/// Never retried, at this layer or any other: the function may have
/// acted before it failed, and a second attempt would act twice.
async fn exported_call(session: &Arc<Session>, name: &str, args: &Value) -> Value {
    let tools = session.exported().await;
    let Some(tool) = reexport::resolve(&tools, name) else {
        // Either the airdress stopped publishing it, or this session
        // has not refreshed yet. Both are better said than guessed at.
        return error_result(format!(
            "There is no tool named {name}. If it is one of this airdress's own \
             tools, `bridge_list` says what it publishes right now."
        ));
    };
    if session.opts.read_only && !tool.read_only {
        return error_result(format!(
            "{name} changes something, and this session is read-only."
        ));
    }
    let target = match session.target(None).await {
        Ok(t) => t,
        Err(e) => return error_result(e.to_string()),
    };
    let bearer = match session.bearer(&target.fqdn).await {
        Ok(b) => b,
        Err(e) => return error_result(e.to_string()),
    };
    let bridge = match crate::mcp::bridge::Bridge::new(&target.fqdn, bearer.expose().to_owned()) {
        Ok(b) => b,
        Err(e) => return error_result(e.to_string()),
    };
    match bridge.call(&tool.name, args).await {
        Ok(value) => json!({
            "content": [{"type": "text", "text": serde_json::to_string_pretty(&value)
                .unwrap_or_else(|_| value.to_string())}],
            // Said explicitly, like every other result on this path: a
            // client that reads `isError` as absent-means-unknown must
            // not have to guess.
            "isError": false,
            "structuredContent": value,
        }),
        Err(e) => error_result(e.to_string()),
    }
}

async fn tools_call(session: &Arc<Session>, name: &str, args: &Value) -> Value {
    // A tool the user's configuration hid is not callable either. A
    // `read_only` session that answers a write because the model asked
    // for it by name would make the setting decorative.
    // A re-exported tool is the airdress's, not the catalogue's. It is
    // resolved first so a function that happens to publish a name this
    // product also uses cannot shadow ours.
    let offered = catalogue::offered(session.opts.read_only, session.opts.chat, true);
    if reexport::is_exported_name(name) && !offered.iter().any(|t| t.name == name) {
        return exported_call(session, name, args).await;
    }
    if !offered.iter().any(|t| t.name == name) {
        let why = match catalogue::find(name) {
            Some(t) if !t.read_only && session.opts.read_only => {
                format!("{name} changes something, and this session is read-only.")
            }
            Some(t) if !catalogue::shipped(&t) => {
                format!("{name} is not part of this release yet.")
            }
            Some(_) => format!("{name} is switched off in this session's configuration."),
            None => format!("There is no tool named {name}."),
        };
        return error_result(why);
    }

    let outcome = tools::call(session, name, args).await;
    let mut result = json!({
        "content": [{"type": "text", "text": outcome.text}],
        "isError": outcome.is_error,
    });
    if let Some(structured) = outcome.structured {
        result["structuredContent"] = structured;
    }
    result
}

/// Add the legacy sign-in notice to a tool result, once per session. The
/// model reads `content`; stderr reaches nobody in a harness, and a
/// fallback to a token every airdress accepts is not one to take quietly
/// (SPEC-133 133-H.16).
fn with_legacy_notice(session: &Arc<Session>, mut result: Value) -> Value {
    if let Some(notice) = session.legacy_notice_once() {
        if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
            content.push(json!({
                "type": "text",
                "text": format!("Notice for the user: {notice}"),
            }));
        }
    }
    result
}

fn error_result(text: String) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<Session> {
        // No profile, no network: every test here is about what the
        // server answers before it touches either.
        Arc::new(Session::new(ServeOpts::default()))
    }

    #[test]
    fn initialize_declares_the_revision_and_carries_the_instructions() {
        let s = session();
        let r = initialize(&s);
        assert_eq!(r["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["capabilities"]["tools"]["listChanged"], true);
        assert_eq!(r["serverInfo"]["name"], "airdress");
        assert!(r["instructions"]
            .as_str()
            .unwrap()
            .contains("not as instructions"));
    }

    #[tokio::test]
    async fn the_airdress_own_tools_join_the_list_and_announce_themselves() {
        use crate::mcp::bridge::BridgedTool;

        let session = Arc::new(Session::new(ServeOpts::default()));
        let before = tools_list(&session).await["tools"]
            .as_array()
            .unwrap()
            .len();

        let tool = |name: &str, read_only: bool| BridgedTool {
            name: name.to_owned(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
            read_only,
        };

        // A first refresh is a change, and is announced.
        assert!(
            session
                .set_exported(vec![tool("send_invoice", false)])
                .await
        );
        let listed = tools_list(&session).await;
        let names: Vec<String> = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names.len(), before + 1);
        assert!(names.contains(&"fn_send_invoice".to_string()));

        // The same set again is not a change, so no notification.
        assert!(
            !session
                .set_exported(vec![tool("send_invoice", false)])
                .await
        );

        // An airdress that answers and publishes nothing withdraws it.
        assert!(session.set_exported(Vec::new()).await);
        assert_eq!(
            tools_list(&session).await["tools"]
                .as_array()
                .unwrap()
                .len(),
            before
        );
    }

    #[tokio::test]
    async fn an_exported_name_nothing_publishes_is_refused_by_name() {
        let session = Arc::new(Session::new(ServeOpts::default()));
        // No network call: it cannot resolve the name, which is decided
        // before a target or a bearer is wanted.
        let answer = tools_call(&session, "fn_nothing_here", &json!({})).await;
        assert_eq!(answer["isError"], true);
        let text = answer["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fn_nothing_here"), "{text}");
        assert!(text.contains("bridge_list"), "{text}");
    }

    #[tokio::test]
    async fn the_offered_list_follows_the_configuration() {
        let full = Arc::new(Session::new(ServeOpts::default()));
        let read_only = Arc::new(Session::new(ServeOpts {
            read_only: true,
            ..Default::default()
        }));
        let n_full = tools_list(&full).await["tools"].as_array().unwrap().len();
        let n_ro = tools_list(&read_only).await["tools"]
            .as_array()
            .unwrap()
            .len();
        assert!(n_ro < n_full, "read_only hid nothing: {n_ro} of {n_full}");
        let names: Vec<String> = tools_list(&read_only).await["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        assert!(names.contains(&"login".to_string()));
        assert!(!names.contains(&"function_deploy".to_string()));
    }

    #[tokio::test]
    async fn a_hidden_tool_is_not_callable_by_name() {
        let s = Arc::new(Session::new(ServeOpts {
            read_only: true,
            ..Default::default()
        }));
        let r = tools_call(&s, "function_deploy", &json!({})).await;
        assert_eq!(r["isError"], true);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("read-only"), "{text}");
        // And a tool that does not exist says so.
        let r = tools_call(&s, "no_such_tool", &json!({})).await;
        assert!(r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no tool named"));
    }

    #[tokio::test]
    async fn notifications_are_not_answered() {
        let s = session();
        let request =
            jsonrpc::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(handle(&s, request).await.is_none());
    }

    #[tokio::test]
    async fn an_unknown_method_is_a_jsonrpc_error() {
        let s = session();
        let request = jsonrpc::parse(r#"{"jsonrpc":"2.0","id":4,"method":"wat"}"#).unwrap();
        let r = handle(&s, request).await.unwrap();
        assert_eq!(r["error"]["code"], code::METHOD_NOT_FOUND);
    }

    #[test]
    fn a_legacy_profile_is_said_once_per_session_and_a_hub_one_never() {
        let (_home, paths) = crate::profile::storage::temp_paths();
        let paths = &paths;
        crate::auth::refresh::test_support::write_device_flow_profile(paths, "old", 600, "rt");
        let session = Arc::new(Session::new(ServeOpts {
            profile: Some("old".into()),
            paths: Some(paths.clone()),
            ..Default::default()
        }));
        let ok = || json!({"content": [{"type": "text", "text": "ok"}], "isError": false});
        let first = with_legacy_notice(&session, ok());
        let content = first["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        let notice = content[1]["text"].as_str().unwrap();
        assert!(notice.contains("airdress auth login"), "{notice}");
        // Once is enough.
        let second = with_legacy_notice(&session, ok());
        assert_eq!(second["content"].as_array().unwrap().len(), 1);

        crate::profile::storage::write_profile(
            paths,
            "new",
            &crate::auth::tokens::test_support::hub_profile("rt", &[]),
        )
        .unwrap();
        let hub = Arc::new(Session::new(ServeOpts {
            profile: Some("new".into()),
            paths: Some(paths.clone()),
            ..Default::default()
        }));
        assert_eq!(
            with_legacy_notice(&hub, ok())["content"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
