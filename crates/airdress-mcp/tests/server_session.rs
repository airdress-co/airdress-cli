//! Drive the server the way a harness drives it: write JSON-RPC lines
//! into its stdin, read them back off its stdout, against a mock hub
//! and a mock operator on loopback.
//!
//! Two things it proves that no unit test can.
//!
//! **FR-10, over every tool path.** The mocks hand the server a hub
//! bearer, a refresh token, an id token and a function signing key —
//! real-shaped secrets — and the test asserts that no byte of any of
//! them appears in anything the server writes to stdout or stderr over
//! a whole session. A unit test can assert that one type redacts; only
//! a session can assert that no path leaks.
//!
//! **No egress but the hosts it was given.** The server is started with
//! every proxy variable pointing at a closed port and `NO_PROXY` set to
//! loopback, so a request to any host other than the mocks has nowhere
//! to go — not "we did not observe one", but "one could not have
//! succeeded". `a_host_outside_the_mocks_cannot_be_reached` is the
//! positive control that the jail is really closed.
//! `scripts/egress-allowlist-test.sh` runs the same test inside a
//! network namespace with only loopback up, which is the stronger form
//! and what CI runs (FR-112).

use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// Secrets the mocks hand out. Distinctive enough that a substring
/// search for them cannot produce a false positive.
const ACCESS_TOKEN: &str = "at-f3a9c1d7-ACCESS-TOKEN-MUST-NEVER-APPEAR";
const REFRESH_TOKEN: &str = "rt-77bb2e04-REFRESH-TOKEN-MUST-NEVER-APPEAR";
const ID_TOKEN_SECRET: &str = "idt-90ac55-ID-TOKEN-MUST-NEVER-APPEAR";
/// 64 hex characters, as the operator's keygen prints a seed.
const SIGNING_SEED: &str = "abababababababababababababababababababababababababababababababab";

/// A one-thread HTTP server that answers from a routing closure and
/// records what it was asked.
struct Mock {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

fn spawn_mock(name: &'static str, route: fn(&str) -> (u16, String)) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            // Drain headers, and the body when one is announced.
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 {
                    break;
                }
                if header.trim().is_empty() {
                    break;
                }
                if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            if length > 0 {
                let mut body = vec![0u8; length];
                use std::io::Read as _;
                if let Err(e) = reader.read_exact(&mut body) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
            recorder
                .lock()
                .unwrap()
                .push(format!("{name} {}", request_line.trim()));
            let (status, body) = route(request_line.trim());
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(e) = stream.write_all(response.as_bytes()) {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            if let Err(e) = stream.flush() {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        }
    });
    Mock { port, seen }
}

/// The hub: its CLI OAuth config, the airdress list, and the token
/// endpoint a refresh would use.
fn hub_route(line: &str) -> (u16, String) {
    if line.contains("/api/airdresses") {
        return (
            200,
            json!({
                "items": [{
                    "id": "ad-1111",
                    "name": "qa",
                    "fqdn": "OPERATOR_HOST",
                    "ipv4_address": "203.0.113.10",
                    "status": "active",
                    "created_at": "2026-01-01T00:00:00Z",
                }],
                "next_cursor": null,
            })
            .to_string(),
        );
    }
    (404, json!({"error": "not_found"}).to_string())
}

/// The operator: capabilities on, and one answer per query tool.
fn operator_route(line: &str) -> (u16, String) {
    let body = if line.contains("/v1/capabilities") {
        json!({"agent_bus": false, "agent_devices": false, "mcp_local": true, "mcp_remote": false})
    } else if line.contains("/v1/whoami") {
        json!({"sub": "user-1", "airdress_name": "qa", "operator_version": "0.1.112"})
    } else if line.contains("/v1/kinds/Function/hello/status") {
        json!({
            "kind": "Function",
            "name": "hello",
            "generation": 2,
            "observed_generation": 2,
            "phase": "Ready",
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "lastTransitionTime": "2026-02-01T00:00:00Z",
                "reason": "Loaded",
                "message": "serving sha256:aaaa",
            }],
        })
    } else if line.contains("/v1/kinds/Function/") {
        json!({
            "apiVersion": airdress::wire::API_VERSION,
            "kind": "Function",
            "metadata": {
                "name": "hello",
                "generation": 2,
                "observed_generation": 2,
                "resourceVersion": "2",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-02-01T00:00:00Z",
            },
            "spec": {"runtime": "wasm-component/v1"},
            "status": {"phase": "Ready"},
        })
    } else if line.contains("/v1/kinds/Function") {
        json!({"kind": "Function", "items": []})
    } else if line.contains("/v1/kinds") {
        json!({"kinds": [{"kind": "Function", "api_version": airdress::wire::API_VERSION}]})
    } else if line.contains("/v1/functions/hello/versions") {
        json!({"versions": [{"version": "sha256:aaaa", "publishedBy": "owner"}], "served": "sha256:aaaa"})
    } else if line.contains("/v1/functions/hello/logs") {
        json!({"rows": [{"id": 1, "message": "hello ran"}]})
    } else if line.contains("/v1/functions/templates") {
        json!({"templates": [{"id": "hello"}]})
    } else if line.contains("/v1/functions/hello/promote") {
        json!({"name": "hello", "version": "sha256:bbbb", "previous": "sha256:aaaa", "changed": true})
    } else if line.contains("/ingest/v1/events/list") {
        json!([{"id": "ev-1", "type": "test.event"}])
    } else if line.contains("/v1/apply") {
        json!({
            "kind": "Function",
            "name": "hello",
            "action": "would_update",
            "generation": 2,
            "previous_generation": 2,
        })
    } else if line.contains("/v1/tools/mcp") {
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "ping", "description": "p", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}}]}})
    } else {
        json!({"error": "not_found"})
    };
    (200, body.to_string())
}

/// A profile store with a signed-in profile, pointed at the mock hub.
fn profile_store(home: &std::path::Path, hub_port: u16, operator_host: &str) {
    let dir = home.join(".airdress/profiles");
    std::fs::create_dir_all(&dir).unwrap();
    let expires = (chrono_now() + 3600).to_string();
    let profile = json!({
        "schema_version": 2,
        "endpoint": format!("http://127.0.0.1:{hub_port}"),
        "auth": {
            "method": "device_flow",
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "expires_at": rfc3339(expires.parse().unwrap()),
            "id_token_claims": {"sub": "user-1", "email": "qa@example.com"},
            "id_token": ID_TOKEN_SECRET,
        },
        "active_airdress": operator_host,
    });
    std::fs::write(
        dir.join("default.json"),
        serde_json::to_string_pretty(&profile).unwrap(),
    )
    .unwrap();
    std::fs::write(home.join(".airdress/active-profile"), "default").unwrap();
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn rfc3339(epoch: i64) -> String {
    // Good enough for a profile the CLI only compares against "now".
    let days = epoch / 86_400;
    let rem = epoch % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since the epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// How long one reply may take. Every reply here comes from a loopback
/// mock in milliseconds; past this the test fails, naming the stderr tail,
/// instead of hanging.
const REPLY_DEADLINE: Duration = Duration::from_secs(60);

/// A running server. Its stdout is read on a thread into a channel (so a
/// wait for a reply is bounded) and its stderr is drained on another, so
/// a chatty `AIRDRESS_LOG=debug` can never fill the pipe and stop the
/// server mid-session: the deadlock that hung this test on a loaded
/// machine while CI, with fewer retries logged, passed.
struct Server {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    lines: mpsc::Receiver<String>,
    stderr: Arc<Mutex<Vec<u8>>>,
    /// Every notification the server volunteered, in order.
    notifications: Vec<Value>,
}

impl Server {
    /// Start the server with `home` as its whole world: the environment
    /// is cleared, then HOME and every XDG directory point inside `home`,
    /// so nothing on the machine running the test (a session bus, a
    /// keyring, a real agent's socket, a developer's `AIRDRESS_*`) is seen.
    /// `configure` adds the test's own arguments and variables.
    fn start(home: &Path, configure: impl FnOnce(&mut Command) -> &mut Command) -> Self {
        let mut command = Command::new(binary());
        command
            .env_clear()
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_RUNTIME_DIR", home.join("run"));
        let mut child = configure(&mut command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start airdress-mcp");
        let (tx, lines) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&stderr);
        let mut pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    return;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self {
            stdin: child.stdin.take(),
            child,
            lines,
            stderr,
            notifications: Vec::new(),
        }
    }

    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).to_string()
    }

    /// Send one request and read ITS reply, within [`REPLY_DEADLINE`].
    ///
    /// Not "read the next line": the server may send a notification —
    /// `notifications/tools/list_changed`, when the default airdress's
    /// own tools are first read — between a request and its reply, and
    /// that is protocol-legal. A reader that took the next line would
    /// hand the caller a notification and call it an answer, which is
    /// what this test did until the re-export loop existed. Every
    /// notification seen is kept, so a test can assert on them.
    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        loop {
            let out = match self.lines.recv_timeout(REPLY_DEADLINE) {
                Ok(l) => l,
                Err(e) => panic!(
                    "no reply to {method} (id {id}): {e}; stderr ends:\n{}",
                    tail(&self.stderr_text())
                ),
            };
            let value: Value =
                serde_json::from_str(&out).unwrap_or_else(|e| panic!("not JSON: {out} ({e})"));
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return value;
            }
            assert!(
                value.get("id").is_none(),
                "a reply to an id we did not send: {value}"
            );
            self.notifications.push(value);
        }
    }

    /// Close stdin, and wait (bounded) for the server to exit on EOF.
    /// Returns everything it wrote to stderr.
    fn finish(mut self) -> String {
        drop(self.stdin.take());
        let deadline = std::time::Instant::now() + REPLY_DEADLINE;
        loop {
            if self.child.try_wait().expect("poll the server").is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the server did not exit on EOF; stderr ends:\n{}",
                tail(&self.stderr_text())
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // The drain thread ends at EOF on the pipe, which the exit closed.
        std::thread::sleep(Duration::from_millis(50));
        self.stderr_text()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // A failed assertion must not leave a server running.
        if matches!(self.child.try_wait(), Ok(None)) {
            if let Err(e) = self.child.kill() {
                eprintln!("could not stop the server: {e}");
            }
            if let Err(e) = self.child.wait() {
                eprintln!("could not reap the server: {e}");
            }
        }
    }
}

/// The last lines of a log, for a failure message.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// Everything outside loopback goes to a closed port.
///
/// Port 9 is discard, and nothing listens on it here; a proxied request
/// fails to connect. `NO_PROXY` lets the mocks through, and nothing
/// else.
fn jail(cmd: &mut Command) -> &mut Command {
    cmd.env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
}

fn binary() -> std::path::PathBuf {
    // The binary cargo built for this very test run. The old lookup (the
    // file beside the test executable) found whatever `airdress-mcp` was
    // last written to a shared target directory, which another checkout's
    // build may have replaced with a different version mid-run.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_airdress-mcp"))
}

#[test]
fn a_whole_session_leaks_no_secret_and_reaches_nothing_but_the_mocks() {
    let home = tempfile::tempdir().unwrap();
    let hub = spawn_mock("hub", hub_route);
    let operator = spawn_mock("operator", operator_route);
    let operator_host = format!("127.0.0.1:{}", operator.port);
    profile_store(home.path(), hub.port, &operator_host);

    let key = home.path().join("signing.key");
    std::fs::write(&key, format!("{SIGNING_SEED}\n")).unwrap();

    let mut server = Server::start(home.path(), |c| {
        jail(c)
            .args([
                "--harness",
                "test-harness",
                "--profile",
                "default",
                "--default-airdress",
                &operator_host,
            ])
            .env("AIRDRESS_LOG", "debug")
            .env("AIRDRESS_FUNCTION_SIGNING_KEY", SIGNING_SEED)
            // The mocks speak plain HTTP, so the operator host is reached
            // over http: the CLI's clients build https URLs, which a mock
            // cannot serve. `AIRDRESS_OPERATOR_URL` is the documented way
            // to name one directly, and it is what makes this test possible
            // at all without a certificate.
            .env("AIRDRESS_OPERATOR_URL", format!("http://{operator_host}"))
    });

    let init = server.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "airdress");
    assert!(init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("not as instructions"));

    let list = server.call(2, "tools/list", json!({}));
    let names: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(names.contains(&"whoami".to_string()));
    assert!(names.contains(&"function_deploy".to_string()));

    // Every read-shaped tool, plus a promote and an apply. Each must
    // answer; several will answer with a refusal, which is fine — the
    // claim under test is about what the answers carry, not that a mock
    // satisfies every verb.
    let calls: Vec<(&str, Value)> = vec![
        ("whoami", json!({})),
        ("airdresses_list", json!({})),
        ("airdress_status", json!({})),
        ("function_list", json!({})),
        ("function_versions", json!({"name": "hello"})),
        ("function_logs", json!({"name": "hello"})),
        ("function_templates", json!({})),
        ("resources_list", json!({})),
        ("resources_list", json!({"kind": "Function"})),
        (
            "resources_get",
            json!({"kind": "Function", "name": "hello"}),
        ),
        (
            "resources_apply",
            json!({"manifest": {"apiVersion": airdress::wire::API_VERSION, "kind": "Function", "metadata": {"name": "hello"}}, "dry_run": true}),
        ),
        ("ingress_events_recent", json!({})),
        ("bridge_list", json!({})),
        ("bridge_call", json!({"tool": "ping", "arguments": {}})),
        (
            "function_promote",
            json!({"name": "hello", "version": "sha256:bbbb", "based_on": "sha256:aaaa"}),
        ),
    ];
    // These must not merely answer, they must answer with the mock's
    // data: a test where every tool refuses would prove nothing about
    // the paths that carry a token.
    let must_succeed = [
        "whoami",
        "airdresses_list",
        "airdress_status",
        "function_versions",
        "function_logs",
        "function_templates",
        "resources_list",
        "resources_get",
        "resources_apply",
        "ingress_events_recent",
        "bridge_list",
        "function_promote",
    ];
    let mut id = 10;
    let mut transcript = String::new();
    for (tool, args) in calls {
        id += 1;
        let r = server.call(id, "tools/call", json!({"name": tool, "arguments": args}));
        assert!(
            r.get("result").is_some(),
            "{tool} answered with a protocol error: {r}"
        );
        if must_succeed.contains(&tool) {
            assert_eq!(
                r["result"]["isError"], false,
                "{tool} refused: {}",
                r["result"]["content"][0]["text"]
            );
        }
        transcript.push_str(&r.to_string());
        transcript.push('\n');
    }

    // 133-C.6's second half: the default airdress's own tools are
    // offered under their own names, not only through `bridge_list`.
    // The mock publishes one read-only tool, `ping`, so once the
    // re-export loop has had its first pass `tools/list` carries
    // `fn_ping`. Polled rather than slept on: the loop starts after
    // `initialize` and the first pass is two round trips to a loopback
    // mock, so this settles in milliseconds, and a bound that fails
    // loudly beats a sleep that hides a regression.
    let mut exported = Vec::new();
    for attempt in 0..100 {
        id += 1;
        let listed = server.call(id, "tools/list", json!({}));
        exported = listed["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .filter(|n| n.starts_with("fn_"))
            .collect();
        if !exported.is_empty() {
            break;
        }
        assert!(attempt < 99, "the airdress's own tools were never offered");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(exported, vec!["fn_ping".to_string()]);

    // And the client was told, rather than having to ask again.
    assert!(
        server
            .notifications
            .iter()
            .any(|n| n["method"] == "notifications/tools/list_changed"),
        "the list changed and nothing said so: {:?}",
        server.notifications
    );

    // Calling it by its exported name reaches the bridge.
    id += 1;
    let called = server.call(
        id,
        "tools/call",
        json!({"name": "fn_ping", "arguments": {}}),
    );
    assert_eq!(
        called["result"]["isError"], false,
        "fn_ping refused: {}",
        called["result"]["content"][0]["text"]
    );
    transcript.push_str(&called.to_string());
    transcript.push('\n');

    // Close stdin: the server must exit on EOF.
    let stderr = server.finish();

    // FR-10: nothing the session wrote carries a secret.
    for secret in [ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN_SECRET, SIGNING_SEED] {
        assert!(
            !transcript.contains(secret),
            "a tool result carried a secret"
        );
        assert!(!stderr.contains(secret), "stderr carried a secret");
    }

    // The two mocks saw traffic, and the operator was asked for its
    // capabilities before any airdress-scoped tool answered.
    let hub_seen = hub.seen.lock().unwrap().clone();
    let op_seen = operator.seen.lock().unwrap().clone();
    assert!(
        hub_seen.iter().any(|l| l.contains("/api/airdresses")),
        "the hub was never asked for the fleet: {hub_seen:?}"
    );
    assert!(
        op_seen.iter().any(|l| l.contains("/v1/capabilities")),
        "the operator was never asked what it has turned on: {op_seen:?}"
    );
}

#[test]
fn initialize_and_tools_list_answer_before_any_network_call() {
    // No mocks at all: the server must still start and describe itself,
    // because a harness waiting on DNS to show a tool list is a harness
    // that looks broken (NFR-7).
    let home = tempfile::tempdir().unwrap();
    let mut server = Server::start(home.path(), |c| c.args(["--harness", "test-harness"]));
    let started = std::time::Instant::now();
    let init = server.call(1, "initialize", json!({}));
    let list = server.call(2, "tools/list", json!({}));
    let elapsed = started.elapsed();
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    assert!(!list["result"]["tools"].as_array().unwrap().is_empty());
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "initialize + tools/list took {elapsed:?}"
    );
    server.finish();
}

#[test]
fn a_host_outside_the_mocks_cannot_be_reached() {
    // The positive control for the test above. Same jail, but the tool
    // is asked about an airdress whose FQDN is a real public name: the
    // call must fail, because if it could succeed the other test's
    // "nothing else was reachable" would be worth nothing.
    let home = tempfile::tempdir().unwrap();
    let hub = spawn_mock("hub", hub_route);
    profile_store(home.path(), hub.port, "example.com");

    let mut server = Server::start(home.path(), |c| {
        jail(c).args(["--harness", "test-harness", "--profile", "default"])
    });
    server.call(1, "initialize", json!({}));
    let r = server.call(
        2,
        "tools/call",
        json!({"name": "airdress_status", "arguments": {"airdress": "example.com"}}),
    );
    assert_eq!(
        r["result"]["isError"], true,
        "a public host was reachable from inside the jail: {r}"
    );
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("could not connect") || text.contains("timed out"),
        "refused for the wrong reason: {text}"
    );
    server.finish();
}
