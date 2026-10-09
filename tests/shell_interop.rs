//! This CLI's own shell-client session code against the real shell host,
//! through the host's test operator: the two halves of the end-to-end
//! protocol, written separately, agree on the prologue, the hello, the
//! CLI's `none` presence, the device-key statement, the records and the
//! inner messages.

use std::time::Duration;

use airdress::shell_client::api::ShellApi;
use airdress::shell_client::device::device_keys_statement;
use airdress::shell_client::recordings;
use airdress::shell_client::run::{self, Command, Conn, Front, Outcome};
use airdress::shell_client::session::{ClientSession, Event, Target};
use airdress_shell_host::channel::LinkTimings;
use airdress_shell_host::host::Timings;
use airdress_shell_host::paths::Paths;
use airdress_shell_host::run::{run_until, RunOptions};
use airdress_shell_host::testkit::{delegation, FromHost, Inbox, MockOperator};
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::prologue::Action;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn the_cli_client_opens_types_and_resumes_on_the_real_host() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    std::fs::create_dir_all(&paths.home).unwrap();
    std::fs::create_dir_all(paths.config_dir()).unwrap();
    std::fs::write(
        paths.profiles_file(),
        "[[profile]]\nid = \"cat\"\nprogram = \"/bin/cat\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            paths.profiles_file(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let (mock, rx) = MockOperator::start([42; 32]).await;
    let (machine, principal) = (Uuid::new_v4(), Uuid::new_v4());
    let root = SigningKey::from_bytes(&[7; 32]);
    mock.approve(machine, principal, Some(root.verifying_key().to_bytes()));
    let (_stop, stop_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(run_until(
        RunOptions {
            paths: paths.clone(),
            operator: Some(mock.origin.clone()),
            name: Some("interop".into()),
            ca_file: None,
            host_version: "test".into(),
            timings: Timings {
                tick: Duration::from_millis(50),
                ..Timings::default()
            },
            link: LinkTimings {
                retry_min: Duration::from_millis(100),
                ..LinkTimings::default()
            },
        },
        stop_rx,
    ));
    let mut inbox = Inbox::new(rx);
    let info = inbox.frame("host_info").await.unwrap();
    let host_static: [u8; 32] = STANDARD
        .decode(info["shellKeyPublic"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    // The CLI as a device: its identity, its shell key, its own statement.
    let device = Uuid::new_v4();
    let identity = SigningKey::from_bytes(&[3; 32]);
    let shell = ShellKeypair::from_secret([4; 32]);
    let sig = identity.sign(&device_keys_statement(&device, shell.public()));
    let attestation = json!({
        "device": device, "principal": principal, "deviceClass": "human", "deviceKind": "cli",
        "identityPublic": STANDARD.encode(identity.verifying_key().to_bytes()),
        "delegation": delegation(&root, &identity.verifying_key().to_bytes(), "127.0.0.1", "cli"),
        "dhPublic": STANDARD.encode(shell.public()), "presencePublic": null, "presenceAlg": "none",
        "keysSig": STANDARD.encode(sig.to_bytes()),
    });
    let session = Uuid::new_v4();
    let target = Target {
        airdress: "127.0.0.1".into(),
        machine: machine.to_string(),
        host_static,
        profile: "cat".into(),
        device: device.to_string(),
    };
    let mut cs = ClientSession::new(target, shell, &session.to_string());
    let leg = Uuid::new_v4();
    let msg1 = cs.begin(Action::Open, 80, 24).unwrap();
    mock.send("open", json!({ "sessionId": session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": attestation, "handshake": STANDARD.encode(msg1) }));
    let msg2 = inbox.record(leg).await.expect("msg2");
    let (hello, first) = cs.finish(&msg2, 0).unwrap();
    assert!(hello
        .profile_hash
        .as_deref()
        .is_some_and(|h| h.starts_with("sha256:")));
    for r in first {
        mock.send_data(session, leg, &r);
    }
    assert!(
        inbox.frame("opened").await.is_some(),
        "the host admitted the CLI's `none`"
    );
    let r = cs
        .seal(
            &[Message::In {
                data: b"interop\n".to_vec(),
            }],
            0,
        )
        .unwrap();
    mock.send_data(session, leg, &r);
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while String::from_utf8_lossy(&out).matches("interop").count() < 2 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let rec = inbox
            .take(left, |m| match m {
                FromHost::Data { leg: l, record, .. } if *l == leg => Some(record.clone()),
                _ => None,
            })
            .await
            .expect("output");
        let (events, replies) = cs.receive(&rec, 0).unwrap();
        for e in events {
            if let Event::Output(b) = e {
                out.extend(b);
            }
        }
        for r in replies {
            mock.send_data(session, leg, &r);
        }
    }
    // The leg drops; the CLI resumes with its ticket and no new handshake.
    mock.send(
        "detach",
        json!({ "sessionId": session, "leg": leg, "reason": "peer_gone" }),
    );
    inbox.frame("detached").await.unwrap();
    let leg2 = Uuid::new_v4();
    let (ticket, msg1) = cs.begin_resume().unwrap();
    mock.send("attach", json!({ "sessionId": session, "leg": leg2, "attestation": attestation, "resume": { "ticketId": ticket.encode(), "handshake": STANDARD.encode(msg1) } }));
    let msg2 = inbox.record(leg2).await.expect("resume msg2");
    let (_, first) = cs.finish(&msg2, 0).unwrap();
    for r in first {
        mock.send_data(session, leg2, &r);
    }
    let attached = inbox.frame("attached").await.unwrap();
    assert_eq!(attached["reason"], "resume");
    let r = cs
        .seal(
            &[Message::In {
                data: b"again\n".to_vec(),
            }],
            0,
        )
        .unwrap();
    mock.send_data(session, leg2, &r);
    // The host says who has input on a resume, then echoes.
    let mut seen = Vec::new();
    while !seen
        .iter()
        .any(|e| matches!(e, Event::Output(b) if String::from_utf8_lossy(b).contains("again")))
    {
        let rec = inbox.record(leg2).await.expect("echo after resume");
        let (events, _) = cs.receive(&rec, 0).unwrap();
        seen.extend(events);
    }
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::Roles { reason, .. } if reason == "resumed")),
        "{seen:?}"
    );
}

// ---------------------------------------------------------------------------
// The CLI's whole client — its HTTP calls, its legs, its run loop and its
// recordings commands — against the real host, through a bridge that speaks
// the operator's client routes (design §5.1) on one side and the host's
// channel (the test kit's operator) on the other. It relays records without
// reading them, and ends legs as the operator does.
// ---------------------------------------------------------------------------

mod bridge {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use airdress_shell_host::testkit::{FromHost, MockOperator};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    #[derive(Default)]
    struct Leg {
        records: Vec<(u64, Vec<u8>)>,
        closed: Option<(u16, String)>,
        session: Uuid,
    }

    #[derive(Default)]
    pub struct State {
        legs: HashMap<Uuid, Leg>,
        seq: u64,
        /// Every frame the host sent, in order.
        pub frames: Vec<Value>,
        /// End every leg of the host on its `host_stopping` frame, as
        /// operators before v0.1.117 did (VM3 ran one on 2026-10-04).
        pub end_legs_on_stopping: bool,
        /// Restarted, and the host has not listed its sessions since: an
        /// attach is `503 shell_host_offline`, as the operator answers.
        pub offline: bool,
    }

    impl State {
        fn close_where(&mut self, code: u16, reason: &str, pred: impl Fn(&Leg) -> bool) {
            for l in self.legs.values_mut().filter(|l| pred(l)) {
                l.closed.get_or_insert((code, reason.to_owned()));
            }
        }
    }

    pub struct Bridge {
        pub base: String,
        pub state: Arc<Mutex<State>>,
        mock: MockOperator,
    }

    impl Bridge {
        /// The operator restarts, as `systemctl restart` does: every leg
        /// ends `shutdown`, the host's channel drops, and until the host is
        /// back and has listed its sessions an attach is `503`.
        pub fn restart(&self) {
            {
                let mut s = self.state.lock().unwrap();
                s.offline = true;
                s.close_where(4001, "shutdown", |_| true);
            }
            self.mock.close(1012, "shutdown");
        }
    }

    /// Start the bridge in front of `mock`; `rx` is the host's side.
    pub async fn start(
        mock: MockOperator,
        mut rx: mpsc::UnboundedReceiver<FromHost>,
        attestation: Value,
    ) -> Bridge {
        let state = Arc::new(Mutex::new(State::default()));
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                let mut s = st.lock().unwrap();
                match m {
                    FromHost::Data { leg, record, .. } => {
                        s.seq += 1;
                        let seq = s.seq;
                        if let Some(l) = s.legs.get_mut(&leg) {
                            l.records.push((seq, record));
                        }
                    }
                    FromHost::Frame(v) => {
                        match v["type"].as_str().unwrap_or_default() {
                            "refused" => {
                                let leg: Uuid = v["leg"].as_str().unwrap().parse().unwrap();
                                let code = v["code"].as_str().unwrap_or("refused").to_owned();
                                if let Some(l) = s.legs.get_mut(&leg) {
                                    l.closed.get_or_insert((4001, code));
                                }
                            }
                            "sessions" => s.offline = false,
                            "host_stopping" if s.end_legs_on_stopping => {
                                s.close_where(4001, "shell_host_stopping", |_| true);
                            }
                            // As the operator: a session's end ends its legs,
                            // as stopped when the host said it was stopping.
                            "exited" => {
                                let stopping =
                                    s.frames.iter().any(|f| f["type"] == "host_stopping");
                                let reason = if stopping || v["reason"] == "host_stopped" {
                                    "shell_host_stopping"
                                } else {
                                    "session_ended"
                                };
                                let session = v["sessionId"].as_str().unwrap_or("").to_owned();
                                s.close_where(4001, reason, |l| l.session.to_string() == session);
                            }
                            _ => {}
                        }
                        s.frames.push(v);
                    }
                    FromHost::Closed(_) | FromHost::Protocol(_) => {}
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let st = Arc::clone(&state);
        let att = Arc::new(attestation);
        let m = mock.clone();
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                tokio::spawn(handle(Arc::clone(&st), m.clone(), Arc::clone(&att), sock));
            }
        });
        Bridge { base, state, mock }
    }

    struct Req {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    async fn read_req(sock: &mut TcpStream) -> Option<Req> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end = loop {
            let n = sock.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut first = lines.next()?.split(' ');
        let method = first.next()?.to_owned();
        let path = first.next()?.to_owned();
        let headers: HashMap<String, String> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < len {
            let n = sock.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Some(Req {
            method,
            path,
            headers,
            body,
        })
    }

    async fn respond(sock: &mut TcpStream, status: &str, body: &Value) {
        let b = body.to_string();
        if let Err(e) = sock
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                )
                .as_bytes(),
            )
            .await {
            eprintln!("best effort, the peer may have gone: {e}");
        }
    }

    fn new_leg(st: &Mutex<State>, session: Uuid) -> Uuid {
        let leg = Uuid::new_v4();
        st.lock().unwrap().legs.insert(
            leg,
            Leg {
                session,
                ..Leg::default()
            },
        );
        leg
    }

    async fn handle(
        st: Arc<Mutex<State>>,
        mock: MockOperator,
        att: Arc<Value>,
        mut sock: TcpStream,
    ) {
        let Some(req) = read_req(&mut sock).await else {
            return;
        };
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let parts: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
        match (req.method.as_str(), parts.as_slice()) {
            ("POST", ["v1", "shells", _, "sessions"]) => {
                let session: Uuid = body["session"].as_str().unwrap().parse().unwrap();
                let leg = new_leg(&st, session);
                mock.send(
                    "open",
                    json!({ "sessionId": session, "leg": leg, "profile": body["profile"],
                        "cols": body["cols"], "rows": body["rows"], "attestation": *att,
                        "handshake": body["handshake"] }),
                );
                respond(
                    &mut sock,
                    "202 Accepted",
                    &json!({"session": session, "leg": leg}),
                )
                .await;
            }
            ("POST", ["v1", "shells", "sessions", id, "legs"]) => {
                if st.lock().unwrap().offline {
                    respond(
                        &mut sock,
                        "503 Service Unavailable",
                        &json!({"error": {"code": "shell_host_offline"}}),
                    )
                    .await;
                    return;
                }
                let session: Uuid = id.parse().unwrap();
                let leg = new_leg(&st, session);
                let mut f = json!({ "sessionId": session, "leg": leg, "attestation": *att });
                if let Some(r) = body.get("resume") {
                    f["resume"] = r.clone();
                } else {
                    f["handshake"] = body["handshake"].clone();
                }
                mock.send("attach", f);
                respond(&mut sock, "202 Accepted", &json!({"leg": leg})).await;
            }
            ("POST", ["v1", "shells", "sessions", _, "input"]) => {
                respond(&mut sock, "200 OK", &json!({"released": false})).await;
            }
            ("POST", ["v1", "shells", "legs", leg, "frames"]) => {
                let leg: Uuid = leg.parse().unwrap();
                let session = st.lock().unwrap().legs.get(&leg).map(|l| l.session);
                let Some(session) = session else {
                    respond(
                        &mut sock,
                        "404 Not Found",
                        &json!({"error": {"code": "shell_leg_not_found"}}),
                    )
                    .await;
                    return;
                };
                for r in body["records"].as_array().unwrap() {
                    mock.send_data(session, leg, &STANDARD.decode(r.as_str().unwrap()).unwrap());
                }
                respond(&mut sock, "200 OK", &json!({"accepted": 1})).await;
            }
            ("GET", ["v1", "shells", "legs", leg, "events"]) => {
                let leg: Uuid = leg.parse().unwrap();
                let mut after: u64 = req
                    .headers
                    .get("last-event-id")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if !st.lock().unwrap().legs.contains_key(&leg) {
                    respond(
                        &mut sock,
                        "404 Not Found",
                        &json!({"error": {"code": "shell_leg_not_found"}}),
                    )
                    .await;
                    return;
                }
                if let Err(e) = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                    .await {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
                loop {
                    let (out, closed) = {
                        let s = st.lock().unwrap();
                        let Some(l) = s.legs.get(&leg) else { return };
                        (
                            l.records
                                .iter()
                                .filter(|(q, _)| *q > after)
                                .cloned()
                                .collect::<Vec<_>>(),
                            l.closed.clone(),
                        )
                    };
                    for (q, r) in out {
                        after = q;
                        let ev = format!("id: {q}\ndata: {}\n\n", STANDARD.encode(r));
                        if sock.write_all(ev.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    if let Some((code, reason)) = closed {
                        let ev = format!(
                            "event: closed\ndata: {}\n\n",
                            json!({"code": code, "reason": reason})
                        );
                        if let Err(e) = sock.write_all(ev.as_bytes()).await {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                        st.lock().unwrap().legs.remove(&leg);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            (m, p) => panic!("the bridge has no route {m} {p:?}"),
        }
    }
}

/// A host with `profiles`, enrolled with the test kit's operator; the CLI as
/// one device of its person; and the bridge in front.
struct Live {
    bridge: bridge::Bridge,
    api: ShellApi,
    target: Target,
    shell: ShellKeypair,
    device: Uuid,
    stop: tokio::sync::mpsc::Sender<()>,
    host: tokio::task::JoinHandle<anyhow::Result<i32>>,
    _dir: tempfile::TempDir,
}

async fn live(profiles: &str, profile: &str) -> Live {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    std::fs::create_dir_all(&paths.home).unwrap();
    std::fs::create_dir_all(paths.config_dir()).unwrap();
    std::fs::write(paths.profiles_file(), profiles).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            paths.profiles_file(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let (mock, mut rx) = MockOperator::start([42; 32]).await;
    let (machine, principal) = (Uuid::new_v4(), Uuid::new_v4());
    let root = SigningKey::from_bytes(&[7; 32]);
    mock.approve(machine, principal, Some(root.verifying_key().to_bytes()));
    let (stop, stop_rx) = tokio::sync::mpsc::channel(1);
    let host = tokio::spawn(run_until(
        RunOptions {
            paths: paths.clone(),
            operator: Some(mock.origin.clone()),
            name: Some("interop".into()),
            ca_file: None,
            host_version: "test".into(),
            timings: Timings {
                tick: Duration::from_millis(50),
                kill_after: Duration::from_secs(2),
                ..Timings::default()
            },
            link: LinkTimings {
                retry_min: Duration::from_millis(100),
                ..LinkTimings::default()
            },
        },
        stop_rx,
    ));
    // The host's key, from its first frame; then the bridge takes the rest.
    let host_static: [u8; 32] = loop {
        match rx.recv().await.expect("the host's channel") {
            FromHost::Frame(v) if v["type"] == "host_info" => {
                break STANDARD
                    .decode(v["shellKeyPublic"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            }
            _ => {}
        }
    };
    let device = Uuid::new_v4();
    let identity = SigningKey::from_bytes(&[3; 32]);
    let shell = ShellKeypair::from_secret([4; 32]);
    let sig = identity.sign(&device_keys_statement(&device, shell.public()));
    let attestation = json!({
        "device": device, "principal": principal, "deviceClass": "human", "deviceKind": "cli",
        "identityPublic": STANDARD.encode(identity.verifying_key().to_bytes()),
        "delegation": delegation(&root, &identity.verifying_key().to_bytes(), "127.0.0.1", "cli"),
        "dhPublic": STANDARD.encode(shell.public()), "presencePublic": null, "presenceAlg": "none",
        "keysSig": STANDARD.encode(sig.to_bytes()),
    });
    let bridge = bridge::start(mock, rx, attestation).await;
    let api = ShellApi::new(&bridge.base, &"device-token".into()).unwrap();
    Live {
        bridge,
        api,
        target: Target {
            airdress: "127.0.0.1".into(),
            machine: machine.to_string(),
            host_static,
            profile: profile.into(),
            device: device.to_string(),
        },
        shell,
        device,
        stop,
        host,
        _dir: dir,
    }
}

#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn lines(&self) -> Vec<serde_json::Value> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
    fn output(&self) -> String {
        let mut t = Vec::new();
        for v in self.lines() {
            if v["type"] == "output" || v["type"] == "redraw" {
                t.extend(STANDARD.decode(v["data"].as_str().unwrap()).unwrap());
            }
        }
        String::from_utf8_lossy(&t).into_owned()
    }
    fn said(&self, kind: &str) -> usize {
        self.lines().iter().filter(|v| v["type"] == kind).count()
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Open `profile` and run the session loop on it, as `airdress shell` does.
async fn run_session(
    l: &Live,
) -> (
    String,
    Captured,
    tokio::sync::mpsc::Sender<Command>,
    tokio::task::JoinHandle<anyhow::Result<Outcome>>,
) {
    let session = Uuid::new_v4().to_string();
    let cs = ClientSession::new(l.target.clone(), l.shell.clone(), &session);
    let conn = Conn::open(l.api.clone(), "dev", cs, (80, 24))
        .await
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let out = Captured::default();
    let mut front = Front::json(Box::new(out.clone()));
    let task = tokio::spawn(async move { run::run(conn, &mut front, rx).await });
    (session, out, tx, task)
}

/// AC-11's replay, end to end: `recordings play` lists on its connection
/// and then fetches on the same one. Live on VM3 (2026-10-04) it timed out
/// every time, and the host logged nothing: the fetch waited for a second
/// snapshot that never comes, so it was never sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recordings_play_lists_then_fetches_on_one_connection_from_the_real_host() {
    let l = live(
        "[[profile]]\nid = \"rec\"\nprogram = \"/bin/cat\"\nrecord = true\n",
        "rec",
    )
    .await;
    let (session, out, tx, task) = run_session(&l).await;
    eventually("connected", || out.said("connected") == 1).await;
    tx.send(Command::Input(b"recorded-line\n".to_vec()))
        .await
        .unwrap();
    eventually("the echo", || {
        out.output().matches("recorded-line").count() >= 2
    })
    .await;
    tx.send(Command::Detach).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap(), Outcome::Detached);
    // The recorder seals what it buffered every few seconds.
    tokio::time::sleep(Duration::from_secs(6)).await;

    // As `airdress shell recordings play <session>`: attach as a viewer,
    // list, then fetch — one connection.
    let cs = ClientSession::new(l.target.clone(), l.shell.clone(), &session);
    let mut conn = Conn::attach(l.api.clone(), "dev", cs, (80, 24), false)
        .await
        .unwrap();
    let listing = recordings::list(&mut conn).await.unwrap();
    let info = listing
        .iter()
        .find(|r| r.recording == session)
        .expect("the recording is listed");
    let (data, _complete) = tokio::time::timeout(
        Duration::from_secs(15),
        recordings::fetch(
            &mut conn,
            &session,
            info.segments,
            &l.device.to_string(),
            l.shell.secret(),
        ),
    )
    .await
    .expect("the host answers the fetch")
    .unwrap();
    let frames = recordings::parse_cast(&data).unwrap();
    let text: String = frames
        .iter()
        .map(|f| String::from_utf8_lossy(&f.data).into_owned())
        .collect();
    assert!(text.contains("recorded-line"), "{text:?}");
    drop(conn);
    l.stop.send(()).await.unwrap();
}

/// AC-13 end to end: Ctrl-C on the real host with this CLI attached. The
/// person reads that the host is stopping and the session ended; the CLI
/// does not say "connection lost; reconnecting…" and does not try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_the_real_host_ends_the_cli_session_and_says_so() {
    for end_legs_on_stopping in [false, true] {
        stop_case(end_legs_on_stopping).await;
    }
}

async fn stop_case(end_legs_on_stopping: bool) {
    let l = live("[[profile]]\nid = \"cat\"\nprogram = \"/bin/cat\"\n", "cat").await;
    l.bridge.state.lock().unwrap().end_legs_on_stopping = end_legs_on_stopping;
    let (_session, out, _tx, task) = run_session(&l).await;
    eventually("connected", || out.said("connected") == 1).await;
    l.stop.send(()).await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("the run ends")
        .unwrap()
        .unwrap();
    assert_eq!(outcome, Outcome::Ended(run::HOST_STOPPED.into()));
    assert_eq!(out.said("host_stopping"), 1);
    assert_eq!(out.said("reconnecting"), 0);
    // The host told the operator too, and ended the session as stopped.
    let frames = l.bridge.state.lock().unwrap().frames.clone();
    assert!(frames.iter().any(|f| f["type"] == "host_stopping"));
    assert!(frames
        .iter()
        .any(|f| f["type"] == "exited" && f["reason"] == "host_stopped"));
    assert_eq!(l.host.await.unwrap().unwrap(), 0);
}

/// An operator restart under an idle session (found live on VM3, v0.1.119,
/// 2026-10-05): the clients were told `503 shell_host_offline`, resumed on a
/// new leg once the host was back, and the host admitted the resume, but
/// then stayed on "reconnecting…" for minutes, refusing input as "not
/// connected". The host had nothing new to say (the session was idle and
/// every byte acknowledged), and the client counted itself live only once
/// it heard a record after message 2, so each waited for the other. Now the
/// resume's message 2 is enough, and the host says who has input.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_restart_under_an_idle_session_resumes_and_takes_input() {
    let l = live("[[profile]]\nid = \"cat\"\nprogram = \"/bin/cat\"\n", "cat").await;
    let (_session, out, tx, task) = run_session(&l).await;
    eventually("connected", || out.said("connected") == 1).await;
    tx.send(Command::Input(b"before-restart\n".to_vec()))
        .await
        .unwrap();
    eventually("the echo", || {
        out.output().matches("before-restart").count() >= 2
    })
    .await;
    // Idle: everything acknowledged before the restart.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let restarted = std::time::Instant::now();
    l.bridge.restart();
    eventually("reconnecting", || out.said("reconnecting") == 1).await;
    eventually("the host admitting the resume", || {
        l.bridge
            .state
            .lock()
            .unwrap()
            .frames
            .iter()
            .any(|f| f["type"] == "attached" && f["reason"] == "resume")
    })
    .await;
    eventually("reconnected", || out.said("reconnected") == 1).await;
    assert!(
        restarted.elapsed() < Duration::from_secs(5),
        "resumed {:?} after the restart",
        restarted.elapsed()
    );
    tx.send(Command::Input(b"after-restart\n".to_vec()))
        .await
        .unwrap();
    eventually("the echo after the restart", || {
        out.output().matches("after-restart").count() >= 2
    })
    .await;
    assert_eq!(out.said("dropped"), 0, "no input was refused");
    assert_eq!(out.said("reconnecting"), 1);
    tx.send(Command::Detach).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap(), Outcome::Detached);
    l.stop.send(()).await.unwrap();
}
