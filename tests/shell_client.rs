//! The shell client end to end against a mock operator over real HTTP, with
//! the protocol crate's reference host behind it.
//!
//! The mock speaks the operator's routes (design §5.1) as the operator
//! builds them: the open, the legs, the P transport (server-sent events
//! down with `Last-Event-ID`, `POST …/frames` up), take-input and close. It
//! relays end-to-end records without reading them, as the operator does,
//! and hands them to the reference host. A cut leg is forgotten, as the
//! operator forgets a leg whose device went away.
//!
//! What is held here:
//!
//! - an open needs no prompt and spawns only after the CLI's `presence:
//!   none` record (D-30, the protocol crate's note N-2);
//! - typed input reaches the host, and output comes back in order;
//! - **resume on a network change (D.4):** legs cut mid-stream come back
//!   with the ticket, without a reattach, and the output equals the host's
//!   journal byte for byte — nothing lost, nothing repeated;
//! - a ticket past its 120 s ends in a silent reattach, still without loss;
//! - **take-over (AC-5's CLI half):** a CLI attach takes input from a phone,
//!   and the phone is told;
//! - the program's exit is the CLI's exit code.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use airdress_shell_proto::conformance::{RefClient, RefHost};
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::presence::{DeviceKeys, PresenceAlg};
use airdress_shell_proto::ticket::TicketId;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use airdress::shell_client::api::ShellApi;
use airdress::shell_client::run::{self, Command, Conn, Front, Outcome};
use airdress::shell_client::session::{ClientSession, Target};

const AIRDRESS: &str = "019e0000-test.a.airdr.es";
const MACHINE: &str = "7bcf8051-0000-4000-8000-000000000001";
const CLI: &str = "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11";
const PHONE: &str = "phone-1";
const PRINCIPAL: &str = "anna";

struct MockLeg {
    session: String,
    device: String,
    records: Vec<(u64, Vec<u8>)>,
    closed: Option<(u16, String)>,
}

struct State {
    host: RefHost,
    legs: HashMap<String, MockLeg>,
    current: HashMap<(String, String), String>,
    seq: u64,
    epoch: Instant,
    clock_offset: u64,
    /// `handshake` (IK) or `resume`, per attach, in order.
    attaches: Vec<&'static str>,
    /// When each `POST …/legs` arrived, answered or not.
    leg_posts: Vec<Instant>,
    /// Answer `POST …/legs` with `503 shell_host_offline` (the host's
    /// channel is down).
    offline: bool,
    /// Refuse a session the host does not hold as hosts before this fix
    /// did, with `shell_resume_expired`, which is not final on its own.
    legacy_refusal: bool,
    /// Answer `POST …/legs` with `410 shell_session_ended` and this reason.
    ended: Option<&'static str>,
    /// Answer this many `POST …/legs` with `429 shell_reconnect_throttled`
    /// and `Retry-After: 2`.
    throttle: u32,
    take_input: u32,
}

impl State {
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64 + self.clock_offset
    }

    fn new_leg(&mut self, session: &str, device: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.legs.insert(
            id.clone(),
            MockLeg {
                session: session.into(),
                device: device.into(),
                records: Vec::new(),
                closed: None,
            },
        );
        self.current
            .insert((session.into(), device.into()), id.clone());
        id
    }

    fn push(&mut self, leg: &str, rec: Vec<u8>) {
        self.seq += 1;
        let seq = self.seq;
        if let Some(l) = self.legs.get_mut(leg) {
            l.records.push((seq, rec));
        }
    }

    fn deliver(&mut self, out: Vec<airdress_shell_proto::conformance::Outbound>) {
        for o in out {
            if o.device == PHONE {
                phone_inbox().lock().unwrap().push((o.session, o.record));
                continue;
            }
            if let Some(leg) = self.current.get(&(o.session, o.device)).cloned() {
                self.push(&leg, o.record);
            }
        }
    }

    fn close(&mut self, leg: &str, code: u16, reason: &str) {
        if let Some(l) = self.legs.get_mut(leg) {
            l.closed = Some((code, reason.into()));
        }
    }

    /// The network takes the CLI's leg away: the operator forgets it and
    /// the host starts the ticket's clock.
    fn cut(&mut self, session: &str, device: &str) {
        if let Some(leg) = self.current.remove(&(session.into(), device.into())) {
            self.legs.remove(&leg);
        }
        let now = self.now();
        self.host.leg_dropped(session, device, now);
    }
}

type Inbox = Mutex<Vec<(String, Vec<u8>)>>;

fn phone_inbox() -> &'static Inbox {
    static INBOX: std::sync::OnceLock<Inbox> = std::sync::OnceLock::new();
    INBOX.get_or_init(|| Mutex::new(Vec::new()))
}

type Shared = Arc<Mutex<State>>;

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
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\n\
                 Content-Length: {}\r\n\r\n{b}",
                b.len()
            )
            .as_bytes(),
        )
        .await
    {
        eprintln!("best effort, the peer may have gone: {e}");
    }
    if let Err(e) = sock.shutdown().await {
        eprintln!("best effort, the peer may have gone: {e}");
    }
}

fn b64(raw: &str) -> Vec<u8> {
    STANDARD.decode(raw).expect("base64")
}

async fn handle(state: Shared, mut sock: TcpStream) {
    let Some(req) = read_req(&mut sock).await else {
        return;
    };
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer device-token"),
        "{} {}",
        req.method,
        req.path
    );
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let parts: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();
    match (req.method.as_str(), parts.as_slice()) {
        ("GET", ["v1", "shells"]) => {
            let pubkey = STANDARD.encode(state.lock().unwrap().host.public());
            respond(
                &mut sock,
                "200 OK",
                &json!({"hosts": [{"name": "dev", "machine": MACHINE, "ready": true,
                    "connected": true, "enabled": true, "shellKeyPublic": pubkey,
                    "profiles": [{"id": "sh", "label": "Shell", "kind": "shell", "state": "ready"}],
                    "sessions": []}]}),
            )
            .await;
        }
        ("POST", ["v1", "shells", "dev", "sessions"]) => {
            let (session, leg) = {
                let mut s = state.lock().unwrap();
                let session = body["session"]
                    .as_str()
                    .expect("a proposed session")
                    .to_owned();
                let now = s.now();
                let msg2 = s
                    .host
                    .open(
                        &session,
                        body["profile"].as_str().unwrap(),
                        CLI,
                        &b64(body["handshake"].as_str().unwrap()),
                        now,
                    )
                    .expect("the host takes the open");
                let leg = s.new_leg(&session, CLI);
                s.push(&leg, msg2);
                (session, leg)
            };
            respond(
                &mut sock,
                "202 Accepted",
                &json!({"session": session, "leg": leg}),
            )
            .await;
        }
        ("POST", ["v1", "shells", "sessions", id, "legs"]) => {
            let (offline, ended, throttled) = {
                let mut s = state.lock().unwrap();
                s.leg_posts.push(Instant::now());
                let throttled = s.throttle > 0;
                s.throttle = s.throttle.saturating_sub(1);
                (s.offline, s.ended, throttled)
            };
            if let Some(reason) = ended {
                respond(
                    &mut sock,
                    "410 Gone",
                    &json!({"error": {"code": "shell_session_ended",
                        "message": "this session has ended", "reason": reason}}),
                )
                .await;
                return;
            }
            if throttled {
                let b = json!({"error": {"code": "shell_reconnect_throttled"}}).to_string();
                if let Err(e) = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\
                             Content-Type: application/json\r\nContent-Length: {}\r\n\
                             Connection: close\r\n\r\n{b}",
                            b.len()
                        )
                        .as_bytes(),
                    )
                    .await
                {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
                return;
            }
            if offline {
                respond(
                    &mut sock,
                    "503 Service Unavailable",
                    &json!({"error": {"code": "shell_host_offline"}}),
                )
                .await;
                return;
            }
            let leg = {
                let mut s = state.lock().unwrap();
                let now = s.now();
                let leg = s.new_leg(id, CLI);
                let answer = if let Some(r) = body.get("resume") {
                    s.attaches.push("resume");
                    let ticket = TicketId::decode(r["ticketId"].as_str().unwrap()).unwrap();
                    s.host.resume(
                        id,
                        CLI,
                        &ticket,
                        &b64(r["handshake"].as_str().unwrap()),
                        now,
                    )
                } else {
                    s.attaches.push("handshake");
                    s.host
                        .attach(id, CLI, &b64(body["handshake"].as_str().unwrap()), now)
                };
                match answer {
                    Ok(msg2) => s.push(&leg, msg2),
                    // A session the host does not hold: the real host's
                    // answer is `session_ended`.
                    Err(_) if !s.host.spawned(id) => {
                        let code = if s.legacy_refusal {
                            "shell_resume_expired"
                        } else {
                            "session_ended"
                        };
                        s.close(&leg, 4001, code);
                    }
                    // The host's `refused` ends the leg with its code.
                    Err(e) => s.close(&leg, 4001, e.code()),
                }
                leg
            };
            respond(&mut sock, "202 Accepted", &json!({"leg": leg})).await;
        }
        ("POST", ["v1", "shells", "sessions", _, "input"]) => {
            state.lock().unwrap().take_input += 1;
            respond(&mut sock, "200 OK", &json!({"released": false})).await;
        }
        ("POST", ["v1", "shells", "legs", leg, "frames"]) => {
            let found = {
                let mut s = state.lock().unwrap();
                let found = s
                    .legs
                    .get(*leg)
                    .map(|l| (l.session.clone(), l.device.clone()));
                if let Some((session, device)) = &found {
                    for r in body["records"].as_array().unwrap() {
                        let now = s.now();
                        match s
                            .host
                            .record(session, device, &b64(r.as_str().unwrap()), now)
                        {
                            Ok(out) => s.deliver(out),
                            Err(e) => {
                                let leg = leg.to_string();
                                s.close(&leg, 4001, e.code());
                            }
                        }
                    }
                }
                found.is_some()
            };
            if !found {
                respond(
                    &mut sock,
                    "404 Not Found",
                    &json!({"error": {"code": "shell_leg_not_found"}}),
                )
                .await;
                return;
            }
            respond(&mut sock, "200 OK", &json!({"accepted": 1})).await;
        }
        ("GET", ["v1", "shells", "legs", leg, "events"]) => {
            let leg = leg.to_string();
            let mut after: u64 = req
                .headers
                .get("last-event-id")
                .and_then(|v| v.parse().ok())
                .unwrap_or(u64::MAX);
            if !state.lock().unwrap().legs.contains_key(&leg) {
                respond(
                    &mut sock,
                    "404 Not Found",
                    &json!({"error": {"code": "shell_leg_not_found"}}),
                )
                .await;
                return;
            }
            if after == u64::MAX {
                // No Last-Event-ID: nothing buffered is replayed (the
                // operator's behaviour); the client must ask from 0.
                after = state.lock().unwrap().seq;
            }
            if let Err(e) = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            loop {
                let (out, closed, gone) = {
                    let s = state.lock().unwrap();
                    match s.legs.get(&leg) {
                        None => (Vec::new(), None, true),
                        Some(l) => (
                            l.records
                                .iter()
                                .filter(|(q, _)| *q > after)
                                .cloned()
                                .collect::<Vec<_>>(),
                            l.closed.clone(),
                            false,
                        ),
                    }
                };
                if gone {
                    // Cut: the connection drops without a word.
                    return;
                }
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
                    state.lock().unwrap().legs.remove(&leg);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        }
        ("DELETE", ["v1", "shells", "sessions", id]) => {
            {
                let mut s = state.lock().unwrap();
                let now = s.now();
                let out = s.host.exit(id, 129, now).unwrap();
                s.deliver(out);
            }
            respond(&mut sock, "202 Accepted", &json!({})).await;
        }
        (m, p) => panic!("the mock has no route {m} {p:?}"),
    }
}

struct Harness {
    state: Shared,
    base: String,
    cli_keys: ShellKeypair,
}

/// The reference host as it comes up: no sessions, and the CLI trusted.
fn fresh_host() -> (RefHost, ShellKeypair) {
    let mut host = RefHost::new(b"host", AIRDRESS, MACHINE, PRINCIPAL);
    // The CLI's statement, as the host admits it: no presence key, under a
    // delegation of kind `cli`.
    let cli_keys = ShellKeypair::from_secret([0x42; 32]);
    let identity = SigningKey::from_bytes(&[0x43; 32]);
    let statement = DeviceKeys {
        device: CLI.into(),
        principal: PRINCIPAL.into(),
        identity_public: identity.verifying_key().to_bytes(),
        dh_public: *cli_keys.public(),
        presence_alg: PresenceAlg::None,
        presence_public: None,
    };
    let sig = statement.sign(&identity).unwrap();
    host.trust(&statement, &sig, "cli", "airdress CLI on desk")
        .unwrap();
    (host, cli_keys)
}

async fn harness() -> Harness {
    let (host, cli_keys) = fresh_host();
    let state = Arc::new(Mutex::new(State {
        host,
        legs: HashMap::new(),
        current: HashMap::new(),
        seq: 0,
        epoch: Instant::now(),
        clock_offset: 0,
        attaches: Vec::new(),
        leg_posts: Vec::new(),
        offline: false,
        legacy_refusal: false,
        ended: None,
        throttle: 0,
        take_input: 0,
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let st = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::spawn(handle(Arc::clone(&st), sock));
        }
    });
    Harness {
        state,
        base,
        cli_keys,
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn lines(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// The screen as the client drew it: a redraw replaces it (the
    /// reference host's snapshot is its journal), output appends.
    fn transcript(&self) -> Vec<u8> {
        let mut t = Vec::new();
        for v in self.lines() {
            match v["type"].as_str() {
                Some("redraw") => t = STANDARD.decode(v["data"].as_str().unwrap()).unwrap(),
                Some("output") => t.extend(STANDARD.decode(v["data"].as_str().unwrap()).unwrap()),
                _ => {}
            }
        }
        t
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn target(h: &Harness) -> Target {
    Target {
        airdress: AIRDRESS.into(),
        machine: MACHINE.into(),
        host_static: h.state.lock().unwrap().host.public(),
        profile: "sh".into(),
        device: CLI.into(),
    }
}

struct Running {
    session: String,
    tx: mpsc::Sender<Command>,
    out: Captured,
    task: tokio::task::JoinHandle<anyhow::Result<Outcome>>,
}

async fn open(h: &Harness) -> Running {
    let api = ShellApi::new(&h.base, &"device-token".into()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let cs = ClientSession::new(target(h), h.cli_keys.clone(), &session);
    let conn = Conn::open(api, "dev", cs, (100, 30)).await.unwrap();
    start(conn, session)
}

fn start(conn: Conn, session: String) -> Running {
    let (tx, rx) = mpsc::channel(64);
    let out = Captured::default();
    let mut front = Front::json(Box::new(out.clone()));
    let task = tokio::spawn(async move { run::run(conn, &mut front, rx).await });
    Running {
        session,
        tx,
        out,
        task,
    }
}

fn output(h: &Harness, session: &str, data: &[u8]) {
    let mut s = h.state.lock().unwrap();
    let now = s.now();
    let out = s.host.output(session, data, now).unwrap();
    s.deliver(out);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_needs_no_prompt_and_input_and_output_flow() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    assert_eq!(
        h.state.lock().unwrap().host.typist(&r.session).as_deref(),
        Some(CLI)
    );
    assert!(
        h.state.lock().unwrap().host.unlocks_verified.is_empty(),
        "a Linux CLI never unlocks"
    );
    r.tx.send(Command::Input(b"echo hi\r".to_vec()))
        .await
        .unwrap();
    eventually("the input", || {
        h.state.lock().unwrap().host.input(&r.session) == b"echo hi\r"
    })
    .await;
    output(&h, &r.session, b"hi\r\n$ ");
    eventually("the output", || r.out.transcript() == b"hi\r\n$ ").await;

    // The program exits: that is the CLI's exit code.
    let now = h.state.lock().unwrap().now();
    let out = h
        .state
        .lock()
        .unwrap()
        .host
        .exit(&r.session, 3, now)
        .unwrap();
    h.state.lock().unwrap().deliver(out);
    let outcome = r.task.await.unwrap().unwrap();
    assert_eq!(outcome.exit_code(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_changes_resume_without_a_reattach_and_lose_nothing() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    let mut n = 0u32;
    for round in 0..5 {
        for _ in 0..40 {
            n += 1;
            output(
                &h,
                &r.session,
                format!("line {n:05} {round}\r\n").as_bytes(),
            );
        }
        // The network changes in the middle of the stream: the leg is gone,
        // and what was in flight with it.
        h.state.lock().unwrap().cut(&r.session, CLI);
        for _ in 0..10 {
            n += 1;
            output(
                &h,
                &r.session,
                format!("line {n:05} {round} cut\r\n").as_bytes(),
            );
        }
        let resumes = round + 1;
        eventually("the resume", || {
            let s = h.state.lock().unwrap();
            s.attaches.iter().filter(|a| **a == "resume").count() >= resumes
                && s.current.contains_key(&(r.session.clone(), CLI.into()))
        })
        .await;
    }
    for _ in 0..20 {
        n += 1;
        output(&h, &r.session, format!("line {n:05} end\r\n").as_bytes());
    }
    let journal = h.state.lock().unwrap().host.journal(&r.session);
    eventually("every byte, once", || r.out.transcript() == journal).await;
    {
        let s = h.state.lock().unwrap();
        assert!(
            !s.attaches.contains(&"handshake"),
            "a cut under 120 s is a resume, never a reattach: {:?}",
            s.attaches
        );
        assert!(s.host.unlocks_verified.is_empty());
    }
    r.tx.send(Command::Detach).await.unwrap();
    assert_eq!(r.task.await.unwrap().unwrap(), Outcome::Detached);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_ticket_ends_in_a_silent_reattach() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    output(&h, &r.session, b"before\r\n");
    eventually("the output", || r.out.transcript() == b"before\r\n").await;
    {
        let mut s = h.state.lock().unwrap();
        s.cut(&r.session, CLI);
        // Past the ticket's 120 s.
        s.clock_offset += 121_000;
    }
    output(&h, &r.session, b"while away\r\n");
    eventually("the reattach", || {
        h.state.lock().unwrap().attaches.contains(&"handshake")
    })
    .await;
    output(&h, &r.session, b"after\r\n");
    let journal = h.state.lock().unwrap().host.journal(&r.session);
    eventually("the screen", || r.out.transcript() == journal).await;
    let s = h.state.lock().unwrap();
    assert_eq!(s.attaches.first(), Some(&"resume"), "{:?}", s.attaches);
    assert!(s.host.unlocks_verified.is_empty(), "no prompt on Linux");
    // The reattach took input back.
    assert_eq!(s.host.typist(&r.session).as_deref(), Some(CLI));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cli_attach_takes_input_from_the_phone_and_the_phone_is_told() {
    let h = harness().await;
    // The phone opens the session on the host directly.
    let session = "11111111-2222-4333-8444-555555555555";
    let pin = h.state.lock().unwrap().host.public();
    let mut phone = RefClient::new(b"phone", PHONE, PRINCIPAL, true, pin, AIRDRESS, MACHINE);
    {
        let mut s = h.state.lock().unwrap();
        let (keys, sig) = phone.statement();
        let (keys, sig) = (keys.clone(), *sig);
        s.host.trust(&keys, &sig, "phone", "Galaxy S23").unwrap();
        let now = s.now();
        let m1 = phone
            .begin(session, "sh", airdress_shell_proto::prologue::Action::Open)
            .unwrap();
        let m2 = s.host.open(session, "sh", PHONE, &m1, now).unwrap();
        let first = phone.finish(session, &m2, now).unwrap();
        let out = s.host.record(session, PHONE, &first, now).unwrap();
        s.deliver(out);
        assert_eq!(s.host.typist(session).as_deref(), Some(PHONE));
    }
    let api = ShellApi::new(&h.base, &"device-token".into()).unwrap();
    let cs = ClientSession::new(target(&h), h.cli_keys.clone(), session);
    let conn = Conn::attach(api, "dev", cs, (120, 40), true).await.unwrap();
    let r = start(conn, session.into());
    eventually("the take-over", || {
        h.state.lock().unwrap().host.typist(session).as_deref() == Some(CLI)
    })
    .await;
    assert!(
        h.state.lock().unwrap().take_input >= 1,
        "POST …/input first"
    );
    // The phone's records say input moved.
    let now = h.state.lock().unwrap().now();
    let mut told = false;
    for (s, rec) in phone_inbox().lock().unwrap().drain(..) {
        if s == session {
            phone
                .receive(session, &rec, now)
                .expect("a record from the host opens");
        }
    }
    if let Some(leg) = phone.leg(session) {
        told = leg.typist.as_deref() == Some(CLI) && leg.last_reason.is_some();
    }
    assert!(told, "the phone hears that input moved");
    // Input from the phone is now refused by the host.
    let rec = phone
        .send(
            session,
            &[airdress_shell_proto::inner::Message::In {
                data: b"x".to_vec(),
            }],
            now,
        )
        .unwrap();
    let out = h
        .state
        .lock()
        .unwrap()
        .host
        .record(session, PHONE, &rec, now);
    assert!(out.is_ok());
    assert!(h.state.lock().unwrap().host.input(session).is_empty());
    // The CLI attached with no prompt.
    assert!(!h
        .state
        .lock()
        .unwrap()
        .host
        .unlocks_verified
        .iter()
        .any(|(d, _)| d == CLI));
    r.tx.send(Command::Detach).await.unwrap();
    assert_eq!(r.task.await.unwrap().unwrap(), Outcome::Detached);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_ends_the_session() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    r.tx.send(Command::Close).await.unwrap();
    let outcome = r.task.await.unwrap().unwrap();
    assert_eq!(outcome, Outcome::Ended("closed".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_overview_reads() {
    let h = harness().await;
    let api = ShellApi::new(&h.base, &"device-token".into()).unwrap();
    let hosts = api.overview().await.unwrap();
    assert_eq!(hosts[0].name, "dev");
    assert_eq!(hosts[0].machine.as_deref(), Some(MACHINE));
    assert_eq!(hosts[0].profiles[0].id, "sh");
}

/// The lines a run said to the person, by kind.
fn said(out: &Captured, kind: &str) -> usize {
    out.lines().iter().filter(|v| v["type"] == kind).count()
}

/// After a host restart the session is gone. Found live on VM3 (2026-10-04):
/// two clients retried 373 times in about 15 s and never said the session
/// had ended. Now the ladder runs once — the ticket, the reattach — each
/// step after a wait, and the refused reattach ends the run with a reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_restart_ends_the_session_without_a_retry_storm() {
    // `session_ended` (this host) is final at the first step; the old
    // `shell_resume_expired` runs the ladder once: resume, then the
    // reattach, whose refusal is the end.
    for (legacy, ladder) in [
        (false, &["resume"][..]),
        (true, &["resume", "handshake"][..]),
    ] {
        let h = harness().await;
        h.state.lock().unwrap().legacy_refusal = legacy;
        let r = open(&h).await;
        eventually("the spawn", || {
            h.state.lock().unwrap().host.spawned(&r.session)
        })
        .await;
        output(&h, &r.session, b"before\r\n");
        eventually("the output", || r.out.transcript() == b"before\r\n").await;
        {
            let mut s = h.state.lock().unwrap();
            // The host restarts: same key, no sessions, and the leg is gone.
            s.host = fresh_host().0;
            s.cut(&r.session, CLI);
        }
        let outcome = tokio::time::timeout(Duration::from_secs(20), r.task)
            .await
            .expect("the run ends by itself")
            .unwrap()
            .unwrap();
        assert!(
            matches!(&outcome, Outcome::Ended(why) if why.starts_with("the session has ended")),
            "legacy {legacy}: {outcome:?}"
        );
        let s = h.state.lock().unwrap();
        assert_eq!(s.attaches, ladder, "legacy {legacy}: not a storm");
        // Each attempt waited: nothing back to back.
        for w in s.leg_posts.windows(2) {
            assert!(
                w[1] - w[0] >= Duration::from_millis(100),
                "{:?}",
                w[1] - w[0]
            );
        }
        assert_eq!(said(&r.out, "reconnecting"), 1, "said once, then the end");
    }
}

/// AC-13, the client's half: the host says it is stopping on the channel,
/// then the operator ends the leg. The person reads that the host stopped,
/// not "connection lost; reconnecting…", and nothing is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopping_host_is_said_and_ends_the_run_without_a_reconnect() {
    for close_reason in [Some("shell_host_stopping"), Some("peer_gone"), None] {
        let h = harness().await;
        let r = open(&h).await;
        eventually("the spawn", || {
            h.state.lock().unwrap().host.spawned(&r.session)
        })
        .await;
        {
            let mut s = h.state.lock().unwrap();
            let now = s.now();
            // The host's `host_stopping`, ahead of its frame to the
            // operator; its `exit` never gets through, because the operator
            // ends the leg on that frame.
            let out = s.host.announce_stop(10, now).unwrap();
            s.deliver(out);
        }
        eventually("the notice", || said(&r.out, "host_stopping") == 1).await;
        {
            let mut s = h.state.lock().unwrap();
            match close_reason {
                Some(reason) => {
                    let leg = s.current[&(r.session.clone(), CLI.to_owned())].clone();
                    s.close(&leg, 4001, reason);
                }
                // The leg just goes, without a word.
                None => s.cut(&r.session, CLI),
            }
        }
        let outcome = tokio::time::timeout(Duration::from_secs(10), r.task)
            .await
            .expect("the run ends")
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Ended(run::HOST_STOPPED.into()),
            "{close_reason:?}"
        );
        assert_eq!(said(&r.out, "reconnecting"), 0, "{close_reason:?}");
        assert!(
            h.state.lock().unwrap().leg_posts.is_empty(),
            "{close_reason:?}"
        );
    }
}

/// Every reconnect waits, longer each time, with jitter: a host that is
/// offline for a while is asked a handful of times, not hammered, and the
/// session comes back when it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_host_is_retried_with_backoff_and_resumed_when_back() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    {
        let mut s = h.state.lock().unwrap();
        s.offline = true;
        s.cut(&r.session, CLI);
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let posts = h.state.lock().unwrap().leg_posts.clone();
    assert!(
        (2..=6).contains(&posts.len()),
        "{} attempts in 4 s",
        posts.len()
    );
    let gaps: Vec<Duration> = posts.windows(2).map(|w| w[1] - w[0]).collect();
    for g in gaps.windows(2) {
        assert!(g[1] > g[0], "the waits grow: {gaps:?}");
    }
    h.state.lock().unwrap().offline = false;
    eventually("the resume", || {
        let s = h.state.lock().unwrap();
        s.attaches.contains(&"resume") && s.current.contains_key(&(r.session.clone(), CLI.into()))
    })
    .await;
    output(&h, &r.session, b"back\r\n");
    eventually("the output", || r.out.transcript().ends_with(b"back\r\n")).await;
    r.tx.send(Command::Detach).await.unwrap();
    assert_eq!(r.task.await.unwrap().unwrap(), Outcome::Detached);
}

/// The operator's `410 shell_session_ended {reason}` is final: one attempt,
/// and the person reads why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ended_session_answer_is_final_and_says_why() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    {
        let mut s = h.state.lock().unwrap();
        s.ended = Some("host_stopped");
        s.cut(&r.session, CLI);
    }
    let outcome = tokio::time::timeout(Duration::from_secs(10), r.task)
        .await
        .expect("the run ends")
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome,
        Outcome::Ended("the session has ended: its host stopped".into())
    );
    assert_eq!(h.state.lock().unwrap().leg_posts.len(), 1);
}

/// `429 shell_reconnect_throttled` with `Retry-After`: the next attempt
/// waits at least that long, and then the session resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_throttled_reconnect_waits_as_long_as_the_operator_asks() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    {
        let mut s = h.state.lock().unwrap();
        s.throttle = 1;
        s.cut(&r.session, CLI);
    }
    eventually("the resume", || {
        let s = h.state.lock().unwrap();
        s.attaches.contains(&"resume") && s.current.contains_key(&(r.session.clone(), CLI.into()))
    })
    .await;
    let posts = h.state.lock().unwrap().leg_posts.clone();
    assert_eq!(posts.len(), 2, "one refused, one resumed");
    assert!(
        posts[1] - posts[0] >= Duration::from_secs(2),
        "{:?}",
        posts[1] - posts[0]
    );
    output(&h, &r.session, b"back\r\n");
    eventually("the output", || r.out.transcript().ends_with(b"back\r\n")).await;
    r.tx.send(Command::Detach).await.unwrap();
    assert_eq!(r.task.await.unwrap().unwrap(), Outcome::Detached);
}

/// An operator that shuts down closes legs as `shutdown`: transient, so the
/// session resumes with its ticket, after a wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_shutdown_is_resumed_after() {
    let h = harness().await;
    let r = open(&h).await;
    eventually("the spawn", || {
        h.state.lock().unwrap().host.spawned(&r.session)
    })
    .await;
    {
        let mut s = h.state.lock().unwrap();
        let leg = s.current[&(r.session.clone(), CLI.to_owned())].clone();
        s.close(&leg, 4001, "shutdown");
        let now = s.now();
        s.host.leg_dropped(&r.session, CLI, now);
    }
    eventually("the resume", || {
        h.state.lock().unwrap().attaches.contains(&"resume")
    })
    .await;
    output(&h, &r.session, b"after shutdown\r\n");
    eventually("the output", || {
        r.out.transcript().ends_with(b"after shutdown\r\n")
    })
    .await;
    assert_eq!(said(&r.out, "reconnecting"), 1);
    r.tx.send(Command::Detach).await.unwrap();
    assert_eq!(r.task.await.unwrap().unwrap(), Outcome::Detached);
}
