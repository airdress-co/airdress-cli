//! The test kit: devices that sign as real ones do, a client that speaks the
//! end-to-end protocol, and a mock operator that enrolls a host and carries
//! its frames over both transports. For the integration tests only; built
//! with the `testkit` feature, never shipped.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use airdress_shell_proto::handshake::{
    ticket_from_hello, Channel, DeviceHello, InitiatorHandshake,
};
use airdress_shell_proto::inner::{seal_rekey, Message};
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::presence::{presence_message, PresenceAlg};
use airdress_shell_proto::prologue::{Action, Prologue};
use airdress_shell_proto::ticket::TicketId;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::trust::{canonical_json, device_keys_statement, introduction_statement};

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

/// A device: an identity key, a shell key, and a presence key for a phone.
pub struct Device {
    pub id: Uuid,
    pub identity: SigningKey,
    pub shell: ShellKeypair,
    pub presence: Option<p256::ecdsa::SigningKey>,
    pub label: String,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl Device {
    fn new(seed: u8, phone: bool, label: &str) -> Self {
        let mut shell = [seed; 32];
        shell[0] = 0xAA;
        Self {
            id: Uuid::from_u128(0x0199_0000_0000_4000_8000_0000_0000_0000 | u128::from(seed)),
            identity: SigningKey::from_bytes(&[seed; 32]),
            shell: ShellKeypair::from_secret(shell),
            presence: phone.then(|| {
                let mut s = [seed; 32];
                s[0] = 0x11;
                p256::ecdsa::SigningKey::from_slice(&s).expect("a valid scalar")
            }),
            label: label.to_owned(),
        }
    }

    /// A phone: it unlocks.
    pub fn phone(seed: u8, label: &str) -> Self {
        Self::new(seed, true, label)
    }

    /// A Linux CLI: no presence key.
    pub fn cli(seed: u8, label: &str) -> Self {
        Self::new(seed, false, label)
    }

    pub fn identity_public(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }

    fn presence_point(&self) -> Option<Vec<u8>> {
        self.presence.as_ref().map(|p| {
            p.verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        })
    }

    /// The attestation the operator puts in `open` and `attach`, with this
    /// device's own signed statement.
    pub fn attestation(&self, principal: Uuid, delegation: Option<Value>) -> Value {
        let point = self.presence_point();
        let alg = if point.is_some() { "p256" } else { "none" };
        let st = device_keys_statement(self.id, self.shell.public(), alg, point.as_deref());
        json!({
            "device": self.id,
            "principal": principal,
            "deviceClass": "human",
            "deviceKind": if point.is_some() { "phone" } else { "cli" },
            "identityPublic": STANDARD.encode(self.identity_public()),
            "delegation": delegation,
            "dhPublic": STANDARD.encode(self.shell.public()),
            "presencePublic": point.map(|p| STANDARD.encode(p)),
            "presenceAlg": alg,
            "keysSig": STANDARD.encode(self.identity.sign(&st).to_bytes()),
            "label": self.label,
        })
    }

    /// This device as `GET /v1/shells/host/devices` lists it, with the
    /// operator's claim of its kind.
    pub fn listing(&self, kind: &str) -> Value {
        let fp = crate::trust::identity_fingerprint;
        json!({
            "device": self.id,
            "kind": kind,
            "label": self.label,
            "identityPublic": STANDARD.encode(self.identity_public()),
            "identityFingerprint": fp(&self.identity_public()),
            "shellKey": airdress_shell_proto::keys::fingerprint(self.shell.public()),
            "shellKeyPublic": STANDARD.encode(self.shell.public()),
            "presenceAlg": if self.presence.is_some() { "p256" } else { "none" },
            "createdAt": "2026-10-01T00:00:00Z",
            "lastSeenAt": null,
        })
    }

    /// This device introduces `other` as `kind`.
    pub fn introduce(&self, other: &Device, kind: &str) -> Value {
        let sig = self.identity.sign(&introduction_statement(
            self.id,
            other.id,
            &other.identity_public(),
            kind,
        ));
        json!({
            "device": other.id,
            "deviceKind": kind,
            "identityPublic": STANDARD.encode(other.identity_public()),
            "introducedBy": self.id,
            "sig": STANDARD.encode(sig.to_bytes()),
        })
    }
}

/// A root-signed delegation of `identity`, with `kind`.
pub fn delegation(root: &SigningKey, identity: &[u8; 32], airdress: &str, kind: &str) -> Value {
    let mut v = json!({
        "airdress": airdress,
        "device_session_public_key": URL_SAFE_NO_PAD.encode(identity),
        "issued_at": "2026-10-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "role": "human_held",
        "device_kind": kind,
    });
    let mut c = Vec::new();
    canonical_json(&v, &mut c);
    v["signature"] = Value::from(URL_SAFE_NO_PAD.encode(root.sign(&c).to_bytes()));
    v
}

// ---------------------------------------------------------------------------
// A client
// ---------------------------------------------------------------------------

/// One device's end of one session.
pub struct Client {
    pub dev: Device,
    host_pin: [u8; 32],
    airdress: String,
    machine: String,
    pub session: Uuid,
    profile: String,
    ch: Option<Channel>,
    pending: Option<(InitiatorHandshake, Action)>,
    ticket: Option<TicketId>,
    /// The screen as this client renders it.
    pub screen: vt100::Parser,
    /// The next output offset expected.
    pub offset: u64,
    pub typist: Option<String>,
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
    pub exit: Option<(Option<i32>, Option<i32>)>,
    pub host_stopping: bool,
    pub snapshots: u32,
    pub rekeys_seen: u32,
    pub other: Vec<Message>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("session", &self.session)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client of `dev` for `session` of `profile`, pinning `host_pin`.
    pub fn new(
        dev: Device,
        host_pin: [u8; 32],
        airdress: &str,
        machine: Uuid,
        session: Uuid,
        profile: &str,
    ) -> Self {
        Self {
            dev,
            host_pin,
            airdress: airdress.to_owned(),
            machine: machine.to_string(),
            session,
            profile: profile.to_owned(),
            ch: None,
            pending: None,
            ticket: None,
            screen: vt100::Parser::new(24, 80, 100),
            offset: 0,
            typist: None,
            reasons: Vec::new(),
            errors: Vec::new(),
            exit: None,
            host_stopping: false,
            snapshots: 0,
            rekeys_seen: 0,
            other: Vec::new(),
        }
    }

    fn prologue(&self, action: Action) -> Prologue {
        Prologue {
            airdress: self.airdress.clone(),
            machine_id: self.machine.clone(),
            session_id: self.session.to_string(),
            profile_id: self.profile.clone(),
            action,
        }
    }

    /// msg1 of an open or a reattach.
    pub fn begin(&mut self, action: Action) -> Vec<u8> {
        let hello = DeviceHello {
            device: self.dev.id.to_string(),
            cols: Some(80),
            rows: Some(24),
            client_version: Some("testkit".into()),
        };
        let (hs, m1) = InitiatorHandshake::start(
            &mut rand::rngs::OsRng,
            &self.dev.shell,
            &self.host_pin,
            &self.prologue(action),
            &hello,
        )
        .expect("msg1");
        self.pending = Some((hs, action));
        m1
    }

    /// The ticket id and msg1 of a resume.
    pub fn begin_resume(&mut self) -> (String, Vec<u8>) {
        let secret = *self
            .ch
            .as_ref()
            .expect("a channel to resume")
            .resume_secret();
        let ticket = self.ticket.expect("a ticket");
        let hello = DeviceHello {
            device: self.dev.id.to_string(),
            cols: None,
            rows: None,
            client_version: None,
        };
        let (hs, m1) = InitiatorHandshake::start_resume(
            &mut rand::rngs::OsRng,
            &self.dev.shell,
            &self.host_pin,
            &self.prologue(Action::Resume),
            &secret,
            &hello,
        )
        .expect("resume msg1");
        self.pending = Some((hs, Action::Resume));
        (ticket.encode(), m1)
    }

    /// Read msg2; returns the first record (an unlock, a CLI's `none`, or a
    /// resume's ack).
    pub fn finish(&mut self, msg2: &[u8]) -> Vec<u8> {
        self.finish_with(msg2, true)
    }

    /// As [`Client::finish`]; `unlock = false` makes a phone skip it.
    pub fn finish_with(&mut self, msg2: &[u8], unlock: bool) -> Vec<u8> {
        let (hs, action) = self.pending.take().expect("a handshake");
        let (mut ch, hello) = hs.finish(msg2, 0).expect("msg2");
        self.ticket = Some(ticket_from_hello(&hello).expect("ticket"));
        let first = match action {
            Action::Resume => Message::Ack {
                offset: self.offset,
            },
            a => {
                let (alg, sig) = match (&self.dev.presence, unlock) {
                    (Some(pk), true) => {
                        use p256::ecdsa::signature::Signer as _;
                        let s: p256::ecdsa::Signature =
                            pk.sign(&presence_message(ch.handshake_hash(), a).expect("msg"));
                        (PresenceAlg::P256, Some(s.to_der().as_bytes().to_vec()))
                    }
                    (Some(_), false) | (None, _) => (PresenceAlg::None, None),
                };
                Message::Presence {
                    action: a,
                    alg,
                    sig,
                }
            }
        };
        let rec = ch.seal(&first.encode().expect("encode"), 0).expect("seal");
        self.ch = Some(ch);
        rec
    }

    /// Seal messages.
    pub fn send(&mut self, msgs: &[Message]) -> Vec<u8> {
        let ch = self.ch.as_mut().expect("a channel");
        ch.seal(&Message::encode_all(msgs).expect("encode"), 0)
            .expect("seal")
    }

    /// Open a record from the host. Returns records to send back.
    pub fn receive(
        &mut self,
        record: &[u8],
    ) -> Result<Vec<Vec<u8>>, airdress_shell_proto::ProtoError> {
        let ch = self.ch.as_mut().expect("a channel");
        let (_, pt) = ch.open(record)?;
        let mut replies = Vec::new();
        for m in Message::decode_all(&pt)? {
            match m {
                Message::Out { offset, data } => {
                    if offset + data.len() as u64 > self.offset && offset <= self.offset {
                        let skip = (self.offset - offset) as usize;
                        self.screen.process(&data[skip..]);
                        self.offset = offset + data.len() as u64;
                    }
                }
                Message::Snapshot {
                    offset,
                    cols,
                    rows,
                    data,
                } => {
                    self.screen = vt100::Parser::new(rows, cols, 100);
                    self.screen.process(&data);
                    self.offset = offset;
                    self.snapshots += 1;
                }
                Message::Roles { typist, reason, .. } => {
                    self.typist = typist;
                    self.reasons.push(reason);
                }
                Message::Exit { code, signal } => self.exit = Some((code, signal)),
                Message::HostStopping { .. } => self.host_stopping = true,
                Message::Error { code, .. } => self.errors.push(code),
                Message::Rekey { switch_at, request } => {
                    self.rekeys_seen += 1;
                    ch.note_peer_rekey(switch_at);
                    if request {
                        replies.push(seal_rekey(ch, false, 0)?);
                    }
                }
                other => self.other.push(other),
            }
        }
        Ok(replies)
    }

    /// The screen's text.
    pub fn text(&self) -> String {
        self.screen.screen().contents()
    }

    /// Forget the channel (a revoked or detached device).
    pub fn forget(&mut self) {
        self.ch = None;
        self.ticket = None;
    }
}

// ---------------------------------------------------------------------------
// A mock operator
// ---------------------------------------------------------------------------

/// What the host sent.
#[derive(Debug, Clone, PartialEq)]
pub enum FromHost {
    Frame(Value),
    Data {
        session: Uuid,
        leg: Uuid,
        record: Vec<u8>,
    },
    /// The host closed the channel, with a code when it gave one.
    Closed(Option<u16>),
    /// The mock refused a frame as the operator does, and closed the
    /// channel 4009.
    Protocol(String),
}

#[derive(Debug)]
enum Down {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String),
}

#[derive(Debug)]
struct Chan {
    id: Uuid,
    seq: u64,
    ws: Option<mpsc::UnboundedSender<Down>>,
    poll: Option<mpsc::UnboundedSender<String>>,
    buffered: VecDeque<(u64, String)>,
    transport: &'static str,
}

#[derive(Debug)]
struct Inner {
    key: SigningKey,
    origin: String,
    decided: Option<Value>,
    enroll_key: Option<[u8; 32]>,
    purpose: Option<String>,
    chan: Option<Chan>,
    refuse_ws: bool,
    keyids: Vec<String>,
    from_host: mpsc::UnboundedSender<FromHost>,
    frame_max: u64,
    /// What `GET /v1/shells/host/devices` lists.
    devices: Vec<Value>,
    /// How many times the host asked for that list.
    devices_asked: u32,
}

/// An operator in a test: it enrolls a shell host and carries its channel.
#[derive(Clone)]
pub struct MockOperator {
    pub addr: SocketAddr,
    pub origin: String,
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for MockOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockOperator")
            .field("addr", &self.addr)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn signed(key: &SigningKey, ch: &mut Chan, frame_type: &str, mut fields: Value) -> (u64, String) {
    ch.seq += 1;
    fields["session"] = Value::from(ch.id.to_string());
    fields["seq"] = Value::from(ch.seq);
    fields["notAfter"] = Value::from(now_unix() + 60);
    let frame = fields.to_string();
    let sig = URL_SAFE_NO_PAD.encode(
        key.sign(&crate::frames::signed_bytes(frame_type, &frame))
            .to_bytes(),
    );
    (
        ch.seq,
        json!({ "type": frame_type, "frame": frame, "sig": sig }).to_string(),
    )
}

impl MockOperator {
    /// Start one on a loopback port. Frames from the host arrive on the
    /// receiver.
    pub async fn start(key_seed: [u8; 32]) -> (Self, mpsc::UnboundedReceiver<FromHost>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let origin = format!("http://{addr}");
        // The test kit (never in a shipped build) is a mock operator whose
        // sends happen under a std lock, where nothing can wait for room;
        // its test drains the queue (R-ASY-5 bounds shipped code).
        #[expect(
            clippy::disallowed_methods,
            reason = "test kit: sent from under a std lock, drained by the test"
        )]
        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(Inner {
            key: SigningKey::from_bytes(&key_seed),
            origin: origin.clone(),
            decided: None,
            enroll_key: None,
            purpose: None,
            chan: None,
            refuse_ws: false,
            keyids: Vec::new(),
            from_host: tx,
            frame_max: 65_536,
            devices: Vec::new(),
            devices_asked: 0,
        }));
        let app = axum::Router::new()
            .route("/v1/machines/enroll", post(enroll))
            .route("/v1/machines/enroll/poll", post(enroll_poll))
            .route(crate::channel::SESSION_PATH, get(session))
            .route(crate::channel::POLL_PATH, post(poll))
            .route(crate::channel::FRAMES_PATH, post(frames))
            .route(crate::roster::DEVICES_PATH, get(person_devices))
            .with_state(Arc::clone(&inner));
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        });
        (
            Self {
                addr,
                origin,
                inner,
            },
            rx,
        )
    }

    /// The operator's frame-signing key.
    pub fn public(&self) -> [u8; 32] {
        self.inner.lock().unwrap().key.verifying_key().to_bytes()
    }

    /// Approve the next enrollment, binding it to `principal`.
    pub fn approve(&self, machine: Uuid, principal: Uuid, root: Option<[u8; 32]>) {
        let mut g = self.inner.lock().unwrap();
        let op = g.key.verifying_key().to_bytes();
        g.decided = Some(json!({
            "machine_id": machine,
            "kid": "k-test",
            "authorized_until": "2099-01-01T00:00:00Z",
            "principal": { "id": principal, "displayName": "Anna" },
            "rootPublicKey": root.map(|r| STANDARD.encode(r)),
            "operatorKey": { "kid": "k-op", "publicKey": STANDARD.encode(op) },
        }));
    }

    /// What the operator lists as the person's devices.
    pub fn set_devices(&self, devices: Vec<Value>) {
        self.inner.lock().unwrap().devices = devices;
    }

    /// How many times the host asked for its person's devices.
    pub fn devices_asked(&self) -> u32 {
        self.inner.lock().unwrap().devices_asked
    }

    /// The purpose the host enrolled with.
    pub fn purpose(&self) -> Option<String> {
        self.inner.lock().unwrap().purpose.clone()
    }

    /// The keyids the host signed its channel requests with.
    pub fn keyids(&self) -> Vec<String> {
        self.inner.lock().unwrap().keyids.clone()
    }

    /// Refuse the WebSocket upgrade (a proxy that does not upgrade).
    pub fn refuse_ws(&self, refuse: bool) {
        self.inner.lock().unwrap().refuse_ws = refuse;
    }

    /// The transport of the live channel.
    pub fn transport(&self) -> Option<&'static str> {
        self.inner
            .lock()
            .unwrap()
            .chan
            .as_ref()
            .map(|c| c.transport)
    }

    /// Send a signed frame to the host.
    pub fn send(&self, frame_type: &str, fields: Value) {
        let mut g = self.inner.lock().unwrap();
        let key = g.key.clone();
        let Some(ch) = g.chan.as_mut() else {
            panic!("no channel")
        };
        let (seq, line) = signed(&key, ch, frame_type, fields);
        if let Some(ws) = &ch.ws {
            if let Err(e) = ws.send(Down::Text(line)) {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        } else if let Some(p) = &ch.poll {
            ch.buffered.push_back((seq, line.clone()));
            if let Err(e) = p.send(line + "\n") {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        }
    }

    /// Send one record to the host for a leg.
    pub fn send_data(&self, session: Uuid, leg: Uuid, record: &[u8]) {
        let ws = {
            let g = self.inner.lock().unwrap();
            g.chan.as_ref().and_then(|c| c.ws.clone())
        };
        match ws {
            Some(ws) => {
                if let Err(e) = ws.send(Down::Binary(crate::frames::data_frame(
                    session, leg, record,
                ))) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
            None => self.send(
                "data",
                json!({ "sessionId": session, "leg": leg, "records": [STANDARD.encode(record)] }),
            ),
        }
    }

    /// End the channel with a code.
    pub fn close(&self, code: u16, reason: &str) {
        let g = self.inner.lock().unwrap();
        if let Some(ch) = &g.chan {
            if let Some(ws) = &ch.ws {
                if let Err(e) = ws.send(Down::Close(code, reason.into())) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            } else if let Some(p) = &ch.poll {
                if let Err(e) = p.send(
                    json!({ "type": "closed", "code": code, "reason": reason }).to_string() + "\n",
                ) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
        }
    }
}

type St = State<Arc<Mutex<Inner>>>;

fn answer_message(origin: &str, user_code: &str, machine_key: &[u8; 32]) -> Vec<u8> {
    let mut m = b"airdress-machine-enroll-answer-v1\0".to_vec();
    m.extend_from_slice(origin.trim_end_matches('/').to_ascii_lowercase().as_bytes());
    m.push(0x1f);
    m.extend_from_slice(user_code.as_bytes());
    m.push(0x1f);
    m.extend_from_slice(machine_key);
    m
}

async fn enroll(State(s): St, axum::Json(body): axum::Json<Value>) -> Response {
    let mut g = s.lock().unwrap();
    let Some(public): Option<[u8; 32]> = body["public_key"]
        .as_str()
        .and_then(|k| URL_SAFE_NO_PAD.decode(k).ok())
        .and_then(|b| b.try_into().ok())
    else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_request"})),
        )
            .into_response();
    };
    g.enroll_key = Some(public);
    g.purpose = body["purpose"].as_str().map(str::to_owned);
    let user_code = "WDJB-MJHT";
    let proof = URL_SAFE_NO_PAD.encode(
        g.key
            .sign(&answer_message(&g.origin, user_code, &public))
            .to_bytes(),
    );
    axum::Json(json!({
        "device_code": "dc-test",
        "user_code": user_code,
        "expires_in": 60,
        "interval": 1,
        "fingerprint": crate::binding::key_fingerprint(&public),
        "verification_uri_complete": format!("{}/machines/approve?user_code={user_code}", g.origin),
        "operator_key": { "kid": "k-op", "public_key": URL_SAFE_NO_PAD.encode(g.key.verifying_key().to_bytes()) },
        "operator_proof": proof,
    }))
    .into_response()
}

async fn enroll_poll(State(s): St, axum::Json(body): axum::Json<Value>) -> Response {
    let g = s.lock().unwrap();
    // The proof is the enrolling key's signature over the device code.
    let ok = g.enroll_key.is_some_and(|k| {
        let mut m = b"airdress-machine-enroll-v1\0".to_vec();
        m.extend_from_slice(body["device_code"].as_str().unwrap_or("").as_bytes());
        body["proof"]
            .as_str()
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
            .is_some_and(|sig| {
                ed25519_dalek::VerifyingKey::from_bytes(&k)
                    .is_ok_and(|v| v.verify_strict(&m, &sig).is_ok())
            })
    });
    if !ok {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    match &g.decided {
        Some(d) => axum::Json(d.clone()).into_response(),
        None => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "authorization_pending"})),
        )
            .into_response(),
    }
}

fn machine_signed(s: &Arc<Mutex<Inner>>, headers: &HeaderMap) -> bool {
    let input = headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ok = headers.contains_key("signature") && input.contains("tag=\"airdress-machine\"");
    if let Some(k) = input
        .split("keyid=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
    {
        s.lock().unwrap().keyids.push(k.to_owned());
    }
    ok
}

async fn person_devices(State(s): St, headers: HeaderMap) -> Response {
    if !machine_signed(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut g = s.lock().unwrap();
    g.devices_asked += 1;
    let principal = g
        .decided
        .as_ref()
        .map_or(Value::Null, |d| d["principal"]["id"].clone());
    axum::Json(json!({
        "shellHost": "test box",
        "principal": principal,
        "devices": g.devices,
    }))
    .into_response()
}

/// The operator's checks on what a host sends (operator PR 345): a
/// `host_info` whose shell key the machine did not sign, or a profile whose
/// state is not `ready`/`invalid` with a short-code reason, closes the
/// channel 4009.
fn check_host_frame(g: &Inner, v: &Value) -> Result<(), String> {
    match v["type"].as_str() {
        Some("host_info") => {
            let machine: Uuid = g
                .decided
                .as_ref()
                .and_then(|d| d["machine_id"].as_str())
                .and_then(|m| m.parse().ok())
                .ok_or("no machine")?;
            let key = g.enroll_key.ok_or("no machine key")?;
            let public: [u8; 32] = v["shellKeyPublic"]
                .as_str()
                .and_then(crate::trust::b64)
                .and_then(|b| b.try_into().ok())
                .ok_or("host_info without a 32-byte shellKeyPublic")?;
            if v["shellKey"].as_str() != Some(&airdress_shell_proto::keys::fingerprint(&public)) {
                return Err("shellKey is not the fingerprint of shellKeyPublic".into());
            }
            let sig = v["sig"]
                .as_str()
                .and_then(crate::trust::b64)
                .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                .ok_or("host_info without a 64-byte sig")?;
            let mut msg = b"airdress.shell.host-key.v1".to_vec();
            msg.push(0);
            msg.extend_from_slice(machine.as_bytes());
            msg.extend_from_slice(&public);
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .ok()
                .filter(|k| k.verify_strict(&msg, &sig).is_ok())
                .ok_or("sig is not the machine's over its shell key")?;
            Ok(())
        }
        Some("profiles") => {
            for p in v["profiles"].as_array().into_iter().flatten() {
                let reason = p.get("reason").and_then(Value::as_str);
                match (p["state"].as_str(), reason) {
                    (Some("ready"), _) => {}
                    (Some("invalid"), Some(r)) if crate::profiles::valid_reason(r) => {}
                    other => return Err(format!("a profile's state and reason: {other:?}")),
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn hello(g: &mut Inner) -> Vec<String> {
    let key = g.key.clone();
    let frame_max = g.frame_max;
    let ch = g.chan.as_mut().expect("chan");
    let transport = ch.transport;
    let (_, h) = signed(
        &key,
        ch,
        "hello",
        json!({ "protocol": 1, "transport": transport, "operatorKid": "k-op", "frameMaxBytes": frame_max }),
    );
    let (_, c) = signed(
        &key,
        ch,
        "config",
        json!({ "enabled": true, "limits": { "maxViewers": 4, "opensPerMinute": 6 } }),
    );
    vec![h, c]
}

async fn session(State(s): St, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if !machine_signed(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if s.lock().unwrap().refuse_ws {
        return (StatusCode::BAD_REQUEST, "this proxy does not upgrade").into_response();
    }
    ws.protocols([crate::frames::SUBPROTOCOL])
        .on_upgrade(move |socket| run_ws(s, socket))
}

async fn run_ws(s: Arc<Mutex<Inner>>, socket: WebSocket) {
    // The test kit (never in a shipped build) is a mock operator whose
    // sends happen under a std lock, where nothing can wait for room;
    // its test drains the queue (R-ASY-5 bounds shipped code).
    #[expect(
        clippy::disallowed_methods,
        reason = "test kit: sent from under a std lock, drained by the test"
    )]
    let (tx, mut rx) = mpsc::unbounded_channel::<Down>();
    let (greet, from_host) = {
        let mut g = s.lock().unwrap();
        g.chan = Some(Chan {
            id: Uuid::new_v4(),
            seq: 0,
            ws: Some(tx),
            poll: None,
            buffered: VecDeque::new(),
            transport: "ws",
        });
        (hello(&mut g), g.from_host.clone())
    };
    let (mut sink, mut stream) = socket.split();
    for l in greet {
        if let Err(e) = sink.send(WsMessage::Text(l.into())).await {
            eprintln!("best effort, the peer may have gone: {e}");
        }
    }
    loop {
        tokio::select! {
            // cancel-safe: `mpsc::UnboundedReceiver::recv`.
            d = rx.recv() => match d {
                Some(Down::Text(t)) => {
                    if let Err(e) = sink.send(WsMessage::Text(t.into())).await {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                }
                Some(Down::Binary(b)) => {
                    if let Err(e) = sink.send(WsMessage::Binary(b.into())).await {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                }
                Some(Down::Close(code, reason)) => {
                    if let Err(e) = sink.send(WsMessage::Close(Some(axum::extract::ws::CloseFrame { code, reason: reason.into() }))).await {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                    break;
                }
                None => break,
            },
            // cancel-safe: `SplitStream::next` over a WebSocket.
            m = stream.next() => match m {
                Some(Ok(WsMessage::Text(t))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(t.as_str()) {
                        let checked = check_host_frame(&s.lock().unwrap(), &v);
                        if let Err(why) = checked {
                            if let Err(e) = from_host.send(FromHost::Protocol(why)) {
                                eprintln!("best effort, the peer may have gone: {e}");
                            }
                            if let Err(e) = sink.send(WsMessage::Close(Some(axum::extract::ws::CloseFrame { code: 4009, reason: "protocol".into() }))).await {
                                eprintln!("best effort, the peer may have gone: {e}");
                            }
                            break;
                        }
                        if let Err(e) = from_host.send(FromHost::Frame(v)) {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                    }
                }
                Some(Ok(WsMessage::Binary(b))) => {
                    if let Some((session, leg, record)) = crate::frames::parse_data_frame(&b) {
                        if let Err(e) = from_host.send(FromHost::Data { session, leg, record: record.to_vec() }) {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                    }
                }
                Some(Ok(WsMessage::Close(f))) => {
                    if let Err(e) = from_host.send(FromHost::Closed(f.map(|f| f.code))) {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    if let Err(e) = from_host.send(FromHost::Closed(None)) {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                    break;
                }
            }
        }
    }
    s.lock().unwrap().chan = None;
}

async fn poll(State(s): St, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if !machine_signed(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    // The test kit (never in a shipped build) is a mock operator whose
    // sends happen under a std lock, where nothing can wait for room;
    // its test drains the queue (R-ASY-5 bounds shipped code).
    #[expect(
        clippy::disallowed_methods,
        reason = "test kit: sent from under a std lock, drained by the test"
    )]
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    {
        let mut g = s.lock().unwrap();
        let named: Option<Uuid> = req["session"].as_str().and_then(|x| x.parse().ok());
        let ack = req["ack"].as_u64().unwrap_or(0);
        let reattach =
            matches!((&g.chan, named), (Some(c), Some(n)) if c.id == n && c.poll.is_some());
        if reattach {
            let ch = g.chan.as_mut().expect("chan");
            while ch.buffered.front().is_some_and(|(q, _)| *q <= ack) {
                ch.buffered.pop_front();
            }
            for (_, l) in &ch.buffered {
                if let Err(e) = tx.send(l.clone() + "\n") {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
            ch.poll = Some(tx);
        } else {
            g.chan = Some(Chan {
                id: Uuid::new_v4(),
                seq: 0,
                ws: None,
                poll: Some(tx.clone()),
                buffered: VecDeque::new(),
                transport: "poll",
            });
            for l in hello(&mut g) {
                if let Err(e) = tx.send(l + "\n") {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
        }
    }
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::io::Error>(axum::body::Bytes::from(l)), rx))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .body(axum::body::Body::from_stream(stream))
        .unwrap()
}

async fn frames(
    State(s): St,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    if !machine_signed(&s, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let from_host = {
        let g = s.lock().unwrap();
        let ok = g
            .chan
            .as_ref()
            .is_some_and(|c| Some(c.id.to_string()) == q.get("session").cloned());
        if !ok {
            return StatusCode::NOT_FOUND.into_response();
        }
        g.from_host.clone()
    };
    for line in body.split(|b| *b == b'\n') {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        match v["type"].as_str() {
            Some("ack") => {}
            Some("data") => {
                let session = v["sessionId"]
                    .as_str()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or_default();
                let leg = v["leg"]
                    .as_str()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or_default();
                for r in v["records"].as_array().into_iter().flatten() {
                    if let Some(record) = r.as_str().and_then(|r| STANDARD.decode(r).ok()) {
                        if let Err(e) = from_host.send(FromHost::Data {
                            session,
                            leg,
                            record,
                        }) {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                    }
                }
            }
            _ => {
                let checked = check_host_frame(&s.lock().unwrap(), &v);
                if let Err(why) = checked {
                    if let Err(e) = from_host.send(FromHost::Protocol(why)) {
                        eprintln!("best effort, the peer may have gone: {e}");
                    }
                    let mut g = s.lock().unwrap();
                    if let Some(p) = g.chan.as_ref().and_then(|c| c.poll.clone()) {
                        if let Err(e) = p.send(
                            json!({ "type": "closed", "code": 4009, "reason": "protocol" })
                                .to_string()
                                + "\n",
                        ) {
                            eprintln!("best effort, the peer may have gone: {e}");
                        }
                    }
                    g.chan = None;
                    return StatusCode::NOT_FOUND.into_response();
                }
                if let Err(e) = from_host.send(FromHost::Frame(v)) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
            }
        }
    }
    axum::Json(json!({ "accepted": 1 })).into_response()
}

/// What the host sent, with whatever a wait skipped kept for the next.
#[derive(Debug)]
pub struct Inbox {
    rx: mpsc::UnboundedReceiver<FromHost>,
    held: VecDeque<FromHost>,
}

impl Inbox {
    pub fn new(rx: mpsc::UnboundedReceiver<FromHost>) -> Self {
        Self {
            rx,
            held: VecDeque::new(),
        }
    }

    /// The first item `pick` accepts, held ones first, within `within`.
    pub async fn take<T>(
        &mut self,
        within: Duration,
        mut pick: impl FnMut(&FromHost) -> Option<T>,
    ) -> Option<T> {
        if let Some(i) = self.held.iter().position(|m| pick(m).is_some()) {
            let m = self.held.remove(i).expect("found");
            return pick(&m);
        }
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let m = tokio::time::timeout_at(deadline, self.rx.recv())
                .await
                .ok()??;
            if let Some(t) = pick(&m) {
                return Some(t);
            }
            self.held.push_back(m);
        }
    }

    /// The next frame of `kind`.
    pub async fn frame(&mut self, kind: &str) -> Option<Value> {
        self.take(Duration::from_secs(10), |m| match m {
            FromHost::Frame(v) if v["type"] == kind => Some(v.clone()),
            _ => None,
        })
        .await
    }

    /// The next frame of `kind` for which `pred` holds.
    pub async fn frame_where(
        &mut self,
        kind: &str,
        pred: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        self.take(Duration::from_secs(10), |m| match m {
            FromHost::Frame(v) if v["type"] == kind && pred(v) => Some(v.clone()),
            _ => None,
        })
        .await
    }

    /// The next record for `leg`.
    pub async fn record(&mut self, leg: Uuid) -> Option<Vec<u8>> {
        self.take(Duration::from_secs(10), |m| match m {
            FromHost::Data { leg: l, record, .. } if *l == leg => Some(record.clone()),
            _ => None,
        })
        .await
    }

    /// Every record for `leg` that arrives within `within`.
    pub async fn records(&mut self, leg: Uuid, within: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(r) = self
            .take(within, |m| match m {
                FromHost::Data { leg: l, record, .. } if *l == leg => Some(record.clone()),
                _ => None,
            })
            .await
        {
            out.push(r);
        }
        out
    }

    /// Whether the host closed its channel, and with what.
    pub async fn closed(&mut self, within: Duration) -> Option<Option<u16>> {
        self.take(within, |m| match m {
            FromHost::Closed(c) => Some(*c),
            _ => None,
        })
        .await
    }

    /// Everything held or arriving within `within`, for a negative check.
    pub async fn drain(&mut self, within: Duration) -> Vec<FromHost> {
        let mut out: Vec<FromHost> = self.held.drain(..).collect();
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Some(m)) = tokio::time::timeout_at(deadline, self.rx.recv()).await {
            out.push(m);
        }
        out
    }
}
