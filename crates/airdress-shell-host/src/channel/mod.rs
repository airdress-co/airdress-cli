//! The host's held channel to its operator (design §8.1, FR-H7): the home
//! channel's two transports, parameterised for shells.
//!
//! - **W**: `GET /v1/shells/host/session`, a WebSocket with the
//!   subprotocol `airdress.shell-host.v1`. Signed frames are text; a `data`
//!   record is one binary message with the fixed header, sent at once with
//!   Nagle off (design §8.4). Pinged every 30 s; silent for 90 s is gone.
//! - **P**: `POST /v1/shells/host/poll` (NDJSON down, rotated every 240 s
//!   with the last `seq` held, so a rotation repeats but never loses a
//!   frame) and `POST /v1/shells/host/frames?session=<id>` (NDJSON up; a
//!   `data` line flushed at once, other frames batched 50 ms or 32).
//!
//! Every request is machine-signed. The host dials out; it has no inbound
//! port. Which transport is used is negotiated per network
//! ([`negotiate`]), and remembered in a small file holding no address
//! ([`hints`]).

pub mod hints;
pub mod negotiate;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use uuid::Uuid;

use crate::binding::MachineSigner;
use crate::frames::{data_frame, parse_data_frame, Line, OpFrame, Reject, Verifier, SUBPROTOCOL};
use crate::host::Outgoing;
use crate::log_err::LogErr as _;
use crate::profiles::TransportPref;
use negotiate::{Ending, Negotiator, Transport};

/// The W route.
pub const SESSION_PATH: &str = "/v1/shells/host/session";
/// The P routes.
pub const POLL_PATH: &str = "/v1/shells/host/poll";
pub const FRAMES_PATH: &str = "/v1/shells/host/frames";

/// What the channel tells the host.
/// How long a closing channel waits for the operator to echo its close
/// frame before dropping the connection anyway.
const CLOSE_ECHO: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum LinkEvent {
    /// A channel is open on this transport.
    Up(Transport),
    /// A verified frame.
    Frame(Box<OpFrame>),
    /// A record for a leg.
    Data {
        session: Uuid,
        leg: Uuid,
        record: Vec<u8>,
    },
    /// The channel ended; another is being dialled.
    Down { code: Option<u16>, reason: String },
    /// The operator refused this machine; the reason is for the person.
    Refused(String),
    /// The operator ended this host for good (revoked, unlinked).
    Gone { code: u16, reason: String },
}

/// The channel's timers, shortened in tests.
#[derive(Debug, Clone)]
pub struct LinkTimings {
    pub ping: Duration,
    pub idle: Duration,
    pub rotate: Duration,
    pub batch: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
}

impl Default for LinkTimings {
    fn default() -> Self {
        Self {
            ping: Duration::from_secs(30),
            idle: Duration::from_secs(90),
            rotate: Duration::from_secs(240),
            batch: Duration::from_millis(50),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
        }
    }
}

/// How the channel reaches its operator.
pub struct LinkConfig {
    pub origin: String,
    pub signer: Arc<MachineSigner>,
    pub operator_key: ed25519_dalek::VerifyingKey,
    pub pref: TransportPref,
    pub hints: hints::HintFile,
    pub http: reqwest::Client,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub timings: LinkTimings,
}

impl std::fmt::Debug for LinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkConfig")
            .field("origin", &self.origin)
            .field("pref", &self.pref)
            .finish_non_exhaustive()
    }
}

/// Why opening a transport failed.
#[derive(Debug)]
enum OpenError {
    /// Refused on the way: try the next transport.
    Refused(String),
    /// The operator's own answer, the same on every transport.
    Operator(String),
    /// Unreachable, or the operator in trouble: wait and retry.
    Unreachable(String),
}

/// The rustls configuration the WebSocket uses: the Mozilla roots, and a
/// private CA file when the person gave one.
pub fn tls_config(ca_file: Option<&std::path::Path>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem =
            std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
        for cert in rustls::pki_types::pem::PemObject::pem_slice_iter(&pem) {
            let cert: rustls::pki_types::CertificateDer<'static> =
                cert.context("a certificate in the CA file is malformed")?;
            roots
                .add(cert)
                .context("a certificate in the CA file is not usable")?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn order(pref: TransportPref) -> Vec<Transport> {
    match pref {
        TransportPref::Auto => vec![Transport::Ws, Transport::Poll],
        TransportPref::Ws => vec![Transport::Ws],
        TransportPref::Poll => vec![Transport::Poll],
    }
}

/// Run the channel until the host sends `Close` or drops its queue,
/// re-dialling whatever ends it.
pub async fn run(
    cfg: LinkConfig,
    mut out: mpsc::Receiver<Outgoing>,
    events: mpsc::Sender<LinkEvent>,
) {
    let mut neg = Negotiator::new(order(cfg.pref), cfg.hints.load());
    let mut verifier = Verifier::new(cfg.operator_key);
    let mut backoff = cfg.timings.retry_min;
    loop {
        let net = hints::network_key(&cfg.origin).await;
        let wall = hints::wall_now();
        let (plan, reprobing) = neg.plan(&net, wall);
        let mut refused = Vec::new();
        let mut opened: Option<(Transport, Conn)> = None;
        let mut operator_answer: Option<String> = None;
        let mut unreachable: Option<String> = None;
        for t in plan {
            verifier.reset();
            match open(&cfg, t).await {
                Ok(c) => {
                    opened = Some((t, c));
                    break;
                }
                Err(OpenError::Refused(why)) => {
                    tracing::info!(transport = t.as_str(), why, "transport refused here");
                    refused.push(t);
                }
                Err(OpenError::Operator(why)) => {
                    operator_answer = Some(why);
                    break;
                }
                Err(OpenError::Unreachable(why)) => {
                    unreachable = Some(why);
                    break;
                }
            }
        }
        let Some((t, conn)) = opened else {
            let why = operator_answer
                .clone()
                .or(unreachable)
                .unwrap_or_else(|| "no transport worked on this network".into());
            if operator_answer.is_some() {
                events
                    .send(LinkEvent::Refused(why.clone()))
                    .await
                    .log_debug("handing a channel event to the host");
            }
            tracing::info!(why, retry_in = ?backoff, "the channel could not be opened");
            if wait_or_close(&mut out, backoff).await {
                return;
            }
            backoff = (backoff * 2).min(cfg.timings.retry_max);
            continue;
        };
        if neg.opened(&net, t, &refused, reprobing, wall) {
            cfg.hints.save(&neg.hints);
        }
        events
            .send(LinkEvent::Up(t))
            .await
            .log_debug("handing a channel event to the host");
        let started = Instant::now();
        let ended = match conn {
            Conn::Ws(ws) => run_ws(&cfg, *ws, &mut verifier, &mut out, &events).await,
            Conn::Poll(first) => run_poll(&cfg, first, &mut verifier, &mut out, &events).await,
        };
        let lived = started.elapsed();
        let (ending, code, reason, stop) = match ended {
            Ended::ByHost => (Ending::ByHost, None, "the host closed it".to_owned(), true),
            Ended::Code(c, r) => (Ending::Code(c), Some(c), r, false),
            Ended::Dropped(r) => (Ending::Dropped, None, r, false),
        };
        if neg.settled(&net, t, lived, ending, hints::wall_now()) {
            cfg.hints.save(&neg.hints);
        }
        if stop {
            return;
        }
        if matches!(code, Some(4003 | 4004)) {
            events
                .send(LinkEvent::Gone {
                    code: code.unwrap_or_default(),
                    reason: reason.clone(),
                })
                .await
                .log_debug("handing a channel event to the host");
        }
        events
            .send(LinkEvent::Down { code, reason })
            .await
            .log_debug("handing a channel event to the host");
        if lived >= negotiate::EARLY_DROP {
            backoff = cfg.timings.retry_min;
        }
        let pause = if matches!(code, Some(4001)) {
            cfg.timings.retry_min
        } else {
            backoff
        };
        if wait_or_close(&mut out, pause).await {
            return;
        }
        backoff = (backoff * 2).min(cfg.timings.retry_max);
    }
}

/// Wait `d`, dropping what the host sends meanwhile (no channel to carry
/// it; the end-to-end layer recovers by offset). True when the host closed.
async fn wait_or_close(out: &mut mpsc::Receiver<Outgoing>, d: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + d;
    loop {
        match tokio::time::timeout_at(deadline, out.recv()).await {
            Err(_) => return false,
            Ok(None) | Ok(Some(Outgoing::Close(..))) => return true,
            Ok(Some(_)) => {}
        }
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

enum Conn {
    Ws(Box<Ws>),
    Poll(reqwest::Response),
}

#[derive(Debug)]
enum Ended {
    ByHost,
    Code(u16, String),
    Dropped(String),
}

async fn open(cfg: &LinkConfig, t: Transport) -> Result<Conn, OpenError> {
    match t {
        Transport::Ws => open_ws(cfg).await.map(|w| Conn::Ws(Box::new(w))),
        Transport::Poll => start_poll(cfg, None, None).await.map(Conn::Poll),
    }
}

fn ws_url(origin: &str) -> String {
    let base = if let Some(rest) = origin.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = origin.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        origin.to_owned()
    };
    format!("{}{SESSION_PATH}", base.trim_end_matches('/'))
}

fn origin_url(origin: &str, path: &str) -> String {
    format!("{}{path}", origin.trim_end_matches('/'))
}

fn code_of(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("error")
        .and_then(|e| e.get("code").or(Some(e)))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| v.get("code").and_then(Value::as_str).map(str::to_owned))
}

async fn open_ws(cfg: &LinkConfig) -> Result<Ws, OpenError> {
    let url = ws_url(&cfg.origin);
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|e| OpenError::Unreachable(format!("bad URL: {e}")))?;
    let signed = cfg
        .signer
        .headers(
            &http::Method::GET,
            &origin_url(&cfg.origin, SESSION_PATH),
            None,
            b"",
        )
        .await
        .map_err(|e| OpenError::Unreachable(e.to_string()))?;
    for (k, v) in &signed {
        req.headers_mut().insert(k.clone(), v.clone());
    }
    req.headers_mut().insert(
        "sec-websocket-protocol",
        http::HeaderValue::from_static(SUBPROTOCOL),
    );
    let connector = cfg.tls.clone().map(tokio_tungstenite::Connector::Rustls);
    let config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(2 << 20))
        .max_frame_size(Some(2 << 20));
    match tokio_tungstenite::connect_async_tls_with_config(req, Some(config), true, connector).await
    {
        Ok((ws, resp)) => {
            let chosen = resp
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok());
            if chosen != Some(SUBPROTOCOL) {
                return Err(OpenError::Refused(
                    "the upgrade did not select our subprotocol".into(),
                ));
            }
            Ok(ws)
        }
        Err(tungstenite::Error::Http(resp)) => {
            let status = resp.status().as_u16();
            let code = resp.body().as_deref().and_then(code_of);
            match status {
                401 => Err(OpenError::Operator(
                    code.unwrap_or_else(|| "unauthorized".into()),
                )),
                // A refused upgrade carries no body a proxy would not also
                // send: ask the next transport, whose answer stands.
                403 => Err(OpenError::Refused(
                    code.unwrap_or_else(|| "upgrade_403".into()),
                )),
                s if (500..600).contains(&s) && s != 501 => {
                    Err(OpenError::Unreachable(format!("handshake_{s}")))
                }
                s => Err(OpenError::Refused(format!("handshake_{s}"))),
            }
        }
        Err(tungstenite::Error::Io(e)) => Err(OpenError::Unreachable(e.to_string())),
        Err(e) => Err(OpenError::Refused(format!("handshake: {e}"))),
    }
}

fn now_ms_since(t: Instant) -> u128 {
    t.elapsed().as_millis()
}

async fn handle_line(
    raw: &str,
    verifier: &mut Verifier,
    events: &mpsc::Sender<LinkEvent>,
) -> Result<Option<Line>, Ended> {
    match verifier.line(raw, unix_now()) {
        Ok(Line::Frame(_, f)) => {
            if let OpFrame::Data {
                session_id,
                leg,
                records,
            } = *f
            {
                for record in records {
                    events
                        .send(LinkEvent::Data {
                            session: session_id,
                            leg,
                            record,
                        })
                        .await
                        .log_debug("handing a channel event to the host");
                }
            } else {
                events
                    .send(LinkEvent::Frame(f))
                    .await
                    .log_debug("handing a channel event to the host");
            }
            Ok(None)
        }
        Ok(other) => Ok(Some(other)),
        Err(Reject::Duplicate | Reject::Stale) => Ok(None),
        Err(Reject::OtherChannel) => {
            tracing::warn!("a frame for another channel; ignored");
            Ok(None)
        }
        Err(Reject::Malformed(why)) => {
            tracing::warn!(why, "a malformed frame; ignored");
            Ok(None)
        }
        Err(Reject::Forged(why)) => {
            tracing::warn!(
                why,
                "a frame that is not the operator's; closing the channel"
            );
            Err(Ended::Dropped(format!("forged: {why}")))
        }
    }
}

async fn run_ws(
    cfg: &LinkConfig,
    ws: Ws,
    verifier: &mut Verifier,
    out: &mut mpsc::Receiver<Outgoing>,
    events: &mpsc::Sender<LinkEvent>,
) -> Ended {
    let (mut sink, mut stream) = ws.split();
    let mut ping = tokio::time::interval(cfg.timings.ping);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut last_heard = Instant::now();
    loop {
        let idle_left = cfg.timings.idle.saturating_sub(last_heard.elapsed());
        tokio::select! {
            // cancel-safe: `SplitStream::next` over a WebSocket; a partly read
            // frame stays inside the stream, not in this future.
            msg = stream.next() => {
                last_heard = Instant::now();
                match msg {
                    Some(Ok(tungstenite::Message::Text(t))) => {
                        match handle_line(t.as_str(), verifier, events).await {
                            Ok(_) => {}
                            Err(e) => {
                                // The connection is being dropped for the error below either way.
                                sink.send(tungstenite::Message::Close(Some(CloseFrame { code: CloseCode::from(4009), reason: "protocol".into() }))).await.log_debug("closing the channel on a protocol error");
                                return e;
                            }
                        }
                    }
                    Some(Ok(tungstenite::Message::Binary(b))) => match parse_data_frame(&b) {
                        Some((session, leg, record)) => {
                            events.send(LinkEvent::Data { session, leg, record: record.to_vec() }).await.log_debug("handing a channel event to the host");
                        }
                        None => tracing::warn!("a binary frame outside the protocol; ignored"),
                    },
                    Some(Ok(tungstenite::Message::Ping(p))) => {
                        // A failed write surfaces as the next read or write failing.
                        sink.send(tungstenite::Message::Pong(p)).await.log_debug("answering a ping");
                    }
                    Some(Ok(tungstenite::Message::Pong(_) | tungstenite::Message::Frame(_))) => {}
                    Some(Ok(tungstenite::Message::Close(frame))) => {
                        return match frame {
                            Some(f) => Ended::Code(u16::from(f.code), f.reason.to_string()),
                            None => Ended::Dropped("closed".into()),
                        };
                    }
                    Some(Err(e)) => return Ended::Dropped(e.to_string()),
                    None => return Ended::Dropped("end of stream".into()),
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`.
            item = out.recv() => match item {
                Some(Outgoing::Frame(v)) => {
                    if sink.send(tungstenite::Message::Text(v.to_string().into())).await.is_err() {
                        return Ended::Dropped("write failed".into());
                    }
                }
                Some(Outgoing::Data { session, leg, record }) => {
                    if sink.send(tungstenite::Message::Binary(data_frame(session, leg, &record).into())).await.is_err() {
                        return Ended::Dropped("write failed".into());
                    }
                }
                Some(Outgoing::Close(code, reason)) => {
                    sink.send(tungstenite::Message::Close(Some(CloseFrame { code: CloseCode::from(code), reason: reason.into() }))).await.log_debug("sending the close frame");
                    // Elapsed: the operator did not echo the close in time;
                    // the connection is dropped anyway.
                    let _echoed = tokio::time::timeout(CLOSE_ECHO, async {
                        while let Some(Ok(m)) = stream.next().await {
                            if matches!(m, tungstenite::Message::Close(_)) { break; }
                        }
                    }).await.is_ok();
                    return Ended::ByHost;
                }
                None => return Ended::ByHost,
            },
            // cancel-safe: `Interval::tick` (tokio's list).
            _ = ping.tick() => {
                if sink.send(tungstenite::Message::Ping(Vec::new().into())).await.is_err() {
                    return Ended::Dropped("write failed".into());
                }
            }
            // cancel-safe: a sleep, made afresh from `last_heard` each pass.
            () = tokio::time::sleep(idle_left) => {
                return Ended::Dropped("silent past the idle limit".into());
            }
        }
    }
}

async fn start_poll(
    cfg: &LinkConfig,
    session: Option<Uuid>,
    ack: Option<u64>,
) -> Result<reqwest::Response, OpenError> {
    let body = serde_json::to_vec(&json!({ "session": session, "ack": ack })).unwrap_or_default();
    let url = origin_url(&cfg.origin, POLL_PATH);
    let headers = cfg
        .signer
        .headers(&http::Method::POST, &url, Some("application/json"), &body)
        .await
        .map_err(|e| OpenError::Unreachable(e.to_string()))?;
    let resp = cfg
        .http
        .post(&url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| OpenError::Unreachable(e.to_string()))?;
    let status = resp.status().as_u16();
    if status == 200 {
        return Ok(resp);
    }
    let code = resp.bytes().await.ok().and_then(|b| code_of(&b));
    match status {
        401 | 403 => Err(OpenError::Operator(
            code.unwrap_or_else(|| format!("poll_{status}")),
        )),
        404 if session.is_some() => Err(OpenError::Unreachable("session_unknown".into())),
        s if (500..600).contains(&s) => Err(OpenError::Unreachable(format!("poll_{s}"))),
        s => Err(OpenError::Refused(format!("poll_{s}"))),
    }
}

/// Lines from a streaming body, read by a task in `readers` (R-ASY-1): the
/// set belongs to the poll session and ends with it. A rotation's earlier
/// reader keeps going until its poll ends, so nothing it still carries is
/// lost; finished ones are reaped here.
fn spawn_reader(
    readers: &mut tokio::task::JoinSet<()>,
    resp: reqwest::Response,
    generation: u64,
    tx: mpsc::Sender<(u64, Option<String>)>,
) {
    while readers.try_join_next().is_some() {}
    readers.spawn(async move {
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else { break };
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                let text = String::from_utf8_lossy(&line).trim().to_owned();
                if !text.is_empty() && tx.send((generation, Some(text))).await.is_err() {
                    return;
                }
            }
        }
        // Closed: the poller has moved to a newer generation.
        tx.send((generation, None))
            .await
            .log_debug("reporting the end of a streaming body");
    });
}

async fn post_frames(cfg: &LinkConfig, session: Uuid, lines: &[Value]) -> Result<(), String> {
    let mut body = Vec::new();
    for l in lines {
        body.extend_from_slice(l.to_string().as_bytes());
        body.push(b'\n');
    }
    let url = format!("{}?session={session}", origin_url(&cfg.origin, FRAMES_PATH));
    let headers = cfg
        .signer
        .headers(
            &http::Method::POST,
            &url,
            Some("application/x-ndjson"),
            &body,
        )
        .await
        .map_err(|e| e.to_string())?;
    let resp = cfg
        .http
        .post(&url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("frames answered {}", resp.status()))
    }
}

async fn run_poll(
    cfg: &LinkConfig,
    first: reqwest::Response,
    verifier: &mut Verifier,
    out: &mut mpsc::Receiver<Outgoing>,
    events: &mpsc::Sender<LinkEvent>,
) -> Ended {
    let (tx, mut rx) = mpsc::channel::<(u64, Option<String>)>(256);
    let mut generation = 1u64;
    let mut readers = tokio::task::JoinSet::new();
    spawn_reader(&mut readers, first, generation, tx.clone());
    let mut rotate = tokio::time::interval(cfg.timings.rotate);
    rotate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    rotate.tick().await;
    let mut pending: Vec<Value> = Vec::new();
    let mut flush_at: Option<tokio::time::Instant> = None;
    let mut last_heard = Instant::now();
    let started = Instant::now();
    loop {
        // Upstream needs the channel's id, which its first frame names.
        let ready = verifier.channel().is_some();
        let flush_due = ready
            && !pending.is_empty()
            && flush_at.is_some_and(|t| t <= tokio::time::Instant::now());
        if flush_due || (ready && pending.len() >= 32) {
            let session = verifier.channel().expect("ready");
            let mut lines = vec![json!({ "type": "ack", "seq": verifier.last_seq() })];
            lines.append(&mut pending);
            flush_at = None;
            if let Err(e) = post_frames(cfg, session, &lines).await {
                return Ended::Dropped(e);
            }
        }
        let idle_left = cfg.timings.idle.saturating_sub(last_heard.elapsed());
        let flush_wait = flush_at.map_or(Duration::from_secs(3600), |t| {
            t.saturating_duration_since(tokio::time::Instant::now())
        });
        tokio::select! {
            // cancel-safe: `mpsc::Receiver::recv`; the reader task owns the
            // partial line, not this future.
            got = rx.recv() => {
                let Some((g, line)) = got else { return Ended::Dropped("reader gone".into()) };
                match line {
                    Some(text) => {
                        last_heard = Instant::now();
                        match handle_line(&text, verifier, events).await {
                            Ok(Some(Line::Closed(code, reason))) => return Ended::Code(code, reason),
                            Ok(_) => {}
                            Err(e) => return e,
                        }
                    }
                    // The current poll ended without a `closed` line: a drop.
                    None if g == generation => return Ended::Dropped(format!("poll ended after {} ms", now_ms_since(started))),
                    None => {}
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`.
            item = out.recv() => match item {
                Some(Outgoing::Frame(v)) => {
                    pending.push(v);
                    flush_at.get_or_insert(tokio::time::Instant::now() + cfg.timings.batch);
                }
                Some(Outgoing::Data { session, leg, record }) => {
                    pending.push(json!({ "type": "data", "sessionId": session, "leg": leg, "records": [crate::binding::b64_std(&record)] }));
                    // Data is not batched (design §8.4).
                    flush_at = Some(tokio::time::Instant::now());
                }
                Some(Outgoing::Close(..)) | None => {
                    if let (Some(session), false) = (verifier.channel(), pending.is_empty()) {
                        let mut lines = vec![json!({ "type": "ack", "seq": verifier.last_seq() })];
                        lines.append(&mut pending);
                        // The last acknowledgement on the way out; the operator
                        // replays anything unacknowledged to the next channel.
                        post_frames(cfg, session, &lines)
                            .await
                            .log_debug("posting the final frames");
                    }
                    return Ended::ByHost;
                }
            },
            // cancel-safe: `Interval::tick`.
            _ = rotate.tick() => {
                let Some(session) = verifier.channel() else { continue };
                match start_poll(cfg, Some(session), Some(verifier.last_seq())).await {
                    Ok(resp) => {
                        generation += 1;
                        spawn_reader(&mut readers, resp, generation, tx.clone());
                    }
                    Err(e) => return Ended::Dropped(format!("rotation failed: {e:?}")),
                }
            }
            // cancel-safe: a sleep, made afresh from `flush_at` each pass.
            () = tokio::time::sleep(flush_wait) => {}
            // cancel-safe: a sleep, made afresh from `last_heard` each pass.
            () = tokio::time::sleep(idle_left) => {
                return Ended::Dropped("silent past the idle limit".into());
            }
        }
    }
}
