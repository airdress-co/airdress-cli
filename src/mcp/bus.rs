//! The agent bus, from inside an editor: the tools, and the session this
//! server keeps on the bus while it runs.
//!
//! With `--bus` on (and not read-only) the server registers a session at
//! start, labelled `<host> · <repo>`, heartbeats it, holds one event
//! stream, renews the claims it holds at a third of their lease, and on
//! exit releases them and ends the session. Items from other sessions are
//! verified, labelled and pushed into the client as channel events; every
//! one of them is also readable with `bus_read`, which is the delivery
//! that cannot be dropped.
//!
//! Every write is signed by this machine's agent device, through its
//! device host. Reads need only the account.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _, Result};
use rand::Rng as _;
use reqwest::Method;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use crate::agent_bus::client::{self, attest, BusClient, Signer};
use crate::agent_bus::socket;
use crate::agent_bus::sse;
use crate::agent_bus::state::{bus_dir, Delivery, Pins, Policies};
use crate::agent_bus::verify::{self, Known};
use crate::log_err::LogErr as _;
use crate::mcp::channel_push;
use crate::mcp::session::{Session, Target};

/// Heartbeat interval when the operator does not say.
const HEARTBEAT_DEFAULT: Duration = Duration::from_secs(30);
/// Reconnect backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long shutdown waits for the bus to release held names and end the
/// session; past it the leases expire on their own.
const RELEASE_AT_SHUTDOWN: Duration = Duration::from_secs(5);

/// A claim this session holds.
#[derive(Debug, Clone)]
struct Held {
    token: i64,
    ttl: u64,
    renewed_at: Instant,
}

/// This server's session on one airdress's bus.
pub struct Link {
    fqdn: String,
    /// What `/info` said this airdress is called, for the signed bytes.
    airdress: String,
    info: Value,
    session: Mutex<String>,
    enrollment: Mutex<String>,
    signer: Signer,
    dir: PathBuf,
    registered: AtomicBool,
    /// Set once a registration has used the current id.
    used: AtomicBool,
    stopped: AtomicBool,
    /// Bumped by every registration; a background loop from an older one
    /// sees the change and ends.
    generation: AtomicU64,
    held: Mutex<HashMap<(String, String), Held>>,
    known: Mutex<Known>,
    delivery: Mutex<Delivery>,
    /// The current registration's background loop (heartbeat, renewals,
    /// the stream), owned here (R-ASY-1). A new registration replaces it,
    /// which aborts the old one; `shutdown` ends it.
    task: std::sync::Mutex<tokio::task::JoinSet<()>>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("fqdn", &self.fqdn)
            .finish_non_exhaustive()
    }
}

impl Link {
    fn task(&self) -> std::sync::MutexGuard<'_, tokio::task::JoinSet<()>> {
        // Never held across an await (R-ASY-4); a poisoned lock still holds
        // a whole set.
        self.task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The session id this server holds on the bus.
    pub async fn session_id(&self) -> String {
        self.session.lock().await.clone()
    }

    /// Whether the session is registered right now.
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::SeqCst)
    }

    /// The claims this session holds, as `topic/name`.
    pub async fn claims(&self) -> Vec<String> {
        self.held
            .lock()
            .await
            .keys()
            .map(|(t, n)| format!("{t}/{n}"))
            .collect()
    }
}

// ---------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------

/// Percent-encode one path segment: a claim name or state key may hold
/// `/`, which travels as `%2F`.
fn seg(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn bus_client(session: &Session, fqdn: &str) -> Result<BusClient> {
    let bearer = session.bearer(fqdn).await?;
    BusClient::new(&crate::mcp::operator_base(fqdn), bearer.expose().to_owned())
}

fn state_dir(session: &Session) -> Result<PathBuf> {
    match &session.opts.state_dir {
        Some(d) => Ok(d.clone()),
        None => Ok(socket::default_state_dir(session.paths()?)),
    }
}

/// The device host for `fqdn` on this machine.
fn host_signer(session: &Session, fqdn: &str) -> Result<Signer> {
    Ok(Signer::Host(socket::socket_path(
        &socket::device_dir(&state_dir(session)?, fqdn),
        session.paths()?.runtime_dir(),
    )))
}

/// The link for `fqdn`, built (and registered) when `create` and absent.
async fn link(session: &Arc<Session>, fqdn: &str, create: bool) -> Result<Option<Arc<Link>>> {
    let mut links = session.bus_links.lock().await;
    if let Some(l) = links.get(fqdn) {
        if l.is_registered() || !create {
            return Ok(Some(Arc::clone(l)));
        }
    }
    if !create {
        return Ok(None);
    }
    let l = match links.get(fqdn) {
        Some(l) => Arc::clone(l),
        None => {
            let api = bus_client(session, fqdn).await?;
            let info = api.get("/info").await?;
            let airdress = info["airdress"]
                .as_str()
                .context("the operator's bus answered no airdress in /info")?
                .to_owned();
            let signer = host_signer(session, fqdn)?;
            let dir = bus_dir(&state_dir(session)?, fqdn);
            let l = Arc::new(Link {
                fqdn: fqdn.to_owned(),
                airdress: airdress.clone(),
                info,
                session: Mutex::new(uuid::Uuid::new_v4().to_string()),
                enrollment: Mutex::new(String::new()),
                signer,
                dir,
                registered: AtomicBool::new(false),
                used: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                generation: AtomicU64::new(0),
                held: Mutex::new(HashMap::new()),
                known: Mutex::new(Known {
                    airdress,
                    ..Known::default()
                }),
                delivery: Mutex::new(Delivery::default()),
                task: std::sync::Mutex::new(tokio::task::JoinSet::new()),
            });
            links.insert(fqdn.to_owned(), Arc::clone(&l));
            l
        }
    };
    drop(links);
    register(session, &l).await?;
    let generation = l.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let mut task = tokio::task::JoinSet::new();
    task.spawn(run(Arc::clone(session), Arc::clone(&l), generation));
    // The previous generation's loop, if any, is aborted as it is dropped.
    *l.task() = task;
    Ok(Some(l))
}

/// Register (or re-register, under a fresh id) this server's session.
async fn register(session: &Arc<Session>, l: &Arc<Link>) -> Result<()> {
    let enrollment = l.signer.enrollment().await?;
    *l.enrollment.lock().await = enrollment.clone();
    let mut id = l.session.lock().await;
    // An id is registered once; a re-registration is a new session.
    if l.used.swap(true, Ordering::SeqCst) {
        *id = uuid::Uuid::new_v4().to_string();
    }
    let mut body = json!({
        "id": *id,
        "harness": session.opts.harness,
        "host": crate::mcp::session::hostname(),
        "repo": crate::mcp::session::repo_name(),
        "label": session.session_label(),
        "topics": session.opts.bus_topics,
    });
    attest(
        &l.signer,
        &l.airdress,
        &id,
        &enrollment,
        "session.register",
        &id,
        &mut body,
    )
    .await?;
    let answer = bus_client(session, &l.fqdn)
        .await?
        .request(Method::POST, "/sessions", Some(&body))
        .await?;
    // A re-registration keeps where reading had got to; a first one
    // starts at the airdress's head as the operator reports it, so a new
    // session is not handed the topics' whole history.
    let previous = std::mem::take(&mut *l.delivery.lock().await);
    let mut d = Delivery::load(&l.dir, &id);
    d.advance(previous.cursor);
    if previous.cursor == 0 {
        if let Some(head) = answer["cursor"].as_i64() {
            d.advance(head);
        }
    }
    for p in previous.pushed {
        d.pushed(&p);
    }
    *l.delivery.lock().await = d;
    l.registered.store(true, Ordering::SeqCst);
    l.stopped.store(false, Ordering::SeqCst);
    tracing::info!(session = %*id, "registered on the agent bus");
    Ok(())
}

/// One signed write. A session the operator no longer knows is registered
/// again and the write retried once.
async fn write(
    session: &Arc<Session>,
    l: &Arc<Link>,
    method: Method,
    path: &str,
    op: &str,
    target: &str,
    body: &Value,
) -> Result<Value> {
    for attempt in 0..2 {
        let sid = l.session_id().await;
        let enrollment = l.enrollment.lock().await.clone();
        let mut b = body.clone();
        // The register op signs its own id; every other op signs the
        // session's.
        let target = if op.starts_with("session.") {
            sid.clone()
        } else {
            target.to_owned()
        };
        attest(
            &l.signer,
            &l.airdress,
            &sid,
            &enrollment,
            op,
            &target,
            &mut b,
        )
        .await?;
        let path = path.replace("{session}", &sid);
        match bus_client(session, &l.fqdn)
            .await?
            .request(method.clone(), &path, Some(&b))
            .await
        {
            Err(e)
                if attempt == 0
                    && client::refusal(&e).is_some_and(|r| {
                        matches!(
                            r.code.as_str(),
                            "agent_session_expired" | "agent_session_unknown"
                        )
                    }) =>
            {
                register(session, l).await?;
            }
            other => return other,
        }
    }
    unreachable!("the loop returns on its second pass")
}

// ---------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------

/// Join the bus at start, when the configuration says to.
pub async fn start(session: Arc<Session>) {
    if !session.opts.bus || session.opts.read_only {
        return;
    }
    let target = match session.target(None).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "agent bus: no airdress to join");
            return;
        }
    };
    if let Err(e) = link(&session, &target.fqdn, true).await {
        // Said once, on stderr and in whoami; tools still answer.
        eprintln!("airdress-mcp: could not join the agent bus: {e:#}");
        *session.bus_error.lock().await = Some(format!("{e:#}"));
    }
}

/// Release every held claim and end every session. Bounded: a dead
/// operator must not hold the process open after its client has gone.
pub async fn shutdown(session: &Arc<Session>) {
    let links: Vec<Arc<Link>> = session.bus_links.lock().await.values().cloned().collect();
    let work = async {
        for l in links {
            l.stopped.store(true, Ordering::SeqCst);
            if !l.is_registered() {
                continue;
            }
            let held: Vec<((String, String), Held)> = l.held.lock().await.drain().collect();
            for ((topic, name), h) in held {
                write(
                    session,
                    &l,
                    Method::POST,
                    &format!("/topics/{}/claims/{}/release", seg(&topic), seg(&name)),
                    "claim.release",
                    &format!("{topic}/{name}"),
                    &json!({"token": h.token}),
                )
                .await
                .log_debug("releasing a held name at shutdown");
            }
            write(
                session,
                &l,
                Method::DELETE,
                "/sessions/{session}",
                "session.end",
                "",
                &json!({}),
            )
            .await
            .log_debug("releasing a held name at shutdown");
            l.registered.store(false, Ordering::SeqCst);
        }
    };
    if tokio::time::timeout(RELEASE_AT_SHUTDOWN, work)
        .await
        .is_err()
    {
        tracing::debug!(
            ?RELEASE_AT_SHUTDOWN,
            "the bus did not finish releasing in time; its leases expire on their own"
        );
    }
    // The loops end with the session, released or not.
    let links: Vec<Arc<Link>> = session.bus_links.lock().await.values().cloned().collect();
    for l in links {
        l.task().abort_all();
    }
}

fn heartbeat_every(info: &Value) -> Duration {
    info["limits"]["heartbeat_seconds"]
        .as_u64()
        .or_else(|| info["heartbeat_seconds"].as_u64())
        .filter(|s| *s > 0)
        .map_or(HEARTBEAT_DEFAULT, Duration::from_secs)
}

/// Heartbeat, renew, and hold the stream, until stopped.
async fn run(session: Arc<Session>, l: Arc<Link>, generation: u64) {
    // Both in this one task, so neither outlives the other's owner.
    tokio::join!(
        keep_alive(Arc::clone(&session), Arc::clone(&l), generation),
        stream(session, l, generation),
    );
}

impl Link {
    fn current(&self, generation: u64) -> bool {
        !self.stopped.load(Ordering::SeqCst) && self.generation.load(Ordering::SeqCst) == generation
    }
}

async fn keep_alive(session: Arc<Session>, l: Arc<Link>, generation: u64) {
    let every = heartbeat_every(&l.info);
    let mut last_beat = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if !l.current(generation) {
            return;
        }
        if !l.is_registered() {
            continue;
        }
        if last_beat.elapsed() >= every {
            last_beat = Instant::now();
            if let Err(e) = write(
                &session,
                &l,
                Method::POST,
                "/sessions/{session}/heartbeat",
                "session.heartbeat",
                "",
                &json!({}),
            )
            .await
            {
                tracing::warn!(error = %e, "agent bus heartbeat failed");
            }
        }
        renew_due(&session, &l).await;
    }
}

/// Renew each held claim a third of the way through its lease (FR-53).
async fn renew_due(session: &Arc<Session>, l: &Arc<Link>) {
    let due: Vec<((String, String), Held)> = l
        .held
        .lock()
        .await
        .iter()
        .filter(|(_, h)| h.renewed_at.elapsed() >= Duration::from_secs((h.ttl / 3).max(1)))
        .map(|(k, h)| (k.clone(), h.clone()))
        .collect();
    for ((topic, name), h) in due {
        let r = write(
            session,
            l,
            Method::POST,
            &format!("/topics/{}/claims/{}/renew", seg(&topic), seg(&name)),
            "claim.renew",
            &format!("{topic}/{name}"),
            &json!({"token": h.token, "ttl_seconds": h.ttl}),
        )
        .await;
        let mut held = l.held.lock().await;
        match r {
            Ok(_) => {
                if let Some(x) = held.get_mut(&(topic.clone(), name.clone())) {
                    x.renewed_at = Instant::now();
                }
            }
            Err(e) => {
                // Lost: say so the next time anyone asks, and stop
                // pretending to hold it.
                held.remove(&(topic.clone(), name.clone()));
                session.bus_notices.lock().await.push(format!(
                    "the claim {topic}/{name} could not be renewed and is no longer held: {e:#}"
                ));
            }
        }
    }
}

/// Hold the session's event stream, reconnecting with backoff.
async fn stream(session: Arc<Session>, l: Arc<Link>, generation: u64) {
    let mut backoff = BACKOFF_MIN;
    let mut last: Option<i64> = None;
    loop {
        if !l.current(generation) {
            return;
        }
        let sid = l.session_id().await;
        let since = last.or_else(|| {
            l.delivery
                .try_lock()
                .ok()
                .map(|d| d.cursor)
                .filter(|c| *c > 0)
        });
        let opened = match bus_client(&session, &l.fqdn).await {
            Ok(api) => api.events(&sid, since).await,
            Err(e) => Err(e),
        };
        match opened {
            Ok(mut resp) => {
                backoff = BACKOFF_MIN;
                let mut parser = sse::Parser::default();
                while let Ok(Some(bytes)) = resp.chunk().await {
                    for ev in parser.feed(&bytes) {
                        if let Some(id) = ev.id.as_deref().and_then(|i| i.parse().ok()) {
                            last = Some(id);
                        }
                        if handle_event(&session, &l, &ev).await == Flow::Stop {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                if let Some(r) = client::refusal(&e) {
                    match r.code.as_str() {
                        "agent_session_expired" | "agent_session_unknown" => {
                            register(&session, &l)
                                .await
                                .log_warn("registering with the bus again");
                        }
                        "not_enabled" => {
                            l.registered.store(false, Ordering::SeqCst);
                            l.stopped.store(true, Ordering::SeqCst);
                            return;
                        }
                        _ => {}
                    }
                }
                tracing::debug!(error = %e, "agent bus stream refused");
            }
        }
        let jitter = rand::thread_rng().gen_range(0..=backoff.as_millis() as u64 / 2);
        tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Go,
    Stop,
}

async fn handle_event(session: &Arc<Session>, l: &Arc<Link>, ev: &sse::Event) -> Flow {
    match ev.event.as_str() {
        "session" => Flow::Go,
        "session_ended" => {
            let reason = serde_json::from_str::<Value>(&ev.data)
                .ok()
                .and_then(|v| v["reason"].as_str().map(str::to_owned))
                .unwrap_or_default();
            if reason == "expired" {
                register(session, l)
                    .await
                    .log_warn("registering with the bus again");
                return Flow::Go;
            }
            l.registered.store(false, Ordering::SeqCst);
            l.stopped.store(true, Ordering::SeqCst);
            session
                .bus_notices
                .lock()
                .await
                .push(format!("this session left the agent bus ({reason})"));
            Flow::Stop
        }
        _ => {
            if let Ok(item) = serde_json::from_str::<Value>(&ev.data) {
                deliver(session, l, item).await;
            }
            Flow::Go
        }
    }
}

/// Verify an item, and label it for a model.
async fn label(session: &Arc<Session>, l: &Arc<Link>, item: &mut Value) {
    let sender = item["attestation"]["session"].as_str().map(str::to_owned);
    let unknown = match &sender {
        Some(s) => !l.known.lock().await.sessions.contains_key(s),
        None => false,
    };
    let operator = item["attestation"]["signed_by"] == "operator"
        && !l
            .known
            .lock()
            .await
            .operator_keys
            .contains_key(item["attestation"]["key_id"].as_str().unwrap_or_default());
    if unknown || operator {
        refresh_known(session, l).await;
    }
    let mut pins = Pins::load(&l.dir);
    let verdict = verify::verify(item, &*l.known.lock().await, &mut pins);
    pins.save(&l.dir).log_warn("saving the bus signer pins");
    verdict.label_item(item);
    if item["kind"] == "policy" {
        let data = item["data"].clone();
        observe_policy(l, &data, item).await;
    }
}

async fn refresh_known(session: &Arc<Session>, l: &Arc<Link>) {
    let Ok(api) = bus_client(session, &l.fqdn).await else {
        return;
    };
    if let Ok(list) = api.get("/sessions").await {
        l.known.lock().await.set_sessions(&list);
    }
    if let Ok(keys) = api.get("/.well-known/airdress/keys.json").await {
        l.known.lock().await.set_operator_keys(&keys);
    }
}

async fn observe_policy(l: &Arc<Link>, p: &Value, into: &mut Value) {
    let (Some(topic), Some(strict)) = (
        p["topic"].as_str().or_else(|| p["name"].as_str()),
        p["require_device_signature"].as_bool(),
    ) else {
        return;
    };
    let mut policies = Policies::load(&l.dir);
    if let Some(w) = policies.observe(topic, strict) {
        if let Some(m) = into.as_object_mut() {
            m.insert("policy_warning".into(), json!(w));
        }
    }
    policies
        .save(&l.dir)
        .log_warn("saving the bus topic policies");
}

/// Push one item from the stream. Never moves the read cursor: a pushed
/// item is still returned by the next `bus_read`, marked `already_pushed`.
async fn deliver(session: &Arc<Session>, l: &Arc<Link>, mut item: Value) {
    let me = l.session_id().await;
    if item["from_session"].as_str() == Some(me.as_str()) {
        return;
    }
    adopt_handoff(l, &item, &me).await;
    let id = item["id"].as_str().unwrap_or_default().to_owned();
    {
        let d = l.delivery.lock().await;
        if d.was_pushed(&id) {
            return;
        }
    }
    label(session, l, &mut item).await;
    let verdict = verify::Verdict {
        signed_by: match item["signed_by"].as_str() {
            Some("device-signed") => "device".into(),
            Some("operator-attested") => "operator".into(),
            _ => "none".into(),
        },
        valid: item["signature"] == "valid",
        // Why, when it did not hold (or held another way): without it a
        // person sees "[signature invalid]" and nothing to act on.
        notes: item["signature_notes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_str().map(str::to_owned))
            .collect(),
    };
    session
        .notify(channel_push::notification(&item, &verdict))
        .await;
    {
        let mut d = l.delivery.lock().await;
        d.pushed(&id);
        d.save(&l.dir, &me)
            .log_warn("saving the bus delivery cursor");
    }
    if item["kind"] == "message" {
        ack_delivered(session, l, &id).await;
    }
}

async fn ack_delivered(session: &Arc<Session>, l: &Arc<Link>, id: &str) {
    if let Err(e) = write(
        session,
        l,
        Method::POST,
        &format!("/messages/{}/acks", seg(id)),
        "ack",
        id,
        &json!({"state": "delivered"}),
    )
    .await
    {
        tracing::debug!(error = %e, "delivered ack not sent");
    }
}

// ---------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------

fn s<'a>(args: &'a Value, k: &str) -> Option<&'a str> {
    args.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn need<'a>(args: &'a Value, k: &str) -> Result<&'a str> {
    s(args, k).ok_or_else(|| anyhow!("{k} is required"))
}

fn limit(args: &Value) -> i64 {
    args.get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(20)
        .clamp(1, 100)
}

/// The message body a post or reply sends, optional fields omitted.
fn message_body(args: &Value, content: &str) -> Value {
    let mut m = Map::new();
    m.insert("content".into(), json!(content));
    if let Some(d) = args.get("data").filter(|d| d.is_object()) {
        m.insert("data".into(), d.clone());
    }
    if let Some(sch) = s(args, "data_schema") {
        m.insert("data_schema".into(), json!(sch));
    }
    Value::Object(m)
}

/// The lease a claim is renewed to when nobody said: the operator's default.
fn default_ttl(l: &Link) -> u64 {
    l.info["limits"]["claim_ttl_default_seconds"]
        .as_u64()
        .unwrap_or(300)
}

/// A handoff item addressed to this session, as the claim it now holds:
/// `((topic, name), token, ttl)`. The operator moved the claim in the same
/// transaction that wrote the item, so the receiver holds it from here on
/// — with no `bus_claim` of its own (FR-50).
fn handed_to(item: &Value, me: &str, default_ttl: u64) -> Option<((String, String), i64, u64)> {
    if item["kind"] != "handoff" {
        return None;
    }
    let d = &item["data"];
    if d["to_session"].as_str() != Some(me) {
        return None;
    }
    let lapsed = d["expires_at"]
        .as_str()
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
        .is_some_and(|e| e < chrono::Utc::now());
    if lapsed {
        return None;
    }
    Some((
        (
            d["topic"].as_str()?.to_owned(),
            d["name"].as_str()?.to_owned(),
        ),
        d["token"].as_i64()?,
        d["ttl_seconds"].as_u64().unwrap_or(default_ttl),
    ))
}

/// A claim row from the operator, if it says this session holds it: the
/// token. A lapsed lease comes back with no holder.
fn held_by(row: &Value, me: &str) -> Option<i64> {
    (row["holder_session"].as_str() == Some(me))
        .then(|| row["token"].as_i64())
        .flatten()
}

/// Record a claim handed to this session, so renewals, releases and
/// fenced writes use its token. Never replaces a newer token.
async fn adopt_handoff(l: &Arc<Link>, item: &Value, me: &str) {
    let Some((key, token, ttl)) = handed_to(item, me, default_ttl(l)) else {
        return;
    };
    let mut held = l.held.lock().await;
    if held.get(&key).is_some_and(|h| h.token >= token) {
        return;
    }
    tracing::info!(topic = %key.0, claim = %key.1, token, "a claim was handed to this session");
    held.insert(
        key,
        Held {
            token,
            ttl,
            renewed_at: Instant::now(),
        },
    );
}

/// The token of a claim this session holds. When there is no local record
/// — a handoff whose event this server has not seen yet — ask the operator,
/// and adopt the claim if it names this session as the holder.
async fn held_token(session: &Arc<Session>, l: &Arc<Link>, topic: &str, name: &str) -> Option<i64> {
    let key = (topic.to_owned(), name.to_owned());
    if let Some(h) = l.held.lock().await.get(&key) {
        return Some(h.token);
    }
    let api = bus_client(session, &l.fqdn).await.ok()?;
    let row = api
        .get(&format!("/topics/{}/claims/{}", seg(topic), seg(name)))
        .await
        .ok()?;
    let token = held_by(&row, &l.session_id().await)?;
    let mut held = l.held.lock().await;
    let h = held.entry(key).or_insert(Held {
        token,
        ttl: default_ttl(l),
        renewed_at: Instant::now(),
    });
    Some(h.token)
}

/// Add `fence: {claim, token}` from a claim this session holds.
async fn fenced(
    session: &Arc<Session>,
    l: &Arc<Link>,
    topic: &str,
    args: &Value,
    body: &mut Value,
) -> Result<()> {
    if let Some(name) = s(args, "fence") {
        let token = held_token(session, l, topic, name).await.ok_or_else(|| {
            anyhow!("this session holds no claim named {name} on {topic}; claim it first")
        })?;
        body["fence"] = json!({"claim": name, "token": token});
    }
    Ok(())
}

async fn label_all(session: &Arc<Session>, l: Option<&Arc<Link>>, fqdn: &str, items: &mut [Value]) {
    if let Some(l) = l {
        for item in items.iter_mut() {
            label(session, l, item).await;
        }
        return;
    }
    // Not on the bus: verify against a fresh listing, without a session.
    let Ok(api) = bus_client(session, fqdn).await else {
        return;
    };
    let Ok(info) = api.get("/info").await else {
        return;
    };
    let mut known = Known {
        airdress: info["airdress"].as_str().unwrap_or_default().to_owned(),
        ..Known::default()
    };
    if let Ok(list) = api.get("/sessions").await {
        known.set_sessions(&list);
    }
    if let Ok(keys) = api.get("/.well-known/airdress/keys.json").await {
        known.set_operator_keys(&keys);
    }
    let Ok(dir) = state_dir(session).map(|d| bus_dir(&d, fqdn)) else {
        return;
    };
    let mut pins = Pins::load(&dir);
    for item in items.iter_mut() {
        verify::verify(item, &known, &mut pins).label_item(item);
    }
    pins.save(&dir).log_warn("saving the bus signer pins");
}

fn items_of(v: &mut Value) -> Vec<Value> {
    v["items"].as_array().cloned().unwrap_or_default()
}

async fn writer(session: &Arc<Session>, target: &Target) -> Result<Arc<Link>> {
    link(session, &target.fqdn, true)
        .await?
        .ok_or_else(|| anyhow!("could not join the agent bus"))
}

fn written(mut v: Value, what: &str) -> Value {
    if let Some(m) = v.as_object_mut() {
        m.insert("signed_by".into(), json!("device-signed"));
        m.insert("done".into(), json!(what));
        v
    } else {
        json!({"done": what, "signed_by": "device-signed", "answer": v})
    }
}

/// Run one bus tool against `target`.
pub async fn call(
    session: &Arc<Session>,
    target: &Target,
    name: &str,
    args: &Value,
) -> Result<Value> {
    let fqdn = &target.fqdn;
    let api = bus_client(session, fqdn).await?;
    let existing = link(session, fqdn, false).await?;
    match name {
        "bus_sessions" => {
            let mut v = api.get("/sessions").await?;
            let me = match &existing {
                Some(l) => Some(l.session_id().await),
                None => None,
            };
            if let Some(list) = v["sessions"].as_array_mut() {
                for row in list.iter_mut() {
                    let you = me.as_deref() == row["id"].as_str();
                    row["you"] = json!(you);
                    row["writes"] = json!(if row["attestation"] == "operator" {
                        "operator-attested"
                    } else {
                        "device-signed"
                    });
                }
            }
            let items = v["sessions"].as_array().cloned().unwrap_or_default();
            let page = crate::mcp::bounds::page(
                items,
                s(args, "cursor"),
                args.get("limit").and_then(Value::as_i64),
            );
            let mut out = json!({"sessions": page.items, "total": page.total});
            if let Some(n) = page.next_cursor {
                out["next_cursor"] = json!(n);
            }
            Ok(out)
        }
        "bus_topics" => {
            let mut v = api.get("/topics").await?;
            let dir = bus_dir(&state_dir(session)?, fqdn);
            let mut policies = Policies::load(&dir);
            let mut warnings = Vec::new();
            for t in v["topics"].as_array().into_iter().flatten() {
                if let (Some(n), Some(r)) =
                    (t["name"].as_str(), t["require_device_signature"].as_bool())
                {
                    warnings.extend(policies.observe(n, r));
                }
            }
            policies
                .save(&dir)
                .log_warn("saving the bus topic policies");
            if !warnings.is_empty() {
                v["policy_warnings"] = json!(warnings);
            }
            Ok(v)
        }
        "bus_read" => read(session, existing.as_ref(), fqdn, &api, args).await,
        "bus_thread" => {
            let mut v = api
                .get(&format!(
                    "/messages/{}/thread",
                    seg(need(args, "message_id")?)
                ))
                .await?;
            let mut items = items_of(&mut v);
            label_all(session, existing.as_ref(), fqdn, &mut items).await;
            Ok(json!({"items": items}))
        }
        "bus_claims" => {
            let topic = need(args, "topic")?;
            let path = match s(args, "name") {
                Some(n) => format!("/topics/{}/claims/{}", seg(topic), seg(n)),
                None => format!("/topics/{}/claims", seg(topic)),
            };
            api.get(&path).await
        }
        "bus_state_get" => {
            api.get(&format!(
                "/topics/{}/state/{}",
                seg(need(args, "topic")?),
                seg(need(args, "key")?)
            ))
            .await
        }
        "bus_state_list" => {
            api.get(&format!("/topics/{}/state", seg(need(args, "topic")?)))
                .await
        }
        "bus_topic_policy" => {
            let topic = need(args, "topic")?;
            let path = format!("/topics/{}/policy", seg(topic));
            let strict = args
                .get("require_device_signature")
                .and_then(Value::as_bool);
            let hours = args.get("retention_hours").and_then(Value::as_i64);
            let dir = bus_dir(&state_dir(session)?, fqdn);
            let mut v = if strict.is_none() && hours.is_none() {
                api.get(&path).await?
            } else {
                if session.opts.read_only {
                    bail!("changing a topic's policy changes something, and this session is read-only");
                }
                // A PUT replaces both: read what is there for the one not given.
                let now = api.get(&path).await?;
                let body = json!({
                    "require_device_signature": strict.or_else(|| now["require_device_signature"].as_bool()).unwrap_or(false),
                    "retention_hours": hours.or_else(|| now["retention_hours"].as_i64()).unwrap_or(72),
                });
                let l = writer(session, target).await?;
                written(
                    write(session, &l, Method::PUT, &path, "policy.put", topic, &body).await?,
                    "policy changed",
                )
            };
            if let Some(r) = v["require_device_signature"].as_bool() {
                let mut policies = Policies::load(&dir);
                if let Some(w) = policies.observe(topic, r) {
                    v["policy_warning"] = json!(w);
                }
                policies
                    .save(&dir)
                    .log_warn("saving the bus topic policies");
            }
            Ok(v)
        }
        _ => write_tool(session, target, name, args).await,
    }
}

async fn read(
    session: &Arc<Session>,
    existing: Option<&Arc<Link>>,
    fqdn: &str,
    api: &BusClient,
    args: &Value,
) -> Result<Value> {
    if let Some(topic) = s(args, "topic") {
        let after = args.get("after_seq").and_then(Value::as_i64).unwrap_or(0);
        let mut v = api
            .get(&format!(
                "/topics/{}/messages?after_seq={after}&limit={}",
                seg(topic),
                limit(args)
            ))
            .await?;
        let mut items = items_of(&mut v);
        label_all(session, existing, fqdn, &mut items).await;
        return Ok(json!({"items": items, "next_after_seq": v["next_after_seq"]}));
    }
    // The inbox: everything after this session's cursor, pushed or not.
    let Some(l) = existing.filter(|l| l.is_registered()) else {
        bail!(
            "this session is not on the agent bus, so it has no inbox; pass a topic, or \
             turn the bus on in the plugin's settings"
        );
    };
    let sid = l.session_id().await;
    let cursor = l.delivery.lock().await.cursor;
    let mut v = api
        .get(&format!(
            "/messages?session={sid}&after={cursor}&limit={}",
            limit(args)
        ))
        .await?;
    let mut items = items_of(&mut v);
    let mut to_ack = Vec::new();
    for item in &mut items {
        label(session, l, item).await;
        let id = item["id"].as_str().unwrap_or_default().to_owned();
        let pushed = l.delivery.lock().await.was_pushed(&id);
        item["already_pushed"] = json!(pushed);
        let mine = item["from_session"].as_str() == Some(sid.as_str());
        if item["kind"] == "message" && !pushed && !mine {
            to_ack.push(id);
        }
    }
    let next = v["next_cursor"]
        .as_i64()
        .or_else(|| items.iter().filter_map(|i| i["cursor"].as_i64()).max());
    {
        let mut d = l.delivery.lock().await;
        if let Some(n) = next {
            d.advance(n);
        }
        d.save(&l.dir, &sid)
            .log_warn("saving the bus delivery cursor");
    }
    for id in to_ack {
        ack_delivered(session, l, &id).await;
    }
    Ok(json!({"items": items, "cursor": l.delivery.lock().await.cursor}))
}

async fn write_tool(
    session: &Arc<Session>,
    target: &Target,
    name: &str,
    args: &Value,
) -> Result<Value> {
    let l = writer(session, target).await?;
    match name {
        "bus_post" => {
            let content = need(args, "content")?;
            let mut body = message_body(args, content);
            match (s(args, "topic"), s(args, "to_session")) {
                (Some(t), None) => {
                    fenced(session, &l, t, args, &mut body).await?;
                    let v = write(
                        session,
                        &l,
                        Method::POST,
                        &format!("/topics/{}/messages", seg(t)),
                        "message.post",
                        &format!("topic:{t}"),
                        &body,
                    )
                    .await?;
                    Ok(written(v, "posted"))
                }
                (None, Some(to)) => {
                    if s(args, "fence").is_some() {
                        bail!("a direct message cannot be fenced; post to the claim's topic");
                    }
                    let v = write(
                        session,
                        &l,
                        Method::POST,
                        &format!("/sessions/{}/messages", seg(to)),
                        "message.post",
                        &format!("session:{to}"),
                        &body,
                    )
                    .await?;
                    Ok(written(v, "sent"))
                }
                _ => bail!("name exactly one of topic and to_session"),
            }
        }
        "bus_reply" => {
            let parent = need(args, "message_id")?;
            let api = bus_client(session, &l.fqdn).await?;
            let thread = api
                .get(&format!("/messages/{}/thread", seg(parent)))
                .await?;
            let original = thread["items"]
                .as_array()
                .and_then(|a| a.iter().find(|i| i["id"] == parent).or_else(|| a.first()))
                .cloned()
                .ok_or_else(|| anyhow!("no message {parent} is readable here"))?;
            let mut body = message_body(args, need(args, "content")?);
            body["in_reply_to"] = json!(parent);
            let stream = original["stream"].as_str().unwrap_or_default();
            let v = if let Some(t) = stream.strip_prefix("topic:") {
                fenced(session, &l, t, args, &mut body).await?;
                write(
                    session,
                    &l,
                    Method::POST,
                    &format!("/topics/{}/messages", seg(t)),
                    "message.post",
                    &format!("topic:{t}"),
                    &body,
                )
                .await?
            } else {
                let to = original["from_session"]
                    .as_str()
                    .ok_or_else(|| anyhow!("the message has no sender to reply to"))?;
                write(
                    session,
                    &l,
                    Method::POST,
                    &format!("/sessions/{}/messages", seg(to)),
                    "message.post",
                    &format!("session:{to}"),
                    &body,
                )
                .await?
            };
            Ok(written(v, "replied"))
        }
        "bus_ack" => {
            let id = need(args, "message_id")?;
            let mut body = json!({"state": s(args, "state").unwrap_or("handled")});
            if let Some(n) = s(args, "note") {
                body["note"] = json!(n);
            }
            let v = write(
                session,
                &l,
                Method::POST,
                &format!("/messages/{}/acks", seg(id)),
                "ack",
                id,
                &body,
            )
            .await?;
            Ok(written(v, "acknowledged"))
        }
        "bus_claim" | "bus_renew" => {
            let topic = need(args, "topic")?;
            let cname = need(args, "name")?;
            let ttl = args.get("ttl_seconds").and_then(Value::as_u64);
            let key = (topic.to_owned(), cname.to_owned());
            let (verb, op, mut body) = if name == "bus_claim" {
                ("acquire", "claim.acquire", json!({}))
            } else {
                let token = held_token(session, &l, topic, cname)
                    .await
                    .ok_or_else(|| anyhow!("this session holds no claim {cname} on {topic}"))?;
                ("renew", "claim.renew", json!({"token": token}))
            };
            if let Some(t) = ttl {
                body["ttl_seconds"] = json!(t);
            }
            let v = write(
                session,
                &l,
                Method::POST,
                &format!("/topics/{}/claims/{}/{verb}", seg(topic), seg(cname)),
                op,
                &format!("{topic}/{cname}"),
                &body,
            )
            .await;
            let v = match v {
                Err(e) => {
                    if let Some(r) = client::refusal(&e).filter(|r| r.code == "claim_held") {
                        // Held already — by this session, through a handoff.
                        let me = l.session_id().await;
                        if r.extra("holder_session").and_then(Value::as_str) == Some(me.as_str()) {
                            if let Some(token) = held_token(session, &l, topic, cname).await {
                                return Ok(json!({
                                    "granted": true,
                                    "done": "already held by this session",
                                    "token": token,
                                    "holder_session": me,
                                    "renewed_automatically": true,
                                }));
                            }
                        }
                        return Ok(json!({
                            "granted": false,
                            "held_by": r.extra("holder_session"),
                            "holder_label": r.extra("holder_label"),
                            "expires_at": r.extra("expires_at"),
                            "say": "Somebody else holds this claim. Do not start the work; ask the user or wait.",
                        }));
                    }
                    l.held.lock().await.remove(&key);
                    return Err(e);
                }
                Ok(v) => v,
            };
            let token = v["token"]
                .as_i64()
                .context("the operator answered no token")?;
            let lease = ttl.unwrap_or_else(|| default_ttl(&l));
            l.held.lock().await.insert(
                key,
                Held {
                    token,
                    ttl: lease,
                    renewed_at: Instant::now(),
                },
            );
            let mut out = written(
                v,
                if name == "bus_claim" {
                    "claimed"
                } else {
                    "renewed"
                },
            );
            out["granted"] = json!(true);
            out["renewed_automatically"] = json!(true);
            Ok(out)
        }
        "bus_release" | "bus_handoff" => {
            let topic = need(args, "topic")?;
            let cname = need(args, "name")?;
            let key = (topic.to_owned(), cname.to_owned());
            let token = held_token(session, &l, topic, cname)
                .await
                .ok_or_else(|| anyhow!("this session holds no claim {cname} on {topic}"))?;
            let (verb, op, mut body) = if name == "bus_release" {
                ("release", "claim.release", json!({"token": token}))
            } else {
                (
                    "handoff",
                    "claim.handoff",
                    json!({"token": token, "to_session": need(args, "to_session")?}),
                )
            };
            if name == "bus_handoff" {
                if let Some(n) = s(args, "note") {
                    body["note"] = json!(n);
                }
            }
            let r = write(
                session,
                &l,
                Method::POST,
                &format!("/topics/{}/claims/{}/{verb}", seg(topic), seg(cname)),
                op,
                &format!("{topic}/{cname}"),
                &body,
            )
            .await;
            // Released, handed on, or refused because it had already
            // moved: either way this session no longer holds it.
            l.held.lock().await.remove(&key);
            Ok(written(
                r?,
                if name == "bus_release" {
                    "released"
                } else {
                    "handed off"
                },
            ))
        }
        "bus_state_put" | "bus_state_delete" => {
            let topic = need(args, "topic")?;
            let key = need(args, "key")?;
            let if_version = args
                .get("if_version")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("if_version is required (0 creates only)"))?;
            let mut body = json!({"if_version": if_version});
            let method = if name == "bus_state_put" {
                body["value"] = args
                    .get("value")
                    .cloned()
                    .ok_or_else(|| anyhow!("value is required"))?;
                Method::PUT
            } else {
                Method::DELETE
            };
            fenced(session, &l, topic, args, &mut body).await?;
            let op = if name == "bus_state_put" {
                "state.put"
            } else {
                "state.delete"
            };
            let v = write(
                session,
                &l,
                method,
                &format!("/topics/{}/state/{}", seg(topic), seg(key)),
                op,
                &format!("{topic}/{key}"),
                &body,
            )
            .await?;
            Ok(written(
                v,
                if name == "bus_state_put" {
                    "written"
                } else {
                    "deleted"
                },
            ))
        }
        other => bail!("no tool named {other}"),
    }
}

/// What `whoami` says about the bus and about delivery.
pub async fn report(session: &Arc<Session>) -> Value {
    let links: Vec<Arc<Link>> = session.bus_links.lock().await.values().cloned().collect();
    let mut sessions = Vec::new();
    for l in links {
        sessions.push(json!({
            "airdress": l.fqdn,
            "session_id": l.session_id().await,
            "registered": l.is_registered(),
            "label": session.session_label(),
            "topics": session.opts.bus_topics,
            "claims_held": l.claims().await,
            "read_cursor": l.delivery.lock().await.cursor,
        }));
    }
    json!({
        "joined_at_start": session.opts.bus && !session.opts.read_only,
        "sessions": sessions,
        "error": *session.bus_error.lock().await,
        "notices": session.bus_notices.lock().await.clone(),
    })
}

/// How messages reach the model, in one sentence.
pub const DELIVERY: &str = "Bus items from other sessions are pushed as channel events \
    when the client has the channel turned on, and are always readable with bus_read \
    (without a topic: everything since this session last read, with already_pushed \
    marking what was pushed). Nothing is lost when pushes are dropped.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_or_key_with_a_slash_stays_one_segment() {
        assert_eq!(seg("db/x"), "db%2Fx");
        assert_eq!(seg("status/x"), "status%2Fx");
        assert_eq!(seg("a b"), "a%20b");
    }

    fn handoff(to: &str, expires_at: &str) -> Value {
        json!({
            "id": "m-1", "kind": "handoff", "from_session": "giver",
            "content": "yours now",
            "data": {
                "topic": "work", "name": "lease", "token": 2, "ttl_seconds": 240,
                "expires_at": expires_at, "from_session": "giver", "to_session": to,
            },
        })
    }

    /// FR-50 — the receiver holds the claim from the handoff item alone:
    /// topic, name, the new token and the lease, with no `bus_claim`.
    #[test]
    fn a_handoff_to_this_session_is_a_claim_it_holds() {
        let later = (chrono::Utc::now() + chrono::Duration::minutes(4)).to_rfc3339();
        let got = handed_to(&handoff("me", &later), "me", 300).expect("held");
        assert_eq!(got, (("work".into(), "lease".into()), 2, 240));
        // An older operator says no lease length: the default stands in.
        let mut item = handoff("me", &later);
        item["data"].as_object_mut().unwrap().remove("ttl_seconds");
        assert_eq!(handed_to(&item, "me", 300).unwrap().2, 300);
    }

    #[test]
    fn a_handoff_to_someone_else_or_already_lapsed_is_not_held() {
        let later = (chrono::Utc::now() + chrono::Duration::minutes(4)).to_rfc3339();
        let earlier = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        assert!(handed_to(&handoff("other", &later), "me", 300).is_none());
        assert!(handed_to(&handoff("me", &earlier), "me", 300).is_none());
        let mut msg = handoff("me", &later);
        msg["kind"] = json!("message");
        assert!(handed_to(&msg, "me", 300).is_none());
    }

    /// Reading the claim is the fallback when the event has not arrived.
    #[test]
    fn a_claim_row_naming_this_session_gives_its_token() {
        let row = json!({"name": "lease", "holder_session": "me", "token": 2});
        assert_eq!(held_by(&row, "me"), Some(2));
        assert_eq!(held_by(&row, "other"), None);
        let lapsed =
            json!({"name": "lease", "holder_session": null, "token": null, "last_token": 2});
        assert_eq!(held_by(&lapsed, "me"), None);
    }

    #[test]
    fn optional_message_fields_are_omitted_not_null() {
        let b = message_body(&json!({"data_schema": ""}), "hi");
        assert_eq!(b, json!({"content": "hi"}));
        let b = message_body(
            &json!({"data": {"task": "x"}, "data_schema": "airdress.task.v1"}),
            "hi",
        );
        assert_eq!(b["data"]["task"], "x");
    }
}
