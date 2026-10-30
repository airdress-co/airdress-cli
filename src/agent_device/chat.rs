//! Agent chat in the device host: the MLS member, the envelope pump, and
//! the four socket operations the editor's server asks (design §9.5).
//!
//! The device host is the only process on this machine that holds the
//! device's chat keys. It keeps one [`airdress_mls_client::Client`] (the
//! engine over the sealed MLS state, and the conversation↔group
//! directory) and one [`ChatStore`], pumps envelopes from the operator's
//! per-device stream, stores what decrypts, acknowledges it, and wakes
//! whoever is waiting in `chat.wait`.
//!
//! Two kinds of conversation, and nothing else (FR-23, FR-28, FR-31):
//!
//! - **own** — this device's lane with the operator's agent. The device
//!   asks the operator for its lane (one per enrollment), and on the first
//!   send establishes the group itself: it fetches the operator agent's key
//!   package and root, and sends the Welcome and the first message.
//! - **assigned** — a conversation a person gave this device. A phone of
//!   theirs that is a member adds this device's leaf; the Welcome arrives
//!   on the stream like any envelope. This device never seats itself.
//!
//! Socket operations: `chat.conversations`, `chat.read {conversation_id?,
//! after?, limit}`, `chat.send {conversation_id, text,
//! reply_to_message_id?, reply_to?}`, `chat.reply_ref {conversation_id,
//! message_id}` (the `reply_to` a reply to that message carries),
//! `chat.wait {after?, timeout_ms}` (a long poll; `after: null` answers
//! the head).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use airdress_mls_client::{
    Client, Event, InboundEnvelope, OutboundEnvelope, PinObservation, PinStore,
};
use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use reqwest::Method;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Notify};

use super::chat_store::{ChatStore, Message, Reply};
use super::formatted;
use super::reply;
use super::store::{AgentDevice, AgentStore};
use crate::agent_bus::session_sig;
use crate::log_err::LogErr as _;
use crate::redact::Redacted;

/// Where the operator's own agent lives, as the lane names it.
pub const OPERATOR_LANE_TARGET: &str = "operator.local";
/// Key packages kept published, so a phone can add this device.
const KEY_PACKAGES: usize = 8;

/// How many of its stored key packages a host offers again when it starts
/// (SPEC-166 166-I.7). The operator holds at most 64 per pool, which phones
/// share.
const REPUBLISH_MAX: usize = 2 * KEY_PACKAGES;
/// Stream reconnect bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// The longest a `chat.wait` is held.
const WAIT_MAX: Duration = Duration::from_secs(30);

/// How long a session's name is held after its last wait: two of the
/// longest waits, so one slow poll does not free it (SPEC-166 §5.2).
const NAME_HELD: Duration = Duration::from_secs(60);

/// How long a holder must have been silent before a session with the same
/// pinned name takes it over: one longest wait and a margin. A live holder
/// starts a wait the moment the last one ends, so it is never this quiet;
/// a restarted session finds its old self this quiet within a wait or two
/// (the operator's takeover rule for the bus, FR-18).
const NAME_TAKEOVER: Duration = Duration::from_secs(35);

/// The names of the sessions waiting on this host (SPEC-166 §5.2). Each
/// name is held by the nonce of the session that took it, and lapses
/// [`NAME_HELD`] after that session's last wait.
#[derive(Debug, Default)]
pub struct NameTable {
    held: HashMap<String, (String, Instant)>,
}

/// What a wait carrying a name is answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// The name is this session's (now, or again).
    Held,
    /// Another live session holds it; this one could be `suggested`. For a
    /// pinned name, `retry_after` says when the holder will count as gone
    /// if it does not wait again.
    Taken {
        suggested: String,
        retry_after: Option<Duration>,
    },
}

impl NameTable {
    /// `nonce`'s session waits as `name` at `now`. A `pinned` name (one a
    /// person configured) is taken over from a holder that has stopped
    /// waiting, so a restarted session gets its name back.
    pub fn claim(&mut self, name: &str, nonce: &str, pinned: bool, now: Instant) -> Claim {
        self.lapse(now);
        match self.held.get(name) {
            Some((holder, seen))
                if holder != nonce
                    && !(pinned && now.saturating_duration_since(*seen) >= NAME_TAKEOVER) =>
            {
                let retry_after = pinned.then(|| {
                    NAME_TAKEOVER
                        .saturating_sub(now.saturating_duration_since(*seen))
                        .max(Duration::from_secs(1))
                });
                let taken: Vec<String> = self.held.keys().cloned().collect();
                Claim::Taken {
                    suggested: crate::mcp::names::free(name, &taken),
                    retry_after,
                }
            }
            _ => {
                // A session that renamed itself frees its old name.
                self.held
                    .retain(|n, (holder, _)| holder != nonce || n == name);
                self.held.insert(name.to_owned(), (nonce.to_owned(), now));
                Claim::Held
            }
        }
    }

    /// The live names, sorted.
    pub fn here(&mut self, now: Instant) -> Vec<String> {
        self.lapse(now);
        let mut v: Vec<String> = self.held.keys().cloned().collect();
        v.sort_unstable();
        v
    }

    fn lapse(&mut self, now: Instant) {
        self.held
            .retain(|_, (_, seen)| now.saturating_duration_since(*seen) < NAME_HELD);
    }
}

/// What the host needs of the device to talk to the operator.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub operator: String,
    pub airdress: String,
    pub enrollment_id: String,
    pub token: Redacted<String>,
    pub root_public: [u8; 32],
}

impl Credentials {
    /// From an approved, enrolled device; `None` otherwise.
    pub fn of(dev: &AgentDevice) -> Option<Self> {
        if dev.record.enrollment_id.is_empty() || dev.token.expose().is_empty() {
            return None;
        }
        let root_public = URL_SAFE_NO_PAD
            .decode(&dev.record.root_public)
            .ok()?
            .try_into()
            .ok()?;
        Some(Self {
            operator: dev.record.operator.trim_end_matches('/').to_owned(),
            airdress: dev.record.airdress.clone(),
            enrollment_id: dev.record.enrollment_id.clone(),
            token: dev.token.clone(),
            root_public,
        })
    }
}

/// `POST /v1/chat/key-packages` with `packages`.
async fn post_key_packages(api: &Api, packages: &[Vec<u8>]) -> Result<()> {
    let list: Vec<String> = packages.iter().map(|k| STANDARD.encode(k)).collect();
    api.request(
        Method::POST,
        "/v1/chat/key-packages",
        Some(&json!({"key_packages": list})),
    )
    .await?;
    Ok(())
}

/// Retire this device's unconsumed packages on the operator, then publish
/// `stored` (what the engine still holds) and `fresh`. A refused retire is
/// said and the publish still happens: an operator without the route keeps
/// what it had, which is no worse than before.
async fn retire_and_publish(api: &Api, stored: Vec<Vec<u8>>, fresh: Vec<Vec<u8>>) -> Result<()> {
    api.request(Method::DELETE, "/v1/chat/key-packages", None)
        .await
        .log_warn("agent chat: retiring this device's published key packages");
    let mut all = stored;
    all.extend(fresh);
    if all.is_empty() {
        return Ok(());
    }
    post_key_packages(api, &all).await
}

/// The operator's chat routes, as this device's bearer reaches them.
#[derive(Debug)]
struct Api {
    base: String,
    token: Redacted<String>,
    http: reqwest::Client,
}

impl Api {
    fn new(c: &Credentials) -> Result<Self> {
        Ok(Self {
            base: c.operator.clone(),
            token: c.token.clone(),
            http: crate::http::client()?,
        })
    }

    async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.base))
            .bearer_auth(self.token.expose());
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("{method} {path}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            bail!(
                "{method} {path} answered {status} {}: {}",
                v["error"]["code"].as_str().unwrap_or(""),
                v["error"]["message"].as_str().unwrap_or(&text)
            );
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn post(&self, out: &OutboundEnvelope) -> Result<Value> {
        let body = serde_json::to_value(out)?;
        self.request(
            Method::POST,
            &format!("/v1/chat/conversations/{}/envelopes", out.conversation_id),
            Some(&body),
        )
        .await
    }

    async fn root_key(&self, airdress: &str) -> Result<[u8; 32]> {
        // The operator's own lane is served by this operator; any other
        // airdress by its own.
        let url = if airdress == OPERATOR_LANE_TARGET {
            format!("{}/v1/endpoints/airdresses/{airdress}/root-key", self.base)
        } else {
            format!("https://{airdress}/v1/endpoints/airdresses/{airdress}/root-key")
        };
        let v: Value = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        URL_SAFE_NO_PAD
            .decode(
                v["root_public_key"]
                    .as_str()
                    .context("no root_public_key")?,
            )
            .ok()
            .and_then(|k| k.try_into().ok())
            .context("a root key that is not 32 bytes")
    }
}

/// The roots the engine may chain leaves to, read synchronously from
/// inside engine calls; primed (with a TOFU pin) before they are needed.
type Roots = Arc<RwLock<HashMap<String, [u8; 32]>>>;

/// One conversation this device may read, as the operator lists it.
#[derive(Debug, Clone)]
struct Conversation {
    id: String,
    lane: &'static str,
    state: Option<String>,
    title: String,
    target: String,
    /// The session this conversation is with, when it is one (SPEC-166
    /// phase C): every message in it is for that name.
    session_name: Option<String>,
}

/// Whether a conversation's `target` names another airdress: not this
/// one, and not a placeholder (`self.local`, `operator.local`, …).
fn is_peer_airdress(target: &str, own: &str) -> bool {
    !target.is_empty()
        && !target.eq_ignore_ascii_case(own)
        && target.contains('.')
        && !target.to_ascii_lowercase().ends_with(".local")
}

/// The chat half of the device host.
pub struct Chat {
    store: AgentStore,
    client: Mutex<Option<Client>>,
    messages: Mutex<Option<ChatStore>>,
    roots: Roots,
    own_lane: Mutex<Option<String>>,
    conversations: Mutex<Vec<Conversation>>,
    arrived: Notify,
    names: std::sync::Mutex<NameTable>,
}

impl std::fmt::Debug for Chat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chat").finish_non_exhaustive()
    }
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": code, "message": message})
}

/// The text of a block array, for the store and the push.
pub fn text_of(blocks: &Value) -> String {
    blocks
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|b| match b["type"].as_str() {
            Some("text") => b["text"].as_str().map(str::to_owned),
            Some("code") => b["code"].as_str().map(|c| format!("```\n{c}\n```")),
            // A notice the app sends, such as a radio session starting:
            // its words matter, or the session sees an empty "[system]"
            // (finding of SPEC-166 166-B.7).
            Some("system") => b["text"].as_str().map(|t| format!("[system] {t}")),
            Some(other) => Some(format!("[{other}]")),
            None => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The reference and the `reply_to` a decrypted message's payload carried,
/// as the shared decoder read them; `reply::parse` then holds `reply_to`
/// to this host's own checks.
fn lane_extras(m: &airdress_mls_client::Message) -> (Option<String>, Option<Value>) {
    (
        m.r#ref.clone(),
        m.reply_to
            .as_ref()
            .and_then(|r| serde_json::to_value(r).ok()),
    )
}

impl Chat {
    pub fn new(store: AgentStore) -> Self {
        Self {
            store,
            client: Mutex::new(None),
            messages: Mutex::new(None),
            roots: Arc::default(),
            own_lane: Mutex::new(None),
            conversations: Mutex::new(Vec::new()),
            arrived: Notify::new(),
            names: std::sync::Mutex::default(),
        }
    }

    fn chat_dir(&self) -> std::path::PathBuf {
        self.store.dir().join("chat")
    }

    /// Open the client and the message store for an approved device.
    async fn open(&self, dev: &AgentDevice, creds: &Credentials) -> Result<()> {
        if self.client.lock().await.is_some() {
            return Ok(());
        }
        let engine = super::join::open_engine(&self.store, dev)?;
        // Past the credential cutover on every live operator; the engine
        // binds the AAD only once told. Past it, no leaf verifies until a
        // revocation lookup is registered (airdress-mls 0.3.0, fail
        // closed): the operator answers it for every member here.
        engine.set_v2_cutover();
        // Each member is asked of its own airdress's operator (owner
        // decision (a), 2026-10-08): this one with the bearer, any other at
        // its own name with no credential.
        engine.set_revocation_lookup(super::revocation::OperatorRevocation::of_operator(
            &creds.operator,
            &creds.airdress,
            creds.token.clone(),
        ));
        self.roots
            .write()
            .map_err(|_| anyhow!("roots poisoned"))?
            .insert(creds.airdress.clone(), creds.root_public);
        let roots = Arc::clone(&self.roots);
        engine.set_root_key_lookup(Arc::new(move |airdress: &str| {
            // Check 2 names the member's airdress right before check 5 asks
            // about its device, on this thread: say whose device it is.
            super::revocation::note_subject(airdress);
            roots.read().ok().and_then(|r| r.get(airdress).copied())
        }));
        let dir = self.chat_dir();
        let client = Client::open(engine, &dir.join("mls-client"), dev.state_key.expose())
            .map_err(|e| anyhow!("open the chat directory: {e}"))?;
        *self.client.lock().await = Some(client);
        *self.messages.lock().await = Some(ChatStore::open(&dir, *dev.state_key.expose())?);
        Ok(())
    }

    /// Learn (and pin, first use) the root an airdress's leaves chain to.
    async fn prime_root(&self, api: &Api, airdress: &str) -> Result<()> {
        if self
            .roots
            .read()
            .map_err(|_| anyhow!("roots poisoned"))?
            .contains_key(airdress)
        {
            return Ok(());
        }
        let fetched = api.root_key(airdress).await?;
        let pins_dir = self.chat_dir();
        let key = self.state_key().await?;
        let mut pins =
            PinStore::open(&pins_dir.join("pins"), key.expose()).map_err(|e| anyhow!(e))?;
        let accepted = match pins
            .observe(airdress, &fetched, &Utc::now().to_rfc3339())
            .map_err(|e| anyhow!(e))?
        {
            PinObservation::Pinned | PinObservation::Matched => fetched,
            // A changed root is recorded, not adopted: the pinned one stays
            // in force and the new one's leaves do not verify.
            PinObservation::Changed { pinned, .. } => {
                tracing::warn!(
                    event = "airdress.agent_chat.root_pin_changed",
                    %airdress,
                    "an airdress presented a different root than the one pinned; keeping the pin"
                );
                pinned
            }
        };
        self.roots
            .write()
            .map_err(|_| anyhow!("roots poisoned"))?
            .insert(airdress.to_owned(), accepted);
        Ok(())
    }

    async fn state_key(&self) -> Result<Redacted<[u8; 32]>> {
        Ok(self
            .store
            .load()?
            .context("no agent device on this machine")?
            .state_key)
    }

    /// Refresh the operator's list of this device's conversations, asking
    /// for the own lane first (the operator creates it on first ask).
    async fn refresh(&self, api: &Api) -> Result<Vec<Conversation>> {
        let lane = api
            .request(Method::POST, "/v1/chat/agent-lane", Some(&json!({})))
            .await?;
        let lane_id = lane["conversation_id"]
            .as_str()
            .or(lane["conversation"]["id"].as_str())
            .context("the operator answered no lane")?
            .to_owned();
        *self.own_lane.lock().await = Some(lane_id.clone());
        let v = api
            .request(Method::GET, "/v1/chat/agent-conversations", None)
            .await?;
        let mut out = vec![Conversation {
            id: lane_id.clone(),
            lane: "own",
            state: None,
            title: "Operator".into(),
            target: OPERATOR_LANE_TARGET.into(),
            session_name: None,
        }];
        for c in v["conversations"].as_array().into_iter().flatten() {
            let conversation_row = if c["conversation"].is_object() {
                &c["conversation"]
            } else {
                c
            };
            let Some(id) = conversation_row["id"]
                .as_str()
                .or(c["conversation_id"].as_str())
            else {
                continue;
            };
            if id == lane_id {
                continue;
            }
            out.push(Conversation {
                id: id.to_owned(),
                lane: "assigned",
                state: c["assignment_state"]
                    .as_str()
                    .or(c["state"].as_str())
                    .map(str::to_owned),
                title: conversation_row["title"].as_str().unwrap_or("").to_owned(),
                target: conversation_row["target_airdress"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                session_name: c["session_name"]
                    .as_str()
                    .and_then(|n| crate::mcp::names::normalise(n).ok()),
            });
        }
        *self.conversations.lock().await = out.clone();
        Ok(out)
    }

    /// Whether this device's listing has `conversation`.
    async fn knows(&self, conversation: &str) -> bool {
        self.conversations
            .lock()
            .await
            .iter()
            .any(|c| c.id == conversation)
    }

    /// The other airdress of `conversation`, when it is with one: its
    /// target, unless that is this airdress or a placeholder such as
    /// `self.local`.
    async fn peer_of(&self, conversation: &str, own: &str) -> Option<String> {
        let conversations = self.conversations.lock().await;
        let target = conversations
            .iter()
            .find(|c| c.id == conversation)
            .map(|c| c.target.clone())?;
        is_peer_airdress(&target, own).then_some(target)
    }

    /// The session `conversation` is with, when it is one.
    async fn session_of(&self, conversation: &str) -> Option<String> {
        self.conversations
            .lock()
            .await
            .iter()
            .find(|c| c.id == conversation)
            .and_then(|c| c.session_name.clone())
    }

    async fn lane_of(&self, conversation: &str) -> &'static str {
        if self.own_lane.lock().await.as_deref() == Some(conversation) {
            "own"
        } else {
            "assigned"
        }
    }

    /// Store one decrypted message; wake waiters.
    async fn keep(&self, m: Message) -> Result<()> {
        let mut guard = self.messages.lock().await;
        let store = guard.as_mut().context("the message store is not open")?;
        if store.append(m, Utc::now())?.is_some() {
            self.arrived.notify_waiters();
        }
        Ok(())
    }

    /// A received reply, resolved against what this machine holds.
    async fn resolve_reply(&self, conversation: &str, wire: &reply::WireReply) -> Option<Reply> {
        let guard = self.messages.lock().await;
        Some(reply::resolve(guard.as_ref()?, conversation, wire))
    }

    /// The `reply_to` this host sends to answer `message_id` in
    /// `conversation`, or the refusal `reply_target_unknown`.
    async fn reply_wire(
        &self,
        conversation: &str,
        message_id: &str,
    ) -> std::result::Result<(Value, Reply), Value> {
        let guard = self.messages.lock().await;
        let original = guard
            .as_ref()
            .and_then(|s| s.get(conversation, message_id))
            .ok_or_else(|| {
                refusal(
                    "reply_target_unknown",
                    "this machine holds no message with that id in that conversation; \
                     take the id from chat_read or a pushed message",
                )
            })?;
        let wire = reply::wire_of(original);
        let resolved = Reply {
            message_id: Some(original.message_id.clone()),
            from: original.from.clone(),
            by_session: original.by_session.clone(),
            kind: original.kind.clone().unwrap_or_else(|| "text".into()),
            text: original
                .quotable
                .clone()
                .unwrap_or_else(|| original.text.clone()),
            resolved: true,
        };
        Ok((wire, resolved))
    }

    /// Publish key packages so a phone can add this device to a
    /// conversation it was assigned.
    async fn publish_key_packages(&self, api: &Api) -> Result<()> {
        let packages = {
            let mut guard = self.client.lock().await;
            let client = guard.as_mut().context("chat is not open")?;
            client.key_packages(KEY_PACKAGES).map_err(|e| anyhow!(e))?
        };
        post_key_packages(api, &packages).await
    }

    /// What a host publishes when it starts: the operator's pool for this
    /// device is replaced by what this device's engine can open
    /// (SPEC-166 166-I.7).
    ///
    /// The pool serves a device's packages oldest first, and a package
    /// whose private half this engine does not hold yields a Welcome that
    /// can never be joined, so every conversation assigned next was lost
    /// while one such package was left (measured 2026-10-30: "cannot join
    /// from this Welcome: key package not found"). The phone retires its
    /// own before it republishes (SPEC-061 061-KP.1); the host never did.
    async fn republish_key_packages(&self, api: &Api) -> Result<()> {
        let (stored, fresh) = {
            let mut guard = self.client.lock().await;
            let client = guard.as_mut().context("chat is not open")?;
            let mut stored = client
                .engine()
                .stored_key_packages()
                .map_err(|e| anyhow!(e))?;
            stored.truncate(REPUBLISH_MAX);
            let fresh = if stored.len() < KEY_PACKAGES {
                client
                    .key_packages(KEY_PACKAGES - stored.len())
                    .map_err(|e| anyhow!(e))?
            } else {
                Vec::new()
            };
            (stored, fresh)
        };
        retire_and_publish(api, stored, fresh).await
    }

    /// One envelope from the stream: process, keep, acknowledge.
    async fn handle(&self, api: &Api, creds: &Credentials, env: InboundEnvelope) -> Result<()> {
        if !env.from_airdress.is_empty() && env.from_airdress != creds.airdress {
            // Unpinned, the sender's leaves do not verify and the envelope
            // is refused below; the failure is said here, where it is known.
            self.prime_root(api, &env.from_airdress)
                .await
                .log_warn("agent chat: learning a sender's root");
        }
        // A conversation with another airdress holds that airdress's
        // leaves, whose chain verifies against its root. A Welcome into it
        // comes from this device's own owner, so the sender check above
        // never learns that root, and the join failed "published root key
        // unavailable" (SPEC-166 phase D). The listing
        // names the conversation's other airdress; read it first when the
        // conversation is new to this device.
        if self
            .peer_of(&env.conversation_id, &creds.airdress)
            .await
            .is_none()
            && !self.knows(&env.conversation_id).await
        {
            self.refresh(api)
                .await
                .map(|_| ())
                .log_warn("agent chat: refreshing conversations");
        }
        if let Some(peer) = self.peer_of(&env.conversation_id, &creds.airdress).await {
            self.prime_root(api, &peer)
                .await
                .log_warn("agent chat: learning a conversation's other airdress's root");
        }
        let processed = {
            let mut guard = self.client.lock().await;
            let client = guard.as_mut().context("chat is not open")?;
            client.process(&env)
        };
        match &processed.event {
            Event::Message(m) => {
                let from = match m.origin.as_deref() {
                    Some("agent") => "operator".to_owned(),
                    _ => m.from_airdress.clone(),
                };
                let lane = self.lane_of(&m.conversation_id).await;
                let for_session = self.session_of(&m.conversation_id).await;
                let (msg_ref, reply_wire) = lane_extras(m);
                let reply_to = match reply_wire.as_ref().and_then(reply::parse) {
                    Some(w) => self.resolve_reply(&m.conversation_id, &w).await,
                    None => None,
                };
                self.keep(Message {
                    seq: 0,
                    message_id: m.envelope_id.clone(),
                    conversation_id: m.conversation_id.clone(),
                    from,
                    lane: lane.into(),
                    from_self: false,
                    text: text_of(&m.blocks),
                    at: m
                        .received_at
                        .as_deref()
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .map_or_else(Utc::now, |t| t.with_timezone(&Utc)),
                    for_session,
                    msg_ref,
                    reply_to,
                    by_session: None,
                    kind: Some(reply::kind_of(&m.blocks).to_owned()),
                    quotable: Some(reply::quotable_text(&m.blocks)),
                })
                .await?;
            }
            Event::RejoinNeeded {
                conversation_id,
                reason,
            } => {
                tracing::warn!(%conversation_id, %reason, "agent chat: asking to rejoin");
                api.request(
                    Method::POST,
                    &format!("/v1/chat/conversations/{conversation_id}/rejoin-request"),
                    Some(&json!({})),
                )
                .await
                .log_warn("agent chat: asking to rejoin");
            }
            Event::Joined {
                conversation_id, ..
            } => {
                tracing::info!(%conversation_id, "agent chat: joined a conversation");
                // A conversation with a named session says so only in the
                // listing; learn it before its first message is kept.
                self.refresh(api)
                    .await
                    .map(|_| ())
                    .log_warn("agent chat: refreshing conversations");
            }
            Event::Removed { conversation_id } => {
                tracing::info!(%conversation_id, "agent chat: removed from a conversation");
            }
            Event::Failed { reason, retryable } => {
                tracing::warn!(%reason, retryable, "agent chat: an envelope did not process");
            }
            Event::Membership { .. } | Event::Ignored { .. } => {}
        }
        if processed.ack {
            api.request(
                Method::POST,
                &format!(
                    "/v1/chat/conversations/{}/envelopes/{}/ack",
                    env.conversation_id, env.envelope_id
                ),
                None,
            )
            .await?;
        }
        Ok(())
    }

    /// Hold the device's envelope stream until `cancel`, reconnecting with
    /// backoff. Does nothing until the device is approved.
    pub async fn pump(
        self: Arc<Self>,
        device: Arc<Mutex<Option<AgentDevice>>>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let mut backoff = BACKOFF_MIN;
        let mut published = false;
        loop {
            let ready = {
                let guard = device.lock().await;
                match guard.as_ref() {
                    Some(dev) => match Credentials::of(dev) {
                        Some(c) => self.open(dev, &c).await.map(|()| c).ok(),
                        None => None,
                    },
                    None => None,
                }
            };
            let Some(creds) = ready else {
                tokio::select! {
                    // cancel-safe: `CancellationToken::cancelled`.
                    () = cancel.cancelled() => return,
                    // cancel-safe: a sleep.
                    () = tokio::time::sleep(Duration::from_secs(5)) => continue,
                }
            };
            let result = self.stream_once(&creds, &mut published, &cancel).await;
            if let Err(e) = result {
                tracing::debug!(error = %format!("{e:#}"), "agent chat stream ended");
            } else {
                backoff = BACKOFF_MIN;
            }
            tokio::select! {
                // cancel-safe: `CancellationToken::cancelled`.
                () = cancel.cancelled() => return,
                // cancel-safe: a sleep.
                () = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn stream_once(
        &self,
        creds: &Credentials,
        published: &mut bool,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let api = Api::new(creds)?;
        self.refresh(&api)
            .await
            .log_warn("agent chat: refreshing conversations");
        if !*published {
            self.republish_key_packages(&api).await?;
            *published = true;
        }
        let mut resp = api
            .http
            .get(format!("{}/v1/chat/envelopes/events", api.base))
            .bearer_auth(api.token.expose())
            .header("accept", "text/event-stream")
            .send()
            .await?
            .error_for_status()?;
        let mut parser = crate::agent_bus::sse::Parser::default();
        loop {
            let chunk = tokio::select! {
                // cancel-safe: `CancellationToken::cancelled`.
                () = cancel.cancelled() => return Ok(()),
                // cancel-safe: `Response::chunk` hands back a body frame in
                // the poll that reads it, and the parser holds any partial
                // event outside the loop; the only loser is the cancel arm,
                // which ends the stream anyway.
                c = resp.chunk() => c?,
            };
            let Some(bytes) = chunk else { return Ok(()) };
            for ev in parser.feed(&bytes) {
                match ev.event.as_str() {
                    "envelope" => {
                        let env: InboundEnvelope = match serde_json::from_str(&ev.data) {
                            Ok(e) => e,
                            Err(e) => {
                                tracing::warn!(error = %e, "agent chat: an envelope event did not parse");
                                continue;
                            }
                        };
                        if let Err(e) = self.handle(&api, creds, env).await {
                            tracing::warn!(error = %format!("{e:#}"), "agent chat: envelope handling failed");
                        }
                    }
                    "key_package_pool_low" => {
                        self.publish_key_packages(&api)
                            .await
                            .log_warn("agent chat: topping up key packages");
                    }
                    _ => {}
                }
            }
        }
    }

    // ---- socket operations ---------------------------------------------

    /// Answer one `chat.*` operation for an approved device.
    pub async fn op(&self, op: &str, req: &Value, dev: Option<&AgentDevice>) -> Value {
        let Some(dev) = dev else {
            return refusal("not_approved", "this machine is not an agent device yet");
        };
        // An expired device stops chat and says so (FR-24); its renewal is
        // approved on a phone.
        if super::join::standing(dev.record.expires_at, Utc::now())
            == super::join::Standing::Expired
        {
            return refusal(
                "expired",
                &format!(
                    "'{}' expired: chat is stopped until its renewal is approved on your phone",
                    dev.record.label
                ),
            );
        }
        let Some(creds) = Credentials::of(dev) else {
            return refusal(
                "not_approved",
                "this agent device is not approved yet; approve it on your phone",
            );
        };
        if let Err(e) = self.open(dev, &creds).await {
            return refusal("failed", &format!("{e:#}"));
        }
        let answer = match op {
            "chat.conversations" => self.conversations(&creds).await,
            "chat.read" => Ok(self.read(req).await),
            "chat.wait" => Ok(self.wait_as(req, dev).await),
            "chat.group" => Ok(self.group(req).await),
            "chat.send" => self.send(&creds, req, dev).await,
            "chat.reply_ref" => Ok(self.reply_ref(req).await),
            _ => return refusal("unknown_op", "no such chat operation"),
        };
        answer.unwrap_or_else(|e| refusal("failed", &format!("{e:#}")))
    }

    async fn conversations(&self, creds: &Credentials) -> Result<Value> {
        let api = Api::new(creds)?;
        let list = self.refresh(&api).await?;
        let list: Vec<Value> = list
            .into_iter()
            .map(|c| {
                json!({
                    "conversation_id": c.id, "lane": c.lane, "state": c.state,
                    "title": c.title, "target": c.target,
                })
            })
            .collect();
        Ok(json!({"ok": true, "conversations": list}))
    }

    async fn read(&self, req: &Value) -> Value {
        let guard = self.messages.lock().await;
        let Some(store) = guard.as_ref() else {
            return refusal("failed", "the message store is not open");
        };
        let limit = req["limit"].as_u64().unwrap_or(20).clamp(1, 100) as usize;
        let after = req["after"].as_i64().unwrap_or(0);
        let msgs = store.read(req["conversation_id"].as_str(), after, limit);
        let next = msgs.last().map(|m| m.seq);
        let mut v =
            json!({"ok": true, "messages": msgs, "next_cursor": next, "head": store.head()});
        // The quote source is the host's, for building quotes; a reader
        // has the text.
        for m in v["messages"].as_array_mut().into_iter().flatten() {
            if let Some(o) = m.as_object_mut() {
                o.remove("quotable");
            }
        }
        v
    }

    /// `chat.reply_ref`: the `reply_to` object a reply to `message_id`
    /// carries, for a session to sign before it sends (design §7.3).
    async fn reply_ref(&self, req: &Value) -> Value {
        let (Some(conversation), Some(id)) =
            (req["conversation_id"].as_str(), req["message_id"].as_str())
        else {
            return refusal("bad_request", "conversation_id and message_id are required");
        };
        match self.reply_wire(conversation, id).await {
            Ok((wire, _)) => json!({"ok": true, "reply_to": wire}),
            Err(refused) => refused,
        }
    }

    /// A wait, and for a named session that sent its key, the delegation
    /// that lets it sign what it writes (design §11.6). Renewed on every
    /// wait, so it lapses a day after the session stops waiting.
    async fn wait_as(&self, req: &Value, dev: &AgentDevice) -> Value {
        let mut v = self.wait(req).await;
        if v["name_taken"] == json!(true) {
            return v;
        }
        let name = req["session_name"]
            .as_str()
            .and_then(|n| crate::mcp::names::normalise(n).ok());
        if let (Some(name), Some(key)) = (name, req["session_key"].as_str()) {
            match session_sig::delegate(
                &dev.identity,
                &dev.record.airdress,
                &dev.record.device_id,
                &name,
                key,
                Utc::now(),
            ) {
                Ok(d) => v["session_delegation"] = d,
                Err(e) => tracing::debug!(error = %e, "agent chat: no session delegation"),
            }
        }
        v
    }

    /// The MLS group a conversation has on this device, if any: what a
    /// session's signature binds.
    async fn group(&self, req: &Value) -> Value {
        let Some(conversation) = req["conversation_id"].as_str() else {
            return refusal("bad_request", "conversation_id is required");
        };
        let guard = self.client.lock().await;
        let group = guard
            .as_ref()
            .and_then(|c| c.directory().group_for(conversation))
            .map(|g| URL_SAFE_NO_PAD.encode(g));
        json!({"ok": true, "group_id": group})
    }

    async fn wait(&self, req: &Value) -> Value {
        let head = || async {
            self.messages
                .lock()
                .await
                .as_ref()
                .map_or(0, ChatStore::head)
        };
        // A session that says its name holds it while it waits; a wait
        // without one (an older server) is served as before.
        let named = req["session_name"]
            .as_str()
            .and_then(|n| crate::mcp::names::normalise(n).ok())
            .zip(req["session_nonce"].as_str().map(str::to_owned));
        let pinned = req["session_pinned"] == json!(true);
        if let Some((name, nonce)) = &named {
            let claim = self
                .names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .claim(name, nonce, pinned, Instant::now());
            if let Claim::Taken {
                suggested,
                retry_after,
            } = claim
            {
                let mut v = json!({"ok": true, "name_taken": true, "suggested": suggested});
                if let Some(r) = retry_after {
                    v["retry_after_seconds"] = json!(r.as_secs());
                }
                return v;
            }
        }
        let names_here = |named: &Option<(String, String)>| {
            let mut t = self
                .names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // The wait just ended counts as seen, so a long poll does not
            // let its own name lapse.
            if let Some((name, nonce)) = named {
                t.claim(name, nonce, pinned, Instant::now());
            }
            t.here(Instant::now())
        };
        let Some(after) = req["after"].as_i64() else {
            // A session's first wait starts at the head, but what was
            // written for its name while no session of that name waited
            // is handed now, once (SPEC-166 FR-23).
            let waiting = match &named {
                Some((name, _)) => self.hand_over(name, None).await,
                None => Vec::new(),
            };
            return json!({"ok": true, "messages": waiting, "head": head().await,
                          "names_here": names_here(&named)});
        };
        let timeout =
            Duration::from_millis(req["timeout_ms"].as_u64().unwrap_or(25_000)).min(WAIT_MAX);
        if head().await <= after {
            let notified = self.arrived.notified();
            // Elapsed is how a long poll with nothing new ends: the read
            // below answers either way.
            let _woken = tokio::time::timeout(timeout, notified).await.is_ok();
        }
        let mut v = self.read(&json!({"after": after, "limit": 100})).await;
        if let Some((name, _)) = &named {
            let read: Vec<Message> =
                serde_json::from_value(v["messages"].clone()).unwrap_or_default();
            self.hand_over(name, Some(&read)).await;
        }
        v["head"] = json!(head().await);
        v["names_here"] = json!(names_here(&named));
        v
    }

    /// Record that the session `name` was handed `read`; with `None`, find
    /// and record what is still waiting for it. A store that cannot be
    /// written hands the messages anyway: losing the record repeats them
    /// at the next start, which is better than losing them.
    async fn hand_over(&self, name: &str, read: Option<&[Message]>) -> Vec<Message> {
        let mut guard = self.messages.lock().await;
        let Some(store) = guard.as_mut() else {
            return Vec::new();
        };
        let waiting = match read {
            Some(r) => r.to_vec(),
            None => store.undelivered_for(name, 100),
        };
        store
            .handed(name, &waiting)
            .log_warn("agent chat: recording what a session was handed");
        if read.is_some() {
            Vec::new()
        } else {
            waiting
        }
    }

    /// A session's signed send, checked (design §11.6), as the block's
    /// `by_session`; `None` when the conversation has no group yet.
    async fn by_session(
        &self,
        dev: &AgentDevice,
        conversation: &str,
        text: &str,
        reply_to: Option<&Value>,
        by: &Value,
    ) -> std::result::Result<Option<Value>, Value> {
        let group = {
            let guard = self.client.lock().await;
            guard
                .as_ref()
                .and_then(|c| c.directory().group_for(conversation))
        };
        let sig = by["sig"].as_str().unwrap_or_default();
        let signed = session_sig::check_send(
            &by["delegation"],
            sig,
            &dev.identity.verifying_key(),
            &dev.record.airdress,
            &dev.record.device_id,
            text,
            reply_to,
            group.as_deref(),
            Utc::now(),
        )
        .map_err(|r| refusal(r.code, &r.message))?;
        Ok(signed.then(|| {
            json!({
                "delegation": by["delegation"],
                "device_delegation": dev.record.delegation,
                "sig": sig,
            })
        }))
    }

    async fn send(&self, creds: &Credentials, req: &Value, dev: &AgentDevice) -> Result<Value> {
        let conversation = req["conversation_id"]
            .as_str()
            .context("conversation_id is required")?
            .to_owned();
        let text = req["text"].as_str().context("text is required")?.to_owned();
        let api = Api::new(creds)?;
        let known = self.refresh(&api).await?;
        let Some(conversation_row) = known.iter().find(|c| c.id == conversation).cloned() else {
            return Ok(refusal(
                "not_assigned",
                "this device may write only into its own lane and the conversations assigned to it",
            ));
        };
        if conversation_row.state.as_deref() == Some("pending_add") {
            return Ok(refusal(
                "pending_add",
                "this conversation is assigned, but no phone has added this device to it yet; \
                 open the conversation on a phone that is in it",
            ));
        }
        // A reply: the host builds `reply_to` from its own store, and a
        // session's copy (the one it signed) must be that, byte for byte
        // in meaning, or nothing is sent.
        let reply = match req["reply_to_message_id"].as_str() {
            Some(id) => match self.reply_wire(&conversation, id).await {
                Ok(r) => Some(r),
                Err(refused) => return Ok(refused),
            },
            None => None,
        };
        if let Some(theirs) = req.get("reply_to").filter(|r| !r.is_null()) {
            if reply.as_ref().map(|(w, _)| w) != Some(theirs) {
                return Ok(refusal(
                    "reply_mismatch",
                    "the reply_to sent is not the one this machine builds for that message; \
                     ask chat.reply_ref again and sign what it answers",
                ));
            }
        }
        let reply_wire = reply.as_ref().map(|(w, _)| w);
        let mut signed: Option<Value> = None;
        if let Some(by) = req.get("by_session").filter(|b| b.is_object()) {
            match self
                .by_session(dev, &conversation, &text, reply_wire, by)
                .await
            {
                Ok(b) => signed = b,
                Err(refused) => return Ok(refused),
            }
        }
        // No group yet (the own lane's first message): sent as the device,
        // its prefix plain text.
        let signed_by: Option<String> = signed
            .as_ref()
            .and_then(|b| b["delegation"]["session_name"].as_str())
            .map(str::to_owned);
        let block = text_block(&text, signed);
        let msg_ref = reply::mint_ref();
        let payload = reply::payload(&json!([block]), &msg_ref, reply_wire)?;
        let encrypted = {
            let mut guard = self.client.lock().await;
            let client = guard.as_mut().context("chat is not open")?;
            client.encrypt(&conversation, &payload, &creds.airdress)
        };
        let outbound: Vec<OutboundEnvelope> = match encrypted {
            Ok(one) => vec![one],
            Err(airdress_mls_client::SendError::NoGroup) if conversation_row.lane == "own" => {
                // The own lane is this device's to found: the operator's
                // agent is the other member.
                self.prime_root(&api, OPERATOR_LANE_TARGET).await?;
                let kp = api
                    .request(
                        Method::GET,
                        &format!("/v1/chat/key-packages/{OPERATOR_LANE_TARGET}"),
                        None,
                    )
                    .await?;
                let kp = STANDARD
                    .decode(kp["key_package"].as_str().context("no key_package")?)
                    .context("a key package that is not base64")?;
                let mut guard = self.client.lock().await;
                let client = guard.as_mut().context("chat is not open")?;
                client
                    .establish(
                        &conversation,
                        OPERATOR_LANE_TARGET,
                        &kp,
                        &payload,
                        &creds.airdress,
                    )
                    .map_err(|e| anyhow!("{e}"))?
            }
            Err(airdress_mls_client::SendError::NoGroup) => return Ok(refusal(
                "no_group",
                "this device has not been added to that conversation yet; a phone in it adds it",
            )),
            Err(e) => bail!("{e}"),
        };
        let mut last = Value::Null;
        for out in &outbound {
            last = api.post(out).await?;
        }
        let id = last["envelope_id"]
            .as_str()
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
        self.keep(Message {
            seq: 0,
            message_id: id.clone(),
            conversation_id: conversation.clone(),
            from: creds.airdress.clone(),
            lane: conversation_row.lane.into(),
            from_self: true,
            quotable: Some(text.clone()),
            text,
            at: Utc::now(),
            for_session: None,
            msg_ref: Some(msg_ref),
            reply_to: reply.map(|(_, r)| r),
            by_session: signed_by,
            kind: Some("text".into()),
        })
        .await?;
        Ok(json!({"ok": true, "message_id": id}))
    }
}

/// The one text block a send carries. A session's signed reply also
/// carries its markdown as blocks, beside the text it signed (SPEC-166
/// D-20): the app is told the text is markdown, never left to guess, and
/// the text and its signature are unchanged, so an older app shows it as
/// before. A reply with nothing but plain paragraphs carries no blocks.
fn text_block(text: &str, by_session: Option<Value>) -> Value {
    let mut block = json!({"type": "text", "text": text});
    let Some(by) = by_session else {
        return block;
    };
    if let Some(name) = by["delegation"]["session_name"].as_str() {
        if let Some(blocks) = formatted::formatted(formatted::body_of(text, name)) {
            block["formatted"] = Value::Array(blocks);
        }
    }
    block["by_session"] = by;
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers each request with `200 {}` and records its request line and
    /// body, in order.
    fn recording_operator(
        requests: usize,
    ) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..requests {
                let (mut s, _) = listener.accept().expect("a request");
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                tx.send((line.trim().to_owned(), String::from_utf8(body).unwrap()))
                    .unwrap();
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                    .unwrap();
            }
        });
        (base, rx)
    }

    #[tokio::test]
    async fn a_starting_host_retires_its_published_packages_before_offering_what_it_holds() {
        let (base, rx) = recording_operator(2);
        let api = Api {
            base,
            token: Redacted::new("t".to_owned()),
            http: crate::http::client().unwrap(),
        };
        let stored = vec![b"held-1".to_vec(), b"held-2".to_vec()];
        let fresh = vec![b"new-1".to_vec()];
        retire_and_publish(&api, stored, fresh).await.unwrap();
        let (first, _) = rx.recv().unwrap();
        assert_eq!(first, "DELETE /v1/chat/key-packages HTTP/1.1");
        let (second, body) = rx.recv().unwrap();
        assert_eq!(second, "POST /v1/chat/key-packages HTTP/1.1");
        let v: Value = serde_json::from_str(&body).unwrap();
        let sent: Vec<&str> = v["key_packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap())
            .collect();
        assert_eq!(
            sent,
            [
                STANDARD.encode(b"held-1"),
                STANDARD.encode(b"held-2"),
                STANDARD.encode(b"new-1")
            ]
        );
    }

    #[test]
    fn a_name_is_held_by_one_session_and_lapses_after_its_last_wait() {
        let t0 = Instant::now();
        let mut t = NameTable::default();
        assert_eq!(t.claim("bob", "n-1", false, t0), Claim::Held);
        assert_eq!(
            t.claim("bob", "n-1", false, t0),
            Claim::Held,
            "its own again"
        );
        assert_eq!(
            t.claim("bob", "n-2", false, t0),
            Claim::Taken {
                suggested: "bob-2".into(),
                retry_after: None,
            }
        );
        assert_eq!(t.claim("dave", "n-2", false, t0), Claim::Held);
        assert_eq!(t.here(t0), ["bob", "dave"]);
        // Renaming frees the old name.
        assert_eq!(t.claim("dave-x", "n-2", false, t0), Claim::Held);
        assert_eq!(t.here(t0), ["bob", "dave-x"]);
        // Two long waits without a word, and the name is free.
        let later = t0 + NAME_HELD;
        assert_eq!(t.here(later), Vec::<String>::new());
        assert_eq!(t.claim("bob", "n-3", false, later), Claim::Held);
    }

    #[test]
    fn a_restarted_session_gets_its_pinned_name_back_from_its_silent_old_self() {
        let t0 = Instant::now();
        let mut t = NameTable::default();
        assert_eq!(t.claim("bob", "old", true, t0), Claim::Held);
        // The restart asks while the old process may still be waiting: it is
        // told when to ask again rather than renamed.
        let soon = t0 + Duration::from_secs(10);
        assert_eq!(
            t.claim("bob", "new", true, soon),
            Claim::Taken {
                suggested: "bob-2".into(),
                retry_after: Some(NAME_TAKEOVER - Duration::from_secs(10)),
            }
        );
        // The old process never waits again, so the name passes over.
        let quiet = t0 + NAME_TAKEOVER;
        assert_eq!(t.claim("bob", "new", true, quiet), Claim::Held);
        assert_eq!(t.here(quiet), ["bob"]);
        // The old one's in-flight wait ending does not take it back.
        assert!(matches!(
            t.claim("bob", "old", true, quiet),
            Claim::Taken { .. }
        ));
        // An unpinned name is never taken over, however quiet its holder.
        assert_eq!(t.claim("ann", "a-1", false, t0), Claim::Held);
        assert_eq!(
            t.claim("ann", "a-2", false, quiet),
            Claim::Taken {
                suggested: "ann-2".into(),
                retry_after: None,
            }
        );
    }

    #[test]
    fn a_peer_airdress_is_neither_this_one_nor_a_placeholder() {
        let own = "home.example";
        assert!(is_peer_airdress("peer.example", own));
        assert!(!is_peer_airdress(own, own));
        assert!(!is_peer_airdress("self.local", own));
        assert!(!is_peer_airdress("operator.local", own));
        assert!(!is_peer_airdress("", own));
    }

    #[test]
    fn a_signed_session_reply_carries_its_markdown_as_blocks_beside_the_text() {
        let by = json!({"delegation": {"session_name": "bob"}, "sig": "s"});
        let md = "bob: ## Done\n\n- **tests** pass";
        let b = text_block(md, Some(by.clone()));
        assert_eq!(b["text"], md, "the signed text is unchanged");
        assert_eq!(b["by_session"], by);
        assert_eq!(
            b["formatted"],
            json!([
                {"type": "rich_text", "kind": "heading", "level": 2, "spans": [{"text": "Done"}]},
                {"type": "rich_text", "kind": "list_item", "spans": [
                    {"text": "tests", "bold": true}, {"text": " pass"}]},
            ])
        );
        // Plain words stay one text block, signed or not.
        let plain = text_block("bob: done, @alice", Some(by));
        assert!(plain.get("formatted").is_none());
        // Unsigned (no group yet): sent as the device, as before.
        assert_eq!(
            text_block("# not a session's", None),
            json!({"type": "text", "text": "# not a session's"})
        );
    }

    #[test]
    fn text_of_blocks_reads_text_and_code_and_names_the_rest() {
        let blocks = json!([
            {"type": "text", "text": "hello"},
            {"type": "code", "code": "ls", "language": "sh"},
            {"type": "system", "text": "Radio session started"},
            {"type": "image", "url": "https://x"},
        ]);
        assert_eq!(
            text_of(&blocks),
            "hello\n```\nls\n```\n[system] Radio session started\n[image]"
        );
        assert_eq!(text_of(&json!("not blocks")), "");
    }
}
