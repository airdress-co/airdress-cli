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
//! after?, limit}`, `chat.send {conversation_id, text}`, `chat.wait
//! {after?, timeout_ms}` (a long poll; `after: null` answers the head).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

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

use super::chat_store::{ChatStore, Message};
use super::store::{AgentDevice, AgentStore};
use crate::log_err::LogErr as _;
use crate::redact::Redacted;

/// Where the operator's own agent lives, as the lane names it.
pub const OPERATOR_LANE_TARGET: &str = "operator.local";
/// Key packages kept published, so a phone can add this device.
const KEY_PACKAGES: usize = 8;
/// Stream reconnect bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// The longest a `chat.wait` is held.
const WAIT_MAX: Duration = Duration::from_secs(30);

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
            Some(other) => Some(format!("[{other}]")),
            None => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        engine.set_revocation_lookup(super::revocation::OperatorRevocation::of_operator(
            &creds.operator,
            creds.token.clone(),
        ));
        self.roots
            .write()
            .map_err(|_| anyhow!("roots poisoned"))?
            .insert(creds.airdress.clone(), creds.root_public);
        let roots = Arc::clone(&self.roots);
        engine.set_root_key_lookup(Arc::new(move |airdress: &str| {
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
            });
        }
        *self.conversations.lock().await = out.clone();
        Ok(out)
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

    /// Publish key packages so a phone can add this device to a
    /// conversation it was assigned.
    async fn publish_key_packages(&self, api: &Api) -> Result<()> {
        let packages = {
            let mut guard = self.client.lock().await;
            let client = guard.as_mut().context("chat is not open")?;
            client.key_packages(KEY_PACKAGES).map_err(|e| anyhow!(e))?
        };
        let list: Vec<String> = packages.iter().map(|k| STANDARD.encode(k)).collect();
        api.request(
            Method::POST,
            "/v1/chat/key-packages",
            Some(&json!({"key_packages": list})),
        )
        .await?;
        Ok(())
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
            self.publish_key_packages(&api).await?;
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
            "chat.wait" => Ok(self.wait(req).await),
            "chat.send" => self.send(&creds, req).await,
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
        json!({"ok": true, "messages": msgs, "next_cursor": next, "head": store.head()})
    }

    async fn wait(&self, req: &Value) -> Value {
        let head = || async {
            self.messages
                .lock()
                .await
                .as_ref()
                .map_or(0, ChatStore::head)
        };
        let Some(after) = req["after"].as_i64() else {
            return json!({"ok": true, "messages": [], "head": head().await});
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
        v["head"] = json!(head().await);
        v
    }

    async fn send(&self, creds: &Credentials, req: &Value) -> Result<Value> {
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
        let payload = serde_json::to_vec(&json!([{"type": "text", "text": text}]))?;
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
            text,
            at: Utc::now(),
        })
        .await?;
        Ok(json!({"ok": true, "message_id": id}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_of_blocks_reads_text_and_code_and_names_the_rest() {
        let blocks = json!([
            {"type": "text", "text": "hello"},
            {"type": "code", "code": "ls", "language": "sh"},
            {"type": "image", "url": "https://x"},
        ]);
        assert_eq!(text_of(&blocks), "hello\n```\nls\n```\n[image]");
        assert_eq!(text_of(&json!("not blocks")), "");
    }
}
