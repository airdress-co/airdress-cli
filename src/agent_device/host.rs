//! The device host: one per machine and airdress, shared by every session
//! on it (design §6.2, D-13, FR-26).
//!
//! Two processes advancing one MLS state fork the group, so exactly one
//! process holds the device. It holds `host.lock` (`flock`, exclusive) and
//! serves `host.sock` (mode 0600, in a 0700 directory). Everyone else is a
//! client of that socket, or a follower waiting for the lock: a follower
//! retries every two seconds, and when the holder dies (the kernel drops
//! its lock with it) the next one takes the lock, reloads the device from
//! its store and sealed state, and serves. Nothing is lost in between that
//! the store did not already hold, because every change is saved before it
//! is answered.
//!
//! No key crosses the socket. A client asks the host to **sign**; it never
//! reads the identity key, the bearer or the state key.
//!
//! The protocol is one JSON object per line each way:
//!
//! | `op` | Answer |
//! |------|--------|
//! | `device.status` | the device's standing, its approval's expiry, a pending request |
//! | `device.request` | ask to join (or renew); "Approve '<label>' on your phone" |
//! | `device.leave` | sign the device out and delete its keys and state |
//! | `sign` | `{payload}` (base64) signed by the device key, while approved |
//! | `chat.*` | not available yet: the agent's own lane comes with chat |
//!
//! The holder also keeps the approval alive: it advances a pending request
//! until a phone answers, and from seven days before expiry files the
//! renewal itself (FR-24), once an hour at most.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::Signer as _;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use super::join::{self, Hub, Progress, Standing};
use super::store::{AgentDevice, AgentStore};
use crate::redact::Redacted;

/// How often a follower tries the lock.
pub const FOLLOW_EVERY: Duration = Duration::from_secs(2);

/// Where the hub's enrollment assertions come from.
#[derive(Debug, Clone)]
pub enum HubAuth {
    /// A fixed hub and bearer (tests; a caller that already resolved them).
    Static {
        /// The hub's base URL.
        base: String,
        /// The account bearer.
        bearer: Redacted<String>,
    },
    /// A CLI credential profile, refreshed at each use.
    Profile {
        /// Where the CLI's files are.
        paths: crate::paths::Paths,
        /// The profile's name.
        name: String,
    },
}

impl HubAuth {
    async fn resolve(&self) -> Result<(String, Redacted<String>)> {
        match self {
            Self::Static { base, bearer } => Ok((base.clone(), bearer.clone())),
            Self::Profile { paths, name } => {
                let hub = crate::airdresses::client::HubClient::from_profile(paths, name).await?;
                Ok((hub.endpoint().to_owned(), hub.bearer().to_owned()))
            }
        }
    }
}

/// What a new device is asked as, when the host has to make one.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The operator's base URL.
    pub operator: String,
    /// What the phone is shown.
    pub label: String,
    /// Which program runs the agent (data).
    pub harness: String,
}

/// The socket path (see [`crate::agent_bus::socket::socket_path`], which
/// the MCP server uses too, so the two cannot drift).
pub fn socket_path(store: &AgentStore) -> PathBuf {
    crate::agent_bus::socket::socket_path(store.dir(), store.runtime_dir())
}

/// The exclusive lock on `host.lock`, held while this value lives.
#[derive(Debug)]
pub struct HostLock {
    _file: std::fs::File,
}

impl HostLock {
    /// Take the lock without waiting; `None` when another process holds it.
    pub fn try_take(path: &Path) -> Result<Option<Self>> {
        let dir = path.parent().context("a lock path with no parent")?;
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            crate::fsx::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        // SAFETY: flock on a descriptor this function owns.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        Err(err).with_context(|| format!("lock {}", path.display()))
    }
}

/// The host's shared state.
#[derive(Debug)]
struct State {
    store: AgentStore,
    hub: HubAuth,
    identity: Identity,
    device: Arc<Mutex<Option<AgentDevice>>>,
    /// Agent chat: the MLS member, the pump and the message store.
    chat: Arc<super::chat::Chat>,
    /// When the holder last filed a renewal by itself.
    last_renewal: Mutex<Option<tokio::time::Instant>>,
}

fn standing_word(s: Standing) -> &'static str {
    match s {
        Standing::NotApproved => "not_approved",
        Standing::Approved => "approved",
        Standing::RenewalDue => "renewal_due",
        Standing::Expired => "expired",
    }
}

/// The status a person (or a tool) is shown. Nothing secret.
pub fn status_of(dev: Option<&AgentDevice>, airdress: &str) -> Value {
    let Some(dev) = dev else {
        return json!({
            "airdress": airdress,
            "enrolled": false,
            "standing": "not_approved",
            "message": "this machine is not an agent device of this airdress yet",
        });
    };
    let r = &dev.record;
    let standing = join::standing(r.expires_at, Utc::now());
    let message = match (standing, r.pending_request.is_some()) {
        (_, true) => format!("Approve '{}' on your phone.", r.label),
        (Standing::NotApproved, false) => "not approved yet".to_owned(),
        (Standing::Approved, false) => "approved".to_owned(),
        (Standing::RenewalDue, false) => format!(
            "'{}' needs renewing; a renewal will be asked on your phone",
            r.label
        ),
        (Standing::Expired, false) => format!(
            "'{}' expired: chat and device-signed writes are stopped until you approve its \
             renewal on your phone",
            r.label
        ),
    };
    json!({
        "airdress": r.airdress,
        "enrolled": !r.enrollment_id.is_empty(),
        "enrollment_id": (!r.enrollment_id.is_empty()).then_some(&r.enrollment_id),
        "device_id": r.device_id,
        "label": r.label,
        "harness": r.harness,
        "expires_at": r.expires_at,
        "standing": standing_word(standing),
        "pending": r.pending_request.is_some(),
        "keys": match r.secrets_at {
            crate::shell_client::store::SecretsAt::Keyring => "keychain",
            crate::shell_client::store::SecretsAt::File => "file",
        },
        "message": message,
    })
}

/// A copy of the device for work that must not hold the device lock.
fn clone_device(d: &AgentDevice) -> AgentDevice {
    AgentDevice {
        record: d.record.clone(),
        identity: d.identity.clone(),
        token: d.token.clone(),
        state_key: d.state_key.clone(),
    }
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": code, "message": message})
}

impl State {
    async fn hub(&self) -> Result<(String, Redacted<String>)> {
        self.hub.resolve().await
    }

    async fn request(&self) -> Result<Value> {
        let mut guard = self.device.lock().await;
        let dev = match guard.as_mut() {
            Some(d) => d,
            None => {
                let mut d = join::new_device(
                    self.store.airdress(),
                    &self.identity.operator,
                    self.identity.label.clone(),
                    &self.identity.harness,
                );
                let at = self.store.save(&mut d)?;
                if at == crate::shell_client::store::SecretsAt::File {
                    tracing::warn!(
                        dir = %self.store.dir().display(),
                        "no OS keychain: this agent device's keys are in a 0600 file"
                    );
                }
                guard.insert(d)
            }
        };
        let standing = join::standing(dev.record.expires_at, Utc::now());
        if dev.record.pending_request.is_none()
            && (dev.record.enrollment_id.is_empty()
                || matches!(standing, Standing::RenewalDue | Standing::Expired))
        {
            let (base, bearer) = self.hub().await?;
            join::request(
                &self.store,
                dev,
                &Hub {
                    base: &base,
                    bearer: &bearer,
                },
            )
            .await?;
        }
        let mut v = status_of(Some(dev), self.store.airdress());
        v["ok"] = json!(true);
        Ok(v)
    }

    async fn leave(&self) -> Result<Value> {
        let mut guard = self.device.lock().await;
        if let Some(dev) = guard.as_ref() {
            if !dev.record.enrollment_id.is_empty() {
                join::AgentApi::new(&dev.record.operator)?
                    .leave(&dev.record, &dev.token)
                    .await?;
            }
        }
        let existed = self.store.forget()?;
        *guard = None;
        Ok(json!({"ok": true, "left": existed}))
    }

    async fn sign(&self, req: &Value) -> Value {
        let Some(payload) = req["payload"]
            .as_str()
            .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
        else {
            return refusal("bad_request", "sign takes a base64 payload");
        };
        let guard = self.device.lock().await;
        let Some(dev) = guard
            .as_ref()
            .filter(|d| !d.record.enrollment_id.is_empty())
        else {
            return refusal(
                "not_approved",
                "this machine is not an approved agent device; ask with device.request",
            );
        };
        match join::standing(dev.record.expires_at, Utc::now()) {
            Standing::Approved | Standing::RenewalDue => {}
            Standing::Expired => {
                return refusal(
                    "expired",
                    &format!(
                        "'{}' expired; approve its renewal on your phone",
                        dev.record.label
                    ),
                )
            }
            Standing::NotApproved => return refusal("not_approved", "not approved yet"),
        }
        let sig = dev.identity.sign(&payload);
        json!({
            "ok": true,
            "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            "public_key": dev.record.identity_public,
            "enrollment_id": dev.record.enrollment_id,
        })
    }

    async fn handle(&self, req: &Value) -> Value {
        let op = req["op"].as_str().unwrap_or_default();
        let answer = match op {
            "device.status" => {
                let guard = self.device.lock().await;
                let mut v = status_of(guard.as_ref(), self.store.airdress());
                v["ok"] = json!(true);
                Ok(v)
            }
            "device.request" => self.request().await,
            "device.leave" => self.leave().await,
            "sign" => Ok(self.sign(req).await),
            o if o.starts_with("chat.") => {
                // The device is read under its lock and released before the
                // chat work, which may wait (chat.wait) or reach the network.
                let snapshot = {
                    let guard = self.device.lock().await;
                    guard.as_ref().map(clone_device)
                };
                Ok(self.chat.op(o, req, snapshot.as_ref()).await)
            }
            _ => Ok(refusal("unknown_op", "no such operation")),
        };
        answer.unwrap_or_else(|e| refusal("failed", &format!("{e:#}")))
    }

    /// One pass of keeping the approval alive.
    async fn tick(&self) {
        let mut guard = self.device.lock().await;
        let Some(dev) = guard.as_mut() else { return };
        let result: Result<()> = async {
            if dev.record.pending_request.is_some() {
                let (base, bearer) = self.hub().await?;
                let hub = Hub {
                    base: &base,
                    bearer: &bearer,
                };
                match join::advance(&self.store, dev, &hub).await? {
                    Progress::Done => tracing::info!("agent device approved"),
                    Progress::Ended(why) => tracing::warn!(%why, "agent device request ended"),
                    Progress::Idle | Progress::Waiting => {}
                }
                return Ok(());
            }
            let due = !dev.record.enrollment_id.is_empty()
                && matches!(
                    join::standing(dev.record.expires_at, Utc::now()),
                    Standing::RenewalDue | Standing::Expired
                );
            let mut last = self.last_renewal.lock().await;
            let recent = last.is_some_and(|t| t.elapsed() < Duration::from_secs(3600));
            if due && !recent {
                *last = Some(tokio::time::Instant::now());
                let (base, bearer) = self.hub().await?;
                join::request(
                    &self.store,
                    dev,
                    &Hub {
                        base: &base,
                        bearer: &bearer,
                    },
                )
                .await?;
                tracing::info!(label = %dev.record.label, "asked the phone to renew this agent device");
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %format!("{e:#}"), "agent device upkeep failed; will retry");
        }
    }
}

/// Serve as the holder until `cancel`: bind the socket, answer clients, and
/// keep the approval alive every `upkeep`.
pub async fn serve(
    lock: HostLock,
    store: AgentStore,
    hub: HubAuth,
    identity: Identity,
    upkeep: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let device = store.load()?;
    let state = Arc::new(State {
        store: store.clone(),
        hub,
        identity,
        device: Arc::new(Mutex::new(device)),
        chat: Arc::new(super::chat::Chat::new(store.clone())),
        last_renewal: Mutex::new(None),
    });
    // Every task of this holder is owned here (R-ASY-1): the envelope pump
    // and one per connected client. Cancelling ends them; they are joined
    // within [`DRAIN`] before the lock goes, and a panic in one is this
    // function's error, so a holder never keeps the lock as a ghost.
    let mut tasks = tokio::task::JoinSet::new();
    // The envelope pump: idle until the device is approved, then holds the
    // device's stream for as long as this process holds the lock.
    tasks.spawn(Arc::clone(&state.chat).pump(Arc::clone(&state.device), cancel.child_token()));
    let path = socket_path(&store);
    // The lock is ours, so a socket file here is a dead holder's. One that
    // cannot be removed makes the bind below fail, naming it.
    remove_socket(&path);
    if let Some(dir) = path.parent() {
        crate::fsx::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        crate::fsx::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut ticker = tokio::time::interval(upkeep);
    let mut failed = None;
    loop {
        tokio::select! {
            // cancel-safe: `CancellationToken::cancelled`.
            () = cancel.cancelled() => break,
            // cancel-safe: `Interval::tick` (tokio's list); the upkeep runs
            // in the arm's body, not in the race.
            _ = ticker.tick() => state.tick().await,
            // cancel-safe: `UnixListener::accept` (tokio's list). Not polled
            // while MAX_CLIENTS are connected (R-ASY-5).
            accepted = listener.accept(), if tasks.len() <= MAX_CLIENTS => {
                let Ok((sock, _)) = accepted else { continue };
                let st = Arc::clone(&state);
                let stop = cancel.child_token();
                let serve_client = async move {
                    let (r, mut w) = sock.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                        let mut out = serde_json::to_vec(&st.handle(&req).await).unwrap_or_default();
                        out.push(b'\n');
                        if w.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                };
                tasks.spawn(async move {
                    stop.run_until_cancelled_owned(serve_client).await;
                });
            }
            // cancel-safe: `JoinSet::join_next` (documented cancel-safe).
            // Reaps a finished task; a panicked one stops the holder.
            Some(done) = tasks.join_next() => {
                if let Err(e) = done {
                    if e.is_panic() {
                        failed = Some(e.to_string());
                        break;
                    }
                }
            }
        }
    }
    cancel.cancel();
    drop(listener);
    remove_socket(&path);
    if tokio::time::timeout(DRAIN, async {
        while let Some(r) = tasks.join_next().await {
            if let Err(e) = r {
                if e.is_panic() {
                    failed.get_or_insert_with(|| e.to_string());
                }
            }
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    drop(lock);
    match failed {
        Some(p) => Err(anyhow::anyhow!("the agent device host failed: {p}")),
        None => Ok(()),
    }
}

/// How many clients a holder serves at once (R-ASY-5); past it the socket
/// is not accepted from until one leaves.
pub const MAX_CLIENTS: usize = 64;
/// How long a stopping holder waits for its tasks before it lets go of the
/// lock.
pub const DRAIN: Duration = Duration::from_secs(3);

/// Hold the device, or wait to: take the lock and serve; while another
/// process holds it, retry every [`FOLLOW_EVERY`] and take over when it dies.
pub async fn run(
    store: AgentStore,
    hub: HubAuth,
    identity: Identity,
    upkeep: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        if let Some(lock) = HostLock::try_take(&store.lock_path())? {
            return serve(lock, store, hub, identity, upkeep, cancel).await;
        }
        tokio::select! {
            // cancel-safe: `CancellationToken::cancelled`.
            () = cancel.cancelled() => return Ok(()),
            // cancel-safe: a sleep.
            () = tokio::time::sleep(FOLLOW_EVERY) => {}
        }
    }
}

/// Ask the holder one question. Errors when no host is serving.
pub async fn call(store: &AgentStore, req: &Value) -> Result<Value> {
    crate::agent_bus::socket::call(&socket_path(store), req).await
}

/// The holder's cancellation (R-ASY-3): one token, children per task.
pub use tokio_util::sync::CancellationToken;

/// Remove this host's socket file. Absent is the usual case; anything else
/// is logged, and a socket left behind is replaced by the next host.
fn remove_socket(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not remove the host socket")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            operator: "http://127.0.0.1:9".into(),
            label: "Agent on box".into(),
            harness: "test-harness".into(),
        }
    }

    fn hub() -> HubAuth {
        HubAuth::Static {
            base: "http://127.0.0.1:9".into(),
            bearer: "b".into(),
        }
    }

    #[test]
    fn the_lock_is_exclusive_and_released_with_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.lock");
        let a = HostLock::try_take(&path).unwrap().expect("first");
        assert!(HostLock::try_take(&path).unwrap().is_none(), "held");
        drop(a);
        assert!(HostLock::try_take(&path).unwrap().is_some(), "released");
    }

    #[tokio::test]
    async fn a_follower_takes_over_when_the_holder_dies() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::file_only(dir.path(), "a.example").unwrap();
        // A device on disk: the follower must reload it, not start over.
        let mut dev = join::new_device(
            "a.example",
            "http://127.0.0.1:9",
            "Agent on box".into(),
            "test-harness",
        );
        store.save(&mut dev).unwrap();

        let first = CancellationToken::new();
        let holder = tokio::spawn(run(
            store.clone(),
            hub(),
            identity(),
            Duration::from_secs(3600),
            first.clone(),
        ));
        let second = CancellationToken::new();
        let follower = tokio::spawn(run(
            store.clone(),
            hub(),
            identity(),
            Duration::from_secs(3600),
            second.clone(),
        ));

        let status = |store: AgentStore| async move {
            for _ in 0..100 {
                if let Ok(v) = call(&store, &json!({"op": "device.status"})).await {
                    return v;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("no host answered");
        };
        let v = status(store.clone()).await;
        assert_eq!(v["device_id"], dev.record.device_id.as_str());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let m = std::fs::metadata(socket_path(&store))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }

        // The holder dies; within a follow interval the follower serves the
        // same device from the store.
        first.cancel();
        holder.await.unwrap().unwrap();
        let started = std::time::Instant::now();
        let v = status(store.clone()).await;
        assert!(started.elapsed() < FOLLOW_EVERY + Duration::from_secs(3));
        assert_eq!(v["device_id"], dev.record.device_id.as_str());
        second.cancel();
        follower.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn no_key_crosses_and_nothing_is_signed_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::file_only(dir.path(), "a.example").unwrap();
        let mut dev = join::new_device(
            "a.example",
            "http://127.0.0.1:9",
            "Agent on box".into(),
            "test-harness",
        );
        store.save(&mut dev).unwrap();
        let cancel = CancellationToken::new();
        let host = tokio::spawn(run(
            store.clone(),
            hub(),
            identity(),
            Duration::from_secs(3600),
            cancel.clone(),
        ));
        let payload = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let mut refused = None;
        for _ in 0..100 {
            match call(&store, &json!({"op": "sign", "payload": payload})).await {
                Err(e) if e.to_string().contains("no device host") => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                other => {
                    refused = Some(other);
                    break;
                }
            }
        }
        let err = refused.expect("answered").expect_err("unapproved");
        assert!(
            err.to_string().contains("not an approved agent device"),
            "{err}"
        );

        // Approved (a record that says so): it signs, and the answer holds a
        // public key and a signature and nothing else of the device's.
        let mut approved = store.load().unwrap().unwrap();
        approved.record.enrollment_id = "e1".into();
        approved.record.expires_at = Some(Utc::now() + chrono::Duration::days(20));
        store.save(&mut approved).unwrap();
        cancel.cancel();
        host.await.unwrap().unwrap();
        let cancel = CancellationToken::new();
        let host = tokio::spawn(run(
            store.clone(),
            hub(),
            identity(),
            Duration::from_secs(3600),
            cancel.clone(),
        ));
        let mut v = None;
        for _ in 0..100 {
            if let Ok(a) = call(&store, &json!({"op": "sign", "payload": payload})).await {
                v = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let v = v.expect("signed");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["enrollment_id", "ok", "public_key", "signature"]);
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(v["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        approved
            .identity
            .verifying_key()
            .verify_strict(b"hello", &ed25519_dalek::Signature::from_bytes(&sig))
            .unwrap();

        // Expired: refused, and says so.
        let mut lapsed = store.load().unwrap().unwrap();
        lapsed.record.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        store.save(&mut lapsed).unwrap();
        cancel.cancel();
        host.await.unwrap().unwrap();
        let cancel = CancellationToken::new();
        let host = tokio::spawn(run(
            store.clone(),
            hub(),
            identity(),
            Duration::from_secs(3600),
            cancel.clone(),
        ));
        let mut err = None;
        for _ in 0..100 {
            match call(&store, &json!({"op": "sign", "payload": payload})).await {
                Err(e) if e.to_string().contains("no device host") => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                other => {
                    err = Some(other.expect_err("expired"));
                    break;
                }
            }
        }
        assert!(err.unwrap().to_string().contains("expired"));
        let chat = call(&store, &json!({"op": "chat.send"}))
            .await
            .expect_err("chat");
        assert!(chat.to_string().contains("expired"), "{chat}");
        cancel.cancel();
        host.await.unwrap().unwrap();
    }

    #[test]
    fn a_long_state_dir_gets_a_short_socket() {
        let long = std::path::PathBuf::from(format!("/{}", "x".repeat(120)));
        let store = AgentStore::file_only(&long, "a.example").unwrap();
        let p = socket_path(&store);
        assert!(p.as_os_str().len() < 100, "{}", p.display());
        assert_eq!(p, socket_path(&store), "stable");
        // The runtime directory comes from `Paths`, never the environment.
        let run = std::path::PathBuf::from("/run/user/4242");
        let paths = crate::paths::Paths::under(std::path::Path::new("/home/ada"))
            .with_runtime_dir(Some(run.clone()));
        let store = store.with_runtime_dir(paths.runtime_dir());
        assert!(socket_path(&store).starts_with(&run));
    }
}
