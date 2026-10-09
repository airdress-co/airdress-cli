//! The host's state and what it does with every event (design §7.3, §6.7,
//! §8.3).
//!
//! One task owns a [`HostCore`]; it is fed operator frames from the channel,
//! PTY events from the sessions, a tick, and the stop signal. Everything it
//! sends goes out through one queue to the channel.
//!
//! The order of an open is the design's: the operator's signature (checked
//! before a frame gets here), the attestation, `max_sessions`, the Noise
//! handshake, and the device's first record. Only then is the profile
//! spawned. A failed open costs the host one Noise operation and spawns
//! nothing.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime};

use airdress_shell_proto::handshake::HostHello;
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::prologue::Action;
use airdress_shell_proto::ticket::TicketId;
use anyhow::Context as _;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::binding::Binding;
use crate::endpoint::{Admitted, Endpoint, Handshake};
use crate::frames::OpFrame;
use crate::journal::Journal;
use crate::log_err::LogErr as _;
use crate::paths::Paths;
use crate::profiles::{ProfileFile, State};
use crate::pty::PtyEvent;
use crate::recording::Recorder;
use crate::session::{Client, Send, Session};
use crate::trust::{check_attestation, BindingFacts, DeviceStore, Verified};

/// The timers of design §7.3 and D-18, shortened in tests.
#[derive(Debug, Clone)]
pub struct Timings {
    /// How often lifetimes, rekeys and the profile file are looked at.
    pub tick: Duration,
    /// `SIGKILL` this long after `SIGHUP`.
    pub kill_after: Duration,
    /// An exited session stays readable this long (FR-S12).
    pub exit_readable: Duration,
    /// Clients are warned this long before `max_lifetime`.
    pub lifetime_warning: Duration,
    /// An open whose device never sent its first record is dropped.
    pub open_timeout: Duration,
    /// How long the host stops reading its link for a program that does
    /// not take its input, before it tells the typist and drops what waits
    /// (R-ASY-5, R-ASY-6). While it waits, no session's input is read.
    pub input_stall: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(1),
            kill_after: Duration::from_secs(10),
            exit_readable: Duration::from_secs(600),
            lifetime_warning: Duration::from_secs(600),
            open_timeout: Duration::from_secs(60),
            input_stall: Duration::from_secs(10),
        }
    }
}

/// What the host sends its operator.
#[derive(Debug, Clone, PartialEq)]
pub enum Outgoing {
    /// A host → operator frame (JSON with its `type`).
    Frame(Value),
    /// One end-to-end record for a leg.
    Data {
        session: Uuid,
        leg: Uuid,
        record: Vec<u8>,
    },
    /// End the channel with this code.
    Close(u16, String),
}

/// How many messages wait for the channel (R-ASY-5). A data message is
/// one sealed record under the operator's frame ceiling (64 KiB), so at
/// most about 8 MiB.
pub const OUT_QUEUE: usize = 128;

/// The host's queue to its channel (R-ASY-5).
///
/// [`HostCore`] is a synchronous state machine, so it cannot wait for
/// room. What does not fit waits here in order, and while anything does
/// the runner stops reading the sessions' output and the probes: a slow
/// operator link slows the programs, rather than the host's memory
/// growing. The runner keeps reading the link itself, because the channel
/// waits on that queue too and the two waiting on each other would stop
/// both; what link events add here is bounded by each client's credit
/// (FR-S9), never by a program's output.
#[derive(Debug)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    backlog: std::sync::Mutex<std::collections::VecDeque<Outgoing>>,
}

impl Outbox {
    /// A queue into `tx`.
    pub fn new(tx: mpsc::Sender<Outgoing>) -> Self {
        Self {
            tx,
            backlog: std::sync::Mutex::default(),
        }
    }

    fn backlog(&self) -> std::sync::MutexGuard<'_, std::collections::VecDeque<Outgoing>> {
        // A poisoned lock would mean a panic here, which ends the process
        // (the host's panic hook); the queue itself is still whole.
        self.backlog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queue `o` behind everything before it. A closed channel takes
    /// nothing: the host is stopping.
    pub fn send(&self, o: Outgoing) {
        let mut b = self.backlog();
        if !b.is_empty() {
            b.push_back(o);
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(o)) = self.tx.try_send(o) {
            b.push_back(o);
        }
    }

    /// Whether messages wait for room; the runner then waits on
    /// [`Outbox::sender`] with `reserve`.
    pub fn backlogged(&self) -> bool {
        !self.backlog().is_empty()
    }

    /// The channel's queue, to wait for room on.
    pub fn sender(&self) -> mpsc::Sender<Outgoing> {
        self.tx.clone()
    }

    /// Room: the oldest waiting message takes `permit`, then as many as
    /// fit without waiting.
    pub fn on_room(&self, permit: mpsc::Permit<'_, Outgoing>) {
        let mut b = self.backlog();
        if let Some(o) = b.pop_front() {
            permit.send(o);
        }
        self.pump_locked(&mut b);
    }

    /// Move what fits now; true when nothing waits any more.
    pub fn pump(&self) -> bool {
        let mut b = self.backlog();
        self.pump_locked(&mut b);
        b.is_empty()
    }

    fn pump_locked(&self, b: &mut std::collections::VecDeque<Outgoing>) {
        while let Some(o) = b.pop_front() {
            match self.tx.try_send(o) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(o)) => {
                    b.push_front(o);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    b.clear();
                    return;
                }
            }
        }
    }

    /// Wait until everything queued has gone to the channel, or `bound`
    /// passed. For a stopping host, so its last words are not lost.
    pub async fn flush(&self, bound: Duration) {
        let tx = self.sender();
        let flushed = tokio::time::timeout(bound, async {
            while self.backlogged() {
                // The lock is not held across this wait (R-ASY-4).
                match tx.reserve().await {
                    Ok(permit) => self.on_room(permit),
                    Err(_) => {
                        self.backlog().clear();
                    }
                }
            }
        })
        .await;
        if flushed.is_err() {
            tracing::debug!("the last frames did not all leave within {bound:?}");
        }
    }
}

/// What the host says about itself in `host_info`.
#[derive(Debug, Clone)]
pub struct HostFacts {
    pub host_version: String,
    pub autostart: &'static str,
    pub runs_as_root: bool,
}

#[derive(Debug)]
struct PendingOpen {
    profile: String,
    size: (u16, u16),
    leg: Uuid,
    device: Uuid,
    label: String,
    at: Instant,
}

/// What a device revocation did, step by step (design §6.7).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RevokeReport {
    /// Step 1: the legs cut, by session.
    pub cut: Vec<(Uuid, Uuid)>,
    /// Whether the device's tickets are gone and it is in the revoked set.
    pub forgotten: bool,
    /// Step 2: the remaining legs rekeyed.
    pub rekeyed: Vec<Uuid>,
    /// Step 3: the sessions whose spill key was rotated.
    pub spill_rotated: Vec<Uuid>,
    /// Step 4: the sessions whose recording rolled to a new segment.
    pub recordings_rolled: Vec<Uuid>,
    /// Step 5: the sessions whose remaining clients were told.
    pub told: Vec<Uuid>,
}

/// The host.
pub struct HostCore {
    pub paths: Paths,
    pub binding: Binding,
    facts: BindingFacts,
    pub profiles: ProfileFile,
    profiles_stamp: Option<(SystemTime, u64)>,
    pub store: DeviceStore,
    pub endpoint: Endpoint,
    pub sessions: BTreeMap<Uuid, Session>,
    pending: HashMap<Uuid, PendingOpen>,
    enabled: bool,
    max_viewers: Option<u32>,
    frame_max: usize,
    /// The queue to the channel; the runner drains its backlog.
    pub out: Outbox,
    pty_tx: mpsc::Sender<(Uuid, PtyEvent)>,
    epoch: Instant,
    pub timings: Timings,
    pub host: HostFacts,
    stopping: Option<Instant>,
    last_prune: Option<Instant>,
    /// Harness reports by profile id, from the probes.
    pub harness: BTreeMap<String, Value>,
    /// The event socket, when the runner made one (design §9.4).
    pub events_socket: Option<std::path::PathBuf>,
    /// Where probe results go (the runner reads them back in).
    pub probe_tx: Option<mpsc::Sender<(String, String, Value)>>,
    /// The probes running now, owned here (R-ASY-1) and reaped by the tick.
    probes: tokio::task::JoinSet<()>,
    probed: HashMap<String, (Instant, String)>,
    probing: std::collections::HashSet<String>,
    store_stamp: Option<SystemTime>,
    /// The machine identity's signature over the shell key (`host_info.sig`),
    /// made once at start: a host that cannot sign it does not start, since
    /// the operator closes a channel whose `host_info` is unsigned (4009).
    shell_key_sig: String,
}

impl std::fmt::Debug for HostCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostCore")
            .field("sessions", &self.sessions.len())
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Room for one inner message inside one record under the operator's
/// frame ceiling: the record's nonce and tag, the message header, an
/// `out` offset, and headroom.
fn budget_for(frame_max: usize) -> usize {
    frame_max.saturating_sub(128).max(1024)
}

impl HostCore {
    /// A host for `binding`, its profiles loaded, its devices read.
    pub fn new(
        paths: Paths,
        binding: Binding,
        profiles: ProfileFile,
        out: mpsc::Sender<Outgoing>,
        pty_tx: mpsc::Sender<(Uuid, PtyEvent)>,
        host: HostFacts,
        timings: Timings,
    ) -> anyhow::Result<Self> {
        let store = DeviceStore::load(&paths)?;
        let facts = binding.facts();
        let endpoint = Endpoint::new(
            binding.shell_keypair(&paths)?,
            &binding.airdress,
            binding.machine_id,
        );
        let shell_key_sig = binding.sign_shell_key(&paths, &endpoint.public()).context(
            "the machine key could not sign this host's shell key, and the operator \
                 refuses a host_info without that signature",
        )?;
        let profiles_stamp = stamp(&paths);
        Ok(Self {
            paths,
            binding,
            facts,
            profiles,
            profiles_stamp,
            store,
            endpoint,
            sessions: BTreeMap::new(),
            pending: HashMap::new(),
            enabled: true,
            max_viewers: None,
            frame_max: 65_536,
            out: Outbox::new(out),
            pty_tx,
            epoch: Instant::now(),
            timings,
            host,
            stopping: None,
            last_prune: None,
            harness: BTreeMap::new(),
            events_socket: None,
            probe_tx: None,
            probes: tokio::task::JoinSet::new(),
            probed: HashMap::new(),
            probing: std::collections::HashSet::new(),
            shell_key_sig,
            store_stamp: None,
        })
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn budget(&self) -> usize {
        budget_for(self.frame_max)
    }

    fn frame(&self, kind: &str, mut body: Value) {
        body["type"] = Value::from(kind);
        self.out.send(Outgoing::Frame(body));
    }

    fn data(&self, session: Uuid, leg: Uuid, record: Vec<u8>) {
        self.out.send(Outgoing::Data {
            session,
            leg,
            record,
        });
    }

    fn deliver(&mut self, session: Uuid, sends: Vec<Send>) {
        let now = self.now_ms();
        for s in sends {
            if let Some(rec) = self.endpoint.seal(s.leg, std::slice::from_ref(&s.msg), now) {
                self.data(session, s.leg, rec);
            }
        }
    }

    fn refuse(&mut self, session: Uuid, leg: Uuid, code: &str) {
        tracing::info!(session = %session, code, "refused a device");
        self.send_refused(session, leg, code);
    }

    /// Refuse, and say why on this host. The device only ever learns the
    /// code (a peer learns that a handshake failed, not which check did);
    /// the person reading this host's log needs the check, or every
    /// `shell_handshake_failed` looks the same.
    fn refuse_because(
        &mut self,
        session: Uuid,
        leg: Uuid,
        code: &str,
        reason: &dyn std::fmt::Display,
        context: &str,
    ) {
        tracing::warn!(session = %session, code, %reason, context, "refused a device");
        self.send_refused(session, leg, code);
    }

    fn send_refused(&mut self, session: Uuid, leg: Uuid, code: &str) {
        self.frame(
            "refused",
            json!({ "sessionId": session, "leg": leg, "code": code }),
        );
    }

    fn save_store(&mut self) {
        if let Err(e) = self.store.save(&self.paths) {
            tracing::warn!(error = %e, "the device store could not be written");
        }
        self.store_stamp = std::fs::metadata(self.paths.devices())
            .ok()
            .and_then(|m| m.modified().ok());
    }

    fn label_of(&self, device: Uuid, kind: &str) -> String {
        self.store
            .devices
            .get(&device)
            .and_then(|d| d.label.clone())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| format!("{kind} {}", &device.to_string()[..8]))
    }

    /// Whether the host is stopping.
    pub fn stopping(&self) -> bool {
        self.stopping.is_some()
    }

    // -- what the host publishes ---------------------------------------------

    /// The `profiles` frame (FR-P5): no program, argument, directory,
    /// environment or bridge address, only a hash of the definition.
    pub fn profiles_frame(&self) -> Value {
        let profiles: Vec<Value> = self
            .profiles
            .profiles
            .iter()
            .map(|p| {
                let mut v = json!({
                    "id": p.id,
                    "label": p.label,
                    "kind": p.kind,
                    "source": match p.source { crate::profiles::Source::Process(_) => "process", crate::profiles::Source::Bridge(_) => "bridge" },
                    "state": p.state_word(),
                    "record": p.record,
                    "notify": p.notify,
                    "idleTimeout": crate::duration::format(p.idle_timeout),
                    "maxLifetime": crate::duration::format(p.max_lifetime),
                    "definitionHash": p.definition_hash,
                });
                if let Some(r) = p.reason() {
                    v["reason"] = Value::from(r);
                }
                if let Some(s) = &p.structured {
                    v["structured"] = Value::from(s.as_str());
                }
                if p.notify_bell {
                    v["notifyBell"] = Value::from(true);
                }
                if let Some(h) = self.harness.get(&p.id) {
                    v["harness"] = h.clone();
                }
                v
            })
            .collect();
        json!({ "type": "profiles", "profiles": profiles })
    }

    /// `host_info` (design §8.3), with the shell key signed by the machine.
    pub fn host_info_frame(&self) -> Value {
        let shell = self.endpoint.public();
        json!({
            "type": "host_info",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostVersion": self.host.host_version,
            "autostart": self.host.autostart,
            "runsAsRoot": self.host.runs_as_root,
            "maxSessions": self.profiles.host.max_sessions,
            "principalPin": self.binding.principal.id.to_string(),
            "rootPin": self.binding.root_fingerprint(),
            "shellKey": airdress_shell_proto::keys::fingerprint(&shell),
            "shellKeyPublic": crate::binding::b64_std(&shell),
            "sig": self.shell_key_sig,
        })
    }

    /// `sessions`: every live session, for reconciliation on connect.
    pub fn sessions_frame(&self) -> Value {
        let sessions: Vec<Value> = self
            .sessions
            .values()
            .filter(|s| s.exited.is_none())
            .map(Session::report)
            .collect();
        json!({ "type": "sessions", "sessions": sessions })
    }

    /// The channel came up: say who this host is and what it has.
    pub fn on_connected(&mut self) {
        self.out.send(Outgoing::Frame(self.host_info_frame()));
        self.out.send(Outgoing::Frame(self.profiles_frame()));
        self.out.send(Outgoing::Frame(self.sessions_frame()));
        if self.stopping.is_some() {
            self.frame("host_stopping", json!({ "inSeconds": 0 }));
        }
    }

    /// The channel went down: every leg is gone with it, but a device may
    /// resume within 120 s once it is back.
    pub fn on_disconnected(&mut self) {
        let now = self.now_ms();
        let legs: Vec<(Uuid, Uuid)> = self
            .sessions
            .values()
            .flat_map(|s| {
                s.clients
                    .values()
                    .filter_map(|c| c.leg)
                    .map(move |l| (s.id, l))
            })
            .collect();
        for (_, leg) in legs {
            if let Some((session, device)) = self.endpoint.drop_leg(leg, true, now) {
                if let Some(s) = self.sessions.get_mut(&session) {
                    s.detach(device, true, Instant::now());
                }
            }
        }
        for (_, p) in self.pending.drain() {
            self.endpoint.drop_leg(p.leg, false, now);
        }
    }

    // -- operator frames -------------------------------------------------------

    /// One verified operator frame.
    pub fn on_frame(&mut self, f: OpFrame) {
        match f {
            OpFrame::Hello {
                machine,
                frame_max_bytes,
                ..
            } => {
                if machine.is_some_and(|m| m != self.binding.machine_id) {
                    tracing::warn!("the operator's hello names another machine");
                }
                self.frame_max = frame_max_bytes.unwrap_or(65_536).clamp(4096, 1 << 20);
            }
            OpFrame::Config {
                enabled,
                max_viewers,
            } => {
                self.enabled = enabled;
                self.max_viewers = max_viewers;
            }
            OpFrame::Open {
                session_id,
                leg,
                profile,
                cols,
                rows,
                attestation,
                handshake,
            } => self.on_open(
                session_id,
                leg,
                &profile,
                (cols, rows),
                &attestation,
                &handshake,
            ),
            OpFrame::Attach {
                session_id,
                leg,
                attestation,
                handshake,
                resume,
            } => self.on_attach(session_id, leg, &attestation, handshake, resume),
            OpFrame::Data {
                session_id,
                leg,
                records,
            } => {
                for r in records {
                    self.on_data(session_id, leg, &r);
                }
            }
            OpFrame::Detach {
                session_id,
                leg,
                reason,
            } => self.on_detach(session_id, leg, &reason),
            OpFrame::Close { session_id, device } => self.on_close(session_id, device),
            OpFrame::ReleaseInput { session_id, device } => {
                if let Some(s) = self.sessions.get_mut(&session_id) {
                    if s.typist == Some(device) {
                        s.typist = None;
                        let sends = s.broadcast(&s.roles("Input released"));
                        self.deliver(session_id, sends);
                    }
                }
            }
            OpFrame::RevokeDevice { device } => {
                let report = self.revoke_device(device);
                tracing::info!(device = %device, legs = report.cut.len(), "a device was revoked");
            }
            OpFrame::Introduce {
                device,
                device_kind,
                identity_public,
                introduced_by,
                sig,
            } => {
                self.refresh_store();
                let introduced = self.store.introduce(
                    introduced_by,
                    device,
                    &identity_public,
                    &device_kind,
                    &sig,
                );
                match introduced {
                    Ok(()) => {
                        self.save_store();
                        tracing::info!(device = %device, kind = %device_kind, "a device was introduced");
                    }
                    Err(r) => {
                        tracing::warn!(device = %device, refusal = %r, "an introduction was refused")
                    }
                }
            }
        }
    }

    fn verify(
        &mut self,
        session: Uuid,
        leg: Uuid,
        att: &crate::trust::Attestation,
    ) -> Option<Verified> {
        self.refresh_store();
        match check_attestation(att, &self.facts, &mut self.store, SystemTime::now()) {
            Ok(v) => {
                self.save_store();
                Some(v)
            }
            Err(r) => {
                if r.code == "shell_device_not_introduced" {
                    self.save_store();
                    if let Some(p) = self.store.pending.get(&att.device) {
                        if let Some(k) = crate::trust::b64(&p.identity)
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        {
                            eprintln!(
                                "A device that is not introduced on this host asked to connect.\n\
                                 If it is yours, run on this machine, at its terminal:\n  \
                                 airdress shell host trust {}",
                                crate::trust::identity_fingerprint(&k)
                            );
                        }
                    }
                }
                let context = refusal_context(att, &self.facts);
                self.refuse_because(session, leg, r.code, &r.why, &context);
                None
            }
        }
    }

    fn on_open(
        &mut self,
        session: Uuid,
        leg: Uuid,
        profile_id: &str,
        size: (Option<u16>, Option<u16>),
        att: &crate::trust::Attestation,
        msg1: &[u8],
    ) {
        if self.stopping.is_some() {
            return self.refuse(session, leg, "shell_host_stopping");
        }
        if !self.enabled {
            return self.refuse(session, leg, "shell_host_disabled");
        }
        if self.sessions.contains_key(&session) || self.pending.contains_key(&session) {
            return self.refuse(session, leg, "shell_handshake_failed");
        }
        let Some(profile) = self.profiles.get(profile_id).cloned() else {
            return self.refuse(session, leg, "shell_profile_unknown");
        };
        if profile.state != State::Ready || profile.process().is_none() {
            return self.refuse(session, leg, "shell_profile_invalid");
        }
        let live = self.sessions.values().filter(|s| s.running()).count() + self.pending.len();
        if live >= self.profiles.host.max_sessions as usize {
            return self.refuse(session, leg, "shell_session_limit");
        }
        let Some(dev) = self.verify(session, leg, att) else {
            return;
        };
        let hello = HostHello {
            host_version: Some(self.host.host_version.clone()),
            profile_hash: Some(profile.definition_hash.clone()),
            resume_ticket: String::new(),
        };
        let now = self.now_ms();
        match self.endpoint.accept(
            &dev,
            Handshake {
                session,
                leg,
                profile: profile_id,
                action: Action::Open,
                resume: None,
                msg1,
                hello,
            },
            now,
        ) {
            Ok((msg2, hello)) => {
                let cols = hello.cols.or(size.0).unwrap_or(80);
                let rows = hello.rows.or(size.1).unwrap_or(24);
                let label = self.label_of(dev.device, &dev.kind);
                self.pending.insert(
                    session,
                    PendingOpen {
                        profile: profile_id.to_owned(),
                        size: (cols, rows),
                        leg,
                        device: dev.device,
                        label,
                        at: Instant::now(),
                    },
                );
                self.data(session, leg, msg2);
            }
            Err(e) => {
                let context = format!("device {}", dev.device);
                self.refuse_because(session, leg, e.code(), &e, &context);
            }
        }
    }

    fn on_attach(
        &mut self,
        session: Uuid,
        leg: Uuid,
        att: &crate::trust::Attestation,
        handshake: Option<Vec<u8>>,
        resume: Option<(String, Vec<u8>)>,
    ) {
        if !self.enabled {
            return self.refuse(session, leg, "shell_host_disabled");
        }
        let Some(s) = self.sessions.get(&session) else {
            // A session still being opened has no ticket to resume yet. One
            // this host does not hold at all has ended (or this host
            // restarted since): `session_ended` is final, so a client stops
            // there instead of retrying a ticket that can never work (found
            // live on a test operator, 2026-10-04: `shell_resume_expired` here kept two
            // clients reattaching 373 times in 15 s after a host restart).
            let code = if self.pending.contains_key(&session) {
                "shell_resume_expired"
            } else {
                "session_ended"
            };
            return self.refuse(session, leg, code);
        };
        let profile = s.profile.id.clone();
        let hash = s.profile.definition_hash.clone();
        let already = s.clients.contains_key(&att.device);
        if let Some(max) = self.max_viewers {
            if !already && s.attached_count() >= max as usize {
                return self.refuse(session, leg, "shell_viewer_limit");
            }
        }
        let Some(dev) = self.verify(session, leg, att) else {
            return;
        };
        let (action, msg1, ticket) = match (handshake, resume) {
            (Some(h), None) => (Action::Attach, h, None),
            (None, Some((t, h))) => match TicketId::decode(&t) {
                Ok(t) => (Action::Resume, h, Some(t)),
                Err(_) => return self.refuse(session, leg, "shell_resume_expired"),
            },
            _ => return self.refuse(session, leg, "shell_handshake_failed"),
        };
        let hello = if action == Action::Resume {
            HostHello {
                host_version: None,
                profile_hash: None,
                resume_ticket: String::new(),
            }
        } else {
            HostHello {
                host_version: Some(self.host.host_version.clone()),
                profile_hash: Some(hash),
                resume_ticket: String::new(),
            }
        };
        let now = self.now_ms();
        match self.endpoint.accept(
            &dev,
            Handshake {
                session,
                leg,
                profile: &profile,
                action,
                resume: ticket,
                msg1: &msg1,
                hello,
            },
            now,
        ) {
            Ok((msg2, hello)) => {
                let size = hello.cols.zip(hello.rows);
                let label = self.label_of(dev.device, &dev.kind);
                if let Some(s) = self.sessions.get_mut(&session) {
                    // The client entry waits for admission; remember its size.
                    let at = s.journal.end();
                    let c = s
                        .clients
                        .entry(dev.device)
                        .or_insert_with(|| Client::new(leg, label.clone(), at, size));
                    c.leg = None;
                    if size.is_some() {
                        c.size = size;
                    }
                    c.label = label;
                }
                self.data(session, leg, msg2);
            }
            Err(e) => {
                let context = format!("device {}", dev.device);
                self.refuse_because(session, leg, e.code(), &e, &context);
            }
        }
    }

    /// One record from a device.
    pub fn on_data(&mut self, session: Uuid, leg: Uuid, record: &[u8]) {
        let now = self.now_ms();
        match self.endpoint.receive(leg, record, now) {
            Err(e) => {
                if self.endpoint.leg(leg).is_none() {
                    // A leg that was never admitted, refused for good.
                    if self.pending.get(&session).is_some_and(|p| p.leg == leg) {
                        self.pending.remove(&session);
                    }
                    self.refuse(session, leg, e.code());
                }
            }
            Ok(rcv) => {
                for r in rcv.replies {
                    self.data(session, leg, r);
                }
                if let Some(a) = rcv.admitted {
                    self.on_admitted(a);
                }
                if let Some((_, device)) = self.endpoint.leg(leg) {
                    for m in rcv.messages {
                        self.on_message(session, device, m);
                    }
                }
            }
        }
    }

    fn on_admitted(&mut self, a: Admitted) {
        match a.action {
            Action::Open => {
                let Some(p) = self.pending.remove(&a.session) else {
                    return;
                };
                match self.spawn(a.session, &p) {
                    Ok(()) => {
                        self.frame(
                            "opened",
                            json!({ "sessionId": a.session, "client": a.device.to_string(), "profile": p.profile, "leg": a.leg }),
                        );
                        self.frame(
                            "input_moved",
                            json!({ "sessionId": a.session, "client": a.device.to_string() }),
                        );
                        if let Some(s) = self.sessions.get(&a.session) {
                            let sends = s.broadcast(&s.roles("Opened"));
                            self.deliver(a.session, sends);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(session = %a.session, error = %e, "the profile could not be started");
                        let msg = Message::Error {
                            code: "shell_profile_invalid".into(),
                            message: "The profile could not be started on the host".into(),
                        };
                        let now_ms = self.now_ms();
                        if let Some(rec) = self.endpoint.seal(a.leg, &[msg], now_ms) {
                            self.data(a.session, a.leg, rec);
                        }
                        self.endpoint.forget_session(a.session);
                        self.refuse(a.session, a.leg, "shell_profile_invalid");
                    }
                }
            }
            Action::Attach => {
                let budget = self.budget();
                let Some(s) = self.sessions.get_mut(&a.session) else {
                    return;
                };
                let at = s.journal.end();
                let c = s
                    .clients
                    .entry(a.device)
                    .or_insert_with(|| Client::new(a.leg, String::new(), at, None));
                c.leg = Some(a.leg);
                c.sent = at;
                c.acked = at;
                c.lagging = false;
                c.resend_on_ack = false;
                let label = c.label.clone();
                s.idle_since = None;
                let snap = s.snapshot(budget);
                let mut sends = vec![Send {
                    leg: a.leg,
                    msg: snap,
                }];
                sends.extend(crate::structured::input::replay(s, a.leg, budget));
                if let Some((code, signal, _)) = s.exited {
                    sends.push(Send {
                        leg: a.leg,
                        msg: Message::Exit { code, signal },
                    });
                }
                sends.extend(s.broadcast(&s.roles(&format!("{label} joined"))));
                self.deliver(a.session, sends);
                self.frame(
                    "attached",
                    json!({ "sessionId": a.session, "client": a.device.to_string(), "leg": a.leg }),
                );
            }
            Action::Resume => {
                let Some(s) = self.sessions.get_mut(&a.session) else {
                    return;
                };
                if let Some(c) = s.clients.get_mut(&a.device) {
                    c.leg = Some(a.leg);
                    c.resend_on_ack = true;
                    c.lagging = false;
                }
                s.idle_since = None;
                // Who has input now, to the resumed device alone: it may
                // have moved while this device was away, and an idle session
                // has nothing else to say. Clients up to cli `233c2ad` and
                // chat `66f9e2d` counted a resumed leg live only once they
                // heard a record after message 2, so after an operator
                // restart they waited on an idle session for minutes (found
                // live on a test operator, v0.1.119, 2026-10-05).
                let roles = s.roles("resumed");
                // Structured events sent while the leg was away are not in
                // the journal: the transcript says where things are now.
                let budget = budget_for(self.frame_max);
                let mut sends = vec![Send {
                    leg: a.leg,
                    msg: roles,
                }];
                sends.extend(crate::structured::input::replay(s, a.leg, budget));
                self.deliver(a.session, sends);
                self.frame(
                    "attached",
                    json!({ "sessionId": a.session, "client": a.device.to_string(), "leg": a.leg, "reason": "resume" }),
                );
            }
        }
    }

    fn spawn(&mut self, id: Uuid, p: &PendingOpen) -> anyhow::Result<()> {
        let profile = self
            .profiles
            .get(&p.profile)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the profile is gone"))?;
        let spec = profile
            .process()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the profile is not ready"))?;
        let mut env = crate::environment::build(&profile, id, &crate::environment::host_env);
        let (tx, mut rx) = mpsc::channel::<PtyEvent>(64);
        let adapter = profile
            .structured
            .as_deref()
            .and_then(crate::structured::Adapter::parse);
        // Design §7.5: a harness driven through its terminal gets the event
        // socket and a token of its own for its hooks.
        let events_token = match (adapter, &self.events_socket) {
            (Some(crate::structured::Adapter::TerminalHooks), Some(sock)) => {
                use rand::RngCore as _;
                let mut raw = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut raw);
                let token = crate::binding::b64_std(&raw);
                env.vars
                    .insert("AIRDRESS_SHELL_SOCKET".into(), sock.as_os_str().to_owned());
                env.vars
                    .insert("AIRDRESS_SHELL_EVENTS_TOKEN".into(), token.clone().into());
                Some(crate::structured::events::HookToken::new(token))
            }
            _ => None,
        };
        let stdio = adapter.is_some_and(crate::structured::Adapter::uses_stdio);
        let (pty, pipes) =
            crate::pty::spawn_with(&spec, &env, p.size.0, p.size.1, tx.clone(), stdio)?;
        let structured = adapter.map(|adapter| crate::session::StructuredSide {
            adapter,
            handle: crate::structured::start(
                crate::structured::Connect {
                    session: id,
                    adapter,
                    stdio: pipes,
                    cwd: spec.cwd.clone(),
                    args: spec.args.clone(),
                    server_password: env.server_password(),
                },
                tx.clone(),
            ),
            transcript: crate::structured::transcript::Transcript::default(),
            events_token,
            hooks: crate::structured::events::Mapper::default(),
            waiting: std::collections::HashMap::new(),
        });
        drop(tx);
        // The session's events, onto the host's queue: owned by the
        // session (R-ASY-1), so it ends with it.
        let main = self.pty_tx.clone();
        let mut forward = tokio::task::JoinSet::new();
        forward.spawn(async move {
            while let Some(e) = rx.recv().await {
                if main.send((id, e)).await.is_err() {
                    break;
                }
            }
        });
        let journal = Journal::new(
            self.profiles.host.journal_bytes,
            self.profiles.host.journal_spill_bytes,
            Some(self.paths.spill_dir().join(id.to_string())),
        )?;
        let recording = if profile.record {
            match Recorder::start(
                &self.paths,
                id,
                &profile.id,
                profile.recording_retention,
                profile.record_input,
                p.size,
                &self.store.recipients(),
            ) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(session = %id, error = %e, "this session is not recorded");
                    None
                }
            }
        } else {
            None
        };
        let mut clients = BTreeMap::new();
        clients.insert(
            p.device,
            Client::new(p.leg, p.label.clone(), 0, Some(p.size)),
        );
        self.sessions.insert(
            id,
            Session {
                id,
                emulator: crate::emulator::Emulator::new(
                    p.size.0,
                    p.size.1,
                    self.profiles.host.scrollback_lines,
                ),
                profile,
                pty: Some(pty),
                journal,
                clients,
                typist: Some(p.device),
                size: p.size,
                opened_at: Instant::now(),
                opened_wall: chrono::Utc::now(),
                idle_since: None,
                lifetime_warned: false,
                exited: None,
                ending: None,
                recording,
                last_input: None,
                state: "working",
                stalled_input: std::collections::VecDeque::new(),
                stalled_since: None,
                forward,
                structured,
            },
        );
        Ok(())
    }

    fn on_message(&mut self, session: Uuid, device: Uuid, m: Message) {
        let budget = self.budget();
        let paths = self.paths.clone();
        let Some(s) = self.sessions.get_mut(&session) else {
            return;
        };
        let Some(leg) = s.clients.get(&device).and_then(|c| c.leg) else {
            return;
        };
        let reply = |msg: Message| vec![Send { leg, msg }];
        let not_held = || Message::Error {
            code: "shell_input_not_held".into(),
            message: "Input is on another device; take input first".into(),
        };
        let sends: Vec<Send> = match m {
            Message::In { .. } | Message::Signal { .. } if s.stdio_is_protocol() => {
                reply(Message::Error {
                    code: "shell_terminal_unavailable".into(),
                    message: "This profile's terminal only shows its log; use the structured view"
                        .into(),
                })
            }
            Message::In { data } => {
                if !s.is_typist(device) {
                    reply(not_held())
                } else {
                    if let Some(r) = s.recording.as_mut() {
                        r.input(&data).log_warn("recording the session's input");
                    }
                    let now = Instant::now();
                    s.last_input = Some(now);
                    s.type_in(data, now);
                    Vec::new()
                }
            }
            Message::Signal { signal } => {
                if !s.is_typist(device) {
                    reply(not_held())
                } else {
                    let now = Instant::now();
                    s.last_input = Some(now);
                    // The signal's control character, as a keyboard sends
                    // it: behind what was typed before it.
                    let c = s
                        .pty
                        .as_ref()
                        .and_then(|p| p.control_char(signal).ok().flatten());
                    if let Some(c) = c {
                        s.type_in(vec![c], now);
                    }
                    Vec::new()
                }
            }
            Message::Resize { cols, rows } => {
                if let Some(c) = s.clients.get_mut(&device) {
                    c.size = Some((cols, rows));
                }
                if s.is_typist(device) {
                    s.apply_size(cols, rows);
                }
                Vec::new()
            }
            Message::Ack { offset } => s.ack(device, offset, budget),
            Message::Credit { bytes } => {
                if let Some(c) = s.clients.get_mut(&device) {
                    c.credit = bytes.clamp(4096, crate::session::MAX_CREDIT);
                }
                Vec::new()
            }
            Message::TakeInput => {
                let sends = s.take_input(device).unwrap_or_default();
                self.frame(
                    "input_moved",
                    json!({ "sessionId": session, "client": device.to_string() }),
                );
                sends
            }
            Message::RecordingList => reply(Message::RecordingListing {
                recordings: crate::recording::list(&paths),
            }),
            Message::RecordingFetch {
                recording,
                segment,
                from_chunk,
            } => match crate::recording::fetch(&paths, &recording, segment, from_chunk) {
                Ok((header, chunks)) => {
                    let mut v = vec![Send {
                        leg,
                        msg: Message::RecordingHeader {
                            recording: recording.clone(),
                            segment,
                            header,
                        },
                    }];
                    v.extend(chunks.into_iter().map(|(index, sealed)| Send {
                        leg,
                        msg: Message::RecordingChunk {
                            segment,
                            index,
                            sealed,
                        },
                    }));
                    v
                }
                Err(e) => reply(Message::Error {
                    code: "shell_recording_unreadable".into(),
                    message: e.to_string(),
                }),
            },
            Message::RecordingRewrap {
                recording,
                segment,
                entry,
            } => match crate::recording::rewrap(&paths, &recording, segment, entry) {
                Ok(()) => Vec::new(),
                Err(e) => reply(Message::Error {
                    code: "shell_recording_unreadable".into(),
                    message: e.to_string(),
                }),
            },
            Message::Structured { body } => {
                let (replies, events) = crate::structured::input::from_client(s, device, &body);
                let mut sends: Vec<Send> =
                    replies.into_iter().map(|msg| Send { leg, msg }).collect();
                for e in events {
                    let (more, attention) = crate::structured::input::from_adapter(
                        s,
                        crate::structured::AdapterOut::Event(e),
                        budget,
                    );
                    sends.extend(more);
                    if let Some(state) = attention {
                        self.out.send(Outgoing::Frame(
                            json!({ "type": "attention", "sessionId": session, "state": state }),
                        ));
                    }
                }
                sends
            }
            _ => Vec::new(),
        };
        self.deliver(session, sends);
    }

    fn on_detach(&mut self, session: Uuid, leg: Uuid, reason: &str) {
        let keep = reason == "peer_gone";
        let now = self.now_ms();
        if self.pending.get(&session).is_some_and(|p| p.leg == leg) {
            self.pending.remove(&session);
        }
        let Some((s_id, device)) = self.endpoint.drop_leg(leg, keep, now) else {
            return;
        };
        if let Some(s) = self.sessions.get_mut(&s_id) {
            let was = s.clients.get(&device).and_then(|c| c.leg) == Some(leg);
            if !was {
                return;
            }
            s.detach(device, keep, Instant::now());
            let sends = s.broadcast(&s.roles("A device left"));
            self.deliver(s_id, sends);
            self.frame(
                "detached",
                json!({ "sessionId": s_id, "client": device.to_string(), "leg": leg, "reason": reason }),
            );
        }
    }

    fn on_close(&mut self, session: Uuid, device: Uuid) {
        let Some(s) = self.sessions.get_mut(&session) else {
            return;
        };
        if !(s.clients.contains_key(&device) || self.store.trusted(&device)) {
            tracing::warn!(session = %session, device = %device, "a close from a device that is not this person's");
            return;
        }
        if s.exited.is_some() {
            self.finalize(session, "closed");
        } else {
            s.end("closed", Instant::now());
        }
    }

    // -- revocation (design §6.7, D-24) ----------------------------------------

    /// Cut `device` off, and protect what it may have seen.
    pub fn revoke_device(&mut self, device: Uuid) -> RevokeReport {
        self.refresh_store();
        let mut r = RevokeReport::default();
        // 1. Cut off at once: channels closed, keys and tickets zeroed, the
        // device added to the revoked set, its typist role cleared.
        self.store.revoke(device);
        self.save_store();
        r.cut = self.endpoint.forget_device(device);
        r.forgotten = true;
        let now = self.now_ms();
        // Steps 2–4 run on EVERY session, whether or not the device is
        // attached to it now. The operator closes a revoked device's legs
        // before it tells the host, so by the time this runs the device is
        // usually no longer a client anywhere (found live on a test operator,
        // 2026-10-04: `legs=0`, and nothing rekeyed or rolled). What D-24
        // protects does not depend on the leg: a running recording is
        // wrapped to every device of the person at its segment's start,
        // attached or not, and only a roll keeps the revoked one out of what
        // is recorded next.
        let ids: Vec<Uuid> = self.sessions.keys().copied().collect();
        let recipients = self.store.recipients();
        for id in ids {
            let Some(s) = self.sessions.get_mut(&id) else {
                continue;
            };
            let was_here = s.clients.contains_key(&device) || s.typist == Some(device);
            let label = s
                .clients
                .get(&device)
                .map(|c| c.label.clone())
                .unwrap_or_else(|| "A device".into());
            let cut_leg = s.clients.get(&device).and_then(|c| c.leg);
            s.clients.remove(&device);
            if s.typist == Some(device) {
                s.typist = None;
            }
            if was_here && s.attached_count() == 0 && s.idle_since.is_none() {
                s.idle_since = Some(Instant::now());
            }
            // 2. Rekey every remaining leg of the session.
            let legs: Vec<Uuid> = s.attached().filter_map(|(_, c)| c.leg).collect();
            for leg in legs {
                if let Some(rec) = self.endpoint.rekey(leg, true, now) {
                    self.out.send(Outgoing::Data {
                        session: id,
                        leg,
                        record: rec,
                    });
                    r.rekeyed.push(leg);
                }
            }
            // 3. A new spill key, and the spill re-encrypted under it.
            match s.journal.rotate_key() {
                Ok(()) => r.spill_rotated.push(id),
                Err(e) => {
                    tracing::warn!(session = %id, error = %e, "the spill could not be re-encrypted")
                }
            }
            // 4. Roll the recording to the remaining devices.
            if let Some(rec) = s.recording.as_mut() {
                match rec.roll(&recipients) {
                    Ok(true) => r.recordings_rolled.push(id),
                    Ok(false) => {
                        r.recordings_rolled.push(id);
                        s.recording = None;
                    }
                    Err(e) => {
                        tracing::warn!(session = %id, error = %e, "the recording stopped");
                        s.recording = None;
                    }
                }
            }
            // 5. Tell the rest, where it was one of them, and the operator
            // for its audit.
            if !was_here {
                continue;
            }
            let sends = s.broadcast(&s.roles(&format!("{label} was signed out")));
            self.deliver(id, sends);
            r.told.push(id);
            if let Some(leg) = cut_leg {
                self.frame(
                    "detached",
                    json!({ "sessionId": id, "client": device.to_string(), "leg": leg, "reason": "device_revoked" }),
                );
            }
        }
        self.pending.retain(|_, p| p.device != device);
        r
    }

    // -- PTY events ------------------------------------------------------------

    /// An event from a session's PTY.
    pub fn on_pty(&mut self, id: Uuid, ev: PtyEvent) {
        let budget = self.budget();
        match ev {
            PtyEvent::Structured(out) => self.on_structured(id, out),
            PtyEvent::Hook(call) => self.on_hook(id, call),
            PtyEvent::Output(data) => {
                let Some(s) = self.sessions.get_mut(&id) else {
                    return;
                };
                let sends = s.output(&data, budget);
                let bells = s.emulator.take_bells();
                let bell = bells > 0 && s.profile.notify_bell;
                self.deliver(id, sends);
                if bell {
                    self.frame("attention", json!({ "sessionId": id, "state": "bell" }));
                }
            }
            PtyEvent::Exited { code, signal } => {
                let Some(s) = self.sessions.get_mut(&id) else {
                    return;
                };
                s.exited = Some((code, signal, Instant::now()));
                s.pty = None;
                if let Some(r) = s.recording.take() {
                    if let Err(e) = r.finish() {
                        tracing::warn!(session = %id, error = %e, "the recording could not be closed");
                    }
                }
                let sends = s.broadcast(&Message::Exit { code, signal });
                let reason = s.ending.as_ref().map(|e| e.reason);
                self.deliver(id, sends);
                // Ended by the host or a person: gone now. Exited by itself:
                // readable for a while (FR-S12), finalized by the tick.
                if let Some(r) = reason {
                    self.finalize(id, r);
                }
            }
        }
    }

    /// The session whose input waits for its program, the queue to wait
    /// for room on, and when to give up (R-ASY-5). While there is one the
    /// runner reads nothing from the link. A session that exited, or a host
    /// that is stopping, has nothing to wait for.
    pub fn stalled_input(&mut self) -> Option<(Uuid, mpsc::Sender<Vec<u8>>, tokio::time::Instant)> {
        let stopping = self.stopping.is_some();
        let stall = self.timings.input_stall;
        for (id, s) in &mut self.sessions {
            if s.stalled_input.is_empty() {
                continue;
            }
            match (&s.pty, stopping) {
                (Some(p), false) => {
                    let since = s.stalled_since.unwrap_or_else(Instant::now);
                    let give_up = tokio::time::Instant::from_std(since + stall);
                    return Some((*id, p.input(), give_up));
                }
                _ => {
                    s.abandon_stalled_input();
                }
            }
        }
        None
    }

    /// Room in a stalled session's queue (`None`: the program is gone).
    pub fn on_input_room(&mut self, id: Uuid, permit: Option<mpsc::Permit<'_, Vec<u8>>>) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        match permit {
            Some(permit) => s.input_room(permit, Instant::now()),
            None => {
                s.abandon_stalled_input();
            }
        }
    }

    /// The program took nothing for [`Timings::input_stall`]: the waiting
    /// input is dropped, and the typist is told how much, so nothing is
    /// lost silently and one stopped program does not hold every other
    /// session's input.
    pub fn on_input_stalled(&mut self, id: Uuid) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let lost = s.abandon_stalled_input();
        if lost == 0 {
            return;
        }
        tracing::warn!(session = %id, bytes = lost, "the program did not read its input; dropped");
        let leg = s.typist.and_then(|t| s.clients.get(&t)).and_then(|c| c.leg);
        if let Some(leg) = leg {
            let msg = Message::Error {
                code: "shell_input_stalled".into(),
                message: format!(
                    "The program is not reading its input; {lost} bytes were not delivered"
                ),
            };
            self.deliver(id, vec![Send { leg, msg }]);
        }
    }

    /// An event from a session's adapter: into its transcript, out to every
    /// attached client, and attention to the operator where the profile
    /// asks for it (design §9.3, D-20).
    fn on_structured(&mut self, id: Uuid, out: crate::structured::AdapterOut) {
        let budget = self.budget();
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let (sends, attention) = crate::structured::input::from_adapter(s, out, budget);
        self.deliver(id, sends);
        if let Some(state) = attention {
            self.frame("attention", json!({ "sessionId": id, "state": state }));
        }
    }

    /// A hook call from the event socket (design §9.4): only with the
    /// session's own token, only for a session whose harness is driven
    /// through its terminal.
    fn on_hook(&mut self, id: Uuid, call: crate::structured::events::HookCall) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let Some(side) = s.structured.as_mut() else {
            return;
        };
        let ok = side
            .events_token
            .as_ref()
            .is_some_and(|t| crate::structured::events::token_eq(t.expose(), call.token.expose()));
        if !ok {
            tracing::warn!(session = %id, "a hook call with the wrong token was refused");
            return;
        }
        let (events, approval) = side.hooks.hook(&call.input);
        if let (Some(a), Some(reply)) = (approval, call.reply) {
            side.waiting.insert(a, reply);
        }
        for e in events {
            self.on_structured(id, crate::structured::AdapterOut::Event(e));
        }
    }

    /// Report the session's end and drop it.
    fn finalize(&mut self, id: Uuid, reason: &str) {
        let Some(mut s) = self.sessions.remove(&id) else {
            return;
        };
        let (code, signal) = s.exited.map_or((None, None), |(c, g, _)| (c, g));
        if let Some(r) = s.recording.take() {
            r.finish().log_warn("finishing the session's recording");
        }
        s.journal.destroy();
        self.endpoint.forget_session(id);
        self.frame(
            "exited",
            json!({ "sessionId": id, "code": code, "signal": signal, "reason": reason }),
        );
    }

    // -- time --------------------------------------------------------------------

    /// Lifetimes, rekeys, stale opens, the profile file. Called every
    /// [`Timings::tick`].
    pub fn tick(&mut self) {
        // Reap the probes that finished (their reports came on the queue).
        while let Some(done) = self.probes.try_join_next() {
            if let Err(e) = done {
                tracing::warn!(error = %e, "a harness probe did not finish");
            }
        }
        let now = Instant::now();
        let ids: Vec<Uuid> = self.sessions.keys().copied().collect();
        for id in ids {
            let Some(s) = self.sessions.get_mut(&id) else {
                continue;
            };
            if s.lifetime_warning_due(now, self.timings.lifetime_warning) {
                s.lifetime_warned = true;
                let mins = self.timings.lifetime_warning.as_secs().div_ceil(60);
                let sends = s.broadcast(&Message::Error {
                    code: "shell_lifetime_warning".into(),
                    message: format!(
                        "This session reaches its maximum lifetime in {mins} minutes and will end"
                    ),
                });
                self.deliver(id, sends);
            }
            let Some(s) = self.sessions.get_mut(&id) else {
                continue;
            };
            if let Some(reason) = s.due(now) {
                s.end(reason, now);
            }
            s.kill_if_due(now, self.timings.kill_after);
            // A permission hook that stopped waiting (FR-K3's 120 s): its
            // card goes, and the terminal's own prompt is what stands.
            let gave_up: Vec<String> = s
                .structured
                .as_mut()
                .map(|side| {
                    let ids: Vec<String> = side
                        .waiting
                        .iter()
                        .filter(|(_, tx)| tx.is_closed())
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in &ids {
                        side.waiting.remove(k);
                    }
                    ids
                })
                .unwrap_or_default();
            for approval in gave_up {
                use airdress_shell_proto::structured::{ApprovalOutcome, Event, SessionState};
                self.on_structured(
                    id,
                    crate::structured::AdapterOut::Event(Event::ApprovalResolved {
                        id: approval,
                        outcome: ApprovalOutcome::Withdrawn,
                    }),
                );
                self.on_structured(
                    id,
                    crate::structured::AdapterOut::Event(Event::Status {
                        state: SessionState::WaitingForInput,
                    }),
                );
            }
            let Some(s) = self.sessions.get_mut(&id) else {
                continue;
            };
            if let Some(r) = s.recording.as_mut() {
                r.flush_if_due()
                    .log_warn("flushing the session's recording");
            }
            if s.exited
                .is_some_and(|(_, _, at)| now.duration_since(at) >= self.timings.exit_readable)
            {
                self.finalize(id, "exit");
            }
        }
        let now_ms = self.now_ms();
        for leg in self.endpoint.due_for_rekey(now_ms) {
            if let (Some(rec), Some((session, _))) = (
                self.endpoint.rekey(leg, false, now_ms),
                self.endpoint.leg(leg),
            ) {
                self.data(session, leg, rec);
            }
        }
        self.endpoint.prune(now_ms);
        let stale: Vec<(Uuid, Uuid)> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.at) >= self.timings.open_timeout)
            .map(|(s, p)| (*s, p.leg))
            .collect();
        for (session, leg) in stale {
            self.pending.remove(&session);
            self.endpoint.drop_leg(leg, false, now_ms);
            self.refuse(session, leg, "shell_presence_required");
        }
        self.reload_profiles_if_changed();
        self.schedule_probes(now);
        if self
            .last_prune
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(86_400))
        {
            self.last_prune = Some(now);
            let n = crate::recording::prune(&self.paths, SystemTime::now());
            if n > 0 {
                tracing::info!(removed = n, "recordings past their retention were removed");
            }
        }
    }

    /// Start the probes that are due (design §9.2): at start, when a
    /// profile changed, every `probe_interval`; never while a session of
    /// that profile had input in the last minute.
    pub fn schedule_probes(&mut self, now: Instant) {
        let Some(tx) = self.probe_tx.clone() else {
            return;
        };
        let interval = self.profiles.host.probe_interval;
        for p in &self.profiles.profiles {
            if p.harness().is_none() || self.probing.contains(&p.id) {
                continue;
            }
            let due = match self.probed.get(&p.id) {
                None => true,
                Some((at, hash)) => {
                    *hash != p.definition_hash || now.duration_since(*at) >= interval
                }
            };
            let busy = self.sessions.values().any(|s| {
                s.profile.id == p.id
                    && s.last_input
                        .is_some_and(|t| now.duration_since(t) < crate::probes::QUIET_FOR)
            });
            if !due || busy {
                continue;
            }
            self.probing.insert(p.id.clone());
            let prof = p.clone();
            let tx = tx.clone();
            self.probes.spawn(async move {
                let hash = prof.definition_hash.clone();
                let v = crate::probes::probe(&prof, &crate::environment::host_env)
                    .await
                    .map_or(Value::Null, |s| s.to_json());
                // Closed: the host is stopping; nobody wants the report.
                tx.send((prof.id, hash, v))
                    .await
                    .log_debug("reporting a harness probe");
            });
        }
    }

    /// A probe finished.
    pub fn on_probe(&mut self, id: String, hash: String, report: Value) {
        self.probing.remove(&id);
        self.probed
            .insert(id.clone(), (Instant::now(), hash.clone()));
        if report.is_null()
            || self
                .profiles
                .get(&id)
                .is_none_or(|p| p.definition_hash != hash)
        {
            return;
        }
        if self.harness.get(&id) != Some(&report) {
            self.harness.insert(id, report);
            self.out.send(Outgoing::Frame(self.profiles_frame()));
        }
    }

    /// Reload the profile file when it changed on disk, and announce it.
    pub fn reload_profiles_if_changed(&mut self) -> bool {
        let st = stamp(&self.paths);
        if st == self.profiles_stamp {
            return false;
        }
        self.profiles_stamp = st;
        let next = match crate::profiles::load(&self.paths) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("The profile file was refused, so no profile is offered: {e:#}");
                ProfileFile {
                    host: self.profiles.host.clone(),
                    profiles: Vec::new(),
                }
            }
        };
        if next == self.profiles {
            return false;
        }
        let before: BTreeMap<&str, &str> = self
            .profiles
            .profiles
            .iter()
            .map(|p| (p.id.as_str(), p.definition_hash.as_str()))
            .collect();
        for p in &next.profiles {
            match before.get(p.id.as_str()) {
                None => eprintln!("profile added: {}", p.id),
                Some(h) if *h != p.definition_hash => eprintln!("profile changed: {}", p.id),
                _ => {}
            }
        }
        for id in before.keys() {
            if next.get(id).is_none() {
                eprintln!("profile removed: {id}");
            }
        }
        self.profiles = next;
        self.out.send(Outgoing::Frame(self.profiles_frame()));
        true
    }

    // -- stopping (FR-S14) ----------------------------------------------------------

    /// Ctrl-C or SIGTERM: say so, hang every session up, `SIGKILL` later.
    pub fn begin_stop(&mut self) {
        if self.stopping.is_some() {
            return;
        }
        let now = Instant::now();
        self.stopping = Some(now);
        let secs = self.timings.kill_after.as_secs().max(1) as u32;
        // 1. Every client first, in its own channel, and only then the
        // operator. The operator ends every leg of a host the moment it
        // reads `host_stopping`; the channel is ordered, so the records
        // queued ahead of that frame reach the devices and the frame does
        // not overtake them. In the other order the clients only saw their
        // legs go (found live on a test operator, 2026-10-04: "connection lost;
        // reconnecting…" where "the host is stopping" was owed).
        let ids: Vec<Uuid> = self.sessions.keys().copied().collect();
        let mut done = Vec::new();
        for id in ids {
            let Some(s) = self.sessions.get_mut(&id) else {
                continue;
            };
            let sends = s.broadcast(&Message::HostStopping { in_seconds: secs });
            if s.exited.is_some() {
                done.push(id);
            } else {
                s.ending = None;
                s.end("host_stopped", now);
            }
            self.deliver(id, sends);
        }
        self.frame("host_stopping", json!({ "inSeconds": secs }));
        for id in done {
            self.finalize(id, "host_stopped");
        }
        let pending: Vec<(Uuid, Uuid)> = self.pending.iter().map(|(s, p)| (*s, p.leg)).collect();
        for (session, leg) in pending {
            self.pending.remove(&session);
            self.refuse(session, leg, "shell_host_stopping");
        }
    }

    /// Whether the stop has finished: every session ended, or the grace
    /// and the kill have both passed (anything left is reported anyway).
    pub fn stop_finished(&mut self) -> bool {
        let Some(at) = self.stopping else {
            return false;
        };
        if self.sessions.is_empty() {
            return true;
        }
        if at.elapsed() >= self.timings.kill_after + Duration::from_secs(2) {
            let ids: Vec<Uuid> = self.sessions.keys().copied().collect();
            for id in ids {
                if let Some(s) = self.sessions.get(&id) {
                    if let Some(p) = &s.pty {
                        p.kill();
                    }
                }
                self.finalize(id, "host_stopped");
            }
            return true;
        }
        false
    }

    /// A second Ctrl-C: kill what is left now and report it.
    pub fn force_stop(&mut self) {
        self.begin_stop();
        let ids: Vec<Uuid> = self.sessions.keys().copied().collect();
        for id in ids {
            if let Some(p) = self.sessions.get(&id).and_then(|s| s.pty.as_ref()) {
                p.kill();
            }
            self.finalize(id, "host_stopped");
        }
    }

    /// Re-read the device store when another process (`airdress shell host
    /// trust`) changed it, before this one changes it.
    fn refresh_store(&mut self) {
        let st = std::fs::metadata(self.paths.devices())
            .ok()
            .and_then(|m| m.modified().ok());
        if st != self.store_stamp {
            if let Ok(s) = DeviceStore::load(&self.paths) {
                self.store = s;
            }
            self.store_stamp = st;
        }
    }

    /// The last thing a stopping host sends.
    pub fn close_channel(&self) {
        self.out
            .send(Outgoing::Close(4001, "shell_host_stopping".into()));
    }
}

/// Who was refused, for this host's log: the device id and the
/// fingerprints of its identity key and of the root this host pinned.
/// Fingerprints only, never a key, a delegation or a signature — enough to
/// see that a device's root is not the one this host was bound to, the
/// refusal that otherwise reads as a bare `shell_handshake_failed`.
fn refusal_context(att: &crate::trust::Attestation, facts: &crate::trust::BindingFacts) -> String {
    let identity = crate::trust::b64(&att.identity_public)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map_or_else(
            || "unreadable".to_owned(),
            |k| crate::trust::identity_fingerprint(&k),
        );
    let root = facts
        .root
        .as_ref()
        .map_or_else(|| "none".to_owned(), crate::trust::identity_fingerprint);
    format!(
        "device {}, identity {identity}, pinned root {root}, airdress {}",
        att.device, facts.airdress
    )
}

#[cfg(test)]
mod refusal_context_tests {
    use super::refusal_context;
    use crate::trust::{identity_fingerprint, Attestation, BindingFacts};
    use base64::Engine as _;

    fn attestation(identity: &str) -> Attestation {
        serde_json::from_value(serde_json::json!({
            "device": uuid::Uuid::from_u128(9),
            "principal": uuid::Uuid::from_u128(1),
            "identityPublic": identity,
            "dhPublic": "",
            "presenceAlg": "none",
            "keysSig": "",
        }))
        .unwrap()
    }

    #[test]
    fn names_both_fingerprints_and_never_a_key() {
        let identity = [3u8; 32];
        let root = [4u8; 32];
        let identity_b64 = base64::engine::general_purpose::STANDARD.encode(identity);
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(root);
        let facts = BindingFacts {
            principal: uuid::Uuid::from_u128(1),
            root: Some(root),
            airdress: "qa.example".into(),
        };
        let line = refusal_context(&attestation(&identity_b64), &facts);
        assert!(line.contains(&identity_fingerprint(&identity)), "{line}");
        assert!(line.contains(&identity_fingerprint(&root)), "{line}");
        assert!(line.contains("qa.example"), "{line}");
        assert!(
            !line.contains(&identity_b64) && !line.contains(&root_b64),
            "{line}"
        );
    }

    #[test]
    fn says_when_no_root_is_pinned_or_the_key_is_unreadable() {
        let facts = BindingFacts {
            principal: uuid::Uuid::from_u128(1),
            root: None,
            airdress: "qa.example".into(),
        };
        let line = refusal_context(&attestation("not base64!"), &facts);
        assert!(line.contains("pinned root none"), "{line}");
        assert!(line.contains("identity unreadable"), "{line}");
    }
}

fn stamp(paths: &Paths) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(paths.profiles_file()).ok()?;
    Some((m.modified().ok()?, m.len()))
}

#[cfg(test)]
mod outbox_tests {
    use super::*;

    fn frame(n: u64) -> Outgoing {
        Outgoing::Frame(json!({ "n": n }))
    }

    /// R-ASY-5: what the channel has no room for waits in order, the
    /// runner is told, and room moves it in the order it was sent.
    #[tokio::test]
    async fn a_full_channel_backlogs_in_order_and_room_drains_it() {
        let (tx, mut rx) = mpsc::channel(2);
        let out = Outbox::new(tx);
        for n in 0..5 {
            out.send(frame(n));
        }
        assert!(out.backlogged());
        let mut got = Vec::new();
        while got.len() < 5 {
            if let Ok(o) = rx.try_recv() {
                got.push(o);
                continue;
            }
            // The channel is empty: the backlog moves into it.
            out.pump();
        }
        assert!(!out.backlogged());
        assert_eq!(got, (0..5).map(frame).collect::<Vec<_>>());
        // Behind a backlog, a new message waits even when room appears.
        let (tx, mut rx) = mpsc::channel(1);
        let out = Outbox::new(tx);
        out.send(frame(0));
        out.send(frame(1));
        assert_eq!(rx.recv().await, Some(frame(0)));
        out.send(frame(2));
        let permit = out.sender();
        out.on_room(permit.reserve().await.unwrap());
        assert_eq!(rx.recv().await, Some(frame(1)));
        assert!(out.pump());
        assert_eq!(rx.recv().await, Some(frame(2)));
    }
}

#[cfg(all(test, feature = "testkit"))]
#[allow(
    clippy::tests_outside_test_module,
    reason = "the lint reads only a bare cfg(test), not cfg(all(test, ..))"
)]
mod tests {
    //! The revocation sequence of design §6.7, one step at a time, on a host
    //! core with a real session and two attached devices.
    use super::*;
    use crate::testkit::{delegation, Client, Device};
    use base64::Engine as _;

    #[derive(Debug)]
    struct Bench {
        core: HostCore,
        out: mpsc::Receiver<Outgoing>,
        pty: mpsc::Receiver<(Uuid, PtyEvent)>,
        root: ed25519_dalek::SigningKey,
        principal: Uuid,
        _dir: tempfile::TempDir,
    }

    fn bench() -> Bench {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        std::fs::create_dir_all(&paths.home).unwrap();
        crate::binding::ensure_machine_key(&paths).unwrap();
        crate::binding::ensure_shell_key(&paths).unwrap();
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let principal = Uuid::from_u128(77);
        let binding = Binding {
            operator: "https://h.example".into(),
            airdress: "h.example".into(),
            machine_id: Uuid::from_u128(5),
            kid: "k".into(),
            principal: crate::binding::Principal {
                id: principal,
                display_name: None,
            },
            root_public_key: Some(crate::binding::b64_std(&root.verifying_key().to_bytes())),
            operator_key: crate::binding::b64_std(&[1; 32]),
            operator_kid: None,
            bound_at: chrono::Utc::now(),
        };
        let profiles = crate::profiles::parse_str(
            "[[profile]]\nid = \"rec\"\nprogram = \"/bin/cat\"\nrecord = true\n",
            &paths,
        )
        .unwrap();
        let (out_tx, out) = mpsc::channel(OUT_QUEUE);
        let (pty_tx, pty) = mpsc::channel(64);
        let core = HostCore::new(
            paths,
            binding,
            profiles,
            out_tx,
            pty_tx,
            HostFacts {
                host_version: "t".into(),
                autostart: "none",
                runs_as_root: false,
            },
            Timings::default(),
        )
        .unwrap();
        Bench {
            core,
            out,
            pty,
            root,
            principal,
            _dir: dir,
        }
    }

    impl Bench {
        fn records(&mut self, leg: Uuid) -> Vec<Vec<u8>> {
            let mut v = Vec::new();
            loop {
                while let Ok(o) = self.out.try_recv() {
                    if let Outgoing::Data { leg: l, record, .. } = o {
                        if l == leg {
                            v.push(record);
                        }
                    }
                }
                if self.core.out.pump() && self.out.is_empty() {
                    break;
                }
            }
            v
        }

        fn connect(&mut self, c: &mut Client, action: Action, deleg: serde_json::Value) -> Uuid {
            let leg = Uuid::new_v4();
            let msg1 = c.begin(action);
            let att: crate::trust::Attestation =
                serde_json::from_value(c.dev.attestation(self.principal, Some(deleg))).unwrap();
            let f = if action == Action::Open {
                OpFrame::Open {
                    session_id: c.session,
                    leg,
                    profile: "rec".into(),
                    cols: Some(80),
                    rows: Some(24),
                    attestation: Box::new(att),
                    handshake: msg1,
                }
            } else {
                OpFrame::Attach {
                    session_id: c.session,
                    leg,
                    attestation: Box::new(att),
                    handshake: Some(msg1),
                    resume: None,
                }
            };
            self.core.on_frame(f);
            let msg2 = self.records(leg).pop().expect("msg2");
            let first = c.finish(&msg2);
            self.core.on_data(c.session, leg, &first);
            for r in self.records(leg) {
                c.receive(&r).expect("a record from the host opens");
            }
            leg
        }
    }

    #[tokio::test]
    async fn a_revocation_cuts_zeroes_rekeys_rotates_rolls_and_tells() {
        let mut b = bench();
        let host_pin = b.core.endpoint.public();
        let cli = Device::cli(1, "laptop");
        let cd = delegation(&b.root, &cli.identity_public(), "h.example", "cli");
        let session = Uuid::new_v4();
        let mut c = Client::new(
            cli,
            host_pin,
            "h.example",
            Uuid::from_u128(5),
            session,
            "rec",
        );
        let cleg = b.connect(&mut c, Action::Open, cd);
        assert!(b.core.sessions.contains_key(&session), "spawned");
        let phone = Device::phone(2, "Galaxy");
        let pd = delegation(&b.root, &phone.identity_public(), "h.example", "phone");
        let pid = phone.id;
        let mut p = Client::new(
            phone,
            host_pin,
            "h.example",
            Uuid::from_u128(5),
            session,
            "rec",
        );
        let pleg = b.connect(&mut p, Action::Attach, pd);
        assert_eq!(b.core.sessions[&session].attached_count(), 2);
        // A typist role to clear: the phone takes input.
        let r = p.send(&[Message::TakeInput]);
        b.core.on_data(session, pleg, &r);
        assert_eq!(b.core.sessions[&session].typist, Some(pid));
        // Some output, spilled, to rotate.
        for _ in 0..200 {
            b.core
                .sessions
                .get_mut(&session)
                .unwrap()
                .journal
                .append(&[b'x'; 32 * 1024])
                .unwrap();
        }
        // The output went straight into the journal: everyone has seen it.
        let end = b.core.sessions[&session].journal.end();
        for cl in b
            .core
            .sessions
            .get_mut(&session)
            .unwrap()
            .clients
            .values_mut()
        {
            cl.sent = end;
            cl.acked = end;
        }
        c.offset = end;
        let spill_before: Vec<Vec<u8>> =
            std::fs::read_dir(b.core.paths.spill_dir().join(session.to_string()))
                .unwrap()
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
        assert!(!spill_before.is_empty());
        let tickets_before = b.core.endpoint.tickets();
        let _ = b.records(cleg);

        let report = b.core.revoke_device(pid);

        // 1. Cut off: its leg is gone, its tickets too, it is in the revoked
        // set, and it no longer holds input.
        assert_eq!(report.cut, vec![(pleg, session)]);
        assert!(report.forgotten);
        assert!(b.core.endpoint.leg(pleg).is_none());
        assert_eq!(b.core.endpoint.tickets(), tickets_before - 1);
        assert!(b.core.store.revoked.contains(&pid));
        assert_eq!(b.core.sessions[&session].typist, None);
        // 2. Every remaining leg rekeyed: the laptop got a `rekey` asking it
        // to rekey back, and keeps decrypting.
        assert_eq!(report.rekeyed, vec![cleg]);
        let recs = b.records(cleg);
        let mut replies = Vec::new();
        for r in &recs {
            replies.extend(c.receive(r).unwrap());
        }
        assert!(c.rekeys_seen >= 1);
        for r in replies {
            b.core.on_data(session, cleg, &r);
        }
        // 3. The spill was re-encrypted under a new key.
        assert_eq!(report.spill_rotated, vec![session]);
        let spill_after: Vec<Vec<u8>> =
            std::fs::read_dir(b.core.paths.spill_dir().join(session.to_string()))
                .unwrap()
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
        assert!(spill_after.iter().all(|f| !spill_before.contains(f)));
        // 4. The recording rolled to a segment wrapped to the laptop only.
        assert_eq!(report.recordings_rolled, vec![session]);
        let seg1 = std::fs::read_dir(b.core.paths.recordings_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .join(format!("{session}.1.cast.enc"));
        let (h, _) =
            airdress_shell_proto::recording::SegmentHeader::parse(&std::fs::read(seg1).unwrap())
                .unwrap();
        let who: Vec<&str> = h.recipients.iter().map(|e| e.device.as_str()).collect();
        assert_eq!(who, [c.dev.id.to_string()]);
        // 5. The rest were told, and the operator's audit got the detach.
        assert_eq!(report.told, vec![session]);
        assert!(
            c.reasons.iter().any(|r| r.contains("signed out")),
            "{:?}",
            c.reasons
        );
        // The session goes on: the laptop types, the program answers.
        let r = c.send(&[
            Message::TakeInput,
            Message::In {
                data: b"after\n".to_vec(),
            },
        ]);
        b.core.on_data(session, cleg, &r);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !c.text().contains("after") {
            let (id, ev) = tokio::time::timeout_at(deadline, b.pty.recv())
                .await
                .unwrap()
                .unwrap();
            b.core.on_pty(id, ev);
            for r in b.records(cleg) {
                c.receive(&r).expect("a record from the host opens");
            }
        }
        let _ = base64::engine::general_purpose::STANDARD.encode([0u8]);
    }

    /// D-24 as it happens on a live fleet: the operator closes the revoked
    /// device's leg first (`detach {reason: device_revoked}`) and only then
    /// sends `revoke_device`, so the host no longer has the device attached
    /// anywhere (`legs=0`). The recording must roll all the same: the
    /// revoked device was a recipient of the running segment whether or not
    /// it was attached, and must not be one of the next.
    #[tokio::test]
    async fn a_revocation_after_the_leg_is_gone_still_rolls_and_rekeys() {
        let mut b = bench();
        let host_pin = b.core.endpoint.public();
        let cli = Device::cli(1, "laptop");
        let cd = delegation(&b.root, &cli.identity_public(), "h.example", "cli");
        let session = Uuid::new_v4();
        let mut c = Client::new(
            cli,
            host_pin,
            "h.example",
            Uuid::from_u128(5),
            session,
            "rec",
        );
        let cleg = b.connect(&mut c, Action::Open, cd);
        let phone = Device::phone(2, "Galaxy");
        let pd = delegation(&b.root, &phone.identity_public(), "h.example", "phone");
        let pid = phone.id;
        let mut p = Client::new(
            phone,
            host_pin,
            "h.example",
            Uuid::from_u128(5),
            session,
            "rec",
        );
        let pleg = b.connect(&mut p, Action::Attach, pd);
        // The phone is a recipient of the running segment 0, only now: the
        // recording started when the laptop alone was known, so roll once to
        // make segment 1 wrapped to both, as a long-running session's is.
        let both = b.core.store.recipients();
        assert_eq!(both.len(), 2);
        b.core
            .sessions
            .get_mut(&session)
            .unwrap()
            .recording
            .as_mut()
            .unwrap()
            .roll(&both)
            .unwrap();
        let _ = b.records(cleg);

        // The operator closes the phone's leg first ...
        b.core.on_frame(OpFrame::Detach {
            session_id: session,
            leg: pleg,
            reason: "device_revoked".into(),
        });
        assert!(!b.core.sessions[&session].clients.contains_key(&pid));
        // ... and then tells the host.
        let report = b.core.revoke_device(pid);

        assert!(
            report.cut.is_empty(),
            "nothing left to cut: {:?}",
            report.cut
        );
        assert!(b.core.store.revoked.contains(&pid));
        // The laptop's leg is rekeyed, and it keeps decrypting.
        assert_eq!(report.rekeyed, vec![cleg]);
        let mut replies = Vec::new();
        for r in &b.records(cleg) {
            replies.extend(c.receive(r).unwrap());
        }
        assert!(c.rekeys_seen >= 1);
        for r in replies {
            b.core.on_data(session, cleg, &r);
        }
        assert_eq!(report.spill_rotated, vec![session]);
        // The recording rolled: segment 2 is the laptop's alone, while
        // segment 1 still names the phone (what it could read before).
        assert_eq!(report.recordings_rolled, vec![session]);
        let day = std::fs::read_dir(b.core.paths.recordings_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let who = |n: u32| -> Vec<String> {
            let (h, _) = airdress_shell_proto::recording::SegmentHeader::parse(
                &std::fs::read(day.join(format!("{session}.{n}.cast.enc"))).unwrap(),
            )
            .unwrap();
            let mut v: Vec<String> = h.recipients.into_iter().map(|e| e.device).collect();
            v.sort();
            v
        };
        let mut was = vec![c.dev.id.to_string(), pid.to_string()];
        was.sort();
        assert_eq!(who(1), was);
        assert_eq!(who(2), [c.dev.id.to_string()]);
        // Not attached here when revoked: nobody is told it was signed out
        // a second time.
        assert!(report.told.is_empty());
    }
}
