//! One attached session: the handshake on a leg, the stream, take-over,
//! detach and close, and resume when the network changes (design §7.3,
//! §10.2, task D.4).
//!
//! The loop is the same for the terminal and for `--json-proto`; only the
//! front differs. It never blocks on the host: input goes up the moment it
//! is typed, output is written the moment it is in order.
//!
//! **Resume (D.4).** A leg that is lost (the network changed, the operator
//! forgot it, the relay's idle cut) is replaced without asking anything:
//!
//! 1. the same leg again, if the operator still has it (in [`super::leg`]);
//! 2. else a new leg with the resume ticket (`IKpsk2`), whose first record
//!    acknowledges the offset this device holds, so the host replays from
//!    exactly there;
//! 3. if the host refuses that ticket, once more with the ticket the last
//!    resume redeemed (the protocol crate's note N-4);
//! 4. else a full reattach (`IK`). On Linux the CLI takes no step-up (D-30),
//!    so even that asks nothing.
//!
//! Output is never repeated or lost across any of these: it is reassembled
//! by offset ([`super::session`]).
//!
//! **Every attempt waits** ([`Backoff`]: doubling from 250 ms to 30 s, with
//! jitter), and **a definitive answer ends the run** instead of starting
//! the ladder again: the session or the host is gone, the host said it is
//! stopping, or the full reattach at the bottom of the ladder was itself
//! refused. Found live on VM3 (2026-10-04): after a host restart the
//! reattach was refused, the client went back to the top with no wait, and
//! two clients made 373 attempts in about 15 s without ever saying the
//! session had ended.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use airdress_shell_proto::inner::Message;
use airdress_shell_proto::prologue::Action;
use airdress_shell_proto::ProtoError;

use crate::log_err::LogErr as _;

use super::api::{ended_because, explain, Refusal, ShellApi};
use super::leg::{Backoff, Leg, LegEvent};
use super::session::{ClientSession, Event};
use super::terminal::{notice, EscapeParser, Key, ESCAPE_HELP};

/// How long to wait for the host's message 2 before treating the leg as
/// lost.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(20);
/// How often unacknowledged output is acknowledged, and a due rekey sent.
const TICK: Duration = Duration::from_millis(200);
/// Give up re-establishing a session after this long without success.
pub const RECONNECT_GIVE_UP: Duration = Duration::from_secs(15 * 60);
/// The first wait before re-establishing a lost leg.
pub const RECONNECT_BASE: Duration = Duration::from_millis(250);
/// The longest wait between two attempts.
pub const RECONNECT_CAP: Duration = Duration::from_secs(30);

/// Leg close reasons that say nothing about the session: the operator or the
/// host's channel went away under the leg. A handshake refused for one of
/// these is tried again; refused for anything else, it is the host's answer.
fn is_transient(reason: &str) -> bool {
    matches!(
        reason,
        "peer_gone" | "shutdown" | "displaced" | "lifetime" | "idle" | "shell_host_offline"
    ) || reason.starts_with("http_5")
}

/// What a person reads when the host stopped under the session.
pub const HOST_STOPPED: &str = "the host stopped, and this session with it";

/// Leg close reasons after which nothing is retried.
fn is_final(reason: &str) -> bool {
    matches!(
        reason,
        "session_ended"
            | "device_revoked"
            | "host_revoked"
            | "shell_host_stopping"
            | "shell_host_disabled"
            | "unlinked"
            | "unauthorized"
            | "not_enabled"
            | "shell_caller_not_eligible"
            | "shell_device_not_introduced"
            | "shell_presence_required"
            | "shell_session_not_found"
    )
}

/// How a session run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The program exited.
    Exited {
        /// Exit code.
        code: Option<i32>,
        /// Signal.
        signal: Option<i32>,
    },
    /// This device detached; the session keeps running.
    Detached,
    /// The session or this device's access to it ended.
    Ended(String),
}

impl Outcome {
    /// The process exit code `airdress shell` returns.
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Exited { code: Some(c), .. } => *c,
            Outcome::Exited {
                signal: Some(s), ..
            } => 128 + s,
            Outcome::Exited { .. } | Outcome::Detached => 0,
            Outcome::Ended(_) => 1,
        }
    }
}

/// Where output goes and how input is read.
pub struct Front {
    /// Stdout.
    out: Box<dyn Write + Send>,
    /// JSON lines on stdio for the editor (`--json-proto`), rather than a
    /// raw terminal (bytes in, bytes out, the escape key).
    json: bool,
    /// The first write that failed. Once output is lost nothing more is
    /// written, and [`run`] ends at its next turn rather than run blind.
    lost: Option<std::io::Error>,
}

impl std::fmt::Debug for Front {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Front")
            .field("json", &self.json)
            .finish_non_exhaustive()
    }
}

impl Front {
    /// A raw terminal: bytes in, bytes out, the escape key.
    pub fn terminal(out: Box<dyn Write + Send>) -> Self {
        Self {
            out,
            json: false,
            lost: None,
        }
    }

    /// JSON lines on stdio for the editor (`--json-proto`).
    pub fn json(out: Box<dyn Write + Send>) -> Self {
        Self {
            out,
            json: true,
            lost: None,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.lost.is_some() {
            return;
        }
        if let Err(e) = self.out.write_all(bytes).and_then(|()| self.out.flush()) {
            self.lost = Some(e);
        }
    }

    fn is_json(&self) -> bool {
        self.json
    }

    /// A failed write, once: the reason this run must stop.
    fn take_lost(&mut self) -> Option<std::io::Error> {
        self.lost.take()
    }

    /// A line for the human (terminal) or a lifecycle event (JSON).
    fn say(&mut self, kind: &str, text: &str, extra: Value) {
        if self.is_json() {
            let mut v = json!({ "type": kind, "message": text });
            if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
                for (k, x) in e {
                    o.insert(k.clone(), x.clone());
                }
            }
            self.write(format!("{v}\n").as_bytes());
        } else {
            self.write(&notice(text));
        }
    }

    fn event(&mut self, ev: &Event) {
        match self.json {
            false => match ev {
                Event::Output(b) => self.write(b),
                // A redraw supersedes the screen: clear it and draw.
                Event::Redraw { data, .. } => {
                    self.write(b"\x1b[H\x1b[2J");
                    self.write(data);
                }
                _ => {}
            },
            true => {
                let v = match ev {
                    Event::Output(b) => json!({"type": "output", "data": STANDARD.encode(b)}),
                    Event::Redraw { cols, rows, data } => json!({
                        "type": "redraw", "cols": cols, "rows": rows, "data": STANDARD.encode(data)
                    }),
                    Event::Roles {
                        typist,
                        viewers,
                        reason,
                    } => {
                        json!({"type": "roles", "typist": typist, "viewers": viewers, "reason": reason})
                    }
                    Event::Exit { code, signal } => {
                        json!({"type": "exit", "code": code, "signal": signal})
                    }
                    Event::HostStopping { in_seconds } => {
                        json!({"type": "host_stopping", "inSeconds": in_seconds})
                    }
                    Event::Error { code, message } => {
                        json!({"type": "error", "code": code, "message": message})
                    }
                    Event::RecordingListing(r) => {
                        json!({"type": "recording_listing", "recordings": r})
                    }
                    Event::RecordingHeader {
                        recording,
                        segment,
                        header,
                    } => json!({"type": "recording_header", "recording": recording,
                                "segment": segment, "header": STANDARD.encode(header)}),
                    Event::RecordingChunk {
                        segment,
                        index,
                        sealed,
                    } => json!({"type": "recording_chunk", "segment": segment, "index": index,
                                "sealed": STANDARD.encode(sealed)}),
                    Event::Structured(body) => json!({"type": "structured", "body": body}),
                };
                self.write(format!("{v}\n").as_bytes());
            }
        }
    }
}

/// What the person (or the editor) asked for.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Bytes for the program.
    Input(Vec<u8>),
    /// A new window size.
    Resize(u16, u16),
    /// Take input on this device.
    TakeInput,
    /// Detach.
    Detach,
    /// Close the session (already confirmed).
    Close,
    /// Any other inner message (editor only; never `presence` or `rekey`).
    Message(Message),
}

/// Turn one `--json-proto` input line into a command.
pub fn json_command(line: &str) -> Result<Command> {
    let v: Value = serde_json::from_str(line).map_err(|e| anyhow!("not JSON: {e}"))?;
    match v["type"].as_str().unwrap_or_default() {
        "detach" => return Ok(Command::Detach),
        "close" => return Ok(Command::Close),
        _ => {}
    }
    let m: Message = serde_json::from_value(v).map_err(|e| anyhow!("not an inner message: {e}"))?;
    Ok(match m {
        Message::In { data } => Command::Input(data),
        Message::Resize { cols, rows } => Command::Resize(cols, rows),
        Message::TakeInput => Command::TakeInput,
        Message::Presence { .. }
        | Message::Rekey { .. }
        | Message::Ack { .. }
        | Message::Credit { .. } => {
            return Err(anyhow!("that message is the CLI's own to send"));
        }
        other => Command::Message(other),
    })
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Closed,
    Other,
}

/// How the run loop re-establishes a lost leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Resume,
    Fallback,
    Reattach,
}

/// The connection to one session.
pub struct Conn {
    /// The operator.
    pub api: ShellApi,
    /// The `ShellHost` name.
    pub host: String,
    /// The end-to-end state.
    pub cs: ClientSession,
    /// The live leg.
    pub leg: Option<Leg>,
    /// The window size at the last open, attach or resize.
    pub size: (u16, u16),
    /// Whether this device should hold input (re-taken after a reattach).
    pub wants_input: bool,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("host", &self.host)
            .field("size", &self.size)
            .field("wants_input", &self.wants_input)
            .finish_non_exhaustive()
    }
}

fn now_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

fn refusal_code(e: &anyhow::Error) -> Option<String> {
    e.downcast_ref::<Refusal>().map(|r| r.code.clone())
}

fn refusal_of(e: &anyhow::Error) -> Option<&Refusal> {
    e.downcast_ref::<Refusal>()
}

impl Conn {
    /// Open a new session of `profile`: propose a session id, send message
    /// 1, and connect the leg. The handshake completes in the loop.
    pub async fn open(
        api: ShellApi,
        host: &str,
        mut cs: ClientSession,
        size: (u16, u16),
    ) -> Result<Self> {
        let msg1 = cs.begin(Action::Open, size.0, size.1)?;
        let profile = cs.target().profile.clone();
        let opened = api
            .open(host, cs.session(), &profile, size.0, size.1, &msg1)
            .await?;
        if opened.session != cs.session() {
            return Err(anyhow!(
                "the operator gave the session another id ({}) than the one this device's \
                 handshake binds ({}); this operator does not take a proposed session id yet",
                opened.session,
                cs.session()
            ));
        }
        let leg = Leg::connect(&api, &opened.leg);
        Ok(Self {
            api,
            host: host.to_owned(),
            cs,
            leg: Some(leg),
            size,
            wants_input: true,
        })
    }

    /// Attach to a running session with a full handshake.
    pub async fn attach(
        api: ShellApi,
        host: &str,
        mut cs: ClientSession,
        size: (u16, u16),
        take_input: bool,
    ) -> Result<Self> {
        let msg1 = cs.begin(Action::Attach, size.0, size.1)?;
        let leg = api.attach(cs.session(), &msg1).await?;
        let leg = Leg::connect(&api, &leg);
        Ok(Self {
            api,
            host: host.to_owned(),
            cs,
            leg: Some(leg),
            size,
            wants_input: take_input,
        })
    }

    /// One attempt at a new leg in `mode`.
    async fn re_establish(&mut self, mode: Mode) -> Result<()> {
        let session = self.cs.session().to_owned();
        let leg = match mode {
            Mode::Resume | Mode::Fallback => {
                let (ticket, msg1) = if mode == Mode::Resume {
                    self.cs.begin_resume()?
                } else {
                    self.cs.fallback_resume()?
                };
                self.api.resume(&session, &ticket.encode(), &msg1).await?
            }
            Mode::Reattach => {
                let msg1 = self.cs.begin(Action::Attach, self.size.0, self.size.1)?;
                self.api.attach(&session, &msg1).await?
            }
        };
        self.leg = Some(Leg::connect(&self.api, &leg));
        Ok(())
    }

    async fn send(&mut self, msgs: &[Message], epoch: Instant) -> Result<()> {
        if !self.cs.is_live() || self.leg.is_none() {
            return Err(anyhow!("not connected"));
        }
        let rec = self.cs.seal(msgs, now_ms(epoch))?;
        if let Some(leg) = &self.leg {
            leg.send(rec).await;
        }
        Ok(())
    }
}

/// The channel just became live: say so, and take input back if this
/// device wants it.
async fn became_live(
    conn: &mut Conn,
    front: &mut Front,
    first: &mut bool,
    told_offline: &mut bool,
    typist: Option<&str>,
    me: &str,
    epoch: Instant,
) {
    if *first {
        *first = false;
        front.say(
            "connected",
            &format!(
                "connected to {} (session {}) — {ESCAPE_HELP}",
                conn.host,
                conn.cs.session()
            ),
            json!({"host": conn.host, "session": conn.cs.session()}),
        );
    } else if *told_offline {
        front.say(
            "reconnected",
            "reconnected",
            json!({"host": conn.host, "session": conn.cs.session()}),
        );
    }
    *told_offline = false;
    if conn.wants_input && typist != Some(me) {
        if let Some(l) = &conn.leg {
            conn.api
                .take_input(conn.cs.session(), &l.id)
                .await
                .log_warn("taking input back");
        }
        conn.send(&[Message::TakeInput], epoch)
            .await
            .log_debug("asking the host for input");
    }
}

/// Run the session until it exits, this device detaches, or it ends.
pub async fn run(
    mut conn: Conn,
    front: &mut Front,
    mut commands: mpsc::Receiver<Command>,
) -> Result<Outcome> {
    let epoch = Instant::now();
    let me = conn.cs.target().device.clone();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut leg_since = Instant::now();
    // Re-establishing: the mode to try next, when, and since when.
    let mut retry: Option<(Mode, Instant)> = None;
    let mut lost_since: Option<Instant> = None;
    let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_CAP);
    let mut typist: Option<String> = None;
    let mut told_offline = false;
    let mut first = true;
    // The handshake on the current leg, when this loop started it.
    let mut inflight: Option<Mode> = None;
    // The host said it is stopping: whatever ends the leg next ends the run.
    let mut host_stopping = false;

    loop {
        // Output that cannot be written is a session nobody can see. Stop
        // this device here; the session keeps running on the host, as on a
        // detach, and the error says why.
        if let Some(e) = front.take_lost() {
            tracing::warn!(error = %e, "the session's output could not be written; stopping");
            return Err(anyhow::Error::new(e).context(
                "writing the session's output failed; this device stopped, and the session keeps \
                 running on the host",
            ));
        }
        // A due attempt runs before anything else is awaited.
        if let Some((mode, at)) = retry {
            if Instant::now() >= at {
                retry = None;
                match conn.re_establish(mode).await {
                    Ok(()) => {
                        leg_since = Instant::now();
                        inflight = Some(mode);
                    }
                    Err(e) => {
                        let code = refusal_code(&e);
                        // `410 shell_session_ended {reason}`: over, and why.
                        if code.as_deref() == Some("shell_session_ended") {
                            let reason = refusal_of(&e).and_then(|r| r.reason.as_deref());
                            return Ok(Outcome::Ended(ended_because(reason)));
                        }
                        let gone = matches!(
                            code.as_deref(),
                            Some("shell_session_not_found" | "shell_host_not_found")
                        ) || e
                            .downcast_ref::<ProtoError>()
                            .is_some_and(|p| *p == ProtoError::ResumeExpired)
                            && mode == Mode::Reattach;
                        if gone {
                            return Ok(Outcome::Ended("the session has ended".into()));
                        }
                        if let Some(c) = code.as_deref().filter(|c| is_final(c)) {
                            return Ok(Outcome::Ended(explain(c, "")));
                        }
                        // No ticket left: straight to a reattach.
                        let next = match (mode, e.downcast_ref::<ProtoError>()) {
                            (Mode::Resume, Some(ProtoError::ResumeExpired)) => Mode::Fallback,
                            (Mode::Fallback, Some(ProtoError::ResumeExpired)) => Mode::Reattach,
                            _ => mode,
                        };
                        if lost_since.is_some_and(|t| t.elapsed() > RECONNECT_GIVE_UP) {
                            return Ok(Outcome::Ended(format!(
                                "could not reach the session again: {e:#}"
                            )));
                        }
                        // `429 shell_reconnect_throttled`: the operator says
                        // how long; never sooner than that, nor than the
                        // backoff.
                        let wait = match refusal_of(&e) {
                            Some(r) if r.code == "shell_reconnect_throttled" => {
                                backoff.wait().max(r.retry_after.unwrap_or(RECONNECT_CAP))
                            }
                            _ => backoff.wait(),
                        };
                        retry = Some((next, Instant::now() + wait));
                        continue;
                    }
                }
            }
        }

        let retry_at = retry.map(|(_, at)| tokio::time::Instant::from_std(at));
        let leg_event = async {
            match conn.leg.as_mut() {
                Some(l) => l.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            // cancel-safe: `Leg::recv` is `mpsc::Receiver::recv`; the leg's
            // reader task owns any partly read event.
            ev = leg_event => {
                let ev = ev.unwrap_or_else(|| LegEvent::Lost("leg ended".into()));
                let ev_kind = if matches!(ev, LegEvent::Closed { .. }) { Kind::Closed } else { Kind::Other };
                match ev {
                    LegEvent::Record(rec) => {
                        let now = now_ms(epoch);
                        let was_live = conn.cs.is_live();
                        if conn.cs.awaiting_msg2() {
                            match conn.cs.finish(&rec, now) {
                                Ok((_, out)) => {
                                    for r in out {
                                        if let Some(l) = &conn.leg { l.send(r).await; }
                                    }
                                    lost_since = None;
                                    backoff.reset();
                                    inflight = None;
                                }
                                Err(e) => return Ok(Outcome::Ended(format!(
                                    "the end-to-end handshake with {} failed: {e}", conn.host))),
                            }
                            // A resume is live at its message 2: the host may
                            // have nothing new to say (an idle session).
                            if !was_live && conn.cs.is_live() {
                                became_live(&mut conn, front, &mut first, &mut told_offline, typist.as_deref(), &me, epoch).await;
                            }
                            continue;
                        }
                        let (events, replies) = match conn.cs.receive(&rec, now) {
                            Ok(x) => x,
                            // A duplicate or a replay after a reconnect: drop it.
                            Err(ProtoError::Replay | ProtoError::RecordAuth) => continue,
                            Err(e) => return Ok(Outcome::Ended(format!("the host sent something unreadable: {e}"))),
                        };
                        for r in replies {
                            if let Some(l) = &conn.leg { l.send(r).await; }
                        }
                        if !was_live && conn.cs.is_live() {
                            became_live(&mut conn, front, &mut first, &mut told_offline, typist.as_deref(), &me, epoch).await;
                        }
                        for ev in &events {
                            match ev {
                                Event::Exit { code, signal } => {
                                    front.event(ev);
                                    // The host hung the program up because it is
                                    // stopping: that is what ended it, not the
                                    // program.
                                    if host_stopping {
                                        conn.cs.forget();
                                        return Ok(Outcome::Ended(HOST_STOPPED.into()));
                                    }
                                    return Ok(Outcome::Exited { code: *code, signal: *signal });
                                }
                                Event::Roles { typist: t, viewers, reason } => {
                                    let had = typist.as_deref() == Some(me.as_str());
                                    typist = t.clone();
                                    let has = typist.as_deref() == Some(me.as_str());
                                    if front.is_json() {
                                        front.event(ev);
                                    } else if had && !has {
                                        conn.wants_input = false;
                                        let who = viewers.iter().find(|v| Some(&v.client) == t.as_ref())
                                            .map(|v| v.label.clone())
                                            .or_else(|| t.clone())
                                            .unwrap_or_else(|| "nobody".into());
                                        front.say("roles", &format!("Input moved to {who}. Ctrl-] i takes it back."), json!({}));
                                    } else if has && !had && reason != "opened" {
                                        front.say("roles", "You have input.", json!({}));
                                    }
                                }
                                Event::HostStopping { in_seconds } => {
                                    host_stopping = true;
                                    front.say("host_stopping",
                                        &format!("the host is stopping; this session ends with it (within {in_seconds} s)"),
                                        json!({"inSeconds": in_seconds}));
                                }
                                Event::Error { code, message } => {
                                    if front.is_json() { front.event(ev); }
                                    else { front.say("error", &explain(code, message), json!({})); }
                                }
                                other => front.event(other),
                            }
                        }
                    }
                    // The host said it is stopping: the leg going is the
                    // session ending, whatever the operator calls it.
                    LegEvent::Closed { .. } | LegEvent::Lost(_) if host_stopping => {
                        conn.cs.forget();
                        return Ok(Outcome::Ended(HOST_STOPPED.into()));
                    }
                    LegEvent::Closed { reason, .. } if is_final(&reason) => {
                        conn.cs.forget();
                        return Ok(Outcome::Ended(explain(&reason, "")));
                    }
                    LegEvent::Closed { reason, .. } | LegEvent::Lost(reason) => {
                        // A close while message 2 is awaited is the host's
                        // refusal of that handshake. A loss is the network:
                        // the ticket being redeemed is still good, because
                        // the host spends it only once it hears from this
                        // device on the new leg (protocol note N-4).
                        let refused = matches!(ev_kind, Kind::Closed)
                            && conn.cs.awaiting_msg2()
                            && !is_transient(&reason);
                        // A full handshake refused (the first open or attach,
                        // or the reattach at the bottom of the ladder) leaves
                        // nothing to try: the host has answered.
                        let full = first || inflight == Some(Mode::Reattach) || !conn.cs.can_resume();
                        conn.leg = None;
                        inflight = None;
                        if refused && (full || reason == "shell_handshake_failed") {
                            conn.cs.forget();
                            return Ok(Outcome::Ended(match reason.as_str() {
                                "shell_resume_expired" | "session_ended" | "shell_session_not_found" => {
                                    "the session has ended".to_owned()
                                }
                                r if is_final(r) => explain(r, ""),
                                r => format!("the host refused this device: {}", explain(r, "")),
                            }));
                        }
                        let mode = match refused {
                            true => Mode::Fallback,
                            false if conn.cs.can_resume() => Mode::Resume,
                            false => Mode::Reattach,
                        };
                        if lost_since.is_none() {
                            lost_since = Some(Instant::now());
                        }
                        if lost_since.is_some_and(|t| t.elapsed() > RECONNECT_GIVE_UP) {
                            return Ok(Outcome::Ended(format!(
                                "could not reach the session again: {}", explain(&reason, ""))));
                        }
                        if !told_offline && !refused {
                            told_offline = true;
                            front.say("reconnecting", "connection lost; reconnecting…", json!({"reason": reason}));
                        }
                        retry = Some((mode, Instant::now() + backoff.wait()));
                    }
                }
            }
            // cancel-safe: `mpsc::Receiver::recv`.
            cmd = commands.recv() => {
                let Some(cmd) = cmd else {
                    return Ok(Outcome::Detached);
                };
                match cmd {
                    Command::Input(data) => {
                        if conn.send(&[Message::In { data }], epoch).await.is_err() && !front.is_json() {
                            front.say("dropped", "not connected; that input was not sent", json!({}));
                        }
                    }
                    Command::Resize(c, r) => {
                        conn.size = (c, r);
                        // Not live: the size is sent again when it is.
                        conn.send(&[Message::Resize { cols: c, rows: r }], epoch)
                            .await
                            .log_debug("sending the terminal size");
                    }
                    Command::TakeInput => {
                        conn.wants_input = true;
                        if let Some(l) = &conn.leg {
                            if let Err(e) = conn.api.take_input(conn.cs.session(), &l.id).await {
                                front.say("error", &format!("{e:#}"), json!({}));
                            }
                        }
                        // Not live: `wants_input` and the size are sent again when it is.
                        conn.send(&[Message::TakeInput], epoch)
                            .await
                            .log_debug("asking the host for input");
                        let (c, r) = conn.size;
                        conn.send(&[Message::Resize { cols: c, rows: r }], epoch)
                            .await
                            .log_debug("sending the terminal size");
                    }
                    Command::Detach => return Ok(Outcome::Detached),
                    Command::Close => {
                        conn.api.close(conn.cs.session()).await?;
                        return Ok(Outcome::Ended("closed".into()));
                    }
                    Command::Message(m) => {
                        if let Err(e) = conn.send(&[m], epoch).await {
                            front.say("dropped", &format!("not sent: {e:#}"), json!({}));
                        }
                    }
                }
            }
            // cancel-safe: `Interval::tick` (tokio's list).
            _ = tick.tick() => {
                let now = now_ms(epoch);
                if conn.cs.is_live() {
                    if conn.cs.unacked() {
                        // Not live: the next tick acknowledges instead.
                        conn.send(&[Message::Ack { offset: conn.cs.delivered() }], epoch)
                            .await
                            .log_debug("acknowledging output");
                    }
                    if let Ok(Some(r)) = conn.cs.rekey_if_due(now) {
                        if let Some(l) = &conn.leg { l.send(r).await; }
                    }
                } else if conn.leg.is_some() && conn.cs.awaiting_msg2() && leg_since.elapsed() > HANDSHAKE_WAIT {
                    conn.leg = None;
                    inflight = None;
                    let mode = if conn.cs.can_resume() { Mode::Fallback } else { Mode::Reattach };
                    if first {
                        return Ok(Outcome::Ended(format!(
                            "{} did not answer the handshake within {} s", conn.host, HANDSHAKE_WAIT.as_secs())));
                    }
                    lost_since.get_or_insert_with(Instant::now);
                    retry = Some((mode, Instant::now() + backoff.wait()));
                }
            }
            // cancel-safe: a sleep, made afresh from `retry` each pass.
            _ = async { match retry_at { Some(t) => tokio::time::sleep_until(t).await, None => std::future::pending().await } } => {}
        }
    }
}

/// Read the terminal into commands: the escape key, and `Ctrl-] q` asks
/// before it closes. Runs on a thread: a blocking read must not hold the
/// runtime at exit.
pub fn spawn_terminal_reader(tx: mpsc::Sender<Command>) {
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut parser = EscapeParser::default();
        let mut confirming = false;
        let mut buf = [0u8; 4096];
        loop {
            let n = match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    // Closed: the run has already ended.
                    tx.blocking_send(Command::Detach)
                        .log_debug("detaching at the end of input");
                    return;
                }
                Ok(n) => n,
            };
            if confirming {
                confirming = false;
                let yes = matches!(buf[0], b'y' | b'Y');
                if !show_or_detach(&tx, &notice(if yes { "closing" } else { "not closed" })) {
                    return;
                }
                if yes && tx.blocking_send(Command::Close).is_err() {
                    return;
                }
                continue;
            }
            for key in parser.feed(&buf[..n]) {
                let cmd = match key {
                    Key::Input(b) => Command::Input(b),
                    Key::Detach => Command::Detach,
                    Key::TakeInput => Command::TakeInput,
                    Key::Close => {
                        confirming = true;
                        if !show_or_detach(
                            &tx,
                            &notice("Close this session? Its program is ended. [y/N]"),
                        ) {
                            return;
                        }
                        continue;
                    }
                    Key::Help => {
                        if !show_or_detach(&tx, &notice(ESCAPE_HELP)) {
                            return;
                        }
                        continue;
                    }
                };
                if tx.blocking_send(cmd).is_err() {
                    return;
                }
            }
        }
    });
}

fn show(bytes: &[u8]) -> std::io::Result<()> {
    let mut o = std::io::stdout().lock();
    o.write_all(bytes)?;
    o.flush()
}

/// Show a notice from the reader thread. When stdout is gone, ask the run
/// to detach and say so with `false`: the reader stops, and the session
/// keeps running on the host.
fn show_or_detach(tx: &mpsc::Sender<Command>, bytes: &[u8]) -> bool {
    match show(bytes) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "the terminal's output could not be written; detaching");
            if tx.blocking_send(Command::Detach).is_err() {
                tracing::debug!("the session had already ended");
            }
            false
        }
    }
}

/// Read `--json-proto` lines into commands, on a thread.
pub fn spawn_json_reader(tx: mpsc::Sender<Command>, errors: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            match json_command(&line) {
                Ok(c) => {
                    if tx.blocking_send(c).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    // Waits while the reports are not being written: this
                    // thread then reads no further (R-ASY-5).
                    if errors.blocking_send(e.to_string()).is_err() {
                        return;
                    }
                }
            }
        }
        // Closed: the run has already ended.
        tx.blocking_send(Command::Detach)
            .log_debug("detaching at the end of input");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_lost_stdout_is_kept_until_the_run_reads_it() {
        let mut front = Front::terminal(Box::new(Broken));
        front.write(b"one");
        front.write(b"two");
        let e = front.take_lost().expect("the failed write is kept");
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
        // Nothing more is written once output is lost.
        assert!(front.take_lost().is_none());
    }

    #[test]
    fn json_commands_take_the_inner_forms_and_refuse_what_the_cli_sends_itself() {
        assert_eq!(
            json_command(r#"{"type":"in","data":"aGk="}"#).unwrap(),
            Command::Input(b"hi".to_vec())
        );
        assert_eq!(
            json_command(r#"{"type":"resize","cols":100,"rows":30}"#).unwrap(),
            Command::Resize(100, 30)
        );
        assert_eq!(
            json_command(r#"{"type":"detach"}"#).unwrap(),
            Command::Detach
        );
        assert!(json_command(r#"{"type":"presence","action":"open","alg":"none"}"#).is_err());
        assert!(json_command(r#"{"type":"rekey","switch_at":1,"request":false}"#).is_err());
        assert!(json_command("nope").is_err());
    }

    #[test]
    fn exit_codes() {
        assert_eq!(
            Outcome::Exited {
                code: Some(3),
                signal: None
            }
            .exit_code(),
            3
        );
        assert_eq!(
            Outcome::Exited {
                code: None,
                signal: Some(9)
            }
            .exit_code(),
            137
        );
        assert_eq!(Outcome::Detached.exit_code(), 0);
        assert_eq!(Outcome::Ended("x".into()).exit_code(), 1);
    }
}
