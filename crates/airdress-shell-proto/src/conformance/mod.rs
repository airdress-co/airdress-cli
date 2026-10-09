//! The conformance kit (design §14.2–14.3): a reference host and client
//! in-process, the scripted conversation driver, the fault model, and the
//! vector generator.
//!
//! The reference host is not the shell host (`airdress-shell-host` owns the
//! PTY, the profiles and the operator channel); it is the smallest host that
//! speaks the whole E2E protocol, so the protocol can be driven end to end
//! before, and independently of, the real one. Its "PTY" is a byte journal:
//! output is appended by the script, input is collected for assertions.
//!
//! Built only with the `conformance` feature.

pub mod generate;
pub mod script;
pub mod world;

use std::collections::{BTreeMap, HashMap, HashSet};

use ed25519_dalek::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

use crate::error::{ProtoError, Result};
use crate::handshake::{
    ticket_from_hello, Channel, DeviceHello, HostHello, InitiatorHandshake, ResponderHandshake,
};
use crate::inner::{seal_rekey, Message, Viewer};
use crate::keys::ShellKeypair;
use crate::presence::{
    admit, presence_message, presence_rule, DeviceKeys, PresenceAlg, PresenceRequirement,
};
use crate::prologue::{Action, Prologue};
use crate::ticket::{TicketBook, TicketId};
use crate::vectors::DetRng;

/// A record for a device, from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The session.
    pub session: String,
    /// The device.
    pub device: String,
    /// The record.
    pub record: Vec<u8>,
}

enum LegState {
    AwaitPresence(Action, PresenceRequirement),
    AwaitConfirm,
    Live,
}

struct Leg {
    ch: Channel,
    state: LegState,
    sent: u64,
    ticket: TicketId,
}

struct Session {
    profile: String,
    journal: Vec<u8>,
    legs: HashMap<String, Leg>,
    typist: Option<String>,
    input: Vec<u8>,
    spawned: bool,
    ended: bool,
}

struct Trusted {
    keys: DeviceKeys,
    kind: String,
    label: String,
}

/// The reference host.
pub struct RefHost {
    keys: ShellKeypair,
    airdress: String,
    machine: String,
    principal: String,
    devices: HashMap<String, Trusted>,
    revoked: HashSet<String>,
    sessions: HashMap<String, Session>,
    tickets: TicketBook,
    rng: DetRng,
    /// Every unlock the host verified, as (device, action).
    pub unlocks_verified: Vec<(String, Action)>,
}

impl std::fmt::Debug for RefHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefHost").finish_non_exhaustive()
    }
}

impl RefHost {
    /// A host for `principal` on `machine`.
    pub fn new(seed: &[u8], airdress: &str, machine: &str, principal: &str) -> Self {
        let mut rng = DetRng::new(seed);
        Self {
            keys: ShellKeypair::generate(&mut rng),
            airdress: airdress.into(),
            machine: machine.into(),
            principal: principal.into(),
            devices: HashMap::new(),
            revoked: HashSet::new(),
            sessions: HashMap::new(),
            tickets: TicketBook::new(),
            rng,
            unlocks_verified: Vec::new(),
        }
    }

    /// The host's shell key, as a client pins it.
    pub fn public(&self) -> [u8; 32] {
        *self.keys.public()
    }

    /// Admit a device's key statement, with the kind the host verified from
    /// its delegation or introduction (design §6.3 steps 2–6).
    pub fn trust(&mut self, keys: &DeviceKeys, sig: &[u8], kind: &str, label: &str) -> Result<()> {
        keys.verify(sig)?;
        if keys.principal != self.principal {
            return Err(ProtoError::Handshake("another principal"));
        }
        presence_rule(keys, kind)?;
        self.devices.insert(
            keys.device.clone(),
            Trusted {
                keys: keys.clone(),
                kind: kind.into(),
                label: label.into(),
            },
        );
        Ok(())
    }

    fn prologue(&self, session: &str, profile: &str, action: Action) -> Prologue {
        Prologue {
            airdress: self.airdress.clone(),
            machine_id: self.machine.clone(),
            session_id: session.into(),
            profile_id: profile.into(),
            action,
        }
    }

    fn device(&self, device: &str) -> Result<&Trusted> {
        if self.revoked.contains(device) {
            return Err(ProtoError::Handshake("device revoked"));
        }
        self.devices
            .get(device)
            .ok_or(ProtoError::Handshake("device not introduced"))
    }

    #[allow(clippy::too_many_arguments)]
    fn handshake(
        &mut self,
        session: &str,
        profile: &str,
        device: &str,
        action: Action,
        psk: Option<&[u8; 32]>,
        msg1: &[u8],
        now_ms: u64,
    ) -> Result<(Leg, Vec<u8>)> {
        let t = self.device(device)?;
        let req = presence_rule(&t.keys, &t.kind)?;
        let dh = t.keys.dh_public;
        let pro = self.prologue(session, profile, action);
        let (rsp, hello) =
            ResponderHandshake::read(&mut self.rng, &self.keys, &pro, &dh, psk, msg1)?;
        if hello.device != device {
            return Err(ProtoError::Handshake("hello names another device"));
        }
        let (ch, ticket, msg2) = rsp.respond(
            &mut self.rng,
            HostHello {
                host_version: Some("reference".into()),
                profile_hash: None,
                resume_ticket: String::new(),
            },
            now_ms,
        )?;
        self.tickets
            .issue(ticket, ch.resume_secret(), session, device);
        let state = match action {
            Action::Resume => LegState::AwaitConfirm,
            a => LegState::AwaitPresence(a, req),
        };
        Ok((
            Leg {
                ch,
                state,
                sent: 0,
                ticket,
            },
            msg2,
        ))
    }

    /// An `open` frame. The session is created but nothing is spawned until
    /// the device's presence record arrives.
    pub fn open(
        &mut self,
        session: &str,
        profile: &str,
        device: &str,
        msg1: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        if self.sessions.contains_key(session) {
            return Err(ProtoError::InvalidInput("session exists"));
        }
        let (leg, msg2) =
            self.handshake(session, profile, device, Action::Open, None, msg1, now_ms)?;
        let mut legs = HashMap::new();
        legs.insert(device.to_owned(), leg);
        self.sessions.insert(
            session.into(),
            Session {
                profile: profile.into(),
                journal: Vec::new(),
                legs,
                typist: None,
                input: Vec::new(),
                spawned: false,
                ended: false,
            },
        );
        Ok(msg2)
    }

    fn live_session(&self, session: &str) -> Result<&Session> {
        match self.sessions.get(session) {
            Some(s) if s.spawned && !s.ended => Ok(s),
            _ => Err(ProtoError::InvalidInput("no such session")),
        }
    }

    /// An `attach` frame with a full handshake (a reattach).
    pub fn attach(
        &mut self,
        session: &str,
        device: &str,
        msg1: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let profile = self.live_session(session)?.profile.clone();
        self.tickets.detach(session, device);
        let (leg, msg2) = self.handshake(
            session,
            &profile,
            device,
            Action::Attach,
            None,
            msg1,
            now_ms,
        )?;
        self.sessions
            .get_mut(session)
            .expect("checked")
            .legs
            .insert(device.into(), leg);
        Ok(msg2)
    }

    /// An `attach` frame with `resume {ticketId, handshake}`.
    pub fn resume(
        &mut self,
        session: &str,
        device: &str,
        ticket: &TicketId,
        msg1: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let profile = self.live_session(session)?.profile.clone();
        self.device(device)?;
        let psk = self.tickets.redeem(ticket, session, device, now_ms)?;
        let (leg, msg2) = self.handshake(
            session,
            &profile,
            device,
            Action::Resume,
            Some(&psk),
            msg1,
            now_ms,
        )?;
        self.sessions
            .get_mut(session)
            .expect("checked")
            .legs
            .insert(device.into(), leg);
        Ok(msg2)
    }

    /// The leg of `device` on `session` was lost; its ticket's clock starts.
    pub fn leg_dropped(&mut self, session: &str, device: &str, now_ms: u64) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.legs.remove(device);
        }
        self.tickets.leg_dropped(session, device, now_ms);
    }

    /// The device detached for good (closed, or backgrounded past grace).
    pub fn detach(&mut self, session: &str, device: &str) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.legs.remove(device);
        }
        self.tickets.detach(session, device);
    }

    fn roles(s: &Session, devices: &HashMap<String, Trusted>, reason: &str) -> Message {
        let mut viewers: Vec<Viewer> = s
            .legs
            .iter()
            .filter(|(_, l)| matches!(l.state, LegState::Live))
            .map(|(d, _)| Viewer {
                client: d.clone(),
                label: devices.get(d).map(|t| t.label.clone()).unwrap_or_default(),
            })
            .collect();
        viewers.sort_by(|a, b| a.client.cmp(&b.client));
        Message::Roles {
            typist: s.typist.clone(),
            viewers,
            reason: reason.into(),
        }
    }

    fn send(
        out: &mut Vec<Outbound>,
        session: &str,
        device: &str,
        leg: &mut Leg,
        msgs: &[Message],
        now_ms: u64,
    ) -> Result<()> {
        let pt = Message::encode_all(msgs)?;
        out.push(Outbound {
            session: session.into(),
            device: device.into(),
            record: leg.ch.seal(&pt, now_ms)?,
        });
        Ok(())
    }

    fn broadcast_roles(
        &mut self,
        session: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let s = self.sessions.get_mut(session).expect("caller checked");
        let msg = Self::roles(s, &self.devices, reason);
        for (d, leg) in s.legs.iter_mut() {
            if matches!(leg.state, LegState::Live) {
                Self::send(
                    &mut out,
                    session,
                    d,
                    leg,
                    std::slice::from_ref(&msg),
                    now_ms,
                )?;
            }
        }
        Ok(out)
    }

    /// A record from a device. Returns what the host sends in reply.
    pub fn record(
        &mut self,
        session: &str,
        device: &str,
        record: &[u8],
        now_ms: u64,
    ) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let Some(s) = self.sessions.get_mut(session) else {
            return Err(ProtoError::InvalidInput("no such session"));
        };
        let Some(leg) = s.legs.get_mut(device) else {
            return Err(ProtoError::InvalidInput("no leg"));
        };
        let (_, pt) = leg.ch.open(record)?;
        let msgs = Message::decode_all(&pt)?;
        let mut msgs = msgs.into_iter();
        let mut reason: Option<&str> = None;

        match std::mem::replace(&mut leg.state, LegState::Live) {
            LegState::AwaitPresence(expected, req) => {
                let first = msgs.next();
                let Some(Message::Presence { action, alg, sig }) = first else {
                    s.legs.remove(device);
                    return Err(ProtoError::PresenceRequired("first record is not presence"));
                };
                if let Err(e) = admit(
                    &req,
                    leg.ch.handshake_hash(),
                    expected,
                    action,
                    alg,
                    sig.as_deref(),
                ) {
                    s.legs.remove(device);
                    return Err(e);
                }
                if alg == PresenceAlg::P256 {
                    self.unlocks_verified.push((device.into(), action));
                }
                self.tickets.admit(&leg.ticket);
                // Every check has passed: only now is anything spawned.
                if expected == Action::Open {
                    s.spawned = true;
                    s.typist = Some(device.into());
                    reason = Some("opened");
                } else {
                    reason = Some("attached");
                }
                let snapshot = Message::Snapshot {
                    offset: s.journal.len() as u64,
                    cols: 80,
                    rows: 24,
                    data: s.journal.clone(),
                };
                leg.sent = s.journal.len() as u64;
                Self::send(&mut out, session, device, leg, &[snapshot], now_ms)?;
            }
            LegState::AwaitConfirm => {
                // The first record under the resumed keys is the device's
                // proof that it held the ticket's secret: only now does the
                // old ticket die and the new one count.
                self.tickets.admit(&leg.ticket);
            }
            LegState::Live => {}
        }

        for m in msgs {
            let s = self.sessions.get_mut(session).expect("present");
            let leg = s.legs.get_mut(device).expect("present");
            match m {
                Message::In { data } => {
                    if s.typist.as_deref() == Some(device) {
                        s.input.extend_from_slice(&data);
                    } else {
                        Self::send(
                            &mut out,
                            session,
                            device,
                            leg,
                            &[Message::Error {
                                code: "shell_input_not_held".into(),
                                message: "Input is on another device".into(),
                            }],
                            now_ms,
                        )?;
                    }
                }
                Message::Ack { offset } => {
                    // Resend from what the client has: the journal holds it all.
                    let len = s.journal.len() as u64;
                    if offset < len {
                        let data = s.journal[offset as usize..].to_vec();
                        Self::send(
                            &mut out,
                            session,
                            device,
                            leg,
                            &[Message::Out { offset, data }],
                            now_ms,
                        )?;
                    }
                    leg.sent = len;
                }
                Message::TakeInput => {
                    s.typist = Some(device.into());
                    reason = Some("input moved");
                }
                Message::Rekey { switch_at, request } => {
                    leg.ch.note_peer_rekey(switch_at);
                    if request {
                        out.push(Outbound {
                            session: session.into(),
                            device: device.into(),
                            record: seal_rekey(&mut leg.ch, false, now_ms)?,
                        });
                    }
                }
                Message::Presence { .. } => {
                    return Err(ProtoError::PresenceRequired("presence on a live leg"));
                }
                _ => {}
            }
        }
        if let Some(r) = reason {
            out.extend(self.broadcast_roles(session, r, now_ms)?);
        }
        Ok(out)
    }

    /// The session's program wrote `data`.
    pub fn output(&mut self, session: &str, data: &[u8], now_ms: u64) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(ProtoError::InvalidInput("no such session"))?;
        let offset = s.journal.len() as u64;
        s.journal.extend_from_slice(data);
        let len = s.journal.len() as u64;
        for (d, leg) in s.legs.iter_mut() {
            if matches!(leg.state, LegState::Live) && leg.sent == offset {
                Self::send(
                    &mut out,
                    session,
                    d,
                    leg,
                    &[Message::Out {
                        offset,
                        data: data.to_vec(),
                    }],
                    now_ms,
                )?;
                leg.sent = len;
            }
        }
        Ok(out)
    }

    /// Revoke a device (design §6.7): cut it off, drop its tickets, and
    /// rekey every remaining leg of the sessions it was on.
    pub fn revoke(&mut self, device: &str, now_ms: u64) -> Result<Vec<Outbound>> {
        self.revoked.insert(device.into());
        self.tickets.forget_device(device);
        let mut out = Vec::new();
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            let s = self.sessions.get_mut(&id).expect("listed");
            if s.legs.remove(device).is_none() && s.typist.as_deref() != Some(device) {
                continue;
            }
            if s.typist.as_deref() == Some(device) {
                s.typist = None;
            }
            for (d, leg) in s.legs.iter_mut() {
                if matches!(leg.state, LegState::Live) {
                    out.push(Outbound {
                        session: id.clone(),
                        device: d.clone(),
                        record: seal_rekey(&mut leg.ch, true, now_ms)?,
                    });
                }
            }
            out.extend(self.broadcast_roles(&id, "device revoked", now_ms)?);
        }
        Ok(out)
    }

    /// `release_input` from the operator (one session at a time).
    pub fn release_input(
        &mut self,
        session: &str,
        device: &str,
        now_ms: u64,
    ) -> Result<Vec<Outbound>> {
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(ProtoError::InvalidInput("no such session"))?;
        if s.typist.as_deref() != Some(device) {
            return Ok(Vec::new());
        }
        s.typist = None;
        self.broadcast_roles(session, "input released", now_ms)
    }

    fn end(&mut self, session: &str, msgs: &[Message], now_ms: u64) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        if let Some(s) = self.sessions.get_mut(session) {
            for (d, leg) in s.legs.iter_mut() {
                if matches!(leg.state, LegState::Live) {
                    Self::send(&mut out, session, d, leg, msgs, now_ms)?;
                }
            }
            s.ended = true;
        }
        self.tickets.forget_session(session);
        Ok(out)
    }

    /// The program exited.
    pub fn exit(&mut self, session: &str, code: i32, now_ms: u64) -> Result<Vec<Outbound>> {
        self.end(
            session,
            &[Message::Exit {
                code: Some(code),
                signal: None,
            }],
            now_ms,
        )
    }

    /// The first step of a stop alone (design §7.3, Stop, step 1): every
    /// live leg is told the host is stopping, in its own record, and the
    /// sessions go on until [`RefHost::stop`]. A real host's `exit` follows
    /// only once each program has exited, and an operator that ends the
    /// legs on the host's `host_stopping` frame lets nothing after it
    /// through.
    pub fn announce_stop(&mut self, in_seconds: u32, now_ms: u64) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let msgs = [Message::HostStopping { in_seconds }];
        for (id, s) in self.sessions.iter_mut() {
            for (d, leg) in s.legs.iter_mut() {
                if matches!(leg.state, LegState::Live) {
                    Self::send(&mut out, id, d, leg, &msgs, now_ms)?;
                }
            }
        }
        Ok(out)
    }

    /// The host is stopping (design §7.3, Stop).
    pub fn stop(&mut self, now_ms: u64) -> Result<Vec<Outbound>> {
        let mut out = Vec::new();
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            out.extend(self.end(
                &id,
                &[
                    Message::HostStopping { in_seconds: 0 },
                    Message::Exit {
                        code: None,
                        signal: Some(1),
                    },
                ],
                now_ms,
            )?);
        }
        Ok(out)
    }

    /// Everything the session's typist has typed.
    pub fn input(&self, session: &str) -> Vec<u8> {
        self.sessions
            .get(session)
            .map(|s| s.input.clone())
            .unwrap_or_default()
    }

    /// The session's whole output.
    pub fn journal(&self, session: &str) -> Vec<u8> {
        self.sessions
            .get(session)
            .map(|s| s.journal.clone())
            .unwrap_or_default()
    }

    /// Whether the session's program was spawned.
    pub fn spawned(&self, session: &str) -> bool {
        self.sessions.get(session).is_some_and(|s| s.spawned)
    }

    /// The typist of a session.
    pub fn typist(&self, session: &str) -> Option<String> {
        self.sessions.get(session).and_then(|s| s.typist.clone())
    }

    /// How many tickets the host holds.
    pub fn tickets(&self) -> usize {
        self.tickets.len()
    }
}

/// A handshake in flight: the state, its action, and for a resume the
/// ticket and secret it redeems.
type Pending = (InitiatorHandshake, Action, Option<(TicketId, [u8; 32])>);

/// Per-session state on a reference client.
#[derive(Default)]
pub struct ClientLeg {
    ch: Option<Channel>,
    pending: Option<Pending>,
    ticket: Option<TicketId>,
    /// The ticket and secret the last resume redeemed, kept until the host
    /// is heard on the resumed leg (a resume cut short leaves it valid).
    prev: Option<(TicketId, [u8; 32])>,
    /// Whether this reconnect already fell back to `prev`.
    fell_back: bool,
    /// The output stream as reassembled.
    pub stream: Vec<u8>,
    ahead: BTreeMap<u64, Vec<u8>>,
    /// The typist as last announced.
    pub typist: Option<String>,
    /// The last `roles` reason.
    pub last_reason: Option<String>,
    /// Exit status, once received.
    pub exited: Option<(Option<i32>, Option<i32>)>,
    /// Error codes received.
    pub errors: Vec<String>,
    /// Whether `host_stopping` arrived.
    pub host_stopping: bool,
    /// Records refused (replays, duplicates).
    pub refused_records: u32,
}

impl std::fmt::Debug for ClientLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientLeg").finish_non_exhaustive()
    }
}

/// The reference client (a phone with a presence key, or a CLI without).
pub struct RefClient {
    /// The device id.
    pub device: String,
    keys: ShellKeypair,
    presence: Option<P256SigningKey>,
    statement: DeviceKeys,
    statement_sig: [u8; 64],
    host_pin: [u8; 32],
    airdress: String,
    machine: String,
    legs: HashMap<String, ClientLeg>,
    profiles: HashMap<String, String>,
    rng: DetRng,
    /// How many unlocks this client asked of its human.
    pub unlocks: u32,
}

impl std::fmt::Debug for RefClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefClient")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl RefClient {
    /// A phone (with a presence key) or a CLI (`phone = false`).
    pub fn new(
        seed: &[u8],
        device: &str,
        principal: &str,
        phone: bool,
        host_pin: [u8; 32],
        airdress: &str,
        machine: &str,
    ) -> Self {
        let mut rng = DetRng::new(seed);
        let keys = ShellKeypair::generate(&mut rng);
        let mut id = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut id);
        let identity = SigningKey::from_bytes(&id);
        let presence = phone.then(|| {
            let mut s = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rng, &mut s);
            s[0] &= 0x7f; // well below the group order
            P256SigningKey::from_slice(&s).expect("valid scalar")
        });
        let statement = DeviceKeys {
            device: device.into(),
            principal: principal.into(),
            identity_public: identity.verifying_key().to_bytes(),
            dh_public: *keys.public(),
            presence_alg: if phone {
                PresenceAlg::P256
            } else {
                PresenceAlg::None
            },
            presence_public: presence
                .as_ref()
                .map(|p| p.verifying_key().to_encoded_point(true).as_bytes().to_vec()),
        };
        let statement_sig = statement.sign(&identity).expect("own statement");
        Self {
            device: device.into(),
            keys,
            presence,
            statement,
            statement_sig,
            host_pin,
            airdress: airdress.into(),
            machine: machine.into(),
            legs: HashMap::new(),
            profiles: HashMap::new(),
            rng,
            unlocks: 0,
        }
    }

    /// The device's statement and its signature, for the host's `trust`.
    pub fn statement(&self) -> (&DeviceKeys, &[u8; 64]) {
        (&self.statement, &self.statement_sig)
    }

    /// The profile a session was opened or attached with.
    pub fn profile_of(&self, session: &str) -> Option<String> {
        self.profiles.get(session).cloned()
    }

    /// The state of one session.
    pub fn leg(&self, session: &str) -> Option<&ClientLeg> {
        self.legs.get(session)
    }

    fn prologue(&self, session: &str, profile: &str, action: Action) -> Prologue {
        Prologue {
            airdress: self.airdress.clone(),
            machine_id: self.machine.clone(),
            session_id: session.into(),
            profile_id: profile.into(),
            action,
        }
    }

    /// Start an open or a reattach. Returns msg1.
    pub fn begin(&mut self, session: &str, profile: &str, action: Action) -> Result<Vec<u8>> {
        let pro = self.prologue(session, profile, action);
        let hello = DeviceHello {
            device: self.device.clone(),
            cols: Some(80),
            rows: Some(24),
            client_version: Some("reference".into()),
        };
        let (hs, m1) =
            InitiatorHandshake::start(&mut self.rng, &self.keys, &self.host_pin, &pro, &hello)?;
        self.profiles.insert(session.into(), profile.into());
        let leg = self.legs.entry(session.into()).or_default();
        leg.ch = None;
        leg.pending = Some((hs, action, None));
        Ok(m1)
    }

    /// Start a resume with the current ticket. Returns the ticket id and
    /// msg1, or [`ProtoError::ResumeExpired`] when there is nothing to
    /// resume.
    pub fn begin_resume(&mut self, session: &str) -> Result<(TicketId, Vec<u8>)> {
        let leg = self.legs.get(session).ok_or(ProtoError::ResumeExpired)?;
        let ch = leg.ch.as_ref().ok_or(ProtoError::ResumeExpired)?;
        let ticket = leg.ticket.ok_or(ProtoError::ResumeExpired)?;
        let secret = *ch.resume_secret();
        self.legs.get_mut(session).expect("present").fell_back = false;
        self.resume_with(session, ticket, secret)
    }

    /// The host refused the current ticket: try the one the last resume
    /// redeemed, once per reconnect. It stays the fallback until a record
    /// arrives on the resumed leg.
    pub fn fallback_resume(&mut self, session: &str) -> Result<(TicketId, Vec<u8>)> {
        let leg = self
            .legs
            .get_mut(session)
            .ok_or(ProtoError::ResumeExpired)?;
        if leg.fell_back {
            return Err(ProtoError::ResumeExpired);
        }
        let (ticket, secret) = leg.prev.ok_or(ProtoError::ResumeExpired)?;
        leg.fell_back = true;
        self.resume_with(session, ticket, secret)
    }

    fn resume_with(
        &mut self,
        session: &str,
        ticket: TicketId,
        secret: [u8; 32],
    ) -> Result<(TicketId, Vec<u8>)> {
        let profile = self
            .profiles
            .get(session)
            .cloned()
            .ok_or(ProtoError::ResumeExpired)?;
        let pro = self.prologue(session, &profile, Action::Resume);
        let hello = DeviceHello {
            device: self.device.clone(),
            cols: None,
            rows: None,
            client_version: None,
        };
        let (hs, m1) = InitiatorHandshake::start_resume(
            &mut self.rng,
            &self.keys,
            &self.host_pin,
            &pro,
            &secret,
            &hello,
        )?;
        let leg = self
            .legs
            .get_mut(session)
            .ok_or(ProtoError::ResumeExpired)?;
        leg.pending = Some((hs, Action::Resume, Some((ticket, secret))));
        Ok((ticket, m1))
    }

    /// Read msg2. Returns the first record: the presence message after an
    /// open or attach (an unlock on a phone), or the `ack` after a resume.
    pub fn finish(&mut self, session: &str, msg2: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        let leg = self
            .legs
            .get_mut(session)
            .ok_or(ProtoError::InvalidInput("no leg"))?;
        let (hs, action, used) = leg
            .pending
            .take()
            .ok_or(ProtoError::InvalidInput("no handshake"))?;
        let (mut ch, hello) = hs.finish(msg2, now_ms)?;
        // The ticket this resume redeemed was admitted (nothing else is
        // redeemable), and the host keeps it until the new one is: it is
        // the way back if this leg is lost before the host hears from it.
        leg.prev = used;
        leg.ticket = Some(ticket_from_hello(&hello)?);
        let first = match action {
            Action::Resume => Message::Ack {
                offset: leg.stream.len() as u64,
            },
            a => {
                let sig = match &self.presence {
                    Some(pk) => {
                        self.unlocks += 1;
                        let s: P256Signature = pk.sign(&presence_message(ch.handshake_hash(), a)?);
                        Some(s.to_der().as_bytes().to_vec())
                    }
                    None => None,
                };
                Message::Presence {
                    action: a,
                    alg: self.statement.presence_alg,
                    sig,
                }
            }
        };
        let rec = ch.seal(&first.encode()?, now_ms)?;
        leg.ch = Some(ch);
        Ok(rec)
    }

    /// Seal messages on a live leg.
    pub fn send(&mut self, session: &str, msgs: &[Message], now_ms: u64) -> Result<Vec<u8>> {
        let ch = self
            .legs
            .get_mut(session)
            .and_then(|l| l.ch.as_mut())
            .ok_or(ProtoError::InvalidInput("no channel"))?;
        ch.seal(&Message::encode_all(msgs)?, now_ms)
    }

    /// The leg's channel is gone for good (revoked, ended, detached).
    pub fn forget(&mut self, session: &str) {
        if let Some(l) = self.legs.get_mut(session) {
            l.ch = None;
            l.ticket = None;
        }
    }

    /// A record from the host. Returns records to send back.
    pub fn receive(&mut self, session: &str, record: &[u8], now_ms: u64) -> Result<Vec<Vec<u8>>> {
        let leg = self
            .legs
            .get_mut(session)
            .ok_or(ProtoError::InvalidInput("no leg"))?;
        let ch = leg
            .ch
            .as_mut()
            .ok_or(ProtoError::InvalidInput("no channel"))?;
        let pt = match ch.open(record) {
            Ok((_, pt)) => pt,
            Err(e @ (ProtoError::Replay | ProtoError::RecordAuth)) => {
                leg.refused_records += 1;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        leg.prev = None;
        let mut replies = Vec::new();
        for m in Message::decode_all(&pt)? {
            match m {
                Message::Out { offset, data } => {
                    leg.ahead.insert(offset, data);
                }
                Message::Snapshot { offset, data, .. } => {
                    // The reference host's screen is its journal.
                    leg.stream = data;
                    debug_assert_eq!(leg.stream.len() as u64, offset);
                    leg.ahead.retain(|o, d| o + d.len() as u64 > offset);
                }
                Message::Roles { typist, reason, .. } => {
                    leg.typist = typist;
                    leg.last_reason = Some(reason);
                }
                Message::Exit { code, signal } => leg.exited = Some((code, signal)),
                Message::HostStopping { .. } => leg.host_stopping = true,
                Message::Error { code, .. } => leg.errors.push(code),
                Message::Rekey { switch_at, request } => {
                    ch.note_peer_rekey(switch_at);
                    if request {
                        replies.push(seal_rekey(ch, false, now_ms)?);
                    }
                }
                _ => {}
            }
        }
        // Reassemble in order; drop what is already held.
        while let Some((&o, _)) = leg.ahead.iter().next() {
            let have = leg.stream.len() as u64;
            if o > have {
                break;
            }
            let d = leg.ahead.remove(&o).expect("present");
            let end = o + d.len() as u64;
            if end > have {
                leg.stream.extend_from_slice(&d[(have - o) as usize..]);
            }
        }
        Ok(replies)
    }
}
