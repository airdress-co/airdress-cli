//! A reference host, its clients and a network between them, on simulated
//! time.
//!
//! The network stands in for both hops (device ↔ operator ↔ host). It can
//! delay each message independently (which reorders them), duplicate
//! records, and cut a leg: everything in flight on a cut leg is lost, and
//! the client comes back with a resume, or with a reattach when its ticket
//! is gone. That is the record-level shape of every fault in design §14.3:
//! a hard cut, an address change and the relay's idle cut all end a leg;
//! TCP-level loss and reordering surface as delay; a retransmission across
//! two legs surfaces as a duplicate.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use rand_core::RngCore;

use super::{RefClient, RefHost};
use crate::error::ProtoError;
use crate::prologue::Action;
use crate::ticket::TicketId;
use crate::vectors::DetRng;

/// What the network does to traffic.
#[derive(Debug, Clone, Copy)]
pub struct FaultPlan {
    /// Least one-way delay, ms.
    pub delay_min_ms: u64,
    /// Most one-way delay, ms. Different delays per message reorder them.
    pub delay_max_ms: u64,
    /// Chance, per thousand, that a record is delivered twice.
    pub duplicate_per_mille: u32,
}

impl FaultPlan {
    /// A perfect network: no delay, no duplicates.
    pub fn none() -> Self {
        Self {
            delay_min_ms: 0,
            delay_max_ms: 0,
            duplicate_per_mille: 0,
        }
    }
}

#[derive(Debug, Clone)]
enum Payload {
    Open { profile: String, msg1: Vec<u8> },
    Attach { msg1: Vec<u8> },
    Resume { ticket: TicketId, msg1: Vec<u8> },
    Msg2(Vec<u8>),
    Refused(String),
    Record(Vec<u8>),
}

#[derive(Debug, Clone)]
struct InFlight {
    to_host: bool,
    session: String,
    device: String,
    epoch: u64,
    payload: Payload,
}

/// Per-leg measurements.
#[derive(Debug, Default, Clone)]
pub struct LegStats {
    /// When the current reconnect started, if one is in progress.
    pub reconnect_started: Option<u64>,
    /// How long each reconnect took, until the first host record arrived.
    pub reconnect_ms: Vec<u64>,
    /// The codes of handshakes the host refused.
    pub refusals: Vec<String>,
    /// Whether the last reconnect was a full reattach (with an unlock).
    pub reattached: u32,
    /// Records the host rejected (duplicates, replays).
    pub host_rejected: u32,
}

/// The simulation.
pub struct World {
    /// The host.
    pub host: RefHost,
    /// Clients by device id.
    pub clients: BTreeMap<String, RefClient>,
    /// Simulated time, ms.
    pub now: u64,
    /// Faults.
    pub plan: FaultPlan,
    rng: DetRng,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    flights: HashMap<u64, InFlight>,
    seq: u64,
    epochs: HashMap<(String, String), u64>,
    /// Measurements per (session, device).
    pub stats: HashMap<(String, String), LegStats>,
    /// Host-side errors, for the log.
    pub host_errors: Vec<String>,
}

impl std::fmt::Debug for World {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("World")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl World {
    /// A world with one host.
    pub fn new(seed: &[u8], plan: FaultPlan) -> Self {
        Self {
            host: RefHost::new(
                &[seed, b"/host"].concat(),
                "airdress-test",
                "machine-1",
                "principal-1",
            ),
            clients: BTreeMap::new(),
            now: 0,
            plan,
            rng: DetRng::new(&[seed, b"/net"].concat()),
            queue: BinaryHeap::new(),
            flights: HashMap::new(),
            seq: 0,
            epochs: HashMap::new(),
            stats: HashMap::new(),
            host_errors: Vec::new(),
        }
    }

    /// Add a device and introduce it to the host with `kind`.
    pub fn add_device(
        &mut self,
        device: &str,
        phone: bool,
        kind: &str,
        label: &str,
    ) -> Result<(), ProtoError> {
        let c = RefClient::new(
            &[b"client/", device.as_bytes()].concat(),
            device,
            "principal-1",
            phone,
            self.host.public(),
            "airdress-test",
            "machine-1",
        );
        let (keys, sig) = c.statement();
        self.host.trust(keys, sig, kind, label)?;
        self.clients.insert(device.into(), c);
        Ok(())
    }

    fn key(session: &str, device: &str) -> (String, String) {
        (session.to_owned(), device.to_owned())
    }

    fn epoch(&self, session: &str, device: &str) -> u64 {
        *self.epochs.get(&Self::key(session, device)).unwrap_or(&0)
    }

    fn delay(&mut self) -> u64 {
        let span = self.plan.delay_max_ms - self.plan.delay_min_ms;
        if span == 0 {
            self.plan.delay_min_ms
        } else {
            self.plan.delay_min_ms + self.rng.next_u64() % (span + 1)
        }
    }

    fn push(&mut self, f: InFlight) {
        let dup = matches!(f.payload, Payload::Record(_))
            && self.plan.duplicate_per_mille > 0
            && (self.rng.next_u32() % 1000) < self.plan.duplicate_per_mille;
        let copies = if dup { 2 } else { 1 };
        for _ in 0..copies {
            let at = self.now + self.delay();
            self.seq += 1;
            self.queue.push(Reverse((at, self.seq)));
            self.flights.insert(self.seq, f.clone());
        }
    }

    fn send_host(&mut self, session: &str, device: &str, payload: Payload) {
        let epoch = self.epoch(session, device);
        self.push(InFlight {
            to_host: true,
            session: session.into(),
            device: device.into(),
            epoch,
            payload,
        });
    }

    fn send_client(&mut self, session: &str, device: &str, payload: Payload) {
        let epoch = self.epoch(session, device);
        self.push(InFlight {
            to_host: false,
            session: session.into(),
            device: device.into(),
            epoch,
            payload,
        });
    }

    fn host_out(&mut self, out: Vec<super::Outbound>) {
        for o in out {
            self.send_client(&o.session, &o.device, Payload::Record(o.record));
        }
    }

    /// A device opens a session.
    pub fn open(&mut self, device: &str, session: &str, profile: &str) {
        let m1 = self
            .clients
            .get_mut(device)
            .expect("known device")
            .begin(session, profile, Action::Open)
            .expect("begin");
        self.send_host(
            session,
            device,
            Payload::Open {
                profile: profile.into(),
                msg1: m1,
            },
        );
    }

    /// A device attaches with a full handshake.
    pub fn attach(&mut self, device: &str, session: &str, profile: &str) {
        let m1 = self
            .clients
            .get_mut(device)
            .expect("known device")
            .begin(session, profile, Action::Attach)
            .expect("begin");
        self.send_host(session, device, Payload::Attach { msg1: m1 });
    }

    /// The leg is cut: everything in flight on it is lost.
    pub fn cut(&mut self, device: &str, session: &str) {
        *self.epochs.entry(Self::key(session, device)).or_default() += 1;
        self.host.leg_dropped(session, device, self.now);
    }

    /// The device comes back: a resume if it can, a reattach if not.
    pub fn reconnect(&mut self, device: &str, session: &str, profile: &str) {
        self.stats
            .entry(Self::key(session, device))
            .or_default()
            .reconnect_started = Some(self.now);
        let c = self.clients.get_mut(device).expect("known device");
        match c.begin_resume(session) {
            Ok((ticket, m1)) => {
                self.send_host(session, device, Payload::Resume { ticket, msg1: m1 })
            }
            Err(_) => self.attach(device, session, profile),
        }
    }

    /// The device detaches for good.
    pub fn detach(&mut self, device: &str, session: &str) {
        *self.epochs.entry(Self::key(session, device)).or_default() += 1;
        self.host.detach(session, device);
        if let Some(c) = self.clients.get_mut(device) {
            c.forget(session);
        }
    }

    /// A client sends inner messages.
    pub fn client_send(&mut self, device: &str, session: &str, msgs: &[crate::inner::Message]) {
        let rec = self
            .clients
            .get_mut(device)
            .expect("known device")
            .send(session, msgs, self.now)
            .expect("live leg");
        self.send_host(session, device, Payload::Record(rec));
    }

    /// The session's program writes.
    pub fn output(&mut self, session: &str, data: &[u8]) {
        let out = self.host.output(session, data, self.now).expect("session");
        self.host_out(out);
    }

    /// Run a host action that returns records.
    pub fn host_action(
        &mut self,
        f: impl FnOnce(&mut RefHost, u64) -> Result<Vec<super::Outbound>, ProtoError>,
    ) {
        let now = self.now;
        match f(&mut self.host, now) {
            Ok(out) => self.host_out(out),
            Err(e) => self.host_errors.push(e.code().into()),
        }
    }

    /// Deliver everything due by `until`, then set the clock to it.
    pub fn run_until(&mut self, until: u64) {
        while let Some(Reverse((at, seq))) = self.queue.peek().copied() {
            if at > until {
                break;
            }
            self.queue.pop();
            self.now = self.now.max(at);
            let f = self.flights.remove(&seq).expect("queued");
            if f.epoch != self.epoch(&f.session, &f.device) {
                continue; // lost with its leg
            }
            if f.to_host {
                self.deliver_to_host(f);
            } else {
                self.deliver_to_client(f);
            }
        }
        self.now = self.now.max(until);
    }

    /// Deliver until nothing is in flight.
    pub fn settle(&mut self) {
        while let Some(Reverse((at, _))) = self.queue.peek().copied() {
            self.run_until(at);
        }
    }

    fn deliver_to_host(&mut self, f: InFlight) {
        let (s, d, now) = (f.session.clone(), f.device.clone(), self.now);
        let result = match f.payload {
            Payload::Open { profile, msg1 } => self
                .host
                .open(&s, &profile, &d, &msg1, now)
                .map(Payload::Msg2),
            Payload::Attach { msg1 } => self.host.attach(&s, &d, &msg1, now).map(Payload::Msg2),
            Payload::Resume { ticket, msg1 } => self
                .host
                .resume(&s, &d, &ticket, &msg1, now)
                .map(Payload::Msg2),
            Payload::Record(rec) => {
                match self.host.record(&s, &d, &rec, now) {
                    Ok(out) => self.host_out(out),
                    Err(e) => {
                        let st = self.stats.entry(Self::key(&s, &d)).or_default();
                        if matches!(e, ProtoError::Replay | ProtoError::RecordAuth) {
                            st.host_rejected += 1;
                        }
                        self.host_errors.push(e.code().into());
                    }
                }
                return;
            }
            _ => unreachable!("host-bound payloads only"),
        };
        match result {
            Ok(p) => self.send_client(&s, &d, p),
            Err(e) => self.send_client(&s, &d, Payload::Refused(e.code().into())),
        }
    }

    fn deliver_to_client(&mut self, f: InFlight) {
        let (s, d, now) = (f.session.clone(), f.device.clone(), self.now);
        let key = Self::key(&s, &d);
        match f.payload {
            Payload::Msg2(m2) => {
                let c = self.clients.get_mut(&d).expect("known device");
                match c.finish(&s, &m2, now) {
                    Ok(first) => self.send_host(&s, &d, Payload::Record(first)),
                    Err(e) => self
                        .stats
                        .entry(key)
                        .or_default()
                        .refusals
                        .push(e.code().into()),
                }
            }
            Payload::Refused(code) => {
                let st = self.stats.entry(key.clone()).or_default();
                st.refusals.push(code.clone());
                if code == "shell_resume_expired" {
                    // The current ticket is gone. Try the one before the
                    // last resume; failing that, a full handshake, which on
                    // a phone means an unlock.
                    let c = self.clients.get_mut(&d).expect("known device");
                    match c.fallback_resume(&s) {
                        Ok((ticket, m1)) => {
                            self.send_host(&s, &d, Payload::Resume { ticket, msg1: m1 })
                        }
                        Err(_) => {
                            self.stats.entry(key).or_default().reattached += 1;
                            let profile = self.clients[&d].profile_of(&s).unwrap_or_default();
                            self.attach(&d, &s, &profile);
                        }
                    }
                }
            }
            Payload::Record(rec) => {
                let st = self.stats.entry(key.clone()).or_default();
                if let Some(start) = st.reconnect_started.take() {
                    st.reconnect_ms.push(now - start);
                }
                let c = self.clients.get_mut(&d).expect("known device");
                if let Ok(replies) = c.receive(&s, &rec, now) {
                    for r in replies {
                        self.send_host(&s, &d, Payload::Record(r));
                    }
                }
            }
            _ => unreachable!("client-bound payloads only"),
        }
    }
}
