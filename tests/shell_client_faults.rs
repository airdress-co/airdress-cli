//! The fault model of design §14.3 with the CLI's own session as the client
//! (task D.4): the protocol crate's reference host on one side, the CLI's
//! `ClientSession` on the other, and between them a network on simulated
//! time that delays every message by 50–400 ms (which reorders them),
//! duplicates some, and cuts legs — hard cuts of 0.5–10 s, an address
//! change (a cut with an immediate reconnect), the relay's 300 s idle cut,
//! and a cut between message 2 and the first record of a resume.
//!
//! The pass criteria are the design's, for the CLI:
//!
//! - no lost or duplicated output bytes after any resume (the CLI's stream
//!   against the host's journal);
//! - resume < 2 s p95 for cuts under 5 s;
//! - no reattach for a cut under 120 s (and so nothing a phone would have
//!   to unlock; the CLI unlocks nothing anyway, D-30);
//! - past 120 s, a reattach that asks nothing.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use airdress_shell_proto::conformance::RefHost;
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::presence::{DeviceKeys, PresenceAlg};
use airdress_shell_proto::prologue::Action;
use airdress_shell_proto::ticket::TicketId;
use airdress_shell_proto::ProtoError;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng as _};

use airdress::shell_client::session::{ClientSession, Event, Target};

const S: &str = "0b0b0b0b-1111-4222-8333-444444444444";
const DEV: &str = "cli-device";

#[derive(Debug, Clone)]
enum Payload {
    Attach(Vec<u8>),
    Resume(TicketId, Vec<u8>),
    Msg2(Vec<u8>),
    Refused,
    ToHost(Vec<u8>),
    ToClient(Vec<u8>),
}

struct Net {
    rng: StdRng,
    now: u64,
    epoch: u64,
    queue: BinaryHeap<Reverse<(u64, u64, usize)>>,
    items: Vec<Option<(u64, Payload)>>,
    dup_per_mille: u32,
}

impl Net {
    fn send(&mut self, p: Payload) {
        let copies = if matches!(p, Payload::ToHost(_) | Payload::ToClient(_))
            && self.rng.gen_range(0..1000) < self.dup_per_mille
        {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let at = self.now + self.rng.gen_range(50..=400);
            let id = self.items.len();
            self.items.push(Some((self.epoch, p.clone())));
            self.queue.push(Reverse((at, id as u64, id)));
        }
    }
}

struct Sim {
    host: RefHost,
    cs: ClientSession,
    net: Net,
    connected: bool,
    /// Drop the first record after the next msg2 (a cut mid-resume).
    cut_after_msg2: bool,
    pending_mode: Option<Action>,
    stream: Vec<u8>,
    reattaches: u32,
    resumes: u32,
    reconnect_started: Option<u64>,
    reconnect_ms: Vec<u64>,
    lines: u64,
}

impl Sim {
    fn new(seed: u64, dup_per_mille: u32) -> Self {
        let mut host = RefHost::new(b"faults", "a.example", "m", "anna");
        let keys = ShellKeypair::from_secret([0x51; 32]);
        let identity = SigningKey::from_bytes(&[0x52; 32]);
        let st = DeviceKeys {
            device: DEV.into(),
            principal: "anna".into(),
            identity_public: identity.verifying_key().to_bytes(),
            dh_public: *keys.public(),
            presence_alg: PresenceAlg::None,
            presence_public: None,
        };
        let sig = st.sign(&identity).unwrap();
        host.trust(&st, &sig, "cli", "airdress CLI").unwrap();
        let cs = ClientSession::new(
            Target {
                airdress: "a.example".into(),
                machine: "m".into(),
                host_static: host.public(),
                profile: "sh".into(),
                device: DEV.into(),
            },
            keys,
            S,
        );
        Self {
            host,
            cs,
            net: Net {
                rng: StdRng::seed_from_u64(seed),
                now: 0,
                epoch: 0,
                queue: BinaryHeap::new(),
                items: Vec::new(),
                dup_per_mille,
            },
            connected: false,
            cut_after_msg2: false,
            pending_mode: None,
            stream: Vec::new(),
            reattaches: 0,
            resumes: 0,
            reconnect_started: None,
            reconnect_ms: Vec::new(),
            lines: 0,
        }
    }

    fn open(&mut self) {
        let m1 = self.cs.begin(Action::Open, 80, 24).unwrap();
        let m2 = self.host.open(S, "sh", DEV, &m1, self.net.now).unwrap();
        let (_, first) = self.cs.finish(&m2, self.net.now).unwrap();
        for r in first {
            let out = self.host.record(S, DEV, &r, self.net.now).unwrap();
            for o in out {
                self.on_client(&o.record);
            }
        }
        self.connected = true;
        assert!(self.cs.is_live());
    }

    fn cut(&mut self) {
        self.net.epoch += 1;
        self.connected = false;
        self.host.leg_dropped(S, DEV, self.net.now);
    }

    /// The device reconnects: a resume while it holds a ticket, else a
    /// reattach.
    fn reconnect(&mut self) {
        self.reconnect_started.get_or_insert(self.net.now);
        match self.cs.begin_resume() {
            Ok((t, m1)) => {
                self.resumes += 1;
                self.pending_mode = Some(Action::Resume);
                self.net.send(Payload::Resume(t, m1));
            }
            Err(ProtoError::ResumeExpired) => self.reattach(),
            Err(e) => panic!("{e}"),
        }
    }

    fn reattach(&mut self) {
        self.reattaches += 1;
        self.pending_mode = Some(Action::Attach);
        let m1 = self.cs.begin(Action::Attach, 80, 24).unwrap();
        self.net.send(Payload::Attach(m1));
    }

    fn on_client(&mut self, rec: &[u8]) {
        match self.cs.receive(rec, self.net.now) {
            Ok((events, replies)) => {
                if let Some(t) = self.reconnect_started.take() {
                    self.reconnect_ms.push(self.net.now - t);
                }
                for e in events {
                    match e {
                        Event::Output(b) => self.stream.extend(b),
                        // The reference host's snapshot is its journal.
                        Event::Redraw { data, .. } => self.stream = data,
                        _ => {}
                    }
                }
                for r in replies {
                    self.net.send(Payload::ToHost(r));
                }
            }
            Err(ProtoError::Replay | ProtoError::RecordAuth) => {}
            Err(e) => panic!("client: {e}"),
        }
    }

    fn deliver(&mut self, epoch: u64, p: Payload) {
        if epoch != self.net.epoch {
            return; // in flight on a cut leg: lost
        }
        let now = self.net.now;
        match p {
            Payload::Resume(t, m1) => match self.host.resume(S, DEV, &t, &m1, now) {
                Ok(m2) => self.net.send(Payload::Msg2(m2)),
                Err(_) => self.net.send(Payload::Refused),
            },
            Payload::Attach(m1) => {
                let m2 = self.host.attach(S, DEV, &m1, now).unwrap();
                self.net.send(Payload::Msg2(m2));
            }
            Payload::Msg2(m2) => {
                let (_, first) = self.cs.finish(&m2, now).unwrap();
                self.pending_mode = None;
                self.connected = true;
                if std::mem::take(&mut self.cut_after_msg2) {
                    // The leg dies before the first record reaches the host.
                    self.cut();
                    self.reconnect();
                    return;
                }
                for r in first {
                    self.net.send(Payload::ToHost(r));
                }
            }
            Payload::Refused => {
                // N-4: the ticket the last resume redeemed, once; then a
                // reattach.
                match self.cs.fallback_resume() {
                    Ok((t, m1)) => self.net.send(Payload::Resume(t, m1)),
                    Err(_) => self.reattach(),
                }
            }
            Payload::ToHost(r) => {
                if let Ok(out) = self.host.record(S, DEV, &r, now) {
                    for o in out {
                        self.net.send(Payload::ToClient(o.record));
                    }
                }
            }
            Payload::ToClient(r) => self.on_client(&r),
        }
    }

    /// Run until `until` ms: a line of output every 20 ms, an ack every
    /// 200 ms.
    fn run_until(&mut self, until: u64) {
        while self.net.now < until {
            self.net.now += 10;
            while let Some(Reverse((at, _, id))) = self.net.queue.peek().copied() {
                if at > self.net.now {
                    break;
                }
                self.net.queue.pop();
                if let Some((epoch, p)) = self.net.items[id].take() {
                    self.deliver(epoch, p);
                }
            }
            if self.net.now.is_multiple_of(20) {
                self.lines += 1;
                let line = format!(
                    "line {:06} {}\r\n",
                    self.lines,
                    "x".repeat((self.lines % 37) as usize)
                );
                if let Ok(out) = self.host.output(S, line.as_bytes(), self.net.now) {
                    if self.connected {
                        for o in out {
                            self.net.send(Payload::ToClient(o.record));
                        }
                    }
                }
            }
            if self.net.now.is_multiple_of(200) && self.connected && self.cs.is_live() {
                let r = self
                    .cs
                    .seal(
                        &[Message::Ack {
                            offset: self.cs.delivered(),
                        }],
                        self.net.now,
                    )
                    .unwrap();
                self.net.send(Payload::ToHost(r));
            }
        }
    }

    /// Stop output and let everything settle.
    fn settle(&mut self) {
        let end = self.net.now + 5_000;
        while self.net.now < end {
            self.net.now += 10;
            while let Some(Reverse((at, _, id))) = self.net.queue.peek().copied() {
                if at > self.net.now {
                    break;
                }
                self.net.queue.pop();
                if let Some((epoch, p)) = self.net.items[id].take() {
                    self.deliver(epoch, p);
                }
            }
            if self.net.now.is_multiple_of(200) && self.connected && self.cs.is_live() {
                let r = self
                    .cs
                    .seal(
                        &[Message::Ack {
                            offset: self.cs.delivered(),
                        }],
                        self.net.now,
                    )
                    .unwrap();
                self.net.send(Payload::ToHost(r));
            }
        }
    }

    fn outage(&mut self, len: u64) {
        self.cut();
        let back = self.net.now + len;
        self.run_until(back);
        self.reconnect();
    }
}

fn p95(v: &[u64]) -> u64 {
    let mut v = v.to_vec();
    v.sort_unstable();
    v[((v.len() as f64) * 0.95).ceil() as usize - 1]
}

#[test]
fn cuts_under_five_seconds_resume_fast_and_lose_nothing() {
    // p95 over every resume of every seed, not per seed: a dozen samples
    // have no 95th percentile worth the name.
    let mut all = Vec::new();
    for seed in 0..8u64 {
        let mut sim = Sim::new(seed, 30);
        sim.open();
        let mut rng = StdRng::seed_from_u64(1000 + seed);
        for _ in 0..20 {
            let gap = rng.gen_range(2_000..6_000);
            let t = sim.net.now + gap;
            sim.run_until(t);
            let len = rng.gen_range(500..5_000);
            sim.outage(len);
        }
        // An address change: a cut and an immediate reconnect.
        let t = sim.net.now + 1_000;
        sim.run_until(t);
        sim.outage(0);
        let t = sim.net.now + 3_000;
        sim.run_until(t);
        sim.settle();
        assert_eq!(
            sim.reattaches, 0,
            "seed {seed}: a cut under 120 s is a resume"
        );
        assert_eq!(
            sim.stream,
            sim.host.journal(S),
            "seed {seed}: every byte, once, in order"
        );
        all.extend_from_slice(&sim.reconnect_ms);
    }
    let p = p95(&all);
    assert!(p < 2_000, "resume p95 {p} ms over {} resumes", all.len());
}

#[test]
fn a_cut_between_msg2_and_the_first_record_costs_no_reattach() {
    let mut sim = Sim::new(42, 0);
    sim.open();
    sim.run_until(2_000);
    sim.cut_after_msg2 = true;
    sim.outage(1_000);
    sim.run_until(sim.net.now + 4_000);
    sim.settle();
    assert_eq!(sim.reattaches, 0);
    assert!(sim.resumes >= 2, "the fallback ticket was used");
    assert_eq!(sim.stream, sim.host.journal(S));
}

#[test]
fn the_relays_idle_cut_resumes_and_past_120_s_reattaches_silently() {
    let mut sim = Sim::new(7, 10);
    sim.open();
    sim.run_until(3_000);
    // The relay's 300 s idle cut on an idle leg is a cut with an
    // immediate reconnect, well within the ticket.
    sim.outage(200);
    sim.run_until(sim.net.now + 3_000);
    assert_eq!(sim.reattaches, 0);
    // A cut longer than the ticket's 120 s.
    sim.outage(125_000);
    sim.run_until(sim.net.now + 3_000);
    sim.settle();
    assert_eq!(
        sim.reattaches, 1,
        "past 120 s: one reattach, with no prompt"
    );
    assert_eq!(sim.stream, sim.host.journal(S));
    assert!(sim.host.unlocks_verified.is_empty());
}
