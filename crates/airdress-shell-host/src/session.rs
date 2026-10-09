//! One session inside the host process (design §7.1, §7.3, D-7, D-17, D-18).
//!
//! A session is a PTY, an emulator for snapshots, a journal for resumes, an
//! optional recording, and its attached clients. It belongs to the host
//! process: when the host stops, its sessions end (D-17).
//!
//! **One typist.** The opener types first. Another attached client of the
//! same person takes input explicitly; the previous typist becomes a viewer
//! and is told. Input, signals and resizes from anyone else are refused
//! (FR-S4, FR-S6).
//!
//! **Flow control (FR-S9).** Output goes to a client at most `credit` bytes
//! ahead of its `ack`. A client further behind is marked lagging and is
//! sent nothing until it acks; then it gets a snapshot at the current offset,
//! not the gap. The PTY is drained regardless, so a slow phone never slows
//! the program or another viewer.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use airdress_shell_proto::inner::{Message, Viewer};
use uuid::Uuid;

use crate::emulator::Emulator;
use crate::journal::Journal;
use crate::log_err::LogErr as _;
use crate::profiles::Profile;
use crate::pty::Pty;
use crate::recording::Recorder;

/// What a client accepts beyond its ack until it says otherwise.
pub const DEFAULT_CREDIT: u64 = 256 * 1024;
/// The most a client may ask for.
pub const MAX_CREDIT: u64 = 16 << 20;

/// One attached client (a device; the desk is not in this build).
#[derive(Debug, Clone)]
pub struct Client {
    pub leg: Option<Uuid>,
    pub label: String,
    /// The next offset to send.
    pub sent: u64,
    pub acked: u64,
    pub credit: u64,
    pub lagging: bool,
    /// After a resume: resend from the ack that comes next.
    pub resend_on_ack: bool,
    /// The client's own terminal size, applied when it types.
    pub size: Option<(u16, u16)>,
}

impl Client {
    pub fn new(leg: Uuid, label: String, at: u64, size: Option<(u16, u16)>) -> Self {
        Self {
            leg: Some(leg),
            label,
            sent: at,
            acked: at,
            credit: DEFAULT_CREDIT,
            lagging: false,
            resend_on_ack: false,
            size,
        }
    }
}

/// How a session is ending.
#[derive(Debug, Clone)]
pub struct Ending {
    pub reason: &'static str,
    pub hup_at: Instant,
    pub killed: bool,
}

/// One session.
pub struct Session {
    pub id: Uuid,
    pub profile: Profile,
    pub pty: Option<Pty>,
    pub emulator: Emulator,
    pub journal: Journal,
    pub clients: BTreeMap<Uuid, Client>,
    pub typist: Option<Uuid>,
    pub size: (u16, u16),
    pub opened_at: Instant,
    pub opened_wall: chrono::DateTime<chrono::Utc>,
    /// When the last client detached; `None` while one is attached.
    pub idle_since: Option<Instant>,
    pub lifetime_warned: bool,
    /// `(code, signal, when)` once the program exited.
    pub exited: Option<(Option<i32>, Option<i32>, Instant)>,
    pub ending: Option<Ending>,
    pub recording: Option<Recorder>,
    pub last_input: Option<Instant>,
    /// The last attention state the host reported.
    pub state: &'static str,
    /// Input the program has not taken yet, waiting for room in its PTY's
    /// queue (R-ASY-5). Non-empty only while the host has stopped reading
    /// its link for it, so it holds at most what one record carried.
    pub stalled_input: std::collections::VecDeque<Vec<u8>>,
    /// Since when the program last took input while some was waiting.
    pub stalled_since: Option<Instant>,
    /// The task that forwards this session's events to the host's queue,
    /// owned here (R-ASY-1): it ends when the session is dropped.
    pub forward: tokio::task::JoinSet<()>,
    /// The structured tier, for a profile that names an adapter.
    pub structured: Option<StructuredSide>,
}

/// A session's structured tier (design §9).
#[derive(Debug)]
pub struct StructuredSide {
    pub adapter: crate::structured::Adapter,
    /// `None` once the adapter ended, and always for the plugin adapter,
    /// whose events arrive on the host's event socket.
    pub handle: Option<crate::structured::AdapterHandle>,
    pub transcript: crate::structured::transcript::Transcript,
    /// For a harness driven through its terminal: the token its hooks
    /// present on the event socket, their mapper, and the permission hooks
    /// waiting for a human, by approval id.
    pub events_token: Option<crate::structured::events::HookToken>,
    pub hooks: crate::structured::events::Mapper,
    pub waiting: std::collections::HashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("profile", &self.profile.id)
            .field("clients", &self.clients.len())
            .field("typist", &self.typist)
            .finish_non_exhaustive()
    }
}

/// One message for one leg.
#[derive(Debug, Clone, PartialEq)]
pub struct Send {
    pub leg: Uuid,
    pub msg: Message,
}

impl Session {
    /// Whether the program is still running.
    pub fn running(&self) -> bool {
        self.exited.is_none()
    }

    /// Clients with a live leg.
    pub fn attached(&self) -> impl Iterator<Item = (&Uuid, &Client)> {
        self.clients.iter().filter(|(_, c)| c.leg.is_some())
    }

    /// How many clients are attached now.
    pub fn attached_count(&self) -> usize {
        self.attached().count()
    }

    /// `roles`, as every attached client is told.
    pub fn roles(&self, reason: &str) -> Message {
        Message::Roles {
            typist: self.typist.map(|t| t.to_string()),
            viewers: self
                .attached()
                .map(|(d, c)| Viewer {
                    client: d.to_string(),
                    label: c.label.clone(),
                })
                .collect(),
            reason: reason.to_owned(),
        }
    }

    /// `msg` to every attached client.
    pub fn broadcast(&self, msg: &Message) -> Vec<Send> {
        self.attached()
            .filter_map(|(_, c)| {
                c.leg.map(|leg| Send {
                    leg,
                    msg: msg.clone(),
                })
            })
            .collect()
    }

    /// A snapshot of the screen at the journal's end, within `budget`.
    pub fn snapshot(&mut self, budget: usize) -> Message {
        let (cols, rows) = self.emulator.size();
        Message::Snapshot {
            offset: self.journal.end(),
            cols,
            rows,
            data: self.emulator.snapshot(budget),
        }
    }

    /// Output from the PTY: into the emulator, the journal and the
    /// recording, and out to every client that is keeping up.
    pub fn output(&mut self, data: &[u8], budget: usize) -> Vec<Send> {
        let start = self.journal.end();
        self.emulator.process(data);
        if let Err(e) = self.journal.append(data) {
            tracing::warn!(session = %self.id, error = %e, "the journal could not spill");
        }
        if let Some(r) = self.recording.as_mut() {
            if let Err(e) = r.output(data) {
                tracing::warn!(session = %self.id, error = %e, "the recording stopped");
                self.recording = None;
            }
        }
        let end = self.journal.end();
        let mut out = Vec::new();
        for c in self.clients.values_mut() {
            let Some(leg) = c.leg else { continue };
            if c.lagging || c.resend_on_ack || c.sent != start {
                continue;
            }
            if end - c.acked > c.credit {
                c.lagging = true;
                continue;
            }
            for (i, piece) in data.chunks(budget.max(1)).enumerate() {
                out.push(Send {
                    leg,
                    msg: Message::Out {
                        offset: start + (i * budget.max(1)) as u64,
                        data: piece.to_vec(),
                    },
                });
            }
            c.sent = end;
        }
        out
    }

    /// An `ack` from `device`: a lagging client gets a snapshot, a resumed
    /// one everything after its ack (or a snapshot when the journal no
    /// longer has it).
    pub fn ack(&mut self, device: Uuid, offset: u64, budget: usize) -> Vec<Send> {
        let end = self.journal.end();
        let Some(c) = self.clients.get_mut(&device) else {
            return Vec::new();
        };
        let Some(leg) = c.leg else { return Vec::new() };
        c.acked = offset.min(end);
        if c.resend_on_ack {
            c.resend_on_ack = false;
            if let Some(bytes) = self
                .journal
                .read(offset, c.credit as usize)
                .filter(|b| offset + b.len() as u64 == end)
            {
                c.sent = end;
                return bytes
                    .chunks(budget.max(1))
                    .enumerate()
                    .map(|(i, piece)| Send {
                        leg,
                        msg: Message::Out {
                            offset: offset + (i * budget.max(1)) as u64,
                            data: piece.to_vec(),
                        },
                    })
                    .collect();
            }
            // Gone from the journal, or more than a credit window behind:
            // the latest screen, not every intermediate one.
            c.sent = end;
            c.acked = end;
            return vec![Send {
                leg,
                msg: self.snapshot(budget),
            }];
        }
        if c.lagging {
            c.lagging = false;
            c.sent = end;
            c.acked = end;
            return vec![Send {
                leg,
                msg: self.snapshot(budget),
            }];
        }
        Vec::new()
    }

    /// Whether the program's stdio is its adapter's protocol, so the
    /// terminal only shows its log and takes no input.
    pub fn stdio_is_protocol(&self) -> bool {
        self.structured
            .as_ref()
            .is_some_and(|x| x.adapter.uses_stdio())
    }

    /// Whether `device` holds input.
    pub fn is_typist(&self, device: Uuid) -> bool {
        self.typist == Some(device)
    }

    /// `device` takes input: its size is applied, everyone is told.
    pub fn take_input(&mut self, device: Uuid) -> Option<Vec<Send>> {
        let c = self.clients.get(&device)?;
        c.leg?;
        let (size, label) = (c.size, c.label.clone());
        self.typist = Some(device);
        if let Some((cols, rows)) = size {
            self.apply_size(cols, rows);
        }
        Some(self.broadcast(&self.roles(&format!("Input moved to {label}"))))
    }

    /// Type into the program, in order. When its queue is full the bytes
    /// wait in [`Session::stalled_input`], and the host stops reading its
    /// link until the program takes them (R-ASY-5).
    pub fn type_in(&mut self, data: Vec<u8>, now: Instant) {
        let Some(p) = &self.pty else {
            return;
        };
        if !self.stalled_input.is_empty() {
            self.stalled_input.push_back(data);
            return;
        }
        if let Err(back) = p.try_write(data) {
            self.stalled_input.push_back(back);
            self.stalled_since = Some(now);
        }
    }

    /// The program made room: the oldest waiting chunk takes `permit`, then
    /// as many as fit without waiting. A program that has exited takes
    /// nothing, and its exit is what its clients hear.
    pub fn input_room(&mut self, permit: tokio::sync::mpsc::Permit<'_, Vec<u8>>, now: Instant) {
        if let Some(d) = self.stalled_input.pop_front() {
            permit.send(d);
        }
        while let Some(d) = self.stalled_input.pop_front() {
            let Some(p) = &self.pty else {
                continue;
            };
            if let Err(back) = p.try_write(d) {
                self.stalled_input.push_front(back);
                self.stalled_since = Some(now);
                return;
            }
        }
        self.stalled_since = None;
    }

    /// Give up on the waiting input; the bytes given up.
    pub fn abandon_stalled_input(&mut self) -> usize {
        self.stalled_since = None;
        self.stalled_input.drain(..).map(|d| d.len()).sum()
    }

    /// Resize the terminal (the typist's size).
    pub fn apply_size(&mut self, cols: u16, rows: u16) {
        if (cols, rows) == self.size || cols == 0 || rows == 0 {
            return;
        }
        self.size = (cols, rows);
        self.emulator.resize(cols, rows);
        if let Some(p) = &self.pty {
            p.resize(cols, rows)
                .log_warn("resizing the session's terminal");
        }
    }

    /// The client is gone (`keep` its entry for a resume, or not).
    pub fn detach(&mut self, device: Uuid, keep: bool, now: Instant) {
        if keep {
            if let Some(c) = self.clients.get_mut(&device) {
                c.leg = None;
            }
        } else {
            self.clients.remove(&device);
            if self.typist == Some(device) {
                self.typist = None;
            }
        }
        if self.attached_count() == 0 && self.idle_since.is_none() {
            self.idle_since = Some(now);
        }
    }

    /// Why the session should end now, from its lifetimes (D-18).
    pub fn due(&self, now: Instant) -> Option<&'static str> {
        if self.ending.is_some() || self.exited.is_some() {
            return None;
        }
        if now.duration_since(self.opened_at) >= self.profile.max_lifetime {
            return Some("lifetime");
        }
        if self
            .idle_since
            .is_some_and(|t| now.duration_since(t) >= self.profile.idle_timeout)
        {
            return Some("idle");
        }
        None
    }

    /// Whether the 10-minute warning before `max_lifetime` is due.
    pub fn lifetime_warning_due(&self, now: Instant, warn_before: Duration) -> bool {
        !self.lifetime_warned
            && self.exited.is_none()
            && now.duration_since(self.opened_at) + warn_before >= self.profile.max_lifetime
    }

    /// Start ending: `SIGHUP` to the process group, `SIGKILL` later.
    pub fn end(&mut self, reason: &'static str, now: Instant) {
        if self.ending.is_some() {
            return;
        }
        if let Some(p) = &self.pty {
            p.hangup();
        }
        self.ending = Some(Ending {
            reason,
            hup_at: now,
            killed: false,
        });
    }

    /// `SIGKILL` once `after` has passed since the hangup.
    pub fn kill_if_due(&mut self, now: Instant, after: Duration) {
        if let (Some(e), Some(p)) = (self.ending.as_mut(), self.pty.as_ref()) {
            if !e.killed && self.exited.is_none() && now.duration_since(e.hup_at) >= after {
                p.kill();
                e.killed = true;
            }
        }
    }

    /// The listing the host reports on connect.
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "profile": self.profile.id,
            "openedAt": self.opened_wall,
            "attached": self.attached_count(),
            "typist": self.typist.map(|t| t.to_string()),
            "state": self.state,
        })
    }
}
