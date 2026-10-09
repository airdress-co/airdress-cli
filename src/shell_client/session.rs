//! The device's half of one session's end-to-end channel, without I/O.
//!
//! One [`ClientSession`] is one session on one host, as seen from this
//! device: the handshake in flight, the established channel, the resume
//! ticket (and the one the last resume redeemed, kept as a fallback), and
//! the output stream reassembled by offset. The run loop feeds it records
//! and sends what it returns; the tests drive it against the protocol
//! crate's reference host with no network at all.
//!
//! **The CLI on Linux has no presence key** (D-30). The first record after
//! an open or an attach is still a `presence` message, saying `none`
//! (protocol crate note N-2): it is the host's proof that this device holds
//! the channel keys before anything is spawned. A resume's first record is
//! an `ack` with the offset this device holds, and the host replays from
//! there.
//!
//! **A resume keeps a fallback** (note N-4): the ticket the last resume
//! redeemed stays usable until the host is heard from on the resumed leg,
//! so a cut between message 2 and the first record does not cost a full
//! reattach.

use std::collections::BTreeMap;

use airdress_shell_proto::handshake::{
    ticket_from_hello, Channel, DeviceHello, HostHello, InitiatorHandshake,
};
use airdress_shell_proto::inner::{seal_rekey, Message, RecordingInfo, Viewer};
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::presence::PresenceAlg;
use airdress_shell_proto::prologue::{Action, Prologue};
use airdress_shell_proto::ticket::TicketId;
use airdress_shell_proto::{ProtoError, Result};

/// The credit this client grants the host beyond its last ack (design §7.10).
pub const CREDIT_BYTES: u64 = 256 * 1024;
/// Acknowledge at least every this many bytes of output.
pub const ACK_EVERY: u64 = 32 * 1024;

/// Who and what one session is bound to: everything in the prologue, and
/// the host key this device pinned.
#[derive(Debug, Clone)]
pub struct Target {
    /// The airdress the host is enrolled with (its FQDN).
    pub airdress: String,
    /// The host's machine id.
    pub machine: String,
    /// The host's pinned X25519 shell key.
    pub host_static: [u8; 32],
    /// The profile the session runs.
    pub profile: String,
    /// This device's id (its enrollment).
    pub device: String,
}

/// What a record from the host means to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Output, in order, never repeated: write it to the terminal.
    Output(Vec<u8>),
    /// Redraw the screen (a snapshot). Earlier output is superseded.
    Redraw {
        /// Columns the snapshot was taken at.
        cols: u16,
        /// Rows.
        rows: u16,
        /// The VT sequence.
        data: Vec<u8>,
    },
    /// Who types and who watches changed.
    Roles {
        /// The typist.
        typist: Option<String>,
        /// Everyone attached.
        viewers: Vec<Viewer>,
        /// Why.
        reason: String,
    },
    /// The program exited.
    Exit {
        /// Exit code.
        code: Option<i32>,
        /// Signal.
        signal: Option<i32>,
    },
    /// The host is stopping.
    HostStopping {
        /// Seconds left.
        in_seconds: u32,
    },
    /// The host refused something inside the channel.
    Error {
        /// A design §13 code.
        code: String,
        /// For a human.
        message: String,
    },
    /// The host's recordings.
    RecordingListing(Vec<RecordingInfo>),
    /// A segment header, before its chunks.
    RecordingHeader {
        /// The recording.
        recording: String,
        /// The segment.
        segment: u32,
        /// The serialized header.
        header: Vec<u8>,
    },
    /// One sealed chunk of the current segment.
    RecordingChunk {
        /// The segment.
        segment: u32,
        /// The chunk index.
        index: u64,
        /// As stored.
        sealed: Vec<u8>,
    },
    /// A structured-tier event (not rendered by the terminal client).
    Structured(serde_json::Value),
}

type Pending = (InitiatorHandshake, Action, Option<(TicketId, [u8; 32])>);

/// One session's end-to-end state on this device.
pub struct ClientSession {
    target: Target,
    keys: ShellKeypair,
    session: String,
    ch: Option<Channel>,
    pending: Option<Pending>,
    ticket: Option<TicketId>,
    prev: Option<(TicketId, [u8; 32])>,
    fell_back: bool,
    heard: bool,
    delivered: u64,
    acked: u64,
    ahead: BTreeMap<u64, Vec<u8>>,
}

impl core::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientSession")
            .field("session", &self.session)
            .field("established", &self.ch.is_some())
            .field("delivered", &self.delivered)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// A session this device is about to open or attach. `session` is the
    /// id the prologue binds: for an open, the one this device proposes.
    pub fn new(target: Target, keys: ShellKeypair, session: &str) -> Self {
        Self {
            target,
            keys,
            session: session.to_owned(),
            ch: None,
            pending: None,
            ticket: None,
            prev: None,
            fell_back: false,
            heard: false,
            delivered: 0,
            acked: 0,
            ahead: BTreeMap::new(),
        }
    }

    /// The session id.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The target.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Bytes of output delivered so far (the stream offset).
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Whether a channel is established, the host has been heard on it, and
    /// no handshake is in flight.
    ///
    /// A resume's message 2 is the host heard: it answered the ticket with
    /// this session's resume secret, and its own record layer is keyed by it.
    /// Waiting for a record after it instead deadlocked an idle session
    /// (found live on a test operator, v0.1.119, 2026-10-05): the host had nothing new
    /// to send after an operator restart, so the client stayed on
    /// "reconnecting…" and refused input for minutes.
    pub fn is_live(&self) -> bool {
        self.ch.is_some() && self.heard && self.pending.is_none()
    }

    /// Whether there is a ticket (or a fallback) to resume with.
    pub fn can_resume(&self) -> bool {
        (self.ch.is_some() && self.ticket.is_some()) || self.prev.is_some()
    }

    fn prologue(&self, action: Action) -> Prologue {
        Prologue {
            airdress: self.target.airdress.clone(),
            machine_id: self.target.machine.clone(),
            session_id: self.session.clone(),
            profile_id: self.target.profile.clone(),
            action,
        }
    }

    /// Start an open (`Action::Open`) or a reattach (`Action::Attach`) with a
    /// full `IK` handshake. Returns message 1.
    pub fn begin(&mut self, action: Action, cols: u16, rows: u16) -> Result<Vec<u8>> {
        if action == Action::Resume {
            return Err(ProtoError::InvalidInput("a resume uses begin_resume"));
        }
        let hello = DeviceHello {
            device: self.target.device.clone(),
            cols: Some(cols),
            rows: Some(rows),
            client_version: Some(format!("airdress-cli/{}", crate::build_version())),
        };
        let (hs, msg1) = InitiatorHandshake::start(
            &mut rand::rngs::OsRng,
            &self.keys,
            &self.target.host_static,
            &self.prologue(action),
            &hello,
        )?;
        // A reattach starts over: the old channel and its tickets are gone.
        self.ch = None;
        self.ticket = None;
        self.prev = None;
        self.heard = false;
        self.pending = Some((hs, action, None));
        Ok(msg1)
    }

    /// Start a resume with the current ticket: the ticket id (in the clear)
    /// and message 1. [`ProtoError::ResumeExpired`] when there is none.
    pub fn begin_resume(&mut self) -> Result<(TicketId, Vec<u8>)> {
        let ch = self.ch.as_ref().ok_or(ProtoError::ResumeExpired)?;
        let ticket = self.ticket.ok_or(ProtoError::ResumeExpired)?;
        let secret = *ch.resume_secret();
        self.fell_back = false;
        self.resume_with(ticket, secret)
    }

    /// The host refused the current ticket: try the one the last resume
    /// redeemed, once per reconnect.
    pub fn fallback_resume(&mut self) -> Result<(TicketId, Vec<u8>)> {
        if self.fell_back {
            return Err(ProtoError::ResumeExpired);
        }
        let (ticket, secret) = self.prev.ok_or(ProtoError::ResumeExpired)?;
        self.fell_back = true;
        self.resume_with(ticket, secret)
    }

    fn resume_with(&mut self, ticket: TicketId, secret: [u8; 32]) -> Result<(TicketId, Vec<u8>)> {
        let hello = DeviceHello {
            device: self.target.device.clone(),
            cols: None,
            rows: None,
            client_version: None,
        };
        let (hs, msg1) = InitiatorHandshake::start_resume(
            &mut rand::rngs::OsRng,
            &self.keys,
            &self.target.host_static,
            &self.prologue(Action::Resume),
            &secret,
            &hello,
        )?;
        self.pending = Some((hs, Action::Resume, Some((ticket, secret))));
        Ok((ticket, msg1))
    }

    /// Whether a handshake is waiting for message 2.
    pub fn awaiting_msg2(&self) -> bool {
        self.pending.is_some()
    }

    /// Read message 2. Returns the records to send: the first one (presence
    /// `none` after an open or attach; an `ack` after a resume), and after
    /// an open or attach the credit.
    pub fn finish(&mut self, msg2: &[u8], now_ms: u64) -> Result<(HostHello, Vec<Vec<u8>>)> {
        let (hs, action, used) = self
            .pending
            .take()
            .ok_or(ProtoError::InvalidInput("no handshake in flight"))?;
        let (mut ch, hello) = hs.finish(msg2, now_ms)?;
        // The redeemed ticket stays valid until the host is heard on this
        // leg (N-4); it is the way back if this leg is lost first.
        self.prev = used;
        self.ticket = Some(ticket_from_hello(&hello)?);
        // An open or an attach is live once the host has admitted this
        // device and said so (its snapshot or roles); a resume at once (see
        // [`Self::is_live`]). The fallback ticket stays until a record comes
        // either way (N-4).
        self.heard = action == Action::Resume;
        let mut first = match action {
            Action::Resume => vec![Message::Ack {
                offset: self.delivered,
            }],
            a => vec![Message::Presence {
                action: a,
                alg: PresenceAlg::None,
                sig: None,
            }],
        };
        first.push(Message::Credit {
            bytes: CREDIT_BYTES,
        });
        let rec = ch.seal(&Message::encode_all(&first)?, now_ms)?;
        self.acked = self.delivered;
        self.ch = Some(ch);
        Ok((hello, vec![rec]))
    }

    /// Seal messages on the live channel.
    pub fn seal(&mut self, msgs: &[Message], now_ms: u64) -> Result<Vec<u8>> {
        if msgs.iter().any(|m| matches!(m, Message::Ack { .. })) {
            self.acked = self.delivered;
        }
        let ch = self
            .ch
            .as_mut()
            .ok_or(ProtoError::InvalidInput("no channel"))?;
        ch.seal(&Message::encode_all(msgs)?, now_ms)
    }

    /// An ack, when enough output arrived since the last one.
    pub fn ack_due(&self) -> bool {
        self.ch.is_some() && self.delivered.saturating_sub(self.acked) >= ACK_EVERY
    }

    /// Whether any output is unacknowledged.
    pub fn unacked(&self) -> bool {
        self.ch.is_some() && self.delivered > self.acked
    }

    /// A rekey announcement, when this direction's key is due (1 h or 1 GiB).
    pub fn rekey_if_due(&mut self, now_ms: u64) -> Result<Option<Vec<u8>>> {
        match self.ch.as_mut() {
            Some(ch) if ch.rekey_due(now_ms) => Ok(Some(seal_rekey(ch, false, now_ms)?)),
            _ => Ok(None),
        }
    }

    /// The channel is gone for good (closed, ended, revoked).
    pub fn forget(&mut self) {
        self.ch = None;
        self.ticket = None;
        self.prev = None;
        self.pending = None;
    }

    /// A record from the host. Returns what it means, and records to send
    /// back (a rekey answer).
    pub fn receive(&mut self, record: &[u8], now_ms: u64) -> Result<(Vec<Event>, Vec<Vec<u8>>)> {
        let ch = self
            .ch
            .as_mut()
            .ok_or(ProtoError::InvalidInput("no channel"))?;
        let (_, pt) = ch.open(record)?;
        // Heard on this leg: the redeemed ticket is spent.
        self.heard = true;
        self.prev = None;
        let mut events = Vec::new();
        let mut replies = Vec::new();
        for m in Message::decode_all(&pt)? {
            match m {
                Message::Out { offset, data } => {
                    if let Some(out) = self.accept(offset, data) {
                        events.push(Event::Output(out));
                    }
                }
                Message::Snapshot {
                    offset,
                    cols,
                    rows,
                    data,
                } => {
                    self.delivered = offset;
                    self.ahead
                        .retain(|o, d| o.saturating_add(d.len() as u64) > offset);
                    events.push(Event::Redraw { cols, rows, data });
                    if let Some(out) = self.drain() {
                        events.push(Event::Output(out));
                    }
                }
                Message::Roles {
                    typist,
                    viewers,
                    reason,
                } => events.push(Event::Roles {
                    typist,
                    viewers,
                    reason,
                }),
                Message::Exit { code, signal } => events.push(Event::Exit { code, signal }),
                Message::HostStopping { in_seconds } => {
                    events.push(Event::HostStopping { in_seconds })
                }
                Message::Error { code, message } => events.push(Event::Error { code, message }),
                Message::Rekey { switch_at, request } => {
                    let ch = self.ch.as_mut().expect("checked above");
                    ch.note_peer_rekey(switch_at);
                    if request {
                        replies.push(seal_rekey(ch, false, now_ms)?);
                    }
                }
                Message::RecordingListing { recordings } => {
                    events.push(Event::RecordingListing(recordings))
                }
                Message::RecordingHeader {
                    recording,
                    segment,
                    header,
                } => events.push(Event::RecordingHeader {
                    recording,
                    segment,
                    header,
                }),
                Message::RecordingChunk {
                    segment,
                    index,
                    sealed,
                } => events.push(Event::RecordingChunk {
                    segment,
                    index,
                    sealed,
                }),
                Message::Structured { body } => events.push(Event::Structured(body)),
                // Client-to-host messages arriving here are a host bug; they
                // carry nothing to show.
                _ => {}
            }
        }
        Ok((events, replies))
    }

    /// Take `data` at `offset` into the stream: what is new and in order is
    /// returned, what is early waits, what was already delivered is dropped.
    fn accept(&mut self, offset: u64, data: Vec<u8>) -> Option<Vec<u8>> {
        if offset > self.delivered {
            let keep = match self.ahead.get(&offset) {
                Some(have) => data.len() > have.len(),
                None => true,
            };
            if keep {
                self.ahead.insert(offset, data);
            }
            return None;
        }
        let end = offset + data.len() as u64;
        let mut out = Vec::new();
        if end > self.delivered {
            out.extend_from_slice(&data[(self.delivered - offset) as usize..]);
            self.delivered = end;
        }
        if let Some(more) = self.drain() {
            out.extend(more);
        }
        (!out.is_empty()).then_some(out)
    }

    fn drain(&mut self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        while let Some((&o, _)) = self.ahead.iter().next() {
            if o > self.delivered {
                break;
            }
            let d = self.ahead.remove(&o).expect("present");
            let end = o + d.len() as u64;
            if end > self.delivered {
                out.extend_from_slice(&d[(self.delivered - o) as usize..]);
                self.delivered = end;
            }
        }
        (!out.is_empty()).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ClientSession {
        ClientSession::new(
            Target {
                airdress: "a.example".into(),
                machine: "m".into(),
                host_static: [9; 32],
                profile: "p".into(),
                device: "d".into(),
            },
            ShellKeypair::from_secret([1; 32]),
            "s",
        )
    }

    #[test]
    fn output_is_reassembled_by_offset_and_never_repeated() {
        let mut s = session();
        assert_eq!(s.accept(0, b"one".to_vec()), Some(b"one".to_vec()));
        // Early: held back.
        assert_eq!(s.accept(6, b"two".to_vec()), None);
        // A duplicate of what was delivered: dropped.
        assert_eq!(s.accept(0, b"one".to_vec()), None);
        // Overlapping: only the new part, then what waited.
        assert_eq!(s.accept(2, b"e, t".to_vec()), Some(b", ttwo".to_vec()));
        assert_eq!(s.delivered(), 9);
    }

    #[test]
    fn a_resume_without_a_channel_is_expired() {
        let mut s = session();
        assert_eq!(s.begin_resume().unwrap_err(), ProtoError::ResumeExpired);
        assert_eq!(s.fallback_resume().unwrap_err(), ProtoError::ResumeExpired);
        assert!(!s.can_resume());
    }
}
