//! The host's end of every end-to-end channel (design §6.3–§6.7, FR-E).
//!
//! One channel per (session, device), keyed by the operator's leg id. The
//! operator carries msg1 in a signed `open` or `attach` frame and the rest as
//! opaque `data` records; this module turns them into admitted legs and
//! inner messages, and seals what goes back.
//!
//! The order is the design's, and nothing is spawned or attached before the
//! last step:
//!
//! - step 1, the frame's operator signature — checked by the channel before
//!   the frame gets here;
//! - steps 2–6, the attestation ([`crate::trust::check_attestation`]);
//! - step 7, the Noise handshake with the attested `dhPublic`;
//! - step 8, the device's first record: a phone's unlock signature over the final
//!   handshake hash, or a CLI's `none`. A resume is admitted on its first
//!   authenticated record instead (DESIGN-NOTES N-2).
//!
//! Tickets follow the protocol crate's book: provisional until the leg is
//! admitted, single use once a resume is admitted, 120 s after a drop.

use std::collections::HashMap;

use airdress_shell_proto::handshake::{Channel, HostHello, ResponderHandshake};
use airdress_shell_proto::inner::{seal_rekey, Message};
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::presence::{admit, PresenceAlg, PresenceRequirement};
use airdress_shell_proto::prologue::{Action, Prologue};
use airdress_shell_proto::ticket::{TicketBook, TicketId};
use airdress_shell_proto::ProtoError;
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::trust::Verified;

#[derive(Debug)]
enum LegState {
    AwaitPresence(Action, PresenceRequirement),
    AwaitConfirm,
    Live,
}

struct Leg {
    session: Uuid,
    device: Uuid,
    ch: Channel,
    state: LegState,
    ticket: TicketId,
    /// Whether this leg verified a phone's unlock.
    unlocked: bool,
}

/// A leg the host just admitted: from here on the session may serve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub leg: Uuid,
    pub session: Uuid,
    pub device: Uuid,
    /// `Open`, `Attach` or `Resume`.
    pub action: Action,
    /// A phone's unlock was verified (never for a resume or a CLI).
    pub unlocked: bool,
}

/// What a device's record held.
#[derive(Debug, Default)]
pub struct Received {
    /// Set on the record that admitted the leg.
    pub admitted: Option<Admitted>,
    /// The inner messages for the session. `rekey` is handled here.
    pub messages: Vec<Message>,
    /// Records to send back on the same leg (a rekey answer).
    pub replies: Vec<Vec<u8>>,
}

/// What a handshake is for.
pub struct Handshake<'a> {
    pub session: Uuid,
    pub leg: Uuid,
    pub profile: &'a str,
    pub action: Action,
    /// The redeemed ticket, for a resume.
    pub resume: Option<TicketId>,
    pub msg1: &'a [u8],
    pub hello: HostHello,
}

impl std::fmt::Debug for Handshake<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("session", &self.session)
            .field("leg", &self.leg)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// The host's end of every channel.
pub struct Endpoint {
    keys: ShellKeypair,
    airdress: String,
    machine: Uuid,
    legs: HashMap<Uuid, Leg>,
    tickets: TicketBook,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("legs", &self.legs.len())
            .field("tickets", &self.tickets.len())
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// The end of `machine` on `airdress`, with the host's shell key.
    pub fn new(keys: ShellKeypair, airdress: &str, machine: Uuid) -> Self {
        Self {
            keys,
            airdress: airdress.to_owned(),
            machine,
            legs: HashMap::new(),
            tickets: TicketBook::new(),
        }
    }

    /// The host's X25519 shell key.
    pub fn public(&self) -> [u8; 32] {
        *self.keys.public()
    }

    fn prologue(&self, session: Uuid, profile: &str, action: Action) -> Prologue {
        Prologue {
            airdress: self.airdress.clone(),
            machine_id: self.machine.to_string(),
            session_id: session.to_string(),
            profile_id: profile.to_owned(),
            action,
        }
    }

    /// Step 7: answer msg1 for a device that passed steps 2–6. Returns msg2
    /// and the device's hello. The leg waits for its first record.
    pub fn accept(
        &mut self,
        device: &Verified,
        hs: Handshake<'_>,
        now_ms: u64,
    ) -> Result<(Vec<u8>, airdress_shell_proto::handshake::DeviceHello), ProtoError> {
        let psk = match (hs.action, hs.resume.as_ref()) {
            (Action::Resume, Some(t)) => Some(self.tickets.redeem(
                t,
                &hs.session.to_string(),
                &device.device.to_string(),
                now_ms,
            )?),
            (Action::Resume, None) => return Err(ProtoError::ResumeExpired),
            _ => None,
        };
        let pro = self.prologue(hs.session, hs.profile, hs.action);
        let (rsp, hello) = ResponderHandshake::read(
            &mut OsRng,
            &self.keys,
            &pro,
            &device.dh,
            psk.as_deref(),
            hs.msg1,
        )?;
        if hello.device != device.device.to_string() {
            return Err(ProtoError::Handshake("hello names another device"));
        }
        let (ch, ticket, msg2) = rsp.respond(&mut OsRng, hs.hello, now_ms)?;
        if hs.action != Action::Resume {
            // A full handshake replaces whatever way back the device had.
            self.tickets
                .detach(&hs.session.to_string(), &device.device.to_string());
        }
        self.tickets.issue(
            ticket,
            ch.resume_secret(),
            &hs.session.to_string(),
            &device.device.to_string(),
        );
        // One leg per (session, device): a new one replaces the old.
        self.legs
            .retain(|_, l| !(l.session == hs.session && l.device == device.device));
        let state = match hs.action {
            Action::Resume => LegState::AwaitConfirm,
            a => LegState::AwaitPresence(a, device.requirement.clone()),
        };
        self.legs.insert(
            hs.leg,
            Leg {
                session: hs.session,
                device: device.device,
                ch,
                state,
                ticket,
                unlocked: false,
            },
        );
        Ok((msg2, hello))
    }

    /// A record from a device. An error means the leg is refused and gone.
    pub fn receive(
        &mut self,
        leg_id: Uuid,
        record: &[u8],
        now_ms: u64,
    ) -> Result<Received, ProtoError> {
        let leg = self
            .legs
            .get_mut(&leg_id)
            .ok_or(ProtoError::InvalidInput("no such leg"))?;
        let (_, pt) = match leg.ch.open(record) {
            Ok(x) => x,
            Err(e) => {
                // A record that does not open on a leg not yet admitted ends
                // it; on a live leg it is dropped (a replay, a duplicate).
                if !matches!(leg.state, LegState::Live) {
                    self.legs.remove(&leg_id);
                }
                return Err(e);
            }
        };
        let msgs = match Message::decode_all(&pt) {
            Ok(m) => m,
            Err(e) => {
                if !matches!(leg.state, LegState::Live) {
                    self.legs.remove(&leg_id);
                }
                return Err(e);
            }
        };
        let mut out = Received::default();
        let mut msgs = msgs.into_iter().peekable();
        match std::mem::replace(&mut leg.state, LegState::Live) {
            LegState::AwaitPresence(expected, req) => {
                let first = msgs.next();
                let Some(Message::Presence { action, alg, sig }) = first else {
                    self.legs.remove(&leg_id);
                    return Err(ProtoError::PresenceRequired(
                        "the first record is not presence",
                    ));
                };
                if let Err(e) = admit(
                    &req,
                    leg.ch.handshake_hash(),
                    expected,
                    action,
                    alg,
                    sig.as_deref(),
                ) {
                    self.legs.remove(&leg_id);
                    return Err(e);
                }
                leg.unlocked = alg == PresenceAlg::P256;
                self.tickets.admit(&leg.ticket);
                out.admitted = Some(Admitted {
                    leg: leg_id,
                    session: leg.session,
                    device: leg.device,
                    action: expected,
                    unlocked: leg.unlocked,
                });
            }
            LegState::AwaitConfirm => {
                self.tickets.admit(&leg.ticket);
                out.admitted = Some(Admitted {
                    leg: leg_id,
                    session: leg.session,
                    device: leg.device,
                    action: Action::Resume,
                    unlocked: false,
                });
            }
            LegState::Live => {}
        }
        let leg = self.legs.get_mut(&leg_id).expect("still here");
        for m in msgs {
            match m {
                Message::Rekey { switch_at, request } => {
                    leg.ch.note_peer_rekey(switch_at);
                    if request {
                        out.replies.push(seal_rekey(&mut leg.ch, false, now_ms)?);
                    }
                }
                Message::Presence { .. } => {
                    return Err(ProtoError::PresenceRequired("presence on a live leg"));
                }
                other => out.messages.push(other),
            }
        }
        Ok(out)
    }

    /// Seal `msgs` for `leg`. `None` when the leg is gone or not admitted.
    pub fn seal(&mut self, leg_id: Uuid, msgs: &[Message], now_ms: u64) -> Option<Vec<u8>> {
        let leg = self.legs.get_mut(&leg_id)?;
        if !matches!(leg.state, LegState::Live) {
            return None;
        }
        let pt = Message::encode_all(msgs).ok()?;
        leg.ch.seal(&pt, now_ms).ok()
    }

    /// The leg dropped. `keep_ticket` when the device may come back within
    /// 120 s without a new handshake (a lost connection, `peer_gone`);
    /// otherwise its way back dies with it.
    pub fn drop_leg(
        &mut self,
        leg_id: Uuid,
        keep_ticket: bool,
        now_ms: u64,
    ) -> Option<(Uuid, Uuid)> {
        let leg = self.legs.remove(&leg_id)?;
        let (s, d) = (leg.session.to_string(), leg.device.to_string());
        if keep_ticket {
            self.tickets.leg_dropped(&s, &d, now_ms);
        } else {
            self.tickets.detach(&s, &d);
        }
        Some((leg.session, leg.device))
    }

    /// Design §6.7 step 1: every channel of `device` closed, its keys and
    /// tickets gone. Returns the legs that were cut, with their sessions.
    pub fn forget_device(&mut self, device: Uuid) -> Vec<(Uuid, Uuid)> {
        let cut: Vec<(Uuid, Uuid)> = self
            .legs
            .iter()
            .filter(|(_, l)| l.device == device)
            .map(|(id, l)| (*id, l.session))
            .collect();
        for (id, _) in &cut {
            // Dropping the channel zeroes its keys and resume secret.
            self.legs.remove(id);
        }
        self.tickets.forget_device(&device.to_string());
        cut
    }

    /// The session ended: its legs and tickets go.
    pub fn forget_session(&mut self, session: Uuid) -> Vec<Uuid> {
        let gone: Vec<Uuid> = self
            .legs
            .iter()
            .filter(|(_, l)| l.session == session)
            .map(|(id, _)| *id)
            .collect();
        for id in &gone {
            self.legs.remove(id);
        }
        self.tickets.forget_session(&session.to_string());
        gone
    }

    /// Design §6.7 step 2: rekey `leg`, asking the device to rekey its own
    /// direction too. The record is the last under the old key.
    pub fn rekey(&mut self, leg_id: Uuid, request: bool, now_ms: u64) -> Option<Vec<u8>> {
        let leg = self.legs.get_mut(&leg_id)?;
        if !matches!(leg.state, LegState::Live) {
            return None;
        }
        seal_rekey(&mut leg.ch, request, now_ms).ok()
    }

    /// The legs whose scheduled rekey (1 h or 1 GiB) is due.
    pub fn due_for_rekey(&self, now_ms: u64) -> Vec<Uuid> {
        self.legs
            .iter()
            .filter(|(_, l)| matches!(l.state, LegState::Live) && l.ch.rekey_due(now_ms))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Expired tickets go.
    pub fn prune(&mut self, now_ms: u64) {
        self.tickets.prune(now_ms);
    }

    /// The device and session of a leg.
    pub fn leg(&self, leg_id: Uuid) -> Option<(Uuid, Uuid)> {
        self.legs.get(&leg_id).map(|l| (l.session, l.device))
    }

    /// The live leg of `device` on `session`.
    pub fn leg_of(&self, session: Uuid, device: Uuid) -> Option<Uuid> {
        self.legs
            .iter()
            .find(|(_, l)| {
                l.session == session && l.device == device && matches!(l.state, LegState::Live)
            })
            .map(|(id, _)| *id)
    }

    /// Every leg (admitted or not) of a session.
    pub fn legs_of(&self, session: Uuid) -> Vec<(Uuid, Uuid)> {
        self.legs
            .iter()
            .filter(|(_, l)| l.session == session)
            .map(|(id, l)| (*id, l.device))
            .collect()
    }

    /// How many tickets are held.
    pub fn tickets(&self) -> usize {
        self.tickets.len()
    }

    /// How many legs are held.
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    /// The next nonce a leg will send under (for tests of a rekey).
    pub fn next_send_nonce(&self, leg_id: Uuid) -> Option<u64> {
        self.legs.get(&leg_id).map(|l| l.ch.next_send_nonce())
    }
}
