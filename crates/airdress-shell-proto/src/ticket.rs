//! Resumption tickets (design §6.5, FR-E4).
//!
//! The host issues a ticket id in every msg2. Its secret is the channel's
//! resume secret, which both ends derive and neither sends. A ticket is:
//!
//! - **provisional** until its leg is admitted: after the unlock (or a
//!   CLI's `none`) for an open or attach, after the first authenticated
//!   record for a resume. A provisional ticket cannot be redeemed, so a
//!   device that completed a handshake but never unlocked cannot resume its
//!   way past the unlock. DESIGN-NOTES.md N-3;
//! - **single use on success**: when a resume is admitted, every other
//!   ticket of that session and device dies. A resume whose leg is lost
//!   before it is admitted leaves the old ticket standing, so a cut in the
//!   middle of a resume does not cost the person an unlock. DESIGN-NOTES.md
//!   N-4;
//! - valid while its leg is live and for [`TICKET_TTL_MS`] after the leg
//!   drops;
//! - dead the moment its device detaches (backgrounded past the grace), is
//!   revoked, or its session ends.
//!
//! The book holds no clock; the caller passes `now_ms`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::error::{ProtoError, Result};

/// Bytes in a ticket id.
pub const TICKET_ID_LEN: usize = 16;
/// How long a ticket outlives its leg.
pub const TICKET_TTL_MS: u64 = 120_000;

/// A ticket id. Travels in the clear beside a resume's msg1; it names the
/// secret, it is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TicketId(pub [u8; TICKET_ID_LEN]);

impl TicketId {
    /// Base64, as it travels in `resumeTicket` and `ticketId`.
    pub fn encode(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Parse the base64 form.
    pub fn decode(s: &str) -> Result<Self> {
        let raw = STANDARD
            .decode(s)
            .map_err(|_| ProtoError::InvalidInput("ticket id"))?;
        Ok(Self(raw.try_into().map_err(|_| {
            ProtoError::InvalidInput("ticket id length")
        })?))
    }
}

struct Entry {
    secret: Zeroizing<[u8; 32]>,
    session: String,
    device: String,
    dropped_at: Option<u64>,
    admitted: bool,
}

/// The host's tickets, one live ticket per (session, device).
#[derive(Default)]
pub struct TicketBook {
    entries: HashMap<TicketId, Entry>,
}

impl std::fmt::Debug for TicketBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketBook").finish_non_exhaustive()
    }
}

impl TicketBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// File the ticket a handshake just issued, provisionally.
    pub fn issue(&mut self, id: TicketId, secret: &[u8; 32], session: &str, device: &str) {
        self.entries.insert(
            id,
            Entry {
                secret: Zeroizing::new(*secret),
                session: session.to_owned(),
                device: device.to_owned(),
                dropped_at: None,
                admitted: false,
            },
        );
    }

    /// The leg the ticket was issued on has been admitted. The ticket
    /// becomes redeemable, and every other ticket of the same session and
    /// device dies: there is one way back per leg.
    pub fn admit(&mut self, id: &TicketId) {
        let Some(e) = self.entries.get_mut(id) else {
            return;
        };
        e.admitted = true;
        let (s, d) = (e.session.clone(), e.device.clone());
        self.entries
            .retain(|k, e| k == id || !(e.session == s && e.device == d));
    }

    /// The leg of (session, device) dropped at `now_ms`. An admitted
    /// ticket's 120 s start now (if they had not already); a provisional
    /// one dies with its leg.
    pub fn leg_dropped(&mut self, session: &str, device: &str, now_ms: u64) {
        self.entries
            .retain(|_, e| !(e.session == session && e.device == device && !e.admitted));
        for e in self.entries.values_mut() {
            if e.session == session && e.device == device && e.dropped_at.is_none() {
                e.dropped_at = Some(now_ms);
            }
        }
    }

    /// Look up an admitted ticket for a resume of `session` by `device`.
    /// The ticket stays until the resume is admitted ([`TicketBook::admit`]
    /// on the ticket that resume issued), or until it expires.
    pub fn redeem(
        &mut self,
        id: &TicketId,
        session: &str,
        device: &str,
        now_ms: u64,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let e = self.entries.get(id).ok_or(ProtoError::ResumeExpired)?;
        if !e.admitted || e.session != session || e.device != device {
            return Err(ProtoError::ResumeExpired);
        }
        if let Some(at) = e.dropped_at {
            if now_ms.saturating_sub(at) > TICKET_TTL_MS {
                self.entries.remove(id);
                return Err(ProtoError::ResumeExpired);
            }
        }
        Ok(e.secret.clone())
    }

    /// The device detached (closed its leg, or went to the background past
    /// its grace): no resume, only a reattach.
    pub fn detach(&mut self, session: &str, device: &str) {
        self.entries
            .retain(|_, e| !(e.session == session && e.device == device));
    }

    /// The device was revoked: every ticket it holds, on every session.
    pub fn forget_device(&mut self, device: &str) {
        self.entries.retain(|_, e| e.device != device);
    }

    /// The session ended.
    pub fn forget_session(&mut self, session: &str) {
        self.entries.retain(|_, e| e.session != session);
    }

    /// Drop every ticket past its time.
    pub fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| match e.dropped_at {
            Some(at) => now_ms.saturating_sub(at) <= TICKET_TTL_MS,
            None => true,
        });
    }

    /// How many tickets are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the book is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: TicketId = TicketId([1; TICKET_ID_LEN]);
    const T2: TicketId = TicketId([2; TICKET_ID_LEN]);

    fn admitted(b: &mut TicketBook, id: TicketId) {
        b.issue(id, &[7; 32], "s", "d");
        b.admit(&id);
    }

    #[test]
    fn a_provisional_ticket_cannot_be_redeemed() {
        let mut b = TicketBook::new();
        b.issue(T, &[7; 32], "s", "d");
        assert_eq!(b.redeem(&T, "s", "d", 0), Err(ProtoError::ResumeExpired));
        b.admit(&T);
        assert_eq!(*b.redeem(&T, "s", "d", 0).unwrap(), [7; 32]);
    }

    #[test]
    fn single_use_once_the_resume_is_admitted() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        b.redeem(&T, "s", "d", 0).unwrap();
        b.issue(T2, &[8; 32], "s", "d");
        // Not yet admitted: the old ticket still stands.
        assert!(b.redeem(&T, "s", "d", 0).is_ok());
        b.admit(&T2);
        assert_eq!(b.redeem(&T, "s", "d", 0), Err(ProtoError::ResumeExpired));
        assert!(b.redeem(&T2, "s", "d", 0).is_ok());
    }

    #[test]
    fn a_resume_lost_before_admission_keeps_the_old_ticket() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        b.leg_dropped("s", "d", 1_000);
        b.redeem(&T, "s", "d", 2_000).unwrap();
        b.issue(T2, &[8; 32], "s", "d");
        b.leg_dropped("s", "d", 3_000);
        assert_eq!(
            b.redeem(&T2, "s", "d", 3_000),
            Err(ProtoError::ResumeExpired)
        );
        assert!(b.redeem(&T, "s", "d", 3_000).is_ok());
        // ...and its clock is the first drop's, not the second's.
        assert!(b.redeem(&T, "s", "d", 1_000 + TICKET_TTL_MS + 1).is_err());
    }

    #[test]
    fn expires_120_s_after_the_drop_not_before() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        b.leg_dropped("s", "d", 1_000);
        assert!(b.redeem(&T, "s", "d", 1_000 + TICKET_TTL_MS).is_ok());
        assert_eq!(
            b.redeem(&T, "s", "d", 1_000 + TICKET_TTL_MS + 1),
            Err(ProtoError::ResumeExpired)
        );
    }

    #[test]
    fn a_live_leg_does_not_start_the_clock() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        assert!(b.redeem(&T, "s", "d", 10 * TICKET_TTL_MS).is_ok());
    }

    #[test]
    fn bound_to_session_and_device() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        assert!(b.redeem(&T, "s", "other", 0).is_err());
        assert!(b.redeem(&T, "other", "d", 0).is_err());
    }

    #[test]
    fn detach_revoke_and_end_kill_tickets() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        b.detach("s", "d");
        assert!(b.is_empty());
        admitted(&mut b, T);
        b.forget_device("d");
        assert!(b.is_empty());
        admitted(&mut b, T);
        b.forget_session("s");
        assert!(b.is_empty());
    }

    #[test]
    fn prune_drops_expired() {
        let mut b = TicketBook::new();
        admitted(&mut b, T);
        b.leg_dropped("s", "d", 0);
        b.prune(TICKET_TTL_MS + 1);
        assert!(b.is_empty());
    }

    #[test]
    fn id_round_trip() {
        assert_eq!(TicketId::decode(&T.encode()).unwrap(), T);
        assert!(TicketId::decode("AAAA").is_err());
    }
}
