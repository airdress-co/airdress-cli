//! Which transport the host channel rides, and what worked where (FR-H7;
//! the negotiation of the home channel's library, in Rust).
//!
//! - **Prefer the WebSocket**, and fall back to the long-poll when its
//!   establishment is refused on the way (a proxy that answers the upgrade
//!   with anything but `101`, or cuts it).
//! - **Demote a transport that keeps dropping early:** three channels in a
//!   row that ended within 120 s of their `hello`, for a reason that is not
//!   the operator's own (a lifetime close, a revoke, an unlink, a
//!   displacement, a protocol close) and not a close the host made.
//! - **Remember per network** what worked, so the next start there does not
//!   pay for the refusal again.
//! - **Re-probe the preferred transport** six hours after it last failed on
//!   that network. A re-probed transport that drops early once is demoted
//!   again at once.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Ws,
    Poll,
}

impl Transport {
    /// As the operator reports it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Poll => "poll",
        }
    }
}

/// A channel shorter than this after its `hello` dropped early.
pub const EARLY_DROP: Duration = Duration::from_secs(120);
/// This many early drops in a row demote a transport on a network.
pub const EARLY_DROPS: u32 = 3;
/// After the preferred transport failed on a network, it is tried first
/// there again after this long.
pub const REPROBE: Duration = Duration::from_secs(6 * 3600);

/// Close codes that are the operator's decision, not the transport failing:
/// lifetime, revoked, unlinked, displaced, protocol, disabled.
pub const OPERATOR_CLOSES: [u16; 6] = [4001, 4003, 4004, 4008, 4009, 4010];

/// What worked on one network.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    pub transport: Transport,
    /// Wall-clock seconds the hint was last set.
    pub since: f64,
    /// When the preferred transport last failed here, if it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_failed: Option<f64>,
}

/// How a channel ended, for [`Negotiator::settled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The host closed it (stopping): never counted.
    ByHost,
    /// The operator closed it with this code.
    Code(u16),
    /// It dropped: a reset, an idle timeout, an end of stream.
    Dropped,
}

/// The negotiation's state. Pure: the caller does the I/O and the clock.
#[derive(Debug, Clone)]
pub struct Negotiator {
    order: Vec<Transport>,
    pub hints: BTreeMap<String, Hint>,
    early: BTreeMap<Transport, u32>,
    reprobing: bool,
    pub early_drop: Duration,
    pub early_drops: u32,
    pub reprobe: Duration,
}

impl Negotiator {
    /// Transports in their default order, preferred first.
    pub fn new(order: Vec<Transport>, hints: BTreeMap<String, Hint>) -> Self {
        assert!(!order.is_empty(), "at least one transport");
        Self {
            order,
            hints,
            early: BTreeMap::new(),
            reprobing: false,
            early_drop: EARLY_DROP,
            early_drops: EARLY_DROPS,
            reprobe: REPROBE,
        }
    }

    fn preferred(&self) -> Transport {
        self.order[0]
    }

    /// The transports to try on `net`, in order, and whether this is a
    /// re-probe of the preferred one.
    pub fn plan(&self, net: &str, now: f64) -> (Vec<Transport>, bool) {
        let Some(h) = self.hints.get(net) else {
            return (self.order.clone(), false);
        };
        if h.transport == self.preferred() || !self.order.contains(&h.transport) {
            return (self.order.clone(), false);
        }
        match h.preferred_failed {
            Some(t) if now - t < self.reprobe.as_secs_f64() => {
                let mut v = vec![h.transport];
                v.extend(self.order.iter().copied().filter(|t| *t != h.transport));
                (v, false)
            }
            _ => (self.order.clone(), true),
        }
    }

    /// `opened` came up after `refused` were refused. Returns whether the
    /// hints changed (and should be saved).
    pub fn opened(
        &mut self,
        net: &str,
        opened: Transport,
        refused: &[Transport],
        reprobing: bool,
        now: f64,
    ) -> bool {
        self.reprobing = reprobing && opened == self.preferred();
        if refused.is_empty() {
            return false;
        }
        if opened == self.preferred() {
            return self.hints.remove(net).is_some();
        }
        let old = self.hints.get(net).copied();
        let preferred_failed = if refused.contains(&self.preferred()) {
            Some(now)
        } else {
            old.and_then(|h| h.preferred_failed)
        };
        self.hints.insert(
            net.to_owned(),
            Hint {
                transport: opened,
                since: now,
                preferred_failed,
            },
        );
        true
    }

    /// The channel on `transport` ended after living `lived` since its
    /// `hello`. Returns whether the hints changed.
    pub fn settled(
        &mut self,
        net: &str,
        transport: Transport,
        lived: Duration,
        ending: Ending,
        now: f64,
    ) -> bool {
        if lived >= self.early_drop {
            self.early.insert(transport, 0);
            if self.reprobing {
                // The preferred transport works here again.
                self.reprobing = false;
                return self.hints.remove(net).is_some();
            }
            return false;
        }
        match ending {
            Ending::ByHost => return false,
            Ending::Code(c) if OPERATOR_CLOSES.contains(&c) => return false,
            _ => {}
        }
        let count = self.early.get(&transport).copied().unwrap_or(0) + 1;
        self.early.insert(transport, count);
        let limit = if self.reprobing { 1 } else { self.early_drops };
        if count < limit || self.order.len() == 1 {
            return false;
        }
        self.early.insert(transport, 0);
        self.reprobing = false;
        let idx = self.order.iter().position(|t| *t == transport).unwrap_or(0);
        let following = self.order[(idx + 1) % self.order.len()];
        tracing::info!(
            from = transport.as_str(),
            to = following.as_str(),
            "a transport kept dropping early here; demoted"
        );
        if following == self.preferred() {
            return self.hints.remove(net).is_some();
        }
        let old = self.hints.get(net).copied();
        let preferred_failed = if transport == self.preferred() {
            Some(now)
        } else {
            old.and_then(|h| h.preferred_failed)
        };
        self.hints.insert(
            net.to_owned(),
            Hint {
                transport: following,
                since: now,
                preferred_failed,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n() -> Negotiator {
        Negotiator::new(vec![Transport::Ws, Transport::Poll], BTreeMap::new())
    }

    #[test]
    fn a_refused_upgrade_falls_back_and_is_remembered_per_network() {
        let mut g = n();
        assert_eq!(
            g.plan("home", 0.0),
            (vec![Transport::Ws, Transport::Poll], false)
        );
        assert!(g.opened("home", Transport::Poll, &[Transport::Ws], false, 100.0));
        assert_eq!(
            g.plan("home", 200.0).0,
            vec![Transport::Poll, Transport::Ws]
        );
        assert_eq!(
            g.plan("cafe", 200.0).0,
            vec![Transport::Ws, Transport::Poll],
            "another network starts over"
        );
    }

    #[test]
    fn the_preferred_transport_is_probed_again_after_six_hours_and_forgiven_when_it_holds() {
        let mut g = n();
        g.opened("home", Transport::Poll, &[Transport::Ws], false, 0.0);
        let later = REPROBE.as_secs_f64() + 1.0;
        let (plan, reprobing) = g.plan("home", later);
        assert!(reprobing);
        assert_eq!(plan[0], Transport::Ws);
        g.opened("home", Transport::Ws, &[], true, later);
        assert!(g.settled(
            "home",
            Transport::Ws,
            EARLY_DROP + Duration::from_secs(1),
            Ending::Dropped,
            later + 200.0
        ));
        assert!(g.hints.is_empty());
    }

    #[test]
    fn three_early_drops_demote_and_operator_closes_never_count() {
        let mut g = n();
        let short = Duration::from_secs(5);
        for code in OPERATOR_CLOSES {
            assert!(!g.settled("home", Transport::Ws, short, Ending::Code(code), 1.0));
        }
        assert!(!g.settled("home", Transport::Ws, short, Ending::ByHost, 1.0));
        assert!(!g.settled("home", Transport::Ws, short, Ending::Dropped, 1.0));
        assert!(!g.settled("home", Transport::Ws, short, Ending::Code(1006), 2.0));
        assert!(g.settled("home", Transport::Ws, short, Ending::Dropped, 3.0));
        assert_eq!(g.hints["home"].transport, Transport::Poll);
        assert_eq!(g.hints["home"].preferred_failed, Some(3.0));
        // A channel that lived resets the count.
        let mut g = n();
        g.settled("home", Transport::Ws, short, Ending::Dropped, 1.0);
        g.settled("home", Transport::Ws, short, Ending::Dropped, 1.0);
        g.settled("home", Transport::Ws, EARLY_DROP, Ending::Dropped, 1.0);
        assert!(!g.settled("home", Transport::Ws, short, Ending::Dropped, 1.0));
    }

    #[test]
    fn a_reprobe_that_drops_early_once_is_demoted_at_once() {
        let mut g = n();
        g.opened("home", Transport::Poll, &[Transport::Ws], false, 0.0);
        let later = REPROBE.as_secs_f64() + 1.0;
        g.opened("home", Transport::Ws, &[], true, later);
        assert!(g.settled(
            "home",
            Transport::Ws,
            Duration::from_secs(1),
            Ending::Dropped,
            later + 1.0
        ));
        assert_eq!(g.hints["home"].transport, Transport::Poll);
    }
}
