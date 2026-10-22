//! The session names live on an airdress, read from the bus.
//!
//! Routing a mention needs to know whether a name someone wrote belongs
//! to another live session (then it is not this session's message) or to
//! nobody (a typo: push it, so it is never dropped silently). Phase A of
//! SPEC-166 reads that from the bus's session listing, where each named
//! session's label starts `@<name> · `. The device host keeping its own
//! list of the names waiting on it is phase B (design §5.2).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::mcp::names;
use crate::mcp::session::Session;

/// How long a listing is trusted before a mention reads it again.
const FRESH: Duration = Duration::from_secs(15);

/// Names held by live sessions, as one session sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveNames {
    /// Every name a live session other than this one holds.
    pub others: Vec<String>,
    /// The names of the sessions on this session's own device, this one
    /// included: who shares one device host, and so one chat inbox.
    pub here: Vec<String>,
}

/// Split a bus `/sessions` listing into [`LiveNames`]. `me` is this
/// session's bus id, if it has one; its enrollment says which rows share
/// its device.
pub fn from_listing(listing: &Value, me: Option<&str>, my_name: &str) -> LiveNames {
    let rows = listing["sessions"].as_array().cloned().unwrap_or_default();
    let my_enrollment = me.and_then(|id| {
        rows.iter()
            .find(|r| r["id"].as_str() == Some(id))
            .and_then(|r| r["enrollment_id"].as_str().map(str::to_owned))
    });
    let mut out = LiveNames {
        here: vec![my_name.to_owned()],
        ..LiveNames::default()
    };
    for r in &rows {
        if me.is_some() && r["id"].as_str() == me {
            continue;
        }
        let Some(name) = names::of_row(r) else {
            continue;
        };
        if !out.others.contains(&name) {
            out.others.push(name.clone());
        }
        let same_device =
            my_enrollment.is_some() && r["enrollment_id"].as_str() == my_enrollment.as_deref();
        if same_device && !out.here.contains(&name) {
            out.here.push(name);
        }
    }
    out
}

/// The bus's view joined with the device host's `names_here`: the host
/// knows every session waiting on this machine, the bus also the ones
/// elsewhere. With neither, nothing is known and routing pushes.
pub fn with_host(bus: Option<LiveNames>, host: Option<&[String]>, me: &str) -> Option<LiveNames> {
    let Some(host) = host else {
        return bus;
    };
    let mut l = bus.unwrap_or_else(|| LiveNames {
        here: vec![me.to_owned()],
        ..LiveNames::default()
    });
    // On this machine, the host is the authority on who is here.
    l.here = host.to_vec();
    if !l.here.iter().any(|n| n == me) {
        l.here.push(me.to_owned());
    }
    for n in host {
        if n != me && !l.others.contains(n) {
            l.others.push(n.clone());
        }
    }
    Some(l)
}

/// The live names on `fqdn`, read again when the cached listing is stale
/// or does not know a name that was just mentioned (a session that has
/// only just started). `None` when the bus cannot be read: routing then
/// pushes rather than guesses.
pub async fn get(session: &Arc<Session>, fqdn: &str, mentioned: &[String]) -> Option<LiveNames> {
    let me = session.name();
    if let Some(l) = session.cached_live_names(FRESH).await {
        let known = |m: &String| *m == me || l.others.contains(m);
        if mentioned.iter().all(known) {
            return Some(l);
        }
    }
    let listing = crate::mcp::bus::sessions_listing(session, fqdn)
        .await
        .ok()?;
    let my_id = crate::mcp::bus::own_session_id(session, fqdn).await;
    let l = from_listing(&listing, my_id.as_deref(), &me);
    session.set_live_names(l.clone()).await;
    Some(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_listing_gives_other_names_and_this_devices_names() {
        let listing = json!({"sessions": [
            {"id": "s-me", "label": "@bob · laptop · repo", "enrollment_id": "e-laptop"},
            {"id": "s-a", "label": "@alice · laptop · other", "enrollment_id": "e-laptop"},
            {"id": "s-c", "label": "@carol · framework · x", "enrollment_id": "e-fw"},
            {"id": "s-d", "label": "framework · unnamed", "enrollment_id": "e-fw"},
        ]});
        let l = from_listing(&listing, Some("s-me"), "bob");
        assert_eq!(l.others, ["alice", "carol"]);
        assert_eq!(l.here, ["bob", "alice"]);
        // Not on the bus itself: every name is someone else's, and only
        // this session is known to be here.
        let l = from_listing(&listing, None, "quiet-otter");
        assert_eq!(l.others, ["bob", "alice", "carol"]);
        assert_eq!(l.here, ["quiet-otter"]);
    }

    #[test]
    fn the_device_host_adds_sessions_the_bus_does_not_know() {
        let host = ["bob".to_owned(), "carol".to_owned()];
        // carol never joined the bus: the host still knows she is here.
        let bus = LiveNames {
            others: vec!["alice".into()],
            here: vec!["bob".into()],
        };
        let l = with_host(Some(bus), Some(&host), "bob").unwrap();
        assert_eq!(l.others, ["alice", "carol"]);
        assert_eq!(l.here, ["bob", "carol"]);
        // The bus unreadable: the host alone.
        let l = with_host(None, Some(&host), "bob").unwrap();
        assert_eq!(l.others, ["carol"]);
        // An older host: the bus alone, unchanged.
        assert_eq!(with_host(None, None, "bob"), None);
    }
}
