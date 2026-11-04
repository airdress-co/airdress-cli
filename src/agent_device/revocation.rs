//! Whether a member's device is revoked, asked of the operator of the
//! member's own airdress (check 5).
//!
//! airdress-mls v0.3.0 fails closed: an engine past the credential cutover
//! verifies no leaf until a revocation lookup is registered. Who answers
//! depends on whose device it is, read from the credential's `airdress`
//! (owner decision (a), 2026-10-08; SPEC-061 amendment "peer revocation
//! across airdresses"):
//!
//! ```text
//! this airdress:  GET <operator>/v1/mls/members/{device_id}/revocation
//!                 (the device's bearer)
//! another one:    GET https://<airdress>/v1/mls/members/{device_id}/revocation
//!                 (no credential: this device holds none there, and its
//!                 own bearer never leaves its airdress)
//! 200 {"device_id", "revoked": false, "kind"}      -> live
//! 200 {"device_id", "revoked": true, "revoked_at", "kind"} -> revoked
//! 404 member_not_found, 429, 503 revocation_unavailable -> refuse
//! ```
//!
//! **Which airdress.** The engine asks with the leaf's pin subject and its
//! device id (`RevocationLookup::device_status(subject, device_id)`,
//! airdress-mls 0.7.0): the subject is the bare airdress for an owner's
//! device and `airdress ‖ 0x1F ‖ person_id` for another person's. The
//! route is asked of the airdress before the separator; answers are
//! cached per (subject, device id), because a device id is unique only
//! under one pin subject.
//!
//! `kind` is `device`, `agent_device` or `operator_agent`; any other kind,
//! a body naming another device, a transport error or any other status is
//! a refusal too. Only a live answer is cached, and only for
//! [`LIVE_FOR`]: a revocation takes effect here within that minute, and a
//! refusal is asked again every time, so an operator that was briefly
//! unreachable does not keep a member out once it answers.
//!
//! The engine asks synchronously from inside its own calls, which the
//! device host makes from async tasks. The request therefore runs on a
//! helper thread with its own small runtime and its own client, so it
//! neither blocks the caller's runtime on itself nor shares a connection
//! pool across runtimes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use airdress_mls::credential::{DeviceStatus, RevocationLookup, IDENTITY_SEPARATOR};
use serde_json::Value;

use crate::redact::Redacted;

/// How long a live answer is believed.
pub const LIVE_FOR: Duration = Duration::from_secs(60);
/// One question's deadline: the engine is waiting on it.
const ASK_WITHIN: Duration = Duration::from_secs(10);

/// The kinds of member the route names.
const KINDS: [&str; 3] = ["device", "agent_device", "operator_agent"];

/// An answer from the route: the HTTP status and the JSON body.
pub type Answer = (u16, Value);

/// Asks the route about one device id: of this device's own operator
/// (`None`, with its bearer) or of another airdress's (`Some(airdress)`,
/// with no credential).
pub type Ask = dyn Fn(Option<&str>, &str) -> anyhow::Result<Answer> + Send + Sync;

/// What one answer means for the verifier: `Some(Active)` admits,
/// `Some(Revoked)` and `None` refuse.
pub fn status_of(device_id: &str, (status, body): &Answer) -> Option<DeviceStatus> {
    if *status != 200 {
        return None;
    }
    if body["device_id"].as_str() != Some(device_id) {
        return None;
    }
    if !body["kind"].as_str().is_some_and(|k| KINDS.contains(&k)) {
        return None;
    }
    match body["revoked"].as_bool()? {
        false => Some(DeviceStatus::Active),
        true => Some(DeviceStatus::Revoked),
    }
}

/// The lookup the engine holds: the answer of the member's own airdress's
/// operator, live answers cached for [`LIVE_FOR`] per (pin subject, device).
pub struct OperatorRevocation {
    own_airdress: String,
    ask: Box<Ask>,
    /// Keyed by (pin subject, airdress lowercased; device id).
    live: Mutex<HashMap<(String, String), Instant>>,
    live_for: Duration,
}

impl std::fmt::Debug for OperatorRevocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorRevocation")
            .field("live_for", &self.live_for)
            .finish_non_exhaustive()
    }
}

impl OperatorRevocation {
    /// Over any asker (tests hand in a fake), for a device of
    /// `own_airdress`.
    pub fn new(own_airdress: &str, ask: Box<Ask>, live_for: Duration) -> Self {
        Self {
            own_airdress: own_airdress.to_ascii_lowercase(),
            ask,
            live: Mutex::new(HashMap::new()),
            live_for: live_for.min(LIVE_FOR),
        }
    }

    /// Asking `operator` with this device's bearer about `own_airdress`'s
    /// members, and each other airdress at its own name with none.
    pub fn of_operator(operator: &str, own_airdress: &str, token: Redacted<String>) -> Arc<Self> {
        let base = operator.trim_end_matches('/').to_owned();
        Arc::new(Self::new(
            own_airdress,
            Box::new(move |peer, device_id| match peer {
                None => ask_route(&base, Some(&token), device_id),
                Some(airdress) => ask_route(&format!("https://{airdress}"), None, device_id),
            }),
            LIVE_FOR,
        ))
    }

    /// Forget every live answer, so the next question about any member is
    /// asked of its operator. Called when an envelope was left for a
    /// replay: a commit refused because this device did not yet see a
    /// member as revoked is judged again against fresh answers.
    pub fn forget_live(&self) {
        if let Ok(mut live) = self.live.lock() {
            live.clear();
        }
    }

    /// The airdress to ask, `None` for this device's own operator: this
    /// airdress and the `.local` lanes are the own operator's. `airdress`
    /// is lowercased.
    fn peer_of(&self, airdress: &str) -> Option<String> {
        if airdress == self.own_airdress || airdress.rsplit('.').next() == Some("local") {
            None
        } else {
            Some(airdress.to_owned())
        }
    }
}

/// A pin subject's airdress (lowercased) and the whole subject with that
/// airdress lowercased: the cache key's first half.
fn split_subject(subject: &str) -> (String, String) {
    let sep = char::from(IDENTITY_SEPARATOR);
    let (airdress, rest) = match subject.split_once(sep) {
        Some((a, r)) => (a.to_ascii_lowercase(), Some(r)),
        None => (subject.to_ascii_lowercase(), None),
    };
    let key = match rest {
        Some(r) => format!("{airdress}{sep}{r}"),
        None => airdress.clone(),
    };
    (airdress, key)
}

impl RevocationLookup for OperatorRevocation {
    fn device_status(&self, subject: &str, device_id: &str) -> Option<DeviceStatus> {
        let (airdress, subject_key) = split_subject(subject);
        let peer = self.peer_of(&airdress);
        let key = (subject_key, device_id.to_owned());
        if let Ok(live) = self.live.lock() {
            if live
                .get(&key)
                .is_some_and(|at| at.elapsed() < self.live_for)
            {
                return Some(DeviceStatus::Active);
            }
        }
        let status = match (self.ask)(peer.as_deref(), device_id) {
            Ok(answer) => status_of(device_id, &answer),
            Err(e) => {
                tracing::warn!(error = %e, %device_id, peer = ?peer, "revocation lookup failed; refusing");
                None
            }
        };
        if let Ok(mut live) = self.live.lock() {
            if status == Some(DeviceStatus::Active) {
                live.insert(key, Instant::now());
            } else {
                live.remove(&key);
            }
        }
        if status != Some(DeviceStatus::Active) {
            tracing::info!(%device_id, peer = ?peer, ?status, "member refused by the revocation check");
        }
        status
    }
}

/// One `GET` of the route at `base`, on a helper thread with its own
/// runtime; with `token` as the bearer when given, and no credential
/// otherwise.
fn ask_route(
    base: &str,
    token: Option<&Redacted<String>>,
    device_id: &str,
) -> anyhow::Result<Answer> {
    // The id is one path segment, escaped as one.
    let mut url = reqwest::Url::parse(base)?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("the operator address {base} cannot carry a path"))?
        .pop_if_empty()
        .extend(["v1", "mls", "members", device_id, "revocation"]);
    let bearer = token.map(|t| t.expose().clone());
    let run = move || -> anyhow::Result<Answer> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let http =
                crate::http::client_with(crate::http::Timeouts::at_most(ASK_WITHIN)).build()?;
            let req = http.get(url);
            let req = match bearer {
                Some(b) => req.bearer_auth(b),
                None => req,
            };
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let body = resp.json::<Value>().await.unwrap_or(Value::Null);
            Ok((status, body))
        })
    };
    let join = move || {
        std::thread::spawn(run)
            .join()
            .map_err(|_| anyhow::anyhow!("the revocation lookup thread panicked"))?
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(join)
        }
        _ => join(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn live(kind: &str) -> Answer {
        (
            200,
            json!({"device_id": "d1", "revoked": false, "kind": kind}),
        )
    }

    fn counting(answer: Answer) -> (OperatorRevocation, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&asked);
        let lookup = OperatorRevocation::new(
            "me.test",
            Box::new(move |_, _| {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(answer.clone())
            }),
            LIVE_FOR,
        );
        (lookup, asked)
    }

    #[test]
    fn a_revoked_device_is_refused() {
        let (l, _) = counting((
            200,
            json!({"device_id": "d1", "revoked": true,
                   "revoked_at": "2026-10-08T00:00:00Z", "kind": "device"}),
        ));
        assert_eq!(
            l.device_status("me.test", "d1"),
            Some(DeviceStatus::Revoked)
        );
    }

    #[test]
    fn not_found_and_unavailable_refuse() {
        for answer in [
            (404, json!({"error": {"code": "member_not_found"}})),
            (429, json!({"error": {"code": "too_many_requests"}})),
            (503, json!({"error": {"code": "revocation_unavailable"}})),
        ] {
            let (l, _) = counting(answer);
            assert_eq!(l.device_status("me.test", "d1"), None);
        }
        let failing = OperatorRevocation::new(
            "me.test",
            Box::new(|_, _| anyhow::bail!("offline")),
            LIVE_FOR,
        );
        assert_eq!(failing.device_status("me.test", "d1"), None);
    }

    #[test]
    fn a_live_device_and_the_operator_agent_pass() {
        for kind in ["device", "agent_device", "operator_agent"] {
            let (l, _) = counting(live(kind));
            assert_eq!(
                l.device_status("me.test", "d1"),
                Some(DeviceStatus::Active),
                "{kind}"
            );
        }
    }

    #[test]
    fn an_answer_about_another_device_or_kind_refuses() {
        let (l, _) = counting((
            200,
            json!({"device_id": "d2", "revoked": false, "kind": "device"}),
        ));
        assert_eq!(l.device_status("me.test", "d1"), None);
        let (l, _) = counting(live("stranger"));
        assert_eq!(l.device_status("me.test", "d1"), None);
        let (l, _) = counting((200, json!({"device_id": "d1", "kind": "device"})));
        assert_eq!(l.device_status("me.test", "d1"), None);
    }

    #[test]
    fn only_a_live_answer_is_cached() {
        let (l, asked) = counting(live("device"));
        l.device_status("me.test", "d1");
        l.device_status("me.test", "d1");
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        let (l, asked) = counting((503, Value::Null));
        l.device_status("me.test", "d1");
        l.device_status("me.test", "d1");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn forgetting_asks_again() {
        let (l, asked) = counting(live("device"));
        l.device_status("me.test", "d1");
        l.forget_live();
        l.device_status("me.test", "d1");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_live_answer_expires() {
        let asked = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&asked);
        let l = OperatorRevocation::new(
            "me.test",
            Box::new(move |_, _| {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(live("device"))
            }),
            Duration::ZERO,
        );
        l.device_status("me.test", "d1");
        l.device_status("me.test", "d1");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_cache_never_outlives_a_minute() {
        let l = OperatorRevocation::new(
            "me.test",
            Box::new(|_, _| Ok(live("device"))),
            Duration::from_secs(3600),
        );
        assert_eq!(l.live_for, LIVE_FOR);
    }

    /// Records which operator each question went to.
    fn routed() -> (OperatorRevocation, Arc<Mutex<Vec<Option<String>>>>) {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let lookup = OperatorRevocation::new(
            "me.test",
            Box::new(move |peer, _| {
                log.lock().unwrap().push(peer.map(str::to_owned));
                Ok(live("device"))
            }),
            LIVE_FOR,
        );
        (lookup, asked)
    }

    #[test]
    fn a_member_of_another_airdress_is_asked_of_that_airdress() {
        let (l, asked) = routed();
        assert_eq!(
            l.device_status("Peer.test", "d1"),
            Some(DeviceStatus::Active)
        );
        assert_eq!(*asked.lock().unwrap(), vec![Some("peer.test".to_owned())]);
    }

    #[test]
    fn a_person_of_another_airdress_is_asked_of_that_airdress() {
        let (l, asked) = routed();
        l.device_status("peer.test\u{1f}person-1", "d1");
        assert_eq!(*asked.lock().unwrap(), vec![Some("peer.test".to_owned())]);
    }

    #[test]
    fn this_airdress_its_people_and_a_local_lane_go_to_the_own_operator() {
        let (l, asked) = routed();
        l.device_status("ME.test", "d1");
        l.device_status("me.test\u{1f}person-1", "d2");
        l.device_status("operator.local", "d3");
        assert_eq!(*asked.lock().unwrap(), vec![None, None, None]);
    }

    #[test]
    fn a_live_answer_at_one_airdress_does_not_admit_the_id_at_another() {
        let l = OperatorRevocation::new(
            "me.test",
            Box::new(|peer, _| {
                Ok(if peer == Some("peer.test") {
                    live("device")
                } else {
                    (404, json!({"error": {"code": "member_not_found"}}))
                })
            }),
            LIVE_FOR,
        );
        assert_eq!(
            l.device_status("peer.test", "d1"),
            Some(DeviceStatus::Active)
        );
        assert_eq!(l.device_status("other.test", "d1"), None);
        assert_eq!(l.device_status("me.test", "d1"), None);
    }

    #[test]
    fn a_live_answer_for_one_person_does_not_admit_the_id_for_another() {
        let (l, asked) = routed();
        l.device_status("me.test\u{1f}person-1", "d1");
        l.device_status("me.test\u{1f}person-1", "d1");
        assert_eq!(asked.lock().unwrap().len(), 1, "cached for the pair");
        l.device_status("me.test\u{1f}person-2", "d1");
        l.device_status("me.test", "d1");
        assert_eq!(asked.lock().unwrap().len(), 3, "not for another subject");
    }

    #[test]
    fn the_subject_s_airdress_is_case_insensitive_in_the_cache() {
        let (l, asked) = routed();
        l.device_status("Peer.Test", "d1");
        l.device_status("peer.test", "d1");
        assert_eq!(asked.lock().unwrap().len(), 1);
    }
}
