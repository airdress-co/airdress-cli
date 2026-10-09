//! Whether a member's device is revoked, asked of the operator (check 5).
//!
//! airdress-mls v0.3.0 fails closed: an engine past the credential cutover
//! verifies no leaf until a revocation lookup is registered. This device
//! answers that lookup by asking its operator:
//!
//! ```text
//! GET /v1/mls/members/{device_id}/revocation      (the device's bearer)
//! 200 {"device_id", "revoked": false, "kind"}      -> live
//! 200 {"device_id", "revoked": true, "revoked_at", "kind"} -> revoked
//! 404 member_not_found, 503 revocation_unavailable -> refuse
//! ```
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

use airdress_mls::credential::{DeviceStatus, RevocationLookup};
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

/// Asks the route about one device id.
pub type Ask = dyn Fn(&str) -> anyhow::Result<Answer> + Send + Sync;

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

/// The lookup the engine holds: the operator's answer, live answers
/// cached for [`LIVE_FOR`].
pub struct OperatorRevocation {
    ask: Box<Ask>,
    live: Mutex<HashMap<String, Instant>>,
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
    /// Over any asker (tests hand in a fake).
    pub fn new(ask: Box<Ask>, live_for: Duration) -> Self {
        Self {
            ask,
            live: Mutex::new(HashMap::new()),
            live_for: live_for.min(LIVE_FOR),
        }
    }

    /// Asking `operator` with this device's bearer.
    pub fn of_operator(operator: &str, token: Redacted<String>) -> Arc<Self> {
        let base = operator.trim_end_matches('/').to_owned();
        Arc::new(Self::new(
            Box::new(move |device_id| ask_operator(&base, &token, device_id)),
            LIVE_FOR,
        ))
    }
}

impl RevocationLookup for OperatorRevocation {
    fn device_status(&self, device_id: &str) -> Option<DeviceStatus> {
        if let Ok(live) = self.live.lock() {
            if live
                .get(device_id)
                .is_some_and(|at| at.elapsed() < self.live_for)
            {
                return Some(DeviceStatus::Active);
            }
        }
        let status = match (self.ask)(device_id) {
            Ok(answer) => status_of(device_id, &answer),
            Err(e) => {
                tracing::warn!(error = %e, %device_id, "revocation lookup failed; refusing");
                None
            }
        };
        if let Ok(mut live) = self.live.lock() {
            if status == Some(DeviceStatus::Active) {
                live.insert(device_id.to_owned(), Instant::now());
            } else {
                live.remove(device_id);
            }
        }
        if status != Some(DeviceStatus::Active) {
            tracing::info!(%device_id, ?status, "member refused by the revocation check");
        }
        status
    }
}

/// One `GET` of the route, on a helper thread with its own runtime.
fn ask_operator(base: &str, token: &Redacted<String>, device_id: &str) -> anyhow::Result<Answer> {
    // The id is one path segment, escaped as one.
    let mut url = reqwest::Url::parse(base)?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("the operator address {base} cannot carry a path"))?
        .pop_if_empty()
        .extend(["v1", "mls", "members", device_id, "revocation"]);
    let bearer = token.expose().clone();
    let run = move || -> anyhow::Result<Answer> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let http =
                crate::http::client_with(crate::http::Timeouts::at_most(ASK_WITHIN)).build()?;
            let resp = http.get(url).bearer_auth(bearer).send().await?;
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
            Box::new(move |_| {
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
        assert_eq!(l.device_status("d1"), Some(DeviceStatus::Revoked));
    }

    #[test]
    fn not_found_and_unavailable_refuse() {
        for answer in [
            (404, json!({"error": {"code": "member_not_found"}})),
            (503, json!({"error": {"code": "revocation_unavailable"}})),
        ] {
            let (l, _) = counting(answer);
            assert_eq!(l.device_status("d1"), None);
        }
        let failing = OperatorRevocation::new(Box::new(|_| anyhow::bail!("offline")), LIVE_FOR);
        assert_eq!(failing.device_status("d1"), None);
    }

    #[test]
    fn a_live_device_and_the_operator_agent_pass() {
        for kind in ["device", "agent_device", "operator_agent"] {
            let (l, _) = counting(live(kind));
            assert_eq!(l.device_status("d1"), Some(DeviceStatus::Active), "{kind}");
        }
    }

    #[test]
    fn an_answer_about_another_device_or_kind_refuses() {
        let (l, _) = counting((
            200,
            json!({"device_id": "d2", "revoked": false, "kind": "device"}),
        ));
        assert_eq!(l.device_status("d1"), None);
        let (l, _) = counting(live("stranger"));
        assert_eq!(l.device_status("d1"), None);
        let (l, _) = counting((200, json!({"device_id": "d1", "kind": "device"})));
        assert_eq!(l.device_status("d1"), None);
    }

    #[test]
    fn only_a_live_answer_is_cached() {
        let (l, asked) = counting(live("device"));
        l.device_status("d1");
        l.device_status("d1");
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        let (l, asked) = counting((503, Value::Null));
        l.device_status("d1");
        l.device_status("d1");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_live_answer_expires() {
        let asked = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&asked);
        let l = OperatorRevocation::new(
            Box::new(move |_| {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(live("device"))
            }),
            Duration::ZERO,
        );
        l.device_status("d1");
        l.device_status("d1");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_cache_never_outlives_a_minute() {
        let l =
            OperatorRevocation::new(Box::new(|_| Ok(live("device"))), Duration::from_secs(3600));
        assert_eq!(l.live_for, LIVE_FOR);
    }
}
