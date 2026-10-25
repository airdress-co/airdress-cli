//! The map tools: `map_search`, `map_area`, `map_layers` and `map_link`
//! (maps SPEC-171 phase B).
//!
//! Searches go through the person's own operator (`/v1/maps/…`), which
//! asks the map's front with its own maps token: the hub is not told when
//! somebody uses the map, and no token for the map is held here (D-22).
//! `map_link` calls nothing at all. The answers are links to the map's
//! state; what a place is like is not something these tools say (D-6).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use airdress_mcp_catalogue::{MAP_CATEGORY_WORDS, MAP_DECLINE, MAP_MAY_HAVE_CLOSED};
use airdress_place::link::{link, options_from_catalogue, snapshot, CATALOGUE_SNAPSHOT};
use airdress_place::search::{
    is_category_query, names_a_place, remainder, shape_area, shape_result, AREA_LAYERS,
};
use airdress_place::Options;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::mcp::session::{Session, Target};

/// How long a layer catalogue answer stands in for the switch defaults,
/// as the tool bridge refreshes its own answer.
const CATALOGUE_FRESH: Duration = Duration::from_secs(300);

/// The most results a search returns.
const LIMIT_MAX: i64 = 10;

/// The last layer catalogue an airdress answered with, and when. One per
/// process: every airdress reads the same map.
fn cached() -> &'static Mutex<Option<(Instant, String)>> {
    static C: OnceLock<Mutex<Option<(Instant, String)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// The address options a link is written with: the last live catalogue
/// while it is fresh, otherwise the one this build carries.
fn link_options() -> (Options, &'static str) {
    let fresh = cached().lock().ok().and_then(|c| {
        c.as_ref()
            .filter(|(at, _)| at.elapsed() < CATALOGUE_FRESH)
            .map(|(_, t)| t.clone())
    });
    match fresh.and_then(|t| options_from_catalogue(&t)) {
        Some(o) => (o, "airdress"),
        None => (snapshot(), "snapshot"),
    }
}

/// Whether the session's profile holds a sign-in, read from disk only.
fn signed_in(session: &Session) -> bool {
    session
        .paths()
        .and_then(|p| crate::auth::status::report(p, session.profile_name().ok().as_deref()))
        .is_ok_and(|r| r.status == "authenticated")
}

/// `map_link`: no airdress, no call. Signed-in by product rule only (D-23).
pub fn map_link(session: &Session, args: &Value) -> Result<Value> {
    if !signed_in(session) {
        bail!("Not signed in: call the login tool first, then ask again.");
    }
    let (o, from) = link_options();
    let mut out = link(args, &o).to_json();
    out["switches_from"] = json!(from);
    Ok(out)
}

/// Why the operator refused a map request, in the sentence a model can act on.
fn refusal(status: u16, body: &str) -> anyhow::Error {
    let kind = ["maps_not_configured", "maps_throttled", "maps_unavailable"]
        .into_iter()
        .find(|k| body.contains(k));
    anyhow!(match (status, kind) {
        (_, Some("maps_not_configured")) => {
            "This airdress has no map access set up, so it cannot search the map.".to_owned()
        }
        (429, _) | (_, Some("maps_throttled")) => {
            "The map search is busy: wait a minute before asking again.".to_owned()
        }
        (404, None) =>
            "This airdress's operator does not answer map searches yet: it needs a newer \
                        release."
                .to_owned(),
        (401 | 403, None) => "The airdress refused the map request for this sign-in.".to_owned(),
        _ => "The map search did not answer. Try again later.".to_owned(),
    })
}

/// One GET to the operator's map routes, as text.
async fn get(
    session: &Arc<Session>,
    target: &Target,
    path: &str,
    query: &[(&str, String)],
) -> Result<String> {
    let bearer = session.bearer(&target.fqdn).await?;
    let url = format!("{}{path}", crate::mcp::operator_base(&target.fqdn));
    let resp = crate::http::client()?
        .get(&url)
        .query(query)
        .bearer_auth(bearer.expose())
        .send()
        .await
        .map_err(|e| crate::http::format_transport_error(&url, "GET", e))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(refusal(status.as_u16(), &body));
    }
    Ok(body)
}

/// The operator's search: its results, and its coverage when it says.
async fn search(
    session: &Arc<Session>,
    target: &Target,
    q: &str,
    limit: i64,
    args: &Value,
    kind: &str,
) -> Result<(Vec<Value>, Option<Value>)> {
    let mut query = vec![
        ("q", q.to_owned()),
        ("limit", limit.to_string()),
        ("kind", kind.to_owned()),
    ];
    if let Some(n) = args.get("near") {
        if let (Some(lat), Some(lng)) = (
            n.get("lat").and_then(Value::as_f64),
            n.get("lng").and_then(Value::as_f64),
        ) {
            query.push(("near", format!("{lat},{lng}")));
        }
    }
    if let Some(l) = args.get("lang").and_then(Value::as_str) {
        query.push(("lang", l.to_owned()));
    }
    let body = get(session, target, "/v1/maps/search", &query).await?;
    let v: Value = serde_json::from_str(&body)
        .map_err(|_| anyhow!("The map search answered something unreadable."))?;
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok((results, v.get("coverage").cloned()))
}

fn query_of(args: &Value) -> Result<String> {
    let q = args
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if q.is_empty() {
        bail!("query is required");
    }
    Ok(q.chars().take(200).collect())
}

/// `map_search`.
pub async fn map_search(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let q = query_of(args)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(LIMIT_MAX)
        .clamp(1, LIMIT_MAX);
    let (o, _) = link_options();
    let (results, coverage) = search(session, target, &q, limit, args, "place").await?;

    if is_category_query(&q, MAP_CATEGORY_WORDS) && !names_a_place(&q, &results, MAP_CATEGORY_WORDS)
    {
        // A question about a kind of place: the area it names, never a list.
        let rest = remainder(&q, MAP_CATEGORY_WORDS);
        let area = if rest.is_empty() {
            None
        } else {
            let (found, _) = search(session, target, &rest, 5, args, "place").await?;
            let first_area = found.iter().find(|r| {
                r.get("layer")
                    .and_then(Value::as_str)
                    .is_some_and(|l| AREA_LAYERS.contains(&l))
            });
            first_area
                .or(found.first())
                .and_then(|r| shape_result(r, &o))
        };
        let map_link = area
            .as_ref()
            .and_then(|a| a.get("map_link").cloned())
            .unwrap_or(Value::Null);
        let message = match &area {
            Some(a) => format!(
                "{MAP_DECLINE} Here is {} on the map instead.",
                a.get("name").and_then(Value::as_str).unwrap_or("the area")
            ),
            None => MAP_DECLINE.to_owned(),
        };
        return Ok(
            json!({"declined": true, "message": message, "area": area, "map_link": map_link}),
        );
    }

    let shaped: Vec<Value> = results.iter().filter_map(|r| shape_result(r, &o)).collect();
    let mut notes = Vec::new();
    if shaped.iter().any(|r| r["kind"] == "venue") {
        notes.push(MAP_MAY_HAVE_CLOSED);
    }
    if shaped.is_empty() {
        notes.push("Nothing on the map matches that.");
    }
    let mut out = json!({"results": shaped, "notes": notes});
    if let Some(c) = coverage {
        out["coverage"] = c;
    }
    Ok(out)
}

/// `map_area`.
pub async fn map_area(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let (o, _) = link_options();
    let has_query = args
        .get("query")
        .and_then(Value::as_str)
        .is_some_and(|q| !q.trim().is_empty());
    if !has_query {
        let Some(id) = args
            .get("relation")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
        else {
            bail!("query or relation is required");
        };
        let l = link(&json!({"area": id}), &o);
        return Ok(json!({
            "areas": [{"relation": id, "map_link": l.url}],
            "notes": ["The relation's name was not looked up: the map outlines it when it opens."],
        }));
    }
    let q = query_of(args)?;
    let (results, _) = search(session, target, &q, 5, args, "area").await?;
    let areas: Vec<Value> = results.iter().filter_map(|r| shape_area(r, &o)).collect();
    let notes: Vec<&str> = if areas.is_empty() {
        vec!["No area the map can outline matches that. map_search finds places and towns that are not outlined."]
    } else {
        vec![]
    };
    Ok(json!({"areas": areas, "notes": notes}))
}

/// `map_layers`: the airdress's answer, or this build's copy when it has none.
pub async fn map_layers(session: &Arc<Session>, target: &Target) -> Result<Value> {
    match get(session, target, "/v1/maps/layers", &[]).await {
        Ok(text) => {
            let v: Value = serde_json::from_str(&text)
                .map_err(|_| anyhow!("The map's layer list was unreadable."))?;
            if options_from_catalogue(&text).is_some() {
                if let Ok(mut c) = cached().lock() {
                    *c = Some((Instant::now(), text));
                }
            }
            Ok(json!({"source": "airdress", "catalogue": v}))
        }
        Err(e) => {
            let v: Value = serde_json::from_str(CATALOGUE_SNAPSHOT)?;
            Ok(json!({
                "source": "snapshot",
                "catalogue": v,
                "notes": [format!("{e} This is the list this tool was built with; it may lack newer layers.")],
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_a_closed_sentence_never_the_body() {
        let body = r#"{"error":"maps_throttled","detail":"front said: SECRET-BODY"}"#;
        let e = refusal(429, body).to_string();
        assert!(e.contains("busy"));
        assert!(!e.contains("SECRET-BODY"));
        assert!(refusal(503, r#"{"error":"maps_not_configured"}"#)
            .to_string()
            .contains("no map access"));
        assert!(refusal(404, "").to_string().contains("newer release"));
        assert!(refusal(502, r#"{"error":"maps_unavailable"}"#)
            .to_string()
            .contains("did not answer"));
    }

    #[test]
    fn links_use_the_snapshot_until_a_catalogue_is_fresh() {
        let (o, from) = link_options();
        assert_eq!(from, "snapshot");
        assert_eq!(o, snapshot());
    }
}
