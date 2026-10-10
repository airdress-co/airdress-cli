//! `airdress events …` — the operator's event catalogue, a receiver for
//! what a subscription delivers, and the two subscription verbs.
//!
//! An `EventSubscription` is a declarative resource, so
//! `airdress apply`, `get` and `describe` already write and read it. These
//! verbs cover what a manifest cannot:
//!
//! - `catalog` — every event type the operator can record (name, version,
//!   audience, whether the app or the function bus sees it) and every
//!   interception point a `Hook` can bind.
//! - `tail` — the receiving end of a subscription. The operator serves no
//!   route that reads its event log back out, so `tail` does not poll
//!   anything: it listens, verifies each delivery's `v1a` signature against
//!   the operator's published key, and prints it.
//! - `redeliver` — queue one event, or everything since an instant, to a
//!   subscription again.
//! - `test` — send the subscription one synthetic event.

pub mod client;
pub mod tail;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{ArgGroup, Subcommand};
use serde_json::{json, Value};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use client::{EventsClient, Redeliver};

#[derive(Debug, Subcommand)]
pub enum EventsCommands {
    /// List the event types this operator can record: name, version,
    /// audience (owner, principal, airdress), the client event name the app
    /// sees (if any), whether functions can bind it (bus), and what it says.
    /// With --points, list the interception points a `Hook` can bind
    /// instead. `--output json` prints the operator's document, schemas
    /// included.
    Catalog {
        /// List interception points instead of event types.
        #[arg(long)]
        points: bool,
    },
    /// Receive what a subscription delivers, and print it.
    ///
    /// This is a receiver, not a reader: the operator has no route that
    /// reads its event log back, so `tail` runs a small HTTP server on
    /// --listen and prints each delivery an `EventSubscription` sends to it,
    /// with its Standard Webhooks `v1a` signature checked against the
    /// operator's key (`GET /v1/events/signing-key`, or --signing-key). A
    /// verified delivery is answered 204; anything else 401, and printed
    /// with what was wrong.
    ///
    /// Point a subscription at it with `spec.target.http.url` set to this
    /// address and `signing: { mode: v1a }` (the default). The operator
    /// never delivers to loopback, link-local or its own addresses, so
    /// listen where it can reach you: a tailnet or LAN address with
    /// `allowPrivateNetwork: true` on the subscription (owner only), or a
    /// public endpoint forwarded here.
    #[command(verbatim_doc_comment)]
    Tail {
        /// Address to listen on, e.g. `0.0.0.0:8099`.
        #[arg(long, value_name = "ADDR:PORT")]
        listen: SocketAddr,
        /// The operator's `whpk_…` key. Without it, the key is read from
        /// the operator once at start.
        #[arg(long, value_name = "WHPK")]
        signing_key: Option<String>,
        /// Seconds a delivery's timestamp may differ from this clock.
        #[arg(long, value_name = "SECONDS", default_value_t = tail::DEFAULT_TOLERANCE.as_secs())]
        tolerance: u64,
        /// Exit after this many requests.
        #[arg(long, value_name = "N")]
        count: Option<usize>,
    },
    /// Queue events to a subscription again: one by id, or everything since
    /// an instant (at most 10,000). Only what the subscription would have
    /// received is queued; an event swept from the log (after 7 days)
    /// cannot be.
    #[command(group(ArgGroup::new("which").required(true).args(["event_id", "since"])))]
    Redeliver {
        /// The subscription's `metadata.name`.
        subscription: String,
        /// One event's id.
        #[arg(long, value_name = "UUID")]
        event_id: Option<uuid::Uuid>,
        /// Every matching event at or after this instant (RFC 3339, e.g.
        /// `2026-10-04T08:00:00Z`).
        #[arg(long, value_name = "RFC3339")]
        since: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Send one synthetic `airdress.event_subscription.test.sent` event to
    /// this subscription only. It is queued like any delivery;
    /// `airdress describe EventSubscription/<name>` shows how it went.
    Test {
        /// The subscription's `metadata.name`.
        subscription: String,
    },
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

pub async fn run(command: EventsCommands, args: RunArgs<'_>) -> Result<()> {
    match command {
        EventsCommands::Catalog { points } => {
            let op = connect(&args).await?;
            let doc = op.catalog().await?;
            if args.json {
                print_json(&catalog_json(&doc, points))?;
            } else if points {
                println!("{}", render_points(&doc));
            } else {
                println!("{}", render_events(&doc));
            }
        }
        EventsCommands::Tail {
            listen,
            signing_key,
            tolerance,
            count,
        } => {
            let whpk = match signing_key {
                Some(k) => k,
                None => signing_key_from_operator(&args).await?,
            };
            run_tail(listen, &whpk, Duration::from_secs(tolerance), count, &args).await?;
        }
        EventsCommands::Redeliver {
            subscription,
            event_id,
            since,
        } => {
            let what = match (event_id, since) {
                (Some(id), _) => Redeliver::EventId(id),
                (None, Some(t)) => Redeliver::Since(t),
                (None, None) => unreachable!("clap requires one of --event-id, --since"),
            };
            let op = connect(&args).await?;
            let n = op.redeliver(&subscription, &what).await?;
            if args.json {
                print_json(&json!({ "subscription": subscription, "requeued": n }))?;
            } else {
                ui::ok(redeliver_sentence(&subscription, &what, n));
            }
        }
        EventsCommands::Test { subscription } => {
            let op = connect(&args).await?;
            let id = op.test(&subscription).await?;
            if args.json {
                print_json(&json!({ "subscription": subscription, "eventId": id }))?;
            } else {
                ui::ok(format!(
                    "queued test event {id} to {subscription}; \
                     `airdress describe EventSubscription/{subscription}` shows whether it \
                     was delivered"
                ));
            }
        }
    }
    Ok(())
}

/// A client for the operator with the person's hub bearer for it:
/// `--operator-url` as given, else `https://<fqdn>` of the resolved
/// airdress. Redeliver and test are a person's verbs; no machine
/// credential is ever used here.
async fn connect(args: &RunArgs<'_>) -> Result<EventsClient> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(url) = args.operator_url {
        let bearer = hub.operator_bearer(url).await?;
        return EventsClient::with_base_url(url, Some(bearer));
    }
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }
    let fqdn = hub.resolve_fqdn(&resolved.name).await?;
    let bearer = hub.operator_bearer(&fqdn).await?;
    EventsClient::with_base_url(&format!("https://{}", fqdn.trim_matches('/')), Some(bearer))
}

/// The key is public, so with `--operator-url` no sign-in is needed.
async fn signing_key_from_operator(args: &RunArgs<'_>) -> Result<String> {
    let op = match args.operator_url {
        Some(url) => EventsClient::with_base_url(url, None)?,
        None => connect(args).await?,
    };
    op.signing_key().await
}

async fn run_tail(
    listen: SocketAddr,
    whpk: &str,
    tolerance: Duration,
    count: Option<usize>,
    args: &RunArgs<'_>,
) -> Result<()> {
    let key = tail::parse_whpk(whpk)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    let bound = listener.local_addr()?;
    if !args.quiet {
        ui::note(format!(
            "receiving on http://{bound}/ — point an EventSubscription's \
             spec.target.http.url here; verifying v1a with {}",
            whpk.trim()
        ));
        if bound.ip().is_loopback() {
            ui::warn(
                "a loopback address: the operator never delivers to loopback, so only \
                 something forwarding to this port can reach it",
            );
        }
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tail::Delivery>(64);
    let receiver = tail::Receiver { key, tolerance };
    let server = tokio::spawn(tail::serve(listener, receiver, count, tx));
    let json = args.json;
    let printer = async {
        while let Some(d) = rx.recv().await {
            if json {
                println!("{}", serde_json::to_string(&d.to_json())?);
            } else {
                println!("{}", d.render());
            }
        }
        anyhow::Ok(())
    };
    tokio::select! {
        r = printer => r?,
        _ = tokio::signal::ctrl_c() => {}
    }
    server.abort();
    Ok(())
}

fn redeliver_sentence(subscription: &str, what: &Redeliver, n: u64) -> String {
    match what {
        Redeliver::EventId(id) => format!("queued event {id} to {subscription} again"),
        Redeliver::Since(t) if n == 0 => format!(
            "nothing to queue: no event since {} is one {subscription} receives",
            t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
        Redeliver::Since(t) => format!(
            "queued {n} event(s) since {} to {subscription} again",
            t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// `--output json`: the operator's document, narrowed to what was asked for.
pub fn catalog_json(doc: &Value, points: bool) -> Value {
    let part = if points { "points" } else { "events" };
    json!({
        "catalog_version": doc["catalog_version"],
        part: doc[part].as_array().cloned().unwrap_or_default(),
    })
}

fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for r in rows {
        for (w, c) in widths.iter_mut().zip(r.iter()) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    (*c).to_owned()
                } else {
                    format!("{c:<w$}", w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut out = vec![line(header.to_vec())];
    for r in rows {
        out.push(line(r.iter().map(String::as_str).collect()));
    }
    out.join("\n")
}

/// The event-type table.
pub fn render_events(doc: &Value) -> String {
    let rows: Vec<Vec<String>> = doc["events"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|e| {
            vec![
                e["name"].as_str().unwrap_or("?").to_owned(),
                e["version"]
                    .as_u64()
                    .map_or_else(|| "?".into(), |v| v.to_string()),
                e["audience"].as_str().unwrap_or("?").to_owned(),
                e["client"].as_str().unwrap_or("—").to_owned(),
                if e["bus"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "no"
                }
                .to_owned(),
                e["description"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    if rows.is_empty() {
        return "the operator records no event types".to_owned();
    }
    table(
        &[
            "NAME",
            "VERSION",
            "AUDIENCE",
            "CLIENT",
            "BUS",
            "DESCRIPTION",
        ],
        &rows,
    )
}

/// The interception-point table.
pub fn render_points(doc: &Value) -> String {
    let rows: Vec<Vec<String>> = doc["points"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let mutable: Vec<&str> = p["mutable"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            vec![
                p["name"].as_str().unwrap_or("?").to_owned(),
                if mutable.is_empty() {
                    "— (validate only)".to_owned()
                } else {
                    mutable.join(",")
                },
                p["max_failure_policy"].as_str().unwrap_or("?").to_owned(),
                p["description"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    if rows.is_empty() {
        return "the operator raises no interception points".to_owned();
    }
    table(&["POINT", "MUTABLE", "MAX FAILURE", "DESCRIPTION"], &rows)
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped as `airdress_events::catalog::to_json` answers.
    fn doc() -> Value {
        json!({
            "catalog_version": 1,
            "events": [
                {"name": "airdress.device_join.requested", "version": 1, "audience": "owner",
                 "level": "info", "client": "device_join_requested", "bus": true,
                 "description": "A device asked to join.", "schema": {}},
                {"name": "airdress.event_subscription.test.sent", "version": 1,
                 "audience": "principal", "level": "info", "bus": false,
                 "description": "A test delivery.", "schema": {}}
            ],
            "points": [
                {"name": "airdress.resource.will_apply", "mutable": ["labels", "spec"],
                 "max_failure_policy": "fail", "description": "A resource is about to be applied.",
                 "schema": {}},
                {"name": "airdress.resource.will_delete", "mutable": [],
                 "max_failure_policy": "fail", "description": "A resource is about to be deleted.",
                 "schema": {}}
            ]
        })
    }

    fn cells(line: &str) -> Vec<&str> {
        line.split("  ")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }

    #[test]
    fn the_event_table_names_audience_client_and_bus() {
        let t = render_events(&doc());
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(
            cells(lines[0]),
            [
                "NAME",
                "VERSION",
                "AUDIENCE",
                "CLIENT",
                "BUS",
                "DESCRIPTION"
            ]
        );
        assert_eq!(
            cells(lines[1]),
            [
                "airdress.device_join.requested",
                "1",
                "owner",
                "device_join_requested",
                "yes",
                "A device asked to join."
            ]
        );
        assert_eq!(
            cells(lines[2]),
            [
                "airdress.event_subscription.test.sent",
                "1",
                "principal",
                "—",
                "no",
                "A test delivery."
            ]
        );
    }

    #[test]
    fn the_point_table_says_what_a_hook_may_change() {
        let t = render_points(&doc());
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(
            cells(lines[0]),
            ["POINT", "MUTABLE", "MAX FAILURE", "DESCRIPTION"]
        );
        assert_eq!(
            cells(lines[1]),
            [
                "airdress.resource.will_apply",
                "labels,spec",
                "fail",
                "A resource is about to be applied."
            ]
        );
        assert!(lines[2].contains("— (validate only)"), "{}", lines[2]);
    }

    #[test]
    fn json_keeps_the_operators_entries_whole() {
        let j = catalog_json(&doc(), false);
        assert_eq!(j["catalog_version"], 1);
        assert_eq!(j["events"].as_array().unwrap().len(), 2);
        assert!(j["events"][0]["schema"].is_object());
        assert!(j.get("points").is_none());
        let p = catalog_json(&doc(), true);
        assert_eq!(p["points"][0]["name"], "airdress.resource.will_apply");
        assert!(p.get("events").is_none());
    }

    #[test]
    fn an_empty_catalogue_is_said() {
        let empty = json!({"catalog_version": 1, "events": [], "points": []});
        assert_eq!(render_events(&empty), "the operator records no event types");
        assert_eq!(
            render_points(&empty),
            "the operator raises no interception points"
        );
    }

    #[test]
    fn redelivering_nothing_says_why() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-10-04T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            redeliver_sentence("ha", &Redeliver::Since(t), 0),
            "nothing to queue: no event since 2026-10-04T08:00:00Z is one ha receives"
        );
        assert_eq!(
            redeliver_sentence("ha", &Redeliver::Since(t), 4),
            "queued 4 event(s) since 2026-10-04T08:00:00Z to ha again"
        );
    }
}
