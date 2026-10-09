//! `airdress home …` — the owner's view of the homes linked to an airdress.
//!
//! A `Home` (SPEC-116 D-38) is a declarative resource like any other, so
//! `airdress get Home` already reads it; these verbs say what it means:
//! whether the hub is connected, what it shares, what functions may use,
//! what is opted in as sensitive and where its messages go.
//!
//! **Linking is not here.** A `Home` is linked when its machine is approved
//! (`airdress machines approve … --link-home`), after comparing what the
//! machine printed. `disconnect` goes the other way: it revokes the machine
//! first — the channel ends with it — and then deletes the `Home`. If the
//! delete fails after the revoke succeeded, it says exactly that: the hub is
//! already cut off, and the resource is still there.

use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::machine_admin::client::{plain_refusal, MachineAdminClient};
use crate::profile::storage;
use crate::redact::Redacted;
use crate::resources::client::{OperatorResourcesClient, ResourceView};
use crate::ui;

/// The Kind's wire name. The operator's registry is case-sensitive.
pub const KIND: &str = "Home";

/// The reason a disconnect records on the revocation when none is given.
const DEFAULT_REASON: &str = "home disconnected by its owner";

#[derive(Debug, Subcommand)]
pub enum HomeCommands {
    /// List the homes linked to this airdress: the hub, whether it is
    /// connected, how many entities functions may operate and observe, and
    /// whether its messages reach you.
    List,
    /// Show one home: the hub and its versions, the conditions, what it
    /// shares and what functions may use, the sensitive opt-ins, notify, the
    /// limits and its conversation.
    Get {
        /// The Home's name, as `airdress home list` prints it.
        name: String,
    },
    /// Revoke the home's machine, then delete the Home. The hub is cut off
    /// at once; its conversation is kept, marked disconnected.
    Disconnect {
        /// The Home's name.
        name: String,
        /// Why, for the revocation's audit record.
        #[arg(long)]
        reason: Option<String>,
        /// Do not ask for confirmation.
        #[arg(short, long)]
        yes: bool,
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

/// Both clients a verb may need, over the same operator and bearer.
#[derive(Debug)]
pub struct Clients {
    pub resources: OperatorResourcesClient,
    pub machines: MachineAdminClient,
}

impl Clients {
    pub fn with_base_url(base: &str, bearer: &Redacted<String>) -> Result<Self> {
        Ok(Self {
            resources: OperatorResourcesClient::with_base_url(base.to_owned(), bearer.clone())?,
            machines: MachineAdminClient::with_base_url(base.to_owned(), bearer.clone())?,
        })
    }
}

pub async fn run(command: HomeCommands, args: RunArgs<'_>) -> Result<()> {
    if let HomeCommands::Disconnect {
        reason: Some(r), ..
    } = &command
    {
        if r.trim().is_empty() {
            bail!("--reason must say why; it is kept with the revocation");
        }
    }
    let op = connect(&args).await?;
    match command {
        HomeCommands::List => {
            let list = op.resources.list_resources(KIND).await?;
            if args.json {
                print_json(&json!({
                    "homes": list.items.iter().map(summary).collect::<Vec<_>>()
                }))?;
            } else if list.items.is_empty() {
                ui::say(
                    "no homes linked — approve a Home Assistant machine with \
                     `airdress machines approve … --link-home`",
                );
            } else {
                println!("{}", render_table(&list.items));
            }
        }
        HomeCommands::Get { name } => {
            let view = op.resources.get_one(KIND, &name).await?;
            if args.json {
                print_json(&describe_json(&view))?;
            } else {
                println!("{}", render_describe(&view));
            }
        }
        HomeCommands::Disconnect { name, reason, yes } => {
            let view = op.resources.get_one(KIND, &name).await?;
            let machine = machine_of(&view)?;
            let question = format!(
                "Disconnect home {name}? This revokes machine {machine} (the hub is cut off \
                 and has to enroll again) and deletes the Home."
            );
            ui::confirm(&question, ui::Confirm::new(yes, args.json))?;
            let reason = reason.unwrap_or_else(|| DEFAULT_REASON.to_owned());
            let outcome = disconnect(&op, &name, &machine, &reason).await;
            if args.json {
                print_json(&outcome.to_json(&name, &machine))?;
            }
            outcome.into_result(&name, &machine, args.json)?;
        }
    }
    Ok(())
}

async fn connect(args: &RunArgs<'_>) -> Result<Clients> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(url) = args.operator_url {
        let bearer = hub.operator_bearer(url).await?;
        return Clients::with_base_url(url, &bearer);
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
    Clients::with_base_url(&format!("https://{}", fqdn.trim_matches('/')), &bearer)
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

/// The machine a Home connects as: `spec.hub.homeAssistant.machine`.
pub fn machine_of(view: &ResourceView) -> Result<uuid::Uuid> {
    let raw = view.spec["hub"]["homeAssistant"]["machine"]
        .as_str()
        .unwrap_or_default();
    uuid::Uuid::parse_str(raw.trim()).map_err(|_| {
        anyhow::anyhow!(
            "home {} names no machine id this CLI can revoke (spec.hub: {}). Nothing was \
             changed; `airdress machines revoke` and `airdress delete Home/{}` do the two \
             steps by hand",
            view.metadata.name,
            view.spec["hub"],
            view.metadata.name
        )
    })
}

/// What a disconnect did, step by step.
#[derive(Debug)]
pub enum Disconnected {
    /// Revoked (or already not live), then deleted.
    Done { already_revoked: bool },
    /// The revoke failed; nothing was deleted.
    RevokeFailed(anyhow::Error),
    /// The revoke succeeded; the delete did not.
    DeleteFailed {
        already_revoked: bool,
        error: anyhow::Error,
    },
}

impl Disconnected {
    fn to_json(&self, name: &str, machine: &uuid::Uuid) -> Value {
        match self {
            Self::Done { already_revoked } => json!({
                "home": name, "machine": machine, "revoked": true,
                "already_revoked": already_revoked, "deleted": true,
            }),
            Self::RevokeFailed(e) => json!({
                "home": name, "machine": machine, "revoked": false, "deleted": false,
                "error": format!("{e:#}"),
            }),
            Self::DeleteFailed {
                already_revoked,
                error,
            } => json!({
                "home": name, "machine": machine, "revoked": true,
                "already_revoked": already_revoked, "deleted": false,
                "error": format!("{error:#}"),
            }),
        }
    }

    fn into_result(self, name: &str, machine: &uuid::Uuid, json: bool) -> Result<()> {
        match self {
            Self::Done { already_revoked } => {
                if !json {
                    if already_revoked {
                        ui::ok(format!("machine {machine} was already revoked"));
                    } else {
                        ui::ok(format!("revoked machine {machine}"));
                    }
                    ui::ok(format!(
                        "deleted home {name}; its conversation is kept, marked disconnected"
                    ));
                }
                Ok(())
            }
            Self::RevokeFailed(e) => Err(e.context(format!(
                "disconnect {name}: the machine was not revoked, and the Home was not deleted"
            ))),
            Self::DeleteFailed { error, .. } => Err(error.context(format!(
                "disconnect {name}: machine {machine} IS revoked — the hub is cut off — but \
                 the Home was not deleted. Retry with `airdress delete Home/{name}`"
            ))),
        }
    }
}

/// Revoke, then delete. A machine that is no longer live counts as revoked:
/// that is the state the first step wants.
pub async fn disconnect(
    op: &Clients,
    name: &str,
    machine: &uuid::Uuid,
    reason: &str,
) -> Disconnected {
    let already_revoked = match op.machines.revoke(*machine, reason, None).await {
        Ok(_) => false,
        Err(e) if is_no_machine(&e) => true,
        Err(e) => return Disconnected::RevokeFailed(e),
    };
    match op.resources.delete(KIND, name).await {
        Ok(_) => Disconnected::Done { already_revoked },
        Err(error) => Disconnected::DeleteFailed {
            already_revoked,
            error,
        },
    }
}

fn is_no_machine(e: &anyhow::Error) -> bool {
    plain_refusal("no_machine").is_some_and(|s| format!("{e:#}").contains(s))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn level_count(status: &Value, field: &str, at_least: &[&str]) -> usize {
    status[field]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e["level"].as_str().is_some_and(|l| at_least.contains(&l)))
                .count()
        })
        .unwrap_or(0)
}

/// `ws` / `poll` while connected, else `no`.
fn connected(status: &Value) -> String {
    if status["connectedSince"].is_string() {
        status["transport"].as_str().unwrap_or("yes").to_owned()
    } else {
        "no".to_owned()
    }
}

fn notify_on(spec: &Value) -> bool {
    spec["notify"]["enabled"].as_bool().unwrap_or(true)
}

fn condition<'a>(status: &'a Value, ty: &str) -> Option<&'a Value> {
    status["conditions"]
        .as_array()?
        .iter()
        .find(|c| c["type"].as_str() == Some(ty))
}

fn ready(status: &Value) -> &str {
    condition(status, "Ready")
        .and_then(|c| c["status"].as_str())
        .unwrap_or("Unknown")
}

fn hub_kind(view: &ResourceView) -> String {
    view.status["hub"]["kind"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            view.spec["hub"]
                .as_object()
                .and_then(|o| o.keys().next().cloned())
        })
        .unwrap_or_else(|| "?".to_owned())
}

/// A hub kind as a person says it.
fn hub_label(kind: &str) -> &str {
    match kind {
        "homeAssistant" => "Home Assistant",
        other => other,
    }
}

fn summary(view: &ResourceView) -> Value {
    let s = &view.status;
    json!({
        "name": view.metadata.name,
        "hub": hub_kind(view),
        "ready": ready(s),
        "connected": connected(s),
        "operate": level_count(s, "effective", &["operate"]),
        "observe": level_count(s, "effective", &["observe", "operate"]),
        "notify": notify_on(&view.spec),
        "lastSeenAt": s["lastSeenAt"],
    })
}

/// The list table — the operator's own columns for the Kind, plus READY
/// and NOTIFY. Shared with `airdress get Home`.
pub fn render_table(items: &[ResourceView]) -> String {
    let header = [
        "NAME",
        "HUB",
        "READY",
        "CONNECTED",
        "OPERATE",
        "OBSERVE",
        "NOTIFY",
        "LAST SEEN",
    ];
    let rows: Vec<[String; 8]> = items
        .iter()
        .map(|v| {
            let s = &v.status;
            [
                v.metadata.name.clone(),
                hub_kind(v),
                ready(s).to_owned(),
                connected(s),
                level_count(s, "effective", &["operate"]).to_string(),
                level_count(s, "effective", &["observe", "operate"]).to_string(),
                if notify_on(&v.spec) { "on" } else { "off" }.to_owned(),
                s["lastSeenAt"].as_str().unwrap_or("—").to_owned(),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r.iter()) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        cells
            .iter()
            .zip(widths.iter())
            .map(|(c, w)| format!("{c:<w$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut out = vec![line(header.to_vec())];
    for r in &rows {
        out.push(line(r.iter().map(String::as_str).collect()));
    }
    out.join("\n")
}

fn describe_json(view: &ResourceView) -> Value {
    json!({
        "name": view.metadata.name,
        "spec": view.spec,
        "status": view.status,
        "summary": summary(view),
    })
}

/// The human `home get`.
pub fn render_describe(view: &ResourceView) -> String {
    let spec = &view.spec;
    let s = &view.status;
    let mut out = Vec::new();
    out.push(format!("Home:         {}", view.metadata.name));
    let kind = hub_kind(view);
    let mut hub = hub_label(&kind).to_owned();
    if let Some(v) = s["hub"]["version"].as_str().filter(|v| !v.is_empty()) {
        hub.push_str(&format!(" {v}"));
    }
    if let Some(v) = s["hub"]["integrationVersion"]
        .as_str()
        .filter(|v| !v.is_empty())
    {
        hub.push_str(&format!(" (integration {v})"));
    }
    out.push(format!("Hub:          {hub}"));
    if let Some(m) = spec["hub"]["homeAssistant"]["machine"].as_str() {
        out.push(format!("Machine:      {m}"));
    }
    out.push(format!(
        "Enabled:      {}",
        if spec["enabled"].as_bool().unwrap_or(true) {
            "yes"
        } else {
            "no"
        }
    ));
    let conn = match (s["connectedSince"].as_str(), s["lastSeenAt"].as_str()) {
        (Some(since), _) => format!(
            "yes, over {} since {since}",
            s["transport"].as_str().unwrap_or("?")
        ),
        (None, Some(seen)) => format!("no — last seen {seen}"),
        (None, None) => "no — never seen".to_owned(),
    };
    out.push(format!("Connected:    {conn}"));
    if let Some(p) = s["protocolVersion"].as_str() {
        out.push(format!("Protocol:     {p}"));
    }
    if let Some(n) = s["displacements24h"].as_u64().filter(|n| *n > 0) {
        out.push(format!("Displaced:    {n} channel(s) in the last 24 h"));
    }

    out.push(String::new());
    out.push("Conditions:".to_owned());
    let mut any = false;
    for ty in ["Linked", "Connected", "Ready"] {
        if let Some(c) = condition(s, ty) {
            any = true;
            out.push(format!(
                "  {ty:<10} {:<7} {}{}",
                c["status"].as_str().unwrap_or("?"),
                c["reason"].as_str().unwrap_or(""),
                c["message"]
                    .as_str()
                    .filter(|m| !m.is_empty())
                    .map(|m| format!(" — {m}"))
                    .unwrap_or_default()
            ));
        }
    }
    if !any {
        out.push("  (not reconciled yet)".to_owned());
    }

    out.push(String::new());
    out.push(format!(
        "Shared:       {} to operate, {} to observe",
        level_count(s, "shared", &["operate"]),
        level_count(s, "shared", &["observe", "operate"])
    ));
    out.push(format!(
        "Effective:    {} to operate, {} to observe  (ceiling: {})",
        level_count(s, "effective", &["operate"]),
        level_count(s, "effective", &["observe", "operate"]),
        match &spec["ceiling"] {
            Value::String(c) => c.clone(),
            Value::Object(o) if o.contains_key("explicit") => format!(
                "explicit, {} listed",
                o["explicit"].as_array().map_or(0, Vec::len)
            ),
            Value::Null => "mirror".to_owned(),
            other => other.to_string(),
        }
    ));
    let sensitive: Vec<String> = spec["sensitive"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["entity"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let not_shared: Vec<String> = s["sensitiveNotShared"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if sensitive.is_empty() {
        out.push("Sensitive:    none allowed to operate".to_owned());
    } else {
        out.push(format!(
            "Sensitive:    {} allowed to operate",
            sensitive.len()
        ));
        for e in &sensitive {
            let flag = if not_shared.contains(e) {
                "  (not shared by the hub yet)"
            } else {
                ""
            };
            out.push(format!("  {e}{flag}"));
        }
    }

    out.push(String::new());
    let n = &spec["notify"];
    if notify_on(spec) {
        out.push(format!(
            "Notify:       on, {}/min, {}/day",
            n["perMinute"].as_u64().unwrap_or(3),
            n["perDay"].as_u64().unwrap_or(200)
        ));
    } else {
        out.push("Notify:       off".to_owned());
    }
    out.push(format!(
        "Conversation: {}",
        s["conversation"].as_str().unwrap_or("none yet")
    ));
    let l = &spec["limits"];
    out.push(format!(
        "Limits/min:   {} operate, {} observe, {} reads, {} emits",
        l["callsPerMinute"].as_u64().unwrap_or(3),
        l["observePerMinute"].as_u64().unwrap_or(20),
        l["readsPerMinute"].as_u64().unwrap_or(10),
        l["emitsPerMinute"].as_u64().unwrap_or(10)
    ));
    out.join("\n")
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};

    fn view(spec: Value, status: Value) -> ResourceView {
        serde_json::from_value(json!({
            "apiVersion": crate::wire::API_VERSION,
            "kind": "Home",
            "metadata": {
                "name": "home", "generation": 1, "resourceVersion": "3",
                "created_at": "2026-09-28T08:00:00Z", "updated_at": "2026-09-28T08:00:00Z"
            },
            "spec": spec,
            "status": status,
        }))
        .unwrap()
    }

    const MACHINE: &str = "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee";

    fn linked() -> ResourceView {
        view(
            json!({
                "hub": {"homeAssistant": {"machine": MACHINE}},
                "sensitive": [{"entity": "cover.garage_door", "allow": "operate"},
                              {"entity": "lock.front", "allow": "operate"}],
                "notify": {"enabled": true, "perMinute": 3, "perDay": 200},
                "limits": {"callsPerMinute": 3, "observePerMinute": 20,
                           "readsPerMinute": 10, "emitsPerMinute": 10},
                "enabled": true
            }),
            json!({
                "hub": {"kind": "homeAssistant", "version": "2026.10.0",
                        "integrationVersion": "0.1.0"},
                "protocolVersion": "airdress.home.v1",
                "transport": "ws",
                "shared": [
                    {"entity": "light.kitchen", "level": "operate"},
                    {"entity": "sensor.washer", "level": "observe"},
                    {"entity": "cover.garage_door", "level": "operate",
                     "deviceClass": "garage"}
                ],
                "effective": [
                    {"entity": "light.kitchen", "level": "operate"},
                    {"entity": "sensor.washer", "level": "observe"}
                ],
                "sensitiveNotShared": ["lock.front"],
                "connectedSince": "2026-09-28T08:01:00Z",
                "lastSeenAt": "2026-09-28T08:05:00Z",
                "conversation": "0199ffff-0000-7000-8000-000000000001",
                "conditions": [
                    {"type": "Linked", "status": "True", "reason": "MachineApproved",
                     "message": "the machine is approved",
                     "lastTransitionTime": "2026-09-28T08:00:00Z"},
                    {"type": "Connected", "status": "True", "reason": "ChannelUp",
                     "message": "", "lastTransitionTime": "2026-09-28T08:01:00Z"},
                    {"type": "Ready", "status": "True", "reason": "Ready",
                     "message": "functions can reach the hub",
                     "lastTransitionTime": "2026-09-28T08:01:00Z"}
                ]
            }),
        )
    }

    #[test]
    fn the_table_counts_effective_levels_and_names_the_transport() {
        let t = render_table(&[linked()]);
        let mut lines = t.lines();
        let head: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        assert_eq!(
            head,
            [
                "NAME",
                "HUB",
                "READY",
                "CONNECTED",
                "OPERATE",
                "OBSERVE",
                "NOTIFY",
                "LAST",
                "SEEN"
            ]
        );
        let row: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        assert_eq!(
            row,
            [
                "home",
                "homeAssistant",
                "True",
                "ws",
                "1",
                "2",
                "on",
                "2026-09-28T08:05:00Z"
            ]
        );
    }

    #[test]
    fn a_home_never_reconciled_renders_without_status() {
        let v = view(
            json!({"hub": {"homeAssistant": {"machine": MACHINE}}}),
            json!({}),
        );
        let row = render_table(std::slice::from_ref(&v));
        assert!(row
            .lines()
            .nth(1)
            .unwrap()
            .contains("homeAssistant  Unknown  no"));
        let d = render_describe(&v);
        assert!(d.contains("(not reconciled yet)"), "{d}");
        assert!(d.contains("Connected:    no — never seen"), "{d}");
        assert!(d.contains("Notify:       on, 3/min, 200/day"), "{d}");
        assert!(
            d.contains("Limits/min:   3 operate, 20 observe, 10 reads, 10 emits"),
            "{d}"
        );
    }

    #[test]
    fn describe_says_the_hub_the_conditions_and_the_sensitive_opt_ins() {
        let d = render_describe(&linked());
        for want in [
            "Hub:          Home Assistant 2026.10.0 (integration 0.1.0)",
            "Connected:    yes, over ws since 2026-09-28T08:01:00Z",
            "Linked     True    MachineApproved — the machine is approved",
            "Ready      True    Ready — functions can reach the hub",
            "Shared:       2 to operate, 3 to observe",
            "Effective:    1 to operate, 2 to observe  (ceiling: mirror)",
            "Sensitive:    2 allowed to operate",
            "lock.front  (not shared by the hub yet)",
            "Conversation: 0199ffff-0000-7000-8000-000000000001",
        ] {
            assert!(d.contains(want), "missing {want:?} in:\n{d}");
        }
    }

    #[test]
    fn notify_off_is_said() {
        let v = view(
            json!({"hub": {"homeAssistant": {"machine": MACHINE}},
                   "notify": {"enabled": false}}),
            json!({}),
        );
        assert!(render_describe(&v).contains("Notify:       off"));
        assert!(render_table(&[v]).contains("  off"));
    }

    #[test]
    fn the_machine_comes_from_the_hub_variant() {
        assert_eq!(machine_of(&linked()).unwrap().to_string(), MACHINE);
        let bad = view(
            json!({"hub": {"homeAssistant": {"machine": "nope"}}}),
            json!({}),
        );
        let e = machine_of(&bad).unwrap_err().to_string();
        assert!(e.contains("Nothing was changed"), "{e}");
    }

    fn requests(seen: &[String]) -> Vec<String> {
        seen.iter()
            .map(|r| r.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn disconnect_revokes_then_deletes() {
        let (base, handle) = canned_operator(vec![
            response(
                "200 OK",
                &format!(r#"{{"machine_id":"{MACHINE}","revoked_kids":["k1"]}}"#),
            ),
            response(
                "200 OK",
                r#"{"kind":"Home","name":"home","action":"deleted"}"#,
            ),
        ])
        .await;
        let op = Clients::with_base_url(&base, &"t".into()).unwrap();
        let m = uuid::Uuid::parse_str(MACHINE).unwrap();
        let out = disconnect(&op, "home", &m, "moving house").await;
        assert!(
            matches!(
                out,
                Disconnected::Done {
                    already_revoked: false
                }
            ),
            "{out:?}"
        );
        let seen = handle.await.unwrap();
        assert_eq!(
            requests(&seen),
            [
                format!("POST /v1/admin/machines/{MACHINE}/revoke HTTP/1.1"),
                "DELETE /v1/kinds/Home/home HTTP/1.1".to_owned(),
            ]
        );
        assert!(
            seen[0].ends_with(r#"{"reason":"moving house"}"#),
            "{}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn a_machine_already_revoked_still_deletes() {
        let (base, handle) = canned_operator(vec![
            response(
                "404 Not Found",
                r#"{"error":{"code":"no_machine","message":"no live machine has that id"}}"#,
            ),
            response(
                "200 OK",
                r#"{"kind":"Home","name":"home","action":"deleted"}"#,
            ),
        ])
        .await;
        let op = Clients::with_base_url(&base, &"t".into()).unwrap();
        let m = uuid::Uuid::parse_str(MACHINE).unwrap();
        let out = disconnect(&op, "home", &m, "r").await;
        assert!(
            matches!(
                out,
                Disconnected::Done {
                    already_revoked: true
                }
            ),
            "{out:?}"
        );
        assert_eq!(handle.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_failed_revoke_deletes_nothing() {
        let (base, handle) = canned_operator(vec![response(
            "500 Internal Server Error",
            r#"{"error":{"code":"internal","message":"db down"}}"#,
        )])
        .await;
        let op = Clients::with_base_url(&base, &"t".into()).unwrap();
        let m = uuid::Uuid::parse_str(MACHINE).unwrap();
        let out = disconnect(&op, "home", &m, "r").await;
        assert_eq!(
            handle.await.unwrap().len(),
            1,
            "no DELETE after a failed revoke"
        );
        let e = format!("{:#}", out.into_result("home", &m, true).unwrap_err());
        assert!(
            e.contains("was not revoked, and the Home was not deleted"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn a_failed_delete_after_a_revoke_says_the_hub_is_cut_off() {
        let (base, handle) = canned_operator(vec![
            response(
                "200 OK",
                &format!(r#"{{"machine_id":"{MACHINE}","revoked_kids":[]}}"#),
            ),
            response("500 Internal Server Error", r#"{"error":"internal"}"#),
        ])
        .await;
        let op = Clients::with_base_url(&base, &"t".into()).unwrap();
        let m = uuid::Uuid::parse_str(MACHINE).unwrap();
        let out = disconnect(&op, "home", &m, "r").await;
        handle.await.unwrap();
        let j = out.to_json("home", &m);
        assert_eq!(j["revoked"], true);
        assert_eq!(j["deleted"], false);
        let e = format!("{:#}", out.into_result("home", &m, true).unwrap_err());
        assert!(e.contains("IS revoked"), "{e}");
        assert!(e.contains("airdress delete Home/home"), "{e}");
    }
}
