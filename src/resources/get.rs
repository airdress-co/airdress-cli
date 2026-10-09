//! `airdress get [<ref>]` — list Kinds, list resources of a Kind, or
//! read one resource. The `<ref>` shape is k8s-style:
//!
//! - `airdress get`               → list registered Kinds.
//! - `airdress get <Kind>`        → list resources of that Kind.
//! - `airdress get <Kind>/<name>` → read one resource (spec+status).

use anyhow::Result;
use serde_json::Value;

use super::apply::build_client;
use super::client::{parse_ref, KindsList, OperatorResourcesClient, ResourceList, ResourceView};

#[derive(Debug)]
pub struct GetArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub reference: Option<&'a str>,
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: GetArgs<'_>) -> Result<()> {
    let op = build_client(
        args.paths,
        args.profile,
        args.explicit_airdress,
        args.operator_url,
        args.json,
        args.quiet,
    )
    .await?;

    match args.reference {
        None => {
            let kinds = op.list_kinds().await?;
            render_kinds(&kinds, args.json)?;
        }
        Some(s) => {
            let (kind, name) = parse_ref(s)?;
            let kind = canonical_kind(&op, kind).await?;
            match name {
                None => {
                    let list = op.list_resources(&kind).await?;
                    render_resource_list(&list, args.json)?;
                }
                Some(n) => {
                    let view = op.get_one(&kind, &n).await?;
                    render_resource(&view, args.json)?;
                }
            }
        }
    }
    Ok(())
}

/// Kinds are PascalCase and the operator matches them exactly, so a
/// reference typed all in lowercase (`airdress get home`, `airdress get
/// things`) is resolved against the registered Kinds, ignoring case and a
/// plural `s`. Anything else is sent as typed.
async fn canonical_kind(op: &OperatorResourcesClient, kind: String) -> Result<String> {
    if kind.chars().any(|c| c.is_ascii_uppercase()) {
        return Ok(kind);
    }
    let kinds = op.list_kinds().await?;
    Ok(match_kind(&kinds, &kind).unwrap_or(kind))
}

fn match_kind(kinds: &KindsList, typed: &str) -> Option<String> {
    let find = |t: &str| {
        kinds
            .kinds
            .iter()
            .find(|k| k.kind.eq_ignore_ascii_case(t))
            .map(|k| k.kind.clone())
    };
    find(typed).or_else(|| typed.strip_suffix('s').and_then(find))
}

fn render_kinds(kinds: &KindsList, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "kinds": kinds.kinds.iter().map(|k| serde_json::json!({
                    "kind": k.kind,
                    "apiVersion": k.api_version,
                    "summary_condition_types": k.summary_condition_types,
                })).collect::<Vec<_>>()
            }))?
        );
        return Ok(());
    }
    if kinds.kinds.is_empty() {
        println!("(no kinds registered)");
        return Ok(());
    }
    let max_kind = kinds
        .kinds
        .iter()
        .map(|k| k.kind.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let max_api = kinds
        .kinds
        .iter()
        .map(|k| k.api_version.len())
        .max()
        .unwrap_or(10);
    println!(
        "{:<w$}  {:<a$}  CONDITIONS",
        "KIND",
        "APIVERSION",
        w = max_kind,
        a = max_api
    );
    for k in &kinds.kinds {
        println!(
            "{:<w$}  {:<a$}  {}",
            k.kind,
            k.api_version,
            k.summary_condition_types.join(","),
            w = max_kind,
            a = max_api
        );
    }
    Ok(())
}

fn render_resource_list(list: &ResourceList, json: bool) -> Result<()> {
    if json {
        // Pass-through; the operator's wire shape is already the API.
        println!("{}", serde_json::to_string_pretty(&list_to_value(list))?);
        return Ok(());
    }
    if list.items.is_empty() {
        println!("(no {} resources)", list.kind);
        return Ok(());
    }
    // A Kind whose columns this CLI knows gets them; the operator does not
    // put its list columns on the wire.
    if list.kind == crate::home::KIND {
        println!("{}", crate::home::render_table(&list.items));
        return Ok(());
    }
    if list.kind == super::thing::KIND {
        println!("{}", super::thing::render_table(&list.items));
        return Ok(());
    }
    // Compute widths and pick a per-Kind extra column (phase) so this
    // works without per-Kind knowledge on the CLI side. The operator's
    // status subresource computes the phase string we mirror here.
    let max_name = list
        .items
        .iter()
        .map(|r| r.metadata.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("{:<w$}  GEN  OBS  RV   AGE", "NAME", w = max_name);
    for r in &list.items {
        let obs = r
            .metadata
            .observed_generation
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".into());
        let age = age_short(&r.metadata.created_at);
        println!(
            "{:<w$}  {:<3}  {:<3}  {:<3}  {}",
            r.metadata.name,
            r.metadata.generation,
            obs,
            r.metadata.resource_version,
            age,
            w = max_name
        );
    }
    Ok(())
}

fn render_resource(view: &ResourceView, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&view_to_value(view))?);
        return Ok(());
    }
    // YAML for human reads — k8s convention.
    let v = view_to_value(view);
    let yaml = serde_yaml::to_string(&v).unwrap_or_else(|_| "(failed to render YAML)".into());
    print!("{yaml}");
    Ok(())
}

fn list_to_value(list: &ResourceList) -> Value {
    let items: Vec<Value> = list.items.iter().map(view_to_value).collect();
    serde_json::json!({"kind": list.kind, "items": items})
}

fn view_to_value(v: &ResourceView) -> Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("name".into(), Value::String(v.metadata.name.clone()));
    metadata.insert("generation".into(), Value::from(v.metadata.generation));
    if let Some(og) = v.metadata.observed_generation {
        metadata.insert("observedGeneration".into(), Value::from(og));
    }
    metadata.insert(
        "resourceVersion".into(),
        Value::String(v.metadata.resource_version.clone()),
    );
    metadata.insert("labels".into(), v.metadata.labels.clone());
    metadata.insert(
        "createdAt".into(),
        Value::String(v.metadata.created_at.to_rfc3339()),
    );
    metadata.insert(
        "updatedAt".into(),
        Value::String(v.metadata.updated_at.to_rfc3339()),
    );
    if let Some(ts) = v.metadata.last_reconciled_at {
        metadata.insert("lastReconciledAt".into(), Value::String(ts.to_rfc3339()));
    }
    serde_json::json!({
        "apiVersion": v.api_version,
        "kind": v.kind,
        "metadata": Value::Object(metadata),
        "spec": v.spec,
        "status": v.status,
    })
}

/// `2d`, `15h`, `42m`, `<1m` — k8s-style relative age.
fn age_short(ts: &chrono::DateTime<chrono::Utc>) -> String {
    let dur = chrono::Utc::now() - *ts;
    let secs = dur.num_seconds();
    if secs < 60 {
        return "<1m".into();
    }
    let mins = dur.num_minutes();
    if mins < 60 {
        return format!("{mins}m");
    }
    let hrs = dur.num_hours();
    if hrs < 48 {
        return format!("{hrs}h");
    }
    let days = dur.num_days();
    format!("{days}d")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn a_lowercase_kind_resolves_to_the_registered_one() {
        let kinds: KindsList = serde_json::from_value(serde_json::json!({"kinds": [
            {"kind": "Function", "api_version": crate::wire::API_VERSION},
            {"kind": "Home", "api_version": crate::wire::API_VERSION},
            {"kind": "Thing", "api_version": crate::wire::API_VERSION}
        ]}))
        .unwrap();
        assert_eq!(match_kind(&kinds, "home").as_deref(), Some("Home"));
        assert_eq!(match_kind(&kinds, "function").as_deref(), Some("Function"));
        assert_eq!(match_kind(&kinds, "thing").as_deref(), Some("Thing"));
        assert_eq!(match_kind(&kinds, "nope"), None);
    }

    #[test]
    fn a_plural_kind_resolves_to_the_registered_one() {
        let kinds: KindsList = serde_json::from_value(serde_json::json!({"kinds": [
            {"kind": "Thing", "api_version": crate::wire::API_VERSION},
            {"kind": "Function", "api_version": crate::wire::API_VERSION}
        ]}))
        .unwrap();
        assert_eq!(match_kind(&kinds, "things").as_deref(), Some("Thing"));
        assert_eq!(match_kind(&kinds, "functions").as_deref(), Some("Function"));
        assert_eq!(match_kind(&kinds, "thingss"), None);
    }

    #[test]
    fn age_short_seconds_is_under_minute() {
        let ts = Utc::now() - Duration::seconds(30);
        assert_eq!(age_short(&ts), "<1m");
    }

    #[test]
    fn age_short_minutes() {
        let ts = Utc::now() - Duration::minutes(5);
        assert_eq!(age_short(&ts), "5m");
    }

    #[test]
    fn age_short_hours() {
        let ts = Utc::now() - Duration::hours(3);
        assert_eq!(age_short(&ts), "3h");
    }

    #[test]
    fn age_short_days() {
        let ts = Utc::now() - Duration::days(5);
        assert_eq!(age_short(&ts), "5d");
    }
}
