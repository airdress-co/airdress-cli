//! Every tool call lands here.
//!
//! Each tool is a thin shell over what the CLI already does, which is
//! the point: one implementation of "list my functions", reached by a
//! person at a terminal and by a model through a harness. Nothing in
//! this file holds a credential of its own, and nothing it returns
//! carries one (SPEC-133 FR-10).

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::functions::client::{OperatorAuth, OperatorFunctionsClient, PromoteOutcome};
use crate::functions::{self, deploy};
use crate::mcp::bounds;
use crate::mcp::bridge::Bridge;
use crate::mcp::capabilities::{not_enabled_sentence, Feature};
use crate::mcp::session::{Session, Target};
use crate::resources::client::OperatorResourcesClient;

/// What one tool call answers with.
#[derive(Debug)]
pub struct Outcome {
    /// What the model reads.
    pub text: String,
    /// The same answer as data, for a client that wants it.
    pub structured: Option<Value>,
    /// True renders as `isError`, which tells the harness the call did
    /// not do what was asked — not that the server broke.
    pub is_error: bool,
}

impl Outcome {
    fn data(value: Value) -> Self {
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        let (text, note) = bounds::cap(text, "Narrow it with `limit` and `cursor`.");
        let text = match note {
            Some(n) => format!("{text}\n\n{n}"),
            None => text,
        };
        Self {
            text,
            structured: Some(value),
            is_error: false,
        }
    }

    fn says(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            structured: None,
            is_error: false,
        }
    }

    fn refused(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            structured: None,
            is_error: true,
        }
    }
}

/// Run one tool.
///
/// Errors never escape: a model cannot act on a transport failure, so
/// every one of them comes back as a refusal with a sentence that says
/// what to do next.
pub async fn call(session: &Arc<Session>, name: &str, args: &Value) -> Outcome {
    match dispatch(session, name, args).await {
        Ok(o) => o,
        Err(e) => Outcome::refused(sentence_for(&e)),
    }
}

/// One error, rendered as the one sentence that helps.
///
/// `anyhow`'s chain is for a journal, not for a model: it repeats the
/// same fact in three registers. The outermost context plus the root
/// cause is what a caller can act on.
fn sentence_for(e: &anyhow::Error) -> String {
    let top = e.to_string();
    match e.source() {
        Some(root) if root.to_string() != top => format!("{top}: {root}"),
        _ => top,
    }
}

async fn dispatch(session: &Arc<Session>, name: &str, args: &Value) -> Result<Outcome> {
    // The account tools reach no airdress, so they are answerable
    // before anything is known about one.
    match name {
        "login" => return login(session, args).await,
        "logout" => return logout(session, args).await,
        "whoami" => return whoami(session, args).await,
        _ => {}
    }

    let target = session.target(arg_str(args, "airdress")).await?;

    // The advisory gate (§12.2). It stops this client; it is not a
    // boundary, and the sentence says nothing about why.
    let caps = session.capabilities(&target.fqdn).await?;
    if !caps.mcp_local {
        return Ok(Outcome::refused(not_enabled_sentence(
            Feature::McpLocal,
            target.id.as_deref(),
        )));
    }

    let result = match name {
        "airdresses_list" => airdresses_list(session, args).await,
        "airdress_status" => airdress_status(session, &target).await,
        "function_list" => function_list(session, &target, args).await,
        "function_versions" => function_versions(session, &target, args).await,
        "function_logs" => function_logs(session, &target, args).await,
        "function_templates" => function_templates(session, &target).await,
        "function_validate" => function_deploy_or_plan(session, &target, args, true).await,
        "function_deploy" => function_deploy_or_plan(session, &target, args, false).await,
        "function_promote" => function_promote(session, &target, args).await,
        "resources_list" => resources_list(session, &target, args).await,
        "resources_get" => resources_get(session, &target, args).await,
        "resources_apply" => resources_apply(session, &target, args).await,
        "ingress_events_recent" => ingress_events_recent(session, &target, args).await,
        "bridge_list" => bridge_list(session, &target).await,
        "bridge_call" => bridge_call(session, &target, args).await,
        // The agent bus. Its own switch is the operator's to enforce: a
        // switched-off bus answers `not_enabled`, read below.
        bus if bus.starts_with("bus_") => crate::mcp::bus::call(session, &target, bus, args)
            .await
            .map(Outcome::data),
        // Agent chat: answered by this machine's device host, which holds
        // the keys; the operator's switch reaches us as its refusal.
        chat if chat.starts_with("chat_") => crate::mcp::chat::call(session, &target, chat, args)
            .await
            .map(Outcome::data),
        other => bail!("no tool named {other}"),
    };

    // The operator has the last word on its own switches. When it
    // refuses, forget what we believed and say the sentence.
    match result {
        Err(e) => {
            if let Some(feature) = refused_feature(&e) {
                session.forget_capabilities(&target.fqdn).await;
                return Ok(Outcome::refused(not_enabled_sentence(
                    feature,
                    target.id.as_deref(),
                )));
            }
            Err(e)
        }
        ok => ok,
    }
}

/// Whether an error is an operator's `not_enabled` answer, and for what.
///
/// The body travels inside the error message because that is how the
/// shared HTTP layer reports a refusal; this reads it back rather than
/// giving every client a second error type to thread through.
fn refused_feature(e: &anyhow::Error) -> Option<Feature> {
    let text = format!("{e:#}");
    if !text.contains("\"not_enabled\"") {
        return None;
    }
    let after = text.split("\"feature\"").nth(1)?;
    let name = after
        .trim_start()
        .trim_start_matches(':')
        .trim_start()
        .trim_start_matches('"')
        .split('"')
        .next()?;
    Feature::from_wire(name)
}

// ---------------------------------------------------------------------
// arguments
// ---------------------------------------------------------------------

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    arg_str(args, key).ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key).and_then(Value::as_i64)
}

fn arg_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

/// One page of a list, as every list-shaped tool answers it.
fn paged(items: Vec<Value>, args: &Value, key: &str) -> Value {
    let page = bounds::page(items, arg_str(args, "cursor"), arg_i64(args, "limit"));
    let mut out = Map::new();
    out.insert(key.to_string(), Value::Array(page.items));
    out.insert("total".into(), json!(page.total));
    if let Some(next) = page.next_cursor {
        out.insert("next_cursor".into(), json!(next));
    }
    Value::Object(out)
}

// ---------------------------------------------------------------------
// account
// ---------------------------------------------------------------------

/// The profile a tool call is about: the one it named, else the
/// session's. A `login` for a profile that does not exist yet is
/// legitimate, so an unresolvable session profile is only an error when
/// the caller named none either.
fn profile_of(session: &Arc<Session>, args: &Value) -> Result<String> {
    match arg_str(args, "profile") {
        Some(p) => Ok(p.to_owned()),
        None => session.profile_name(),
    }
}

async fn login(session: &Arc<Session>, args: &Value) -> Result<Outcome> {
    let profile = profile_of(session, args)?;
    let pending = crate::auth::login::begin_background(session.paths()?, Some(&profile)).await?;
    Ok(Outcome::data(json!({
        "profile": pending.profile,
        "verification_url": pending.verification_url,
        "user_code": pending.user_code,
        "expires_in_seconds": pending.expires_in_seconds,
        // What this sign-in does to the profile (the move to the hub's
        // sign-in, or the legacy fallback). Show these too: a profile is
        // never changed silently.
        "notices": pending.notices,
        "next": "Show the URL and the code to the user. Sign-in finishes in their \
                 browser; call whoami afterwards to see whether it did.",
    })))
}

async fn logout(session: &Arc<Session>, args: &Value) -> Result<Outcome> {
    let profile = profile_of(session, args)?;
    crate::auth::logout::run(session.paths()?, Some(&profile)).await?;
    Ok(Outcome::says(format!(
        "Signed out of profile {profile}. Its tokens are gone from this machine."
    )))
}

async fn whoami(session: &Arc<Session>, args: &Value) -> Result<Outcome> {
    let mut out = Map::new();
    let profile = session.profile_name().ok();
    out.insert("profile".into(), json!(profile));
    out.insert("harness".into(), json!(session.opts.harness));
    out.insert("read_only".into(), json!(session.opts.read_only));
    out.insert(
        "launcher".into(),
        serde_json::to_value(&session.launch).unwrap_or(Value::Null),
    );
    out.insert("device_label".into(), json!(session.device_label()));
    out.insert("bus_session_label".into(), json!(session.session_label()));
    out.insert("delivery".into(), json!(crate::mcp::bus::DELIVERY));
    out.insert("bus".into(), crate::mcp::bus::report(session).await);

    // The account. An unauthenticated profile is a state to report, not
    // an error to raise — "who am I" is exactly what somebody asks when
    // they are not signed in.
    match session
        .paths()
        .and_then(|paths| crate::auth::status::report(paths, profile.as_deref()))
    {
        Ok(r) => {
            out.insert("hub".into(), json!(r.endpoint));
            out.insert(
                "account".into(),
                json!({"email": r.identity, "subject": r.sub}),
            );
            out.insert("sign_in_method".into(), json!(r.method));
            // `hub` (a token per airdress) or `zitadel_direct` (the legacy
            // one-token sign-in), as `airdress auth status` names it.
            out.insert("sign_in_kind".into(), json!(r.kind));
            out.insert("sign_in_state".into(), json!(r.status));
            out.insert(
                "token".into(),
                json!({
                    "expires_at": r.expires_at,
                    "access_token_expired": r.access_token_expired,
                    "refreshable": r.refreshable,
                }),
            );
        }
        Err(e) => {
            out.insert("sign_in_state".into(), json!("unknown"));
            out.insert("why".into(), json!(sentence_for(&e)));
        }
    }

    // Anything the person should hear before the rest: today, only that
    // the profile still holds the legacy sign-in.
    let notices: Vec<String> = session.legacy_notice().into_iter().collect();
    out.insert("notices".into(), json!(notices));

    // The airdress and its capabilities, when we can reach them.
    match session.target(arg_str(args, "airdress")).await {
        Ok(target) => {
            out.insert(
                "airdress".into(),
                json!({
                    "name": target.name,
                    "id": target.id,
                    "fqdn": target.fqdn,
                    "source": target.source,
                }),
            );
            match session.capabilities(&target.fqdn).await {
                Ok(caps) => {
                    out.insert("capabilities".into(), serde_json::to_value(caps)?);
                }
                Err(e) => {
                    out.insert("capabilities".into(), Value::Null);
                    out.insert("capabilities_error".into(), json!(sentence_for(&e)));
                }
            }
        }
        Err(e) => {
            out.insert("airdress".into(), Value::Null);
            out.insert("airdress_error".into(), json!(sentence_for(&e)));
        }
    }

    Ok(Outcome::data(Value::Object(out)))
}

// ---------------------------------------------------------------------
// fleet
// ---------------------------------------------------------------------

async fn airdresses_list(session: &Arc<Session>, args: &Value) -> Result<Outcome> {
    let fleet = session.fleet(true).await?;
    let items: Vec<Value> = fleet
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "id": a.id,
                "fqdn": a.fqdn,
                "status": a.status,
                "label": a.label,
                "created_at": a.created_at,
            })
        })
        .collect();
    Ok(Outcome::data(paged(items, args, "airdresses")))
}

async fn airdress_status(session: &Arc<Session>, target: &Target) -> Result<Outcome> {
    let caps = session.capabilities(&target.fqdn).await?;
    let bearer = session.bearer(&target.fqdn).await?;
    let probe = crate::mcp::probe::operator(&target.fqdn, bearer.expose()).await;
    Ok(Outcome::data(json!({
        "name": target.name,
        "id": target.id,
        "fqdn": target.fqdn,
        "source": target.source,
        "operator": match probe {
            Ok(p) => p,
            Err(e) => json!({"reachable": false, "why": sentence_for(&e)}),
        },
        "capabilities": serde_json::to_value(caps)?,
    })))
}

// ---------------------------------------------------------------------
// functions
// ---------------------------------------------------------------------

async fn functions_client(
    session: &Arc<Session>,
    target: &Target,
) -> Result<OperatorFunctionsClient> {
    let bearer = session.bearer(&target.fqdn).await?;
    OperatorFunctionsClient::with_base_url(
        crate::mcp::operator_base(&target.fqdn),
        OperatorAuth::Bearer(bearer),
    )
}

async fn function_list(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let bearer = session.bearer(&target.fqdn).await?;
    let client = OperatorResourcesClient::with_base_url(
        crate::mcp::operator_base(&target.fqdn),
        bearer.expose().to_owned(),
    )?;
    let list = client.list_resources("Function").await?;
    let items: Vec<Value> = list
        .items
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();
    Ok(Outcome::data(paged(items, args, "functions")))
}

async fn function_versions(
    session: &Arc<Session>,
    target: &Target,
    args: &Value,
) -> Result<Outcome> {
    let name = required_str(args, "name")?;
    let client = functions_client(session, target).await?;
    let value = client.versions(name).await?;
    let items = value["versions"]
        .as_array()
        .cloned()
        .or_else(|| value.as_array().cloned())
        .unwrap_or_default();
    let mut page = paged(items, args, "versions");
    if let Some(served) = value.get("served") {
        page["served"] = served.clone();
    }
    Ok(Outcome::data(page))
}

async fn function_logs(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let name = required_str(args, "name")?;
    let client = functions_client(session, target).await?;
    let query = crate::functions::client::LogQuery {
        since: arg_str(args, "since").map(str::to_owned),
        invocation: arg_str(args, "invocation").map(str::to_owned),
        after: arg_i64(args, "after"),
        limit: bounds::limit(arg_i64(args, "limit")) as u32,
    };
    let value = client.logs(name, &query).await?;
    let (text, note) = bounds::cap(
        serde_json::to_string_pretty(&value)?,
        "Read on with `after=<the last row's id>`, or narrow it with `since`.",
    );
    Ok(Outcome {
        text: match note {
            Some(n) => format!("{text}\n\n{n}"),
            None => text,
        },
        structured: Some(value),
        is_error: false,
    })
}

async fn function_templates(session: &Arc<Session>, target: &Target) -> Result<Outcome> {
    let client = functions_client(session, target).await?;
    Ok(Outcome::data(client.templates().await?))
}

/// `function_validate` and `function_deploy` are one code path with one
/// flag between them, because a validate that does not run exactly what
/// a deploy runs is worth nothing.
async fn function_deploy_or_plan(
    session: &Arc<Session>,
    target: &Target,
    args: &Value,
    plan: bool,
) -> Result<Outcome> {
    let dir = std::path::PathBuf::from(required_str(args, "dir")?);
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let opts = deploy::DeployOpts {
        dir: Some(dir),
        name: arg_str(args, "name").map(str::to_owned),
        // Never a terminal question: this process's stdin is the
        // harness's JSON-RPC channel. The harness asks the human.
        yes: true,
        plan,
        ci: false,
        all: false,
        since: None,
        map: None,
        branch: None,
        wait_timeout: arg_i64(args, "wait_timeout_seconds")
            .unwrap_or(60)
            .clamp(1, 600) as u64,
        signing_key: None,
        signer_machine: None,
    };
    let profile_name = session.profile_name()?;
    let run_args = functions::RunArgs {
        paths: session.paths()?,
        profile: Some(&profile_name),
        explicit_airdress: Some(&target.name),
        operator_url: None,
        machine_key: None,
        json: true,
        quiet: true,
        verbose: false,
    };
    let conn = functions::connect(&run_args).await?;
    let reports = functions::deploy_reports(&conn, &opts, false).await?;
    let failed = reports.iter().filter(|r| !r.ok()).count();
    let value = json!({
        "plan": plan,
        "reports": reports,
        "failed": failed,
    });
    let mut outcome = Outcome::data(value);
    outcome.is_error = failed > 0;
    Ok(outcome)
}

async fn function_promote(
    session: &Arc<Session>,
    target: &Target,
    args: &Value,
) -> Result<Outcome> {
    let name = required_str(args, "name")?;
    let version = required_str(args, "version")?;
    let based_on = required_str(args, "based_on")?;
    let dry_run = arg_bool(args, "dry_run").unwrap_or(false);
    let client = functions_client(session, target).await?;
    match client
        .promote(name, version, Some(based_on), dry_run)
        .await?
    {
        PromoteOutcome::Promoted(body) => Ok(Outcome::data(body)),
        PromoteOutcome::Stale {
            based_on,
            current,
            refusal,
        } => Ok(Outcome::refused(format!(
            "Refused: the function serves {} now, not {}. {} Read function_versions \
             and promote from what is actually served.",
            current.as_deref().unwrap_or("no version"),
            based_on.as_deref().unwrap_or("the version you named"),
            refusal.message,
        ))),
        PromoteOutcome::Refused { status, refusal } => Ok(Outcome::refused(format!(
            "Refused ({}): {} [{status}]",
            refusal.error, refusal.message
        ))),
        PromoteOutcome::RouteMissing { .. } => Ok(Outcome::refused(
            "This operator is older than the promote route; deploy with \
             function_deploy instead, or update the operator."
                .to_string(),
        )),
    }
}

// ---------------------------------------------------------------------
// resources and events
// ---------------------------------------------------------------------

async fn resources_list(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let bearer = session.bearer(&target.fqdn).await?;
    let client = OperatorResourcesClient::with_base_url(
        crate::mcp::operator_base(&target.fqdn),
        bearer.expose().to_owned(),
    )?;
    match arg_str(args, "kind") {
        None => {
            let kinds = client.list_kinds().await?;
            let items: Vec<Value> = kinds
                .kinds
                .iter()
                .map(|k| serde_json::to_value(k).unwrap_or(Value::Null))
                .collect();
            Ok(Outcome::data(paged(items, args, "kinds")))
        }
        Some(kind) => {
            let list = client.list_resources(kind).await?;
            let items: Vec<Value> = list
                .items
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Outcome::data(paged(items, args, "resources")))
        }
    }
}

async fn resources_get(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let kind = required_str(args, "kind")?;
    let name = required_str(args, "name")?;
    let bearer = session.bearer(&target.fqdn).await?;
    let client = OperatorResourcesClient::with_base_url(
        crate::mcp::operator_base(&target.fqdn),
        bearer.expose().to_owned(),
    )?;
    let view = client.get_one(kind, name).await?;
    let mut value = json!({"resource": serde_json::to_value(&view)?});
    if arg_bool(args, "status").unwrap_or(true) {
        match client.get_status(kind, name).await {
            Ok(status) => value["status"] = serde_json::to_value(status)?,
            Err(e) => value["status_error"] = json!(sentence_for(&e)),
        }
    }
    Ok(Outcome::data(value))
}

async fn resources_apply(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let manifest = args
        .get("manifest")
        .filter(|m| m.is_object())
        .ok_or_else(|| anyhow!("manifest is required, as an object"))?;
    let dry_run = arg_bool(args, "dry_run").unwrap_or(false);
    let bearer = session.bearer(&target.fqdn).await?;
    let client = OperatorResourcesClient::with_base_url(
        crate::mcp::operator_base(&target.fqdn),
        bearer.expose().to_owned(),
    )?;
    let result = client.apply(manifest, dry_run).await?;
    Ok(Outcome::data(serde_json::to_value(result)?))
}

async fn ingress_events_recent(
    session: &Arc<Session>,
    target: &Target,
    args: &Value,
) -> Result<Outcome> {
    let limit = bounds::limit(arg_i64(args, "limit"));
    let bearer = session.bearer(&target.fqdn).await?;
    let url = format!(
        "{}/ingest/v1/events/list?limit={limit}",
        crate::mcp::operator_base(&target.fqdn)
    );
    let resp = crate::http::client()?
        .get(&url)
        .bearer_auth(bearer.expose())
        .send()
        .await
        .map_err(|e| crate::http::format_transport_error(&url, "GET", e))?;
    if resp.status().as_u16() == 404 {
        return Ok(Outcome::refused(
            "This airdress has no inbound event ingress configured, so there are no \
             events to read."
                .to_string(),
        ));
    }
    let resp = crate::http::handle_status(resp, "read recent events").await?;
    let events: Vec<Value> = resp.json().await.context("parse recent events")?;
    Ok(Outcome::data(paged(events, args, "events")))
}

// ---------------------------------------------------------------------
// the bridge
// ---------------------------------------------------------------------

async fn bridge_list(session: &Arc<Session>, target: &Target) -> Result<Outcome> {
    let bearer = session.bearer(&target.fqdn).await?;
    let bridge = Bridge::new(&target.fqdn, bearer.expose().to_owned())?;
    if !bridge.present().await? {
        return Ok(Outcome::says(format!(
            "{} publishes no tools of its own: no function on it declares any.",
            target.name
        )));
    }
    let tools = bridge.list().await?;
    let items: Vec<Value> = tools
        .iter()
        .map(|t| {
            json!({
                "tool": t.name,
                "exported_as": t.exported_name(0),
                "description": t.description,
                "read_only": t.read_only,
            })
        })
        .collect();
    Ok(Outcome::data(json!({"tools": items})))
}

async fn bridge_call(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Outcome> {
    let tool = required_str(args, "tool")?;
    let arguments = args.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let bearer = session.bearer(&target.fqdn).await?;
    let bridge = Bridge::new(&target.fqdn, bearer.expose().to_owned())?;
    Ok(Outcome::data(bridge.call(tool, &arguments).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_not_enabled_body_is_recognised_whatever_wraps_it() {
        let e = anyhow!(
            "read resources: forbidden — your account doesn't have access to this \
             resource: {{\"error\":\"not_enabled\",\"feature\":\"agent_bus\",\
             \"message\":\"not enabled on this airdress\"}}"
        );
        assert_eq!(refused_feature(&e), Some(Feature::AgentBus));

        // Spacing the way a pretty-printed body has it.
        let e = anyhow!("x: {{ \"error\": \"not_enabled\", \"feature\": \"mcp_remote\" }}");
        assert_eq!(refused_feature(&e), Some(Feature::McpRemote));

        // Anything else is not this.
        assert!(refused_feature(&anyhow!("plain 403 forbidden")).is_none());
        assert!(refused_feature(&anyhow!("{{\"error\":\"not_found\"}}")).is_none());
    }

    #[test]
    fn a_page_carries_a_cursor_only_while_there_is_more() {
        let items: Vec<Value> = (0..3).map(|i| json!(i)).collect();
        let page = paged(items.clone(), &json!({"limit": 2}), "things");
        assert_eq!(page["things"].as_array().unwrap().len(), 2);
        assert_eq!(page["total"], 3);
        assert_eq!(page["next_cursor"], "2");

        let page = paged(items, &json!({}), "things");
        assert!(page.get("next_cursor").is_none());
    }

    #[test]
    fn missing_arguments_are_named() {
        let e = required_str(&json!({}), "name").unwrap_err();
        assert_eq!(e.to_string(), "name is required");
        // Whitespace is not a value.
        assert!(required_str(&json!({"name": "  "}), "name").is_err());
    }

    #[test]
    fn one_error_renders_as_one_sentence() {
        let e = anyhow!("could not reach the operator");
        assert_eq!(sentence_for(&e), "could not reach the operator");
        let wrapped = e.context("read capabilities");
        assert_eq!(
            sentence_for(&wrapped),
            "read capabilities: could not reach the operator"
        );
    }
}
