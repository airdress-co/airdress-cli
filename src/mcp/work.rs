//! The work-item tools: `work_list`, `work_get` and `work_draft`
//! (SPEC-182 182-D.2).
//!
//! They call the person's own operator (`/v1/work/…`) with the person's own
//! sign-in. **None of them makes a work item.** `work_draft` offers the
//! signed-in person a draft, which they create themselves, in the app or
//! with `airdress work`: an assistant drafts, a person confirms.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::mcp::session::{Session, Target};

/// Why the operator refused, in the sentence a model can act on.
fn refusal(status: u16, body: &str) -> anyhow::Error {
    anyhow!(if body.contains("not_enabled") {
        "Work items are not turned on for this airdress.".to_owned()
    } else if status == 404 && body.contains("work_item_not_found") {
        "There is no such work item, or this sign-in cannot read it.".to_owned()
    } else if status == 404 {
        "This airdress's operator does not have work items yet: it needs a newer release."
            .to_owned()
    } else if status == 400 {
        format!("The airdress refused the draft: {}", detail(body))
    } else if status == 401 || status == 403 {
        "The airdress refused this request for this sign-in.".to_owned()
    } else {
        "The airdress did not answer. Try again later.".to_owned()
    })
}

fn detail(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "it is not a usable draft".to_owned())
}

async fn send(
    session: &Arc<Session>,
    target: &Target,
    method: reqwest::Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<&Value>,
) -> Result<Value> {
    let bearer = session.bearer(&target.fqdn).await?;
    let url = format!("{}{path}", crate::mcp::operator_base(&target.fqdn));
    let mut req = crate::http::client()?
        .request(method.clone(), &url)
        .query(query)
        .bearer_auth(bearer.expose());
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| crate::http::format_transport_error(&url, method.as_str(), e))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(refusal(status.as_u16(), &text));
    }
    serde_json::from_str(&text)
        .map_err(|e| anyhow!("the airdress answered something unreadable: {e}"))
}

/// The fields a model needs from an item, and nothing it should not quote.
fn summary(item: &Value) -> Value {
    let profile = item["profile"].as_str().unwrap_or("");
    let due = if profile == "rfi" {
        &item["rfi"]["replyBy"]
    } else {
        &item["due"]
    };
    json!({
        "id": item["id"],
        "label": format!("{} #{}", if profile == "rfi" { "RFI" } else { "Task" }, item["number"].as_u64().unwrap_or(0)),
        "profile": profile,
        "title": item["title"],
        "status": item["status"],
        "due": due["date"].as_str().or_else(|| due["at"].as_str()),
    })
}

/// `work_list`.
pub async fn work_list(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let view = args["view"].as_str().unwrap_or("waiting");
    if !["waiting", "mine", "asked", "all"].contains(&view) {
        return Err(anyhow!("view is waiting, mine, asked or all"));
    }
    let limit = args["limit"]
        .as_u64()
        .unwrap_or(airdress_mcp_catalogue::LIMIT_DEFAULT as u64)
        .clamp(1, airdress_mcp_catalogue::LIMIT_MAX as u64);
    let list = send(
        session,
        target,
        reqwest::Method::GET,
        "/v1/work/items",
        &[("view", view.to_owned()), ("limit", limit.to_string())],
        None,
    )
    .await?;
    let items: Vec<Value> = list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(summary)
        .collect();
    Ok(json!({ "view": view, "items": items }))
}

/// `work_get`. The place's access text (gate codes) is left out: a model
/// has no need to repeat it.
pub async fn work_get(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let id: uuid::Uuid = args["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("id is the work item's id"))?;
    let mut item = send(
        session,
        target,
        reqwest::Method::GET,
        &format!("/v1/work/items/{id}"),
        &[],
        None,
    )
    .await?;
    if let Some(place) = item.get_mut("place").and_then(Value::as_object_mut) {
        place.remove("access");
    }
    let answer = &item["rfi"]["officialAnswer"];
    if answer["costImpact"].as_str().is_some_and(|c| c != "none")
        || answer["scheduleImpact"]
            .as_str()
            .is_some_and(|c| c != "none")
    {
        item["note"] = json!("An answer is not approval of extra cost or time.");
    }
    Ok(item)
}

/// `work_draft`: offer the signed-in person a draft. Never a work item.
pub async fn work_draft(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let text = |k: &str| args[k].as_str().unwrap_or("").to_owned();
    let body = json!({
        "profile": text("profile"),
        "title": text("title"),
        "assignee": text("assignee"),
        "due": text("due"),
        "place": text("place"),
        "question": text("question"),
        "references": args["references"].as_array().cloned().unwrap_or_default(),
        "proposedAnswer": text("proposed_answer"),
    });
    let draft = send(
        session,
        target,
        reqwest::Method::POST,
        "/v1/work/drafts",
        &[],
        Some(&body),
    )
    .await?;
    Ok(json!({
        "draft": draft["id"],
        "created": false,
        "next": "This is a draft, not a work item. The person reviews it and creates it themselves, \
                 in the app or with `airdress work`.",
        "proposed": draft["draft"],
        "expires_at": draft["expiresAt"],
    }))
}
