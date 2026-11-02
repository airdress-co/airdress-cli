//! The work-item tools: `work_list`, `work_get` and `work_draft`
//! (SPEC-182 182-D.2).
//!
//! They call the person's own operator (`/v1/work/…`) with the person's own
//! sign-in. **None of them makes a work item.** `work_draft` offers the
//! signed-in person a draft, which they create themselves, in the app or
//! with `airdress work`: an assistant drafts, a person confirms.
//!
//! Everything but the HTTP call is a pure function, tested below.

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
    let base = crate::mcp::operator_base(&target.fqdn);
    request(&base, bearer.expose(), method, path, query, body).await
}

/// One call to an operator's work routes, read as JSON; a refusal becomes
/// the sentence a model can act on.
async fn request(
    base: &str,
    bearer: &str,
    method: reqwest::Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<&Value>,
) -> Result<Value> {
    let url = format!("{base}{path}");
    let mut req = crate::http::client()?
        .request(method.clone(), &url)
        .query(query)
        .bearer_auth(bearer);
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
        "label": format!(
            "{} #{}",
            if profile == "rfi" { "RFI" } else { "Task" },
            item["number"].as_u64().unwrap_or(0)
        ),
        "profile": profile,
        "title": item["title"],
        "status": item["status"],
        "due": due["date"].as_str().or_else(|| due["at"].as_str()),
    })
}

/// The list a `work_list` call asks for: its view and limit.
fn list_query(args: &Value) -> Result<(&str, u64)> {
    let view = args["view"].as_str().unwrap_or("waiting");
    if !["waiting", "mine", "asked", "all"].contains(&view) {
        return Err(anyhow!("view is waiting, mine, asked or all"));
    }
    let limit = args["limit"]
        .as_u64()
        .unwrap_or(airdress_mcp_catalogue::LIMIT_DEFAULT as u64)
        .clamp(1, airdress_mcp_catalogue::LIMIT_MAX as u64);
    Ok((view, limit))
}

/// What `work_list` answers, from the operator's list.
fn list_answer(view: &str, list: &Value) -> Value {
    let items: Vec<Value> = list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(summary)
        .collect();
    json!({ "view": view, "items": items })
}

/// `work_list`.
pub async fn work_list(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let (view, limit) = list_query(args)?;
    let list = send(
        session,
        target,
        reqwest::Method::GET,
        "/v1/work/items",
        &[("view", view.to_owned()), ("limit", limit.to_string())],
        None,
    )
    .await?;
    Ok(list_answer(view, &list))
}

fn item_id(args: &Value) -> Result<uuid::Uuid> {
    args["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("id is the work item's id"))
}

/// An item as a model may see it: the place's access text (gate codes)
/// left out, and the approval note when an answer flags an impact.
fn scrub(mut item: Value) -> Value {
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
    item
}

/// `work_get`.
pub async fn work_get(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let id = item_id(args)?;
    let item = send(
        session,
        target,
        reqwest::Method::GET,
        &format!("/v1/work/items/{id}"),
        &[],
        None,
    )
    .await?;
    Ok(scrub(item))
}

/// The operator's draft body, from a tool call's arguments.
fn draft_body(args: &Value) -> Value {
    let text = |k: &str| args[k].as_str().unwrap_or("").to_owned();
    json!({
        "profile": text("profile"),
        "title": text("title"),
        "assignee": text("assignee"),
        "due": text("due"),
        "place": text("place"),
        "question": text("question"),
        "references": args["references"].as_array().cloned().unwrap_or_default(),
        "proposedAnswer": text("proposed_answer"),
    })
}

/// What `work_draft` answers: that this is a draft, and what is next.
fn draft_answer(draft: &Value) -> Value {
    json!({
        "draft": draft["id"],
        "created": false,
        "next": "This is a draft, not a work item. The person reviews it and creates it \
                 themselves, in the app or with `airdress work`.",
        "proposed": draft["draft"],
        "expires_at": draft["expiresAt"],
    })
}

/// `work_draft`: offer the signed-in person a draft. Never a work item.
pub async fn work_draft(session: &Arc<Session>, target: &Target, args: &Value) -> Result<Value> {
    let body = draft_body(args);
    let draft = send(
        session,
        target,
        reqwest::Method::POST,
        "/v1/work/drafts",
        &[],
        Some(&body),
    )
    .await?;
    Ok(draft_answer(&draft))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_asks_for_a_known_view_within_the_limits() {
        let default = airdress_mcp_catalogue::LIMIT_DEFAULT as u64;
        assert_eq!(list_query(&json!({})).unwrap(), ("waiting", default));
        assert_eq!(
            list_query(&json!({"view": "asked", "limit": 0})).unwrap(),
            ("asked", 1)
        );
        assert_eq!(
            list_query(&json!({"view": "all", "limit": 10_000}))
                .unwrap()
                .1,
            airdress_mcp_catalogue::LIMIT_MAX as u64
        );
        assert!(list_query(&json!({"view": "everything"})).is_err());
    }

    #[test]
    fn a_list_names_each_item_and_its_due() {
        let list = json!({"items": [
            {"id": "a", "profile": "task", "number": 12, "title": "Re-seal",
             "status": "needs-action", "due": {"date": "2026-11-06"}},
            {"id": "b", "profile": "rfi", "number": 7, "title": "Sill?", "status": "open",
             "rfi": {"replyBy": {"at": "2026-11-04T09:00:00Z"}}},
        ]});
        let a = list_answer("waiting", &list);
        assert_eq!(a["items"][0]["label"], "Task #12");
        assert_eq!(a["items"][0]["due"], "2026-11-06");
        assert_eq!(a["items"][1]["label"], "RFI #7");
        assert_eq!(a["items"][1]["due"], "2026-11-04T09:00:00Z");
        assert_eq!(list_answer("all", &json!({}))["items"], json!([]));
    }

    #[test]
    fn an_item_reaches_a_model_without_its_gate_code() {
        let item = scrub(json!({"place": {"name": "Unit 4", "access": "Gate code 4711"}}));
        assert_eq!(item["place"], json!({"name": "Unit 4"}));
        assert!(item.get("note").is_none());
        let answered = scrub(json!({"rfi": {"officialAnswer":
            {"costImpact": "possible", "scheduleImpact": "none"}}}));
        assert_eq!(
            answered["note"],
            "An answer is not approval of extra cost or time."
        );
        assert!(item_id(&json!({"id": "nope"})).is_err());
        assert!(item_id(&json!({"id": "0b9e2c57-1d3a-4f6e-8a21-5c4d3e2f1a00"})).is_ok());
    }

    #[test]
    fn a_draft_is_said_to_be_a_draft() {
        let body = draft_body(&json!({"profile": "rfi", "title": "Sill?",
            "question": "Under or over?", "proposed_answer": "Under", "references": ["A-301"]}));
        assert_eq!(body["proposedAnswer"], "Under");
        assert_eq!(body["references"], json!(["A-301"]));
        assert_eq!(body["assignee"], "");
        let a = draft_answer(&json!({"id": "d1", "draft": {"title": "Sill?"},
            "expiresAt": "2026-11-03T00:00:00Z"}));
        assert_eq!(a["created"], false);
        assert!(a["next"].as_str().unwrap().contains("not a work item"));
    }

    #[tokio::test]
    async fn a_call_reads_json_and_turns_a_refusal_into_a_sentence() {
        use crate::functions::test_support::{canned_operator, response};
        let (base, handle) = canned_operator(vec![
            response("200 OK", r#"{"items": []}"#),
            response(
                "403 Forbidden",
                r#"{"error":"not_enabled","feature":"work"}"#,
            ),
            response("200 OK", "not json"),
            response(
                "201 Created",
                r#"{"id": "d1", "draft": {}, "expiresAt": "x"}"#,
            ),
        ])
        .await;
        let list = request(
            &base,
            "t",
            reqwest::Method::GET,
            "/v1/work/items",
            &[("view", "mine".to_owned())],
            None,
        )
        .await
        .unwrap();
        assert_eq!(list_answer("mine", &list)["items"], json!([]));
        let refused = request(
            &base,
            "t",
            reqwest::Method::GET,
            "/v1/work/items",
            &[],
            None,
        )
        .await;
        assert!(refused.unwrap_err().to_string().contains("not turned on"));
        let garbled = request(
            &base,
            "t",
            reqwest::Method::GET,
            "/v1/work/items/x",
            &[],
            None,
        )
        .await;
        assert!(garbled.unwrap_err().to_string().contains("unreadable"));
        let body = draft_body(&json!({"profile": "task", "title": "Re-seal"}));
        let draft = request(
            &base,
            "t",
            reqwest::Method::POST,
            "/v1/work/drafts",
            &[],
            Some(&body),
        )
        .await
        .unwrap();
        assert_eq!(draft_answer(&draft)["draft"], "d1");
        let seen = handle.await.unwrap();
        assert!(
            seen[0].starts_with("GET /v1/work/items?view=mine "),
            "{}",
            seen[0]
        );
        assert!(seen[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer t"));
        assert!(seen[3].starts_with("POST /v1/work/drafts "));
        assert!(seen[3].contains("\"title\":\"Re-seal\""));
    }

    #[test]
    fn refusals_say_what_to_do() {
        let says = |status, body: &str| refusal(status, body).to_string();
        assert!(says(403, r#"{"error":"not_enabled"}"#).contains("not turned on"));
        assert!(
            says(404, r#"{"error":{"code":"work_item_not_found"}}"#).contains("no such work item")
        );
        assert!(says(404, "").contains("newer release"));
        assert!(
            says(400, r#"{"error":{"message":"an RFI needs its question"}}"#)
                .contains("an RFI needs its question")
        );
        assert!(says(400, "garbage").contains("not a usable draft"));
        assert!(says(401, "").contains("refused"));
        assert!(says(500, "").contains("Try again"));
    }
}
