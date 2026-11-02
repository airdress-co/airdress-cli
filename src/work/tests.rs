use serde_json::json;

use super::*;
use crate::functions::test_support::{canned_operator, response};

const ANA: &str = "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11";
const ITEM: &str = "0b9e2c57-1d3a-4f6e-8a21-5c4d3e2f1a00";

fn task_json() -> Value {
    json!({
        "id": ITEM, "profile": "task", "number": 12, "title": "Re-seal the bay 3 window",
        "status": "needs-action", "due": { "date": "2026-11-06" },
        "place": { "name": "Holloway Rd", "access": "Gate code 4711" }
    })
}

fn rfi_json() -> Value {
    json!({
        "id": ITEM, "profile": "rfi", "number": 7, "title": "Sill under or over?", "status": "answered",
        "rfi": {
            "question": "Does the sill go under the membrane?", "references": ["Drawing A-301"],
            "replyBy": { "date": "2026-11-04" },
            "officialAnswer": { "text": "Under.", "costImpact": "possible", "scheduleImpact": "none" }
        }
    })
}

#[test]
fn labels_and_the_table() {
    assert_eq!(label(&task_json()), "Task #12");
    assert_eq!(label(&rfi_json()), "RFI #7");
    let t = render_table(&[task_json(), rfi_json()]);
    let lines: Vec<&str> = t.lines().collect();
    assert!(lines[0].starts_with("ITEM"));
    assert!(lines[1].contains("Task #12") && lines[1].contains("2026-11-06"));
    assert!(
        lines[2].contains("RFI #7") && lines[2].contains("2026-11-04"),
        "an RFI shows its reply-by"
    );
}

#[test]
fn an_item_reads_with_its_access_and_its_answer() {
    let t = render_item(&task_json());
    assert!(t.contains("access: Gate code 4711"));
    assert!(t.contains("not end to end"));
    let r = render_item(&rfi_json());
    assert!(r.contains("question: Does the sill"));
    assert!(r.contains("ref: Drawing A-301"));
    assert!(r.contains("An answer is not approval of extra cost or time."));
}

#[test]
fn names_match_once_and_case_blind() {
    let mut people = Map::new();
    people.insert("Ana".into(), json!(ANA));
    people.insert("Bo".into(), json!("00000000-0000-0000-0000-000000000002"));
    assert_eq!(match_person("ana", &people).unwrap().to_string(), ANA);
    assert!(match_person("Cy", &people)
        .unwrap_err()
        .to_string()
        .contains("no person called"));
    people.insert("ANA".into(), json!("00000000-0000-0000-0000-000000000003"));
    assert!(match_person("Ana", &people)
        .unwrap_err()
        .to_string()
        .contains("more than one"));
}

#[tokio::test]
async fn a_task_to_a_named_person_looks_them_up_then_creates() {
    let people = json!([{ "id": ANA, "display_name": "Ana" }]).to_string();
    let (base, handle) = canned_operator(vec![
        response("200 OK", &people),
        response("201 Created", &task_json().to_string()),
    ])
    .await;
    let op = WorkClient::with_base_url(&base, "t".to_owned()).unwrap();
    run_with(
        &op,
        WorkCommands::Task {
            title: "Re-seal the bay 3 window".into(),
            to: vec!["Ana".into()],
            watch: vec![],
            description: None,
            due: Some(chrono::NaiveDate::from_ymd_opt(2026, 11, 6).unwrap()),
            priority: Priority::High,
            at: Some("Holloway Rd".into()),
        },
        true,
    )
    .await
    .unwrap();
    let seen = handle.await.unwrap();
    assert!(
        seen[0].starts_with("GET /v1/admin/sub-users"),
        "{}",
        seen[0]
    );
    assert!(seen[1].starts_with("POST /v1/work/items "), "{}", seen[1]);
    let body: Value = serde_json::from_str(seen[1].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["profile"], "task");
    assert_eq!(
        body["assignees"][0],
        json!({ "kind": "principal", "id": ANA })
    );
    assert_eq!(body["due"], json!({ "date": "2026-11-06" }));
    assert_eq!(body["priority"], "high");
    assert_eq!(body["place"], json!({ "name": "Holloway Rd" }));
}

#[tokio::test]
async fn an_id_needs_no_lookup_and_status_and_answer_say_what_they_send() {
    let (base, handle) = canned_operator(vec![
        response("201 Created", &rfi_json().to_string()),
        response("200 OK", &rfi_json().to_string()),
        response("200 OK", &rfi_json().to_string()),
    ])
    .await;
    let op = WorkClient::with_base_url(&base, "t".to_owned()).unwrap();
    run_with(
        &op,
        WorkCommands::Rfi {
            title: "Sill under or over?".into(),
            question: "Does the sill go under the membrane?".into(),
            to: vec![ANA.into()],
            refs: vec!["Drawing A-301".into()],
            propose: Some("Under".into()),
            reply_by: None,
            watch: vec![],
        },
        true,
    )
    .await
    .unwrap();
    let id: uuid::Uuid = ITEM.parse().unwrap();
    run_with(
        &op,
        WorkCommands::Answer {
            id,
            text: "Under.".into(),
            cost: Impact::Possible,
            schedule: Impact::None,
        },
        true,
    )
    .await
    .unwrap();
    run_with(
        &op,
        WorkCommands::Status {
            id,
            to: StatusArg::Closed,
        },
        true,
    )
    .await
    .unwrap();
    let seen = handle.await.unwrap();
    let body = |i: usize| -> Value {
        serde_json::from_str(seen[i].split("\r\n\r\n").nth(1).unwrap()).unwrap()
    };
    assert!(seen[0].starts_with("POST /v1/work/items "));
    assert_eq!(body(0)["rfi"]["proposedAnswer"], "Under");
    assert_eq!(body(0)["rfi"]["references"], json!(["Drawing A-301"]));
    assert!(seen[1].starts_with(&format!("POST /v1/work/items/{ITEM}/answer")));
    assert_eq!(
        body(1),
        json!({ "text": "Under.", "costImpact": "possible", "scheduleImpact": "none" })
    );
    assert!(seen[2].starts_with(&format!("POST /v1/work/items/{ITEM}/status")));
    assert_eq!(body(2), json!({ "to": "closed" }));
}

#[tokio::test]
async fn a_refusal_says_the_operators_code() {
    let (base, _h) = canned_operator(vec![response(
        "403 Forbidden",
        r#"{"error":"not_enabled","feature":"work"}"#,
    )])
    .await;
    let op = WorkClient::with_base_url(&base, "t".to_owned()).unwrap();
    let e = run_with(
        &op,
        WorkCommands::List {
            view: View::Waiting,
            limit: 50,
        },
        true,
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("not_enabled"), "{e:#}");
}
