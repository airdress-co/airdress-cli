//! Reading the operator's refusals and printing them where a terminal, an
//! editor's problem matcher and a CI log all understand them:
//!
//! ```text
//! src/lib/sign.ts:12:3: SourceImportUnresolved: ./missing does not resolve
//! ```
//!
//! The body is the operator's structured error (SPEC-112 design §15.3):
//! `error` (the reason in snake case), `message`, and — when the refusal is
//! a place in the tree — `locations[]` with `path`, `line`, `column`, and —
//! when the tree asks for more than the owner granted — `denials[]`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A refusal of a publish or a dry run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Refusal {
    pub error: String,
    /// The refusal's name as the status condition spells it
    /// (`TranspileFailed`). Absent on errors that are not refusals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub denials: Vec<Denial>,
    /// The one edit that resolves it, when the operator names one (the
    /// Functions SDK's refusals): `{ file, add | set }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<Value>,
    /// Every other field the operator answered with (`basedOn`, `current`,
    /// a limit, a count …), kept so a refusal is printed with all of them
    /// and a newer operator's fields are never dropped.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Read a refusal body in either of the operator's two shapes: the
/// authoring routes' flat `{"error": "<code>", "message", …}`, and the
/// gate's nested `{"error": {"code", "message"}}` (resource plane, machine
/// signatures). A body that is neither becomes `http_<status>` with the
/// text as its message, so nothing is ever coerced into a known code.
pub fn parse(status: u16, text: &str) -> Refusal {
    let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    if let Some(nested) = value.get("error").and_then(Value::as_object) {
        return Refusal {
            error: nested
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            message: nested
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            ..Refusal::default()
        }
        .or_status(status, text);
    }
    serde_json::from_value::<Refusal>(value)
        .unwrap_or_default()
        .or_status(status, text)
}

impl Refusal {
    fn or_status(mut self, status: u16, text: &str) -> Self {
        if self.error.is_empty() {
            self.error = format!("http_{status}");
            if self.message.is_empty() {
                self.message = text.trim().to_owned();
            }
        }
        self
    }
}

/// Where in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Location {
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub column: Option<u32>,
}

/// One capability the owner has not granted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Denial {
    pub capability: String,
    #[serde(default)]
    pub detail: String,
    #[serde(rename = "grantPath", default)]
    pub grant_path: String,
}

/// The Functions SDK's refusals, in the order of `sdk-refusals.txt`, the
/// list the editor extension carries too, and what to do about each. The
/// codes are the operator's own, passed through verbatim; this only adds
/// the next step.
pub const SDK_REFUSALS: [(&str, &str); 6] = [
    (
        "sdk_not_pinned",
        "pin the library in function.json (`airdress fn sdk pull --pin newest`)",
    ),
    (
        "sdk_version_unknown",
        "pin an exact version this operator carries (`GET /v1/functions/sdk`)",
    ),
    (
        "sdk_version_withdrawn",
        "pin the replacement and deploy again",
    ),
    (
        "sdk_module_unknown",
        "import one of the pinned version's modules",
    ),
    (
        "sdk_module_test_only",
        "import @airdress/functions/testing from test/, beside src/, never from src/",
    ),
    (
        "sdk_capability_not_requested",
        "request the world in function.json; the owner still grants it in spec.capabilities",
    ),
];

/// What to do about one of the library's refusals.
pub fn sdk_hint(code: &str) -> Option<&'static str> {
    SDK_REFUSALS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, h)| *h)
}

/// The operator's `fix` member as a line a person acts on.
pub fn format_fix(fix: &Value) -> Option<String> {
    let file = fix["file"].as_str().unwrap_or("function.json");
    if let Some(add) = fix["add"].as_object() {
        let parts: Vec<String> = add.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        return Some(format!("fix: add to {file}: {}", parts.join(", ")));
    }
    if let Some(set) = fix["set"].as_object() {
        let parts: Vec<String> = set.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        return Some(format!("fix: set in {file}: {}", parts.join(", ")));
    }
    None
}

/// The notes of a check or publish answer (`notes: [{ code, message }]`):
/// information, never a refusal.
pub fn notes(answer: &Value) -> Vec<String> {
    answer["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let code = n["code"].as_str().unwrap_or("note");
            let msg = n["message"].as_str().unwrap_or("");
            match n["location"]["path"].as_str() {
                Some(p) => format!("{p}: {code}: {msg}"),
                None => format!("{code}: {msg}"),
            }
        })
        .collect()
}

/// `409 source_base_stale`: the function moved since the tree was read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleBase {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub based_on: Option<String>,
    pub current: String,
    #[serde(default)]
    pub current_published_at: Option<String>,
    #[serde(default)]
    pub current_published_by: Option<String>,
}

/// The operator's code (`source_import_unresolved`) in the form its
/// condition reasons use (`SourceImportUnresolved`) — the fallback for an
/// answer that carries no `reason`. The operator derives the code from the
/// reason by exactly the inverse of this, so the two agree.
pub fn reason(code: &str) -> String {
    code.split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or_else(String::new, |f| {
                f.to_ascii_uppercase().to_string() + c.as_str()
            })
        })
        .collect()
}

/// One line per location (or one line with none), then one per denial.
pub fn format(r: &Refusal) -> Vec<String> {
    let reason = r
        .reason
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| reason(&r.error));
    let mut out = Vec::new();
    if r.locations.is_empty() {
        out.push(format!("{reason}: {}", r.message));
    }
    for loc in &r.locations {
        let place = match (loc.line, loc.column) {
            (Some(l), Some(c)) => format!("{}:{l}:{c}", loc.path),
            (Some(l), None) => format!("{}:{l}", loc.path),
            _ => loc.path.clone(),
        };
        out.push(format!("{place}: {reason}: {}", r.message));
    }
    for d in &r.denials {
        out.push(format!(
            "{}: {reason}: {} ({})",
            d.grant_path, d.capability, d.detail
        ));
    }
    if let Some(line) = r.fix.as_ref().and_then(format_fix) {
        out.push(format!("  {line}"));
    }
    if let Some(hint) = sdk_hint(&r.error) {
        out.push(format!("  → {hint}"));
    }
    for (k, v) in &r.extra {
        let v = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push(format!("  {k}: {v}"));
    }
    out
}

/// What to print for a stale base: both versions, and who moved it.
pub fn format_stale(s: &StaleBase) -> Vec<String> {
    let mut out = vec![format!(
        "SourceBaseStale: {}",
        if s.message.is_empty() {
            "the function has moved since this tree was read"
        } else {
            &s.message
        }
    )];
    out.push(format!(
        "  based on: {}",
        s.based_on
            .as_deref()
            .unwrap_or("(none given: pass --based-on)")
    ));
    let mut current = format!("  current:  {}", s.current);
    match (&s.current_published_at, &s.current_published_by) {
        (Some(at), Some(by)) => current.push_str(&format!(" (published {at} by {by})")),
        (Some(at), None) => current.push_str(&format!(" (published {at})")),
        (None, Some(by)) => current.push_str(&format!(" (published by {by})")),
        (None, None) => {}
    }
    out.push(current);
    out.push(format!(
        "  compare them: airdress functions source {} <path>, then re-base the tree and publish \
         with --based-on {}",
        s.current, s.current
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_refusal_shapes_are_read_and_nothing_is_coerced() {
        let nested = parse(
            401,
            r#"{"error":{"code":"machine_authorization_expired","message":"re-authenticate"}}"#,
        );
        assert_eq!(nested.error, "machine_authorization_expired");
        assert_eq!(nested.message, "re-authenticate");
        let flat = parse(
            409,
            r#"{"error":"a_code_from_a_newer_operator","message":"m","limit":16}"#,
        );
        assert_eq!(flat.error, "a_code_from_a_newer_operator");
        assert_eq!(flat.extra["limit"], 16);
        assert_eq!(format(&flat), ["ACodeFromANewerOperator: m", "  limit: 16"]);
        let bare = parse(405, "Method Not Allowed");
        assert_eq!(bare.error, "http_405");
        assert_eq!(bare.message, "Method Not Allowed");
    }

    #[test]
    fn codes_become_reasons() {
        assert_eq!(reason("source_import_unresolved"), "SourceImportUnresolved");
        assert_eq!(reason("transpile_failed"), "TranspileFailed");
        assert_eq!(reason("capability_not_granted"), "CapabilityNotGranted");
    }

    #[test]
    fn a_located_refusal_prints_path_line_column() {
        let body: Refusal = serde_json::from_value(serde_json::json!({
            "error": "transpile_failed",
            "message": "Expected ';'",
            "locations": [{ "path": "src/lib/sign.ts", "line": 12, "column": 3 }]
        }))
        .unwrap();
        assert_eq!(
            format(&body),
            ["src/lib/sign.ts:12:3: TranspileFailed: Expected ';'"]
        );
    }

    #[test]
    fn the_operator_reason_wins_over_the_derived_one() {
        let body: Refusal = serde_json::from_value(serde_json::json!({
            "error": "some_code",
            "reason": "SpelledByTheOperator",
            "message": "m"
        }))
        .unwrap();
        assert_eq!(format(&body), ["SpelledByTheOperator: m"]);
    }

    #[test]
    fn a_partial_location_prints_what_it_has() {
        let body: Refusal = serde_json::from_value(serde_json::json!({
            "error": "source_import_cycle",
            "message": "a -> b -> a",
            "locations": [
                { "path": "src/a.ts", "line": 4 },
                { "path": "src/b.ts" }
            ]
        }))
        .unwrap();
        assert_eq!(
            format(&body),
            [
                "src/a.ts:4: SourceImportCycle: a -> b -> a",
                "src/b.ts: SourceImportCycle: a -> b -> a",
            ]
        );
    }

    #[test]
    fn an_unlocated_refusal_is_one_line() {
        let body: Refusal = serde_json::from_value(serde_json::json!({
            "error": "source_unsigned",
            "message": "no signer"
        }))
        .unwrap();
        assert_eq!(format(&body), ["SourceUnsigned: no signer"]);
    }

    #[test]
    fn every_denial_is_named() {
        let body: Refusal = serde_json::from_value(serde_json::json!({
            "error": "capability_not_granted",
            "message": "the tree requests more than spec.capabilities grants",
            "denials": [
                { "capability": "airdress:fn/kv", "detail": "kv: not granted", "grantPath": "spec.capabilities.kv" },
                { "capability": "airdress:fn/http", "detail": "http.hosts not granted: x.example", "grantPath": "spec.capabilities.http" }
            ]
        }))
        .unwrap();
        let lines = format(&body);
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[1],
            "spec.capabilities.kv: CapabilityNotGranted: airdress:fn/kv (kv: not granted)"
        );
        assert!(lines[2].starts_with("spec.capabilities.http: "));
    }

    #[test]
    fn a_stale_base_names_both_versions() {
        let s: StaleBase = serde_json::from_value(serde_json::json!({
            "error": "source_base_stale",
            "message": "the function has moved since this tree was read",
            "basedOn": "sha256:aaaa",
            "current": "sha256:bbbb",
            "currentPublishedAt": "2026-09-25T10:00:00Z",
            "currentPublishedBy": "owner"
        }))
        .unwrap();
        let lines = format_stale(&s);
        assert!(lines[1].contains("sha256:aaaa"));
        assert!(lines[2].contains("sha256:bbbb"));
        assert!(lines[2].contains("by owner"));
    }

    /// Both clients carry the same list; the extension's copy is compared
    /// with this fixture byte for byte.
    #[test]
    fn the_sdk_refusals_equal_the_fixture() {
        let fixture = include_str!("sdk-refusals.txt");
        let codes: Vec<&str> = SDK_REFUSALS.iter().map(|(c, _)| *c).collect();
        assert_eq!(fixture, format!("{}\n", codes.join("\n")));
    }

    #[test]
    fn a_library_refusal_is_located_with_its_fix() {
        let body = parse(
            422,
            r#"{"error":"sdk_capability_not_requested","reason":"SdkCapabilityNotRequested",
                "message":"src/main.ts:4:1 imports @airdress/functions/dwell, which needs airdress:fn/kv",
                "locations":[{"path":"src/main.ts","line":4,"column":1}],
                "fix":{"file":"function.json","add":{"capabilities":[{"name":"airdress:fn/kv@0.1.0"}]}}}"#,
        );
        let lines = format(&body);
        assert!(
            lines[0].starts_with("src/main.ts:4:1: SdkCapabilityNotRequested: "),
            "{lines:?}"
        );
        assert_eq!(
            lines[1],
            r#"  fix: add to function.json: "capabilities": [{"name":"airdress:fn/kv@0.1.0"}]"#
        );
        assert!(lines[2].starts_with("  → request the world"), "{lines:?}");
        assert!(
            !body.extra.contains_key("fix"),
            "read, not left as an extra"
        );
        let pinned = parse(
            422,
            r#"{"error":"sdk_not_pinned","message":"m","fix":{"file":"function.json","set":{"sdk":"1.0.0"}}}"#,
        );
        assert_eq!(
            format(&pinned)[1],
            r#"  fix: set in function.json: "sdk": "1.0.0""#
        );
    }

    #[test]
    fn notes_are_information_with_their_codes() {
        let a = serde_json::json!({ "notes": [
            { "code": "sdk_module_alpha", "message": "dwell is alpha" },
            { "code": "x", "message": "y", "location": { "path": "src/main.ts" } }
        ] });
        assert_eq!(
            notes(&a),
            ["sdk_module_alpha: dwell is alpha", "src/main.ts: x: y"]
        );
        assert!(notes(&serde_json::json!({})).is_empty());
    }
}
