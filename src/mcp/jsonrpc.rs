//! JSON-RPC 2.0 over stdio, as the MCP stdio transport defines it:
//! one JSON object per line, requests and notifications in, responses
//! and notifications out, and nothing else on stdout ever.
//!
//! Written by hand rather than taken from a framework for one reason
//! that matters here: this process must contain no telemetry and no
//! dependency that could grow one (SPEC-133 FR-112), and the framing
//! is twenty lines.

use serde::Serialize;
use serde_json::{json, Value};

/// A request or notification read from the client.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// Absent for a notification, which takes no answer.
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

/// Why a line could not be read as a request.
#[derive(Debug)]
pub enum ParseError {
    /// Not JSON at all.
    Malformed(String),
    /// JSON, but not a JSON-RPC request we can answer.
    Invalid { id: Option<Value>, message: String },
}

/// Parse one line.
pub fn parse(line: &str) -> Result<Incoming, ParseError> {
    let value: Value =
        serde_json::from_str(line).map_err(|e| ParseError::Malformed(e.to_string()))?;
    let id = value.get("id").filter(|v| !v.is_null()).cloned();
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Err(ParseError::Invalid {
            id,
            message: "no method".into(),
        });
    };
    Ok(Incoming {
        id,
        method: method.to_owned(),
        params: value.get("params").cloned().unwrap_or(Value::Null),
    })
}

/// Standard JSON-RPC error codes, plus the one MCP adds.
pub mod code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// A successful response.
pub fn result(id: Value, result: impl Serialize) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// An error response.
pub fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {"code": code, "message": message.into()},
    })
}

/// A notification to the client.
pub fn notification(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_a_notification_and_two_kinds_of_rubbish() {
        let r = parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert_eq!(r.method, "tools/list");
        assert_eq!(r.id, Some(json!(1)));
        assert!(r.params.is_null());

        let n = parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(n.id.is_none());

        // A null id is a notification's id, not a request's.
        let n = parse(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).unwrap();
        assert!(n.id.is_none());

        assert!(matches!(parse("not json"), Err(ParseError::Malformed(_))));
        assert!(matches!(
            parse(r#"{"jsonrpc":"2.0","id":7}"#),
            Err(ParseError::Invalid { .. })
        ));
    }

    #[test]
    fn responses_are_shaped_as_the_protocol_wants() {
        let ok = result(json!(1), json!({"tools": []}));
        assert_eq!(ok["jsonrpc"], "2.0");
        assert_eq!(ok["id"], 1);
        assert!(ok["result"]["tools"].is_array());

        let err = error(Some(json!(2)), code::METHOD_NOT_FOUND, "no such method");
        assert_eq!(err["error"]["code"], code::METHOD_NOT_FOUND);
        // An error with no id still answers, with a null id.
        assert_eq!(error(None, code::PARSE_ERROR, "x")["id"], Value::Null);
    }
}
