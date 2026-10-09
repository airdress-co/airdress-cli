//! Does the airdress answer, and which binary is answering.
//!
//! Direct, not through the hub: `airdress airdress probe` asks the hub
//! to reach the operator because the hub's network reach is the one
//! that matters for "is this airdress published correctly". Here the
//! question is different — this machine is about to deploy a function
//! to that operator, so the reach that matters is this machine's.

use anyhow::Result;
use serde_json::{json, Value};

use crate::http;

/// Ask one operator who it is.
///
/// `/v1/whoami` is authenticated and carries the operator's version and
/// the airdress it believes it serves, which is the pair worth knowing
/// before a write. A 401 is reported rather than raised: "I reached it
/// and it does not accept this token" is a useful answer.
pub async fn operator(fqdn: &str, bearer: &str) -> Result<Value> {
    let url = format!("{}/v1/whoami", crate::mcp::operator_base(fqdn));
    let resp = http::client()?
        .get(&url)
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    let status = resp.status().as_u16();
    if status == 200 {
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        return Ok(json!({
            "reachable": true,
            "accepts_this_token": true,
            "version": body["operator_version"],
            "serves_airdress": body["airdress_name"],
        }));
    }
    Ok(json!({
        "reachable": true,
        "accepts_this_token": false,
        "http_status": status,
        "why": match status {
            401 => "the operator did not accept this account's token",
            503 => "the operator is up but its sign-in is not configured",
            _ => "the operator answered, but not with an identity",
        },
    }))
}
