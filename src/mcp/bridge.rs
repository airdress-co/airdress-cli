//! The airdress's own tools, proxied.
//!
//! An airdress whose functions declare tools mounts a JSON-RPC endpoint
//! at `/v1/tools/mcp`. This module speaks to it so those tools can be
//! re-exported to the harness as `fn_<tool>`, which means a model calls
//! a function the user wrote the same way it calls anything else.
//!
//! Two rules it keeps. A `tools/call` is **never** retried: the
//! function may have acted before it failed, and a second attempt would
//! act twice. And a bridged tool that does not claim to be read-only is
//! exported as destructive — a function's own annotation is a hint from
//! its author, so the safe reading is the one we pass on.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::http;
use crate::redact::Redacted;

/// The prefix a re-exported tool carries.
pub const EXPORT_PREFIX: &str = "fn_";

/// How long an exported name may be, measured the way a harness
/// measures it: with the server prefix a client adds in front.
///
/// Claude Code's tool names arrive as `mcp__<server>__<tool>`; the
/// ceiling applies to the whole thing, so the budget left for ours is
/// what remains after the longest such prefix we know of. A longer name
/// is shortened with a hash rather than cut, so two long names cannot
/// collide.
const MAX_EXPORTED_NAME: usize = 64;

/// A tool the airdress publishes.
#[derive(Debug, Clone)]
pub struct BridgedTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// What the function's author claimed.
    pub read_only: bool,
}

impl BridgedTool {
    /// The name this tool is offered under.
    pub fn exported_name(&self, server_prefix_len: usize) -> String {
        let candidate = format!("{EXPORT_PREFIX}{}", sanitise(&self.name));
        if server_prefix_len + candidate.len() <= MAX_EXPORTED_NAME {
            return candidate;
        }
        // Shorten deterministically: keep what fits, end with a hash of
        // the full name so two long names stay distinct.
        let digest = short_hash(&self.name);
        let room = MAX_EXPORTED_NAME
            .saturating_sub(server_prefix_len + EXPORT_PREFIX.len() + 1 + digest.len());
        let head: String = sanitise(&self.name).chars().take(room).collect();
        format!("{EXPORT_PREFIX}{head}_{digest}")
    }
}

/// Lower-snake a function's tool name so it is a legal tool name here.
fn sanitise(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Eight hex characters of SHA-256 over the full name.
fn short_hash(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// A client for one airdress's tool bridge.
#[derive(Debug)]
pub struct Bridge {
    url: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl Bridge {
    pub fn new(fqdn: &str, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        Ok(Self {
            url: format!("{}/v1/tools/mcp", crate::mcp::operator_base(fqdn)),
            bearer: bearer.into(),
            http: http::client()?,
        })
    }

    /// One JSON-RPC round trip.
    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(self.bearer.expose())
            .json(&body)
            .send()
            .await
            .map_err(|e| http::format_transport_error(&self.url, "POST", e))?;
        let status = resp.status().as_u16();
        if status == 404 || status == 405 {
            bail!("tool_bridge_absent");
        }
        let resp = http::handle_status(resp, "call the airdress's tool bridge").await?;
        let value: Value = resp.json().await.context("parse tool bridge response")?;
        if let Some(err) = value.get("error") {
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the airdress's tool bridge refused the call");
            bail!("{message}");
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Whether this airdress mounts a bridge at all.
    ///
    /// An absent bridge is not an error: most airdresses have no
    /// function publishing a tool.
    pub async fn present(&self) -> Result<bool> {
        match self
            .rpc(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "airdress", "version": crate::build_version()},
                }),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.to_string() == "tool_bridge_absent" => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The tools this airdress publishes.
    pub async fn list(&self) -> Result<Vec<BridgedTool>> {
        let result = self.rpc("tools/list", json!({})).await?;
        let mut out = Vec::new();
        for t in result["tools"].as_array().cloned().unwrap_or_default() {
            let Some(name) = t["name"].as_str() else {
                continue;
            };
            out.push(BridgedTool {
                name: name.to_owned(),
                description: t["description"].as_str().unwrap_or_default().to_owned(),
                input_schema: t
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object"})),
                read_only: t["annotations"]["readOnlyHint"].as_bool().unwrap_or(false),
            });
        }
        Ok(out)
    }

    /// Call one. Once.
    pub async fn call(&self, tool: &str, arguments: &Value) -> Result<Value> {
        self.rpc(
            "tools/call",
            json!({"name": tool, "arguments": arguments.clone()}),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> BridgedTool {
        BridgedTool {
            name: name.into(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
            read_only: false,
        }
    }

    #[test]
    fn a_short_name_is_prefixed_and_left_alone() {
        assert_eq!(tool("send_invoice").exported_name(0), "fn_send_invoice");
        // Anything not a letter or digit becomes an underscore.
        assert_eq!(tool("Send-Invoice!").exported_name(0), "fn_send_invoice_");
    }

    #[test]
    fn a_long_name_is_hashed_not_cut() {
        let long_a = format!("{}_alpha", "x".repeat(80));
        let long_b = format!("{}_beta", "x".repeat(80));
        let a = tool(&long_a).exported_name(17);
        let b = tool(&long_b).exported_name(17);
        assert!(a.len() + 17 <= MAX_EXPORTED_NAME, "{a}");
        assert_ne!(a, b, "two long names collided");
        assert!(a.starts_with("fn_x"));
    }

    #[test]
    fn the_hash_is_stable() {
        assert_eq!(short_hash("send_invoice"), short_hash("send_invoice"));
        assert_ne!(short_hash("a"), short_hash("b"));
        assert_eq!(short_hash("a").len(), 8);
    }
}
