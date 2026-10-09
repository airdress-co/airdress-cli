//! What an airdress has turned on, and what to say when it has not.
//!
//! `GET /v1/capabilities` answers four booleans and nothing else. Three
//! of them are boundaries the operator enforces itself (the agent bus,
//! agent devices, remote MCP). The fourth, `mcp_local`, is read here
//! and nowhere else: the query half calls the airdress's own API over
//! data that is the user's, which the CLI reaches with or without this
//! server, so the switch makes *this* client behave rather than
//! standing between anybody and their data. That is the decision
//! (SPEC-133 D-40), not an oversight.
//!
//! Nothing in this module mentions a plan, a price or an upgrade — the
//! operator does not know about any of those, and the sentence it hands
//! a person points at the hub, which does.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::http;

/// How long a fetched answer is trusted before it is asked again. Short
/// enough that a lapse lands inside the five minutes the fleet promises,
/// long enough that a dozen tool calls in a row ask once.
const TTL: Duration = Duration::from_secs(30);

/// Where a person manages the airdress and sees what it includes.
const ACCOUNT_BASE: &str = "https://account.airdress.co";

/// The four switches, exactly as the operator reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub agent_bus: bool,
    #[serde(default)]
    pub agent_devices: bool,
    #[serde(default)]
    pub mcp_local: bool,
    #[serde(default)]
    pub mcp_remote: bool,
}

impl Capabilities {
    /// What an operator that has never heard of this route says. An old
    /// operator answers 404; treating that as "all off" would lock a
    /// user out of their own functions, so it reads as the pre-switch
    /// world: the query half works, the new surfaces do not exist.
    pub const fn predates_switches() -> Self {
        Self {
            agent_bus: false,
            agent_devices: false,
            mcp_local: true,
            mcp_remote: false,
        }
    }
}

/// One feature's name on the wire, as `not_enabled` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    AgentBus,
    AgentDevices,
    McpLocal,
    McpRemote,
}

impl Feature {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::AgentBus => "agent_bus",
            Self::AgentDevices => "agent_devices",
            Self::McpLocal => "mcp_local",
            Self::McpRemote => "mcp_remote",
        }
    }

    /// The feature in words, for the sentence a person reads.
    pub const fn in_words(self) -> &'static str {
        match self {
            Self::AgentBus => "The agent bus",
            Self::AgentDevices => "Agent devices",
            Self::McpLocal => "Reaching this airdress from an editor",
            Self::McpRemote => "Reaching this airdress from a hosted assistant",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "agent_bus" => Self::AgentBus,
            "agent_devices" => Self::AgentDevices,
            "mcp_local" => Self::McpLocal,
            "mcp_remote" => Self::McpRemote,
            _ => return None,
        })
    }
}

/// The sentence the plugin renders for a switched-off feature.
///
/// Two parts and no third: what is off, and where the person decides
/// about it. `airdress_id` is the hub's id for the airdress; without one
/// the link is to the list, which is still somewhere to go.
pub fn not_enabled_sentence(feature: Feature, airdress_id: Option<&str>) -> String {
    let link = match airdress_id {
        Some(id) => format!("{ACCOUNT_BASE}/airdresses/{id}"),
        None => format!("{ACCOUNT_BASE}/airdresses"),
    };
    format!(
        "{} is not enabled on this airdress. Manage this airdress: {link}",
        feature.in_words()
    )
}

/// A fetched answer and when it was fetched.
#[derive(Debug, Clone)]
pub struct Cached {
    pub value: Capabilities,
    at: Instant,
}

impl Cached {
    pub fn new(value: Capabilities) -> Self {
        Self {
            value,
            at: Instant::now(),
        }
    }

    pub fn fresh(&self) -> bool {
        self.at.elapsed() < TTL
    }
}

/// Ask one operator what it has turned on.
///
/// A 404 is an operator older than the route, not a refusal; anything
/// else that is not a 200 is an error the caller shows.
pub async fn fetch(fqdn: &str, bearer: &str) -> Result<Capabilities> {
    let url = format!("{}/v1/capabilities", crate::mcp::operator_base(fqdn));
    let client = http::client()?;
    let resp = client
        .get(&url)
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    if resp.status().as_u16() == 404 {
        return Ok(Capabilities::predates_switches());
    }
    let resp = http::handle_status(resp, "read capabilities").await?;
    resp.json().await.context("parse capabilities")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sentence_says_what_is_off_and_where_to_go_and_nothing_else() {
        let s = not_enabled_sentence(Feature::AgentBus, Some("abc-123"));
        assert_eq!(
            s,
            "The agent bus is not enabled on this airdress. Manage this airdress: \
             https://account.airdress.co/airdresses/abc-123"
        );
        let lower = s.to_lowercase();
        for word in ["plan", "price", "upgrade", "subscri", "tier", "€", "$"] {
            assert!(!lower.contains(word), "the sentence mentions {word}: {s}");
        }
        // No id: still somewhere to go.
        assert!(not_enabled_sentence(Feature::McpLocal, None).contains("/airdresses"));
    }

    #[test]
    fn wire_names_round_trip() {
        for f in [
            Feature::AgentBus,
            Feature::AgentDevices,
            Feature::McpLocal,
            Feature::McpRemote,
        ] {
            assert_eq!(Feature::from_wire(f.wire()), Some(f));
        }
        assert!(Feature::from_wire("something_else").is_none());
    }

    #[test]
    fn an_operator_that_predates_the_route_keeps_the_query_half() {
        let c = Capabilities::predates_switches();
        assert!(c.mcp_local, "an old operator must not lock a user out");
        assert!(!c.agent_bus && !c.agent_devices && !c.mcp_remote);
    }

    #[test]
    fn missing_fields_read_as_off() {
        let c: Capabilities = serde_json::from_str("{}").unwrap();
        assert_eq!(
            c,
            Capabilities {
                agent_bus: false,
                agent_devices: false,
                mcp_local: false,
                mcp_remote: false
            }
        );
    }
}
