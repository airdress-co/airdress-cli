//! The default airdress's own tools, offered as `fn_<tool>`.
//!
//! `bridge_list` and `bridge_call` already let a model reach a
//! function's tools by asking for them. This is the other half: the
//! tools the default airdress publishes are offered in `tools/list`
//! under their own names, so a model calls a function the user wrote
//! the same way it calls anything else, without being told the bridge
//! exists.
//!
//! Three decisions, because each is a thing that could be done
//! differently:
//!
//!   * **The refresh is a loop, not a lookup per `tools/list`.**
//!     `tools/list` must answer before any network call (NFR-7), and a
//!     harness asks for it during start-up. So the list is whatever
//!     the last refresh saw, and the first refresh happens after
//!     `initialize` has been answered.
//!   * **A change is announced, not waited for.** When the set of
//!     exported names changes, the server sends
//!     `notifications/tools/list_changed`, which is why `initialize`
//!     claims `tools.listChanged`. A client that ignores the
//!     notification still gets the new list the next time it asks.
//!   * **A failed refresh changes nothing.** An airdress that is
//!     unreachable, or a bridge that is absent, leaves the previous
//!     list in place rather than withdrawing tools a model may be
//!     halfway through using. The one exception is an airdress that
//!     answers and publishes nothing, which is a real answer: the list
//!     becomes empty.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::mcp::bridge::{Bridge, BridgedTool};
use crate::mcp::session::Session;

/// How often the exported set is re-read.
///
/// Five minutes, matching the switch reconciler: a function's tools
/// change when somebody deploys one, which is not a thing that needs
/// to be noticed in seconds, and a shorter loop is a request per
/// airdress per interval for a list that rarely moves.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// What one refresh concluded.
#[derive(Debug)]
pub enum Refresh {
    /// The bridge answered. Carries what it published, which may be
    /// nothing.
    Listed(Vec<BridgedTool>),
    /// No bridge on this airdress, or it could not be reached. The
    /// previous list stands.
    Unchanged,
}

/// Ask the default airdress what it publishes.
pub async fn refresh_once(session: &Arc<Session>) -> Refresh {
    let Ok(target) = session.target(None).await else {
        // No default airdress resolved. Not an error here: the session
        // is usable, and every tool that needs a target says so itself.
        return Refresh::Unchanged;
    };
    let Ok(bearer) = session.bearer(&target.fqdn).await else {
        return Refresh::Unchanged;
    };
    let Ok(bridge) = Bridge::new(&target.fqdn, bearer.expose().to_owned()) else {
        return Refresh::Unchanged;
    };
    match bridge.present().await {
        Ok(true) => match bridge.list().await {
            Ok(tools) => Refresh::Listed(tools),
            Err(_) => Refresh::Unchanged,
        },
        // Answered, and publishes nothing. A real answer, so an
        // airdress whose last function was removed stops offering it.
        Ok(false) => Refresh::Listed(Vec::new()),
        Err(_) => Refresh::Unchanged,
    }
}

/// The descriptors for the exported tools, as `tools/list` renders
/// them.
///
/// A bridged tool that does not claim to be read-only is hidden in a
/// read-only session, the same rule the catalogue follows: a session
/// the user set to read-only must not offer a write just because a
/// function's author wrote one.
pub fn descriptors(tools: &[BridgedTool], read_only: bool) -> Vec<Value> {
    tools
        .iter()
        .filter(|t| !read_only || t.read_only)
        .map(|t| {
            json!({
                "name": t.exported_name(0),
                "description": if t.description.is_empty() {
                    format!("A tool published by this airdress ({}).", t.name)
                } else {
                    t.description.clone()
                },
                "inputSchema": t.input_schema.clone(),
                "annotations": {
                    "readOnlyHint": t.read_only,
                    // Said out loud: this tool is the airdress's, not
                    // ours, and its schema and behaviour are whatever
                    // its author wrote.
                    "title": format!("{} (on this airdress)", t.name),
                },
            })
        })
        .collect()
}

/// Find the bridged tool an exported name refers to.
pub fn resolve<'a>(tools: &'a [BridgedTool], exported: &str) -> Option<&'a BridgedTool> {
    tools.iter().find(|t| t.exported_name(0) == exported)
}

/// Whether a name could be one of ours at all.
pub fn is_exported_name(name: &str) -> bool {
    name.starts_with(crate::mcp::bridge::EXPORT_PREFIX)
}

/// The names a list exports, for comparing one refresh against the
/// last.
pub fn exported_names(tools: &[BridgedTool]) -> Vec<String> {
    let mut names: Vec<String> = tools.iter().map(|t| t.exported_name(0)).collect();
    names.sort();
    names
}

/// The notification sent when the exported set changes.
pub fn list_changed() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
}

/// Refresh forever, announcing every change through `announce`.
///
/// The first pass runs immediately: the caller spawns this only after
/// `initialize` has been answered, so there is nothing left to be
/// early for.
pub async fn run<F, Fut>(session: Arc<Session>, announce: F)
where
    F: Fn(Value) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        if let Refresh::Listed(tools) = refresh_once(&session).await {
            if session.set_exported(tools).await {
                announce(list_changed()).await;
            }
        }
        tokio::time::sleep(REFRESH_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, read_only: bool) -> BridgedTool {
        BridgedTool {
            name: name.to_owned(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
            read_only,
        }
    }

    #[test]
    fn a_write_is_hidden_in_a_read_only_session() {
        let tools = vec![tool("read_ledger", true), tool("send_invoice", false)];

        let open = descriptors(&tools, false);
        assert_eq!(open.len(), 2);

        let locked = descriptors(&tools, true);
        assert_eq!(locked.len(), 1);
        assert_eq!(locked[0]["name"], "fn_read_ledger");
    }

    #[test]
    fn a_tool_with_no_description_still_gets_one() {
        let d = descriptors(&[tool("send_invoice", false)], false);
        assert_eq!(d[0]["name"], "fn_send_invoice");
        assert!(d[0]["description"]
            .as_str()
            .unwrap()
            .contains("send_invoice"));
        assert_eq!(d[0]["annotations"]["readOnlyHint"], false);
    }

    #[test]
    fn an_exported_name_resolves_back_to_its_tool() {
        let tools = vec![tool("Send-Invoice!", false)];
        let exported = tools[0].exported_name(0);
        assert_eq!(resolve(&tools, &exported).unwrap().name, "Send-Invoice!");
        assert!(resolve(&tools, "fn_nothing").is_none());
        assert!(is_exported_name(&exported));
        assert!(!is_exported_name("list_airdresses"));
    }

    #[test]
    fn the_notification_carries_no_id() {
        let n = list_changed();
        assert_eq!(n["method"], "notifications/tools/list_changed");
        assert!(n.get("id").is_none());
    }
}
