//! The Airdress MCP server.
//!
//! An editor, or a model inside one, reaches an airdress through this:
//! the same reads and writes the CLI does, offered as tools. It holds
//! no credential of its own — the CLI's profile store owns those — and
//! it knows nothing about which harness started it beyond the strings
//! that harness passed in. That is deliberate: the plugin that launches
//! it is the only place in the product that is specific to one editor
//! (SPEC-133 §6.7).
//!
//! Two entry points, one implementation: `airdress mcp serve` for
//! somebody who already has the CLI, and the `airdress-mcp` binary for
//! a plugin that ships the server on its own.
// Stdout is the MCP protocol channel; the crate root allows printing.
#![deny(clippy::print_stdout)]

pub mod bounds;
pub mod bridge;
pub mod bus;
pub mod capabilities;
pub mod channel_push;
pub mod chat;
pub mod jsonrpc;
pub mod probe;
pub mod reexport;
pub mod server;
pub mod session;
pub mod tools;

pub use server::serve;
pub use session::{parse_flag, ServeOpts};

use anyhow::Result;
use clap::{Args, Subcommand};

/// The base URL for one airdress's operator.
///
/// `https://<fqdn>` for everything real. The one exception is the
/// documented dev-only override `AIRDRESS_OPERATOR_URL`, which the
/// functions commands already honour — and it applies **only** to the
/// operator it names, so setting it cannot silently redirect calls
/// meant for a different airdress.
pub fn operator_base(fqdn: &str) -> String {
    let fqdn = fqdn.trim().trim_end_matches('/');
    if fqdn.contains("://") {
        return fqdn.to_owned();
    }
    if let Ok(url) = std::env::var(crate::functions::OPERATOR_URL_ENV) {
        let url = url.trim().trim_end_matches('/');
        let host = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        if host == fqdn {
            return url.to_owned();
        }
    }
    format!("https://{fqdn}")
}

/// `airdress mcp …`
#[derive(Debug, Subcommand)]
pub enum McpCommands {
    /// Serve the tool catalogue over stdio for an editor or agent.
    Serve(Box<ServeArgs>),
    /// Print the tool catalogue as JSON, without serving anything.
    Catalogue,
}

/// The flags a harness passes. Every one of them has a default, so
/// `airdress mcp serve` with no arguments is a working server.
#[derive(Args, Clone, Debug)]
pub struct ServeArgs {
    /// Free-text name of the harness running this server, recorded with
    /// sessions and enrollments so a person can tell their machines
    /// apart.
    #[arg(long, default_value = "unknown")]
    pub harness: String,
    /// Template for the agent device's label. `{host}` is substituted.
    #[arg(long, default_value = "{host}")]
    pub device_label_template: String,
    /// Where this server may keep state of its own. Never a token.
    #[arg(long, value_name = "DIR")]
    pub state_dir: Option<std::path::PathBuf>,
    /// CLI profile. Empty: the active one.
    #[arg(long, default_value = "")]
    pub profile: String,
    /// Airdress to act on when a tool names none. Empty: the usual
    /// resolution (marker file, then the profile's pin).
    #[arg(long, default_value = "")]
    pub default_airdress: String,
    /// Hide every tool that changes anything.
    #[arg(long, default_value = "false")]
    pub read_only: String,
    /// Offer the agent's chat lanes.
    #[arg(long, default_value = "true")]
    pub chat: String,
    /// Register this session on the agent bus at start.
    #[arg(long, default_value = "false")]
    pub bus: String,
    /// Bus topics to join, comma-separated.
    #[arg(long, default_value = "general")]
    pub bus_topics: String,
    /// Bus session label. Empty: `<host> · <repo>`.
    #[arg(long, default_value = "")]
    pub bus_label: String,
}

impl ServeArgs {
    /// Turn the arguments into options.
    ///
    /// The flags arrive as text because a plugin substitutes a user's
    /// configuration into them, and an unset value arrives as the empty
    /// string (§3.2). A value that is neither empty nor a recognised
    /// boolean is refused rather than read as `false`.
    pub fn into_opts(self, paths: Option<crate::paths::Paths>) -> Result<ServeOpts> {
        let non_empty = |s: String| Some(s).filter(|v| !v.trim().is_empty());
        Ok(ServeOpts {
            harness: self.harness,
            device_label_template: self.device_label_template,
            state_dir: self.state_dir,
            profile: non_empty(self.profile),
            default_airdress: non_empty(self.default_airdress),
            read_only: parse_flag(&self.read_only, false)
                .map_err(|e| anyhow::anyhow!("--read-only: {e}"))?,
            chat: parse_flag(&self.chat, true).map_err(|e| anyhow::anyhow!("--chat: {e}"))?,
            bus: parse_flag(&self.bus, false).map_err(|e| anyhow::anyhow!("--bus: {e}"))?,
            bus_topics: self
                .bus_topics
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            bus_label: non_empty(self.bus_label),
            paths,
        })
    }
}

/// `airdress mcp <command>`
///
/// `paths` is where the CLI's files are, resolved by the caller's entry
/// point; `None` when there is no home directory.
pub async fn run(cmd: McpCommands, paths: Option<crate::paths::Paths>) -> Result<()> {
    match cmd {
        McpCommands::Serve(args) => {
            crate::panic_exit::install("mcp serve");
            serve(args.into_opts(paths)?).await
        }
        McpCommands::Catalogue => {
            let tools: Vec<serde_json::Value> = airdress_mcp_catalogue::all()
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "title": t.title,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                        "annotations": t.annotations(),
                        "remote": t.remote,
                        "slice": t.slice,
                        "family": t.family,
                        "offered_by_this_build": airdress_mcp_catalogue::shipped(t),
                    })
                })
                .collect();
            #[allow(
                clippy::print_stdout,
                reason = "`airdress mcp catalogue` prints for a person; it serves nothing"
            )]
            {
                println!("{}", serde_json::to_string_pretty(&tools)?);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ServeArgs {
        ServeArgs {
            harness: "some-harness".into(),
            device_label_template: "Some Harness on {host}".into(),
            state_dir: None,
            profile: String::new(),
            default_airdress: String::new(),
            read_only: String::new(),
            chat: String::new(),
            bus: String::new(),
            bus_topics: "general".into(),
            bus_label: String::new(),
        }
    }

    #[test]
    fn empty_substitutions_land_on_the_documented_defaults() {
        let opts = args().into_opts(None).unwrap();
        assert!(!opts.read_only);
        assert!(opts.chat, "chat defaults on");
        assert!(!opts.bus, "the bus defaults off");
        assert_eq!(opts.bus_topics, vec!["general".to_string()]);
        assert!(opts.profile.is_none());
        assert!(opts.bus_label.is_none());
    }

    #[test]
    fn a_misspelt_boolean_is_refused_and_names_the_flag() {
        let bad = ServeArgs {
            read_only: "ture".into(),
            ..args()
        };
        let e = bad.into_opts(None).unwrap_err().to_string();
        assert!(e.contains("--read-only"), "{e}");
    }

    #[test]
    fn topics_are_split_and_trimmed() {
        let opts = ServeArgs {
            bus_topics: " release , , docs ".into(),
            ..args()
        }
        .into_opts(None)
        .unwrap();
        assert_eq!(opts.bus_topics, vec!["release", "docs"]);
    }
}
