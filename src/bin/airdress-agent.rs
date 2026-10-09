//! `airdress-agent`: this machine as an agent device of your airdress.
//!
//! The one binary that links the MLS engine. `airdress` and the MCP server
//! carry none; an agent device is an MLS member, so it lives here. All of
//! it is in the library (`airdress::agent_device`), shared with `airdress`;
//! this file only parses the command line.
//!
//! ```text
//! airdress-agent device join     ask (a phone approves), and wait
//! airdress-agent device status   the device's standing and expiry
//! airdress-agent device leave    sign it out and delete its keys
//! airdress-agent device serve    run the device host a coding assistant's sessions share
//! ```

use std::process::ExitCode;

use airdress::agent_device::{self, AgentCommands};
use airdress::{build_version, cli_setup};
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "airdress-agent",
    about = "This machine as an agent device of your airdress",
    version = build_version(),
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: AgentCommands,

    /// Output format
    #[arg(short, long, global = true, default_value = "text")]
    output: OutputFormat,

    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,

    /// Diagnostic verbosity. `-v` shows INFO traces; `-vv` shows DEBUG.
    /// Overridden by `AIRDRESS_LOG=…` or `RUST_LOG=…` if either is set.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Per-request HTTP timeout in seconds. Default 30. This flag beats
    /// `AIRDRESS_TIMEOUT=…`, which beats the default.
    #[arg(long, global = true)]
    timeout: Option<u64>,

    /// Airdress name, id, or FQDN to act on. Overrides AIRDRESS_NAME
    /// env, .airdress marker, and the profile's pinned airdress.
    #[arg(short = 'A', long, global = true)]
    airdress: Option<String>,

    /// Skip TLS certificate validation (dev only; warns every time).
    /// AIRDRESS_INSECURE={1,true,yes,on} has the same effect.
    #[arg(long, global = true)]
    insecure: bool,

    /// Add a PEM (or DER) CA bundle to the system roots.
    /// AIRDRESS_CA_FILE=<path> has the same effect.
    #[arg(long, global = true, value_name = "PATH")]
    ca_file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => return cli_setup::usage(&e, cli_setup::json_requested(&argv), "airdress-agent"),
    };
    let json = matches!(cli.output, OutputFormat::Json);
    match run(cli, json).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => cli_setup::report(&e, json),
    }
}

async fn run(cli: Cli, json: bool) -> anyhow::Result<()> {
    cli_setup::init(&cli_setup::Globals {
        json,
        no_color: cli.no_color,
        verbose: cli.verbose,
        timeout: cli.timeout,
        insecure: cli.insecure,
        ca_file: cli.ca_file.clone(),
    });
    let paths = airdress::paths::Paths::from_env()?;
    agent_device::run(
        cli.command,
        agent_device::RunArgs {
            paths: &paths,
            explicit_airdress: cli.airdress.as_deref(),
            json,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    #[test]
    fn the_command_tree_is_consistent() {
        super::Cli::command().debug_assert();
    }

    #[test]
    fn the_device_verbs_parse_beside_the_global_flags() {
        use clap::Parser as _;
        for argv in [
            &["airdress-agent", "device", "join", "-A", "x", "--wait", "5"][..],
            &["airdress-agent", "-o", "json", "device", "status"],
            &["airdress-agent", "device", "serve", "--state-dir", "/tmp/a"],
            &[
                "airdress-agent",
                "device",
                "leave",
                "--harness",
                "claude-code",
            ],
        ] {
            super::Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }
}
