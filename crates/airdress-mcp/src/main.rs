//! `airdress-mcp` — the Airdress MCP server as its own binary.
//!
//! This is what a plugin ships and a launcher executes. It is the same
//! server `airdress mcp serve` runs; having it as a separate binary
//! means a plugin can carry one small artifact instead of the whole
//! CLI, and that artifact can be built, signed and pinned on its own.
//!
//! It names no harness. The harness's name, the label template and the
//! state directory all arrive as arguments from whatever launched it,
//! which is the one place in the product that knows (SPEC-133 §6.7).
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

use anyhow::Result;
use clap::Parser;

use airdress::mcp::{self, ServeArgs};

#[derive(Parser)]
#[command(
    name = "airdress-mcp",
    about = "Serve the Airdress tool catalogue over stdio",
    version = airdress::build_version(),
)]
#[derive(Debug)]
struct Cli {
    #[command(flatten)]
    serve: ServeArgs,
    /// Print the tool catalogue as JSON and exit, serving nothing.
    #[arg(long)]
    print_catalogue: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics go to stderr. Nothing may ever write to stdout but
    // the protocol, so the subscriber is pinned to stderr rather than
    // left to default.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AIRDRESS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    if cli.print_catalogue {
        return mcp::run(mcp::McpCommands::Catalogue, None).await;
    }
    // Where the CLI's files are, decided here once. No home directory is
    // not fatal: the server still answers, and says why a tool cannot.
    let paths = airdress::paths::Paths::from_env().ok();
    mcp::run(mcp::McpCommands::Serve(Box::new(cli.serve)), paths).await
}
