//! The Airdress CLI as a library.
//!
//! Everything the `airdress` binary does lives here, so a second
//! consumer in this workspace can reuse the profile store, the token
//! refresh, the context resolution and the hub and operator clients
//! without a second copy of any of it. The MCP server
//! (`crates/airdress-mcp`) is that consumer: it holds no credential of
//! its own and writes no second copy of an account token.
//!
//! `src/main.rs` is the thin argument-parsing shell on top.
#![allow(
    clippy::print_stdout,
    reason = "the CLI's commands write their output to stdout; src/mcp denies it again"
)]
#![allow(
    unsafe_code,
    reason = "libc termios, ioctl and flock, and env test helpers; follow-up: allow per module"
)]
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

/// The agent bus, client side (not behind the `mls` feature).
pub mod agent_bus;

/// This machine as an agent device (behind the `mls` feature).
#[cfg(feature = "mls")]
pub mod agent_device;
pub mod airdresses;
pub mod auth;
pub mod chat_assign;
pub mod cli_setup;
pub mod context;
pub mod current;
pub mod device;
pub mod exit;
pub mod fsx;
pub mod functions;
pub mod home;
pub mod http;
pub mod log_err;
pub mod machine;
pub mod machine_admin;
pub mod mcp;
pub mod panic_exit;
pub mod paths;
pub mod plugins;
pub mod preferences;
pub mod profile;
pub mod redact;
pub mod resources;
pub mod shell_client;
pub mod shell_host;
pub mod tls;
pub mod ui;
pub mod update;
pub mod wire;

/// The MLS client engine, behind the `mls` feature (off by default).
#[cfg(feature = "mls")]
pub use airdress_mls as mls;

/// The version this binary reports.
///
/// `AIRDRESS_BUILD_VERSION` is set by the release workflow; a local
/// build falls back to the package version.
pub const fn build_version() -> &'static str {
    match option_env!("AIRDRESS_BUILD_VERSION") {
        Some(v) => v,
        None => env!("CARGO_PKG_VERSION"),
    }
}
