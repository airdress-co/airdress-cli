//! What every binary built from this crate does before its command runs,
//! and how it reports a failure: `airdress` and `airdress-agent` share one
//! reading of the global flags, so `--insecure`, `--ca-file`, `--timeout`
//! and the exit-code contract cannot drift between them.

use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

use crate::{exit, http, ui};

/// The global flags both binaries read, as parsed.
#[derive(Debug, Default)]
pub struct Globals {
    /// `--output json`.
    pub json: bool,
    /// `--no-color`.
    pub no_color: bool,
    /// `-v` count.
    pub verbose: u8,
    /// `--timeout`.
    pub timeout: Option<u64>,
    /// `--insecure`.
    pub insecure: bool,
    /// `--ca-file`.
    pub ca_file: Option<std::path::PathBuf>,
}

/// Apply the global flags: colour, the HTTP timeout, TLS, and tracing.
/// Call once, before the command runs.
pub fn init(g: &Globals) {
    let use_color = should_use_color(g.no_color);
    ui::init_color(use_color);

    // Flag beats env beats default (CLI-14): what was typed on this command
    // line wins over what the shell carries. A garbage env value falls back
    // to the default; bad input shouldn't fail the CLI.
    http::init_timeout(timeout_secs(
        g.timeout,
        std::env::var("AIRDRESS_TIMEOUT").ok().as_deref(),
    ));

    // TLS settings — env-var allows shell-session pinning without
    // re-typing the flag. AIRDRESS_INSECURE uses the same truthy
    // allowlist as AIRDRESS_QUIET (SPEC-043).
    let insecure = g.insecure || env_truthy("AIRDRESS_INSECURE");
    let ca_file = g
        .ca_file
        .clone()
        .or_else(|| std::env::var("AIRDRESS_CA_FILE").ok().map(Into::into));
    http::init_tls(http::TlsConfig { insecure, ca_file });

    // SPEC-044 dev-mode warning. Non-suppressible (NOT gated by
    // --quiet) because turning off TLS validation is exactly the
    // class of decision the user should be reminded of every time.
    if insecure {
        ui::warn(
            "TLS certificate validation is DISABLED (--insecure / AIRDRESS_INSECURE). \
             Any operator on the wire can impersonate the airdress — dev use only.",
        );
    }

    // Diagnostic tracing is silent by default (WARN+ only). `-v` lifts to
    // INFO, `-vv` to DEBUG. `AIRDRESS_LOG=…` / `RUST_LOG=…` override.
    // User-facing output (status, success, warning) goes through `ui::*`
    // — independent of the tracing level.
    let env_filter = std::env::var("AIRDRESS_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| {
            let level = match g.verbose {
                0 => "warn",
                1 => "info",
                _ => "debug",
            };
            EnvFilter::new(format!("airdress={level}"))
        });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_ansi(use_color)
        .without_time()
        .with_target(false)
        .init();
}

fn should_use_color(no_color: bool) -> bool {
    if no_color {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// SPEC-043 — strict case-insensitive allowlist for AIRDRESS_QUIET.
/// Anything outside `1`, `true`, `yes`, `on` (case-insensitive) is
/// non-truthy. A typo like `AIRDRESS_QUIET=yse` must not silently
/// swallow status lines in a CI log.
pub fn quiet_env_set() -> bool {
    env_truthy("AIRDRESS_QUIET")
}

/// Shared truthy allowlist for boolean env vars. Same semantics as
/// [`quiet_env_set`] (SPEC-043): `1` / `true` / `yes` / `on`,
/// case-insensitive, anything else (including empty, typos, `0`,
/// `false`) is non-truthy.
pub fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .as_deref()
        .map(is_truthy)
        .unwrap_or(false)
}

/// The truthy allowlist itself: `1`, `true`, `yes`, `on`, case-insensitive.
pub fn is_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// The HTTP timeout: `--timeout`, else `AIRDRESS_TIMEOUT` when it is a
/// number, else the default.
pub fn timeout_secs(flag: Option<u64>, env: Option<&str>) -> u64 {
    flag.or_else(|| env.and_then(|s| s.trim().parse::<u64>().ok()))
        .unwrap_or(http::DEFAULT_TIMEOUT_SECS)
}

/// Whether `--output json` was asked for, read from the raw arguments: for
/// a command line clap refused, where there is no parsed command to ask.
pub fn json_requested(argv: &[std::ffi::OsString]) -> bool {
    let args: Vec<&str> = argv.iter().filter_map(|a| a.to_str()).collect();
    args.iter().enumerate().any(|(i, a)| match *a {
        "-o" | "--output" => args.get(i + 1) == Some(&"json"),
        "--output=json" | "-ojson" | "-o=json" => true,
        _ => false,
    })
}

/// Report a failure and choose the exit status (`docs/exit-codes.md`).
/// Under `--output json` the report is exactly one JSON object on stderr;
/// otherwise `Error: …` and, when there is one, the hint.
pub fn report(err: &anyhow::Error, json: bool) -> ExitCode {
    let failure = exit::classify(err);
    if json {
        match serde_json::to_string(&failure) {
            Ok(line) => eprintln!("{line}"),
            Err(e) => eprintln!(r#"{{"code":"internal","message":"{e}"}}"#),
        }
    } else {
        eprintln!("Error: {err:?}");
        if let Some(hint) = &failure.hint {
            if !failure.message.contains(hint.as_str()) {
                eprintln!("hint: {hint}");
            }
        }
    }
    ExitCode::from(failure.exit_status())
}

/// A command line clap refused: exit 2 (clap's own), as one JSON object
/// under `--output json`. Help and `--version` are not failures. `program`
/// names the binary in the hint.
pub fn usage(err: &clap::Error, json: bool, program: &str) -> ExitCode {
    if !err.use_stderr() {
        if let Err(e) = err.print() {
            tracing::debug!(error = %e, "could not print help");
        }
        return ExitCode::SUCCESS;
    }
    if json {
        let rendered = err.render().to_string();
        let message = rendered
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start_matches("error: ")
            .to_owned();
        let failure = exit::Failure::usage(message).with_hint(format!("run `{program} --help`"));
        match serde_json::to_string(&failure) {
            Ok(line) => eprintln!("{line}"),
            Err(e) => eprintln!(r#"{{"code":"usage","message":"{e}"}}"#),
        }
    } else if let Err(e) = err.print() {
        tracing::debug!(error = %e, "could not print the usage error");
    }
    ExitCode::from(exit::Exit::Usage.status())
}
