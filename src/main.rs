//! Argument parsing for the `airdress` binary. Everything it calls
//! lives in the library crate beside it (`src/lib.rs`), which the MCP
//! server in this workspace reuses.
#![allow(
    clippy::print_stdout,
    reason = "the binary writes its output to stdout"
)]
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

use airdress::{
    airdresses, auth, build_version, current, device, functions, home, http, machine_admin, mcp,
    plugins, profile, resources, shell_client, tls, ui, update,
};

use std::process::ExitCode;

use airdress::exit;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "airdress",
    about = "Airdress CLI — auth, profiles, and credential management",
    version = build_version(),
    propagate_version = true,
)]
#[derive(Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(short, long, global = true, default_value = "text")]
    output: OutputFormat,

    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,

    /// Diagnostic verbosity. `-v` shows INFO traces; `-vv` shows DEBUG.
    /// User-facing output (status, success, warnings) is always shown.
    /// Overridden by `AIRDRESS_LOG=…` or `RUST_LOG=…` if either is set.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Per-request HTTP timeout in seconds. Default 30. Connect timeout
    /// is fixed at 10s. This flag beats `AIRDRESS_TIMEOUT=…`, which beats
    /// the default.
    #[arg(long, global = true)]
    timeout: Option<u64>,

    /// Airdress name, id, or FQDN to act on. Overrides AIRDRESS_NAME
    /// env, .airdress marker, and the profile's pinned airdress.
    /// (SPEC-043)
    #[arg(short = 'A', long, global = true)]
    airdress: Option<String>,

    /// Suppress the "→ acting on …" status line in text mode.
    /// AIRDRESS_QUIET={1,true,yes,on} (case-insensitive) has the same
    /// effect. (SPEC-043)
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    /// Skip TLS certificate validation. AIRDRESS_INSECURE=
    /// {1,true,yes,on} (case-insensitive) has the same effect.
    /// Dev-only — prints a non-suppressible stderr warning on every
    /// invocation that uses it.
    #[arg(long, global = true)]
    insecure: bool,

    /// Add a PEM (or DER) CA bundle to the client's root store IN
    /// ADDITION to the system roots. Preferred over `--insecure`
    /// when you have a private CA (LE staging, dev internal CA).
    /// AIRDRESS_CA_FILE=<path> has the same effect.
    #[arg(long, global = true, value_name = "PATH")]
    ca_file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Manage authentication
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Manage credential profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Manage airdresses
    #[command(alias = "a")]
    Airdress {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        #[command(subcommand)]
        command: AirdressCommands,
    },
    /// Manage devices paired to your airdress (SPEC-044)
    Device {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        #[command(subcommand)]
        command: DeviceCommands,
    },
    /// Switch the active credential profile (alias for `profile use`).
    /// To switch the active airdress, use `airdress airdress use <name>`
    /// (or its short form `airdress a use <name>`). (SPEC-043)
    Use {
        /// Profile name to activate
        name: String,
    },
    /// Show the resolved context (active profile + airdress + source).
    /// Designed for shell-prompt integration. (SPEC-043)
    Current,
    /// Server-side apply a manifest file against the operator. (SPEC-033)
    Apply {
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
        /// Manifest file (YAML or JSON). `-` reads stdin (not yet
        /// supported — provide a real path for now).
        #[arg(short = 'f', long, value_name = "FILE")]
        file: std::path::PathBuf,
        /// Predict what would happen without writing. Same as
        /// `airdress diff -f <file>`.
        #[arg(long)]
        dry_run: bool,
        /// Dev override — skip hub FQDN lookup, talk to this URL.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
        /// Sign each request as this enrolled machine instead of using the
        /// hub profile (its record `<key>.json` beside it). Needs
        /// --operator-url or AIRDRESS_OPERATOR_URL. What the machine may
        /// apply is whatever its grants say; usually nothing.
        #[arg(long, value_name = "PATH")]
        machine_key: Option<std::path::PathBuf>,
    },
    /// Show what `apply` would change without writing. (SPEC-033)
    Diff {
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
        /// Manifest file (YAML or JSON).
        #[arg(short = 'f', long, value_name = "FILE")]
        file: std::path::PathBuf,
        /// Dev override — skip hub FQDN lookup, talk to this URL.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },
    /// List Kinds, list a Kind's resources, or read one. (SPEC-033)
    Get {
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
        /// `<Kind>` or `<Kind>/<name>`. Omit to list registered Kinds.
        reference: Option<String>,
        /// Dev override — skip hub FQDN lookup, talk to this URL.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },
    /// Show full status + conditions of one resource. (SPEC-033)
    Describe {
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
        /// `<Kind>/<name>` (positional, required).
        reference: String,
        /// Dev override — skip hub FQDN lookup, talk to this URL.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },
    /// Hard-delete one or more resources. (SPEC-033)
    Delete {
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
        /// `<Kind>/<name>` positional. Mutually exclusive with `-f`.
        reference: Option<String>,
        /// Manifest file whose documents enumerate what to delete.
        /// Each document needs `kind` and `metadata.name`.
        #[arg(short = 'f', long, value_name = "FILE")]
        file: Option<std::path::PathBuf>,
        /// Dev override — skip hub FQDN lookup, talk to this URL.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },
    /// Author code-first functions: scaffold from a template, validate,
    /// publish, read versions and source, and tail the log.
    #[command(alias = "fn")]
    Functions {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        /// The operator to talk to, skipping the hub lookup: an FQDN or a
        /// URL. Or set AIRDRESS_OPERATOR_URL. Required with a machine key.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        /// Sign every request as this enrolled machine instead of using the
        /// hub profile: the key file `airdress-operator machine enroll`
        /// wrote (its record `<key>.json` beside it). Or set
        /// AIRDRESS_MACHINE_KEY to the path or the key, and
        /// AIRDRESS_MACHINE_ENROLLMENT to the record.
        #[arg(long, global = true, value_name = "PATH")]
        machine_key: Option<std::path::PathBuf>,
        #[command(subcommand)]
        command: functions::FunctionsCommands,
    },
    /// Decide on machines asking to enroll with your operator: list what
    /// is waiting, approve after comparing what the machine printed, deny;
    /// list and revoke approved machines. Uses your hub sign-in, which the
    /// operator accepts only from its owner.
    Machines {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only, as on `device pair`.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        #[command(subcommand)]
        command: machine_admin::MachinesCommands,
    },
    /// A terminal on your own machine, through your airdress, end to end:
    /// `airdress shell [profile] [--machine <name>]` opens or attaches;
    /// `ls`, `attach`, `close`, `recordings`. This CLI joins your airdress
    /// as a device first (a phone approves it).
    Shell {
        /// Credential profile for the hub sign-in (resolving the airdress,
        /// and asking to join). Shell profiles are the positional argument.
        #[arg(long, global = true, value_name = "NAME")]
        auth_profile: Option<String>,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only, as on `device pair`.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        #[command(flatten)]
        args: shell_client::ShellArgs,
    },
    /// This machine as an agent device of your airdress: `join` (a phone
    /// approves it), `status`, `leave`, and `serve` (the device host a
    /// coding assistant's sessions share). Built with the `mls` feature.
    #[cfg(feature = "mls")]
    Agent {
        #[command(subcommand)]
        command: airdress::agent_device::AgentCommands,
    },
    /// Agent chat, from the owner's side: list the agent devices, assign a
    /// conversation to one (a phone of yours in it then adds the device),
    /// unassign it (delivery stops at once), and see who holds it.
    Chat {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        #[command(subcommand)]
        command: airdress::chat_assign::ChatCommands,
    },
    /// The homes linked to your airdress: list them, read one (the hub,
    /// whether it is connected, what it shares, the sensitive opt-ins,
    /// notify and the limits), or disconnect one — revoke its machine, then
    /// delete it. Linking happens when you approve the machine
    /// (`airdress machines approve … --link-home`).
    Home {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only, as on `device pair`.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        #[command(subcommand)]
        command: home::HomeCommands,
    },
    /// Install and remove plugins on your operator: list what is installed,
    /// install a signed release from the registry (or a definition the
    /// operator loaded), uninstall one, verify a release. Uses your hub
    /// sign-in, which the operator accepts only from its owner.
    Plugins {
        /// Profile to authenticate against
        #[arg(short, long, global = true)]
        profile: Option<String>,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only, as on `device pair`.
        #[arg(long, global = true, value_name = "URL")]
        operator_url: Option<String>,
        #[command(subcommand)]
        command: plugins::PluginsCommands,
    },
    /// Serve the tool catalogue over MCP, for an editor or an agent, or
    /// print it. The server reuses this profile store and writes no
    /// second copy of any token.
    Mcp {
        #[command(subcommand)]
        command: mcp::McpCommands,
    },
    /// Generate shell completions
    Completion {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Update the CLI to the latest version
    Update {
        #[command(flatten)]
        args: update::UpdateArgs,
    },
    /// TLS certificate management for the operator
    Tls {
        #[command(subcommand)]
        command: TlsCommands,
    },
    /// Show version and build information
    Version,
}

#[derive(Debug, Subcommand)]
enum AuthCommands {
    /// Log in in the browser, choosing the account (creates the profile
    /// if it does not exist yet).
    ///
    /// Opens the identity provider's account picker (OAuth authorization
    /// code + PKCE, `prompt=select_account`, answered on a one-shot
    /// localhost port), so a second profile never silently inherits
    /// whatever account the browser is already signed in to. The picker
    /// is forced on every login: logins are rare, and signing a profile in
    /// as the wrong person is not. Afterwards it prints which account the
    /// profile got, and warns when another profile holds the same one.
    ///
    /// `--device` or `--no-browser` use the device flow instead (for a
    /// browser on another machine). Its page CANNOT show a picker — it
    /// signs in whichever account that browser already uses, so open the
    /// link in a private window when you want a different one.
    ///
    /// Signs in through the hub's authorization server when the hub offers
    /// one: the profile then holds one grant and a separate token per
    /// airdress, each accepted only by that airdress (profile schema v3).
    /// The hub forwards the account picker to the identity provider. A
    /// profile signed in directly at the identity provider (schema v2) is
    /// moved by this command, never silently, and it says so. A hub without
    /// its own sign-in is signed in to at the identity provider, as before.
    Login {
        /// Profile to authenticate (created on the default hub if missing;
        /// use `profile create --endpoint` for another hub)
        #[arg(short, long)]
        profile: Option<String>,
        /// Use the device flow (URL + code) instead of the account picker.
        /// No picker is possible there.
        #[arg(long)]
        device: bool,
        /// Don't try to open the browser automatically; implies --device.
        /// URL + code are also written to ~/.airdress/pending-login while
        /// the flow waits.
        #[arg(long)]
        no_browser: bool,
        /// Device flow: use the bare verification URL — don't prefill the
        /// user code in the link. The code is shown separately; you'll
        /// need to type it. Useful when sharing a screen.
        #[arg(long)]
        bare_url: bool,
    },
    /// Show current authentication status. A pure read — never
    /// refreshes, never writes. A stale access token beside a refresh
    /// token is reported as authenticated (it renews on next use);
    /// "expired" means a browser login is really needed.
    Status {
        /// Profile to check
        #[arg(short, long)]
        profile: Option<String>,
    },
    /// Print a fresh access token to stdout and nothing else, for
    /// scripts: `TOKEN=$(airdress auth token)`. Refreshes first when
    /// the cached token is expired or about to be.
    ///
    /// A hub sign-in holds a token per resource: without `--airdress` this
    /// prints the hub API's; `airdress auth token --airdress X` prints the
    /// one only X's operator accepts. A legacy (identity-provider direct)
    /// sign-in has one token for everything and prints that.
    ///
    /// The output is a credential — a bearer that acts as you at the
    /// hub or at your operator. Don't log it, don't paste it into
    /// tickets, and treat anything that captured it as needing a
    /// re-login (`airdress auth logout`, then `airdress auth login`).
    Token {
        /// Profile whose token to print
        #[arg(short, long)]
        profile: Option<String>,
    },
    /// Log out at the identity provider, not just locally: end the
    /// sign-in session this profile's login created (its ID token is the
    /// hint), revoke the refresh and access tokens, then forget them.
    Logout {
        /// Profile to log out
        #[arg(short, long)]
        profile: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AirdressCommands {
    /// List airdresses owned by the authenticated user
    List,
    /// Probe your airdress's operator via the hub and report the
    /// transport (direct vs relay). Named `probe` (not `whoami`)
    /// because OAuth/OIDC tooling uses `whoami` for the parameter-less
    /// caller-identity query (the OIDC `/userinfo` shape); this
    /// command takes a resource arg and reports on a specified
    /// airdress.
    ///
    /// The name argument is optional: when omitted, the current
    /// airdress is resolved via the SPEC-043 precedence (--airdress
    /// flag > AIRDRESS_NAME env > .airdress marker > profile pin).
    Probe {
        /// Airdress name, id, or full FQDN (optional — defaults to
        /// the resolved current airdress)
        name: Option<String>,
    },
    /// Pin an airdress as the current/default for the active profile.
    /// Validates against the hub at set-time. (SPEC-043)
    Use {
        /// Airdress name, id, or FQDN to pin
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommands {
    /// Pair a new device (phone, chat client) to the current airdress.
    /// Renders a QR + deeplink and waits for the scan. (SPEC-044)
    ///
    /// Requires an owner already bound to the operator — this CLI's own
    /// hub session mints the code. For an operator with no owner yet,
    /// use `bootstrap` instead.
    Pair {
        /// Label for the new device (e.g. "alice-phone"). Optional —
        /// the operator generates one if omitted.
        #[arg(long)]
        label: Option<String>,
        /// Skip the QR display (deeplink only).
        #[arg(long)]
        no_qr: bool,
        /// Skip the deeplink URL (QR only).
        #[arg(long)]
        no_link: bool,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only — useful when
        /// hitting a laptop-local operator before DNS is flipped, or
        /// when the operator's externally-visible FQDN doesn't yet
        /// resolve. Example: `--operator-url http://127.0.0.1:8080`.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },

    /// Onboard the FIRST device on a fresh operator, using its bootstrap
    /// token. (SPEC-056)
    ///
    /// This is the one credential that can unlock an operator with no
    /// owner bound yet — `pair` cannot help here, it needs an owner
    /// already authenticated to mint a code. The release chat app is
    /// built to never expose the bootstrap token (SPEC-005 NFR-1); this
    /// is the headless-safe equivalent for a terminal you already
    /// control, not a mobile UI a phishing page can autofill.
    ///
    /// Prints the resulting device session token to stdout. It cannot
    /// be recovered afterwards — store it, or capture it with
    /// `--output json` in a script.
    Bootstrap {
        /// Operator to bootstrap. No hub resolution happens — there is
        /// no owner yet for the hub to resolve against.
        /// Example: `--operator-url https://ada.a.airdr.es`.
        #[arg(long, value_name = "URL")]
        operator_url: String,

        /// Airdress name being bootstrapped (e.g. "ada.a.airdr.es").
        #[arg(long)]
        airdress: String,

        /// The operator's shared admin secret (`enrollment.bootstrap_token`
        /// in its config). Prefer AIRDRESS_BOOTSTRAP_TOKEN over the flag —
        /// flags land in shell history and process listings.
        #[arg(long)]
        bootstrap_token: Option<String>,

        /// Label for this device. Optional — defaults to a generic label.
        #[arg(long)]
        label: Option<String>,
    },

    /// Revoke one device's enrollment by id, with your own sign-in.
    ///
    /// For a device that can no longer act for itself — a lost, wiped or
    /// dead phone. Uses the owner's hub session (`airdress auth login`),
    /// so it needs neither a sibling device's session token nor shell on
    /// the operator. Only the operator's owner is allowed; anyone else
    /// gets the operator's refusal.
    ///
    /// Always previews first: the operator reports the enrollment's id,
    /// airdress and label without revoking it. `--dry-run` stops there.
    /// Otherwise you are asked to confirm; pass `--yes` to skip the
    /// prompt (required when stdin is not a terminal).
    ///
    /// The enrollment id is the one the VS Code extension's Enrollments
    /// node shows, or `id` in `GET /v1/endpoints/enrollments`.
    Revoke {
        /// Enrollment id (UUID) to revoke.
        enrollment_id: uuid::Uuid,
        /// Only show what would be revoked.
        #[arg(long)]
        dry_run: bool,
        /// Revoke without asking for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Talk to this operator URL directly instead of resolving
        /// `https://<fqdn>` via the hub. Dev-only, as on `pair`.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum TlsCommands {
    /// Force-renew the TLS certificate on the currently selected airdress
    /// operator.
    ///
    /// Resolves the active airdress via the standard SPEC-043 precedence
    /// (--airdress flag > AIRDRESS_NAME env > .airdress marker > profile
    /// pin), then POSTs to the operator's `/admin/tls/renew` endpoint.
    ///
    /// Use `--rotate` when a plain renew returns the same cert unchanged.
    /// Google Trust Services (GTS) deduplicates certificates: if the same
    /// domain identifiers are requested within a short window, the CA may
    /// return a cert with an identical "Not Before" timestamp. `--rotate`
    /// revokes the existing cert first, clearing GTS's dedup cache, then
    /// reissues. Revocation failure is non-fatal — the operator stays
    /// TLS-capable while reissuing.
    Renew {
        /// Revoke the existing cert before reissuing so the CA cannot
        /// return a deduplicated cert with the same "Not Before".
        #[arg(long)]
        rotate: bool,
        /// Dev override — talk to this operator URL instead of resolving
        /// the FQDN via the hub. Example: `--operator-url http://127.0.0.1:8080`.
        #[arg(long, value_name = "URL")]
        operator_url: Option<String>,
        /// Profile to authenticate against
        #[arg(short, long)]
        profile: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommands {
    /// Create a new profile
    Create {
        /// Profile name
        name: String,
        /// Hub endpoint URL
        #[arg(long, default_value = profile::storage::DEFAULT_ENDPOINT)]
        endpoint: String,
    },
    /// Set the active profile
    Use {
        /// Profile name to activate
        name: String,
    },
    /// List all profiles
    List,
    /// Show profile configuration (credentials redacted)
    Show {
        /// Profile name (default: active profile)
        name: Option<String>,
    },
}

fn build_info_long() -> String {
    let version = build_version();
    let commit = option_env!("AIRDRESS_BUILD_COMMIT").unwrap_or("unknown");
    let date = option_env!("AIRDRESS_BUILD_DATE").unwrap_or("unknown");
    let target = option_env!("AIRDRESS_BUILD_TARGET").unwrap_or(env!("TARGET"));
    format!("airdress {version}\ncommit:  {commit}\nbuilt:   {date}\ntarget:  {target}",)
}

fn should_use_color(cli: &Cli) -> bool {
    if cli.no_color {
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
fn quiet_env_set() -> bool {
    env_truthy("AIRDRESS_QUIET")
}

/// Shared truthy allowlist for boolean env vars. Same semantics as
/// [`quiet_env_set`] (SPEC-043): `1` / `true` / `yes` / `on`,
/// case-insensitive, anything else (including empty, typos, `0`,
/// `false`) is non-truthy.
fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .as_deref()
        .map(is_truthy_quiet)
        .unwrap_or(false)
}

/// The HTTP timeout: `--timeout`, else `AIRDRESS_TIMEOUT` when it is a
/// number, else the default.
fn timeout_secs(flag: Option<u64>, env: Option<&str>) -> u64 {
    flag.or_else(|| env.and_then(|s| s.trim().parse::<u64>().ok()))
        .unwrap_or(http::DEFAULT_TIMEOUT_SECS)
}

fn is_truthy_quiet(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Whether `--output json` was asked for, read from the raw arguments: for
/// a command line clap refused, where there is no parsed [`Cli`] to ask.
fn json_requested(argv: &[std::ffi::OsString]) -> bool {
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
fn report(err: &anyhow::Error, json: bool) -> ExitCode {
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
/// under `--output json`. Help and `--version` are not failures.
fn usage(err: &clap::Error, json: bool) -> ExitCode {
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
        let failure = exit::Failure::usage(message).with_hint("run `airdress --help`");
        match serde_json::to_string(&failure) {
            Ok(line) => eprintln!("{line}"),
            Err(e) => eprintln!(r#"{{"code":"usage","message":"{e}"}}"#),
        }
    } else if let Err(e) = err.print() {
        tracing::debug!(error = %e, "could not print the usage error");
    }
    ExitCode::from(exit::Exit::Usage.status())
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => return usage(&e, json_requested(&argv)),
    };
    let json = matches!(cli.output, OutputFormat::Json);
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => report(&e, json),
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let use_json = matches!(cli.output, OutputFormat::Json);
    let use_color = should_use_color(&cli);
    ui::init_color(use_color);

    // Flag beats env beats default (CLI-14): what was typed on this command
    // line wins over what the shell carries. A garbage env value falls back
    // to the default; bad input shouldn't fail the CLI.
    let timeout_secs = timeout_secs(
        cli.timeout,
        std::env::var("AIRDRESS_TIMEOUT").ok().as_deref(),
    );
    http::init_timeout(timeout_secs);

    // TLS settings — env-var allows shell-session pinning without
    // re-typing the flag. AIRDRESS_INSECURE uses the same truthy
    // allowlist as AIRDRESS_QUIET (SPEC-043).
    let insecure = cli.insecure || env_truthy("AIRDRESS_INSECURE");
    let ca_file = cli
        .ca_file
        .clone()
        .or_else(|| std::env::var("AIRDRESS_CA_FILE").ok().map(Into::into));
    http::init_tls(http::TlsConfig {
        insecure,
        ca_file: ca_file.clone(),
    });

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
            let level = match cli.verbose {
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

    let quiet = cli.quiet || quiet_env_set();
    let explicit_airdress = cli.airdress.as_deref();
    // Where the CLI's files are, decided once and handed down: nothing
    // below reads `$HOME` for itself.
    let paths = airdress::paths::Paths::from_env()?;

    match cli.command {
        Commands::Auth { command } => match command {
            AuthCommands::Login {
                profile,
                device,
                no_browser,
                bare_url,
            } => {
                auth::login::run_with_opts(
                    &paths,
                    profile.as_deref(),
                    auth::login::LoginOpts {
                        no_browser,
                        bare_url,
                        device,
                    },
                )
                .await?
            }
            AuthCommands::Status { profile } => {
                auth::status::run(&paths, profile.as_deref(), use_json)?
            }
            AuthCommands::Token { profile } => {
                auth::token::run(&paths, profile.as_deref(), explicit_airdress).await?
            }
            AuthCommands::Logout { profile } => {
                auth::logout::run(&paths, profile.as_deref()).await?
            }
        },
        Commands::Airdress { profile, command } => match command {
            AirdressCommands::List => {
                airdresses::list::run(&paths, profile.as_deref(), use_json).await?
            }
            AirdressCommands::Probe { name } => {
                airdresses::probe::run(airdresses::probe::ProbeArgs {
                    name_or_fqdn: name.as_deref(),
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    json: use_json,
                    quiet,
                })
                .await?;
            }
            AirdressCommands::Use { name } => {
                airdresses::use_cmd::run(&paths, &name, profile.as_deref()).await?;
            }
        },
        Commands::Profile { command } => match command {
            ProfileCommands::Create { name, endpoint } => {
                profile::create::run(&paths, &name, &endpoint)?
            }
            ProfileCommands::Use { name } => profile::use_cmd::run(&paths, &name)?,
            ProfileCommands::List => profile::list::run(&paths, use_json)?,
            ProfileCommands::Show { name } => {
                profile::show::run(&paths, name.as_deref(), use_json)?
            }
        },
        Commands::Device { profile, command } => match command {
            DeviceCommands::Pair {
                label,
                no_qr,
                no_link,
                operator_url,
            } => {
                device::pair::run(device::pair::PairArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    json: use_json,
                    quiet,
                    no_qr,
                    no_link,
                    label: label.as_deref(),
                    operator_url: operator_url.as_deref(),
                })
                .await?;
            }
            DeviceCommands::Revoke {
                enrollment_id,
                dry_run,
                yes,
                operator_url,
            } => {
                device::revoke::run(device::revoke::RevokeArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    json: use_json,
                    quiet,
                    enrollment_id,
                    dry_run,
                    yes,
                    operator_url: operator_url.as_deref(),
                })
                .await?;
            }
            DeviceCommands::Bootstrap {
                operator_url,
                airdress,
                bootstrap_token,
                label,
            } => {
                // profile is accepted for CLI-shape symmetry with Pair but
                // unused: bootstrap predates any owner/profile binding.
                let _ = profile;
                // Env beats flag — same precedence as AIRDRESS_TIMEOUT /
                // AIRDRESS_INSECURE above. This one matters more than
                // those: the flag form leaves an admin secret sitting in
                // shell history and `ps`.
                let bootstrap_token = std::env::var("AIRDRESS_BOOTSTRAP_TOKEN")
                    .ok()
                    .or(bootstrap_token)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no bootstrap token: set AIRDRESS_BOOTSTRAP_TOKEN or pass --bootstrap-token"
                        )
                    })?;
                device::bootstrap::run(device::bootstrap::BootstrapArgs {
                    paths: &paths,
                    operator_url: &operator_url,
                    airdress: &airdress,
                    bootstrap_token: bootstrap_token.into(),
                    label: label.as_deref(),
                    json: use_json,
                    quiet,
                })
                .await?;
            }
        },
        Commands::Use { name } => profile::use_cmd::run(&paths, &name)?,
        Commands::Current => current::run(&paths, explicit_airdress, None, use_json)?,
        Commands::Apply {
            profile,
            file,
            dry_run,
            operator_url,
            machine_key,
        } => {
            resources::apply::run(resources::apply::ApplyArgs {
                profile: profile.as_deref(),
                paths: &paths,
                explicit_airdress,
                json: use_json,
                quiet,
                file: &file,
                dry_run,
                operator_url: operator_url.as_deref(),
                machine_key: machine_key.as_deref(),
            })
            .await?;
        }
        Commands::Diff {
            profile,
            file,
            operator_url,
        } => {
            resources::diff::run(resources::diff::DiffArgs {
                profile: profile.as_deref(),
                paths: &paths,
                explicit_airdress,
                json: use_json,
                quiet,
                file: &file,
                operator_url: operator_url.as_deref(),
            })
            .await?;
        }
        Commands::Get {
            profile,
            reference,
            operator_url,
        } => {
            resources::get::run(resources::get::GetArgs {
                profile: profile.as_deref(),
                paths: &paths,
                explicit_airdress,
                json: use_json,
                quiet,
                reference: reference.as_deref(),
                operator_url: operator_url.as_deref(),
            })
            .await?;
        }
        Commands::Describe {
            profile,
            reference,
            operator_url,
        } => {
            resources::describe::run(resources::describe::DescribeArgs {
                profile: profile.as_deref(),
                paths: &paths,
                explicit_airdress,
                json: use_json,
                quiet,
                reference: &reference,
                operator_url: operator_url.as_deref(),
            })
            .await?;
        }
        Commands::Delete {
            profile,
            reference,
            file,
            operator_url,
        } => {
            resources::delete::run(resources::delete::DeleteArgs {
                profile: profile.as_deref(),
                paths: &paths,
                explicit_airdress,
                json: use_json,
                quiet,
                reference: reference.as_deref(),
                file: file.as_deref(),
                operator_url: operator_url.as_deref(),
            })
            .await?;
        }
        Commands::Functions {
            profile,
            operator_url,
            machine_key,
            command,
        } => {
            functions::run(
                command,
                functions::RunArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    machine_key: machine_key.as_deref(),
                    json: use_json,
                    quiet,
                    verbose: cli.verbose > 0,
                },
            )
            .await?;
        }
        Commands::Machines {
            profile,
            operator_url,
            command,
        } => {
            machine_admin::run(
                command,
                machine_admin::RunArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                    quiet,
                },
            )
            .await?;
        }
        Commands::Shell {
            auth_profile,
            operator_url,
            args,
        } => {
            let code = shell_client::run(
                args,
                shell_client::RunArgs {
                    auth_profile: auth_profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                    quiet,
                },
            )
            .await?;
            // The one exception to the exit-code contract: a shell ends
            // with the remote program's own status, passed through
            // (docs/exit-codes.md).
            if code != 0 {
                std::process::exit(code);
            }
        }
        #[cfg(feature = "mls")]
        Commands::Agent { command } => {
            airdress::agent_device::run(
                command,
                airdress::agent_device::RunArgs {
                    paths: &paths,
                    explicit_airdress,
                    json: use_json,
                },
            )
            .await?;
        }
        Commands::Chat {
            profile,
            operator_url,
            command,
        } => {
            airdress::chat_assign::run(
                command,
                airdress::chat_assign::RunArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                },
            )
            .await?;
        }
        Commands::Home {
            profile,
            operator_url,
            command,
        } => {
            home::run(
                command,
                home::RunArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                    quiet,
                },
            )
            .await?;
        }
        Commands::Plugins {
            profile,
            operator_url,
            command,
        } => {
            plugins::run(
                command,
                plugins::RunArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                    quiet,
                },
            )
            .await?;
        }
        Commands::Mcp { command } => {
            mcp::run(command, Some(paths.clone())).await?;
        }
        Commands::Tls { command } => match command {
            TlsCommands::Renew {
                rotate,
                operator_url,
                profile,
            } => {
                tls::renew::run(tls::renew::RenewArgs {
                    profile: profile.as_deref(),
                    paths: &paths,
                    explicit_airdress,
                    rotate,
                    operator_url: operator_url.as_deref(),
                    json: use_json,
                    quiet,
                })
                .await?;
            }
        },
        Commands::Update { args } => update::run(&args, use_json).await?,
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "airdress", &mut std::io::stdout());
        }
        Commands::Version => {
            if use_json {
                let info = serde_json::json!({
                    "version": build_version(),
                    "commit": option_env!("AIRDRESS_BUILD_COMMIT").unwrap_or("unknown"),
                    "built": option_env!("AIRDRESS_BUILD_DATE").unwrap_or("unknown"),
                    "target": option_env!("AIRDRESS_BUILD_TARGET").unwrap_or(env!("TARGET")),
                });
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("{}", build_info_long());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_truthy_quiet;

    /// Clap's own consistency checks (duplicate argument names and the
    /// like) run only when a command is built; this builds every one.
    #[test]
    fn the_command_tree_is_consistent() {
        use clap::CommandFactory as _;
        super::Cli::command().debug_assert();
    }

    /// `plugins authorize` takes a plugin and `deauthorize` takes
    /// `--keep`; both are argument-parsing properties, so they are
    /// asserted here, where the command tree is, rather than beside the
    /// request body they end up in.
    #[test]
    fn the_plugin_grant_verbs_take_what_they_need() {
        use clap::Parser as _;
        assert!(
            super::Cli::try_parse_from(["airdress", "plugins", "authorize"]).is_err(),
            "authorize must name a plugin"
        );
        assert!(super::Cli::try_parse_from([
            "airdress",
            "plugins",
            "deauthorize",
            "geo",
            "--keep"
        ])
        .is_ok());
    }

    /// A global flag and a subcommand's own flag of one name only clash
    /// when parsed (`--verbose` was a panic at run time, not a build
    /// error), so the deploy verbs are parsed, with the globals beside them.
    #[test]
    fn the_function_deploy_verbs_parse_beside_the_global_flags() {
        use clap::Parser as _;
        for argv in [
            &[
                "airdress",
                "-v",
                "--timeout",
                "5",
                "fn",
                "deploy",
                "dir",
                "--yes",
                "--plan",
                "--wait-timeout",
                "90",
                "--signing-key",
                "k",
            ][..],
            &[
                "airdress",
                "fn",
                "--machine-key",
                "m.key",
                "deploy",
                "--ci",
                "--since",
                "abc",
            ],
            &[
                "airdress", "fn", "deploy", "--all", "--map", "a.yaml", "--branch", "main",
            ],
            &[
                "airdress",
                "fn",
                "promote",
                "relay",
                "sha256:b",
                "--based-on",
                "sha256:a",
                "--dry-run",
            ],
            &["airdress", "fn", "keygen", "--out", "k"],
            &[
                "airdress", "fn", "signers", "add", "relay", "--key", "ab", "--yes",
            ],
            &[
                "airdress",
                "fn",
                "signers",
                "remove",
                "relay",
                "--machine",
                "m",
                "--dry-run",
            ],
            &["airdress", "fn", "layout-schema"],
        ] {
            if let Err(e) = super::Cli::try_parse_from(argv) {
                panic!("{argv:?}: {e}");
            }
        }
        // Exactly one member per signer change.
        assert!(super::Cli::try_parse_from(["airdress", "fn", "signers", "add", "relay"]).is_err());
        assert!(super::Cli::try_parse_from([
            "airdress",
            "fn",
            "signers",
            "add",
            "relay",
            "--key",
            "a",
            "--machine",
            "m"
        ])
        .is_err());
    }

    /// The machine verbs beside the global flags, `-o json` included.
    #[test]
    fn the_machine_verbs_parse_beside_the_global_flags() {
        use clap::Parser as _;
        for argv in [
            &["airdress", "-o", "json", "machines", "pending"][..],
            &[
                "airdress",
                "machines",
                "--operator-url",
                "http://127.0.0.1:8080",
                "approve",
                "WDJB-MJHT",
                "--fingerprint",
                "SHA256:abc",
                "--link-home",
                "home",
            ],
            &["airdress", "-A", "ada", "machines", "deny", "WDJB-MJHT"],
            &["airdress", "machines", "list", "-p", "prod"],
            &[
                "airdress",
                "machines",
                "revoke",
                "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11",
                "--reason",
                "retired",
                "--source-signing",
                "rotated",
            ],
        ] {
            if let Err(e) = super::Cli::try_parse_from(argv) {
                panic!("{argv:?}: {e}");
            }
        }
    }

    /// The plugin verbs beside the global flags, `-o json` included.
    #[test]
    fn the_plugin_verbs_parse_beside_the_global_flags() {
        use clap::Parser as _;
        for argv in [
            &["airdress", "-o", "json", "plugins", "list"][..],
            &["airdress", "plugins", "list", "-p", "prod"],
            &[
                "airdress",
                "-A",
                "ada",
                "plugins",
                "install",
                "forms",
                "--subdomain",
                "surveys",
                "--dry-run",
            ],
            &[
                "airdress",
                "plugins",
                "--operator-url",
                "http://127.0.0.1:8080",
                "uninstall",
                "forms",
                "--backup",
                "--yes",
            ],
            &["airdress", "plugins", "uninstall", "forms", "--dry-run"],
        ] {
            if let Err(e) = super::Cli::try_parse_from(argv) {
                panic!("{argv:?}: {e}");
            }
        }
        assert!(super::Cli::try_parse_from(["airdress", "plugins", "install"]).is_err());
        assert!(super::Cli::try_parse_from(["airdress", "plugins", "uninstall"]).is_err());
    }

    #[test]
    fn the_timeout_flag_beats_the_env_which_beats_the_default() {
        use super::timeout_secs;
        let default = airdress::http::DEFAULT_TIMEOUT_SECS;
        assert_eq!(timeout_secs(Some(5), Some("90")), 5, "flag over env");
        assert_eq!(timeout_secs(None, Some("90")), 90, "env over default");
        assert_eq!(timeout_secs(None, None), default);
        assert_eq!(timeout_secs(None, Some("soon")), default, "garbage env");
        assert_eq!(timeout_secs(Some(5), Some("soon")), 5);
    }

    #[test]
    fn quiet_truthy_allowlist() {
        for v in ["1", "true", "yes", "on", "TRUE", "On", "  YES  "] {
            assert!(is_truthy_quiet(v), "should be truthy: {v:?}");
        }
    }

    #[test]
    fn quiet_non_truthy_values() {
        for v in [
            "",
            "0",
            "false",
            "no",
            "off",
            "yse",
            "tru",
            "anything-else",
            "2",
            "  ",
        ] {
            assert!(!is_truthy_quiet(v), "should NOT be truthy: {v:?}");
        }
    }
}
