//! The profile file: what this machine will run for its person (design
//! §7.4, FR-P1–FR-P8, D-1, D-15, D-19, D-32).
//!
//! `~/.config/airdress/shells.toml` is the only source of what a session can
//! run. Nothing over any wire selects a program: a client names a profile
//! **id**, and the host looks the rest up here. The host never reads a
//! profile back from the operator; it publishes only what [`Profile::report`]
//! builds, which carries a hash of the definition and none of it.
//!
//! The parser is strict on purpose:
//!
//! - an unknown key is refused, so a typo cannot silently change meaning;
//! - a key that looks like a secret is refused with "secrets go in the
//!   keychain", anywhere in the file, including `env_set` names (D-32);
//! - `run_as` is refused by name: sessions run as the user who started the
//!   host, always (D-15);
//! - the file must belong to the host user and be writable by nobody else;
//! - a `program` is absolute when a session opens. A bare name is resolved
//!   on `PATH` once, by `profile add` or `profile check`, and written back,
//!   so what runs never depends on a `PATH` read at open time.
//!
//! A profile that parses but cannot run (a missing program, a missing
//! working directory) is kept and published as `invalid` with its reason;
//! it never opens.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::duration;
use crate::paths::Paths;

/// The structured adapters a profile may name (design §9.1). Closed: adding
/// one is a change to the spec, not to a file.
pub const ADAPTERS: [&str; 4] = [
    "acp",
    "opencode-server",
    "codex-app-server",
    "claude-plugin",
];

/// D-19: the default and the ceiling of concurrent sessions.
pub const DEFAULT_MAX_SESSIONS: u32 = 8;
/// The operator's backstop; a host never asks for more.
pub const MAX_SESSIONS_CEILING: u32 = 32;

/// Words that make a key look like a secret.
const SECRET_WORDS: [&str; 7] = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
];

/// The header a new profile file starts with.
pub const FILE_HEADER: &str = "\
# ~/.config/airdress/shells.toml — what this machine will run for you.
# Airdress can start nothing on this machine that is not in this file,
# and nothing at all unless you started `airdress shell host`.
# No secret belongs here: a key that looks like one is refused.

[host]
max_sessions = 8
";

// ---------------------------------------------------------------------------
// The file as written
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    host: RawHost,
    #[serde(default, rename = "profile")]
    profiles: Vec<RawProfile>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    max_sessions: Option<u32>,
    journal_bytes: Option<u64>,
    journal_spill_bytes: Option<u64>,
    scrollback_lines: Option<u32>,
    transport: Option<String>,
    probe_interval: Option<String>,
    default_idle_timeout: Option<String>,
    default_max_lifetime: Option<String>,
}

/// One `[[profile]]` as written.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProfile {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_allow: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_set: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record_input: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_retention: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notify: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notify_bell: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<RawBridge>,
}

/// A bridge to a server the person started (FR-L4). Written only by
/// `airdress shell bridge` at the desk.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawBridge {
    pub adapter: String,
    pub address: String,
}

// ---------------------------------------------------------------------------
// Resolved
// ---------------------------------------------------------------------------

/// How the host reaches its operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPref {
    /// The WebSocket first, the long-poll when it cannot be had.
    Auto,
    /// The WebSocket only.
    Ws,
    /// The long-poll only.
    Poll,
}

/// The `[host]` table, with its defaults (design §12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub max_sessions: u32,
    pub journal_bytes: usize,
    pub journal_spill_bytes: u64,
    pub scrollback_lines: usize,
    pub transport: TransportPref,
    pub probe_interval: Duration,
    pub default_idle_timeout: Duration,
    pub default_max_lifetime: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            journal_bytes: 4 << 20,
            journal_spill_bytes: 64 << 20,
            scrollback_lines: 2000,
            transport: TransportPref::Auto,
            probe_interval: Duration::from_secs(6 * 3600),
            default_idle_timeout: Duration::from_secs(24 * 3600),
            default_max_lifetime: Duration::from_secs(7 * 86_400),
        }
    }
}

/// What a process profile runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    /// Absolute.
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env_allow: Vec<String>,
    pub env_set: BTreeMap<String, String>,
}

/// Where a profile's session comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Process(ProcessSpec),
    Bridge(RawBridge),
}

/// Whether a profile may open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Ready,
    /// Why not, as a short code (`program_missing`, …).
    Invalid(String),
}

/// One profile, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub source: Source,
    pub structured: Option<String>,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub record: bool,
    pub record_input: bool,
    pub recording_retention: Duration,
    pub notify: bool,
    pub notify_bell: bool,
    /// `sha256:<hex>` of the definition's canonical form (FR-P5).
    pub definition_hash: String,
    pub state: State,
}

impl Profile {
    /// The harness this profile names (`harness:<name>`), if any.
    pub fn harness(&self) -> Option<&str> {
        self.kind.strip_prefix("harness:")
    }

    /// The process this profile runs, if it is a ready process profile.
    pub fn process(&self) -> Option<&ProcessSpec> {
        match (&self.state, &self.source) {
            (State::Ready, Source::Process(p)) => Some(p),
            _ => None,
        }
    }

    /// The state as the host publishes it: `ready` or `invalid`. Why a
    /// profile is invalid goes in its own field ([`Profile::reason`]).
    pub fn state_word(&self) -> &'static str {
        match &self.state {
            State::Ready => "ready",
            State::Invalid(_) => "invalid",
        }
    }

    /// Why the profile is not ready, as the short code the operator accepts
    /// (`[a-z][a-z0-9_]{0,63}`); `None` when it is ready. A code outside the
    /// grammar would close the channel, so it goes out as `unspecified`.
    pub fn reason(&self) -> Option<&str> {
        match &self.state {
            State::Ready => None,
            State::Invalid(r) if valid_reason(r) => Some(r),
            State::Invalid(_) => Some("unspecified"),
        }
    }

    /// The state as a person reads it: `ready`, or `invalid (<reason>)`.
    pub fn state_text(&self) -> String {
        match self.reason() {
            None => "ready".into(),
            Some(r) => format!("invalid ({r})"),
        }
    }
}

/// The longest reason code the operator accepts.
pub const REASON_MAX: usize = 64;

/// A profile's reason as the operator accepts it: `[a-z][a-z0-9_]{0,63}`.
/// No path separator, space, `=` or quote fits, so nothing of a
/// definition can leave the machine through it.
pub fn valid_reason(reason: &str) -> bool {
    let b = reason.as_bytes();
    !b.is_empty()
        && b.len() <= REASON_MAX
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// The whole file, resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFile {
    pub host: HostConfig,
    pub profiles: Vec<Profile>,
}

impl ProfileFile {
    /// One profile by id.
    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_kind(kind: &str) -> bool {
    if kind == "shell" {
        return true;
    }
    kind.strip_prefix("harness:").is_some_and(|n| {
        !n.is_empty()
            && n.len() <= 32
            && n.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn valid_env_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn looks_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| k.contains(w))
}

/// Walk every key of the document: refuse secret-looking ones and `run_as`
/// with their own sentence, before the typed parse says "unknown field".
fn screen_keys(v: &toml::Value, at: &str) -> Result<()> {
    match v {
        toml::Value::Table(t) => {
            for (k, child) in t {
                let path = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                if looks_secret(k) {
                    bail!("`{path}` looks like a secret, and secrets go in the keychain, never in this file");
                }
                if k == "run_as" || k == "user" {
                    bail!(
                        "`{path}`: there is no run-as; every session runs as the user who started \
                         `airdress shell host`"
                    );
                }
                screen_keys(child, &path)?;
            }
        }
        toml::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                screen_keys(child, &format!("{at}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn opt_duration(raw: Option<&str>, default: Duration) -> Result<Duration> {
    raw.map_or(Ok(default), duration::parse)
}

fn resolve_host(raw: &RawHost) -> Result<HostConfig> {
    let d = HostConfig::default();
    let max_sessions = raw.max_sessions.unwrap_or(d.max_sessions);
    if !(1..=MAX_SESSIONS_CEILING).contains(&max_sessions) {
        bail!("[host] max_sessions must be between 1 and {MAX_SESSIONS_CEILING}");
    }
    let journal_bytes = raw.journal_bytes.unwrap_or(d.journal_bytes as u64);
    if !(64 << 10..=256 << 20).contains(&journal_bytes) {
        bail!("[host] journal_bytes must be between 64 KiB and 256 MiB");
    }
    let journal_spill_bytes = raw.journal_spill_bytes.unwrap_or(d.journal_spill_bytes);
    if journal_spill_bytes > 1 << 30 {
        bail!("[host] journal_spill_bytes must be at most 1 GiB");
    }
    let scrollback_lines = raw
        .scrollback_lines
        .map_or(d.scrollback_lines, |n| n as usize);
    if scrollback_lines > 100_000 {
        bail!("[host] scrollback_lines must be at most 100000");
    }
    let transport = match raw.transport.as_deref() {
        None | Some("auto") => TransportPref::Auto,
        Some("ws") => TransportPref::Ws,
        Some("poll") => TransportPref::Poll,
        Some(other) => bail!("[host] transport `{other}` is not auto, ws or poll"),
    };
    Ok(HostConfig {
        max_sessions,
        journal_bytes: journal_bytes as usize,
        journal_spill_bytes,
        scrollback_lines,
        transport,
        probe_interval: opt_duration(raw.probe_interval.as_deref(), d.probe_interval)?,
        default_idle_timeout: opt_duration(
            raw.default_idle_timeout.as_deref(),
            d.default_idle_timeout,
        )?,
        default_max_lifetime: opt_duration(
            raw.default_max_lifetime.as_deref(),
            d.default_max_lifetime,
        )?,
    })
}

/// SHA-256 over the profile's canonical form: its JSON, keys sorted at
/// every level, as written (after `program` resolution).
pub fn definition_hash(raw: &RawProfile) -> String {
    let v = serde_json::to_value(raw).expect("a profile serializes");
    let bytes = serde_json::to_vec(&v).expect("a value serializes");
    let digest = Sha256::digest(&bytes);
    let mut out = String::from("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn is_executable(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok() && path.is_file()
}

/// Resolve a bare program name on `path_var`, the way a shell would, once.
pub fn resolve_program(program: &str, path_var: Option<&str>) -> Option<PathBuf> {
    if program.contains('/') {
        return Some(PathBuf::from(program));
    }
    path_var?
        .split(':')
        .filter(|d| !d.is_empty() && Path::new(d).is_absolute())
        .map(|d| Path::new(d).join(program))
        .find(|p| is_executable(p))
}

fn resolve_profile(raw: &RawProfile, host: &HostConfig, paths: &Paths) -> Result<Profile> {
    let kind = raw.kind.clone().unwrap_or_else(|| "shell".into());
    if !valid_kind(&kind) {
        bail!(
            "profile `{}`: kind `{kind}` is not `shell` or `harness:<name>`",
            raw.id
        );
    }
    for n in &raw.env_allow {
        if !valid_env_name(n) {
            bail!(
                "profile `{}`: `{n}` is not an environment variable name",
                raw.id
            );
        }
    }
    for n in raw.env_set.keys() {
        if !valid_env_name(n) {
            bail!(
                "profile `{}`: `{n}` is not an environment variable name",
                raw.id
            );
        }
    }
    let label = raw.label.clone().unwrap_or_else(|| raw.id.clone());
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        bail!(
            "profile `{}`: the label must be 1–80 printable characters",
            raw.id
        );
    }
    let mut state = State::Ready;
    let mut invalid = |r: &str| {
        if state == State::Ready {
            state = State::Invalid(r.into());
        }
    };
    let idle_timeout = opt_duration(raw.idle_timeout.as_deref(), host.default_idle_timeout)?;
    let max_lifetime = opt_duration(raw.max_lifetime.as_deref(), host.default_max_lifetime)?;
    let recording_retention = opt_duration(
        raw.recording_retention.as_deref(),
        Duration::from_secs(30 * 86_400),
    )?;
    if let Some(s) = raw.structured.as_deref() {
        if !ADAPTERS.contains(&s) {
            bail!(
                "profile `{}`: structured `{s}` is not one of {}",
                raw.id,
                ADAPTERS.join(", ")
            );
        }
    }
    let source = match (&raw.program, &raw.bridge) {
        (Some(_), Some(_)) => bail!(
            "profile `{}` has both a program and a bridge; it is one or the other",
            raw.id
        ),
        (None, None) => bail!("profile `{}` has neither a program nor a bridge", raw.id),
        (None, Some(b)) => {
            if !raw.args.is_empty() || raw.cwd.is_some() || !raw.env_allow.is_empty() {
                bail!(
                    "profile `{}`: a bridge has no args, cwd or environment",
                    raw.id
                );
            }
            // Bridges are added at the desk by `airdress shell bridge`, which
            // this host does not have yet: kept and published, never opened.
            invalid("bridge_not_supported");
            Source::Bridge(b.clone())
        }
        (Some(program), None) => {
            let program_path = PathBuf::from(program);
            if !program_path.is_absolute() {
                invalid("program_not_absolute");
            } else if !program_path.exists() {
                invalid("program_missing");
            } else if !is_executable(&program_path) {
                invalid("program_not_executable");
            }
            let cwd = paths.expand(raw.cwd.as_deref().unwrap_or("~"));
            if !cwd.is_absolute() {
                bail!("profile `{}`: cwd must be absolute or start with ~", raw.id);
            }
            if !cwd.is_dir() {
                invalid("cwd_missing");
            }
            if let Some(a) = raw
                .structured
                .as_deref()
                .and_then(crate::structured::Adapter::parse)
            {
                // Requirements §5: an adapter is offered only where the
                // harness's terms row allows it (D-10, AC-17).
                if !crate::structured::allowed(&kind, a) {
                    invalid("structured_not_allowed");
                }
                if a == crate::structured::Adapter::HttpServer {
                    if let Err(why) = crate::structured::http_server::Target::from_profile(
                        &raw.args,
                        None,
                        cwd.clone(),
                    )
                    .base
                    {
                        invalid(why);
                    }
                }
            }
            if raw.structured.as_deref() == Some("claude-plugin")
                && raw.args.iter().any(|a| a == "-p" || a == "--print")
            {
                // The structured tier for this harness runs the interactive
                // binary; a print-mode profile is not one (design §9.4).
                invalid("print_mode_refused");
            }
            Source::Process(ProcessSpec {
                program: program_path,
                args: raw.args.clone(),
                cwd,
                env_allow: raw.env_allow.clone(),
                env_set: raw.env_set.clone(),
            })
        }
    };
    Ok(Profile {
        id: raw.id.clone(),
        label,
        kind,
        source,
        structured: raw.structured.clone(),
        idle_timeout,
        max_lifetime,
        record: raw.record,
        record_input: raw.record_input,
        recording_retention,
        notify: raw.notify,
        notify_bell: raw.notify_bell,
        definition_hash: definition_hash(raw),
        state,
    })
}

fn parse_raw(text: &str) -> Result<RawFile> {
    let value: toml::Value = toml::from_str(text).map_err(|e| anyhow!("not valid TOML: {e}"))?;
    screen_keys(&value, "")?;
    let raw: RawFile = toml::from_str(text).map_err(|e| anyhow!("{}", e.message()))?;
    let mut seen = BTreeSet::new();
    for p in &raw.profiles {
        if !valid_id(&p.id) {
            bail!(
                "profile id `{}` must be 1–63 of a-z, 0-9 and -, starting with a letter or digit",
                p.id
            );
        }
        if !seen.insert(p.id.as_str()) {
            bail!("profile id `{}` appears twice", p.id);
        }
    }
    Ok(raw)
}

/// Parse the file's text. Structural problems (bad TOML, an unknown key, a
/// secret, a duplicate id) refuse the whole file; a profile that cannot run
/// is kept as invalid.
pub fn parse_str(text: &str, paths: &Paths) -> Result<ProfileFile> {
    let raw = parse_raw(text)?;
    let host = resolve_host(&raw.host)?;
    let profiles = raw
        .profiles
        .iter()
        .map(|p| resolve_profile(p, &host, paths))
        .collect::<Result<Vec<_>>>()?;
    Ok(ProfileFile { host, profiles })
}

/// Refuse a file that is not the host user's, or that someone else could
/// write.
pub fn check_file_safety(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let meta =
        std::fs::metadata(path).with_context(|| format!("could not read {}", path.display()))?;
    let uid = rustix::process::geteuid().as_raw();
    if meta.uid() != uid {
        bail!(
            "{} belongs to another user (uid {}); it must be yours",
            path.display(),
            meta.uid()
        );
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "{} is writable by others (mode {mode:o}); anyone who can write it chooses what your \
             sessions run. chmod go-w it",
            path.display()
        );
    }
    Ok(())
}

/// Load the profile file. A missing file is an empty one.
pub fn load(paths: &Paths) -> Result<ProfileFile> {
    let path = paths.profiles_file();
    if !path.exists() {
        return Ok(ProfileFile::default());
    }
    check_file_safety(&path)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("could not read {}", path.display()))?;
    parse_str(&text, paths).with_context(|| format!("{}", path.display()))
}

// ---------------------------------------------------------------------------
// Editing (`airdress shell profile …`), on the host only
// ---------------------------------------------------------------------------

/// What `profile add` or `profile edit` sets. `None` leaves a field alone.
#[derive(Debug, Clone, Default)]
pub struct ProfileEdit {
    pub label: Option<String>,
    pub kind: Option<String>,
    pub program: Option<String>,
    /// Replaces the arguments when `Some`.
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env_allow: Option<Vec<String>>,
    pub structured: Option<String>,
    pub idle_timeout: Option<String>,
    pub max_lifetime: Option<String>,
    pub record: Option<bool>,
    pub notify: Option<bool>,
    pub notify_bell: Option<bool>,
}

fn read_document(paths: &Paths) -> Result<toml_edit::DocumentMut> {
    let path = paths.profiles_file();
    let text = if path.exists() {
        check_file_safety(&path)?;
        crate::fsx::read_to_string(&path)?
    } else {
        FILE_HEADER.to_owned()
    };
    text.parse::<toml_edit::DocumentMut>()
        .map_err(|e| anyhow!("{}: not valid TOML: {e}", path.display()))
}

/// Validate the edited document as a whole, then write it atomically.
fn commit(paths: &Paths, doc: &toml_edit::DocumentMut) -> Result<ProfileFile> {
    let text = doc.to_string();
    let parsed = parse_str(&text, paths)?;
    crate::paths::write_private_atomic(&paths.profiles_file(), text.as_bytes())?;
    Ok(parsed)
}

fn profiles_array(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::ArrayOfTables> {
    if doc.get("profile").is_none() {
        doc.insert(
            "profile",
            toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
        );
    }
    doc.get_mut("profile")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
        .context("`profile` in the file is not a list of [[profile]] tables")
}

fn str_array(items: &[String]) -> toml_edit::Item {
    let mut a = toml_edit::Array::new();
    for i in items {
        a.push(i.as_str());
    }
    toml_edit::value(a)
}

fn apply_edit(t: &mut toml_edit::Table, e: &ProfileEdit, path_var: Option<&str>) -> Result<()> {
    if let Some(v) = &e.label {
        t["label"] = toml_edit::value(v.as_str());
    }
    if let Some(v) = &e.kind {
        t["kind"] = toml_edit::value(v.as_str());
    }
    if let Some(v) = &e.program {
        let resolved = resolve_program(v, path_var)
            .with_context(|| format!("`{v}` is not on PATH; give its absolute path"))?;
        t["program"] = toml_edit::value(resolved.to_string_lossy().as_ref());
    }
    if let Some(v) = &e.args {
        t["args"] = str_array(v);
    }
    if let Some(v) = &e.cwd {
        t["cwd"] = toml_edit::value(v.as_str());
    }
    if let Some(v) = &e.env_allow {
        t["env_allow"] = str_array(v);
    }
    if let Some(v) = &e.structured {
        t["structured"] = toml_edit::value(v.as_str());
    }
    if let Some(v) = &e.idle_timeout {
        t["idle_timeout"] = toml_edit::value(v.as_str());
    }
    if let Some(v) = &e.max_lifetime {
        t["max_lifetime"] = toml_edit::value(v.as_str());
    }
    for (key, v) in [
        ("record", e.record),
        ("notify", e.notify),
        ("notify_bell", e.notify_bell),
    ] {
        if let Some(v) = v {
            t[key] = toml_edit::value(v);
        }
    }
    Ok(())
}

/// `airdress shell profile add`.
pub fn add(
    paths: &Paths,
    id: &str,
    edit: &ProfileEdit,
    path_var: Option<&str>,
) -> Result<ProfileFile> {
    if edit.program.is_none() {
        bail!("a profile needs --program");
    }
    let mut doc = read_document(paths)?;
    let arr = profiles_array(&mut doc)?;
    if arr
        .iter()
        .any(|t| t.get("id").and_then(toml_edit::Item::as_str) == Some(id))
    {
        bail!("a profile `{id}` exists; use `airdress shell profile edit {id}`");
    }
    let mut t = toml_edit::Table::new();
    t["id"] = toml_edit::value(id);
    apply_edit(&mut t, edit, path_var)?;
    arr.push(t);
    commit(paths, &doc)
}

/// `airdress shell profile edit`.
pub fn edit(
    paths: &Paths,
    id: &str,
    edit: &ProfileEdit,
    path_var: Option<&str>,
) -> Result<ProfileFile> {
    let mut doc = read_document(paths)?;
    let arr = profiles_array(&mut doc)?;
    let t = arr
        .iter_mut()
        .find(|t| t.get("id").and_then(toml_edit::Item::as_str) == Some(id))
        .with_context(|| format!("no profile `{id}`"))?;
    apply_edit(t, edit, path_var)?;
    commit(paths, &doc)
}

/// `airdress shell profile remove`.
pub fn remove(paths: &Paths, id: &str) -> Result<ProfileFile> {
    let mut doc = read_document(paths)?;
    let arr = profiles_array(&mut doc)?;
    let before = arr.len();
    arr.retain(|t| t.get("id").and_then(toml_edit::Item::as_str) != Some(id));
    if arr.len() == before {
        bail!("no profile `{id}`");
    }
    commit(paths, &doc)
}

/// `airdress shell profile check`: resolve bare program names on `PATH`
/// once and write them back absolute, then validate.
pub fn check(paths: &Paths, path_var: Option<&str>) -> Result<(ProfileFile, Vec<String>)> {
    let path = paths.profiles_file();
    if !path.exists() {
        return Ok((ProfileFile::default(), Vec::new()));
    }
    let mut doc = read_document(paths)?;
    let mut resolved = Vec::new();
    if let Some(arr) = doc
        .get_mut("profile")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
    {
        for t in arr.iter_mut() {
            let Some(program) = t.get("program").and_then(toml_edit::Item::as_str) else {
                continue;
            };
            if program.contains('/') {
                continue;
            }
            if let Some(abs) = resolve_program(program, path_var) {
                resolved.push(format!("{program} → {}", abs.display()));
                t["program"] = toml_edit::value(abs.to_string_lossy().as_ref());
            }
        }
    }
    let parsed = if resolved.is_empty() {
        load(paths)?
    } else {
        commit(paths, &doc)?
    };
    Ok((parsed, resolved))
}

/// `airdress shell profile show`: the profile as written, for the person at
/// the machine.
pub fn show(paths: &Paths, id: &str) -> Result<String> {
    let text = std::fs::read_to_string(paths.profiles_file()).context("no profile file")?;
    let raw = parse_raw(&text)?;
    let p = raw
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .with_context(|| format!("no profile `{id}`"))?;
    #[derive(Debug, Serialize)]
    struct One {
        profile: Vec<RawProfile>,
    }
    Ok(toml::to_string_pretty(&One { profile: vec![p] })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        std::fs::create_dir_all(&p.home).unwrap();
        (d, p)
    }

    const GOOD: &str = r#"
[host]
max_sessions = 3

[[profile]]
id = "home-sh"
label = "sh in ~"
kind = "shell"
program = "/bin/sh"
args = ["-l"]
cwd = "~"
env_allow = ["PATH", "LANG"]
idle_timeout = "2s"
"#;

    #[test]
    fn a_good_file_resolves() {
        let (_d, p) = paths();
        let f = parse_str(GOOD, &p).unwrap();
        assert_eq!(f.host.max_sessions, 3);
        let sh = f.get("home-sh").unwrap();
        assert_eq!(sh.state, State::Ready);
        assert_eq!(sh.idle_timeout, Duration::from_secs(2));
        assert_eq!(sh.max_lifetime, Duration::from_secs(7 * 86_400));
        let proc = sh.process().unwrap();
        assert_eq!(proc.cwd, p.home);
        assert!(sh.definition_hash.starts_with("sha256:"));
        assert_eq!(sh.definition_hash.len(), 7 + 64);
    }

    #[test]
    fn the_hash_changes_with_the_definition_and_only_with_it() {
        let (_d, p) = paths();
        let a = parse_str(GOOD, &p).unwrap().profiles[0]
            .definition_hash
            .clone();
        let b = parse_str(&GOOD.replace("-l", "-i"), &p).unwrap().profiles[0]
            .definition_hash
            .clone();
        assert_ne!(a, b);
        // Reordering keys in the file is not a change.
        let reordered = GOOD.replace(
            "label = \"sh in ~\"\nkind = \"shell\"",
            "kind = \"shell\"\nlabel = \"sh in ~\"",
        );
        assert_eq!(
            parse_str(&reordered, &p).unwrap().profiles[0].definition_hash,
            a
        );
    }

    #[test]
    fn unknown_keys_and_typos_are_refused() {
        let (_d, p) = paths();
        let err = parse_str(&GOOD.replace("env_allow", "env_alow"), &p).unwrap_err();
        assert!(err.to_string().contains("env_alow"), "{err}");
        let err = parse_str("[hots]\nmax_sessions = 1\n", &p).unwrap_err();
        assert!(err.to_string().contains("hots"), "{err}");
    }

    #[test]
    fn a_secret_looking_key_is_refused_anywhere() {
        let (_d, p) = paths();
        for bad in [
            "password = \"hunter2\"\n",
            "api_token = \"x\"\n",
            "env_set = { OPENAI_API_KEY = \"sk\" }\n",
            "env_set = { GITHUB_TOKEN = \"x\" }\n",
        ] {
            let text = format!("{GOOD}{bad}");
            let err = parse_str(&text, &p).unwrap_err().to_string();
            assert!(err.contains("keychain"), "{bad}: {err}");
        }
    }

    #[test]
    fn there_is_no_run_as() {
        let (_d, p) = paths();
        let err = parse_str(&format!("{GOOD}run_as = \"root\"\n"), &p)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no run-as"), "{err}");
    }

    #[test]
    fn a_profile_that_cannot_run_is_kept_as_invalid() {
        let (_d, p) = paths();
        let f = parse_str(
            &GOOD
                .replace("/bin/sh", "/nonexistent/bin/x")
                .replace("cwd = \"~\"", "cwd = \"~/nope\""),
            &p,
        )
        .unwrap();
        assert_eq!(
            f.profiles[0].state,
            State::Invalid("program_missing".into())
        );
        assert!(f.profiles[0].process().is_none());
        let f = parse_str(&GOOD.replace("/bin/sh", "sh"), &p).unwrap();
        assert_eq!(f.profiles[0].state_word(), "invalid");
        assert_eq!(f.profiles[0].reason(), Some("program_not_absolute"));
    }

    #[test]
    fn every_reason_the_host_gives_fits_the_operators_grammar() {
        for r in [
            "bridge_not_supported",
            "cwd_missing",
            "print_mode_refused",
            "program_missing",
            "program_not_absolute",
            "program_not_executable",
        ] {
            assert!(valid_reason(r), "{r}");
        }
        for bad in ["", "Program", "/bin/x", "a b", "a=b", "1x", &"x".repeat(65)] {
            assert!(!valid_reason(bad), "{bad}");
        }
    }

    #[test]
    fn ids_are_checked_and_unique() {
        let (_d, p) = paths();
        assert!(parse_str(&GOOD.replace("home-sh", "Home"), &p).is_err());
        let twice = format!("{GOOD}\n[[profile]]\nid = \"home-sh\"\nprogram = \"/bin/sh\"\n");
        assert!(parse_str(&twice, &p)
            .unwrap_err()
            .to_string()
            .contains("twice"));
    }

    #[test]
    fn max_sessions_has_a_ceiling() {
        let (_d, p) = paths();
        assert!(parse_str("[host]\nmax_sessions = 33\n", &p).is_err());
        assert!(parse_str("[host]\nmax_sessions = 0\n", &p).is_err());
        assert_eq!(parse_str("", &p).unwrap().host.max_sessions, 8);
    }

    #[test]
    fn a_print_mode_profile_is_not_the_structured_tier() {
        let (_d, p) = paths();
        let f = parse_str(
            &GOOD
                .replace(
                    "kind = \"shell\"",
                    "kind = \"harness:claude-code\"\nstructured = \"claude-plugin\"",
                )
                .replace("[\"-l\"]", "[\"-p\", \"hi\"]"),
            &p,
        )
        .unwrap();
        assert_eq!(f.profiles[0].reason(), Some("print_mode_refused"));
        assert_eq!(f.profiles[0].state_text(), "invalid (print_mode_refused)");
        assert!(parse_str(&GOOD.replace("kind = \"shell\"", "structured = \"x\""), &p).is_err());
    }

    #[test]
    fn a_group_writable_file_is_refused_with_a_reason() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, p) = paths();
        let f = p.profiles_file();
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, GOOD).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).unwrap();
        let err = load(&p).unwrap_err().to_string();
        assert!(err.contains("writable by others"), "{err}");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p).is_ok());
    }

    #[test]
    fn add_edit_remove_keep_comments_and_validate_before_writing() {
        let (_d, p) = paths();
        let path_var = Some("/usr/bin:/bin");
        add(
            &p,
            "cat",
            &ProfileEdit {
                program: Some("cat".into()),
                label: Some("cat".into()),
                ..Default::default()
            },
            path_var,
        )
        .unwrap();
        let text = std::fs::read_to_string(p.profiles_file()).unwrap();
        assert!(text.contains("what this machine will run"), "header kept");
        assert!(text.contains("program = \"/"), "resolved absolute: {text}");
        // A bad edit is refused and the file is untouched.
        let before = std::fs::read_to_string(p.profiles_file()).unwrap();
        assert!(edit(
            &p,
            "cat",
            &ProfileEdit {
                idle_timeout: Some("soon".into()),
                ..Default::default()
            },
            path_var
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(p.profiles_file()).unwrap(), before);
        assert!(add(
            &p,
            "cat",
            &ProfileEdit {
                program: Some("/bin/cat".into()),
                ..Default::default()
            },
            path_var
        )
        .is_err());
        edit(
            &p,
            "cat",
            &ProfileEdit {
                args: Some(vec!["-u".into()]),
                ..Default::default()
            },
            path_var,
        )
        .unwrap();
        assert!(show(&p, "cat").unwrap().contains("-u"));
        remove(&p, "cat").unwrap();
        assert!(load(&p).unwrap().profiles.is_empty());
        assert!(remove(&p, "cat").is_err());
    }

    #[test]
    fn check_resolves_bare_names_once() {
        let (_d, p) = paths();
        let f = p.profiles_file();
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "[[profile]]\nid = \"c\"\nprogram = \"cat\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (parsed, resolved) = check(&p, Some("/usr/bin:/bin")).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(parsed.profiles[0].state, State::Ready);
        let (_, again) = check(&p, Some("/usr/bin:/bin")).unwrap();
        assert!(again.is_empty());
    }
}
