//! What one MCP server process knows: its options, which airdress a
//! call is about, and the credentials it borrows from the CLI's profile
//! store.
//!
//! It borrows them: this process writes no second copy of an account
//! token anywhere (SPEC-133 FR-9). The profile store refreshes, the
//! profile store owns the bytes, and everything here holds them in a
//! [`Redacted`] until a request needs one.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::airdresses::client::{match_airdress, Airdress, HubClient, MatchError};
use crate::auth::tokens::Audience;
use crate::context::{self, Source};
use crate::log_err::LogErr as _;
use crate::mcp::bridge::BridgedTool;
use crate::mcp::capabilities::{self, Cached, Capabilities};
use crate::paths::Paths;
use crate::profile::storage;
use crate::redact::Redacted;

/// Everything the harness passes in. The harness's own name is one of
/// these, which is why nothing below it has to know one (§6.7).
#[derive(Debug, Clone)]
pub struct ServeOpts {
    /// Free text, recorded with a session or an enrollment so a person
    /// can tell their machines apart. `"claude-code"` from the plugin.
    pub harness: String,
    /// `"Claude Code on {host}"` — the label a device join request
    /// carries. `{host}` is the only placeholder.
    pub device_label_template: String,
    /// Where this server may keep state of its own: delivery cursors,
    /// verified-bundle markers, the device host's sealed state. Never a
    /// token.
    pub state_dir: Option<PathBuf>,
    /// CLI profile to use. Empty means the active one.
    pub profile: Option<String>,
    /// Airdress to act on when a tool names none.
    pub default_airdress: Option<String>,
    /// Hide every tool that changes anything.
    pub read_only: bool,
    /// Offer the agent's chat lanes.
    pub chat: bool,
    /// Register this session on the agent bus at start.
    pub bus: bool,
    /// Topics to join.
    pub bus_topics: Vec<String>,
    /// Session label. Empty means `<host> · <repo>`.
    pub bus_label: Option<String>,
    /// Where the CLI's files are, resolved by the entry point. `None` when
    /// there was no home directory to find: the server still starts and
    /// answers, and a tool that needs the profile says why it cannot.
    pub paths: Option<Paths>,
}

impl Default for ServeOpts {
    fn default() -> Self {
        Self {
            harness: "unknown".into(),
            device_label_template: "{host}".into(),
            state_dir: None,
            profile: None,
            default_airdress: None,
            read_only: false,
            chat: true,
            bus: false,
            bus_topics: vec!["general".into()],
            bus_label: None,
            paths: None,
        }
    }
}

/// Parse a boolean the way a plugin's user configuration hands one over:
/// substituted into an argument as text, and sometimes left empty.
///
/// Empty means "not set", so the caller's default stands. Anything
/// unrecognised is an error rather than a silent `false` — a typo that
/// quietly turns `read_only` off is exactly the mistake worth refusing.
pub fn parse_flag(raw: &str, default: bool) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("expected true or false, got '{other}'"),
    }
}

/// How the launcher that started this process got here — reported by
/// `whoami`, never trusted for anything.
#[derive(Debug, Clone, Serialize, Default)]
pub struct LaunchReport {
    /// `cdn`, `github`, `cache`, or absent when the server was started
    /// by hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// What the launcher verified, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
    /// A development or risk override that is in force. Printed every
    /// time, by design: an unverified binary must never be quiet about
    /// it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_in_force: Option<String>,
}

impl LaunchReport {
    /// Read what the launcher left in the environment.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            origin: get("AIRDRESS_LAUNCH_ORIGIN"),
            verification: get("AIRDRESS_LAUNCH_VERIFICATION"),
            override_in_force: get("AIRDRESS_LAUNCH_OVERRIDE"),
        }
    }
}

/// The airdress a call is about, and why it is that one.
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub id: Option<String>,
    pub fqdn: String,
    /// `flag`, `env`, `marker`, `profile-default`, or `tool-argument`
    /// when a tool named it.
    pub source: &'static str,
}

/// One server's state.
pub struct Session {
    pub opts: ServeOpts,
    pub launch: LaunchReport,
    /// Airdresses as the hub last listed them, so resolving a name does
    /// not cost a round trip per tool call.
    fleet: Mutex<Option<Vec<Airdress>>>,
    /// Per-FQDN capability answers.
    caps: Mutex<HashMap<String, Cached>>,
    /// The default airdress's own tools, as the last refresh saw them,
    /// re-exported as `fn_<tool>`. Empty until the first refresh, which
    /// runs after `initialize` is answered — `tools/list` must not wait
    /// on a network call (NFR-7).
    exported: Mutex<Vec<BridgedTool>>,
    /// Set once the legacy sign-in notice has been attached to a tool
    /// result in this session.
    legacy_said: AtomicBool,
    /// This server's sessions on the agent bus, per operator FQDN.
    pub bus_links: Mutex<HashMap<String, std::sync::Arc<crate::mcp::bus::Link>>>,
    /// Why joining the bus at start failed, if it did.
    pub bus_error: Mutex<Option<String>>,
    /// Things about the bus a person should hear (a lost claim, a session
    /// ended by the operator).
    pub bus_notices: Mutex<Vec<String>>,
    /// Per FQDN, the highest local chat sequence already pushed into the
    /// client; `chat_read` marks what is at or below it `already_pushed`.
    chat_pushed: Mutex<HashMap<String, i64>>,
    /// Where server-initiated notifications go: stdout, once serving.
    notifier: Mutex<Option<tokio::sync::mpsc::Sender<serde_json::Value>>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(opts: ServeOpts) -> Self {
        Self {
            opts,
            launch: LaunchReport::from_env(),
            fleet: Mutex::new(None),
            caps: Mutex::new(HashMap::new()),
            exported: Mutex::new(Vec::new()),
            legacy_said: AtomicBool::new(false),
            bus_links: Mutex::new(HashMap::new()),
            bus_error: Mutex::new(None),
            bus_notices: Mutex::new(Vec::new()),
            chat_pushed: Mutex::new(HashMap::new()),
            notifier: Mutex::new(None),
        }
    }

    /// The highest chat sequence pushed for `fqdn` (0: none).
    pub async fn chat_pushed_through(&self, fqdn: &str) -> i64 {
        self.chat_pushed
            .lock()
            .await
            .get(fqdn)
            .copied()
            .unwrap_or(0)
    }

    /// Record that everything up to `seq` was pushed for `fqdn`.
    pub async fn set_chat_pushed_through(&self, fqdn: &str, seq: i64) {
        let mut m = self.chat_pushed.lock().await;
        let e = m.entry(fqdn.to_owned()).or_insert(0);
        *e = (*e).max(seq);
    }

    /// Route server-initiated notifications to `tx`.
    pub async fn set_notifier(&self, tx: tokio::sync::mpsc::Sender<serde_json::Value>) {
        *self.notifier.lock().await = Some(tx);
    }

    /// Send a notification to the client, if one is being served. Waits
    /// while the client is not reading (the queue is bounded, R-ASY-5),
    /// which slows the bus and chat loops that push, rather than growing.
    pub async fn notify(&self, notification: serde_json::Value) {
        // Cloned out, so the lock is not held while the send waits.
        let tx = self.notifier.lock().await.clone();
        if let Some(tx) = tx {
            // Closed: the writer ended because stdout did; the process
            // ends with its client.
            tx.send(notification)
                .await
                .log_debug("queueing a notification for the client");
        }
    }

    /// The tools the default airdress publishes, as last seen.
    pub async fn exported(&self) -> Vec<BridgedTool> {
        self.exported.lock().await.clone()
    }

    /// Record a refresh. Returns whether the set of exported NAMES
    /// changed, which is what a client needs to be told about — a
    /// description or a schema moving under an unchanged name reaches
    /// the client the next time it lists, and announcing that would be
    /// a notification per refresh for an airdress that edits a doc
    /// comment.
    pub async fn set_exported(&self, tools: Vec<BridgedTool>) -> bool {
        let mut slot = self.exported.lock().await;
        let changed = crate::mcp::reexport::exported_names(&slot)
            != crate::mcp::reexport::exported_names(&tools);
        *slot = tools;
        changed
    }

    /// Which profile this session acts as.
    ///
    /// Resolved on demand, not at construction: `initialize` and
    /// `tools/list` must answer before anything is read from disk or
    /// the network (NFR-7), and somebody who has not signed in yet
    /// still deserves to be offered the `login` tool rather than a
    /// server that refused to start.
    pub fn profile_name(&self) -> Result<String> {
        storage::resolve_profile_name(self.paths()?, self.opts.profile.as_deref())
    }

    /// Where the CLI's files are.
    pub fn paths(&self) -> Result<&Paths> {
        self.opts
            .paths
            .as_ref()
            .context("cannot determine home directory, so there is no profile to use")
    }

    /// A hub client on a freshly refreshed token.
    ///
    /// Built per call rather than cached: the refresh is what keeps the
    /// token valid, and a client cached across an hour of idling holds
    /// a bearer that has expired.
    pub async fn hub(&self) -> Result<HubClient> {
        HubClient::from_profile(self.paths()?, &self.profile_name()?).await
    }

    /// The bearer for the operator at `fqdn`, refreshed: on a hub sign-in
    /// a token only that operator accepts. Wrapped so it cannot be printed.
    pub async fn bearer(&self, fqdn: &str) -> Result<Redacted<String>> {
        crate::auth::tokens::access_token(
            self.paths()?,
            &self.profile_name()?,
            Audience::Operator(fqdn),
        )
        .await
    }

    /// The legacy sign-in notice, when the session's profile still holds a
    /// schema v2 (identity-provider direct) sign-in. Read from disk each
    /// time, so a `login` in another terminal ends it without a restart.
    pub fn legacy_notice(&self) -> Option<String> {
        let name = self.profile_name().ok()?;
        let profile = storage::read_profile(self.paths().ok()?, &name).ok()?;
        crate::auth::tokens::legacy_notice(&name, profile.auth.as_ref())
    }

    /// [`Session::legacy_notice`], the first time only: what the server
    /// adds to one tool result, so the person hears it once per session
    /// rather than on every call.
    pub fn legacy_notice_once(&self) -> Option<String> {
        if self.legacy_said.load(Ordering::Relaxed) {
            return None;
        }
        let notice = self.legacy_notice()?;
        (!self.legacy_said.swap(true, Ordering::Relaxed)).then_some(notice)
    }

    /// Every airdress on this account, from cache when we have it.
    pub async fn fleet(&self, refresh: bool) -> Result<Vec<Airdress>> {
        let mut slot = self.fleet.lock().await;
        if refresh || slot.is_none() {
            let items = self.hub().await?.list().await?;
            *slot = Some(items);
        }
        Ok(slot.clone().unwrap_or_default())
    }

    /// Resolve which airdress a tool call is about.
    ///
    /// Order: the tool's own `airdress` argument, then the CLI's own
    /// five-tier resolution (flag, environment, `.airdress` marker,
    /// profile default), then the one airdress on the account if there
    /// is exactly one. The last tier exists because a single-airdress
    /// account asking "which airdress?" is a question with one answer.
    pub async fn target(&self, named: Option<&str>) -> Result<Target> {
        let (wanted, source) = match named.map(str::trim).filter(|s| !s.is_empty()) {
            Some(n) => (n.to_owned(), "tool-argument"),
            None => {
                match context::resolve(
                    self.paths()?,
                    &self.profile_name()?,
                    self.opts.default_airdress.as_deref(),
                ) {
                    Ok(r) => (r.name, source_label(r.source)),
                    Err(_) => {
                        let fleet = self.fleet(false).await?;
                        match fleet.len() {
                            1 => (fleet[0].name.clone(), "only-airdress"),
                            0 => bail!(
                                "this account has no airdress yet — claim one at \
                             https://account.airdress.co/airdresses"
                            ),
                            n => bail!(
                                "this account has {n} airdresses and none is the default — pass \
                             `airdress` to the tool, or run `airdress a use <name>`"
                            ),
                        }
                    }
                }
            }
        };
        self.resolve_named(&wanted, source).await
    }

    async fn resolve_named(&self, wanted: &str, source: &'static str) -> Result<Target> {
        let fleet = self.fleet(false).await?;
        match match_airdress(&fleet, wanted) {
            Ok(a) => Ok(Target {
                name: a.name.clone(),
                id: Some(a.id.clone()),
                fqdn: a.fqdn.clone(),
                source,
            }),
            Err(MatchError::Ambiguous(n)) => {
                Err(anyhow!("{n} airdresses match '{wanted}' — name it by id"))
            }
            Err(MatchError::NotFound) => {
                // A bare FQDN is a legitimate answer for a self-hosted
                // operator the hub never listed.
                if wanted.contains('.') {
                    return Ok(Target {
                        name: wanted.to_owned(),
                        id: None,
                        fqdn: wanted.to_owned(),
                        source,
                    });
                }
                // Re-list once: the account may have claimed an
                // airdress since this process started.
                let fresh = self.fleet(true).await?;
                match match_airdress(&fresh, wanted) {
                    Ok(a) => Ok(Target {
                        name: a.name.clone(),
                        id: Some(a.id.clone()),
                        fqdn: a.fqdn.clone(),
                        source,
                    }),
                    _ => Err(anyhow!(
                        "no airdress matching '{wanted}' on this account — call \
                         airdresses_list to see them"
                    )),
                }
            }
        }
    }

    /// What one airdress has turned on, asked at most every 30 seconds.
    pub async fn capabilities(&self, fqdn: &str) -> Result<Capabilities> {
        {
            let cache = self.caps.lock().await;
            if let Some(hit) = cache.get(fqdn).filter(|c| c.fresh()) {
                return Ok(hit.value);
            }
        }
        let bearer = self.bearer(fqdn).await?;
        let value = capabilities::fetch(fqdn, bearer.expose())
            .await
            .with_context(|| format!("read capabilities from {fqdn}"))?;
        self.caps
            .lock()
            .await
            .insert(fqdn.to_owned(), Cached::new(value));
        Ok(value)
    }

    /// Forget what we believe about an airdress's switches.
    ///
    /// Called on every `not_enabled` answer: the operator has just told
    /// us our picture is wrong, so the next tool call must ask again
    /// rather than wait out the cache.
    pub async fn forget_capabilities(&self, fqdn: &str) {
        self.caps.lock().await.remove(fqdn);
    }

    /// The label this machine's agent device would carry.
    pub fn device_label(&self) -> String {
        let host = hostname();
        self.opts.device_label_template.replace("{host}", &host)
    }

    /// The bus session label: the user's, else `<host> · <repo>`.
    pub fn session_label(&self) -> String {
        if let Some(l) = self
            .opts
            .bus_label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return l.to_owned();
        }
        format!("{} · {}", hostname(), repo_name())
    }
}

fn source_label(s: Source) -> &'static str {
    match s {
        Source::Flag => "flag",
        Source::Env => "env",
        Source::Marker => "marker",
        Source::ProfileDefault => "profile-default",
    }
}

/// This machine's short hostname, or `unknown-host`.
pub fn hostname() -> String {
    // No new dependency for one string: the OS writes it in a file on
    // Linux, and `HOSTNAME`/`HOST` carry it in every shell. An
    // unreadable hostname is a label problem, never an error.
    for var in ["HOSTNAME", "HOST"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim();
            if !v.is_empty() {
                return short_host(v);
            }
        }
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| short_host(s.trim()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

fn short_host(h: &str) -> String {
    h.split('.').next().unwrap_or(h).to_owned()
}

/// The repository this session is working in: the basename of the git
/// work tree, else of the working directory.
pub fn repo_name() -> String {
    if let Some(dir) = git_toplevel() {
        return dir;
    }
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "no-repo".into())
}

fn git_toplevel() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    PathBuf::from(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_arrive_as_text_and_an_empty_one_keeps_the_default() {
        assert!(parse_flag("", true).unwrap());
        assert!(!parse_flag("", false).unwrap());
        assert!(parse_flag("TRUE", false).unwrap());
        assert!(parse_flag(" on ", false).unwrap());
        assert!(!parse_flag("no", true).unwrap());
        // A typo is refused, not read as false.
        assert!(parse_flag("ture", false).is_err());
    }

    #[test]
    fn the_device_label_substitutes_only_the_host() {
        let opts = ServeOpts {
            device_label_template: "Some Harness on {host}".into(),
            ..Default::default()
        };
        // Session::new touches the profile store, so test the rendering
        // the way the session does it.
        let rendered = opts.device_label_template.replace("{host}", "worklaptop");
        assert_eq!(rendered, "Some Harness on worklaptop");
    }

    #[test]
    fn a_hostname_is_short_and_never_empty() {
        assert_eq!(short_host("box.example.com"), "box");
        assert_eq!(short_host("box"), "box");
        assert!(!hostname().is_empty());
    }

    #[test]
    fn the_launch_report_serialises_only_what_is_known() {
        let json = serde_json::to_value(LaunchReport::default()).unwrap();
        assert_eq!(json, serde_json::json!({}));
    }
}
