//! `airdress plugins …` — the owner installs and removes plugins on their
//! operator from a terminal.
//!
//! SPEC-119 task 119-A.2 (the CLI half): `list`, `install` and `uninstall`
//! against the operator's owner-only `/v1/plugins/installs*` routes, with the
//! owner's hub sign-in.
//!
//! 119-R.4: `install <name>[@<version>]` installs a signed release from the
//! registry. The operator verifies it against the keys it pins; the CLI
//! first asks it for a dry run, shows what the plugin will be able to do in
//! each scope, and asks once before the real install (`--yes` for scripts).
//! `--local` installs a definition the operator has loaded instead.
//! `verify <name>@<version>` checks a release against keys the caller pins,
//! without an operator.
//!
//! **Uninstall destroys data, so it is never silent.** It reads the install
//! first (an id that is not installed stops there, before anything is asked),
//! shows what goes, and asks on a terminal; a script must pass `--yes`.
//! `--dry-run` asks the operator to validate without changing anything.

pub mod client;
pub mod verify;

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use client::{Install, InstallBody, PluginsClient};
use serde_json::Value;

#[derive(Debug, Subcommand)]
pub enum PluginsCommands {
    /// List the plugins installed on your airdress, with their runtime state.
    List,
    /// Install a plugin: a signed release from the registry, or with
    /// `--local` a definition the operator has loaded.
    ///
    /// Shows what the plugin will be able to do and asks once; pass `--yes`
    /// to skip the prompt (required when stdin is not a terminal).
    Install {
        /// `<name>[@<version>]` — `forms`, `forms@0.2.0`. Without a version,
        /// the registry's latest.
        plugin: String,
        /// Install the operator's own loaded definition of `<name>` instead
        /// of a registry release.
        #[arg(long)]
        local: bool,
        /// Serve it on this subdomain instead of the one the plugin declares.
        #[arg(long)]
        subdomain: Option<String>,
        /// Show what would be installed and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Install without asking for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Who may sign the releases this install runs: `key:<64 hex>` or
        /// `machine:<name or id>` (repeatable, at most 16). Default: the set
        /// the install already pins, or for a new install the author keys
        /// the registry's signed index lists — shown before you confirm.
        #[arg(long = "signer", value_name = "SIGNER")]
        signers: Vec<String>,
        /// Offer the plugin's personal scope to the people on your airdress;
        /// each then authorizes it for themselves (`airdress plugins
        /// authorize`). Not offered unless you say so.
        #[arg(long)]
        offer_personal: bool,
    },
    /// Authorize a plugin's personal scope for yourself: it may then act
    /// for you, with your data kept as yours — not even the airdress owner
    /// can read it. Only when the owner offers it.
    Authorize {
        /// The plugin's name (or its install id).
        plugin: String,
    },
    /// Revoke your own authorization of a plugin's personal scope. By
    /// default the plugin erases your data in it (after letting you export
    /// it); `--keep` keeps it dormant until you authorize again.
    ///
    /// Erasing asks first; pass `--yes` to skip the prompt (required when
    /// stdin is not a terminal).
    Deauthorize {
        /// The plugin's name (or its install id).
        plugin: String,
        /// Keep your data, dormant, instead of erasing it.
        #[arg(long)]
        keep: bool,
        /// Revoke without asking for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Check a registry release as an operator would: the index signature
    /// and freshness against the registry keys you pin, the author's
    /// signature, the build provenance, and the digest of the manifest and
    /// every artifact. Needs no operator.
    Verify {
        /// `<name>@<version>`, or `<name>` for the latest.
        release: String,
        /// The registry.
        #[arg(long, default_value = "https://plugins.airdress.co")]
        registry: String,
        /// A pinned registry (index) key, `ed25519:<64 hex>` (repeatable).
        /// Default: `AIRDRESS_PLUGIN_INDEX_KEYS`, comma-separated.
        #[arg(long = "index-key", alias = "trusted-key", value_name = "KEY")]
        index_keys: Vec<String>,
        /// A pinned author key, `ed25519:<64 hex>` (repeatable). Default:
        /// the author keys the signed index lists.
        #[arg(long = "author-key", value_name = "KEY")]
        author_keys: Vec<String>,
    },
    /// Uninstall a plugin. Destroys its data; this cannot be undone.
    ///
    /// Shows what would go and asks first; pass `--yes` to skip the prompt
    /// (required when stdin is not a terminal).
    Uninstall {
        /// The install id, as `airdress plugins list` prints it.
        id: String,
        /// Dump the plugin's database schema before dropping it.
        #[arg(long)]
        backup: bool,
        /// Ask the operator to validate the uninstall without making it.
        #[arg(long)]
        dry_run: bool,
        /// Uninstall without asking for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

pub async fn run(command: PluginsCommands, args: RunArgs<'_>) -> Result<()> {
    // Local checks first: nothing is resolved or sent for a malformed call.
    match &command {
        PluginsCommands::Install {
            plugin,
            local,
            subdomain,
            signers,
            ..
        } => {
            let (name, version) = release_spec(plugin)?;
            if *local && version.is_some() {
                bail!(
                    "--local installs the operator's loaded definition; it has no version to pick"
                );
            }
            if *local && !signers.is_empty() {
                bail!("--local installs the operator's loaded definition; nothing signs it");
            }
            parse_signers(signers)?;
            valid_name(name, "plugin name")?;
            if let Some(s) = subdomain {
                valid_name(s, "subdomain")?;
            }
        }
        PluginsCommands::Uninstall { id, .. } => {
            client::valid_id(id)?;
        }
        PluginsCommands::Authorize { plugin } | PluginsCommands::Deauthorize { plugin, .. } => {
            client::valid_id(plugin)?;
        }
        PluginsCommands::Verify {
            release,
            registry,
            index_keys,
            author_keys,
        } => {
            let (name, version) = release_spec(release)?;
            valid_name(name, "plugin name")?;
            let index_keys = verify::index_keys(index_keys)?;
            let author_keys = verify::author_keys(author_keys)?;
            let report = verify::verify(
                registry,
                name,
                version,
                &index_keys,
                &author_keys,
                chrono::Utc::now(),
            )
            .await?;
            if args.json {
                print_json(&report)?;
            } else {
                if let Some(kid) = &report.index_signed_by {
                    ui::say(format!(
                        "  index: signed by registry key {kid}, not expired"
                    ));
                }
                if let Some(kid) = &report.signed_by {
                    ui::say(format!(
                        "  author: {}, key {kid} ({} keys)",
                        report.author.as_deref().unwrap_or("?"),
                        if report.author_keys_from == Some("pinned") {
                            "your pinned"
                        } else {
                            "the signed index's"
                        }
                    ));
                }
                if let Some(commit) = &report.built_from {
                    ui::say(format!(
                        "  provenance: built from {commit} in {}",
                        report.built_in.join(", ")
                    ));
                }
                for c in report.checked.iter().filter(|c| *c != "provenance") {
                    ui::say(format!("  {c}: digest matches"));
                }
                for p in &report.problems {
                    ui::warn(p);
                }
            }
            if !report.problems.is_empty() {
                bail!("{name}@{} does not verify", report.version);
            }
            if !args.json {
                ui::ok(format!(
                    "{name}@{} verifies: signed by author key {}, index and provenance by the \
                     registry",
                    report.version,
                    report.signed_by.as_deref().unwrap_or("?")
                ));
            }
            return Ok(());
        }
        PluginsCommands::List => {}
    }
    let op = connect(&args).await?;
    match command {
        PluginsCommands::List => {
            let installs = op.list().await?;
            if args.json {
                print_json(&serde_json::json!({ "installs": installs }))?;
            } else if installs.is_empty() {
                ui::say("no plugins installed");
            } else {
                println!("{}", render_list(&installs));
            }
        }
        PluginsCommands::Install {
            plugin,
            local,
            subdomain,
            dry_run,
            yes,
            signers,
            offer_personal,
        } => {
            let (name, version) = release_spec(&plugin)?;
            let signers = parse_signers(&signers)?;
            let offer_personal = offer_personal.then_some(true);
            let body = if local {
                InstallBody {
                    app_type: Some(name),
                    subdomain: subdomain.as_deref(),
                    offer_personal,
                    ..InstallBody::default()
                }
            } else {
                InstallBody {
                    plugin: Some(name),
                    version,
                    subdomain: subdomain.as_deref(),
                    signers,
                    offer_personal,
                    ..InstallBody::default()
                }
            };
            install(&op, body, dry_run, yes, args.json).await?;
        }
        PluginsCommands::Verify { .. } => unreachable!("answered before connecting"),
        PluginsCommands::Uninstall {
            id,
            backup,
            dry_run,
            yes,
        } => uninstall(&op, &id, backup, dry_run, yes, args.json).await?,
        PluginsCommands::Authorize { plugin } => {
            let a = op.authorize(&plugin).await?;
            if args.json {
                print_json(&a)?;
            } else {
                ui::ok(format!(
                    "authorized {plugin} {} to act for you in its personal scope; \
                     `airdress plugins deauthorize {plugin}` undoes it",
                    a.version
                ));
            }
        }
        PluginsCommands::Deauthorize { plugin, keep, yes } => {
            deauthorize(&op, &plugin, keep, yes, args.json).await?;
        }
    }
    Ok(())
}

async fn deauthorize(
    op: &PluginsClient,
    plugin: &str,
    keep: bool,
    yes: bool,
    json: bool,
) -> Result<()> {
    // Keeping the data loses nothing; erasing it does, so it is asked.
    if !keep {
        ui::confirm(
            &format!("Revoke {plugin} and have it erase your data in it?"),
            ui::Confirm::new(yes, json),
        )?;
    }
    let revoked = op.deauthorize(plugin, keep).await?;
    if json {
        print_json(&serde_json::json!({
            "plugin": plugin,
            "revoked": revoked,
            "data": if keep { "keep" } else { "erase" },
        }))?;
    } else if !revoked {
        ui::say(format!(
            "you had not authorized {plugin}; nothing was changed"
        ));
    } else if keep {
        ui::ok(format!(
            "revoked {plugin}; your data is kept, dormant, until you authorize it again"
        ));
    } else {
        ui::ok(format!(
            "revoked {plugin}; it will erase your data in it once you have had the chance to export it"
        ));
    }
    Ok(())
}

/// `--signer key:<64 hex>` / `--signer machine:<name or id>`; none is
/// `None` (the operator proposes the set).
fn parse_signers(flags: &[String]) -> Result<Option<Vec<client::Signer>>> {
    if flags.is_empty() {
        return Ok(None);
    }
    if flags.len() > 16 {
        bail!("at most 16 signers");
    }
    flags
        .iter()
        .map(|f| match f.split_once(':') {
            Some(("key", k)) if k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(client::Signer {
                    key: Some(k.to_ascii_lowercase()),
                    machine: None,
                })
            }
            Some(("machine", m)) if !m.trim().is_empty() => Ok(client::Signer {
                key: None,
                machine: Some(m.to_owned()),
            }),
            _ => bail!(
                "`{f}` is not a signer — `key:<64 hex>` (an Ed25519 public key) or \
                 `machine:<name or id>`"
            ),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// `<name>[@<version>]`.
fn release_spec(s: &str) -> Result<(&str, Option<&str>)> {
    match s.split_once('@') {
        None => Ok((s, None)),
        Some((name, version)) => {
            let ok = !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
            if !ok {
                bail!("`{version}` is not a version — `<name>@<version>`, e.g. forms@0.2.0");
            }
            Ok((name, Some(version)))
        }
    }
}

/// Ask the operator for a dry run, show what the plugin will be able to do,
/// ask once, then install exactly the version shown.
async fn install(
    op: &PluginsClient,
    mut body: InstallBody<'_>,
    dry_run: bool,
    yes: bool,
    json: bool,
) -> Result<()> {
    let plan = op.install(&body, true).await?;
    if !json {
        ui::say(consent_summary(&plan));
    }
    if dry_run {
        if json {
            print_json(&serde_json::json!({ "install": plan, "dry_run": true }))?;
        } else {
            ui::ok("nothing was changed (--dry-run)");
        }
        return Ok(());
    }
    ui::confirm("Install it?", ui::Confirm::new(yes, json))?;
    // What was shown is what is installed, even if `latest` moves meanwhile.
    let pinned = plan.version.clone();
    if body.plugin.is_some() && body.version.is_none() {
        body.version = pinned.as_deref();
    }
    let installed = op.install(&body, false).await?;
    if json {
        print_json(&serde_json::json!({ "install": installed, "dry_run": false }))?;
    } else {
        ui::ok(format!(
            "installed {} {} at {} (id {})",
            installed.app_type,
            installed.version.as_deref().unwrap_or(""),
            host_of(&installed),
            installed.id
        ));
    }
    Ok(())
}

/// What the owner approves: where it will serve, where it came from and who
/// signed it, and per scope what it may do.
fn consent_summary(i: &Install) -> String {
    let mut out = format!(
        "plugin {} {}\n  serves:    {}",
        i.app_type,
        i.version.as_deref().unwrap_or(""),
        host_of(i)
    );
    match (i.source.as_deref(), i.signed_by.as_deref()) {
        (Some("registry"), Some(kid)) => {
            let author = i
                .author
                .as_ref()
                .and_then(|a| a.get("author"))
                .and_then(Value::as_str)
                .unwrap_or("an unnamed author");
            out.push_str(&format!(
                "\n  source:    registry release by {author}, signed by key {kid}"
            ));
            if let Some(a) = i.author.as_ref() {
                let members: Vec<String> = a
                    .get("signers")
                    .and_then(Value::as_array)
                    .map(|m| {
                        m.iter()
                            .map(|s| match (s.get("key"), s.get("machine")) {
                                (Some(k), _) => format!("key {}", k.as_str().unwrap_or("?")),
                                (_, Some(m)) => format!("machine {}", m.as_str().unwrap_or("?")),
                                _ => s.to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                out.push_str("\n  signers:   you pin who may sign what it runs next:");
                for m in members {
                    out.push_str(&format!("\n    {m}"));
                }
                if let Some(p) = a.get("provenance_sha256").and_then(Value::as_str) {
                    out.push_str(&format!(
                        "\n  built:     provenance attested by the registry ({})",
                        &p[..p.len().min(16)]
                    ));
                }
            }
        }
        (Some("registry"), None) => {
            out.push_str("\n  source:    registry release, UNSIGNED (a development operator)");
        }
        (Some(other), _) => out.push_str(&format!("\n  source:    {other} definition")),
        _ => {}
    }
    let Some(c) = i.consent.as_ref() else {
        return out;
    };
    let text = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v.to_string())
    };
    if let Some(db) = c.get("database").and_then(Value::as_str) {
        out.push_str(&format!("\n  database:  {db}"));
    }
    if let Some(limits) = c
        .get("limits")
        .and_then(Value::as_object)
        .filter(|l| !l.is_empty())
    {
        let l: Vec<String> = limits
            .iter()
            .map(|(k, v)| format!("{k} {}", text(v)))
            .collect();
        out.push_str(&format!("\n  limits:    {}", l.join(", ")));
    }
    let scope = |label: &str, v: Option<&Value>, out: &mut String| {
        let Some(v) = v.filter(|v| !v.is_null()) else {
            return;
        };
        out.push_str(&format!("\n  {label}"));
        let hosts: Vec<String> = v
            .get("egress_hosts")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(text).collect())
            .unwrap_or_default();
        if hosts.is_empty() {
            out.push_str("\n    egress:  none");
        } else {
            out.push_str(&format!("\n    egress:  {}", hosts.join(", ")));
        }
    };
    scope(
        "airdress scope — you approve this by installing:",
        c.get("airdress"),
        &mut out,
    );
    scope(
        "personal scope — each person approves this for themselves:",
        c.get("personal"),
        &mut out,
    );
    out
}

async fn uninstall(
    op: &PluginsClient,
    id: &str,
    backup: bool,
    dry_run: bool,
    yes: bool,
    json: bool,
) -> Result<()> {
    let Some(install) = op.get(id).await? else {
        bail!(
            "no plugin install `{id}` on this operator — nothing was changed. \
             `airdress plugins list` shows what is installed"
        );
    };
    if !json {
        ui::say(describe(&install, backup));
    }
    // A dry run changes nothing, so it needs no confirmation.
    if !dry_run {
        ui::confirm(
            "Uninstall it and delete its data?",
            ui::Confirm::new(yes, json),
        )?;
    }
    op.uninstall(id, backup, dry_run).await?;
    if json {
        print_json(&serde_json::json!({
            "install": install,
            "backup": backup,
            "dry_run": dry_run,
            "uninstalled": !dry_run,
        }))?;
    } else if dry_run {
        ui::ok(format!(
            "the operator would uninstall {id}; nothing was changed"
        ));
    } else {
        ui::ok(format!("uninstalled {id}"));
    }
    Ok(())
}

/// A plugin name or subdomain: one DNS label (lowercase letters, digits and
/// inner hyphens, at most 63), since it becomes `<label>.<airdress>`.
fn valid_name<'a>(name: &'a str, what: &str) -> Result<&'a str> {
    let b = name.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = !b.is_empty()
        && b.len() <= 63
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| edge(c) || c == b'-');
    if ok {
        Ok(name)
    } else {
        bail!(
            "`{name}` is not a {what}: lowercase letters, digits and inner hyphens, \
             at most 63 characters"
        )
    }
}

async fn connect(args: &RunArgs<'_>) -> Result<PluginsClient> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(url) = args.operator_url {
        let bearer = hub.operator_bearer(url).await?;
        return PluginsClient::with_base_url(url.to_owned(), bearer);
    }
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }
    let fqdn = hub.resolve_fqdn(&resolved.name).await?;
    PluginsClient::new(&fqdn, hub.operator_bearer(&fqdn).await?)
}

/// Where the install is served: `<subdomain>.<airdress>`.
fn host_of(i: &Install) -> String {
    if i.airdress.is_empty() {
        i.subdomain.clone()
    } else {
        format!("{}.{}", i.subdomain, i.airdress)
    }
}

fn describe(i: &Install, backup: bool) -> String {
    let mut out = format!(
        "plugin install {}\n  plugin:   {}\n  serves:   {}",
        i.id,
        i.app_type,
        host_of(i)
    );
    if let Some(schema) = i
        .db_access
        .as_ref()
        .and_then(|d| d.get("schema_name"))
        .and_then(serde_json::Value::as_str)
    {
        let fate = if backup {
            "dumped, then dropped"
        } else {
            "dropped, no backup (--backup keeps a dump)"
        };
        out.push_str(&format!("\n  database: schema {schema} — {fate}"));
    }
    out
}

fn render_list(installs: &[Install]) -> String {
    let mut out = format!(
        "{:<24}  {:<16}  {:<9}  {:<12}  serves",
        "id", "plugin", "state", "last request"
    );
    for i in installs {
        let state = i.runtime_state.as_deref().unwrap_or("-");
        let age = match i.last_request_age_seconds {
            None | Some(0) => "-".to_owned(),
            Some(s) => format!("{s}s ago"),
        };
        out.push_str(&format!(
            "\n{:<24}  {:<16}  {:<9}  {:<12}  {}",
            i.id,
            i.app_type,
            state,
            age,
            host_of(i)
        ));
    }
    out
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};

    const FORMS: &str = r#"{"id":"forms","airdress":"ada.a.airdr.es","subdomain":"forms","app_type":"forms","runtime_state":"hot","last_request_age_seconds":12,"db_access":{"install_id":"01J","airdress":"ada.a.airdr.es","subdomain":"forms","role_name":"p_forms","schema_name":"plugin_forms","tier":1,"capability":"own_schema","ceilings":{},"installed_at":"2026-09-28T00:00:00Z","reconciled":false}}"#;

    fn client(base: String) -> PluginsClient {
        PluginsClient::with_base_url(base, "tok").unwrap()
    }

    fn body_of(request: &str) -> serde_json::Value {
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap()
    }

    #[test]
    fn names_and_subdomains_are_one_dns_label() {
        for ok in ["forms", "relay-transcribe", "a1"] {
            assert!(valid_name(ok, "plugin name").is_ok(), "{ok:?}");
        }
        for bad in ["", "Forms", "-x", "x-", "a.b", "a_b", &"a".repeat(64)] {
            assert!(valid_name(bad, "plugin name").is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn list_sends_the_owner_bearer_and_reads_each_install() {
        let (base, seen) = canned_operator(vec![response("200 OK", &format!("[{FORMS}]"))]).await;
        let installs = client(base).list().await.unwrap();
        assert_eq!(installs.len(), 1);
        let text = render_list(&installs);
        for want in ["forms", "hot", "12s ago", "forms.ada.a.airdr.es"] {
            assert!(text.contains(want), "{want}: {text}");
        }
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("GET /v1/plugins/installs "));
        assert!(seen[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer tok"));
    }

    #[tokio::test]
    async fn install_posts_the_name_and_passes_dry_run_as_a_query() {
        let created = r#"{"id":"surveys","app_type":"forms","subdomain":"surveys","airdress":"ada.a.airdr.es"}"#;
        let (base, seen) = canned_operator(vec![response("201 Created", created)]).await;
        let body = InstallBody {
            app_type: Some("forms"),
            subdomain: Some("surveys"),
            ..InstallBody::default()
        };
        let i = client(base).install(&body, true).await.unwrap();
        assert_eq!(host_of(&i), "surveys.ada.a.airdr.es");
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("POST /v1/plugins/installs?dry_run=true "));
        assert_eq!(
            body_of(&seen[0]),
            serde_json::json!({ "app_type": "forms", "subdomain": "surveys" })
        );
    }

    #[tokio::test]
    async fn an_install_refusal_is_said_with_its_detail() {
        let (base, _) = canned_operator(vec![response(
            "409 Conflict",
            r#"{"error":"subdomain `forms` already installed","detail":"installed app is `webdav`, request was `forms`"}"#,
        )])
        .await;
        let body = InstallBody {
            app_type: Some("forms"),
            ..InstallBody::default()
        };
        let err = client(base)
            .install(&body, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already installed"), "{err}");
        assert!(err.contains("installed app is `webdav`"), "{err}");
    }

    #[tokio::test]
    async fn an_operator_without_the_routes_says_so() {
        let (base, _) = canned_operator(vec![response(
            "404 Not Found",
            r#"{"error":{"code":"route_not_found","message":"No such route on this operator."}}"#,
        )])
        .await;
        let err = client(base).list().await.unwrap_err().to_string();
        assert!(err.contains("does not serve plugin installs"), "{err}");
    }

    #[tokio::test]
    async fn uninstall_reads_first_then_deletes_with_purge() {
        let (base, seen) = canned_operator(vec![
            response("200 OK", FORMS),
            response("204 No Content", ""),
        ])
        .await;
        uninstall(&client(base), "forms", true, false, true, true)
            .await
            .unwrap();
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("GET /v1/plugins/installs/forms "));
        assert!(seen[1].starts_with("DELETE /v1/plugins/installs/forms?purge=true&backup=true "));
    }

    #[tokio::test]
    async fn uninstalling_what_is_not_installed_sends_no_delete() {
        // One canned response: the read. A DELETE would hang on accept.
        let (base, seen) = canned_operator(vec![response(
            "404 Not Found",
            r#"{"error":"not installed"}"#,
        )])
        .await;
        let err = uninstall(&client(base), "forms", false, false, true, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no plugin install `forms`"), "{err}");
        assert!(err.contains("nothing was changed"), "{err}");
        assert_eq!(seen.await.unwrap().len(), 1);
    }

    #[test]
    fn the_uninstall_preview_says_what_happens_to_the_database() {
        let i: Install = serde_json::from_str(FORMS).unwrap();
        assert!(describe(&i, false).contains("schema plugin_forms — dropped, no backup"));
        assert!(describe(&i, true).contains("dumped, then dropped"));
    }

    #[test]
    fn a_release_is_a_name_and_maybe_a_version() {
        assert_eq!(release_spec("forms").unwrap(), ("forms", None));
        assert_eq!(
            release_spec("forms@0.2.0").unwrap(),
            ("forms", Some("0.2.0"))
        );
        for bad in ["forms@", "forms@0.2/0", "forms@a b"] {
            assert!(release_spec(bad).is_err(), "{bad:?}");
        }
    }

    const PLAN: &str = r#"{"id":"01JABCDEFGHJKMNPQRSTVWXYZ0","install_id":"01JABCDEFGHJKMNPQRSTVWXYZ0","app_type":"forms","version":"0.2.0","source":"registry","subdomain":"forms","airdress":"ada","signed_by":"65b60673d6ed884b","author":{"author":"airdress","key":"d89b","signers":[{"key":"d89b"},{"machine":"release-ci"}],"provenance_sha256":"0123456789abcdef0123"},"consent":{"host_api":1,"airdress":{"egress_hosts":["api.example.com:443"]},"database":"db:none","limits":{"memory":"128Mi"}}}"#;

    #[test]
    fn a_signer_is_a_key_or_a_machine() {
        assert_eq!(parse_signers(&[]).unwrap(), None);
        let k = "AB".repeat(32);
        let got = parse_signers(&[format!("key:{k}"), "machine:release-ci".into()])
            .unwrap()
            .unwrap();
        assert_eq!(got[0].key.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(got[1].machine.as_deref(), Some("release-ci"));
        let body = serde_json::to_value(InstallBody {
            plugin: Some("forms"),
            signers: Some(got),
            ..InstallBody::default()
        })
        .unwrap();
        assert_eq!(
            body["signers"][1],
            serde_json::json!({ "machine": "release-ci" })
        );
        for bad in ["key:zz", "ab", "machine:", "user:x"] {
            assert!(parse_signers(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(parse_signers(&vec!["machine:m".to_owned(); 17]).is_err());
    }

    #[test]
    fn the_consent_summary_says_who_signed_it_and_what_each_scope_may_do() {
        let i: Install = serde_json::from_str(PLAN).unwrap();
        let text = consent_summary(&i);
        for want in [
            "plugin forms 0.2.0",
            "forms.ada",
            "registry release by airdress, signed by key 65b60673d6ed884b",
            "you pin who may sign what it runs next",
            "key d89b",
            "machine release-ci",
            "provenance attested by the registry",
            "database:  db:none",
            "memory 128Mi",
            "airdress scope — you approve this by installing",
            "egress:  api.example.com:443",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert!(!text.contains("personal scope"), "{text}");
    }

    #[tokio::test]
    async fn a_registry_install_shows_the_plan_then_installs_the_version_shown() {
        let (base, seen) = canned_operator(vec![
            response("201 Created", PLAN),
            response("201 Created", PLAN),
        ])
        .await;
        let body = InstallBody {
            plugin: Some("forms"),
            ..InstallBody::default()
        };
        install(&client(base), body, false, true, true)
            .await
            .unwrap();
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("POST /v1/plugins/installs?dry_run=true "));
        assert_eq!(body_of(&seen[0]), serde_json::json!({ "plugin": "forms" }));
        assert!(seen[1].starts_with("POST /v1/plugins/installs "));
        assert_eq!(
            body_of(&seen[1]),
            serde_json::json!({ "plugin": "forms", "version": "0.2.0" }),
            "the real install must pin the version the owner was shown"
        );
    }

    #[tokio::test]
    async fn a_script_never_installs_without_yes() {
        let (base, seen) = canned_operator(vec![response("201 Created", PLAN)]).await;
        let body = InstallBody {
            plugin: Some("forms"),
            ..InstallBody::default()
        };
        // Test stdin is not a terminal.
        let err = install(&client(base), body, false, false, true)
            .await
            .unwrap_err();
        let f = crate::exit::classify(&err);
        assert_eq!(f.exit, crate::exit::Exit::ConfirmationRequired);
        assert!(f.hint.unwrap_or_default().contains("--yes"), "{err:#}");
        assert_eq!(seen.await.unwrap().len(), 1, "only the dry run was sent");
    }

    #[tokio::test]
    async fn a_refused_release_says_why_and_where() {
        let (base, _) = canned_operator(vec![response(
            "422 Unprocessable Entity",
            r#"{"error":"signed by key 1234, which this operator does not trust","code":"bundle_signature_invalid","step":"signature"}"#,
        )])
        .await;
        let body = InstallBody {
            plugin: Some("forms"),
            ..InstallBody::default()
        };
        let err = install(&client(base), body, false, true, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bundle_signature_invalid at signature"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn authorize_names_only_the_plugin_and_sends_no_principal() {
        let answer = r#"{"id":"x","installId":"01J","scope":"personal","state":"active","version":"0.1.0","scopeDigest":"d","createdAt":"2026-09-28T00:00:00Z","updatedAt":"2026-09-28T00:00:00Z"}"#;
        let (base, seen) = canned_operator(vec![response("201 Created", answer)]).await;
        let a = client(base).authorize("geo").await.unwrap();
        assert_eq!((a.state.as_str(), a.version.as_str()), ("active", "0.1.0"));
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("POST /v1/plugins/installs/geo/authorizations "));
        let body = seen[0].split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.is_empty(), "the request names nobody: {body:?}");
    }

    #[tokio::test]
    async fn authorize_says_the_operators_refusal() {
        let refused = r#"{"type":"about:blank","status":403,"code":"personal_scope_not_offered"}"#;
        let (base, _) = canned_operator(vec![response("403 Forbidden", refused)]).await;
        let err = client(base).authorize("geo").await.unwrap_err().to_string();
        assert!(err.contains("authorize"), "{err}");
    }

    #[tokio::test]
    async fn deauthorize_keeps_or_erases_as_asked() {
        let (base, seen) = canned_operator(vec![
            response("204 No Content", ""),
            response(
                "404 Not Found",
                r#"{"type":"about:blank","status":404,"code":"not_authorized"}"#,
            ),
        ])
        .await;
        let c = client(base);
        assert!(c.deauthorize("geo", true).await.unwrap());
        assert!(!c.deauthorize("geo", false).await.unwrap());
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("DELETE /v1/plugins/installs/geo/authorizations/me?data=keep "));
        assert!(
            seen[1].starts_with("DELETE /v1/plugins/installs/geo/authorizations/me?data=erase ")
        );
    }

    #[test]
    fn offering_the_personal_scope_is_said_only_when_asked() {
        let v = serde_json::to_value(InstallBody {
            plugin: Some("geo"),
            offer_personal: Some(true),
            ..InstallBody::default()
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "plugin": "geo", "offer_personal": true })
        );
    }
}
