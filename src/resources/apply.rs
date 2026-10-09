//! `airdress apply -f <file>` — server-side apply against the operator.
//!
//! Multi-doc YAML supported per SPEC-033 §8.5. Each manifest in the
//! file is sent in document order; the first failure aborts the run
//! (text mode) or is reported in the JSON envelope alongside earlier
//! successes (json mode).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use super::client::{ApplyResult, OperatorResourcesClient};
use super::parse::read_and_parse;

#[derive(Debug)]
pub struct ApplyArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub file: &'a Path,
    pub dry_run: bool,
    pub operator_url: Option<&'a str>,
    /// `--machine-key`: sign as an enrolled machine (flag only; the
    /// environment variable is not read here, so an `apply` never turns
    /// into a machine's by accident).
    pub machine_key: Option<&'a Path>,
}

pub async fn run(args: ApplyArgs<'_>) -> Result<()> {
    let docs = read_and_parse(args.file)?;
    if docs.is_empty() {
        bail!(
            "manifest file {} contains no documents",
            args.file.display()
        );
    }

    if let Some(key) = args.machine_key {
        return run_as_machine(&args, &docs, key).await;
    }

    let op = build_client(
        args.paths,
        args.profile,
        args.explicit_airdress,
        args.operator_url,
        args.json,
        args.quiet,
    )
    .await?;

    let mut results: Vec<ApplyResult> = Vec::with_capacity(docs.len());
    for (idx, doc) in docs.iter().enumerate() {
        match op.apply(doc, args.dry_run).await {
            Ok(r) => {
                if !args.json {
                    print_text(&r, args.dry_run);
                }
                results.push(r);
            }
            Err(e) => {
                if args.json {
                    let envelope = serde_json::json!({
                        "applied": results,
                        "failed_at_index": idx,
                        "error": e.to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&envelope)?);
                }
                return Err(e.context(format!(
                    "applying document #{} from {}",
                    idx + 1,
                    args.file.display()
                )));
            }
        }
    }

    if args.json {
        let envelope = serde_json::json!({
            "applied": results,
            "dry_run": args.dry_run,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    }

    Ok(())
}

/// Apply each document as an enrolled machine: every request is signed
/// with its key, and the operator decides by the machine's grants. A
/// refusal is printed with every field it carries and stops the run.
async fn run_as_machine(
    args: &ApplyArgs<'_>,
    docs: &[serde_json::Value],
    key: &Path,
) -> Result<()> {
    use crate::functions::client::{OperatorAuth, OperatorFunctionsClient};
    use crate::functions::{operator_base, refusal, OPERATOR_URL_ENV};

    let Some((identity, _)) = crate::machine::load(Some(key))? else {
        bail!("{} holds no machine key", key.display());
    };
    let url = args
        .operator_url
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(OPERATOR_URL_ENV)
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .with_context(|| {
            format!(
                "a machine reads no hub profile, so the operator must be named: pass \
                 --operator-url or set {OPERATOR_URL_ENV}"
            )
        })?;
    let op = OperatorFunctionsClient::with_base_url(
        operator_base(&url),
        OperatorAuth::Machine(std::sync::Arc::new(identity)),
    )?;
    let mut applied = Vec::with_capacity(docs.len());
    for (idx, doc) in docs.iter().enumerate() {
        match op.apply(doc, args.dry_run).await? {
            Ok(answer) => {
                if !args.json {
                    ui::ok(format!(
                        "{}/{} {}",
                        answer["kind"].as_str().unwrap_or("?"),
                        answer["name"].as_str().unwrap_or("?"),
                        answer["action"].as_str().unwrap_or("applied")
                    ));
                }
                applied.push(answer);
            }
            Err((status, r)) => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "applied": applied,
                            "failed_at_index": idx,
                            "status": status,
                            "refusal": r,
                        }))?
                    );
                } else {
                    for line in refusal::format(&r) {
                        ui::say(line);
                    }
                }
                bail!(
                    "document #{} from {} refused ({status} {})",
                    idx + 1,
                    args.file.display(),
                    r.error
                );
            }
        }
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "applied": applied,
                "dry_run": args.dry_run,
            }))?
        );
    }
    Ok(())
}

fn print_text(r: &ApplyResult, dry_run: bool) {
    let prefix = if dry_run { "would " } else { "" };
    let action_clean = r.action.strip_prefix("would_").unwrap_or(&r.action);
    let msg = format!("{}/{} {prefix}{action_clean}", r.kind, r.name);
    match action_clean {
        "created" | "configured" => ui::ok(msg),
        "unchanged" => ui::note(msg),
        _ => ui::say(msg),
    }
}

/// Shared operator-client builder used by every verb in this module.
/// Resolves the airdress via SPEC-043 precedence, looks up the FQDN
/// via the hub, and wires the existing hub bearer into the operator
/// client. `--operator-url` bypasses the hub lookup (dev only).
pub(super) async fn build_client(
    paths: &crate::paths::Paths,
    profile: Option<&str>,
    explicit_airdress: Option<&str>,
    operator_url: Option<&str>,
    json: bool,
    quiet: bool,
) -> Result<OperatorResourcesClient> {
    let profile_name = storage::resolve_profile_name(paths, profile)?;
    let resolved = context::resolve(paths, &profile_name, explicit_airdress)?;

    if !json && !quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }

    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(url) = operator_url {
        let bearer = hub.operator_bearer(url).await?;
        OperatorResourcesClient::with_base_url(url.to_owned(), bearer)
            .context("build operator client from --operator-url")
    } else {
        let fqdn = hub.resolve_fqdn(&resolved.name).await?;
        let bearer = hub.operator_bearer(&fqdn).await?;
        OperatorResourcesClient::new(&fqdn, bearer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(action: &str) -> ApplyResult {
        ApplyResult {
            kind: "K".into(),
            name: "n".into(),
            action: action.into(),
            generation: 1,
            previous_generation: None,
            resource_version: Some(1),
        }
    }

    #[test]
    fn print_text_doesnt_panic_on_actions() {
        for a in [
            "created",
            "configured",
            "unchanged",
            "would_create",
            "would_update",
        ] {
            print_text(&r(a), a.starts_with("would_"));
        }
    }
}
