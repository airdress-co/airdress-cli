//! `airdress fn deploy`: a local tree to serving in one command (SPEC-113
//! design §3).
//!
//! Seven client-side steps over routes that already exist, plus promote.
//! There is no deploy route on the operator, because only the client can
//! sign:
//!
//! | # | step | call |
//! |---|------|------|
//! | 0 | resolve the function and its signer set | `GET /v1/kinds/Function/{name}` (owner) or the committed manifest (CI) |
//! | 1 | check the snapshot | `POST /v1/functions/sources?dry-run=true`, unsigned, `basedOn` |
//! | 2 | digest match | the local canonical digest against the check's `sourceDigest` |
//! | 3 | confirm | one confirmation, before the first write |
//! | 4 | sign | Ed25519 over the digest, locally |
//! | 5 | publish | `POST /v1/functions/sources`, signed |
//! | 6 | promote (exists) / apply (new, owner) | `POST /v1/functions/{name}/promote` / `POST /v1/apply` |
//! | 7 | wait | `GET /v1/kinds/Function/{name}/status` until loaded |
//!
//! The tree is read once (step 1) and that snapshot is what is checked,
//! compared, signed and published. Deploy never applies to an existing
//! function and never widens a grant or changes a signer set: an existing
//! function moves by promote, which writes `spec.source.version` and
//! nothing else.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Serialize;
use serde_json::Value;

use super::client::{
    MachineAuthorizationExpired, OperatorFunctionsClient, PromoteOutcome, PublishOutcome,
};
use super::layout::{self, Changed, Entry};
use super::refusal::{self, Refusal};
use super::signers::{self, Member, OwnSigner};
use super::stops::DeployStop;
use super::tree::{self, Files, Signer};
use super::writeback;
use super::Connection;
use crate::ui;

/// The Function manifest's `apiVersion`.
pub const FUNCTION_API_VERSION: &str = crate::wire::API_VERSION;

#[derive(Args, Clone, Debug)]
pub struct DeployOpts {
    /// A function directory (`function.json`, `src/`, and its
    /// `function.yaml`). Omit it with --ci, --all or --since to deploy the
    /// repository's functions (the map file, or discovery).
    pub dir: Option<PathBuf>,
    /// The Function's `metadata.name`. Defaults to the manifest's, else
    /// the directory's name.
    #[arg(long)]
    pub name: Option<String>,
    /// Print the confirmation and proceed without asking.
    #[arg(short, long)]
    pub yes: bool,
    /// Check, compare, and dry-run the promote; print what a deploy would
    /// do, and write nothing.
    #[arg(long)]
    pub plan: bool,
    /// Unattended: never prompt, never create a function, never apply.
    /// `basedOn` is read from the committed manifest at the branch head,
    /// and the served version is written back into it.
    #[arg(long)]
    pub ci: bool,
    /// Every function in the repository, changed or not.
    #[arg(long, conflicts_with = "since")]
    pub all: bool,
    /// Only the functions whose `function.json` or `src/` changed since
    /// this commit (an all-zero or unknown commit selects all).
    #[arg(long, value_name = "REF")]
    pub since: Option<String>,
    /// The map file. Defaults to `airdress.functions.yaml` at the
    /// repository root, when present.
    #[arg(long, value_name = "FILE")]
    pub map: Option<PathBuf>,
    /// The branch whose head decides `basedOn` and `superseded` in CI.
    /// Defaults to GITHUB_REF_NAME, else the checked-out branch.
    #[arg(long)]
    pub branch: Option<String>,
    /// Seconds to wait for the new version to load (the first function
    /// after an operator deploy compiles the engine, ≈ 15 s).
    #[arg(long, value_name = "SECONDS", default_value_t = 60)]
    pub wait_timeout: u64,
    /// A file holding the Ed25519 source-signing seed (64 hex), or set
    /// AIRDRESS_FUNCTION_SIGNING_KEY to the hex.
    #[arg(long, value_name = "PATH")]
    pub signing_key: Option<PathBuf>,
    /// Sign as this approved machine (its registered source-signing key).
    /// With a machine key it defaults to that machine.
    #[arg(long, value_name = "MACHINE")]
    pub signer_machine: Option<String>,
}

/// One function's result, as `--output json` prints it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub function: String,
    pub operator: String,
    pub previous: Option<String>,
    pub version: Option<String>,
    /// `deployed`, `unchanged`, `superseded`, `skipped`, `planned`, a
    /// [`DeployStop`] code, or an operator refusal's code verbatim.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_back: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Report {
    fn new(function: &str, operator: &str) -> Self {
        Self {
            function: function.to_owned(),
            operator: operator.to_owned(),
            previous: None,
            version: None,
            outcome: String::new(),
            step: None,
            message: None,
            refusal: None,
            elapsed_ms: None,
            write_back: None,
            notes: Vec::new(),
        }
    }

    /// Whether this counts as success.
    pub fn ok(&self) -> bool {
        matches!(
            self.outcome.as_str(),
            "deployed" | "unchanged" | "superseded" | "skipped" | "planned"
        )
    }

    fn stop(mut self, stop: DeployStop, message: impl Into<String>) -> Self {
        self.outcome = stop.code().to_owned();
        self.message = Some(message.into());
        self
    }

    fn refused(mut self, step: &'static str, refusal: Refusal) -> Self {
        self.outcome = refusal.error.clone();
        self.step = Some(step);
        self.message = Some(refusal.message.clone());
        self.refusal = Some(refusal);
        self
    }
}

/// The exit status a failed report means: the operator's code when it
/// decides it (a stale base is a conflict), else the stop's, else a refusal.
pub fn exit_of(r: &Report) -> crate::exit::Exit {
    if let Some(e) = crate::exit::Exit::for_code(&r.outcome) {
        return e;
    }
    match DeployStop::ALL.iter().find(|s| s.code() == r.outcome) {
        Some(s) => s.exit(),
        None if r.refusal.is_some() => crate::exit::Exit::Refused,
        None => crate::exit::Exit::Internal,
    }
}

/// Why one function's loop ended early.
#[derive(Debug)]
enum Halt {
    Done(Box<Report>),
    Err(anyhow::Error),
}

impl Halt {
    fn done(r: Report) -> Self {
        Self::Done(Box::new(r))
    }
}

impl From<anyhow::Error> for Halt {
    fn from(e: anyhow::Error) -> Self {
        Self::Err(e)
    }
}

/// Everything a run shares.
pub struct Run<'a> {
    pub conn: &'a Connection,
    pub opts: &'a DeployOpts,
    pub own: OwnSigner,
    pub seed: Option<[u8; 32]>,
    pub json: bool,
    /// `-v`: list the files each deploy leaves out (FR-34).
    pub verbose: bool,
}

impl std::fmt::Debug for Run<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Run")
            .field("json", &self.json)
            .field("verbose", &self.verbose)
            .finish_non_exhaustive()
    }
}

/// What one function's loop needs to know about it.
#[derive(Debug)]
struct Target {
    name: String,
    dir: PathBuf,
    /// The manifest file on disk, when there is one.
    manifest_path: Option<PathBuf>,
    /// The manifest as the working tree has it.
    local: Option<Value>,
    /// CI: the manifest at the branch head (`basedOn` and the set).
    committed: Option<Value>,
    client: Arc<OperatorFunctionsClient>,
}

/// The host an operator is named by, as reports show it.
fn host_of(operator: &str) -> String {
    let base = super::operator_base(operator);
    reqwest::Url::parse(&base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or(base)
}

fn read_manifest(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_str(&text)
        .with_context(|| format!("{} is not a YAML manifest", path.display()))
}

/// Run a deploy: one directory, or the repository's functions.
pub async fn run(run: &Run<'_>) -> Result<Vec<Report>> {
    let opts = run.opts;
    let repository = opts.ci || opts.all || opts.since.is_some();
    if repository && opts.dir.is_some() && opts.ci {
        bail!("--ci deploys the repository's functions; run it without a directory");
    }
    let reports = if repository && opts.dir.is_none() {
        run_repository(run).await?
    } else {
        let dir = opts.dir.clone().unwrap_or_else(|| PathBuf::from("."));
        vec![run_directory(run, &dir).await?]
    };
    Ok(reports)
}

async fn run_directory(run: &Run<'_>, dir: &Path) -> Result<Report> {
    let manifest_path = dir.join(layout::MANIFEST_FILE);
    let local = manifest_path
        .is_file()
        .then(|| read_manifest(&manifest_path))
        .transpose()?;
    let name = function_name(run.opts.name.as_deref(), local.as_ref(), dir)?;
    let client = run.conn.client_for(None).await?;
    let target = Target {
        name,
        dir: dir.to_path_buf(),
        manifest_path: local.as_ref().map(|_| manifest_path),
        local,
        committed: None,
        client,
    };
    Ok(deploy_one(run, &target).await)
}

/// `--name`, else the manifest's `metadata.name`, else the directory's.
fn function_name(flag: Option<&str>, manifest: Option<&Value>, dir: &Path) -> Result<String> {
    if let Some(n) = flag {
        return Ok(n.to_owned());
    }
    if let Some(n) = manifest
        .and_then(|m| m.pointer("/metadata/name"))
        .and_then(Value::as_str)
    {
        return Ok(n.to_owned());
    }
    let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    abs.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .with_context(|| format!("{} has no usable name; pass --name", dir.display()))
}

/// The branch whose head decides `basedOn` and `superseded`.
fn ci_branch(root: &Path, flag: Option<&str>) -> Result<String> {
    if let Some(b) = flag {
        return Ok(b.to_owned());
    }
    if let Ok(b) = std::env::var("GITHUB_REF_NAME") {
        if !b.trim().is_empty() {
            return Ok(b.trim().to_owned());
        }
    }
    let b = layout::git(root, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let b = b.trim();
    if b == "HEAD" || b.is_empty() {
        bail!("HEAD is detached, so there is no branch to read the head of; pass --branch");
    }
    Ok(b.to_owned())
}

/// The head of `branch` on `origin`, fetched now (FR-40).
fn fetch_head(root: &Path, branch: &str) -> Result<String> {
    layout::git(root, &["fetch", "--quiet", "origin", branch]).with_context(|| {
        format!("fetch origin {branch}: CI mode reads basedOn at the branch head")
    })?;
    Ok(layout::git(root, &["rev-parse", "FETCH_HEAD"])?
        .trim()
        .to_owned())
}

async fn run_repository(run: &Run<'_>) -> Result<Vec<Report>> {
    let opts = run.opts;
    let cwd = std::env::current_dir()?;
    let root = layout::repo_root(&cwd);
    let default_operator = run.conn.default_operator();
    let map_path = opts
        .map
        .clone()
        .unwrap_or_else(|| root.join(layout::MAP_FILE));
    let entries: Vec<Entry> = if map_path.is_file() {
        let text = crate::fsx::read_to_string(&map_path)?;
        match layout::parse_map(&root, &text, default_operator.as_deref()) {
            Ok(e) => e,
            Err(invalid) => {
                let r = Report::new("(map file)", default_operator.as_deref().unwrap_or(""))
                    .stop(DeployStop::LayoutInvalid, invalid.to_string());
                return Ok(vec![r]);
            }
        }
    } else {
        let (found, notes) = layout::discover(&root)?;
        for n in notes {
            ui::note(n);
        }
        found
    };

    let changed = match (&opts.since, opts.all) {
        (Some(base), false) => layout::changed_since(&root, base),
        _ => Changed::All("--all".to_owned()),
    };
    if let Changed::All(why) = &changed {
        if !run.json && opts.since.is_some() {
            ui::note(format!("deploying every function: {why}"));
        }
    }

    let (head, remote) = if opts.ci {
        let branch = ci_branch(&root, opts.branch.as_deref())?;
        let head = layout::git(&root, &["rev-parse", "HEAD"])?
            .trim()
            .to_owned();
        (Some(head), Some(fetch_head(&root, &branch)?))
    } else {
        (None, None)
    };
    let moved: Vec<String> = match (&head, &remote) {
        (Some(h), Some(r)) if h != r => layout::git(&root, &["diff", "--name-only", h, r])?
            .lines()
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };

    let mut reports = Vec::new();
    for entry in &entries {
        let dir = root.join(&entry.path);
        let manifest_path = root.join(&entry.manifest);
        let operator_label = entry
            .operator
            .clone()
            .or_else(|| default_operator.clone())
            .map(|o| host_of(&o))
            .unwrap_or_default();
        let local = match read_manifest(&manifest_path) {
            Ok(v) => v,
            Err(e) => {
                reports.push(
                    Report::new(&entry.path, &operator_label)
                        .stop(DeployStop::LayoutInvalid, format!("{e:#}")),
                );
                continue;
            }
        };
        let name = match function_name(None, Some(&local), &dir) {
            Ok(n) => n,
            Err(e) => {
                reports.push(
                    Report::new(&entry.path, &operator_label)
                        .stop(DeployStop::LayoutInvalid, format!("{e:#}")),
                );
                continue;
            }
        };
        if !changed.selects(&root, entry) {
            let mut r = Report::new(&name, &operator_label);
            r.outcome = "skipped".into();
            r.message =
                Some("nothing under function.json or src/ changed, nor spec.source.version".into());
            reports.push(r);
            continue;
        }
        if moved.iter().any(|p| entry.touched_by(p)) {
            let r = Report::new(&name, &operator_label).stop(
                DeployStop::Superseded,
                "a newer commit on the branch changes this function; that run deploys it",
            );
            reports.push(r);
            continue;
        }
        let committed = match &remote {
            Some(r) => {
                match layout::git(&root, &["show", &format!("{r}:{}", entry.manifest)]) {
                    Ok(text) => Some(serde_yaml::from_str::<Value>(&text).with_context(|| {
                        format!(
                            "{} at the branch head is not a YAML manifest",
                            entry.manifest
                        )
                    })?),
                    // Not at the head yet: the working tree's is the committed one.
                    Err(_) => Some(local.clone()),
                }
            }
            None => None,
        };
        let client = match run.conn.client_for(entry.operator.as_deref()).await {
            Ok(c) => c,
            Err(e) => {
                reports.push(Report::new(&name, &operator_label).refused_err(e));
                continue;
            }
        };
        let target = Target {
            name,
            dir,
            manifest_path: Some(manifest_path),
            local: Some(local),
            committed,
            client,
        };
        reports.push(deploy_one(run, &target).await);
    }
    Ok(reports)
}

impl Report {
    fn refused_err(mut self, e: anyhow::Error) -> Self {
        if let Some(m) = e.downcast_ref::<MachineAuthorizationExpired>() {
            return self.stop(DeployStop::MachineAuthorizationExpired, m.to_string());
        }
        // A confirmation this run could not ask for keeps its own code, so
        // the summary exits 7 rather than 1.
        if let Some(f) = e.downcast_ref::<crate::exit::Failure>() {
            if f.exit == crate::exit::Exit::ConfirmationRequired {
                self.outcome = f.code.clone();
                self.message = Some(f.message.clone());
                return self;
            }
        }
        self.outcome = "error".into();
        self.message = Some(format!("{e:#}"));
        self
    }
}

async fn deploy_one(run: &Run<'_>, t: &Target) -> Report {
    let report = Report::new(&t.name, &t.client.host());
    match deploy_steps(run, t, report.clone()).await {
        Ok(r) => r,
        Err(Halt::Done(r)) => *r,
        Err(Halt::Err(e)) => report.refused_err(e),
    }
}

/// Step 0 — which function, which base, which set; and whether this
/// client may sign for it.
#[derive(Debug)]
struct Resolved {
    /// `None`: the function does not exist and is created (owner only).
    base: Option<String>,
    exists: bool,
    set: Vec<Member>,
}

async fn resolve(run: &Run<'_>, t: &Target, report: &Report) -> Result<Resolved, Halt> {
    if run.opts.ci {
        let committed = t.committed.as_ref().or(t.local.as_ref());
        let source = committed
            .and_then(|m| m.pointer("/spec/source"))
            .cloned()
            .unwrap_or(Value::Null);
        let Some(base) = source.get("version").and_then(Value::as_str) else {
            return Err(Halt::done(report.clone().stop(
                DeployStop::FunctionMissing,
                "the committed manifest names no spec.source.version: the function has not been \
                 created; the owner creates it once, and CI deploys it after",
            )));
        };
        let set = signers::allowed(&source).map_err(|e| {
            Halt::done(
                report
                    .clone()
                    .stop(DeployStop::LayoutInvalid, format!("{e:#}")),
            )
        })?;
        return Ok(Resolved {
            base: Some(base.to_owned()),
            exists: true,
            set,
        });
    }
    let live = t.client.function(&t.name).await?;
    let Some(live) = live else {
        return Ok(Resolved {
            base: None,
            exists: false,
            set: Vec::new(),
        });
    };
    let source = live.pointer("/spec/source").cloned().unwrap_or(Value::Null);
    let set =
        signers::allowed(&source).map_err(|e| Halt::Err(e.context("the applied manifest")))?;
    Ok(Resolved {
        base: source
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
        exists: true,
        set,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered pipeline, as the design's table"
)]
async fn deploy_steps(run: &Run<'_>, t: &Target, mut report: Report) -> Result<Report, Halt> {
    let op = &t.client;
    let stop = |r: &Report, s: DeployStop, m: String| Halt::done(r.clone().stop(s, m));

    // Step 0.
    let resolved = resolve(run, t, &report).await?;
    report.previous.clone_from(&resolved.base);
    if resolved.exists {
        if matches!(run.own, OwnSigner::Unsigned) && !resolved.set.is_empty() {
            return Err(stop(
                &report,
                DeployStop::SignerUnavailable,
                format!(
                    "no signing key here; this function is signed by one of: {}",
                    signers::describe_set(&resolved.set).join("; ")
                ),
            ));
        }
        if !signers::is_member(&resolved.set, &run.own) {
            return Err(stop(
                &report,
                DeployStop::SignerNotThisClient,
                format!(
                    "{} is not a member of {}'s signers: {}. Adding a signer is an apply by the \
                     owner: `airdress fn signers add {} --key <hex> | --machine <id>`",
                    run.own.describe(),
                    t.name,
                    signers::describe_set(&resolved.set).join("; "),
                    t.name
                ),
            ));
        }
        if resolved.set.is_empty() {
            report
                .notes
                .push("this function names no signer: deploying unsigned source".into());
        }
    } else {
        if run.opts.ci {
            return Err(stop(
                &report,
                DeployStop::FunctionMissing,
                format!("{} does not exist; CI never creates a function", t.name),
            ));
        }
        if matches!(run.own, OwnSigner::Unsigned) {
            return Err(stop(
                &report,
                DeployStop::SignerUnavailable,
                "creating a function names this client's key as its signer, and there is no \
                 signing key here"
                    .into(),
            ));
        }
    }
    if run.opts.ci {
        drift_note(t, &mut report).await?;
    }

    // Step 1: the snapshot, read once.
    let (files, ignored) = layout::select(&t.dir).map_err(|e| {
        Halt::done(
            report
                .clone()
                .stop(DeployStop::LayoutInvalid, format!("{e:#}")),
        )
    })?;
    if run.verbose && !run.json {
        for i in &ignored {
            ui::note(format!("{}: left out of the deploy tree: {i}", t.name));
        }
    }
    let base = resolved.base.as_deref();
    let check_body = tree::publish_body(&t.name, base, &Signer::Unsigned, &files);
    let checked = match op.publish(&check_body, true).await? {
        PublishOutcome::Published { body, .. } => body,
        PublishOutcome::Stale(stale) if already_serving(op, t, &files, &stale.current).await? => {
            // FR-25a: what runs is this very tree — an earlier deploy
            // landed and only its write-back was lost. Nothing to do but
            // let git say so.
            report.outcome = "unchanged".into();
            report.version = Some(stale.current.clone());
            report.message = Some(format!(
                "{} already serves this tree (an earlier deploy landed)",
                stale.current
            ));
            write_back_if_needed(run, t, &stale.current, &mut report);
            return Ok(report);
        }
        PublishOutcome::Stale(stale) => {
            // Show the Difference (FR-11): the one line that says how.
            if let Some(hint) = refusal::format_stale(&stale).pop() {
                report.notes.push(hint.trim().to_owned());
            }
            let r = stale_refusal(
                stale.based_on.clone(),
                Some(stale.current.clone()),
                &stale.message,
            );
            return Err(Halt::done(who_moved(run, t, report, "check", r).await));
        }
        PublishOutcome::Refused { refusal, .. } => {
            let mut r = report.stop(
                DeployStop::CheckFailed,
                format!("the check refused: {}", refusal.error),
            );
            if refusal.error == "capability_not_granted" && resolved.exists && !run.opts.ci {
                r.notes.push(format!(
                    "the tree asks for more than the grant. Widening it is its own apply: edit \
                     spec.capabilities in {}, review it with `airdress diff -f <file>`, then \
                     `airdress apply -f <file>`",
                    t.manifest_path.as_deref().map_or_else(
                        || "the Function manifest".to_owned(),
                        |p| p.display().to_string()
                    )
                ));
            }
            r.step = Some("check");
            r.refusal = Some(refusal);
            return Err(Halt::done(r));
        }
    };

    // The check's notes (a deprecated or alpha library module, a
    // concurrency the library warns about): information, never a stop.
    report.notes.extend(refusal::notes(&checked));

    // Step 2.
    let local_digest = format!("sha256:{}", tree::hex(&tree::canonical_digest(&files)));
    if let Some(d) = checked["sourceDigest"].as_str() {
        if d != local_digest {
            return Err(stop(
                &report,
                DeployStop::DigestMismatch,
                format!(
                    "the operator checked {d}, this client holds {local_digest}; nothing was signed"
                ),
            ));
        }
    } else {
        report.notes.push(
            "the operator did not name the source digest (an older operator?); it could not be \
             compared"
                .into(),
        );
    }
    let would_be = checked["version"].as_str().map(str::to_owned);

    // Step 3.
    let manifest = if resolved.exists {
        None
    } else {
        let own = run
            .own
            .member()
            .ok_or_else(|| anyhow::anyhow!("no signer"))?;
        Some(draft_manifest(
            &t.name,
            would_be.as_deref().unwrap_or(""),
            &own,
            t.local.as_ref(),
            &files,
        )?)
    };
    let text = if let Some(m) = &manifest {
        create_text(
            &op.host(),
            &t.name,
            would_be.as_deref(),
            &files,
            &run.own,
            m,
        )
    } else {
        let serving = serving_line(op, &t.name, base).await;
        replace_text(
            &op.host(),
            &t.name,
            base,
            serving.as_deref(),
            would_be.as_deref(),
            files.len(),
            checked["unreachable"].as_array().map_or(0, Vec::len),
            &run.own,
        )
    };

    if run.opts.plan {
        return Ok(plan(
            run,
            t,
            report,
            &text,
            would_be.as_deref(),
            base,
            resolved.exists,
        )
        .await);
    }
    // Printed always: with --yes, and in CI, it is the record of what was
    // sent (stderr, so --output json stays clean).
    eprintln!("{text}");
    let question = if resolved.exists {
        "Deploy?"
    } else {
        "Create and deploy?"
    };
    match ui::confirm(
        question,
        ui::Confirm::new(run.opts.yes || run.opts.ci, run.json),
    ) {
        Ok(()) => {}
        Err(f) if f.exit == crate::exit::Exit::ConfirmationRequired => {
            return Err(Halt::Err(f.into()));
        }
        Err(_) => {
            return Err(stop(
                &report,
                DeployStop::ConfirmationDeclined,
                "nothing was written".into(),
            ));
        }
    }
    let started = Instant::now();

    // Step 4.
    let Some(seed) = run.seed else {
        if !resolved.set.is_empty() || !resolved.exists {
            return Err(stop(
                &report,
                DeployStop::SignerUnavailable,
                "no signing key here".into(),
            ));
        }
        return publish_and_run(
            run,
            t,
            report,
            &files,
            &Signer::Unsigned,
            &local_digest,
            base,
            manifest,
            started,
        )
        .await;
    };
    let signature = tree::sign(&files, &seed);
    let signer = match &run.own {
        OwnSigner::Machine { machine, .. } => Signer::Machine {
            machine: machine.clone(),
            signature,
        },
        _ => Signer::Key(signature),
    };
    publish_and_run(
        run,
        t,
        report,
        &files,
        &signer,
        &local_digest,
        base,
        manifest,
        started,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the loop's state at step 5, spelled out"
)]
async fn publish_and_run(
    run: &Run<'_>,
    t: &Target,
    mut report: Report,
    files: &Files,
    signer: &Signer,
    local_digest: &str,
    base: Option<&str>,
    manifest: Option<Value>,
    started: Instant,
) -> Result<Report, Halt> {
    let op = &t.client;
    // Step 5.
    let body = tree::publish_body(&t.name, base, signer, files);
    let published = match op.publish(&body, false).await? {
        PublishOutcome::Published { body, .. } => body,
        PublishOutcome::Stale(stale) => {
            // Show the Difference (FR-11): the one line that says how.
            if let Some(hint) = refusal::format_stale(&stale).pop() {
                report.notes.push(hint.trim().to_owned());
            }
            let r = stale_refusal(
                stale.based_on.clone(),
                Some(stale.current.clone()),
                &stale.message,
            );
            return Err(Halt::done(who_moved(run, t, report, "publish", r).await));
        }
        PublishOutcome::Refused { refusal, .. } => {
            return Err(Halt::done(report.refused("publish", refusal)))
        }
    };
    if let Some(d) = published["sourceDigest"].as_str() {
        if d != local_digest {
            return Err(Halt::done(report.stop(
                DeployStop::DigestMismatch,
                format!(
                    "the operator stored {d}, this client signed {local_digest}; do not promote it"
                ),
            )));
        }
    }
    let version = published["version"]
        .as_str()
        .context("the publish answer names no version")?
        .to_owned();
    report.version = Some(version.clone());

    // Step 6.
    let generation = if let Some(mut manifest) = manifest {
        manifest["spec"]["source"]["version"] = version.clone().into();
        match op.apply(&manifest, false).await? {
            Ok(answer) => {
                let g = answer["generation"].as_i64().unwrap_or(1);
                write_created_manifest(t, &manifest, &mut report);
                g
            }
            Err((_, refusal)) => return Err(Halt::done(report.refused("apply", refusal))),
        }
    } else {
        match op.promote(&t.name, &version, base, false).await? {
            PromoteOutcome::Promoted(answer) => {
                if answer["changed"] == false {
                    report.outcome = "unchanged".into();
                    report.message = Some(format!("{version} already serves"));
                    write_back_if_needed(run, t, &version, &mut report);
                    return Ok(report);
                }
                answer["generation"].as_i64().unwrap_or_default()
            }
            // FR-25a: a retry after a promote that did land.
            PromoteOutcome::Stale { current, .. }
                if current.as_deref() == Some(version.as_str()) =>
            {
                report.outcome = "unchanged".into();
                report.message = Some(format!(
                    "{version} already serves (an earlier promote landed)"
                ));
                write_back_if_needed(run, t, &version, &mut report);
                return Ok(report);
            }
            PromoteOutcome::Stale {
                based_on,
                current,
                refusal,
            } => {
                let r = Refusal {
                    extra: stale_extra(based_on, current),
                    ..refusal
                };
                return Err(Halt::done(who_moved(run, t, report, "promote", r).await));
            }
            PromoteOutcome::RouteMissing { status } => {
                let msg = if run.opts.ci {
                    format!(
                        "the operator has no promote route (HTTP {status}); {version} is published \
                         but not running. Upgrade the operator"
                    )
                } else {
                    format!(
                        "the operator has no promote route (HTTP {status}); {version} is \
                         published. Today's flow: apply the Function manifest with \
                         spec.source.version: {version}"
                    )
                };
                return Err(Halt::done(
                    report.stop(DeployStop::OperatorPredatesPromote, msg),
                ));
            }
            PromoteOutcome::Refused { refusal, .. }
                if run.opts.ci && refusal.error == "function_not_found" =>
            {
                return Err(Halt::done(report.stop(
                    DeployStop::FunctionMissing,
                    format!("{} does not exist; CI never creates a function", t.name),
                )));
            }
            PromoteOutcome::Refused { refusal, .. } => {
                return Err(Halt::done(report.refused("promote", refusal)))
            }
        }
    };

    // Step 7.
    match wait(
        op,
        &t.name,
        generation,
        &version,
        Duration::from_secs(run.opts.wait_timeout),
        run.json,
    )
    .await?
    {
        Ok(_) => {
            report.outcome = "deployed".into();
            report.elapsed_ms = Some(started.elapsed().as_millis());
            if manifest_exists_for_write_back(t) {
                write_back_if_needed(run, t, &version, &mut report);
            }
            Ok(report)
        }
        Err((stop, message)) => {
            // The version is promoted either way: git should say so.
            write_back_if_needed(run, t, &version, &mut report);
            Ok(report.stop(stop, message))
        }
    }
}

fn manifest_exists_for_write_back(t: &Target) -> bool {
    t.manifest_path.as_ref().is_some_and(|p| p.is_file())
}

fn stale_extra(based_on: Option<String>, current: Option<String>) -> BTreeMap<String, Value> {
    let mut extra = BTreeMap::new();
    extra.insert(
        "basedOn".into(),
        based_on.map_or(Value::Null, Value::String),
    );
    extra.insert("current".into(), current.map_or(Value::Null, Value::String));
    extra
}

fn stale_refusal(based_on: Option<String>, current: Option<String>, message: &str) -> Refusal {
    Refusal {
        error: "source_base_stale".into(),
        message: message.to_owned(),
        extra: stale_extra(based_on, current),
        ..Refusal::default()
    }
}

/// Whether `current` — what the function runs, per a stale answer — is
/// this very tree. Asked with a second dry run based on `current`, which
/// writes nothing and names the version this tree would be; it is how a
/// retry after a deploy that did land (and lost its write-back) reads as
/// `unchanged` rather than as someone else's change (FR-25a).
async fn already_serving(
    op: &OperatorFunctionsClient,
    t: &Target,
    files: &Files,
    current: &str,
) -> Result<bool> {
    let body = tree::publish_body(&t.name, Some(current), &Signer::Unsigned, files);
    Ok(match op.publish(&body, true).await? {
        PublishOutcome::Published { body, .. } => body["version"].as_str() == Some(current),
        _ => false,
    })
}

/// A stale base: say who deployed the version that runs now (FR-64),
/// because with a signer set that may have been another member; and never
/// retry.
async fn who_moved(
    _run: &Run<'_>,
    t: &Target,
    report: Report,
    step: &'static str,
    r: Refusal,
) -> Report {
    let current = r
        .extra
        .get("current")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut report = report.refused(step, r);
    if let Some(current) = current {
        if let Ok(h) = t.client.versions(&t.name).await {
            let by = h["deployments"]
                .as_array()
                .and_then(|d| d.iter().find(|d| d["version"] == current.as_str()))
                .map(|d| {
                    format!(
                        "{current} was deployed by {} at {}",
                        d["actor"].as_str().unwrap_or("?"),
                        d["at"].as_str().unwrap_or("?")
                    )
                });
            if let Some(by) = by {
                report.notes.push(by);
            }
        }
        report.notes.push(format!(
            "bring that change into git: set spec.source.version to {current} in the manifest, \
             commit, and deploy again; nothing is retried"
        ));
    }
    report
}

/// FR-41: where the CI principal may read the live Function, name every
/// difference from the committed manifest other than the version. Nothing
/// is done about any of them.
async fn drift_note(t: &Target, report: &mut Report) -> Result<()> {
    let Some(committed) = t.committed.as_ref().or(t.local.as_ref()) else {
        return Ok(());
    };
    let live = match t.client.function_if_readable(&t.name).await {
        Ok(Some(Some(live))) => live,
        // A lapsed approval stops every step; anything else only means
        // there is no note to make.
        Err(e) if e.is::<MachineAuthorizationExpired>() => return Err(e),
        _ => return Ok(()),
    };
    for path in drift(
        committed.get("spec").unwrap_or(&Value::Null),
        live.get("spec").unwrap_or(&Value::Null),
    ) {
        report.notes.push(format!(
            "the committed manifest differs from the live Function at spec.{path}; CI does not \
             change it (the owner applies)"
        ));
    }
    Ok(())
}

/// The top-level spec fields (and `source`'s signer fields) where the
/// committed manifest names something the live spec does not match.
fn drift(committed: &Value, live: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(c) = committed.as_object() else {
        return out;
    };
    for (k, v) in c {
        if k == "source" {
            let cs = signers::allowed(v).unwrap_or_default();
            let ls = signers::allowed(&live["source"]).unwrap_or_default();
            let same = cs.len() == ls.len() && cs.iter().all(|m| ls.iter().any(|l| l.same(m)));
            if !same {
                out.push("source.signers".into());
            }
            if v.get("import") != live["source"].get("import") {
                out.push("source.import".into());
            }
            continue;
        }
        if live.get(k) != Some(v) {
            out.push(k.clone());
        }
    }
    out
}

/// "serving since …, signed by …" for the replace confirmation; `None`
/// when it cannot be read.
async fn serving_line(
    op: &OperatorFunctionsClient,
    name: &str,
    base: Option<&str>,
) -> Option<String> {
    let base = base?;
    let since = op.versions(name).await.ok().and_then(|h| {
        h["deployments"]
            .as_array()?
            .iter()
            .find(|d| d["version"] == base)
            .and_then(|d| d["at"].as_str().map(str::to_owned))
    });
    let signer =
        op.source(base)
            .await
            .ok()
            .map(|v| match (v["signer"].as_str(), v["signerRef"].as_str()) {
                (_, Some(m)) => format!("machine {m}"),
                (Some(k), None) => format!("key {}", signers::short_hex(k)),
                _ => "nobody (unsigned)".to_owned(),
            });
    match (since, signer) {
        (Some(s), Some(g)) => Some(format!("serving since {s}, signed by {g}")),
        (Some(s), None) => Some(format!("serving since {s}")),
        (None, Some(g)) => Some(format!("signed by {g}")),
        (None, None) => None,
    }
}

/// The confirmation for replacing what runs (design §3.3).
#[allow(clippy::too_many_arguments, reason = "each is one line of the text")]
pub fn replace_text(
    host: &str,
    name: &str,
    base: Option<&str>,
    serving: Option<&str>,
    version: Option<&str>,
    files: usize,
    unreached: usize,
    own: &OwnSigner,
) -> String {
    let mut s = format!("Deploy {name} on {host}\n");
    let base = base.unwrap_or("(no version)");
    match serving {
        Some(sv) => s.push_str(&format!("  replace  {base}  ({sv})\n")),
        None => s.push_str(&format!("  replace  {base}\n")),
    }
    let unreached = if unreached > 0 {
        format!("; {unreached} not reached by an import")
    } else {
        String::new()
    };
    s.push_str(&format!(
        "  with     {}  ({files} file{}{unreached})\n",
        version.unwrap_or("?"),
        if files == 1 { "" } else { "s" }
    ));
    s.push_str(&format!(
        "  signed by {} — a member of this function's signers\n",
        own.describe()
    ));
    s.push_str("  The grant does not change.");
    s
}

/// What `spec.events` binds, as one confirmation line; `None` when the
/// manifest binds no events. Binding `source: location` by this apply is the
/// owner's consent to location events (chat SPEC-114 FR-26), so it is said
/// in words, not left to the YAML below it.
pub fn events_line(manifest: &Value) -> Option<String> {
    let events = manifest.pointer("/spec/events").filter(|e| e.is_object())?;
    let source = events["source"].as_str().unwrap_or("ingress");
    let what = match source {
        "location" => "your location events",
        "ingress" => "events arriving at this operator's ingress endpoints",
        _ => "events",
    };
    let mut line = format!("  It will receive: {what} (source: {source})");
    if events["locationToModels"].as_bool() == Some(true) {
        line.push_str(", and may pass them to a model (locationToModels: true)");
    }
    Some(line)
}

/// The confirmation for creating a function: the manifest to be applied,
/// grant, event binding and signer set in full (FR-7).
pub fn create_text(
    host: &str,
    name: &str,
    version: Option<&str>,
    files: &Files,
    own: &OwnSigner,
    manifest: &Value,
) -> String {
    let yaml = serde_yaml::to_string(manifest).unwrap_or_default();
    let mut s = format!("Create {name} on {host}\n");
    s.push_str(&format!(
        "  version  {}  ({} file{})\n",
        version.unwrap_or("?"),
        files.len(),
        if files.len() == 1 { "" } else { "s" }
    ));
    s.push_str(&format!("  signers  {}\n", own.describe()));
    if let Some(line) = events_line(manifest) {
        s.push_str(&line);
        s.push('\n');
    }
    s.push_str("  It will be applied as:\n");
    for line in yaml.lines() {
        s.push_str(&format!("    {line}\n"));
    }
    s.pop();
    s
}

/// The Function manifest a create applies (FR-6, FR-63): the directory's
/// `function.yaml` when there is one — its grant and config — with
/// `spec.source` set to the new version and the set form holding this
/// client's signer; otherwise one drafted from `function.json`, granting
/// exactly the capabilities the tree asks for, for the owner to read in
/// the confirmation.
///
/// A local manifest's `spec.events` is kept as it is: the event binding
/// travels only in `function.yaml`, where `airdress fn new` writes a
/// template's `events`. The draft binds no events, because `function.json`
/// names none and no template is in scope here; a function written for
/// events needs its `function.yaml`.
pub fn draft_manifest(
    name: &str,
    version: &str,
    own: &Member,
    local: Option<&Value>,
    files: &Files,
) -> Result<Value> {
    let mut m = match local {
        Some(l) => l.clone(),
        None => {
            let fj: Value = files
                .get("function.json")
                .map(|b| serde_json::from_slice(b))
                .transpose()
                .context("function.json is not JSON")?
                .unwrap_or(Value::Null);
            let mut caps = serde_json::Map::new();
            for c in fj["capabilities"].as_array().into_iter().flatten() {
                let full = c["name"].as_str().unwrap_or_default();
                let short = full
                    .trim_start_matches("airdress:fn/")
                    .split('@')
                    .next()
                    .unwrap_or_default();
                if !short.is_empty() {
                    caps.insert(short.to_owned(), serde_json::json!({}));
                }
            }
            serde_json::json!({
                "spec": {
                    "runtime": layout::SOURCE_RUNTIME,
                    "capabilities": caps,
                    "enabled": true,
                }
            })
        }
    };
    let obj = m.as_object_mut().context("the manifest is not a mapping")?;
    obj.entry("apiVersion")
        .or_insert_with(|| FUNCTION_API_VERSION.into());
    obj.entry("kind").or_insert_with(|| "Function".into());
    let meta = obj
        .entry("metadata")
        .or_insert_with(|| serde_json::json!({}));
    meta["name"] = name.into();
    let spec = obj.entry("spec").or_insert_with(|| serde_json::json!({}));
    if spec.get("runtime").is_none() {
        spec["runtime"] = layout::SOURCE_RUNTIME.into();
    }
    let source = spec
        .get("source")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let existing = signers::allowed(&source).unwrap_or_default();
    let set: Vec<Member> = if existing.iter().any(|x| x.same(own)) {
        existing
    } else {
        vec![own.clone()]
    };
    let mut new_source = source.as_object().cloned().unwrap_or_default();
    new_source.remove("signer");
    new_source.remove("signerRef");
    new_source.remove("import");
    new_source.insert("version".into(), version.into());
    new_source.insert(
        "signers".into(),
        Value::Array(set.iter().map(Member::to_json).collect()),
    );
    spec["source"] = Value::Object(new_source);
    Ok(m)
}

/// After a create: the manifest in the directory says what was applied.
fn write_created_manifest(t: &Target, applied: &Value, report: &mut Report) {
    let path = t
        .manifest_path
        .clone()
        .unwrap_or_else(|| t.dir.join(layout::MANIFEST_FILE));
    if let Some(local) = &t.local {
        let mut expect = local.clone();
        if let Some(v) = expect.pointer_mut("/spec/source/version") {
            *v = applied["spec"]["source"]["version"].clone();
        }
        if &expect == applied {
            if let Some(v) = applied["spec"]["source"]["version"].as_str() {
                match writeback::write_back(&path, v) {
                    Ok(()) => report.write_back = Some(path.display().to_string()),
                    Err(e) => report.notes.push(format!("{e:#}")),
                }
            }
            return;
        }
        report.notes.push(format!(
            "{} was rewritten to the manifest that was applied (its signer set is now the set \
             form)",
            path.display()
        ));
    }
    let yaml = serde_yaml::to_string(applied).unwrap_or_default();
    match writeback::write_atomically(&path, yaml.as_bytes()) {
        Ok(()) => report.write_back = Some(path.display().to_string()),
        Err(e) => report
            .notes
            .push(format!("could not write {}: {e:#}", path.display())),
    }
}

/// FR-39: the manifest names the version that serves now.
fn write_back_if_needed(run: &Run<'_>, t: &Target, version: &str, report: &mut Report) {
    let (Some(path), Some(local)) = (&t.manifest_path, &t.local) else {
        return;
    };
    if writeback::version_of(local) == Some(version) {
        return;
    }
    match writeback::write_back(path, version) {
        Ok(()) => report.write_back = Some(path.display().to_string()),
        Err(e) => {
            let msg = format!(
                "{version} serves, but {} could not be rewritten ({e:#}); commit this line by \
                 hand: {}",
                path.display(),
                writeback::manual_line(version)
            );
            if run.opts.ci {
                report.outcome = DeployStop::WriteBackFailed.code().into();
                report.message = Some(msg);
            } else {
                report.notes.push(msg);
            }
        }
    }
}

/// `--plan`: what a deploy would do, and nothing written (FR-13).
async fn plan(
    run: &Run<'_>,
    t: &Target,
    mut report: Report,
    text: &str,
    would_be: Option<&str>,
    base: Option<&str>,
    exists: bool,
) -> Report {
    if !run.json {
        eprintln!("{text}");
    }
    report.version = would_be.map(str::to_owned);
    report.outcome = "planned".into();
    let Some(v) = would_be else {
        return report;
    };
    if !exists {
        report.message = Some("would publish, then create the function by one apply".into());
        return report;
    }
    if base == Some(v) {
        report.message = Some(format!("{v} already serves; a deploy would change nothing"));
        return report;
    }
    match t.client.promote(&t.name, v, base, true).await {
        Ok(PromoteOutcome::Promoted(answer)) => {
            if answer["dryRun"] == true {
                report.message = Some(format!(
                    "would promote {v} (generation {})",
                    answer["generation"]
                ));
            } else {
                // An operator that does not know the dry run performed it.
                report.outcome = "promoted_despite_plan".into();
                report.message = Some(format!(
                    "this operator ignored ?dry-run=true on promote and PROMOTED {v} (generation \
                     {}); it predates the promote dry run",
                    answer["generation"]
                ));
            }
        }
        Ok(PromoteOutcome::Refused { refusal, .. })
            if refusal.error == "source_version_not_found" =>
        {
            report.message = Some(format!(
                "would publish {v}, then promote it (the promote check runs once it is stored)"
            ));
        }
        Ok(PromoteOutcome::Refused { refusal, .. }) => return report.refused("promote", refusal),
        Ok(PromoteOutcome::Stale {
            based_on,
            current,
            refusal,
        }) => {
            return report.refused(
                "promote",
                Refusal {
                    extra: stale_extra(based_on, current),
                    ..refusal
                },
            );
        }
        Ok(PromoteOutcome::RouteMissing { status }) => {
            return report.stop(
                DeployStop::OperatorPredatesPromote,
                format!("the operator has no promote route (HTTP {status})"),
            );
        }
        Err(e) => return report.refused_err(e),
    }
    report
}

/// Step 7 (design §3.4): until the status reports the generation written,
/// `Loaded=True`, and the new version serving.
async fn wait(
    op: &OperatorFunctionsClient,
    name: &str,
    generation: i64,
    version: &str,
    timeout: Duration,
    quiet: bool,
) -> Result<std::result::Result<Duration, (DeployStop, String)>> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(250);
    let mut compiling_said = false;
    let mut restart_said = false;
    loop {
        match op.function_status(name).await? {
            None => {
                if !restart_said && !quiet {
                    ui::note("waiting for the operator to admit functions after a restart");
                }
                restart_said = true;
            }
            Some(s) => {
                let observed = s["observed_generation"]
                    .as_i64()
                    .or_else(|| s["observedGeneration"].as_i64())
                    .unwrap_or(0);
                if observed >= generation {
                    let loaded = s["conditions"]
                        .as_array()
                        .and_then(|c| c.iter().find(|c| c["type"] == "Loaded"));
                    match loaded.and_then(|c| c["status"].as_str()) {
                        Some("True") => {
                            let serving = op
                                .versions(name)
                                .await
                                .ok()
                                .and_then(|h| h["current"].as_str().map(str::to_owned));
                            if serving.is_none() || serving.as_deref() == Some(version) {
                                return Ok(Ok(start.elapsed()));
                            }
                        }
                        Some("False") => {
                            let c = loaded.unwrap_or(&Value::Null);
                            return Ok(Err((
                                DeployStop::LoadFailed,
                                format!(
                                    "{}: {}",
                                    c["reason"].as_str().unwrap_or("?"),
                                    c["message"].as_str().unwrap_or("")
                                ),
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_secs(2) && !compiling_said && !quiet {
            ui::note(
                "compiling — the first function after an operator deploy compiles the engine \
                 (≈ 15 s)",
            );
            compiling_said = true;
        }
        if elapsed >= timeout {
            return Ok(Err((
                DeployStop::NotLoadedInTime,
                format!(
                    "{version} is promoted but did not report loaded within {}s",
                    timeout.as_secs()
                ),
            )));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

/// Print the reports: one table for a person, or the JSON array.
pub fn print(reports: &[Report], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(reports)?);
        return Ok(());
    }
    for r in reports {
        let head = format!(
            "{} on {}: {}{}",
            r.function,
            r.operator,
            r.outcome,
            r.step.map_or_else(String::new, |s| format!(" (at {s})"))
        );
        if r.ok() {
            let detail = match (&r.version, r.elapsed_ms) {
                (Some(v), Some(ms)) => format!(" — {v}, loaded in {:.1} s", ms as f64 / 1000.0),
                (Some(v), None) => format!(" — {v}"),
                _ => String::new(),
            };
            ui::ok(format!("{head}{detail}"));
        } else {
            ui::warn(&head);
        }
        if let Some(m) = &r.message {
            ui::say(format!("  {m}"));
        }
        if let Some(refusal) = &r.refusal {
            for line in refusal::format(refusal) {
                ui::say(format!("  {line}"));
            }
        }
        if let Some(stop) = DeployStop::ALL.iter().find(|s| s.code() == r.outcome) {
            if !stop.is_success() {
                ui::say(format!("  → {}", stop.action()));
            }
        }
        if let Some(w) = &r.write_back {
            ui::note(format!("  wrote the served version into {w}"));
        }
        for n in &r.notes {
            ui::note(format!("  {n}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
