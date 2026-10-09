//! `airdress functions …` — the headless authoring loop for code-first
//! functions (SPEC-112 task 112-H.2): scaffold from a template, validate,
//! publish, read what a function served, and tail its log.
//!
//! A client of the operator's authoring API and nothing more. Every verb is
//! one or two calls to the routes the editor extension uses; the checks
//! (layout, imports, grants, stale bases, signatures) are the operator's,
//! and this module only prints what it answers. Publishing alone never
//! changes what runs; `deploy` chains check, publish and promote (SPEC-113)
//! so that one command does.
//!
//! Every verb authenticates as the owner (the hub profile's bearer) or, with
//! a machine key, as an enrolled machine whose requests are signed — then no
//! hub profile is read at all (SPEC-113 task 113-B.1).

pub mod client;
pub mod deploy;
pub mod layout;
pub mod logs;
pub mod refusal;
pub mod scaffold;
pub mod sdk;
pub mod signers;
pub mod stops;
pub mod tree;
pub mod writeback;

#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::machine::{self, MachineIdentity};
use crate::profile::storage;
use crate::ui;

use client::{LogQuery, OperatorAuth, OperatorFunctionsClient, PromoteOutcome, PublishOutcome};
use signers::OwnSigner;
use tree::Signer;

/// The operator, when no flag names it: an FQDN or an `https://` URL.
/// Required with a machine key, which reads no hub profile to find one.
pub const OPERATOR_URL_ENV: &str = "AIRDRESS_OPERATOR_URL";

/// Where a signing seed may come from besides `--signing-key`: a CI
/// secret exposed as an environment variable, so the seed is never an
/// argument (process listings show arguments).
pub const SIGNING_KEY_ENV: &str = "AIRDRESS_FUNCTION_SIGNING_KEY";

#[derive(Debug, Subcommand)]
pub enum FunctionsCommands {
    /// List the templates a new function can start from.
    Templates,
    /// Write a template's files into DIR as ordinary source, and beside them
    /// the `function.yaml` a deploy applies to create the function: the
    /// `spec.capabilities`, `spec.config` and `spec.events` the template
    /// describes. Nothing is granted or applied.
    New {
        /// Template id, as `airdress functions templates` lists it.
        template: String,
        /// A new or empty directory.
        dir: PathBuf,
        /// The id written into the scaffolded `function.json` in place of
        /// the template's placeholder. Defaults to the directory's name when
        /// it is a dotted id, else `local.<name>`;
        /// the operator refuses an id it does not accept.
        #[arg(long, value_name = "ID")]
        function_id: Option<String>,
    },
    /// Run every check a publish runs, and store nothing
    /// (`?dry-run=true`). Refusals print as `path:line:column: Reason:
    /// message`; any refusal exits non-zero.
    Validate(PublishOpts),
    /// Publish DIR as a new immutable version and print it. Apply the
    /// Function manifest with `spec.source.version` set to it to run it.
    ///
    /// A function that already serves a version needs `--based-on`: the
    /// version this tree was read from. If the function has moved since,
    /// the operator refuses and both versions are printed; nothing is
    /// retried.
    Publish(PublishOpts),
    /// Print the signed JSON publish body for DIR without sending it —
    /// for a pipeline that sends it with a machine's signed request
    /// (`airdress-operator machine request POST
    /// https://<fqdn>/v1/functions/sources --key <key> --data @body.json`).
    Pack(PublishOpts),
    /// What a function served, newest first, and the versions stored for it.
    Versions {
        /// The Function's `metadata.name`.
        name: String,
    },
    /// A published version's manifest and file index, or one file's bytes.
    Source {
        /// `sha256:…`, as `publish` or `versions` prints it.
        #[arg(value_name = "VERSION")]
        source_version: String,
        /// A file in the version, e.g. `src/main.ts`. Omit for the index.
        path: Option<String>,
    },
    /// Take a function directory to serving: check, confirm once, sign,
    /// publish, then promote (an existing function) or apply (a new one,
    /// owner only), and wait until it loads. With --ci, --all or --since,
    /// the repository's functions (`airdress.functions.yaml`, or every
    /// directory holding function.json and function.yaml).
    Deploy(deploy::DeployOpts),
    /// Run another published version of a function, and change nothing
    /// else in its manifest. Prints the answer, or the refusal with every
    /// field.
    Promote {
        /// The Function's `metadata.name`.
        name: String,
        /// The published version to run (`sha256:…`).
        #[arg(value_name = "VERSION")]
        target: String,
        /// The version you believe runs now; a function that moved since
        /// is refused, never overwritten.
        #[arg(long, value_name = "VERSION")]
        based_on: Option<String>,
        /// Run every check and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Create an Ed25519 source-signing key: a new `0600` file holding the
    /// seed (never an existing one), and print its public key and
    /// fingerprint. The seed itself is never printed.
    Keygen {
        /// Where to write the seed.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Who may sign a function's source: add or remove one member of its
    /// signer set, as its own apply by the owner.
    Signers {
        #[command(subcommand)]
        command: SignersCommand,
    },
    /// Print the JSON Schema of `airdress.functions.yaml`, for an editor.
    LayoutSchema,
    /// The Airdress Functions SDK (`@airdress/functions`) beside a function:
    /// its types and a local copy for tests, from the operator — never npm.
    Sdk {
        #[command(subcommand)]
        command: SdkCommand,
    },
    /// Read a function's durable log, oldest line last.
    Logs {
        /// The Function's `metadata.name`.
        name: String,
        /// Keep polling for new lines.
        #[arg(short, long)]
        follow: bool,
        /// Only lines at or after this: RFC 3339, or a span back from now
        /// (`15m`, `2h`, `7d`).
        #[arg(long)]
        since: Option<String>,
        /// Only the lines of one invocation.
        #[arg(long)]
        invocation: Option<String>,
        /// Most lines per read (1–1000).
        #[arg(long, default_value_t = 200)]
        limit: u32,
        /// Seconds between polls with `--follow`.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum SdkCommand {
    /// Refresh `.airdress/sdk-<version>.d.ts` (and a `tsconfig.json` when
    /// there is none) and the local package under
    /// `.airdress/node_modules/@airdress/functions/` for the version
    /// `function.json` pins. With --pin, pin that version first (`newest`:
    /// the operator's newest current one). Nothing here is ever published.
    Pull {
        /// The function directory (holding function.json).
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Pin this version in function.json first, or `newest`.
        #[arg(long, value_name = "VERSION")]
        pin: Option<String>,
    },
    /// Copy the pinned version's modules into `src/sdk/`, make every
    /// `@airdress/functions/<module>` import relative, and remove the pin:
    /// the function then publishes as ordinary source that refers to
    /// nothing.
    Vendor {
        /// The function directory (holding function.json).
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum SignersCommand {
    /// Add one signer: read the live manifest, convert a single `signer` /
    /// `signerRef` to the set, add the member, show the set, and apply it.
    Add(SignerChange),
    /// Remove one signer, the same way. Warns when the member signed the
    /// version that runs now: that version would stop being admissible.
    Remove(SignerChange),
}

#[derive(Args, Clone, Debug)]
#[command(group(clap::ArgGroup::new("member").required(true).args(["key", "machine"])))]
pub struct SignerChange {
    /// The Function's `metadata.name`.
    pub name: String,
    /// An Ed25519 public key, 64 hex characters.
    #[arg(long, value_name = "HEX")]
    pub key: Option<String>,
    /// An approved machine's id.
    #[arg(long, value_name = "UUID")]
    pub machine: Option<String>,
    /// Show the resulting set and apply it without asking.
    #[arg(short, long)]
    pub yes: bool,
    /// Show the resulting set, and have the operator check the apply
    /// without writing it.
    #[arg(long)]
    pub dry_run: bool,
    /// The committed `function.yaml` to keep in step. Defaults to the one
    /// in this repository whose `metadata.name` is the function (the map
    /// file's entries, else discovery); none found, git is left alone.
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<std::path::PathBuf>,
}

/// What `validate`, `publish` and `pack` share: the tree and how it is
/// signed.
#[derive(Debug, Args, Clone)]
pub struct PublishOpts {
    /// The tree's root: `function.json` and `src/`, and nothing else.
    pub dir: PathBuf,
    /// The Function's `metadata.name` this tree is for.
    #[arg(long)]
    pub name: String,
    /// The version this tree was read from. Required once the function
    /// serves a version.
    #[arg(long, value_name = "VERSION")]
    pub based_on: Option<String>,
    /// A file holding the Ed25519 seed (64 hex characters, as
    /// `airdress-operator functions keygen` prints it). Or set
    /// AIRDRESS_FUNCTION_SIGNING_KEY to the hex. Without either the tree
    /// is sent unsigned, which only an operator allowing unsigned source
    /// accepts.
    #[arg(long, value_name = "PATH")]
    pub signing_key: Option<PathBuf>,
    /// Name the signer as this approved machine (its registered
    /// source-signing key) instead of by the literal public key.
    #[arg(long, value_name = "MACHINE")]
    pub signer_machine: Option<String>,
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    /// `--machine-key`: a path, never the key itself.
    pub machine_key: Option<&'a Path>,
    pub json: bool,
    pub quiet: bool,
    /// The global `-v`.
    pub verbose: bool,
}

/// `https://<fqdn>` from an FQDN, or a URL as given.
pub fn operator_base(operator: &str) -> String {
    let o = operator.trim().trim_end_matches('/');
    if o.contains("://") {
        o.to_owned()
    } else {
        format!("https://{o}")
    }
}

/// How this run reaches operators: one credential, the default operator,
/// and a client per operator a map file names.
///
/// On a hub sign-in each operator takes its own token (audience
/// `https://<fqdn>/v1`), so `account` names the profile to fetch one from
/// for every further operator; `auth` is then the default operator's.
pub struct Connection {
    auth: OperatorAuth,
    account: Option<(crate::paths::Paths, String)>,
    default: std::result::Result<(String, Arc<OperatorFunctionsClient>), String>,
    others: Mutex<HashMap<String, Arc<OperatorFunctionsClient>>>,
    machine: Option<Arc<MachineIdentity>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    /// The client for `operator` (a map entry's), or the default one.
    pub async fn client_for(&self, operator: Option<&str>) -> Result<Arc<OperatorFunctionsClient>> {
        let Some(op) = operator else {
            return match &self.default {
                Ok((_, c)) => Ok(Arc::clone(c)),
                Err(why) => bail!("{why}"),
            };
        };
        let base = operator_base(op);
        if let Ok((label, c)) = &self.default {
            if operator_base(label) == base {
                return Ok(Arc::clone(c));
            }
        }
        if let Some(c) = self.others.lock().expect("operator clients").get(&base) {
            return Ok(Arc::clone(c));
        }
        let auth = match &self.account {
            Some((paths, profile)) => OperatorAuth::Bearer(
                crate::auth::tokens::access_token(
                    paths,
                    profile,
                    crate::auth::tokens::Audience::Operator(&base),
                )
                .await?,
            ),
            None => self.auth.clone(),
        };
        let c = Arc::new(OperatorFunctionsClient::with_base_url(base.clone(), auth)?);
        self.others
            .lock()
            .expect("operator clients")
            .insert(base, Arc::clone(&c));
        Ok(c)
    }

    /// The default operator's name, for a map file's entries that name none.
    pub fn default_operator(&self) -> Option<String> {
        self.default.as_ref().ok().map(|(label, _)| label.clone())
    }

    pub fn machine(&self) -> Option<&Arc<MachineIdentity>> {
        self.machine.as_ref()
    }
}

#[cfg(test)]
impl Connection {
    /// One operator at `base`, reached as `auth`.
    pub(crate) fn for_test(base: &str, auth: OperatorAuth) -> Self {
        let machine = match &auth {
            OperatorAuth::Machine(m) => Some(Arc::clone(m)),
            OperatorAuth::Bearer(_) => None,
        };
        let c = OperatorFunctionsClient::with_base_url(base.to_owned(), auth.clone()).unwrap();
        Self {
            auth,
            account: None,
            default: Ok((base.to_owned(), Arc::new(c))),
            others: Mutex::new(HashMap::new()),
            machine,
        }
    }
}

/// Build the connection: a machine key when one is configured (and then
/// no hub profile is read, and the operator must be named), else the hub
/// profile's bearer and its resolved airdress.
pub async fn connect(args: &RunArgs<'_>) -> Result<Connection> {
    let paths = args.paths;
    let flag_or_env = args.operator_url.map(str::to_owned).or_else(|| {
        std::env::var(OPERATOR_URL_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
    });
    if let Some((identity, _)) = machine::load(args.machine_key)? {
        let identity = Arc::new(identity);
        let auth = OperatorAuth::Machine(Arc::clone(&identity));
        let default = match flag_or_env {
            Some(url) => {
                let c = OperatorFunctionsClient::with_base_url(operator_base(&url), auth.clone())?;
                Ok((url, Arc::new(c)))
            }
            None => Err(format!(
                "a machine reads no hub profile, so the operator must be named: pass \
                 --operator-url or set {OPERATOR_URL_ENV} (this machine is enrolled with {})",
                identity.enrollment.operator
            )),
        };
        if let Some(w) = identity
            .enrollment
            .authorized_until
            .as_deref()
            .and_then(|u| machine::authorization_warning(u, std::time::SystemTime::now()))
        {
            ui::warn(w);
        }
        return Ok(Connection {
            auth,
            account: None,
            default,
            others: Mutex::new(HashMap::new()),
            machine: Some(identity),
        });
    }
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    let mut auth = OperatorAuth::Bearer(Default::default());
    let default = if let Some(url) = flag_or_env {
        auth = OperatorAuth::Bearer(hub.operator_bearer(&operator_base(&url)).await?);
        let c = OperatorFunctionsClient::with_base_url(operator_base(&url), auth.clone())
            .context("build operator client from --operator-url")?;
        Ok((url, Arc::new(c)))
    } else {
        match context::resolve(paths, &profile_name, args.explicit_airdress) {
            Ok(resolved) => {
                if !args.json && !args.quiet && resolved.source != Source::Flag {
                    ui::note(format!(
                        "acting on {} (source: {})",
                        resolved.name,
                        resolved.source.as_str()
                    ));
                }
                let fqdn = hub.resolve_fqdn(&resolved.name).await?;
                auth = OperatorAuth::Bearer(hub.operator_bearer(&fqdn).await?);
                let c = OperatorFunctionsClient::new(&fqdn, auth.clone())?;
                Ok((fqdn, Arc::new(c)))
            }
            Err(e) => Err(format!("{e:#}")),
        }
    };
    Ok(Connection {
        auth,
        account: Some((paths.clone(), profile_name)),
        default,
        others: Mutex::new(HashMap::new()),
        machine: None,
    })
}

pub async fn run(cmd: FunctionsCommands, args: RunArgs<'_>) -> Result<()> {
    // `pack`, `keygen` and the layout schema never talk to anything.
    match &cmd {
        FunctionsCommands::Pack(opts) => {
            let (body, _) = build_body(opts)?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            return Ok(());
        }
        FunctionsCommands::Keygen { out } => return keygen(out, args.json),
        FunctionsCommands::LayoutSchema => {
            print!("{}", layout::MAP_SCHEMA);
            return Ok(());
        }
        _ => {}
    }
    let conn = connect(&args).await?;
    if let FunctionsCommands::Deploy(opts) = &cmd {
        return run_deploy(&conn, opts, args.json, args.verbose).await;
    }
    let op = conn.client_for(None).await?;
    match cmd {
        FunctionsCommands::Templates => templates(&op, args.json).await,
        FunctionsCommands::New {
            template,
            dir,
            function_id,
        } => new(&op, &template, &dir, function_id.as_deref(), args.json).await,
        FunctionsCommands::Validate(opts) => publish(&op, &opts, true, args.json).await,
        FunctionsCommands::Publish(opts) => publish(&op, &opts, false, args.json).await,
        FunctionsCommands::Pack(_)
        | FunctionsCommands::Keygen { .. }
        | FunctionsCommands::LayoutSchema
        | FunctionsCommands::Deploy(_) => unreachable!("handled above"),
        FunctionsCommands::Promote {
            name,
            target,
            based_on,
            dry_run,
        } => promote(&op, &name, &target, based_on.as_deref(), dry_run, args.json).await,
        FunctionsCommands::Signers { command } => signers_change(&op, command, args.json).await,
        FunctionsCommands::Sdk { command } => sdk_command(&op, command, args.json).await,
        FunctionsCommands::Versions { name } => versions(&op, &name, args.json).await,
        FunctionsCommands::Source {
            source_version,
            path,
        } => source(&op, &source_version, path.as_deref(), args.json).await,
        FunctionsCommands::Logs {
            name,
            follow,
            since,
            invocation,
            limit,
            interval,
        } => {
            tail(
                &op,
                &name,
                TailOpts {
                    follow,
                    since: since.as_deref(),
                    invocation,
                    limit,
                    interval,
                    json: args.json,
                },
            )
            .await
        }
    }
}

fn read_seed(opts: &PublishOpts) -> Result<Option<[u8; 32]>> {
    read_seed_from(opts.signing_key.as_deref())
}

/// The source-signing seed: `--signing-key <file>`, else the environment.
fn read_seed_from(path: Option<&Path>) -> Result<Option<[u8; 32]>> {
    if let Some(path) = path {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read signing key {}", path.display()))?;
        return tree::parse_seed(&raw)
            .with_context(|| format!("signing key {}", path.display()))
            .map(Some);
    }
    match std::env::var(SIGNING_KEY_ENV) {
        Ok(raw) if !raw.trim().is_empty() => tree::parse_seed(&raw)
            .with_context(|| format!("signing key in {SIGNING_KEY_ENV}"))
            .map(Some),
        _ => Ok(None),
    }
}

/// The publish body, and the canonical digest its signature covers
/// (`sha256:<hex>`), which the operator's answer must name back.
fn build_body(opts: &PublishOpts) -> Result<(Value, String)> {
    // A function directory is published as `function.json` and `src/`
    // only (the manifest beside them is the owner's, never published);
    // any other tree goes as it is, for the operator to judge.
    let files = if opts.dir.join("function.json").is_file() {
        layout::select(&opts.dir)?.0
    } else {
        tree::read_tree(&opts.dir)?
    };
    let signer = match (read_seed(opts)?, &opts.signer_machine) {
        (None, Some(_)) => bail!(
            "--signer-machine names who signed; the signature still has to be made — pass \
             --signing-key or set {SIGNING_KEY_ENV}"
        ),
        (None, None) => Signer::Unsigned,
        (Some(seed), None) => Signer::Key(tree::sign(&files, &seed)),
        (Some(seed), Some(machine)) => Signer::Machine {
            machine: machine.clone(),
            signature: tree::sign(&files, &seed),
        },
    };
    let digest = format!("sha256:{}", tree::hex(&tree::canonical_digest(&files)));
    Ok((
        tree::publish_body(&opts.name, opts.based_on.as_deref(), &signer, &files),
        digest,
    ))
}

/// The operator names the digest it computed over the tree it received.
/// If that is not the digest signed here, the two disagree about the
/// bytes, and a signature from this client means nothing: stop loudly.
fn check_digest(answer: &Value, signed: &str, dry_run: bool) -> Result<()> {
    match answer["sourceDigest"].as_str() {
        Some(d) if d == signed => Ok(()),
        Some(d) => bail!(
            "the operator's source digest {d} is not the digest this client computed and \
             signed ({signed}): the two disagree about the tree's bytes{}",
            if dry_run {
                ""
            } else {
                ". The version was stored anyway; do not apply it"
            }
        ),
        None => {
            ui::warn(
                "the operator did not name the source digest (an older operator?); \
                 the signed digest could not be compared",
            );
            Ok(())
        }
    }
}

/// Who this run signs source as (design §3.6, §9.2): the seed's key, or —
/// with `--signer-machine`, or a machine key — that machine.
fn own_signer(
    seed: Option<&[u8; 32]>,
    signer_machine: Option<&str>,
    machine: Option<&Arc<MachineIdentity>>,
) -> Result<OwnSigner> {
    let Some(seed) = seed else {
        if signer_machine.is_some() {
            bail!(
                "--signer-machine names who signs; the signature still has to be made — pass \
                 --signing-key or set {SIGNING_KEY_ENV}"
            );
        }
        return Ok(OwnSigner::Unsigned);
    };
    let public_hex = tree::hex(
        &ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    );
    Ok(
        match signer_machine
            .map(str::to_owned)
            .or_else(|| machine.map(|m| m.enrollment.machine_id.to_string()))
        {
            Some(machine) => OwnSigner::Machine {
                machine,
                public_hex,
            },
            None => OwnSigner::Key { public_hex },
        },
    )
}

/// Deploy (or plan) without a terminal, returning the reports instead
/// of printing them.
///
/// The same code path `airdress fn deploy` runs: the signer is resolved
/// the way the CLI resolves it, so a deploy driven by a tool is signed
/// exactly as a deploy driven by a person. `opts.yes` must be set —
/// a confirmation needs a terminal, and this caller has none.
pub async fn deploy_reports(
    conn: &Connection,
    opts: &deploy::DeployOpts,
    verbose: bool,
) -> Result<Vec<deploy::Report>> {
    let seed = read_seed_from(opts.signing_key.as_deref())?;
    let own = own_signer(
        seed.as_ref(),
        opts.signer_machine.as_deref(),
        conn.machine(),
    )?;
    let run = deploy::Run {
        conn,
        opts,
        own,
        seed,
        json: true,
        verbose,
    };
    deploy::run(&run).await
}

async fn run_deploy(
    conn: &Connection,
    opts: &deploy::DeployOpts,
    json: bool,
    verbose: bool,
) -> Result<()> {
    let seed = read_seed_from(opts.signing_key.as_deref())?;
    let own = own_signer(
        seed.as_ref(),
        opts.signer_machine.as_deref(),
        conn.machine(),
    )?;
    let run = deploy::Run {
        conn,
        opts,
        own,
        seed,
        json,
        verbose,
    };
    let reports = deploy::run(&run).await?;
    deploy::print(&reports, json)?;
    let failed = reports.iter().filter(|r| !r.ok()).count();
    if let Some(first) = reports.iter().find(|r| !r.ok()) {
        return Err(crate::exit::Failure::new(
            deploy::exit_of(first),
            first.outcome.clone(),
            format!("{failed} of {} function(s) did not deploy", reports.len()),
        )
        .into());
    }
    Ok(())
}

/// `fn keygen --out <path>`: a new `0600` seed file; never an existing one.
fn keygen(out: &Path, json: bool) -> Result<()> {
    use std::io::Write as _;
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(out).with_context(|| {
        format!(
            "could not create {} (an existing key file is never replaced)",
            out.display()
        )
    })?;
    writeln!(file, "{}", tree::hex(key.as_bytes()))?;
    file.sync_all()?;
    let public = key.verifying_key().to_bytes();
    let public_hex = tree::hex(&public);
    let fingerprint = machine::fingerprint(&public);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": out.display().to_string(),
                "publicKey": public_hex,
                "fingerprint": fingerprint,
            }))?
        );
        return Ok(());
    }
    ui::ok(format!(
        "wrote a signing key to {} (mode 0600)",
        out.display()
    ));
    println!("pubkey={public_hex}");
    println!("fingerprint={fingerprint}");
    ui::note(format!(
        "sign with --signing-key {}; a function allows it once its signers list \
         {{ key: {public_hex} }}",
        out.display()
    ));
    Ok(())
}

/// `fn promote`: the answer, or the refusal with every field.
async fn promote(
    op: &OperatorFunctionsClient,
    name: &str,
    version: &str,
    based_on: Option<&str>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let outcome = op.promote(name, version, based_on, dry_run).await?;
    let (status, refusal) = match outcome {
        PromoteOutcome::Promoted(answer) => {
            if dry_run && answer["dryRun"] != true {
                if json {
                    println!("{}", serde_json::to_string_pretty(&answer)?);
                }
                bail!(
                    "this operator does not know the promote dry run and PROMOTED {version} \
                     (generation {}, changed: {})",
                    answer["generation"],
                    answer["changed"]
                );
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&answer)?);
                return Ok(());
            }
            let previous = answer["previous"].as_str().unwrap_or("(none)");
            let generation = &answer["generation"];
            if dry_run {
                ui::ok(format!(
                    "would promote {name}: {previous} → {version} (generation {generation})"
                ));
            } else if answer["changed"] == false {
                ui::note(format!("{name} already runs {version}; nothing changed"));
            } else {
                ui::ok(format!(
                    "promoted {name}: {previous} → {version} (generation {generation})"
                ));
            }
            return Ok(());
        }
        // FR-25a: a retry after a promote that landed is not a failure.
        PromoteOutcome::Stale { current, .. } if current.as_deref() == Some(version) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": name, "version": version, "changed": false,
                        "outcome": "unchanged",
                    }))?
                );
            } else {
                ui::note(format!(
                    "{name} already runs {version} (an earlier promote landed); nothing changed"
                ));
            }
            return Ok(());
        }
        PromoteOutcome::Stale {
            based_on: b,
            current,
            refusal,
        } => {
            let mut refusal = refusal;
            refusal
                .extra
                .insert("basedOn".into(), b.map_or(Value::Null, Value::String));
            refusal
                .extra
                .insert("current".into(), current.map_or(Value::Null, Value::String));
            (409, refusal)
        }
        PromoteOutcome::Refused { status, refusal } => (status, refusal),
        PromoteOutcome::RouteMissing { status } => {
            let stop = stops::DeployStop::OperatorPredatesPromote;
            return Err(crate::exit::Failure::new(
                stop.exit(),
                stop.code(),
                format!(
                    "{stop}: the operator has no promote route (HTTP {status}); publish, then \
                     apply the Function manifest with spec.source.version: {version}"
                ),
            )
            .into());
        }
    };
    if json {
        let mut out = serde_json::to_value(&refusal)?;
        out["refused"] = true.into();
        out["status"] = status.into();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for line in refusal::format(&refusal) {
            eprintln!("{line}");
        }
    }
    Err(crate::exit::Failure::http(
        status,
        refusal.error.clone(),
        format!("promote refused ({status} {})", refusal.error),
    )
    .with_answer(&serde_json::to_value(&refusal)?)
    .into())
}

/// `fn signers add|remove`: one member changes, shown, then its own apply.
async fn signers_change(
    op: &OperatorFunctionsClient,
    command: SignersCommand,
    json: bool,
) -> Result<()> {
    let (change, args) = match command {
        SignersCommand::Add(a) => (signers::Change::Add, a),
        SignersCommand::Remove(a) => (signers::Change::Remove, a),
    };
    let member = match (&args.key, &args.machine) {
        (Some(k), None) => signers::key_member(k)?,
        (None, Some(m)) => signers::machine_member(m)?,
        _ => bail!("name exactly one of --key and --machine"),
    };
    let live = op
        .function(&args.name)
        .await?
        .with_context(|| format!("no Function named {}", args.name))?;
    let source = live
        .pointer("/spec/source")
        .cloned()
        .with_context(|| format!("{} runs a bundle; it has no source signers", args.name))?;
    let before = signers::allowed(&source)?;
    let (new_source, after) = signers::change(&source, change, &member)?;

    // FR-62: removing the signer of what runs makes it inadmissible.
    let mut warnings = Vec::new();
    if change == signers::Change::Remove {
        if let Some(running) = source.get("version").and_then(Value::as_str) {
            if let Ok(info) = op.source(running).await {
                if signers::signed(&member, &info) {
                    warnings.push(format!(
                        "{} signed {running}, the version that runs now: once it is removed, \
                         that version is no longer admissible. It keeps serving until the \
                         operator restarts, and then does not load. Deploy a version signed \
                         by a remaining member",
                        member.describe()
                    ));
                }
            }
        }
    }

    let manifest = serde_json::json!({
        "apiVersion": live["apiVersion"],
        "kind": "Function",
        "metadata": {
            "name": args.name,
            "labels": live.pointer("/metadata/labels").cloned().unwrap_or(Value::Null),
        },
        "spec": {
            // Everything as applied; only the signer set differs.
            "source": new_source,
        },
    });
    let mut manifest = manifest;
    if let Some(spec) = live.get("spec").and_then(Value::as_object) {
        for (k, v) in spec {
            if k != "source" {
                manifest["spec"][k] = v.clone();
            }
        }
    }
    if manifest["metadata"]["labels"].is_null() {
        if let Some(m) = manifest["metadata"].as_object_mut() {
            m.remove("labels");
        }
    }

    if !json {
        ui::say(format!(
            "{} {} {} {}'s signers on {}",
            if change == signers::Change::Add {
                "Add"
            } else {
                "Remove"
            },
            member.describe(),
            if change == signers::Change::Add {
                "to"
            } else {
                "from"
            },
            args.name,
            op.host()
        ));
        ui::say("  before:");
        for m in signers::describe_set(&before) {
            ui::say(format!("    {m}"));
        }
        ui::say("  after:");
        for m in signers::describe_set(&after) {
            ui::say(format!("    {m}"));
        }
        ui::say("  Only spec.source.signers changes; this is its own apply.");
    }
    for w in &warnings {
        ui::warn(w);
    }
    if !args.dry_run {
        ui::confirm(
            "Apply this signer change?",
            ui::Confirm::new(args.yes, json),
        )?;
    }
    match op.apply(&manifest, args.dry_run).await? {
        Ok(answer) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "function": args.name,
                        "signers": after.iter().map(signers::Member::to_json).collect::<Vec<_>>(),
                        "dryRun": args.dry_run,
                        "apply": answer,
                        "warnings": warnings,
                    }))?
                );
            } else if args.dry_run {
                ui::ok(format!(
                    "the operator would accept it ({})",
                    answer["action"].as_str().unwrap_or("?")
                ));
            } else {
                ui::ok(format!("applied: generation {}", answer["generation"]));
            }
            if !args.dry_run {
                sync_committed_signers(&args, &after, json);
            }
            Ok(())
        }
        Err((status, refusal)) => {
            if !json {
                for line in refusal::format(&refusal) {
                    eprintln!("{line}");
                }
            }
            Err(crate::exit::Failure::http(
                status,
                refusal.error.clone(),
                format!("apply refused ({status} {})", refusal.error),
            )
            .with_answer(&serde_json::to_value(&refusal)?)
            .into())
        }
    }
}

/// After a signer change is applied, make the committed `function.yaml`
/// say the same, so "who may sign" read from git is not stale. Only
/// `spec.source.signers` changes; a file that cannot be rewritten that way
/// is left alone, with the lines to commit by hand.
fn sync_committed_signers(args: &SignerChange, after: &[signers::Member], json: bool) {
    let members: Vec<Value> = after.iter().map(signers::Member::to_json).collect();
    let path = match args.manifest.clone().or_else(|| find_manifest(&args.name)) {
        Some(p) => p,
        None => {
            if !json {
                ui::note(format!(
                    "no function.yaml here names {}; nothing in git to update",
                    args.name
                ));
            }
            return;
        }
    };
    let result = std::fs::read_to_string(&path)
        .map_err(anyhow::Error::from)
        .and_then(|text| writeback::rewrite_signers(&text, &members))
        .and_then(|out| writeback::write_atomically(&path, out.as_bytes()));
    match result {
        Ok(()) if !json => ui::note(format!(
            "updated spec.source.signers in {}; commit it",
            path.display()
        )),
        Ok(()) => {}
        Err(e) => ui::warn(format!(
            "{} was not updated ({e:#}); set spec.source.signers there by hand to: {}",
            path.display(),
            serde_json::to_string(&members).unwrap_or_default()
        )),
    }
}

/// The committed manifest for `name` in the repository around the current
/// directory: the map file's entries, else every discovered function.
fn find_manifest(name: &str) -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let root = layout::repo_root(&cwd);
    let entries = match std::fs::read_to_string(root.join(layout::MAP_FILE)) {
        Ok(text) => layout::parse_map(&root, &text, None).ok()?,
        Err(_) => layout::discover(&root).ok()?.0,
    };
    let mut found = entries
        .into_iter()
        .map(|e| root.join(&e.manifest))
        .filter(|p| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|t| serde_yaml::from_str::<Value>(&t).ok())
                .and_then(|v| {
                    v.pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .is_some_and(|n| n == name)
        });
    let first = found.next()?;
    // Two manifests for one name (two operators) are ambiguous: pass --manifest.
    found.next().is_none().then_some(first)
}

async fn templates(op: &OperatorFunctionsClient, json: bool) -> Result<()> {
    let list = op.templates().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }
    let items = list["templates"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        ui::note("the operator serves no templates");
        return Ok(());
    }
    let width = items
        .iter()
        .filter_map(|t| t["id"].as_str().map(str::len))
        .max()
        .unwrap_or(2);
    for t in &items {
        let id = t["id"].as_str().unwrap_or("?");
        let title = t["title"].as_str().unwrap_or("");
        let needs: Vec<&str> = t["requires"]
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let needs = if needs.is_empty() {
            String::new()
        } else {
            format!("  [needs: {}]", needs.join(", "))
        };
        println!("{id:<width$}  {title}{needs}");
    }
    Ok(())
}

async fn new(
    op: &OperatorFunctionsClient,
    id: &str,
    dir: &Path,
    function_id: Option<&str>,
    json: bool,
) -> Result<()> {
    let function_id = match function_id {
        Some(f) => f.to_owned(),
        None => default_function_id(dir)?,
    };
    let t = op.template(id, &function_id).await?;
    let files = t["files"]
        .as_object()
        .with_context(|| format!("template {id} carries no files"))?;
    let written = scaffold::write_files(dir, files)?;
    // The create manifest, beside the tree: what Deploy applies (and shows
    // in full) when it creates the function. Without it a template's
    // `spec.events` would be lost, since `function.json` does not carry it.
    let manifest =
        scaffold::manifest_yaml(&t, deploy::FUNCTION_API_VERSION, layout::SOURCE_RUNTIME);
    let manifest_path = dir.join(layout::MANIFEST_FILE);
    std::fs::write(&manifest_path, &manifest)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    // The library beside the tree: the pin, its types, a local copy for
    // tests, and an example test — none of it under src/, none published.
    let grants: Vec<String> = t["requires"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let sdk_lines = match scaffold_sdk(op, dir, id, &grants).await {
        Ok(lines) => lines,
        Err(e) => vec![format!(
            "the Functions SDK was not set up ({e:#}); run `airdress fn sdk pull {} --pin newest` \
             once the operator serves it",
            dir.display()
        )],
    };
    if json {
        let out = serde_json::json!({
            "template": t["id"],
            "functionId": function_id,
            "dir": dir.display().to_string(),
            "files": written,
            "manifest": layout::MANIFEST_FILE,
            "entry": t["entry"],
            "requires": t["requires"],
            "config": scaffold::config_json(&t["config"]),
            "events": t.get("events").cloned().unwrap_or(Value::Null),
            "sdk": sdk::pin(dir).ok().flatten(),
            "sdkNotes": sdk_lines,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    ui::ok(format!(
        "wrote {} file(s) from template {id} into {} (function id {function_id})",
        written.len(),
        dir.display()
    ));
    for f in &written {
        ui::say(format!("  {f}"));
    }
    for l in &sdk_lines {
        ui::note(l);
    }
    ui::say("");
    ui::say(format!(
        "and {}, the Function manifest `airdress fn deploy` applies to create it. \
         Nothing is granted until you confirm that deploy; edit the grant first:",
        layout::MANIFEST_FILE
    ));
    // The manifest is the command's payload: stdout, so it can be piped.
    print!("{manifest}");
    Ok(())
}

/// Pin the newest current library version when the scaffold pins none,
/// then pull its types and local copy, and write an example test.
async fn scaffold_sdk(
    op: &OperatorFunctionsClient,
    dir: &Path,
    template: &str,
    grants: &[String],
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let version = if let Some(v) = sdk::pin(dir)? {
        v
    } else {
        let cat = op.sdk_catalogue().await?;
        let newest = cat["newest"]
            .as_str()
            .context("the operator carries no current Functions SDK version")?
            .to_owned();
        let fj = dir.join("function.json");
        let text = crate::fsx::read_to_string(&fj)?;
        crate::fsx::write(&fj, sdk::set_pin_text(&text, &newest)?)?;
        lines.push(format!("pinned \"sdk\": \"{newest}\" in function.json"));
        newest
    };
    let release = sdk::Release::from_answer(&op.sdk_release(&version).await?)?;
    for w in sdk::write_types(dir, &release)? {
        lines.push(format!("wrote {w} (types; never published)"));
    }
    lines.extend(sdk::write_package(dir, &release)?);
    if let Some(t) = sdk::write_example_test(dir, template, grants)? {
        lines.push(format!(
            "wrote {t}: run it with `node {t}` (or bun, or deno --node-modules-dir=manual)"
        ));
    }
    Ok(lines)
}

/// `fn sdk pull` and `fn sdk vendor`.
async fn sdk_command(op: &OperatorFunctionsClient, command: SdkCommand, json: bool) -> Result<()> {
    match command {
        SdkCommand::Pull { dir, pin } => {
            let mut lines = Vec::new();
            if let Some(p) = pin {
                let version = if p == "newest" {
                    op.sdk_catalogue().await?["newest"]
                        .as_str()
                        .context("the operator carries no current Functions SDK version")?
                        .to_owned()
                } else {
                    p
                };
                let fj = dir.join("function.json");
                let text = std::fs::read_to_string(&fj)
                    .with_context(|| format!("read {}", fj.display()))?;
                crate::fsx::write(&fj, sdk::set_pin_text(&text, &version)?)?;
                lines.push(format!("pinned \"sdk\": \"{version}\" in function.json"));
            }
            let Some(version) = sdk::pin(&dir)? else {
                bail!(
                    "{} pins no Functions SDK version; pass --pin newest (or a version from \
                     `GET /v1/functions/sdk`)",
                    dir.join("function.json").display()
                );
            };
            let release = sdk::Release::from_answer(&op.sdk_release(&version).await?)?;
            for w in sdk::write_types(&dir, &release)? {
                lines.push(format!("wrote {w}"));
            }
            lines.extend(sdk::write_package(&dir, &release)?);
            lines.push(format!(
                "wrote {}/node_modules/@airdress/functions/ ({version}, {} modules)",
                sdk::LOCAL_DIR,
                release.modules.len()
            ));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": version, "notes": lines,
                    }))?
                );
            } else {
                for l in &lines {
                    ui::ok(l);
                }
            }
            Ok(())
        }
        SdkCommand::Vendor { dir } => {
            let Some(version) = sdk::pin(&dir)? else {
                bail!(
                    "{} pins no Functions SDK version: nothing to vendor",
                    dir.display()
                );
            };
            let release = sdk::Release::from_answer(&op.sdk_release(&version).await?)?;
            let v = sdk::vendor(&dir, &release)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": version, "modules": v.modules, "rewritten": v.rewritten,
                    }))?
                );
                return Ok(());
            }
            ui::ok(format!(
                "vendored sdk {version}: {} module(s) into src/{}/, {} file(s) rewritten, the \
                 pin removed",
                v.modules.len(),
                sdk::VENDOR_DIR,
                v.rewritten.len()
            ));
            for r in &v.rewritten {
                ui::say(format!("  {r}"));
            }
            ui::note(
                "the function now refers to nothing: a library fix no longer reaches it, and its \
                 modules count against the tree's file limits",
            );
            Ok(())
        }
    }
}

/// `--function-id` when absent: the target directory's own name when it is
/// already a dotted id, else `local.<slug>` — the operator's schema needs
/// at least two dot-separated labels (`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`),
/// and a bare directory name never has them. The editor extension derives
/// the same id.
fn default_function_id(dir: &Path) -> Result<String> {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let name = absolute
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .with_context(|| {
            format!(
                "{} has no usable name for a function id; pass --function-id",
                dir.display()
            )
        })?;
    function_id_from_name(name)
        .with_context(|| format!("{name:?} cannot become a function id; pass --function-id"))
}

/// The id a name becomes — the same rule as the editor extension's
/// `defaultFunctionId`: a name that already is a dotted id (at most 255
/// characters) is kept, lowercased; any other becomes `local.<slug>`, the
/// slug lowercased with every run of characters outside `[a-z0-9-]` one
/// dash, dashes collapsed and trimmed, `function` when nothing is left and
/// `fn-` in front when it does not start with a letter.
fn function_id_from_name(name: &str) -> Option<String> {
    let lower = name.trim().to_lowercase();
    if is_function_id(&lower) && lower.len() <= 255 {
        return Some(lower);
    }
    let mut slug = String::new();
    for c in lower.chars() {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            c
        } else {
            '-'
        };
        if c == '-' && slug.ends_with('-') {
            continue;
        }
        slug.push(c);
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() {
        "function".to_owned()
    } else if !slug.starts_with(|c: char| c.is_ascii_lowercase()) {
        format!("fn-{slug}")
    } else {
        slug.to_owned()
    };
    let mut id = format!("local.{slug}");
    id.truncate(255);
    Some(id.trim_end_matches('-').to_owned())
}

/// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`, the operator's schema pattern.
fn is_function_id(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            l.starts_with(|c: char| c.is_ascii_lowercase())
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

async fn publish(
    op: &OperatorFunctionsClient,
    opts: &PublishOpts,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let (body, digest) = build_body(opts)?;
    // A dry run with no signature is checked, not verified, and the
    // operator says so in its warnings; a publish needs the signature.
    if body.get("signature").is_none() && !dry_run && !json {
        ui::warn(
            "sending the tree unsigned; only an operator that allows unsigned source accepts it",
        );
    }
    match op.publish(&body, dry_run).await? {
        PublishOutcome::Published { created, body } => {
            check_digest(&body, &digest, dry_run)?;
            print_published(&body, created, dry_run, json)?;
            Ok(())
        }
        PublishOutcome::Stale(stale) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "refused": true, "status": 409, "error": "source_base_stale",
                        "basedOn": stale.based_on, "current": stale.current,
                        "currentPublishedAt": stale.current_published_at,
                        "currentPublishedBy": stale.current_published_by,
                    }))?
                );
            } else {
                for line in refusal::format_stale(&stale) {
                    eprintln!("{line}");
                }
            }
            Err(crate::exit::Failure::http(
                409,
                "source_base_stale",
                format!(
                    "stale base: this tree was read from {}, the function now serves {}",
                    stale.based_on.as_deref().unwrap_or("(none)"),
                    stale.current
                ),
            )
            .with_hint(format!(
                "re-base the tree and publish with --based-on {}",
                stale.current
            ))
            .with_answer(&serde_json::to_value(&stale)?)
            .into())
        }
        PublishOutcome::Refused { status, refusal } => {
            if json {
                let mut out = serde_json::to_value(&refusal)?;
                out["refused"] = true.into();
                out["status"] = status.into();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                for line in refusal::format(&refusal) {
                    eprintln!("{line}");
                }
            }
            Err(crate::exit::Failure::http(
                status,
                refusal.error.clone(),
                format!(
                    "{} refused ({status} {})",
                    if dry_run { "validation" } else { "publish" },
                    refusal.error
                ),
            )
            .with_answer(&serde_json::to_value(&refusal)?)
            .into())
        }
    }
}

fn print_published(body: &Value, created: bool, dry_run: bool, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(body)?);
        return Ok(());
    }
    let version = body["version"].as_str().unwrap_or("?");
    let files = body["files"].as_array().map_or(0, Vec::len);
    let entry = body["entry"].as_str().unwrap_or("?");
    if dry_run {
        ui::ok(format!(
            "valid: {files} file(s), entry {entry}; would publish {version}"
        ));
    } else if created {
        ui::ok(format!(
            "published {version} ({files} file(s), entry {entry})"
        ));
    } else {
        ui::note(format!(
            "unchanged: the identical tree is already stored as {version}"
        ));
    }
    for u in body["unreachable"].as_array().into_iter().flatten() {
        ui::note(format!(
            "not reached from the entry: {}",
            u.as_str().unwrap_or("?")
        ));
    }
    if let Some(v) = body["sdk"]["version"].as_str() {
        ui::note(format!(
            "sdk {v} ({})",
            body["sdk"]["modules"]
                .as_array()
                .map(|m| m
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default()
        ));
    }
    for n in refusal::notes(body) {
        ui::note(n);
    }
    for w in body["warnings"].as_array().into_iter().flatten() {
        ui::warn(w.as_str().unwrap_or("?"));
    }
    if !dry_run {
        ui::note(format!(
            "to run it: apply the Function manifest with spec.source.version: {version}"
        ));
        // The version alone on stdout, for `VERSION=$(airdress functions publish …)`.
        println!("{version}");
    }
    Ok(())
}

async fn versions(op: &OperatorFunctionsClient, name: &str, json: bool) -> Result<()> {
    let h = op.versions(name).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&h)?);
        return Ok(());
    }
    match h["current"].as_str() {
        Some(c) => println!("current: {c}"),
        None => println!("current: (serves no source version)"),
    }
    let deployments = h["deployments"].as_array().cloned().unwrap_or_default();
    if !deployments.is_empty() {
        println!("\nserved (newest first):");
        for d in &deployments {
            println!(
                "  {} {} generation {} by {}",
                d["at"].as_str().unwrap_or("?"),
                d["version"].as_str().unwrap_or("?"),
                d["generation"],
                d["actor"].as_str().unwrap_or("?"),
            );
        }
    }
    let stored = h["versions"].as_array().cloned().unwrap_or_default();
    if !stored.is_empty() {
        println!("\nstored:");
        for v in &stored {
            println!(
                "  {}{} {} by {} ({}, {} file(s), {} bytes){}{}",
                if v["current"].as_bool() == Some(true) {
                    "* "
                } else {
                    "  "
                },
                v["version"].as_str().unwrap_or("?"),
                v["publishedAt"].as_str().unwrap_or("?"),
                v["publishedBy"].as_str().unwrap_or("?"),
                v["origin"].as_str().unwrap_or("?"),
                v["files"],
                v["bytes"],
                signed_by(&v["signer"]),
                // Operators before v0.1.90 send no such field.
                if v["quarantined"].as_bool() == Some(true) {
                    " QUARANTINED: its key was revoked as compromised; it cannot run"
                } else {
                    ""
                },
            );
        }
    }
    Ok(())
}

/// ", signed by key 95ad…3d04 (machine …)" from a version's `signer`.
fn signed_by(signer: &Value) -> String {
    let key = signer["key"].as_str().map(|k| {
        if k.len() > 12 {
            format!("key {}…{}", &k[..4], &k[k.len() - 4..])
        } else {
            format!("key {k}")
        }
    });
    match (key, signer["machine"].as_str()) {
        (Some(k), Some(m)) => format!(", signed by {k} (machine {m})"),
        (Some(k), None) => format!(", signed by {k}"),
        (None, Some(m)) => format!(", signed by machine {m}"),
        (None, None) => String::new(),
    }
}

async fn source(
    op: &OperatorFunctionsClient,
    version: &str,
    path: Option<&str>,
    json: bool,
) -> Result<()> {
    if let Some(path) = path {
        let bytes = op.source_file(version, path).await?;
        use std::io::Write as _;
        std::io::stdout().write_all(&bytes)?;
        return Ok(());
    }
    let v = op.source(version).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("version:   {}", v["version"].as_str().unwrap_or("?"));
    println!("function:  {}", v["name"].as_str().unwrap_or("?"));
    println!(
        "published: {} by {} ({})",
        v["publishedAt"].as_str().unwrap_or("?"),
        v["publishedBy"].as_str().unwrap_or("?"),
        v["origin"].as_str().unwrap_or("?")
    );
    match (v["signer"].as_str(), v["signerRef"].as_str()) {
        (Some(k), Some(m)) => println!("signer:    {k} (machine {m})"),
        (Some(k), None) => println!("signer:    {k}"),
        _ => println!("signer:    (unsigned)"),
    }
    println!("files:");
    for f in v["files"].as_array().into_iter().flatten() {
        println!(
            "  {} ({} bytes, sha256 {})",
            f["path"].as_str().unwrap_or("?"),
            f["bytes"],
            f["sha256"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

#[derive(Debug)]
struct TailOpts<'a> {
    follow: bool,
    since: Option<&'a str>,
    invocation: Option<String>,
    limit: u32,
    interval: u64,
    json: bool,
}

async fn tail(op: &OperatorFunctionsClient, name: &str, o: TailOpts<'_>) -> Result<()> {
    let since = o
        .since
        .map(|s| logs::parse_since(s, chrono::Utc::now()))
        .transpose()?;
    let limit = o.limit.clamp(1, 1000);
    let mut cursor = logs::Cursor::default();
    loop {
        let query = LogQuery {
            since: since.map(logs::rfc3339),
            invocation: o.invocation.clone(),
            after: cursor.after,
            limit,
        };
        let page = op.logs(name, &query).await?;
        let lines = page["lines"].as_array().cloned().unwrap_or_default();
        let full = lines.len() >= limit as usize;
        let reading_after = cursor.after.is_some();
        for row in cursor.take(&lines) {
            if o.json {
                println!("{}", serde_json::to_string(&row)?);
            } else {
                println!("{}", logs::format_line(&row));
            }
        }
        if !o.follow {
            return Ok(());
        }
        // A full page read after a cursor means more are waiting: read on
        // at once rather than sleeping past them.
        if !(reading_after && full) {
            tokio::time::sleep(std::time::Duration::from_secs(o.interval.max(1))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_the_operator_names_must_be_the_one_signed() {
        let signed = "sha256:aa";
        assert!(check_digest(
            &serde_json::json!({ "sourceDigest": "sha256:aa" }),
            signed,
            false
        )
        .is_ok());
        let err = check_digest(
            &serde_json::json!({ "sourceDigest": "sha256:bb" }),
            signed,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("sha256:bb") && err.contains("sha256:aa"),
            "{err}"
        );
        assert!(err.contains("do not apply it"), "{err}");
        let dry = check_digest(
            &serde_json::json!({ "sourceDigest": "sha256:bb" }),
            signed,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(!dry.contains("stored"), "{dry}");
    }

    #[test]
    fn the_body_digest_is_the_signed_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("function.json"),
            r#"{"entry":"src/main.ts"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/main.ts"),
            "export default () => new Response('a');",
        )
        .unwrap();
        let keys = tempfile::tempdir().unwrap();
        let seed = keys.path().join("seed");
        std::fs::write(&seed, "01".repeat(32)).unwrap();
        let opts = PublishOpts {
            dir: dir.path().to_path_buf(),
            name: "hello".into(),
            based_on: None,
            signing_key: Some(seed),
            signer_machine: None,
        };
        let (body, digest) = build_body(&opts).unwrap();
        // The operator fixture's "two files" digest; see tree.rs.
        assert_eq!(
            digest,
            "sha256:d8dfeaa493ac09e5a0db5c347830428fb3887a2a2401fd5d0b31a49a718af8af"
        );
        assert_eq!(body["signature"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn the_function_id_defaults_to_the_directory_name_made_dotted() {
        assert_eq!(
            default_function_id(Path::new("/tmp/work/co.example.greeter")).unwrap(),
            "co.example.greeter"
        );
        assert_eq!(
            default_function_id(Path::new("greeter/")).unwrap(),
            "local.greeter"
        );
    }
}

#[cfg(test)]
mod default_id_tests {
    use super::{function_id_from_name, is_function_id};

    /// Shared with airdress-vscode's `defaultFunctionId` tests: the same
    /// input must give the same id in both clients.
    const VECTORS: &[(&str, &str)] = &[
        ("e2e-hello", "local.e2e-hello"),
        ("My Hook_2", "local.my-hook-2"),
        ("co.airdress.relay", "co.airdress.relay"),
        ("Relay.Webhook", "relay.webhook"),
        ("9lives", "local.fn-9lives"),
        ("___", "local.function"),
        ("a.9-b", "local.a-9-b"),
        ("tail-", "local.tail"),
        // The extension's own cases.
        ("relay-to-op2", "local.relay-to-op2"),
        (" a b ", "local.a-b"),
        ("Co.Example.Hello", "co.example.hello"),
        ("2fa_check!", "local.fn-2fa-check"),
        ("---", "local.function"),
        ("my.fn_x", "local.my-fn-x"),
    ];

    #[test]
    fn the_same_ids_as_the_extension() {
        for (name, want) in VECTORS {
            assert_eq!(
                function_id_from_name(name).as_deref(),
                Some(*want),
                "{name}"
            );
            assert!(is_function_id(want), "{want}");
        }
    }
}

#[cfg(test)]
mod signed_by_tests {
    use super::signed_by;
    use serde_json::json;

    #[test]
    fn a_version_says_who_signed_it() {
        let k = "95adfd4d26fabd2eb52b28293ef908cebace9daa05095fb56b7ad3d5f5e93d04";
        assert_eq!(signed_by(&json!({"key": k})), ", signed by key 95ad…3d04");
        assert_eq!(
            signed_by(&json!({"key": k, "machine": "m-1"})),
            ", signed by key 95ad…3d04 (machine m-1)"
        );
        assert_eq!(signed_by(&json!(null)), "");
    }
}
