//! `airdress airdress probe <name>` — ask the hub to probe your
//! airdress's operator and report the network path it took.
//!
//! Named `probe` (not `whoami`) deliberately: OAuth/OIDC tooling
//! reserves `whoami` for "given my token, return the caller's
//! identity claims" (kubectl, aws sts, gcloud, gh — all parameter-less
//! caller-identity queries). This command takes a resource argument
//! and reports on a specified airdress, so it's a probe, not a whoami.
//! A future `airdress a whoami` (no arg) can answer the OAuth meaning
//! by calling the hub's /userinfo and printing caller identity.
//!
//! The hub does the DNS resolution and the HTTP call; the CLI only
//! authenticates against the hub. This way:
//!
//! - the user's network reach (IPv6 vs. IPv4) doesn't gate the test
//!   — only the hub's reach matters, and the hub runs dual-stack on
//!   Cloud Run.
//! - ownership and rate limiting are enforced once at the hub edge,
//!   not at every operator.
//! - operators don't need to validate ZITADEL tokens themselves;
//!   `/v1/ping` on the operator is unauthenticated and only the hub
//!   (or anyone the operator's owner trusts) reaches it.

use anyhow::{bail, Context, Result};

use crate::context::{self, Source};
use crate::http;
use crate::profile::storage;
use crate::ui;

use super::client::{match_airdress, HubClient, MatchError};
use crate::log_err::LogErr as _;

#[derive(Debug)]
pub struct ProbeArgs<'a> {
    /// Explicit positional argument (legacy). When `None`, the
    /// resolver picks the airdress per SPEC-043 precedence using
    /// `explicit_airdress` (the `--airdress` / `-A` global flag) and
    /// the AIRDRESS_NAME env / marker / profile pin tiers.
    pub name_or_fqdn: Option<&'a str>,
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    /// Suppress the "→ acting on …" status line (text mode only).
    pub quiet: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProbeResponse {
    fqdn: String,
    ipv4_address: String,
    #[serde(default)]
    ipv6_address: Option<String>,
    transport: String,
    /// Hub-supplied flag. Only meaningful when `transport = "ipv4"`:
    /// `true` when the hub reached the airdress through the SPEC-026
    /// relay VIP set, `false` when the operator publishes its own
    /// direct IPv4. Absent on IPv6 / unreachable, and absent from
    /// pre-`via_relay` hub responses — for backwards-compat the CLI
    /// defaults to "relay" labelling when `transport=ipv4` and the
    /// field is missing (matches the prior single-label behaviour).
    #[serde(default)]
    via_relay: Option<bool>,
    #[serde(default)]
    operator: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn run(args: ProbeArgs<'_>) -> Result<()> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;

    // Two-headed input resolution (SPEC-043):
    //   - positional `name_or_fqdn` (legacy): always treated as Source::Flag-like.
    //     The argument is on the command line, so it's explicit.
    //   - omitted: resolve via the context module's five-tier precedence.
    // The global `--airdress` / `-A` flag is fed in via `explicit_airdress`
    // and takes precedence inside the resolver.
    let (target_input, source, marker_path) = match args.name_or_fqdn {
        Some(n) => (n.to_string(), Source::Flag, None),
        None => {
            let r = context::resolve(paths, &profile_name, args.explicit_airdress)?;
            let marker = r.marker_path.as_deref().map(context::display_marker_path);
            (r.name, r.source, marker)
        }
    };

    let target = match resolve_target(&hub, &target_input).await {
        Ok(t) => t,
        Err(e) if source == Source::ProfileDefault => {
            // SPEC-043: resolve-time recovery from a stale pin. The
            // hub says the pinned airdress is not in our list, so
            // clear the pin and surface a clear error.
            storage::clear_active_airdress(paths, &profile_name)
                .log_warn("clearing the stale airdress pin");
            return Err(e.context(format!(
                "this airdress is no longer accessible on profile '{profile_name}' — \
                 the stale pin has been cleared; run `airdress airdress list` and \
                 `airdress a use <name>` to re-pin"
            )));
        }
        Err(e) => return Err(e),
    };

    // Status line — only when ambient state was used, never on
    // --output json (the resolved value lives in the response
    // envelope), never on --quiet.
    if !args.json && !args.quiet && source != Source::Flag {
        let label = match marker_path {
            Some(p) => format!(
                "acting on {target_input} (source: {} [{p}])",
                source.as_str()
            ),
            None => format!("acting on {target_input} (source: {})", source.as_str()),
        };
        ui::note(label);
    }

    let url = format!(
        "{}/api/airdresses/{}/probe",
        hub.endpoint().trim_end_matches('/'),
        target.id
    );

    let client = http::client()?;
    let resp = client
        .get(&url)
        .bearer_auth(hub.bearer().expose())
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "GET", e))?;
    let resp = http::handle_status(resp, "probe airdress").await?;
    let body: ProbeResponse = resp.json().await.context("parse probe response")?;

    if args.json {
        // SPEC-043 — wrap in an envelope with the resolved airdress
        // so scripted callers see exactly what was acted on.
        let envelope = serde_json::json!({
            "airdress": target_input,
            "source": source.as_str(),
            "probe": body,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    println!("FQDN:      {}", body.fqdn);
    println!(
        "Addresses: A={} AAAA={}",
        body.ipv4_address,
        body.ipv6_address.as_deref().unwrap_or("—")
    );
    let path = match (body.transport.as_str(), body.via_relay) {
        ("ipv6", _) => "direct (IPv6)",
        ("ipv4", Some(false)) => "direct (IPv4)",
        // `Some(true)` AND missing-field both fall here. Pre-`via_relay`
        // hubs always sent transport="ipv4" only when they hit the
        // default-relay IPv4, so the "relay" label remained accurate
        // in practice.
        ("ipv4", _) => "relay (IPv4)",
        _ => "unreachable",
    };
    println!("Transport: {path}");
    if let Some(err) = &body.error {
        println!("Error:     {err}");
    }
    if let Some(op) = &body.operator {
        println!();
        println!("{}", serde_json::to_string_pretty(op)?);
    }
    Ok(())
}

/// Resolved airdress identity. The probe URL is keyed by `id`, so we
/// always need to look up by id even when the user passes a bare name.
#[derive(Debug)]
struct ResolvedTarget {
    id: String,
}

async fn resolve_target(hub: &HubClient, input: &str) -> Result<ResolvedTarget> {
    let items = hub.list().await?;
    match match_airdress(&items, input) {
        Ok(a) => Ok(ResolvedTarget { id: a.id.clone() }),
        Err(MatchError::NotFound) => {
            bail!("no airdress matching '{input}' on this profile — run `airdress a list`")
        }
        Err(MatchError::Ambiguous(n)) => {
            bail!("ambiguous: {n} airdresses match '{input}' — use the id")
        }
    }
}
