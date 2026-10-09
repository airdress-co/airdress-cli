//! SPEC-044 — `airdress device pair` orchestrator.
//!
//! Resolves the current airdress (SPEC-043), looks up its operator
//! FQDN via the hub, mints a pairing code on the operator, renders a
//! QR + deeplink, and waits for the phone to consume it.

use anyhow::{bail, Result};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use super::client::OperatorEnrollClient;
use super::qr;
use super::watcher::{self, WaitOutcome};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct PairArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub no_qr: bool,
    pub no_link: bool,
    pub label: Option<&'a str>,
    /// Dev override: when Some, talk to this URL instead of resolving
    /// `https://<airdress-fqdn>` via the hub. Useful for hitting a
    /// laptop-local operator before DNS is flipped.
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: PairArgs<'_>) -> Result<()> {
    let paths = args.paths;
    if args.no_qr && args.no_link {
        bail!("--no-qr and --no-link cannot both be set — you need at least one of the two to scan or click");
    }

    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;

    // SPEC-043 ambient-context status line.
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }

    // Resolve operator URL. If --operator-url is set, use it verbatim
    // (dev override). Otherwise resolve the airdress's FQDN via the hub
    // and build `https://<fqdn>`.
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    let op = if let Some(url) = args.operator_url {
        OperatorEnrollClient::with_base_url(url.to_owned(), hub.operator_bearer(url).await?)?
    } else {
        let fqdn = hub.resolve_fqdn(&resolved.name).await?;
        OperatorEnrollClient::new(&fqdn, hub.operator_bearer(&fqdn).await?)?
    };

    let mint = op.mint_pairing(args.label).await?;

    // Render the QR + deeplink in text mode.
    if !args.json {
        let minutes = (mint.expires_at - chrono::Utc::now()).num_seconds().max(0) / 60;
        ui::say(format!(
            "Scan this QR with airdress-chat (expires in {minutes}:00):"
        ));
        println!();
        if !args.no_qr {
            qr::render_to_stdout(&mint.pair_uri)?;
        }
        if !args.no_link {
            println!();
            println!("Or open this link on the phone:");
            println!("  {}", mint.pair_uri);
        }
        println!();
        ui::say("Waiting for pairing...");
    }

    // Ctrl-C cancels the wait; the watcher is raced against it here, so
    // no task outlives this function (R-ASY-1).
    let cancel = CancellationToken::new();
    let wait =
        watcher::wait_for_completion(&op, mint.pairing_code_id, mint.expires_at, cancel.clone());
    tokio::pin!(wait);
    let outcome = tokio::select! {
        // cancel-safe: the wait is pinned outside the race and driven to
        // its end below; it sees the cancel and answers `Cancelled`.
        r = &mut wait => r?,
        // cancel-safe: `ctrl_c`, made once.
        signal = tokio::signal::ctrl_c() => {
            // A handler that could not be installed must not read as a
            // Ctrl-C: say so and keep waiting.
            match signal {
                Ok(()) => cancel.cancel(),
                Err(e) => tracing::warn!(error = %e, "could not listen for Ctrl-C"),
            }
            wait.await?
        }
    };

    match outcome {
        WaitOutcome::Paired(device) => {
            if args.json {
                let envelope = serde_json::json!({
                    "airdress": resolved.name,
                    "source": resolved.source.as_str(),
                    "pair_uri": mint.pair_uri,
                    "expires_at": mint.expires_at,
                    "enrollment": {
                        "id": device.id,
                        "device_label": device.device_label,
                        "transport_profile": device.transport_profile,
                        "created_at": device.created_at,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                ui::ok(format!(
                    "paired as {:?} (id: {})",
                    device.device_label, device.id
                ));
            }
            Ok(())
        }
        WaitOutcome::Expired => {
            bail!("pairing timed out — the 5-minute code expired before scanning. Run `airdress device pair` again to mint a new one.");
        }
        WaitOutcome::Cancelled => {
            ui::warn("pairing cancelled — the code stays valid until its 5-minute TTL expires");
            Ok(())
        }
    }
}
