//! `airdress tls renew` — force-renew the TLS certificate on the
//! currently selected airdress operator.
//!
//! Resolves the active airdress via SPEC-043 precedence, looks up the
//! operator FQDN via the hub, then POSTs to `POST /admin/tls/renew`.
//!
//! The `--rotate` flag revokes the existing cert before reissuing. Use
//! it when a plain renew returns the same cert (GTS deduplication:
//! Google Trust Services may return an identical cert with the same
//! "Not Before" for the same domain identifiers within a short window).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::http;
use crate::profile::storage;
use crate::ui;

#[derive(Debug)]
pub struct RenewArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub rotate: bool,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

#[derive(Debug, Serialize)]
struct RenewRequest<'a> {
    fqdn: &'a str,
    rotate: bool,
}

#[derive(Debug, Deserialize)]
struct RenewResponse {
    ok: bool,
    error: Option<String>,
}

pub async fn run(args: RenewArgs<'_>) -> Result<()> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;

    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }

    let hub = HubClient::from_profile(paths, &profile_name).await?;
    let (base_url, fqdn) = if let Some(url) = args.operator_url {
        let fqdn = hub.resolve_fqdn(&resolved.name).await?;
        (url.trim_end_matches('/').to_owned(), fqdn)
    } else {
        let fqdn = hub.resolve_fqdn(&resolved.name).await?;
        let base = format!("https://{}", fqdn.trim_matches('/'));
        (base, fqdn)
    };

    let url = format!("{base_url}/admin/tls/renew");
    let client = http::client_with(http::Timeouts::at_least(http::TLS_RENEW))
        .build()
        .context("build HTTP client")?;

    let bearer = hub.operator_bearer(&fqdn).await?;
    let resp = client
        .post(&url)
        .bearer_auth(bearer.expose())
        .json(&RenewRequest {
            fqdn: &fqdn,
            rotate: args.rotate,
        })
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "POST", e))?;

    let status = resp.status();
    let body: RenewResponse = resp
        .json()
        .await
        .context("parse /admin/tls/renew response")?;

    if args.json {
        let out = serde_json::json!({
            "ok": body.ok,
            "fqdn": fqdn,
            "rotate": args.rotate,
            "error": body.error,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if body.ok {
        ui::ok(format!(
            "TLS certificate renewed for {fqdn}{}",
            if args.rotate { " (rotated)" } else { "" }
        ));
        Ok(())
    } else {
        let msg = body.error.unwrap_or_else(|| format!("HTTP {status}"));
        anyhow::bail!("cert renewal failed: {msg}");
    }
}
