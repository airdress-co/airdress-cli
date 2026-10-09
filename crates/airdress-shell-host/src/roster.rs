//! First-device trust (design §6.3): the operator's list of this host's
//! person's devices, taken as pending devices the person at the machine
//! can confirm by fingerprint.
//!
//! `GET /v1/shells/host/devices` is machine-signed and scoped by the
//! operator to the person the host's link names. The host reads it as a
//! claim: an entry whose fingerprint does not name its key is dropped, the
//! kind stays what the operator says until the person sets it, and nothing
//! is trusted until the person types `y` at `airdress shell host trust`.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use uuid::Uuid;

use crate::binding::Binding;
use crate::paths::Paths;
use crate::trust::{DeviceStore, ListedDevice};

/// The route.
pub const DEVICES_PATH: &str = "/v1/shells/host/devices";

/// The answer: `{shellHost, principal, devices}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    #[serde(default)]
    pub shell_host: Option<String>,
    pub principal: Uuid,
    pub devices: Vec<ListedDevice>,
}

/// Ask the operator for the person's devices.
///
/// # Errors
/// The operator was unreachable or refused, or answered for somebody other
/// than the person this host is bound to.
pub async fn fetch(paths: &Paths, http: &reqwest::Client, binding: &Binding) -> Result<Listing> {
    let url = format!("{}{DEVICES_PATH}", binding.operator);
    let headers = binding
        .signer(paths)?
        .headers(&http::Method::GET, &url, None, b"")
        .await?;
    let resp = http
        .get(&url)
        .headers(headers)
        .timeout(crate::run::REQUEST_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("could not reach {}", binding.operator))?;
    let status = resp.status();
    let body = resp.bytes().await.unwrap_or_default();
    if !status.is_success() {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let code = v["error"]["code"]
            .as_str()
            .or_else(|| v["error"].as_str())
            .unwrap_or("");
        bail!(
            "the operator refused the device list ({status}{}{code})",
            if code.is_empty() { "" } else { " " }
        );
    }
    let listing: Listing =
        serde_json::from_slice(&body).context("the operator's device list does not parse")?;
    if listing.principal != binding.principal.id {
        bail!("the operator listed the devices of another person; ignoring them");
    }
    Ok(listing)
}

/// Fetch the list and take it into `devices.json` as pending devices.
/// Returns how many were new.
///
/// # Errors
/// As [`fetch`], or the store could not be read or written.
pub async fn refresh(paths: &Paths, http: &reqwest::Client, binding: &Binding) -> Result<usize> {
    let listing = fetch(paths, http, binding).await?;
    let mut store = DeviceStore::load(paths)?;
    let added = store.offer(&listing.devices);
    if added > 0 {
        store.save(paths)?;
    }
    Ok(added)
}

/// What the host prints at start when no device is trusted here yet but
/// the operator listed some: each with its fingerprint, and the command.
pub fn first_device_hint(store: &DeviceStore) -> Option<String> {
    if store.devices.keys().any(|d| store.trusted(d)) || store.pending.is_empty() {
        return None;
    }
    let mut out =
        String::from("No device is trusted on this host yet. The operator lists these as yours:\n");
    for (id, p) in &store.pending {
        let fp = crate::trust::b64(&p.identity)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map_or_else(
                || "(malformed)".into(),
                |k| crate::trust::identity_fingerprint(&k),
            );
        out.push_str(&format!(
            "  {:<24} {:<6} {fp}\n",
            p.label
                .clone()
                .unwrap_or_else(|| id.to_string()[..8].to_owned()),
            p.kind_claimed.as_deref().unwrap_or("?"),
        ));
    }
    out.push_str(
        "Compare a fingerprint with what that device shows, then trust it here, at this \
         machine's terminal:\n  airdress shell host trust <fingerprint>\n\
         A device holding a delegation from your airdress root is admitted without this.",
    );
    Some(out)
}
