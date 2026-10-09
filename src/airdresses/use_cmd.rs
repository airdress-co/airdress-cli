//! `airdress airdress use <name>` — pin an airdress as the
//! current/default for the active profile (SPEC-043).
//!
//! Set-time validates against the hub's `/api/airdresses` list — the
//! user gets an immediate, clear error if NAME doesn't exist or
//! isn't theirs. After the pin is written, the resolver trusts it
//! until a later command's server response says otherwise (404/403),
//! at which point the call site clears the stale pin.

use anyhow::{bail, Result};

use super::client::{match_airdress, HubClient, MatchError};
use crate::profile::storage;
use crate::ui;

pub async fn run(
    paths: &crate::paths::Paths,
    name_or_fqdn: &str,
    profile: Option<&str>,
) -> Result<()> {
    let profile_name = storage::resolve_profile_name(paths, profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    let items = hub.list().await?;

    let matched = match match_airdress(&items, name_or_fqdn) {
        Ok(a) => a,
        Err(MatchError::NotFound) => bail!(
            "no airdress matching '{name_or_fqdn}' on profile '{profile_name}' — \
             run `airdress airdress list`"
        ),
        Err(MatchError::Ambiguous(n)) => {
            bail!("ambiguous: {n} airdresses match '{name_or_fqdn}' — use the id")
        }
    };

    storage::set_active_airdress(paths, &profile_name, &matched.name)?;
    ui::ok(format!(
        "pinned airdress '{}' for profile '{}'",
        matched.name, profile_name
    ));
    Ok(())
}
