use anyhow::{bail, Result};

use super::storage::{self, Profile};
use crate::ui;

pub fn run(paths: &crate::paths::Paths, name: &str, endpoint: &str) -> Result<()> {
    let path = paths.profile_path(name);
    if path.exists() {
        bail!("profile '{name}' already exists");
    }

    let profile = Profile {
        schema_version: storage::SCHEMA_VERSION,
        endpoint: endpoint.to_string(),
        auth: None,
        active_airdress: None,
    };
    storage::write_profile(paths, name, &profile)?;

    if storage::read_active_profile(paths)?.is_none() {
        storage::write_active_profile(paths, name)?;
        ui::ok(format!("created profile {name} (set as active)"));
    } else {
        ui::ok(format!("created profile {name}"));
    }

    Ok(())
}
