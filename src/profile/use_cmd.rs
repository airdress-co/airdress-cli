use anyhow::{bail, Result};

use super::storage;
use crate::ui;

pub fn run(paths: &crate::paths::Paths, name: &str) -> Result<()> {
    let path = paths.profile_path(name);
    if !path.exists() {
        bail!("profile '{name}' does not exist — run `airdress profile create {name}` first");
    }
    storage::write_active_profile(paths, name)?;
    ui::ok(format!("active profile: {name}"));
    Ok(())
}
