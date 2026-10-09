use anyhow::Result;

use super::storage;
use crate::ui;

pub fn run(paths: &crate::paths::Paths, json: bool) -> Result<()> {
    let profiles = storage::list_profiles(paths)?;

    if json {
        let items: Vec<_> = profiles
            .iter()
            .map(|(name, active)| serde_json::json!({ "name": name, "active": active }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if profiles.is_empty() {
        ui::say("no profiles configured — run `airdress profile create <name>`");
        return Ok(());
    }

    for (name, is_active) in &profiles {
        let marker = if *is_active { " *" } else { "" };
        println!("{name}{marker}");
    }

    Ok(())
}
