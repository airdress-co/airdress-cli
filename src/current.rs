//! `airdress current` — machine-readable context display (SPEC-043).
//!
//! Designed for shell-prompt integration (starship, p10k, oh-my-zsh):
//! reads cleanly in text mode, structured in JSON mode. Exits 0 even
//! when nothing is configured — a prompt component should never
//! paint the prompt red just because the user isn't logged in yet.

use anyhow::Result;

use crate::context::{self, Source};
use crate::preferences;
use crate::profile::storage;

pub fn run(
    paths: &crate::paths::Paths,
    explicit_airdress: Option<&str>,
    explicit_profile: Option<&str>,
    json: bool,
) -> Result<()> {
    let profile_name = resolve_profile(paths, explicit_profile);
    let (airdress, source, marker_path) = match &profile_name {
        Some(p) => match context::resolve(paths, p, explicit_airdress) {
            Ok(r) => (
                Some(r.name),
                Some(r.source),
                r.marker_path.as_deref().map(context::display_marker_path),
            ),
            Err(_) => (None, None, None),
        },
        None => (None, None, None),
    };

    if json {
        let prefs = preferences::load(paths).unwrap_or_default();
        let out = serde_json::json!({
            "profile": profile_name,
            "airdress": airdress,
            "source": source.map(|s| s.as_str()),
            "marker_path": marker_path,
            "preferences": {
                "discovery": {
                    "directory_marker": prefs.discovery.directory_marker,
                }
            }
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let prof_disp = profile_name.as_deref().unwrap_or("(no profile)");
    let air_disp = airdress.as_deref().unwrap_or("—");
    let src_disp = source.map(Source::as_str).unwrap_or("unset");
    if let Some(path) = &marker_path {
        println!("{prof_disp} / {air_disp} (source: {src_disp} [{path}])");
    } else {
        println!("{prof_disp} / {air_disp} (source: {src_disp})");
    }
    Ok(())
}

fn resolve_profile(paths: &crate::paths::Paths, explicit: Option<&str>) -> Option<String> {
    if let Some(name) = explicit {
        return Some(name.to_string());
    }
    storage::read_active_profile(paths).ok().flatten()
}
