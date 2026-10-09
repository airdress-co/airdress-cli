//! User preferences — opt-in flags that change CLI behavior.
//!
//! SPEC-043 introduces this file. The only flag today is
//! `discovery.directory_marker`, which gates the `.airdress` marker
//! tier of the context resolver. The file is *not* a credential store
//! (those live in `~/.airdress/profiles/<name>.json`) and *not* the
//! active-profile pointer (`~/.airdress/config`, one-line). Keeping
//! preferences in its own TOML file avoids breaking the existing
//! one-line parser of `config` while giving us a stable place to
//! grow future opt-ins.
//!
//! File: `~/.airdress/preferences.toml`. Absent file → all defaults.
//! Malformed file → all defaults + a stderr warning (we never refuse
//! to run because of a typo here).

use std::fs;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::paths::Paths;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Preferences {
    #[serde(default)]
    pub discovery: Discovery,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Discovery {
    /// SPEC-043 — opt in to `.airdress` directory marker discovery.
    /// Off by default to keep the "wrong directory" footgun gated
    /// behind a deliberate user choice.
    #[serde(default)]
    pub directory_marker: bool,
}

/// Load preferences from `~/.airdress/preferences.toml`. Returns all
/// defaults if the file is missing. Logs a warning and returns
/// defaults if the file is malformed — we never refuse to run the CLI
/// because of a preferences-file typo.
pub fn load(paths: &Paths) -> Result<Preferences> {
    let path = paths.preferences_path();
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Preferences::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    match toml::from_str::<Preferences>(&raw) {
        Ok(p) => Ok(p),
        Err(e) => {
            tracing::warn!(
                "malformed {}: {} — using defaults",
                path.display(),
                e.message()
            );
            Ok(Preferences::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.config_dir()).unwrap();
        (dir, paths)
    }

    #[test]
    fn missing_file_returns_defaults() {
        let (_home, paths) = home();
        let p = load(&paths).unwrap();
        assert!(!p.discovery.directory_marker);
    }

    #[test]
    fn explicit_opt_in_parses() {
        let (_home, paths) = home();
        fs::write(
            paths.preferences_path(),
            "[discovery]\ndirectory_marker = true\n",
        )
        .unwrap();
        let p = load(&paths).unwrap();
        assert!(p.discovery.directory_marker);
    }

    #[test]
    fn malformed_falls_back_to_defaults() {
        let (_home, paths) = home();
        fs::write(paths.preferences_path(), "this is = not [valid toml").unwrap();
        let p = load(&paths).unwrap();
        assert!(!p.discovery.directory_marker);
    }
}
