//! Where the CLI keeps its files, decided once.
//!
//! `main` (and the MCP server's entry point) builds one [`Paths`] from the
//! environment with [`Paths::from_env`] and hands it down; nothing below
//! reads `$HOME` for itself. A test builds one over its own temporary
//! directory with [`Paths::under`], so tests share no process-global state
//! and need neither `set_var` nor `#[serial]`.
//!
//! The layout is what it always was: `~/.airdress/` holds the profiles
//! (`profiles/<name>.json`), the active-profile pointer (`config`),
//! `preferences.toml` and the pending-login hint, and the home directory
//! bounds the `.airdress` marker walk. The XDG data and state directories
//! (and the runtime directory) are read here too, once, and nowhere else.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// The CLI's directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    home: PathBuf,
    config: PathBuf,
    /// `$XDG_DATA_HOME`: root keys and device ids.
    data: PathBuf,
    /// `$XDG_STATE_HOME`: the shell client's device, the agent device.
    state: PathBuf,
    /// `$XDG_RUNTIME_DIR`, when set: where an agent socket goes when the
    /// path beside its state is too long for a socket address.
    runtime: Option<PathBuf>,
}

impl Paths {
    /// From the environment: the user's home directory (`$HOME` on unix),
    /// and `~/.airdress` under it.
    ///
    /// # Errors
    /// When there is no home directory to find.
    pub fn from_env() -> Result<Self> {
        let home = dirs::home_dir().context("cannot determine home directory")?;
        let mut p = Self::under(&home);
        // An XDG variable counts only when absolute (the spec's rule).
        let xdg = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|d| d.is_absolute())
        };
        // Data: the platform's own directory when XDG says nothing (on macOS,
        // ~/Library/Application Support), as before.
        if let Some(d) = xdg("XDG_DATA_HOME").or_else(dirs::data_dir) {
            p.data = d;
        }
        if let Some(d) = xdg("XDG_STATE_HOME") {
            p.state = d;
        }
        p.runtime = xdg("XDG_RUNTIME_DIR");
        Ok(p)
    }

    /// Everything under `home`, laid out as for a real user. For tests, and
    /// for a caller that has already decided where home is.
    pub fn under(home: &Path) -> Self {
        Self {
            home: home.to_owned(),
            config: home.join(".airdress"),
            data: home.join(".local").join("share"),
            state: home.join(".local").join("state"),
            runtime: None,
        }
    }

    /// `$XDG_RUNTIME_DIR`, when the environment sets an absolute one.
    pub fn runtime_dir(&self) -> Option<&Path> {
        self.runtime.as_deref()
    }

    /// The same, with `dir` as the runtime directory (tests).
    #[must_use]
    pub fn with_runtime_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.runtime = dir;
        self
    }

    /// `$XDG_DATA_HOME` (`~/.local/share` by default).
    pub fn data_home(&self) -> &Path {
        &self.data
    }

    /// `$XDG_STATE_HOME` (`~/.local/state` by default).
    pub fn state_home(&self) -> &Path {
        &self.state
    }

    /// The home directory: the top of the `.airdress` marker walk.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `~/.airdress`.
    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    /// `~/.airdress/profiles`.
    pub fn profiles_dir(&self) -> PathBuf {
        self.config.join("profiles")
    }

    /// `~/.airdress/profiles/<name>.json`.
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.profiles_dir().join(format!("{name}.json"))
    }

    /// `~/.airdress/config`: the active profile's name.
    pub fn active_profile_path(&self) -> PathBuf {
        self.config.join("config")
    }

    /// `~/.airdress/preferences.toml`.
    pub fn preferences_path(&self) -> PathBuf {
        self.config.join("preferences.toml")
    }

    /// `~/.airdress/pending-login`: the device-flow hint.
    pub fn pending_login_path(&self) -> PathBuf {
        self.config.join("pending-login")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_the_one_users_already_have() {
        let p = Paths::under(Path::new("/home/ada"));
        assert_eq!(p.home(), Path::new("/home/ada"));
        assert_eq!(p.config_dir(), Path::new("/home/ada/.airdress"));
        assert_eq!(
            p.profile_path("qa"),
            Path::new("/home/ada/.airdress/profiles/qa.json")
        );
        assert_eq!(
            p.active_profile_path(),
            Path::new("/home/ada/.airdress/config")
        );
        assert_eq!(
            p.preferences_path(),
            Path::new("/home/ada/.airdress/preferences.toml")
        );
        assert_eq!(
            p.pending_login_path(),
            Path::new("/home/ada/.airdress/pending-login")
        );
        assert_eq!(p.data_home(), Path::new("/home/ada/.local/share"));
        assert_eq!(p.state_home(), Path::new("/home/ada/.local/state"));
    }
}
