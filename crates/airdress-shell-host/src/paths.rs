//! Where the host keeps things, and nowhere else (NFR-11).
//!
//! - **config:** `$XDG_CONFIG_HOME/airdress/` (`~/.config/airdress/`): the
//!   profile file, `shells.toml`, written by the person;
//! - **state:** `$XDG_STATE_HOME/airdress/` (`~/.local/state/airdress/`):
//!   the host's keys, its binding, the devices it trusts, the lock, the
//!   transport hints, recordings and the encrypted journal spill;
//! - **systemd user units:** `$XDG_CONFIG_HOME/systemd/user/`, only when the
//!   person runs `--install`.
//!
//! Every directory the host creates is `0700`, every file `0600`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The roots every other path hangs off. Built from the environment in a
/// real run, and from a temporary directory in a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The person's home directory (`~` in a profile).
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`.
    pub config_home: PathBuf,
    /// `$XDG_STATE_HOME`.
    pub state_home: PathBuf,
}

fn xdg(var: &str, home: &Path, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(default))
}

impl Paths {
    /// The paths of the user running this process.
    pub fn from_env() -> Result<Self> {
        let home = dirs::home_dir().context("this user has no home directory")?;
        Ok(Self {
            config_home: xdg("XDG_CONFIG_HOME", &home, ".config"),
            state_home: xdg("XDG_STATE_HOME", &home, ".local/state"),
            home,
        })
    }

    /// Paths under one root, for a test: `<root>/home`, `<root>/home/.config`
    /// and `<root>/home/.local/state`.
    pub fn under(root: &Path) -> Self {
        let home = root.join("home");
        Self {
            config_home: home.join(".config"),
            state_home: home.join(".local/state"),
            home,
        }
    }

    /// `~/.config/airdress/`.
    pub fn config_dir(&self) -> PathBuf {
        self.config_home.join("airdress")
    }

    /// `~/.config/airdress/shells.toml`: what this machine will run.
    pub fn profiles_file(&self) -> PathBuf {
        self.config_dir().join("shells.toml")
    }

    /// `~/.local/state/airdress/`.
    pub fn state_root(&self) -> PathBuf {
        self.state_home.join("airdress")
    }

    /// `~/.local/state/airdress/shell-host/`: keys, binding, trust, lock.
    pub fn host_dir(&self) -> PathBuf {
        self.state_root().join("shell-host")
    }

    /// The machine identity key (Ed25519 seed).
    pub fn machine_key(&self) -> PathBuf {
        self.host_dir().join("machine.key")
    }

    /// The host's X25519 shell key.
    pub fn shell_key(&self) -> PathBuf {
        self.host_dir().join("shell.key")
    }

    /// What the host is bound to (design §5.4). Written once.
    pub fn binding(&self) -> PathBuf {
        self.host_dir().join("binding.json")
    }

    /// The device keys the host verified, introduced or revoked.
    pub fn devices(&self) -> PathBuf {
        self.host_dir().join("devices.json")
    }

    /// The per-network transport hints.
    pub fn hints(&self) -> PathBuf {
        self.host_dir().join("transport-hints.json")
    }

    /// The single-instance lock for one airdress.
    pub fn lock(&self, airdress: &str) -> PathBuf {
        self.host_dir()
            .join(format!("{}.lock", file_safe(airdress)))
    }

    /// What `--install` wrote, so `--uninstall` removes exactly that.
    pub fn install_manifest(&self) -> PathBuf {
        self.host_dir().join("installed.json")
    }

    /// `~/.local/state/airdress/shells/`.
    pub fn shells_dir(&self) -> PathBuf {
        self.state_root().join("shells")
    }

    /// Recordings, by day.
    pub fn recordings_dir(&self) -> PathBuf {
        self.shells_dir().join("recordings")
    }

    /// The encrypted journal spill, one directory per session.
    pub fn spill_dir(&self) -> PathBuf {
        self.shells_dir().join("spill")
    }

    /// `~/.config/systemd/user/`.
    pub fn systemd_user_dir(&self) -> PathBuf {
        self.config_home.join("systemd").join("user")
    }

    /// Expand a leading `~` to the home directory.
    pub fn expand(&self, raw: &str) -> PathBuf {
        if raw == "~" {
            self.home.clone()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            self.home.join(rest)
        } else {
            PathBuf::from(raw)
        }
    }
}

/// A name usable as one path component: anything but `[A-Za-z0-9._-]`
/// becomes `_`.
pub fn file_safe(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Create `dir` and its missing parents, each new one `0700`.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("could not create {}", dir.display()))
}

/// Write `bytes` to `path` atomically, `0600`: a temporary file beside it,
/// synced, then renamed over it.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path.parent().context("a path with no parent")?;
    ensure_private_dir(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    // A leftover from a crashed write; `create_new` below fails, naming
    // it, if it is still there.
    if let Err(e) = std::fs::remove_file(&tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(error = %e, "removing a stale temporary file");
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("could not create {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("could not write {}", path.display()))
}

/// Create `path` with `bytes`, `0600`, refusing to replace an existing file.
pub fn create_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path.parent().context("a path with no parent")?;
    ensure_private_dir(dir)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "could not create {} (an existing file is never replaced)",
                path.display()
            )
        })?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Refuse a file other users can read or write.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("could not read {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} is open to other users (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_to_home_only_at_the_front() {
        let p = Paths::under(Path::new("/r"));
        assert_eq!(p.expand("~"), PathBuf::from("/r/home"));
        assert_eq!(p.expand("~/src/api"), PathBuf::from("/r/home/src/api"));
        assert_eq!(p.expand("/opt/~x"), PathBuf::from("/opt/~x"));
        assert_eq!(p.expand("~other"), PathBuf::from("~other"));
    }

    #[test]
    fn private_files_are_0600_and_never_replaced_when_new() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a/b/k");
        create_private_new(&f, b"x").unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(d.path().join("a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(create_private_new(&f, b"y").is_err());
        write_private_atomic(&f, b"z").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"z");
        ensure_private_file(&f).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ensure_private_file(&f).is_err());
    }

    #[test]
    fn file_safe_keeps_one_component() {
        assert_eq!(file_safe("019e…a.airdr.es"), "019e_a.airdr.es");
        assert_eq!(file_safe("a/b"), "a_b");
    }
}
