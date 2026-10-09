//! Opt-in autostart for this user, and nothing else (D-16, design §7.7,
//! FR-H9, NFR-11).
//!
//! `airdress shell host --install` writes one systemd **user** unit,
//! `~/.config/systemd/user/airdress-shell-host.service`, reloads the user
//! manager and enables it. It prints what it wrote, and the one thing it
//! will not do for the person: without lingering, a user unit stops at
//! logout and its sessions with it. It never runs `loginctl enable-linger`,
//! and never touches a system location.
//!
//! Everything it creates — the unit, any directory that did not exist, the
//! `.wants` directory systemd makes when it enables the unit — is listed in
//! `~/.local/state/airdress/shell-host/installed.json`, and `--uninstall`
//! removes exactly that and stops the unit. A test lists the file tree
//! before `--install` and after `--uninstall` and expects no difference.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::log_err::LogErr as _;
use crate::paths::Paths;

/// The unit's name.
pub const UNIT: &str = "airdress-shell-host.service";
/// The variable the unit sets, so the host can say how it was started.
pub const AUTOSTART_VAR: &str = "AIRDRESS_SHELL_HOST_AUTOSTART";

/// Runs `systemctl --user …`; a fake in tests.
pub trait Systemctl {
    fn user(&self, args: &[&str]) -> Result<()>;
}

/// The real user manager.
#[derive(Debug, Default)]
pub struct UserManager;

impl Systemctl for UserManager {
    fn user(&self, args: &[&str]) -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .context("could not run systemctl --user (is this a systemd system?)")?;
        if !status.success() {
            bail!("systemctl --user {} failed ({status})", args.join(" "));
        }
        Ok(())
    }
}

/// What `--install` wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Files written.
    pub files: Vec<PathBuf>,
    /// Directories created, outermost first.
    pub dirs: Vec<PathBuf>,
}

/// The unit file's text.
pub fn unit_text(exe: &Path) -> String {
    format!(
        "# Written by `airdress shell host --install`; removed by `--uninstall`.\n\
         [Unit]\n\
         Description=Airdress shell host (runs the profiles in ~/.config/airdress/shells.toml)\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} shell host\n\
         Environment={AUTOSTART_VAR}=systemd-user\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe.display()
    )
}

fn missing_dirs(target: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = target
        .ancestors()
        .filter(|a| !a.as_os_str().is_empty() && !a.exists())
        .map(Path::to_path_buf)
        .collect();
    v.reverse();
    v
}

/// The note on lingering, printed and never acted on.
pub const LINGER_NOTE: &str = "\
Without lingering, a user unit stops when you log out, and your sessions with it.
To keep the host running after you log out, run this yourself:
  loginctl enable-linger \"$USER\"
This host never turns lingering on for you.";

/// `--install`.
pub fn install(paths: &Paths, exe: &Path, sys: &dyn Systemctl, out: &mut dyn Write) -> Result<()> {
    if paths.install_manifest().exists() {
        bail!("already installed; `airdress shell host --uninstall` first");
    }
    if !paths.binding().exists() {
        bail!(
            "this machine is not enrolled yet: run `airdress shell host` once in a terminal, \
             approve it, then --install"
        );
    }
    let unit = paths.systemd_user_dir().join(UNIT);
    let wants = paths.systemd_user_dir().join("default.target.wants");
    let mut m = Manifest {
        files: vec![unit.clone()],
        dirs: missing_dirs(&paths.systemd_user_dir()),
    };
    // systemd makes this when it enables the unit; it goes when it is empty.
    if !wants.exists() {
        m.dirs.push(wants);
    }
    for d in missing_dirs(&paths.host_dir()) {
        if !m.dirs.contains(&d) {
            m.dirs.push(d);
        }
    }
    m.files.push(paths.install_manifest());
    let text = unit_text(exe);
    crate::fsx::create_dir_all(paths.systemd_user_dir())?;
    crate::paths::ensure_private_dir(&paths.host_dir())?;
    let mut bytes = serde_json::to_vec_pretty(&m)?;
    bytes.push(b'\n');
    crate::paths::create_private_new(&paths.install_manifest(), &bytes)?;
    std::fs::write(&unit, &text).with_context(|| format!("could not write {}", unit.display()))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        crate::fsx::set_permissions(&unit, std::fs::Permissions::from_mode(0o644))?;
    }
    sys.user(&["daemon-reload"])?;
    sys.user(&["enable", "--now", UNIT])?;
    writeln!(out, "Wrote {}:\n\n{text}", unit.display())?;
    writeln!(
        out,
        "Enabled and started it for this user.\n\n{LINGER_NOTE}"
    )?;
    Ok(())
}

/// `--uninstall`: stop the unit and remove exactly what `--install` wrote.
pub fn uninstall(paths: &Paths, sys: &dyn Systemctl, out: &mut dyn Write) -> Result<()> {
    let raw = std::fs::read(paths.install_manifest()).context("not installed (no manifest)")?;
    let m: Manifest = serde_json::from_slice(&raw).context("the install manifest is malformed")?;
    if let Err(e) = sys.user(&["disable", "--now", UNIT]) {
        writeln!(out, "warning: {e:#}")?;
    }
    for f in &m.files {
        match std::fs::remove_file(f) {
            Ok(()) => writeln!(out, "removed {}", f.display())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("could not remove {}", f.display())),
        }
    }
    // The unit files are gone either way; systemd forgets them at its next
    // reload if this one fails.
    sys.user(&["daemon-reload"])
        .log_warn("systemctl --user daemon-reload");
    for d in m.dirs.iter().rev() {
        if std::fs::remove_dir(d).is_ok() {
            writeln!(out, "removed {}/", d.display())?;
        }
    }
    writeln!(
        out,
        "Uninstalled. Nothing of the host runs unless you start it."
    )?;
    Ok(())
}

/// How this host was started, for `host_info`.
pub fn autostart_kind() -> &'static str {
    match std::env::var(AUTOSTART_VAR).as_deref() {
        Ok("systemd-user") => "systemd-user",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        wants: Option<PathBuf>,
    }

    impl Systemctl for Fake {
        fn user(&self, args: &[&str]) -> Result<()> {
            self.calls.borrow_mut().push(args.join(" "));
            // Do what the real manager does to the tree.
            if let Some(w) = &self.wants {
                match args {
                    ["enable", ..] => {
                        std::fs::create_dir_all(w)?;
                        std::os::unix::fs::symlink("../x", w.join(UNIT))?;
                    }
                    ["disable", ..] => match std::fs::remove_file(w.join(UNIT)) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    },
                    _ => {}
                }
            }
            Ok(())
        }
    }

    fn tree(root: &Path) -> Vec<String> {
        fn walk(p: &Path, root: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(p).unwrap().flatten() {
                let path = e.path();
                out.push(path.strip_prefix(root).unwrap().display().to_string());
                if path.is_dir() && !path.is_symlink() {
                    walk(&path, root, out);
                }
            }
        }
        let mut v = Vec::new();
        walk(root, root, &mut v);
        v.sort();
        v
    }

    #[test]
    fn install_then_uninstall_leaves_the_tree_as_it_was() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        // An enrolled host: its binding exists.
        std::fs::create_dir_all(p.host_dir()).unwrap();
        std::fs::write(p.binding(), "{}").unwrap();
        let before = tree(d.path());
        let sys = Fake {
            wants: Some(p.systemd_user_dir().join("default.target.wants")),
            ..Default::default()
        };
        let mut out = Vec::new();
        install(&p, Path::new("/usr/bin/airdress"), &sys, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("ExecStart=/usr/bin/airdress shell host"),
            "{text}"
        );
        assert!(
            text.contains("loginctl enable-linger"),
            "the note is printed"
        );
        assert!(p.systemd_user_dir().join(UNIT).exists());
        assert!(
            install(&p, Path::new("/usr/bin/airdress"), &sys, &mut Vec::new()).is_err(),
            "twice"
        );
        uninstall(&p, &sys, &mut Vec::new()).unwrap();
        assert_eq!(tree(d.path()), before);
        let calls = sys.calls.borrow().clone();
        assert_eq!(
            calls,
            [
                "daemon-reload",
                "enable --now airdress-shell-host.service",
                "disable --now airdress-shell-host.service",
                "daemon-reload"
            ]
        );
        assert!(
            !calls.iter().any(|c| c.contains("linger")),
            "never lingering"
        );
    }

    #[test]
    fn install_needs_an_enrolled_host() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let err = install(&p, Path::new("/x"), &Fake::default(), &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("not enrolled"), "{err}");
    }
}
