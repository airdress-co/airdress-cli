//! Whether a package manager owns the running binary.
//!
//! A binary installed from the apt or dnf repository (or a one-off `.deb` /
//! `.rpm`) belongs to dpkg or rpm. Replacing it in place would leave the
//! package database naming a file it no longer matches (`dpkg --verify`
//! reports it modified) and the next package upgrade would silently put
//! the packaged one back. So `airdress update` refuses there and names
//! the package manager's own command instead (SPEC-179 FR-28).

use std::path::Path;

/// The package manager that owns a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Dnf,
}

impl Manager {
    /// The name `--check` reports as `managed_by`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
        }
    }

    /// The command that updates the CLI through this manager.
    pub const fn update_command(self) -> &'static str {
        match self {
            Self::Apt => "sudo apt update && sudo apt install --only-upgrade airdress",
            Self::Dnf => "sudo dnf upgrade airdress",
        }
    }
}

/// What the package databases say about a path. Behind a trait so the
/// rules are tested without a real dpkg or rpm.
pub trait PackageDb {
    /// The contents of dpkg's file list for `package`
    /// (`/var/lib/dpkg/info/<package>.list`), if it exists.
    fn dpkg_list(&self, package: &str) -> Option<String>;
    /// The name of the rpm package owning `path`, if rpm says one does.
    fn rpm_owner(&self, path: &Path) -> Option<String>;
}

/// The package that ships the CLI, in both formats.
const PACKAGE: &str = "airdress";

/// Which package manager owns `exe` (a canonical path), if any. dpkg is
/// asked first: a Debian host with rpm installed has an rpm database that
/// owns nothing.
pub fn managed_by(exe: &Path, db: &impl PackageDb) -> Option<Manager> {
    let exe_str = exe.to_str()?;
    if let Some(list) = db.dpkg_list(PACKAGE) {
        if list.lines().any(|line| line == exe_str) {
            return Some(Manager::Apt);
        }
    }
    if db.rpm_owner(exe).is_some() {
        return Some(Manager::Dnf);
    }
    None
}

/// The host's own package databases.
#[derive(Debug)]
pub struct SystemDb;

impl PackageDb for SystemDb {
    fn dpkg_list(&self, package: &str) -> Option<String> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        std::fs::read_to_string(format!("/var/lib/dpkg/info/{package}.list")).ok()
    }

    fn rpm_owner(&self, path: &Path) -> Option<String> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        // `rpm -qf` exits non-zero for a file no package owns, and when
        // there is no rpm at all the spawn fails: both mean "not rpm's".
        let out = std::process::Command::new("rpm")
            .args(["-qf", "--queryformat", "%{NAME}"])
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let name = String::from_utf8(out.stdout).ok()?;
        let name = name.trim();
        (!name.is_empty()).then(|| name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[derive(Default)]
    struct FakeDb {
        dpkg: HashMap<String, String>,
        rpm: HashMap<PathBuf, String>,
    }

    impl PackageDb for FakeDb {
        fn dpkg_list(&self, package: &str) -> Option<String> {
            self.dpkg.get(package).cloned()
        }
        fn rpm_owner(&self, path: &Path) -> Option<String> {
            self.rpm.get(path).cloned()
        }
    }

    const DPKG_LIST: &str = "/.\n/usr\n/usr/bin\n/usr/bin/airdress\n/usr/share/doc/airdress\n/usr/share/doc/airdress/copyright\n";

    #[test]
    fn a_dpkg_owned_binary_is_managed_by_apt() {
        let mut db = FakeDb::default();
        db.dpkg.insert("airdress".into(), DPKG_LIST.into());
        assert_eq!(
            managed_by(Path::new("/usr/bin/airdress"), &db),
            Some(Manager::Apt)
        );
    }

    #[test]
    fn a_binary_beside_the_package_is_not_managed() {
        // The package is installed, but this copy is the one in ~/.local/bin.
        let mut db = FakeDb::default();
        db.dpkg.insert("airdress".into(), DPKG_LIST.into());
        assert_eq!(
            managed_by(Path::new("/home/me/.local/bin/airdress"), &db),
            None
        );
    }

    #[test]
    fn a_path_is_matched_whole_not_as_a_prefix() {
        let mut db = FakeDb::default();
        db.dpkg.insert("airdress".into(), DPKG_LIST.into());
        assert_eq!(managed_by(Path::new("/usr/bin/airdres"), &db), None);
    }

    #[test]
    fn an_rpm_owned_binary_is_managed_by_dnf() {
        let mut db = FakeDb::default();
        db.rpm
            .insert(PathBuf::from("/usr/bin/airdress"), "airdress".into());
        assert_eq!(
            managed_by(Path::new("/usr/bin/airdress"), &db),
            Some(Manager::Dnf)
        );
    }

    #[test]
    fn no_package_database_means_not_managed() {
        assert_eq!(
            managed_by(Path::new("/usr/local/bin/airdress"), &FakeDb::default()),
            None
        );
    }

    #[test]
    fn dpkg_wins_over_rpm() {
        let mut db = FakeDb::default();
        db.dpkg.insert("airdress".into(), DPKG_LIST.into());
        db.rpm
            .insert(PathBuf::from("/usr/bin/airdress"), "airdress".into());
        assert_eq!(
            managed_by(Path::new("/usr/bin/airdress"), &db),
            Some(Manager::Apt)
        );
    }

    #[test]
    fn the_commands_name_the_manager() {
        assert!(Manager::Apt
            .update_command()
            .contains("apt install --only-upgrade airdress"));
        assert_eq!(Manager::Dnf.update_command(), "sudo dnf upgrade airdress");
        assert_eq!(Manager::Apt.name(), "apt");
        assert_eq!(Manager::Dnf.name(), "dnf");
    }
}
