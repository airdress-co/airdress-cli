//! Airdress context resolution (SPEC-043).
//!
//! Picks the "current airdress" for any subcommand that targets one,
//! given a layered set of sources. Precedence (highest wins):
//!
//! 1. `--airdress` / `-A` flag (CLI invocation)
//! 2. `AIRDRESS_NAME` env var (shell session)
//! 3. `.airdress` marker file in CWD or any ancestor up to `$HOME`
//!    (opt-in via `discovery.directory_marker` in preferences.toml)
//! 4. `active_airdress` field on the active profile (per-profile,
//!    `~/.airdress/profiles/<name>.json`)
//! 5. Error → user runs `airdress airdress list` and `airdress a use`.
//!
//! The resolver does not call the hub. Set-time validation (`airdress
//! a use NAME`) lives in `airdresses::use_cmd`; resolve-time recovery
//! from a stale pin lives at the call site of the request that gets
//! 404/403 back.
//!
//! The marker walk is capped at `$HOME` — we never traverse into
//! `/etc` or `/`. CWD outside `$HOME` skips the marker tier entirely.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::paths::Paths;
use crate::preferences;
use crate::profile::storage;

/// Cap on `.airdress` file size. The legitimate content is one short
/// name; anything bigger is either a misuse or a hostile drop-in.
const MARKER_MAX_BYTES: u64 = 256;
const MARKER_FILENAME: &str = ".airdress";
const ENV_AIRDRESS_NAME: &str = "AIRDRESS_NAME";

/// Source label for the resolved airdress. Machine-friendly: lowercase
/// hyphenated strings, stable for JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Env,
    Marker,
    ProfileDefault,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::Marker => "marker",
            Source::ProfileDefault => "profile-default",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedAirdress {
    pub name: String,
    pub source: Source,
    /// Path to the marker file when `source == Marker`. Used for the
    /// status line (`source: marker [./.airdress]`) — relative to CWD
    /// when possible, absolute otherwise. None for any other source.
    pub marker_path: Option<PathBuf>,
}

/// Resolve the current airdress for the given profile, walking the
/// five-tier precedence. `explicit_flag` is the value of the
/// `--airdress` / `-A` global flag (None when not passed).
pub fn resolve(
    paths: &Paths,
    profile_name: &str,
    explicit_flag: Option<&str>,
) -> Result<ResolvedAirdress> {
    resolve_in(paths, &Ambient::from_process(), profile_name, explicit_flag)
}

/// What the resolver reads from the process besides files: the
/// `AIRDRESS_NAME` variable and the working directory. [`resolve`] reads
/// both at the call; a test passes its own.
#[derive(Debug, Clone, Default)]
pub struct Ambient {
    /// `AIRDRESS_NAME`, if set.
    pub airdress_name: Option<String>,
    /// The working directory, if it can be read.
    pub cwd: Option<PathBuf>,
}

impl Ambient {
    /// `AIRDRESS_NAME` and the working directory of this process.
    pub fn from_process() -> Self {
        Self {
            airdress_name: env::var(ENV_AIRDRESS_NAME).ok(),
            cwd: env::current_dir().ok(),
        }
    }
}

/// [`resolve`] with the environment variable and the working directory
/// given rather than read.
pub fn resolve_in(
    paths: &Paths,
    ambient: &Ambient,
    profile_name: &str,
    explicit_flag: Option<&str>,
) -> Result<ResolvedAirdress> {
    if let Some(name) = explicit_flag {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Ok(ResolvedAirdress {
                name: trimmed.to_string(),
                source: Source::Flag,
                marker_path: None,
            });
        }
    }

    if let Some(raw) = ambient.airdress_name.as_deref() {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(ResolvedAirdress {
                name: trimmed.to_string(),
                source: Source::Env,
                marker_path: None,
            });
        }
    }

    let prefs = preferences::load(paths).unwrap_or_default();
    if prefs.discovery.directory_marker {
        if let Some(hit) = find_marker(paths.home(), ambient.cwd.as_deref())? {
            return Ok(ResolvedAirdress {
                name: hit.name,
                source: Source::Marker,
                marker_path: Some(hit.path),
            });
        }
    }

    let profile = storage::read_profile(paths, profile_name)?;
    if let Some(name) = profile.active_airdress.filter(|s| !s.trim().is_empty()) {
        return Ok(ResolvedAirdress {
            name,
            source: Source::ProfileDefault,
            marker_path: None,
        });
    }

    bail!(
        "no current airdress for profile '{profile_name}'.\n  \
         see what's available: `airdress airdress list`\n  \
         pin one for this profile: `airdress a use <name>`\n  \
         override per-command:    `airdress -A <name> ...`"
    )
}

#[derive(Debug)]
struct MarkerHit {
    name: String,
    path: PathBuf,
}

/// Walk from CWD up to `$HOME`, looking for `.airdress`. The walk
/// stops at `$HOME` (inclusive) — never traverses into `/etc`, `/`,
/// or any other ancestor outside the user's home directory. CWD
/// outside `$HOME` returns `None`.
fn find_marker(home: &Path, cwd: Option<&Path>) -> Result<Option<MarkerHit>> {
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_owned());
    let home = home.canonicalize().unwrap_or_else(|_| home.to_owned());
    // CWD must be within $HOME (or be $HOME itself) for the walk to
    // run at all. Otherwise we silently skip — a marker on a
    // multi-tenant tmpfs would never apply to the wrong user.
    if !cwd.starts_with(&home) {
        return Ok(None);
    }

    let mut cur: &Path = &cwd;
    loop {
        let candidate = cur.join(MARKER_FILENAME);
        if let Some(name) = read_marker(&candidate)? {
            return Ok(Some(MarkerHit {
                name,
                path: candidate,
            }));
        }
        if cur == home.as_path() {
            return Ok(None);
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => return Ok(None),
        }
    }
}

/// Read one marker file. Returns:
/// - `Some(name)` for a readable file whose first non-empty trimmed
///   line is the airdress name.
/// - `None` for: missing file, file too large, empty file, file with
///   only whitespace, or read errors.
fn read_marker(path: &Path) -> Result<Option<String>> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Ok(None),
    };
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > MARKER_MAX_BYTES {
        tracing::debug!(
            "marker {} exceeds {} bytes — ignoring",
            path.display(),
            MARKER_MAX_BYTES
        );
        return Ok(None);
    }
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Ok(Some(trimmed.to_string()));
    }
    Ok(None)
}

/// Format the marker path for the status line. Tries to render
/// relative to CWD (shorter, matches the user's mental model); falls
/// back to the absolute path when the relative form would underflow
/// the CWD (e.g. marker in an ancestor directory).
pub fn display_marker_path(path: &Path) -> String {
    let cwd = match env::current_dir() {
        Ok(c) => c,
        Err(_) => return path.display().to_string(),
    };
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let path_abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Ok(stripped) = path_abs.strip_prefix(&cwd) {
        let s = stripped.display().to_string();
        if s.is_empty() {
            format!("./{}", MARKER_FILENAME)
        } else {
            format!("./{s}")
        }
    } else {
        path_abs.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::storage::{ensure_dirs, write_active_profile, write_profile, Profile};

    /// A fresh home with a `proj/` subdirectory to stand in. Marker tests
    /// write `.airdress` inside `proj/`, which avoids the structural
    /// collision with `$HOME/.airdress/` (our config directory). Nothing
    /// process-global moves: the working directory and `AIRDRESS_NAME` are
    /// handed to the resolver, so these tests run in parallel.
    #[derive(Debug)]
    struct Home {
        _dir: tempfile::TempDir,
        paths: Paths,
        proj: PathBuf,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().canonicalize().unwrap();
            let proj = home.join("proj");
            fs::create_dir_all(&proj).unwrap();
            Self {
                paths: Paths::under(&home),
                _dir: dir,
                proj,
            }
        }

        fn seed_profile_with_pin(&self, pin: Option<&str>) {
            ensure_dirs(&self.paths).unwrap();
            write_profile(
                &self.paths,
                "default",
                &Profile {
                    schema_version: storage::SCHEMA_VERSION,
                    endpoint: "https://account.airdress.co".into(),
                    auth: None,
                    active_airdress: pin.map(String::from),
                },
            )
            .unwrap();
            write_active_profile(&self.paths, "default").unwrap();
        }

        fn enable_marker(&self) {
            fs::create_dir_all(self.paths.config_dir()).unwrap();
            fs::write(
                self.paths.preferences_path(),
                "[discovery]\ndirectory_marker = true\n",
            )
            .unwrap();
        }

        /// Resolve the `default` profile standing in `cwd`, with
        /// `AIRDRESS_NAME` set to `name_env`.
        fn resolve_from(
            &self,
            cwd: &Path,
            name_env: Option<&str>,
            flag: Option<&str>,
        ) -> Result<ResolvedAirdress> {
            let ambient = Ambient {
                airdress_name: name_env.map(String::from),
                cwd: Some(cwd.to_owned()),
            };
            resolve_in(&self.paths, &ambient, "default", flag)
        }

        fn resolve(&self, name_env: Option<&str>, flag: Option<&str>) -> Result<ResolvedAirdress> {
            self.resolve_from(&self.proj, name_env, flag)
        }
    }

    #[test]
    fn tier1_flag_wins_over_env() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        let r = h.resolve(Some("bob"), Some("alice")).unwrap();
        assert_eq!(r.name, "alice");
        assert_eq!(r.source, Source::Flag);
    }

    #[test]
    fn tier2_env_wins_over_marker() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "dave").unwrap();
        let r = h.resolve(Some("bob"), None).unwrap();
        assert_eq!(r.name, "bob");
        assert_eq!(r.source, Source::Env);
    }

    #[test]
    fn tier3_marker_wins_over_profile_default() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "dave").unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.name, "dave");
        assert_eq!(r.source, Source::Marker);
        assert!(r.marker_path.is_some());
    }

    #[test]
    fn tier4_profile_default_returned() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.name, "carol");
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn tier5_error_when_nothing_resolves() {
        let h = Home::new();
        h.seed_profile_with_pin(None);
        let err = h.resolve(None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("airdress a use") || msg.contains("airdress list"),
            "error must point to remediation: {msg}"
        );
    }

    #[test]
    fn marker_disabled_by_default() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        // No preferences file → marker discovery off.
        fs::write(h.proj.join(".airdress"), "dave").unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.name, "carol");
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_walk_stops_at_home() {
        // A home one level below the temporary directory, so the marker
        // outside it is in a directory this test owns.
        let h = Home::new();
        let home = h.proj.parent().unwrap().join("inner-home");
        let proj = home.join("proj");
        fs::create_dir_all(&proj).unwrap();
        let inner = Home {
            _dir: tempfile::tempdir().unwrap(),
            paths: Paths::under(&home),
            proj,
        };
        inner.seed_profile_with_pin(Some("carol"));
        inner.enable_marker();
        // A marker in home's parent (outside home) must NOT be picked up.
        fs::write(home.parent().unwrap().join(".airdress"), "intruder").unwrap();
        let r = inner.resolve(None, None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_walks_up_to_home() {
        // CWD is proj/sub/leaf, marker is at proj/.airdress. Walk
        // should find it.
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "dave").unwrap();
        let leaf = h.proj.join("sub").join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        let r = h.resolve_from(&leaf, None, None).unwrap();
        assert_eq!(r.name, "dave");
        assert_eq!(r.source, Source::Marker);
    }

    #[test]
    fn marker_outside_home_is_never_read() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join(".airdress"), "dave").unwrap();
        let r = h.resolve_from(elsewhere.path(), None, None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_empty_file_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "").unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_whitespace_only_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "   \n\t\n").unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_oversized_file_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "x".repeat(512)).unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn marker_first_non_comment_line_used() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        h.enable_marker();
        fs::write(h.proj.join(".airdress"), "# this is a comment\n  alice  \n").unwrap();
        let r = h.resolve(None, None).unwrap();
        assert_eq!(r.name, "alice");
        assert_eq!(r.source, Source::Marker);
    }

    #[test]
    fn env_empty_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        let r = h.resolve(Some(""), None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn env_whitespace_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        let r = h.resolve(Some("   "), None).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }

    #[test]
    fn flag_empty_falls_through() {
        let h = Home::new();
        h.seed_profile_with_pin(Some("carol"));
        let r = h.resolve(None, Some("   ")).unwrap();
        assert_eq!(r.source, Source::ProfileDefault);
    }
}
