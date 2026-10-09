//! Harness awareness: installed, version, signed in (design §9.2, FR-W1–W3).
//!
//! The host learns these only by **running the harness's own read-only
//! commands**, from a table compiled in here: each argv is a constant, and
//! only the program path comes from the person's profile. A probe runs as
//! the host user, with no PTY, stdin closed, a 5-second timeout and its
//! output capped at 4 KiB, parsed only for a version string and an exit
//! status.
//!
//! The host never opens, reads, stats or hashes a harness's credential file
//! or keychain item, and forwards no credential variable the person did not
//! name themselves. A test runs the probes under `strace` and fails on any
//! file the host process itself touches under a credential path (the
//! harness, of course, reads its own).
//!
//! A probe never runs while a session of that profile has had input in the
//! last minute: our own observation must not look like the person.
//!
//! The sign-in commands are verified against each harness's own
//! documentation or source (task 137-F.8 in the spec, 2026-10-06), and only
//! their exit status is the verdict:
//!
//! - Claude Code 2.1.289: `claude auth status` — "Exits with code 0 if
//!   logged in, 1 if not" (`code.claude.com/docs/en/cli-reference.md`);
//! - Codex CLI 0.160.1: `codex login status` — exit 0 when logged in, 1 when
//!   not (`codex-rs/cli/src/login.rs`, `run_login_status`);
//! - opencode 1.18.25: `opencode auth list` (an alias of `providers list`)
//!   lists providers *and credentials*, and its exit status is not
//!   documented: no sign-in probe, so `unknown` (opencode also runs a free
//!   default model with no sign-in at all);
//! - Gemini CLI 0.62.0: no non-interactive status command exists
//!   (`docs/cli/cli-reference.md`; sign-in is the interactive `/auth`), so
//!   `unknown`.

use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::AsyncReadExt as _;

use crate::profiles::Profile;

/// One harness's documented read-only commands.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub harness: &'static str,
    pub version: &'static [&'static str],
    pub signed_in: Option<&'static [&'static str]>,
}

/// The compile-time table. A harness not in it gets `--version` only.
pub const TABLE: &[ProbeSpec] = &[
    ProbeSpec {
        harness: "claude-code",
        version: &["--version"],
        signed_in: Some(&["auth", "status"]),
    },
    ProbeSpec {
        harness: "codex",
        version: &["--version"],
        signed_in: Some(&["login", "status"]),
    },
    ProbeSpec {
        harness: "opencode",
        version: &["--version"],
        signed_in: None,
    },
    ProbeSpec {
        harness: "gemini",
        version: &["--version"],
        signed_in: None,
    },
];

const DEFAULT: ProbeSpec = ProbeSpec {
    harness: "",
    version: &["--version"],
    signed_in: None,
};

/// How long a probe may run.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// How much of a probe's output is read.
pub const OUTPUT_CAP: usize = 4096;
/// A profile with input more recent than this is not probed.
pub const QUIET_FOR: Duration = Duration::from_secs(60);

/// The table's entry for `harness`.
pub fn spec_for(harness: &str) -> ProbeSpec {
    TABLE
        .iter()
        .copied()
        .find(|s| s.harness == harness)
        .unwrap_or(DEFAULT)
}

/// What a harness said about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessState {
    pub installed: bool,
    pub version: Option<String>,
    /// `yes`, `no` or `unknown`.
    pub signed_in: &'static str,
}

impl HarnessState {
    /// As the `profiles` frame carries it.
    pub fn to_json(&self) -> Value {
        let mut v = json!({ "installed": self.installed, "signedIn": self.signed_in });
        if let Some(ver) = &self.version {
            v["version"] = Value::from(ver.as_str());
        }
        v
    }
}

/// The first `n.n[.n][-x]` in `text`.
pub fn parse_version(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric() || matches!(b[i - 1], b'v' | b'V'))
        {
            let start = i;
            let mut dots = 0;
            let mut j = i;
            while j < b.len()
                && (b[j].is_ascii_digit()
                    || (b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit()))
            {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots >= 1 {
                if j < b.len() && (b[j] == b'-' || b[j] == b'+') {
                    let mut k = j + 1;
                    while k < b.len() && (b[k].is_ascii_alphanumeric() || b[k] == b'.') {
                        k += 1;
                    }
                    if k > j + 1 {
                        j = k;
                    }
                }
                return Some(text[start..j].to_owned());
            }
            i = j;
        }
        i += 1;
    }
    None
}

/// The probe's environment: the base a program needs to find its own
/// configuration, and what the person named in the profile. Nothing else.
fn env_for(
    profile: &Profile,
    host_env: &(dyn Fn(&str) -> Option<OsString> + Sync),
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    for name in ["HOME", "USER", "PATH", "LANG"] {
        if let Some(v) = host_env(name) {
            out.push((name.into(), v));
        }
    }
    if let Some(spec) = profile.process() {
        for n in &spec.env_allow {
            if let Some(v) = host_env(n) {
                out.push((n.into(), v));
            }
        }
        for (k, v) in &spec.env_set {
            out.push((k.into(), v.into()));
        }
    }
    out
}

/// Run one command: `(exited 0, output)`, or `None` when it could not run
/// or ran past the timeout.
async fn run(
    program: &Path,
    argv: &[&str],
    env: &[(OsString, OsString)],
    cwd: &Path,
) -> Option<(bool, String)> {
    let mut child = tokio::process::Command::new(program)
        .args(argv)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let work = async {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut so = (&mut stdout).take(OUTPUT_CAP as u64);
        let mut se = (&mut stderr).take(OUTPUT_CAP as u64);
        let (_, _) = tokio::join!(so.read_to_end(&mut a), se.read_to_end(&mut b));
        let status = child.wait().await.ok()?;
        a.extend_from_slice(&b);
        Some((status.success(), String::from_utf8_lossy(&a).into_owned()))
    };
    tokio::time::timeout(TIMEOUT, work).await.ok().flatten()
}

/// Probe a `harness:<name>` profile.
pub async fn probe(
    profile: &Profile,
    host_env: &(dyn Fn(&str) -> Option<OsString> + Sync),
) -> Option<HarnessState> {
    let harness = profile.harness()?;
    let spec = spec_for(harness);
    let process = match &profile.source {
        crate::profiles::Source::Process(p) => p.clone(),
        crate::profiles::Source::Bridge(_) => return None,
    };
    if !process.program.is_file() {
        return Some(HarnessState {
            installed: false,
            version: None,
            signed_in: "unknown",
        });
    }
    let env = env_for(profile, host_env);
    let cwd = if process.cwd.is_dir() {
        process.cwd.clone()
    } else {
        std::path::PathBuf::from("/")
    };
    let version = run(&process.program, spec.version, &env, &cwd).await;
    let signed_in = match spec.signed_in {
        None => "unknown",
        Some(argv) => match run(&process.program, argv, &env, &cwd).await {
            Some((true, _)) => "yes",
            Some((false, _)) => "no",
            None => "unknown",
        },
    };
    Some(HarnessState {
        installed: version.is_some(),
        version: version.and_then(|(_, out)| parse_version(&out)),
        signed_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;

    #[test]
    fn versions_are_found_in_what_harnesses_print() {
        assert_eq!(
            parse_version("opencode 0.15.2\n").as_deref(),
            Some("0.15.2")
        );
        assert_eq!(
            parse_version("2.1.4 (Claude Code)").as_deref(),
            Some("2.1.4")
        );
        assert_eq!(
            parse_version("codex-cli 0.46.0-alpha.3").as_deref(),
            Some("0.46.0-alpha.3")
        );
        assert_eq!(parse_version("v1.2").as_deref(), Some("1.2"));
        assert_eq!(parse_version("no version here 7").as_deref(), None);
    }

    #[test]
    fn the_table_is_closed_and_unknown_harnesses_get_version_only() {
        assert_eq!(spec_for("codex").signed_in, Some(&["login", "status"][..]));
        assert_eq!(spec_for("aider").signed_in, None);
        assert_eq!(spec_for("aider").version, &["--version"]);
    }

    #[tokio::test]
    async fn a_stand_in_harness_is_probed_by_its_own_commands() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        std::fs::create_dir_all(&p.home).unwrap();
        let bin = d.path().join("harness");
        std::fs::write(
            &bin,
            "#!/bin/sh\ncase \"$1\" in --version) echo 'stand-in 3.4.5';; login) exit 1;; *) exit 0;; esac\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let text = format!(
            "[[profile]]\nid = \"h\"\nkind = \"harness:codex\"\nprogram = \"{}\"\n",
            bin.display()
        );
        let prof = crate::profiles::parse_str(&text, &p)
            .unwrap()
            .profiles
            .remove(0);
        let st = probe(&prof, &crate::environment::host_env).await.unwrap();
        assert_eq!(
            st,
            HarnessState {
                installed: true,
                version: Some("3.4.5".into()),
                signed_in: "no"
            }
        );
        let missing = crate::profiles::parse_str(
            &text.replace(&bin.display().to_string(), "/nonexistent/x"),
            &p,
        )
        .unwrap()
        .profiles
        .remove(0);
        assert!(
            !probe(&missing, &crate::environment::host_env)
                .await
                .unwrap()
                .installed
        );
        let shell =
            crate::profiles::parse_str("[[profile]]\nid = \"s\"\nprogram = \"/bin/sh\"\n", &p)
                .unwrap()
                .profiles
                .remove(0);
        assert!(
            probe(&shell, &crate::environment::host_env).await.is_none(),
            "only harness profiles"
        );
    }

    #[tokio::test]
    async fn a_probe_that_hangs_is_cut_at_the_timeout() {
        let d = tempfile::tempdir().unwrap();
        let start = std::time::Instant::now();
        let r = run(Path::new("/bin/sleep"), &["30"], &[], d.path()).await;
        assert!(r.is_none());
        assert!(start.elapsed() < TIMEOUT + Duration::from_secs(2));
    }
}
