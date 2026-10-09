//! The probes never touch a harness's credentials (design §9.2, FR-W3).
//!
//! Stand-in harnesses (shell scripts named for three real ones) read a decoy
//! credential file when asked their sign-in status, as a real harness reads
//! its own. The probes run in a helper process under `strace -f`, and the
//! test fails if any thread of the host process itself opens, reads or
//! stats a path under a credential location; the stand-ins' own processes
//! are expected to, and are checked to have done so, which proves the
//! watcher sees what it is meant to.
//!
//! `strace` rather than `fanotify`: fanotify needs `CAP_SYS_ADMIN`, and
//! tracing one's own child needs no privilege. Needs `strace` on PATH, so
//! it is `#[ignore]`d and run by name in CI.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::process::Command;

use airdress_shell_host::paths::Paths;

const HELPER: &str = "AIRDRESS_PROBE_HELPER_ROOT";

/// The credential locations of design §9.2, relative to `$HOME`.
const DECOYS: [&str; 4] = [
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".local/share/opencode/auth.json",
    ".config/gemini/oauth_creds.json",
];

fn stand_in(bin: &Path, name: &str, status: &[&str], decoy: &str) {
    let script = format!(
        "#!/bin/sh\ncase \"$1 $2\" in\n  '--version '*) echo '{name} 9.8.7 (stand-in)' ;;\n  '{} {}') cat \"$HOME/{decoy}\" > /dev/null ;;\nesac\nexit 0\n",
        status[0], status[1]
    );
    let p = bin.join(name);
    std::fs::write(&p, script).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn setup(root: &Path) -> Paths {
    let paths = Paths::under(root);
    for d in DECOYS {
        let p = paths.home.join(d);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "DECOY-CREDENTIAL").unwrap();
    }
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    stand_in(&bin, "claude", &["auth", "status"], DECOYS[0]);
    stand_in(&bin, "codex", &["login", "status"], DECOYS[1]);
    // opencode has no sign-in probe (its `auth list` prints credentials):
    // only `--version` runs, and its stand-in would read the decoy if asked
    // anything else.
    stand_in(&bin, "opencode", &["auth", "list"], DECOYS[2]);
    stand_in(&bin, "gemini", &["--version", ""], DECOYS[3]);
    std::fs::create_dir_all(paths.config_dir()).unwrap();
    let mut text = String::new();
    for (id, kind) in [
        ("claude", "claude-code"),
        ("codex", "codex"),
        ("opencode", "opencode"),
        ("gemini", "gemini"),
    ] {
        text.push_str(&format!(
            "[[profile]]\nid = \"{id}\"\nkind = \"harness:{kind}\"\nprogram = \"{}\"\n\n",
            bin.join(id).display()
        ));
    }
    std::fs::write(paths.profiles_file(), text).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
        paths.profiles_file(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    paths
}

/// Runs only as the helper: probe every profile, in this one process.
#[test]
fn helper_probes_every_profile() {
    let Some(root) = std::env::var_os(HELPER) else {
        return;
    };
    let paths = Paths::under(Path::new(&root));
    let file = airdress_shell_host::profiles::load(&paths).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for p in &file.profiles {
            let st =
                airdress_shell_host::probes::probe(p, &airdress_shell_host::environment::host_env)
                    .await
                    .unwrap();
            assert!(st.installed, "{}", p.id);
            assert_eq!(st.version.as_deref(), Some("9.8.7"), "{}", p.id);
        }
    });
}

#[test]
#[ignore = "needs strace; CI runs it by name"]
fn no_probe_opens_a_credential_file() {
    let dir = tempfile::tempdir().unwrap();
    let paths = setup(dir.path());
    let log = dir.path().join("trace.log");
    let exe = std::env::current_exe().unwrap();
    let status = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=%file,execve", "-o"])
        .arg(&log)
        .arg(&exe)
        .args(["--exact", "helper_probes_every_profile", "--test-threads=1"])
        .env(HELPER, dir.path())
        .env("HOME", &paths.home)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", dir.path().join("bin").display()),
        )
        .status()
        .expect("strace on PATH");
    assert!(status.success(), "the helper failed");
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<(u32, &str)> = text
        .lines()
        .filter_map(|l| {
            let (pid, rest) = l.split_once(' ')?;
            Some((pid.trim().parse().ok()?, rest.trim_start()))
        })
        .collect();
    let root = lines.first().expect("a trace").0;
    // A thread that exec'd something is a child process (a stand-in, or a
    // `cat` it ran); everything else is the host process's own threads.
    let children: HashSet<u32> = lines
        .iter()
        .filter(|(pid, rest)| *pid != root && rest.starts_with("execve(") && rest.ends_with("= 0"))
        .map(|(pid, _)| *pid)
        .collect();
    let decoy_hits = |pid_filter: &dyn Fn(u32) -> bool| -> BTreeSet<String> {
        lines
            .iter()
            .filter(|(pid, _)| pid_filter(*pid))
            .filter(|(_, rest)| {
                DECOYS.iter().any(|d| {
                    rest.contains(d.split('/').next().unwrap())
                        && rest.contains(d.rsplit('/').next().unwrap())
                })
            })
            .map(|(_, rest)| (*rest).to_owned())
            .collect()
    };
    let host = decoy_hits(&|p| !children.contains(&p));
    assert!(
        host.is_empty(),
        "the host touched a credential path: {host:#?}"
    );
    let child = decoy_hits(&|p| children.contains(&p));
    assert!(
        child
            .iter()
            .filter(|l| l.contains("DECOY") || l.contains(".json"))
            .count()
            >= 2,
        "the stand-ins read their decoys (the watcher works): {child:#?}"
    );
}
