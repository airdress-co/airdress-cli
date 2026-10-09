//! Where the functions of a repository are, and which of them a change
//! touched (SPEC-113 FR-34–FR-38, design §8).
//!
//! A **function directory** holds `function.json` (the author's request,
//! signed and published), `src/` (the code), and `function.yaml` (the
//! owner's Function manifest — never signed, never published). The deploy
//! tree is exactly `function.json` and every regular file under `src/`.
//! That is a selection, not validation: sizes, case collisions and the
//! rest are the operator's to refuse, with locations.
//!
//! An optional **map file**, `airdress.functions.yaml` at the repository
//! root, lists the directories, a manifest for each and the operator it
//! deploys to. Without it, directories are discovered.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::tree::Files;

/// The map file's name at the repository root.
pub const MAP_FILE: &str = "airdress.functions.yaml";

/// The manifest's default name in a function directory.
pub const MANIFEST_FILE: &str = "function.yaml";

/// The map file's JSON Schema, for editors (`airdress fn layout-schema`).
/// [`parse_map`] enforces the same shape; a test holds the two together.
pub const MAP_SCHEMA: &str = include_str!("functions-layout.schema.json");

/// The runtime a discoverable directory's `function.json` names.
pub const SOURCE_RUNTIME: &str = "js-source/v1";

/// `layout_invalid`: what is wrong, and on which line of which file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutInvalid {
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
}

impl std::fmt::Display for LayoutInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(l) => write!(f, "{}:{l}: {}", self.file, self.message),
            None => write!(f, "{}: {}", self.file, self.message),
        }
    }
}

impl std::error::Error for LayoutInvalid {}

/// One function to deploy: a directory, its manifest, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The function directory, relative to the repository root, `/`-separated
    /// (`.` for the root itself).
    pub path: String,
    /// The manifest, relative to the repository root.
    pub manifest: String,
    /// The operator, when the map file names one (entry or default).
    pub operator: Option<String>,
}

impl Entry {
    /// Whether a change to `changed` (a repository-relative path) touches
    /// what this function publishes: its `function.json` or anything under
    /// its `src/`. The manifest alone never does (FR-38).
    pub fn touched_by(&self, changed: &str) -> bool {
        let prefix = if self.path == "." {
            String::new()
        } else {
            format!("{}/", self.path)
        };
        changed == format!("{prefix}function.json") || changed.starts_with(&format!("{prefix}src/"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapFile {
    layout: u32,
    #[serde(default)]
    operator: Option<String>,
    functions: Vec<MapEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapEntry {
    path: String,
    #[serde(default)]
    manifest: Option<String>,
    #[serde(default)]
    operator: Option<String>,
}

/// The line of each item of the top-level `functions:` sequence (1-based),
/// for naming an entry that is wrong for a reason the parser cannot see.
fn item_lines(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut item_indent = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let indent = line.len() - t.len();
        if indent == 0 && !t.starts_with('-') {
            inside = t.starts_with("functions:");
            item_indent = None;
            continue;
        }
        if inside && (t.starts_with("- ") || t == "-") {
            match item_indent {
                None => {
                    item_indent = Some(indent);
                    out.push(i + 1);
                }
                Some(ind) if ind == indent => out.push(i + 1),
                _ => {}
            }
        }
    }
    out
}

/// A relative path inside the repository, `/`-separated, never escaping.
fn clean_relative(raw: &str) -> Option<String> {
    let p = raw.trim().trim_end_matches('/');
    if p.is_empty() || p.starts_with('/') || p.contains('\\') {
        return None;
    }
    let parts: Vec<&str> = p
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if parts.contains(&"..") {
        return None;
    }
    Some(if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    })
}

fn join(dir: &str, file: &str) -> String {
    if dir == "." {
        file.to_owned()
    } else {
        format!("{dir}/{file}")
    }
}

/// Parse and check a map file (FR-36). `default_operator` is the flag or
/// environment operator, which a map entry's own overrides.
pub fn parse_map(
    root: &Path,
    text: &str,
    default_operator: Option<&str>,
) -> std::result::Result<Vec<Entry>, LayoutInvalid> {
    let invalid = |line: Option<usize>, message: String| LayoutInvalid {
        file: MAP_FILE.to_owned(),
        line,
        message,
    };
    let map: MapFile = serde_yaml::from_str(text).map_err(|e| {
        invalid(
            e.location().map(|l| l.line()),
            e.to_string()
                .split(" at line ")
                .next()
                .unwrap_or_default()
                .to_owned(),
        )
    })?;
    if map.layout != 1 {
        let line = text
            .lines()
            .position(|l| l.starts_with("layout:"))
            .map(|i| i + 1);
        return Err(invalid(
            line,
            format!(
                "layout {} is not known to this client (it reads layout: 1)",
                map.layout
            ),
        ));
    }
    let lines = item_lines(text);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (i, e) in map.functions.iter().enumerate() {
        let line = lines.get(i).copied();
        let path = clean_relative(&e.path).ok_or_else(|| {
            invalid(
                line,
                format!(
                    "path `{}` must be relative and stay inside the repository",
                    e.path
                ),
            )
        })?;
        let manifest = match &e.manifest {
            Some(m) => clean_relative(m).ok_or_else(|| {
                invalid(
                    line,
                    format!("manifest `{m}` must be relative and stay inside the repository"),
                )
            })?,
            None => join(&path, MANIFEST_FILE),
        };
        if !root.join(&path).join("function.json").is_file() {
            return Err(invalid(
                line,
                format!("{path} holds no function.json; it is not a function directory"),
            ));
        }
        if !root.join(&manifest).is_file() {
            return Err(invalid(
                line,
                format!("the manifest {manifest} does not exist"),
            ));
        }
        let operator = e
            .operator
            .clone()
            .or_else(|| map.operator.clone())
            .or_else(|| default_operator.map(str::to_owned));
        if !seen.insert((manifest.clone(), operator.clone())) {
            return Err(invalid(
                line,
                format!(
                    "manifest {manifest} is listed twice for operator {}; each (manifest, \
                     operator) pair deploys once",
                    operator.as_deref().unwrap_or("(default)")
                ),
            ));
        }
        out.push(Entry {
            path,
            manifest,
            operator,
        });
    }
    if out.is_empty() {
        return Err(invalid(None, "functions: lists no function".to_owned()));
    }
    Ok(out)
}

/// Every function directory under `root` (FR-37): a `function.json` whose
/// `runtime` is `js-source/v1`, beside a `function.yaml`. `.git` and
/// `node_modules` are skipped. A directory without a manifest is noted.
pub fn discover(root: &Path) -> Result<(Vec<Entry>, Vec<String>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<Entry>, notes: &mut Vec<String>) -> Result<()> {
        let mut entries = std::fs::read_dir(dir)
            .with_context(|| format!("read {}", dir.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let rel = |p: &Path| {
            let r = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if r.is_empty() {
                ".".to_owned()
            } else {
                r
            }
        };
        let fj = dir.join("function.json");
        if fj.is_file() {
            let runtime = std::fs::read(&fj)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["runtime"].as_str().map(str::to_owned));
            if runtime.as_deref() == Some(SOURCE_RUNTIME) {
                let path = rel(dir);
                if dir.join(MANIFEST_FILE).is_file() {
                    out.push(Entry {
                        manifest: join(&path, MANIFEST_FILE),
                        path,
                        operator: None,
                    });
                } else {
                    notes.push(format!(
                        "{path}: a function directory with no {MANIFEST_FILE}; skipped (the \
                         owner creates it with `airdress fn deploy {path}`)"
                    ));
                }
            }
        }
        for e in entries {
            let name = e.file_name();
            if name == ".git" || name == "node_modules" || name == ".airdress" {
                continue;
            }
            if e.file_type()?.is_dir() {
                walk(root, &e.path(), out, notes)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    let mut notes = Vec::new();
    walk(root, root, &mut out, &mut notes)?;
    Ok((out, notes))
}

/// The deploy tree of a function directory (FR-34): `function.json` and
/// every regular file under `src/`, read once. Everything else is listed
/// as ignored. A symlink under `src/` is an error.
pub fn select(dir: &Path) -> Result<(Files, Vec<String>)> {
    let fj = dir.join("function.json");
    if !fj.is_file() {
        bail!("{} holds no function.json", dir.display());
    }
    let mut files = Files::new();
    files.insert(
        "function.json".into(),
        std::fs::read(&fj).with_context(|| format!("read {}", fj.display()))?,
    );
    let src = dir.join("src");
    if src.is_dir() {
        for (path, bytes) in super::tree::read_tree(&src)? {
            files.insert(format!("src/{path}"), bytes);
        }
    }
    let mut ignored = Vec::new();
    let mut top = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    top.sort_by_key(std::fs::DirEntry::file_name);
    for e in top {
        let name = e.file_name().to_string_lossy().into_owned();
        if name != "function.json" && name != "src" {
            ignored.push(if e.file_type()?.is_dir() {
                format!("{name}/")
            } else {
                name
            });
        }
    }
    Ok((files, ignored))
}

/// Which functions a change touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// Every entry, and why.
    All(String),
    /// The paths `git diff --name-only <base> HEAD` named.
    Paths { base: String, paths: Vec<String> },
}

impl Changed {
    /// Whether this change deploys `entry`: its `function.json` or `src/`
    /// changed, or the committed `spec.source.version` did. The second is
    /// how a refused deploy is recovered — a stale base is resolved by
    /// committing the version that runs, and that commit touches only the
    /// manifest. Any other manifest edit (the grant, the config, who may
    /// sign) still selects nothing: CI never applies it (FR-38).
    pub fn selects(&self, root: &Path, entry: &Entry) -> bool {
        match self {
            Self::All(_) => true,
            Self::Paths { base, paths } => {
                paths.iter().any(|c| entry.touched_by(c))
                    || (paths.contains(&entry.manifest)
                        && version_at(root, base, &entry.manifest)
                            != version_at(root, "HEAD", &entry.manifest))
            }
        }
    }
}

/// `spec.source.version` of the manifest at `rev`, if it is there.
fn version_at(root: &Path, rev: &str, manifest: &str) -> Option<String> {
    let text = git(root, &["show", &format!("{rev}:{manifest}")]).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    doc.get("spec")?
        .get("source")?
        .get("version")?
        .as_str()
        .map(str::to_owned)
}

/// The changed paths between `base` and `HEAD` (design §8.5). An all-zero
/// base (a branch's first push) or one that does not resolve selects all.
pub fn changed_since(root: &Path, base: &str) -> Changed {
    let base = base.trim();
    if !base.is_empty() && base.bytes().all(|b| b == b'0') {
        return Changed::All(format!("the base {base} is all zeros (a new branch)"));
    }
    match git(root, &["diff", "--name-only", base, "HEAD"]) {
        Ok(out) => Changed::Paths {
            base: base.to_owned(),
            paths: out.lines().map(str::to_owned).collect(),
        },
        Err(e) => Changed::All(format!("the base {base} does not resolve ({e})")),
    }
}

/// Run git in `root` and return its stdout.
pub fn git(root: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .context("run git")?;
    if !out.status.success() {
        bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The repository root: `git rev-parse --show-toplevel` from `from`, or
/// `from` itself outside a repository.
pub fn repo_root(from: &Path) -> PathBuf {
    git(from, &["rev-parse", "--show-toplevel"])
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|_| from.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function_dir(root: &Path, rel: &str, runtime: &str, manifest: bool) {
        let d = root.join(rel);
        std::fs::create_dir_all(d.join("src/lib")).unwrap();
        std::fs::write(
            d.join("function.json"),
            format!(r#"{{"runtime":"{runtime}","entry":"src/main.ts"}}"#),
        )
        .unwrap();
        std::fs::write(d.join("src/main.ts"), "export default () => 1;").unwrap();
        std::fs::write(d.join("src/lib/a.ts"), "export const a = 1;").unwrap();
        std::fs::write(d.join("README.md"), "# not deployed").unwrap();
        std::fs::write(d.join("tsconfig.json"), "{}").unwrap();
        if manifest {
            std::fs::write(
                d.join(MANIFEST_FILE),
                "spec:\n  source:\n    version: sha256:1\n",
            )
            .unwrap();
        }
    }

    #[test]
    fn the_selection_is_function_json_and_src_only() {
        let dir = tempfile::tempdir().unwrap();
        function_dir(dir.path(), "relay", SOURCE_RUNTIME, true);
        let (files, ignored) = select(&dir.path().join("relay")).unwrap();
        let paths: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["function.json", "src/lib/a.ts", "src/main.ts"]);
        assert_eq!(ignored, ["README.md", MANIFEST_FILE, "tsconfig.json"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_under_src_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        function_dir(dir.path(), "relay", SOURCE_RUNTIME, true);
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("relay/src/x.ts")).unwrap();
        let err = select(&dir.path().join("relay")).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn discovery_finds_source_functions_with_manifests_and_notes_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        function_dir(dir.path(), "functions/relay", SOURCE_RUNTIME, true);
        function_dir(dir.path(), "functions/draft", SOURCE_RUNTIME, false);
        function_dir(dir.path(), "functions/bundle", "wasm-component/v1", true);
        function_dir(dir.path(), "node_modules/pkg", SOURCE_RUNTIME, true);
        let (found, notes) = discover(dir.path()).unwrap();
        assert_eq!(
            found,
            [Entry {
                path: "functions/relay".into(),
                manifest: "functions/relay/function.yaml".into(),
                operator: None,
            }]
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("functions/draft:"), "{notes:?}");
    }

    #[test]
    fn the_map_file_is_read_with_defaults_and_uniqueness() {
        let dir = tempfile::tempdir().unwrap();
        function_dir(dir.path(), "functions/relay", SOURCE_RUNTIME, true);
        function_dir(dir.path(), "functions/digest", SOURCE_RUNTIME, false);
        std::fs::create_dir_all(dir.path().join("deploy/prod")).unwrap();
        std::fs::create_dir_all(dir.path().join("deploy/staging")).unwrap();
        std::fs::write(dir.path().join("deploy/prod/digest.yaml"), "spec: {}\n").unwrap();
        std::fs::write(dir.path().join("deploy/staging/digest.yaml"), "spec: {}\n").unwrap();
        let text = "layout: 1\n\
                    operator: a.example\n\
                    functions:\n\
                    \x20 - path: functions/relay\n\
                    \x20 - path: functions/digest\n\
                    \x20   manifest: deploy/prod/digest.yaml\n\
                    \x20   operator: b.example\n\
                    \x20 - path: functions/digest/\n\
                    \x20   manifest: deploy/staging/digest.yaml\n";
        let entries = parse_map(dir.path(), text, None).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].manifest, "functions/relay/function.yaml");
        assert_eq!(entries[0].operator.as_deref(), Some("a.example"));
        assert_eq!(entries[1].operator.as_deref(), Some("b.example"));
        assert_eq!(entries[2].path, "functions/digest");

        // The same (manifest, operator) twice names the second entry's line.
        let twice = "layout: 1\nfunctions:\n  - path: functions/relay\n  # again\n  - path: functions/relay\n";
        let err = parse_map(dir.path(), twice, Some("a.example")).unwrap_err();
        assert_eq!(err.line, Some(5), "{err}");
        assert!(err.message.contains("listed twice"), "{err}");
        // With different operators it is two deployments, and allowed.
        let two_ops = "layout: 1\nfunctions:\n  - path: functions/relay\n    operator: a.example\n  - path: functions/relay\n    operator: b.example\n";
        assert_eq!(parse_map(dir.path(), two_ops, None).unwrap().len(), 2);
    }

    #[test]
    fn a_malformed_map_file_names_its_line() {
        let dir = tempfile::tempdir().unwrap();
        function_dir(dir.path(), "functions/relay", SOURCE_RUNTIME, true);
        let unknown = "layout: 1\nfunctions:\n  - path: functions/relay\n    manifests: x.yaml\n";
        let err = parse_map(dir.path(), unknown, None).unwrap_err();
        assert!(err.message.contains("manifests"), "{err}");
        assert!(err.line.is_some(), "{err}");
        let version = "layout: 2\nfunctions:\n  - path: functions/relay\n";
        assert_eq!(
            parse_map(dir.path(), version, None).unwrap_err().line,
            Some(1)
        );
        let missing = "functions:\n  - path: functions/relay\n";
        assert!(parse_map(dir.path(), missing, None)
            .unwrap_err()
            .message
            .contains("layout"));
        let escape = "layout: 1\nfunctions:\n  - path: ../elsewhere\n";
        assert_eq!(
            parse_map(dir.path(), escape, None).unwrap_err().line,
            Some(3)
        );
        let no_dir = "layout: 1\nfunctions:\n  - path: functions/relay\n  - path: functions/none\n";
        let err = parse_map(dir.path(), no_dir, None).unwrap_err();
        assert_eq!(err.line, Some(4));
        assert_eq!(
            err.to_string(),
            "airdress.functions.yaml:4: functions/none holds no function.json; it is not a \
             function directory"
        );
    }

    #[test]
    fn the_schema_names_exactly_the_fields_the_parser_accepts() {
        let schema: serde_json::Value = serde_json::from_str(MAP_SCHEMA).unwrap();
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v["properties"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            k.sort();
            k
        };
        assert_eq!(keys(&schema), ["functions", "layout", "operator"]);
        assert_eq!(schema["additionalProperties"], false);
        let item = &schema["properties"]["functions"]["items"];
        assert_eq!(keys(item), ["manifest", "operator", "path"]);
        assert_eq!(item["additionalProperties"], false);
        assert_eq!(schema["properties"]["layout"]["const"], 1);
    }

    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| git(dir.path(), args).unwrap();
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "t@example.com"]);
        run(&["config", "user.name", "t"]);
        run(&["config", "commit.gpgsign", "false"]);
        dir
    }

    fn commit(root: &Path, msg: &str) -> String {
        git(root, &["add", "-A"]).unwrap();
        git(root, &["commit", "-q", "--no-verify", "-m", msg]).unwrap();
        git(root, &["rev-parse", "HEAD"]).unwrap().trim().to_owned()
    }

    #[test]
    fn a_change_selects_what_it_touched_or_a_moved_version_and_never_a_grant_edit() {
        let repo = git_repo();
        let root = repo.path();
        function_dir(root, "functions/relay", SOURCE_RUNTIME, true);
        function_dir(root, "functions/digest", SOURCE_RUNTIME, true);
        let first = commit(root, "one");
        let (entries, _) = discover(root).unwrap();
        let relay = entries
            .iter()
            .find(|e| e.path == "functions/relay")
            .unwrap();
        let digest = entries
            .iter()
            .find(|e| e.path == "functions/digest")
            .unwrap();

        std::fs::write(
            root.join("functions/relay/src/main.ts"),
            "export default () => 2;",
        )
        .unwrap();
        std::fs::write(
            root.join("functions/digest/function.yaml"),
            "spec:\n  capabilities:\n    kv: {}\n  source:\n    version: sha256:1\n",
        )
        .unwrap();
        std::fs::write(root.join("functions/digest/README.md"), "changed").unwrap();
        let second = commit(root, "two");

        let changed = changed_since(root, &first);
        assert!(matches!(changed, Changed::Paths { .. }), "{changed:?}");
        assert!(changed.selects(root, relay));
        assert!(
            !changed.selects(root, digest),
            "a grant edit in the manifest never deploys"
        );

        // A stale base is resolved by committing the version that runs;
        // that commit touches only the manifest, and must deploy.
        std::fs::write(
            root.join("functions/digest/function.yaml"),
            "spec:\n  capabilities:\n    kv: {}\n  source:\n    version: sha256:9\n",
        )
        .unwrap();
        commit(root, "three");
        let rebased = changed_since(root, &second);
        assert!(rebased.selects(root, digest), "a moved version deploys");
        assert!(!rebased.selects(root, relay));

        assert!(matches!(
            changed_since(root, &"0".repeat(40)),
            Changed::All(ref why) if why.contains("all zeros")
        ));
        assert!(matches!(
            changed_since(root, "no-such-ref"),
            Changed::All(ref why) if why.contains("does not resolve")
        ));
        assert_eq!(
            repo_root(&root.join("functions/relay")),
            root.canonicalize().unwrap()
        );
    }

    #[test]
    fn the_repository_root_itself_can_be_a_function() {
        let e = Entry {
            path: ".".into(),
            manifest: MANIFEST_FILE.into(),
            operator: None,
        };
        assert!(e.touched_by("function.json"));
        assert!(e.touched_by("src/main.ts"));
        assert!(!e.touched_by("function.yaml"));
        assert!(!e.touched_by("other/src/main.ts"));
    }
}
