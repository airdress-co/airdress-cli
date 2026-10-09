//! The Airdress Functions SDK on the author's machine (SPEC-114 §8.3, §11).
//!
//! The library (`@airdress/functions`) is compiled into the operator and
//! resolved there at publish; nothing here changes what runs. What the
//! client adds is what an editor and a local test need, beside
//! `function.json` and never under `src/`, so none of it is ever published
//! (the deploy tree is exactly `function.json` and `src/`):
//!
//! - `.airdress/sdk-<version>.d.ts`: the pinned version's types — every
//!   module and the `airdress` global — and a `tsconfig.json` that
//!   includes them.
//! - `.airdress/node_modules/@airdress/functions/`: the pinned version's
//!   modules as an ordinary package, from the operator — never from npm,
//!   where the scope is reserved and empty.
//! - `node_modules` at the function root, a link to
//!   `.airdress/node_modules`: Node, Bun and Deno (with
//!   `--node-modules-dir=manual`) resolve a bare specifier from a
//!   `node_modules` directory beside or above the importing file, and not
//!   from anywhere a `package.json` field could point at — `imports` only
//!   maps `#` specifiers, and workspaces need an install. Measured with
//!   each runtime; see the tests in `test/`.
//!
//! `vendor` is the other way out: the library copied into `src/sdk/`, the
//! imports made relative and the pin removed, after which the function
//! refers to nothing (SPEC-112 FR-81).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// The reserved import prefix.
pub const PREFIX: &str = "@airdress/functions/";
/// The directory beside `function.json` the client writes into.
pub const LOCAL_DIR: &str = ".airdress";
/// Where vendored modules go, under `src/`.
pub const VENDOR_DIR: &str = "sdk";

/// The exact version `function.json` pins, if any.
pub fn pin(dir: &Path) -> Result<Option<String>> {
    let path = dir.join("function.json");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    Ok(v["sdk"].as_str().map(str::to_owned))
}

/// `function.json` with `"sdk": "<version>"` set, keeping the author's
/// layout: an existing pin is replaced in place; a new one goes on its own
/// line after `minHost` (or first, when there is none).
pub fn set_pin_text(text: &str, version: &str) -> Result<String> {
    let v: Value = serde_json::from_str(text).context("function.json is not JSON")?;
    if v.get("sdk").is_some() {
        let out = replace_string_member(text, "sdk", version)
            .context("function.json's \"sdk\" is not a string")?;
        return Ok(out);
    }
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with("\"minHost\""))
        .or_else(|| lines.iter().position(|l| l.trim_start().starts_with('"')));
    let Some(at) = at else {
        // One line, or an unusual layout: rewrite it.
        let mut v = v;
        v["sdk"] = Value::from(version);
        return Ok(format!("{}\n", serde_json::to_string_pretty(&v)?));
    };
    let indent: String = lines[at]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    let after_min_host = lines[at].trim_start().starts_with("\"minHost\"");
    let entry = format!("{indent}\"sdk\": \"{version}\",");
    if after_min_host {
        if !lines[at].trim_end().ends_with(',') {
            lines[at].push(',');
            // `minHost` was the last member: the pin is, now, without a comma.
            lines.insert(at + 1, entry.trim_end_matches(',').to_owned());
        } else {
            lines.insert(at + 1, entry);
        }
    } else {
        lines.insert(at, entry);
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    serde_json::from_str::<Value>(&out).context("the pinned function.json would not be JSON")?;
    Ok(out)
}

/// `function.json` without its `sdk` member.
pub fn remove_pin_text(text: &str) -> Result<String> {
    let v: Value = serde_json::from_str(text).context("function.json is not JSON")?;
    if v.get("sdk").is_none() {
        return Ok(text.to_owned());
    }
    let lines: Vec<&str> = text.lines().collect();
    if let Some(i) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("\"sdk\""))
    {
        let mut kept: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
        let was_last = !kept[i].trim_end().ends_with(',');
        kept.remove(i);
        if was_last {
            // The member before it loses its trailing comma.
            if let Some(prev) = (0..i).rev().find(|&j| !kept[j].trim().is_empty()) {
                if let Some(stripped) = kept[prev].trim_end().strip_suffix(',') {
                    kept[prev] = stripped.to_owned();
                }
            }
        }
        let mut out = kept.join("\n");
        if text.ends_with('\n') {
            out.push('\n');
        }
        if serde_json::from_str::<Value>(&out)
            .map(|o| o.get("sdk").is_none())
            .unwrap_or(false)
        {
            return Ok(out);
        }
    }
    let mut v = v;
    v.as_object_mut().map(|o| o.remove("sdk"));
    Ok(format!("{}\n", serde_json::to_string_pretty(&v)?))
}

/// Replace the string value of `"key": "…"` in place.
fn replace_string_member(text: &str, key: &str, value: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = text.find(&needle)?;
    let rest = &text[at + needle.len()..];
    let colon = rest.find(':')?;
    let after = &rest[colon + 1..];
    let open = after.find('"')?;
    if !after[..open].trim().is_empty() {
        return None;
    }
    let close = after[open + 1..].find('"')?;
    let start = at + needle.len() + colon + 1 + open + 1;
    let end = start + close;
    Some(format!("{}{value}{}", &text[..start], &text[end..]))
}

/// One version, as `GET /v1/functions/sdk/{version}` answers it.
#[derive(Debug, Clone)]
pub struct Release {
    pub version: String,
    /// Module names, in catalogue order, with whether each is test-only.
    pub modules: Vec<(String, bool)>,
    /// `<module>.js` and `sdk.d.ts`.
    pub files: std::collections::BTreeMap<String, String>,
}

impl Release {
    /// Read the operator's answer.
    pub fn from_answer(v: &Value) -> Result<Self> {
        let version = v["version"]
            .as_str()
            .context("the operator's SDK answer names no version")?
            .to_owned();
        let files = v["files"]
            .as_object()
            .context("the operator's SDK answer carries no files")?
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|s| (k.clone(), s.to_owned()))
                    .with_context(|| format!("SDK file {k} is not text"))
            })
            .collect::<Result<_>>()?;
        let modules = v["modules"]
            .as_array()
            .context("the operator's SDK answer lists no modules")?
            .iter()
            .filter_map(|m| {
                m["name"]
                    .as_str()
                    .map(|n| (n.to_owned(), m["testOnly"].as_bool().unwrap_or(false)))
            })
            .collect();
        let r = Self {
            version,
            modules,
            files,
        };
        for (m, _) in &r.modules {
            // A module name is a path segment below; hold it to the
            // operator's own rule rather than trust it.
            if m.is_empty()
                || !m
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                bail!("the operator names an SDK module {m:?}, which is not a module name");
            }
            if !r.files.contains_key(&format!("{m}.js")) {
                bail!(
                    "the operator's SDK {} lists {m} and sends no {m}.js",
                    r.version
                );
            }
        }
        if !r.files.contains_key("sdk.d.ts") {
            bail!("the operator's SDK {} sends no sdk.d.ts", r.version);
        }
        Ok(r)
    }

    fn types_name(&self) -> String {
        format!("sdk-{}.d.ts", self.version)
    }
}

/// The `tsconfig.json` written beside `function.json` when there is none.
pub const TSCONFIG: &str = r#"{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM"],
    "module": "ES2022",
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "allowJs": true,
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "include": ["src", "test", ".airdress/*.d.ts"]
}
"#;

/// Write the pinned version's types under `.airdress/`, removing any other
/// version's (two versions' ambient modules would conflict), and a
/// `tsconfig.json` when there is none. Returns the paths written.
pub fn write_types(dir: &Path, release: &Release) -> Result<Vec<String>> {
    let local = dir.join(LOCAL_DIR);
    std::fs::create_dir_all(&local).with_context(|| format!("create {}", local.display()))?;
    let name = release.types_name();
    for e in crate::fsx::read_dir(&local)? {
        let e = e?;
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("sdk-") && n.ends_with(".d.ts") && n != name {
            crate::fsx::remove_file(e.path())?;
        }
    }
    crate::fsx::write(local.join(&name), &release.files["sdk.d.ts"])?;
    crate::fsx::write(
        local.join(".gitignore"),
        "# Written by `airdress fn sdk pull` from the operator; never published.\nnode_modules/\n",
    )?;
    let mut written = vec![format!("{LOCAL_DIR}/{name}")];
    let ts = dir.join("tsconfig.json");
    if !ts.exists() {
        std::fs::write(&ts, TSCONFIG).with_context(|| format!("write {}", ts.display()))?;
        written.push("tsconfig.json".into());
    }
    Ok(written)
}

/// The local package's `package.json`.
fn package_json(release: &Release) -> Value {
    let exports: serde_json::Map<String, Value> = release
        .modules
        .iter()
        .map(|(m, _)| (format!("./{m}"), Value::from(format!("./{m}.js"))))
        .collect();
    serde_json::json!({
        "name": "@airdress/functions",
        "version": release.version,
        "private": true,
        "description": "The Airdress Functions SDK, written here by `airdress fn sdk pull` from the operator. Never published; the operator bundles its own compiled-in copy.",
        "type": "module",
        "types": "./index.d.ts",
        "exports": exports,
    })
}

/// Write the pinned version as a local package under
/// `.airdress/node_modules/@airdress/functions/`, and make it resolvable
/// from the function's own files (see the module docs). Returns notes for
/// a person.
pub fn write_package(dir: &Path, release: &Release) -> Result<Vec<String>> {
    let pkg = dir
        .join(LOCAL_DIR)
        .join("node_modules")
        .join("@airdress")
        .join("functions");
    if pkg.exists() {
        std::fs::remove_dir_all(&pkg).with_context(|| format!("replace {}", pkg.display()))?;
    }
    crate::fsx::create_dir_all(&pkg)?;
    for (m, _) in &release.modules {
        crate::fsx::write(
            pkg.join(format!("{m}.js")),
            &release.files[&format!("{m}.js")],
        )?;
    }
    crate::fsx::write(pkg.join("index.d.ts"), &release.files["sdk.d.ts"])?;
    crate::fsx::write(
        pkg.join("package.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&package_json(release))?
        ),
    )?;
    let mut notes = Vec::new();
    notes.extend(link_node_modules(dir)?);
    let pj = dir.join("package.json");
    if !pj.exists() {
        // ES modules for every local runtime, and nothing to install.
        crate::fsx::write(&pj, "{\n  \"private\": true,\n  \"type\": \"module\"\n}\n")?;
        notes.push(
            "wrote package.json (\"type\": \"module\"), for local runs; never published".into(),
        );
    }
    Ok(notes)
}

/// `node_modules` at the root, pointing at `.airdress/node_modules`; or,
/// when a real `node_modules` is there already, `@airdress/functions` inside
/// it pointing at the local package.
fn link_node_modules(dir: &Path) -> Result<Vec<String>> {
    let root = dir.join("node_modules");
    let local = dir.join(LOCAL_DIR).join("node_modules");
    let meta = std::fs::symlink_metadata(&root);
    match meta {
        Err(_) => {
            link(Path::new(".airdress/node_modules"), &root, &local)?;
            Ok(vec![
                "linked node_modules → .airdress/node_modules, so Node, Bun and Deno resolve \
                 @airdress/functions/<module>"
                    .into(),
            ])
        }
        Ok(m) if m.file_type().is_symlink() => Ok(Vec::new()),
        Ok(_) => {
            let scope = root.join("@airdress");
            crate::fsx::create_dir_all(&scope)?;
            let target = scope.join("functions");
            if let Ok(m) = std::fs::symlink_metadata(&target) {
                if !m.file_type().is_symlink() {
                    bail!(
                        "{} exists and is not the local copy; remove it (an npm package there is \
                         not ours: the @airdress scope on npm is reserved and empty)",
                        target.display()
                    );
                }
                crate::fsx::remove_file(&target)?;
            }
            link(
                Path::new("../../.airdress/node_modules/@airdress/functions"),
                &target,
                &local.join("@airdress").join("functions"),
            )?;
            Ok(vec![format!(
                "linked {} → the local copy",
                target.strip_prefix(dir).unwrap_or(&target).display()
            )])
        }
    }
}

#[cfg(unix)]
fn link(relative: &Path, at: &Path, _absolute: &Path) -> Result<()> {
    std::os::unix::fs::symlink(relative, at)
        .with_context(|| format!("link {} → {}", at.display(), relative.display()))
}

#[cfg(not(unix))]
fn link(_relative: &Path, at: &Path, absolute: &Path) -> Result<()> {
    // No unprivileged symlinks: a copy, refreshed by every pull.
    copy_dir(absolute, at)
}

#[cfg(not(unix))]
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    crate::fsx::create_dir_all(to)?;
    for e in crate::fsx::read_dir(from)? {
        let e = e?;
        let t = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &t)?;
        } else {
            crate::fsx::copy(e.path(), &t)?;
        }
    }
    Ok(())
}

/// Source files under `src/` that may import the library.
fn is_source(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("ts" | "mts" | "js" | "mjs")
    )
}

/// Rewrite every quoted `@airdress/functions/<m>` in `text` with `to(m)`.
/// Returns the text and the modules named. Refuses a module `known` does
/// not hold, so a vendored tree never keeps a specifier that no longer
/// resolves.
pub fn rewrite_specifiers(
    text: &str,
    known: &dyn Fn(&str) -> bool,
    to: &dyn Fn(&str) -> String,
) -> Result<(String, Vec<String>)> {
    let mut out = String::with_capacity(text.len());
    let mut named = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(PREFIX) {
        let quote = rest[..i].chars().last();
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let after = &tail[PREFIX.len()..];
        let len = after
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            .count();
        let module = &after[..len];
        let closes = after[len..].chars().next();
        match (quote, closes) {
            (Some(q @ ('"' | '\'')), Some(c)) if c == q && !module.is_empty() => {
                if !known(module) {
                    bail!("{PREFIX}{module} is not a module of the pinned version that can be vendored");
                }
                out.push_str(&to(module));
                named.push(module.to_owned());
                rest = &after[len..];
            }
            _ => {
                // Not a specifier (a comment, a longer string): kept.
                out.push_str(PREFIX);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Ok((out, named))
}

/// What a vendor wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Vendored {
    /// Files written under `src/sdk/`.
    pub modules: Vec<String>,
    /// Tree files whose imports were rewritten.
    pub rewritten: Vec<String>,
}

/// Copy the pinned version's modules into `src/sdk/`, rewrite every
/// library import to a relative one, and remove the pin.
pub fn vendor(dir: &Path, release: &Release) -> Result<Vendored> {
    let src = dir.join("src");
    if !src.is_dir() {
        bail!("{} holds no src/", dir.display());
    }
    let target = src.join(VENDOR_DIR);
    if target.exists() && crate::fsx::read_dir(&target)?.next().is_some() {
        bail!(
            "{} is not empty; the library is vendored there, so move what is in it first",
            target.display()
        );
    }
    let shipped: Vec<&str> = release
        .modules
        .iter()
        .filter(|(_, test_only)| !test_only)
        .map(|(m, _)| m.as_str())
        .collect();
    let known = |m: &str| shipped.contains(&m);

    // The tree first, so a tree importing `testing` stops before anything
    // is written.
    let mut rewrites: Vec<(PathBuf, String, String)> = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(d) = stack.pop() {
        for e in crate::fsx::read_dir(&d)? {
            let e = e?;
            let p = e.path();
            if e.file_type()?.is_dir() {
                stack.push(p);
                continue;
            }
            if !is_source(&p) {
                continue;
            }
            let text = crate::fsx::read_to_string(&p)?;
            if !text.contains(PREFIX) {
                continue;
            }
            let depth = p
                .parent()
                .and_then(|parent| parent.strip_prefix(&src).ok())
                .map_or(0, |r| r.components().count());
            let up = if depth == 0 {
                "./".to_owned()
            } else {
                "../".repeat(depth)
            };
            let rel = p
                .strip_prefix(dir)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            let (new, _) =
                rewrite_specifiers(&text, &known, &|m| format!("{up}{VENDOR_DIR}/{m}.js"))
                    .with_context(|| format!("vendor {rel}"))?;
            rewrites.push((p, new, rel));
        }
    }

    crate::fsx::create_dir_all(&target)?;
    let mut out = Vendored::default();
    for m in &shipped {
        let (text, _) = rewrite_specifiers(&release.files[&format!("{m}.js")], &known, &|n| {
            format!("./{n}.js")
        })?;
        crate::fsx::write(target.join(format!("{m}.js")), text)?;
        out.modules.push(format!("src/{VENDOR_DIR}/{m}.js"));
    }
    rewrites.sort_by(|a, b| a.2.cmp(&b.2));
    for (p, text, rel) in rewrites {
        crate::fsx::write(&p, text)?;
        out.rewritten.push(rel);
    }
    let fj = dir.join("function.json");
    let text = crate::fsx::read_to_string(&fj)?;
    crate::fsx::write(&fj, remove_pin_text(&text)?)?;
    Ok(out)
}

/// The example test a scaffold writes into `test/`, beside `src/`, which a
/// deploy never publishes. `grants` are the worlds the template requires.
pub fn example_test(template: &str, grants: &[String]) -> String {
    if template == "dwell-webhook" {
        return DWELL_TEST.to_owned();
    }
    let granted = grants
        .iter()
        .map(|g| format!("\"{g}\""))
        .collect::<Vec<_>>()
        .join(", ");
    GENERIC_TEST.replace("__GRANTED__", &granted)
}

const RUN_LINES: &str = "// Run it on your own machine — no operator, no deploy — with any of:\n\
//\n\
//   node test/main.test.ts\n\
//   bun test/main.test.ts\n\
//   deno run --node-modules-dir=manual --allow-read test/main.test.ts\n\
//\n\
// once `airdress fn sdk pull` has written the library's local copy (`fn new`\n\
// already did). test/ sits beside src/, so a deploy never publishes it.\n";

const GENERIC_TEST: &str = "// A test of this function against a fake host: the same errors the\n\
// operator's engine throws, with only the worlds you grant here.\n\
//\n\
__RUN__\n\
import { installFakeHost, fakeRequest } from \"@airdress/functions/testing\";\n\
import handler from \"../src/main.ts\";\n\
\n\
const host = installFakeHost({ granted: [__GRANTED__], config: {} });\n\
try {\n\
  const res = await handler(fakeRequest({ url: \"http://fn.local/hello\" }));\n\
  if (res.status >= 500) {\n\
    throw new Error(`the function answered ${res.status}: ${await res.text()}`);\n\
  }\n\
} finally {\n\
  host.restore();\n\
}\n\
console.log(\"ok\");\n";

const DWELL_TEST: &str = "// A test of the stay rule against a fake host: a zone entered, then\n\
// schedule ticks — the webhook is called once, with the stay id as\n\
// Idempotency-Key and no place in the body.\n\
//\n\
__RUN__\n\
import { installFakeHost, cloudEventRequest, tickRequest } from \"@airdress/functions/testing\";\n\
import stayed from \"../src/main.ts\";\n\
\n\
const calls: Array<{ key: string | undefined; body: string }> = [];\n\
const host = installFakeHost({\n\
  granted: [\"kv\", \"http\"],\n\
  httpHosts: [\"hooks.example\"],\n\
  httpRoutes: {\n\
    \"POST https://hooks.example/arrived\": (req) => {\n\
      const key = req.headers.find(([k]) => k === \"idempotency-key\")?.[1];\n\
      calls.push({ key, body: new TextDecoder().decode(req.body) });\n\
      return { status: 202 };\n\
    },\n\
  },\n\
  config: { webhook_url: \"https://hooks.example/arrived\", zone_id: \"z_home\", minutes: 0.001 },\n\
});\n\
const at = new Date().toISOString();\n\
const id = \"0192f4c2-0000-7000-8000-000000000001\";\n\
try {\n\
  await stayed(cloudEventRequest({\n\
    specversion: \"1.0\", id, source: \"/location/phone\", time: at,\n\
    type: \"dev.airdress.location.zone.entered\", datacontenttype: \"application/json\",\n\
    data: { id, at, kind: \"zone\", origin: \"zone_foreground\", enrollment_id: \"phone\",\n\
            zone: { id: \"z_home\", label: \"Home\", transition: \"entered\" } },\n\
  }));\n\
  await new Promise((r) => setTimeout(r, 100));\n\
  await stayed(tickRequest());\n\
  await stayed(tickRequest());\n\
} finally {\n\
  host.restore();\n\
}\n\
if (calls.length !== 1) throw new Error(`the webhook was called ${calls.length} times`);\n\
if (calls[0].key !== id) throw new Error(`Idempotency-Key was ${calls[0].key}`);\n\
if (calls[0].body.includes(\"Home\") || calls[0].body.includes(\"z_home\")) {\n\
  throw new Error(\"the webhook body names the place\");\n\
}\n\
console.log(\"ok\");\n";

/// Write the example test, unless `test/` already has files.
pub fn write_example_test(dir: &Path, template: &str, grants: &[String]) -> Result<Option<String>> {
    let test = dir.join("test");
    if test.exists() && crate::fsx::read_dir(&test)?.next().is_some() {
        return Ok(None);
    }
    crate::fsx::create_dir_all(&test)?;
    let text = example_test(template, grants).replace("__RUN__\n", RUN_LINES);
    crate::fsx::write(test.join("main.test.ts"), text)?;
    Ok(Some("test/main.test.ts".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "{\n  \"apiVersion\": \"airdress.function/v1\",\n  \"id\": \"local.x\",\n  \"minHost\": \"airdress.function-host/1.0\",\n  \"capabilities\": []\n}\n";

    #[test]
    fn a_pin_is_added_after_min_host_and_removed_again() {
        let pinned = set_pin_text(MANIFEST, "1.0.0").unwrap();
        assert!(
            pinned.contains(
                "  \"minHost\": \"airdress.function-host/1.0\",\n  \"sdk\": \"1.0.0\",\n"
            ),
            "{pinned}"
        );
        let v: Value = serde_json::from_str(&pinned).unwrap();
        assert_eq!(v["sdk"], "1.0.0");
        let again = set_pin_text(&pinned, "1.0.1").unwrap();
        assert!(again.contains("\"sdk\": \"1.0.1\""), "{again}");
        assert_eq!(remove_pin_text(&pinned).unwrap(), MANIFEST);
        // Last member: the comma moves.
        let last = "{\n  \"id\": \"local.x\",\n  \"minHost\": \"h\"\n}\n";
        let p = set_pin_text(last, "1.0.0").unwrap();
        assert_eq!(serde_json::from_str::<Value>(&p).unwrap()["sdk"], "1.0.0");
        assert_eq!(remove_pin_text(&p).unwrap(), last);
        // One line: rewritten, still right.
        let one = set_pin_text("{\"id\":\"local.x\"}", "1.0.0").unwrap();
        assert_eq!(serde_json::from_str::<Value>(&one).unwrap()["sdk"], "1.0.0");
    }

    fn release() -> Release {
        Release::from_answer(&serde_json::json!({
            "version": "1.0.0",
            "modules": [
                { "name": "geo" }, { "name": "dwell" }, { "name": "testing", "testOnly": true }
            ],
            "files": {
                "geo.js": "export const geo = 1;\n",
                "dwell.js": "import { geo } from \"@airdress/functions/geo\";\nexport const dwell = geo;\n",
                "testing.js": "export const t = 1;\n",
                "sdk.d.ts": "declare module \"@airdress/functions/geo\" { export const geo: number; }\n",
                "catalogue.json": "{}"
            }
        }))
        .unwrap()
    }

    #[test]
    fn a_hostile_module_name_is_refused() {
        for bad in ["../x", "a/b", ""] {
            let r = Release::from_answer(&serde_json::json!({
                "version": "1.0.0", "modules": [{ "name": bad }],
                "files": { "sdk.d.ts": "", format!("{bad}.js"): "" }
            }));
            assert!(r.is_err(), "{bad}");
        }
    }

    #[test]
    fn types_and_the_local_package_sit_beside_function_json_never_in_src() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("function.json"), MANIFEST).unwrap();
        std::fs::create_dir_all(d.path().join(".airdress")).unwrap();
        std::fs::write(d.path().join(".airdress/sdk-0.9.0.d.ts"), "old").unwrap();
        let written = write_types(d.path(), &release()).unwrap();
        assert_eq!(written, [".airdress/sdk-1.0.0.d.ts", "tsconfig.json"]);
        assert!(
            !d.path().join(".airdress/sdk-0.9.0.d.ts").exists(),
            "one version's types only"
        );
        write_package(d.path(), &release()).unwrap();
        let pkg = d.path().join(".airdress/node_modules/@airdress/functions");
        let pj: Value =
            serde_json::from_str(&std::fs::read_to_string(pkg.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(pj["version"], "1.0.0");
        assert_eq!(pj["exports"]["./geo"], "./geo.js");
        assert!(pkg.join("index.d.ts").is_file());
        #[cfg(unix)]
        assert!(
            d.path()
                .join("node_modules/@airdress/functions/geo.js")
                .is_file(),
            "resolvable from the root"
        );
        // A pull again replaces, and the deploy tree is untouched by all of it.
        write_package(d.path(), &release()).unwrap();
        let (files, ignored) = super::super::layout::select(d.path()).unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), ["function.json"]);
        assert!(ignored.contains(&".airdress/".to_owned()));
        assert!(ignored.contains(&"tsconfig.json".to_owned()));
    }

    #[test]
    fn specifiers_are_rewritten_only_where_they_are_specifiers() {
        let known = |m: &str| m == "geo" || m == "dwell";
        let (t, named) = rewrite_specifiers(
            "import { geo } from \"@airdress/functions/geo\";\n\
             import { dwell } from '@airdress/functions/dwell';\n\
             // see @airdress/functions/geo in the docs\n",
            &known,
            &|m| format!("./sdk/{m}.js"),
        )
        .unwrap();
        assert_eq!(
            t,
            "import { geo } from \"./sdk/geo.js\";\n\
             import { dwell } from './sdk/dwell.js';\n\
             // see @airdress/functions/geo in the docs\n"
        );
        assert_eq!(named, ["geo", "dwell"]);
        assert!(rewrite_specifiers(
            "import x from '@airdress/functions/testing';",
            &known,
            &|m| m.into()
        )
        .is_err());
    }

    #[test]
    fn vendoring_leaves_a_tree_that_refers_to_nothing() {
        let d = tempfile::tempdir().unwrap();
        let fj = "{\n  \"id\": \"local.x\",\n  \"minHost\": \"h\",\n  \"sdk\": \"1.0.0\",\n  \"entry\": \"src/main.ts\"\n}\n";
        std::fs::write(d.path().join("function.json"), fj).unwrap();
        std::fs::create_dir_all(d.path().join("src/lib")).unwrap();
        std::fs::write(
            d.path().join("src/main.ts"),
            "import { dwell } from \"@airdress/functions/dwell\";\nexport default () => dwell;\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("src/lib/where.ts"),
            "import { geo } from '@airdress/functions/geo';\nexport const w = geo;\n",
        )
        .unwrap();
        let v = vendor(d.path(), &release()).unwrap();
        assert_eq!(
            v.modules,
            ["src/sdk/geo.js", "src/sdk/dwell.js"],
            "no test-only module"
        );
        assert_eq!(v.rewritten, ["src/lib/where.ts", "src/main.ts"]);
        let main = std::fs::read_to_string(d.path().join("src/main.ts")).unwrap();
        assert!(main.contains("from \"./sdk/dwell.js\""), "{main}");
        let lib = std::fs::read_to_string(d.path().join("src/lib/where.ts")).unwrap();
        assert!(lib.contains("from '../sdk/geo.js'"), "{lib}");
        let dwell = std::fs::read_to_string(d.path().join("src/sdk/dwell.js")).unwrap();
        assert!(dwell.contains("from \"./geo.js\""), "{dwell}");
        assert!(pin(d.path()).unwrap().is_none());
        // Everything publishable is relative and under src/.
        let (files, _) = super::super::layout::select(d.path()).unwrap();
        for (p, b) in &files {
            assert!(
                !String::from_utf8_lossy(b).contains("from \"@airdress")
                    && !String::from_utf8_lossy(b).contains("from '@airdress"),
                "{p}"
            );
        }
        // Twice: refused, nothing overwritten.
        assert!(vendor(d.path(), &release()).is_err());
    }

    #[test]
    fn a_tree_importing_the_test_module_is_not_vendored() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("function.json"), "{\"sdk\":\"1.0.0\"}").unwrap();
        std::fs::create_dir_all(d.path().join("src")).unwrap();
        std::fs::write(
            d.path().join("src/main.ts"),
            "import { t } from '@airdress/functions/testing';\n",
        )
        .unwrap();
        assert!(vendor(d.path(), &release()).is_err());
        assert!(!d.path().join("src/sdk").exists(), "nothing written");
    }

    #[test]
    fn the_example_test_is_written_once_beside_src() {
        let d = tempfile::tempdir().unwrap();
        let p = write_example_test(d.path(), "hello", &["log".into()]).unwrap();
        assert_eq!(p.as_deref(), Some("test/main.test.ts"));
        let t = std::fs::read_to_string(d.path().join("test/main.test.ts")).unwrap();
        assert!(t.contains("granted: [\"log\"]") && t.contains("node test/main.test.ts"));
        assert!(write_example_test(d.path(), "hello", &[])
            .unwrap()
            .is_none());
        assert!(example_test("dwell-webhook", &[]).contains("Idempotency-Key"));
    }
}
