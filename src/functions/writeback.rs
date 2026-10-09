//! Writing the served version back into a committed `function.yaml`
//! (SPEC-113 FR-39, D-11, design §8.6).
//!
//! After a promote, the manifest in git still names the old version, and it
//! is the next run's `basedOn`. So exactly one scalar is rewritten —
//! `spec.source.version` — and every other byte stays: comments, key
//! order, quoting, blank lines. The rewrite is proven before the disk is
//! touched: the result is parsed again and must equal the original with
//! exactly that one path changed. Anything else aborts, and the caller
//! stops with `write_back_failed`, naming the line to commit by hand.
//!
//! The locator reads block-style YAML only (`spec:` → `source:` →
//! `version:`), which is the form every client writes. A manifest in flow
//! style is not rewritten: it aborts, it is never reformatted.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// The line a person commits by hand when the rewrite cannot be made.
pub fn manual_line(version: &str) -> String {
    format!("spec.source.version: \"{version}\"")
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn is_content(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// The `key:` on `line`, if the line is a mapping key at its indent.
fn key_of(line: &str) -> Option<&str> {
    let t = line.trim_start_matches(' ');
    let (key, rest) = t.split_once(':')?;
    let key = key.trim_matches(|c| c == '"' || c == '\'');
    (rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')).then_some(key)
}

/// Within lines `[from, to)`, the line of `key` among the children at the
/// block's own indent; and the end of that child's block.
fn child(lines: &[&str], from: usize, to: usize, key: &str) -> Option<(usize, usize)> {
    let first = (from..to).find(|&i| is_content(lines[i]))?;
    let indent = indent_of(lines[first]);
    let mut found = None;
    for (i, line) in lines.iter().enumerate().take(to).skip(first) {
        if !is_content(line) {
            continue;
        }
        let ind = indent_of(line);
        if ind < indent {
            break;
        }
        if ind == indent {
            if let Some(start) = found {
                return Some((start, i));
            }
            if key_of(line) == Some(key) {
                found = Some(i);
            }
        }
    }
    found.map(|start| (start, to))
}

/// Replace the scalar after `version:` on `line`, keeping its quoting and
/// any trailing comment.
fn replace_scalar(line: &str, new: &str) -> Option<String> {
    let colon = line.find(':')?;
    let (head, rest) = line.split_at(colon + 1);
    let lead = rest.len() - rest.trim_start().len();
    let (spaces, value) = rest.split_at(lead);
    let (token_len, quote) = match value.chars().next()? {
        q @ ('"' | '\'') => (value[1..].find(q)? + 2, Some(q)),
        _ => {
            let end = value.find(" #").unwrap_or(value.len());
            let plain = value[..end].trim_end();
            if plain.is_empty() || plain.starts_with(['{', '[', '&', '*', '!', '|', '>']) {
                return None;
            }
            (plain.len(), None)
        }
    };
    let token = match quote {
        Some(q) => format!("{q}{new}{q}"),
        None => new.to_owned(),
    };
    Some(format!("{head}{spaces}{token}{}", &value[token_len..]))
}

/// `text` with `spec.source.version` set to `new`, every other byte kept.
/// `Err` says why the rewrite was refused; nothing is written then.
pub fn rewrite_version(text: &str, new: &str) -> Result<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let n = lines.len();
    let Some((spec, spec_end)) = child(&lines, 0, n, "spec") else {
        bail!("no block-style `spec:` mapping at the top level");
    };
    let Some((source, source_end)) = child(&lines, spec + 1, spec_end, "source") else {
        bail!("no block-style `spec.source:` mapping");
    };
    let Some((version, _)) = child(&lines, source + 1, source_end, "version") else {
        bail!("`spec.source` has no `version:` line to rewrite");
    };
    let Some(replaced) = replace_scalar(lines[version], new) else {
        bail!(
            "`spec.source.version` on line {} is not a plain or quoted scalar",
            version + 1
        );
    };
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
    out[version] = replaced;
    let out = out.join("\n");

    // The proof: the result is the original with exactly one path changed.
    let mut expected: Value =
        serde_yaml::from_str(text).context("the manifest does not parse as YAML")?;
    expected
        .pointer_mut("/spec/source/version")
        .map(|v| *v = Value::String(new.to_owned()))
        .context("the manifest has no spec.source.version")?;
    let actual: Value =
        serde_yaml::from_str(&out).context("the rewritten manifest does not parse")?;
    if actual != expected {
        bail!("the rewrite would change more than spec.source.version; refusing it");
    }
    Ok(out)
}

/// Where the block of the key on line `at` ends: the next content line at
/// its indent or shallower, except a `- ` sequence item at exactly its
/// indent (the compact style `serde_yaml` writes).
fn block_end(lines: &[&str], at: usize, to: usize) -> usize {
    let indent = indent_of(lines[at]);
    for (i, line) in lines.iter().enumerate().take(to).skip(at + 1) {
        if !is_content(line) {
            continue;
        }
        let ind = indent_of(line);
        let item = line.trim_start_matches(' ').starts_with("- ") || line.trim() == "-";
        if ind < indent || (ind == indent && !item) {
            // Keep trailing blank or comment lines with what follows.
            let mut end = i;
            while end > at + 1 && !is_content(lines[end - 1]) {
                end -= 1;
            }
            return end;
        }
    }
    let mut end = to;
    while end > at + 1 && !is_content(lines[end - 1]) {
        end -= 1;
    }
    end
}

/// `text` with `spec.source.signers` set to `members` (each `{key}` or
/// `{machine}`), and a single `signer` / `signerRef` it replaces removed.
/// Every other byte stays; the result is proven by parsing it again.
pub fn rewrite_signers(text: &str, members: &[Value]) -> Result<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let n = lines.len();
    let Some((spec, spec_end)) = child(&lines, 0, n, "spec") else {
        bail!("no block-style `spec:` mapping at the top level");
    };
    let Some((source, source_end)) = child(&lines, spec + 1, spec_end, "source") else {
        bail!("no block-style `spec.source:` mapping");
    };
    let first = (source + 1..source_end)
        .find(|&i| is_content(lines[i]))
        .context("`spec.source` is empty")?;
    let indent = indent_of(lines[first]);
    // The blocks to drop, and where the new one goes.
    let mut drop: Vec<(usize, usize)> = Vec::new();
    let mut item_indent = indent;
    for i in first..source_end {
        let line = lines[i];
        if !is_content(line) || indent_of(line) != indent {
            continue;
        }
        if let Some(k @ ("signers" | "signer" | "signerRef")) = key_of(line) {
            let end = block_end(&lines, i, source_end);
            if k == "signers" {
                if let Some(item) = (i + 1..end).find(|&j| is_content(lines[j])) {
                    item_indent = indent_of(lines[item]);
                }
            }
            drop.push((i, end));
        }
    }
    let pad = " ".repeat(indent);
    let item_pad = " ".repeat(item_indent);
    let mut block = vec![format!("{pad}signers:")];
    for m in members {
        let (k, v) = match (m.get("key"), m.get("machine")) {
            (Some(Value::String(k)), None) => ("key", k),
            (None, Some(Value::String(v))) => ("machine", v),
            _ => bail!("a signer member is exactly one of key or machine"),
        };
        block.push(format!("{item_pad}- {k}: {v}"));
    }
    let insert_at = drop
        .first()
        .map_or(source_end_of(&lines, first, source_end), |d| d.0);
    let mut out: Vec<String> = Vec::with_capacity(n + members.len());
    let mut i = 0;
    while i < n {
        if i == insert_at {
            out.extend(block.iter().cloned());
        }
        if let Some(&(_, end)) = drop.iter().find(|d| d.0 == i) {
            i = end;
            continue;
        }
        out.push(lines[i].to_owned());
        i += 1;
    }
    if insert_at >= n {
        out.extend(block);
    }
    let out = out.join("\n");

    let mut expected: Value =
        serde_yaml::from_str(text).context("the manifest does not parse as YAML")?;
    let src = expected
        .pointer_mut("/spec/source")
        .and_then(Value::as_object_mut)
        .context("the manifest has no spec.source")?;
    src.remove("signer");
    src.remove("signerRef");
    src.insert("signers".into(), Value::Array(members.to_vec()));
    let actual: Value =
        serde_yaml::from_str(&out).context("the rewritten manifest does not parse")?;
    if actual != expected {
        bail!("the rewrite would change more than spec.source.signers; refusing it");
    }
    Ok(out)
}

/// The line after the last content line of `spec.source`'s children.
fn source_end_of(lines: &[&str], first: usize, source_end: usize) -> usize {
    let mut end = source_end;
    while end > first + 1 && !is_content(lines[end - 1]) {
        end -= 1;
    }
    end
}

/// The version a manifest file names.
pub fn version_of(manifest: &Value) -> Option<&str> {
    manifest
        .pointer("/spec/source/version")
        .and_then(Value::as_str)
}

/// Rewrite `path` in place, atomically (a sibling file renamed over it).
pub fn write_back(path: &Path, new: &str) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let out = rewrite_version(&text, new).with_context(|| format!("{}", path.display()))?;
    write_atomically(path, out.as_bytes())
}

/// Write `bytes` to `path` through a sibling temporary file and a rename,
/// so a crash leaves the old file or the new one.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".airdress-tmp");
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"# The relay, deployed by CI.
apiVersion: airdress.co/v1alpha1
kind: Function
metadata:
  name: relay-v2   # the route
spec:
  runtime: js-source/v1
  source:
    # the serving version; the next basedOn
    version: "sha256:1111"   # written back by CI
    signers:
      - key: "5c1e"
      - machine: "0b7e3c1a"
  capabilities:
    http: { hosts: ["peer.example"] }
    log: {}
  config:
    - name: version
      value: "not this one"
  enabled: true
"#;

    #[test]
    fn exactly_one_scalar_changes_and_every_other_byte_stays() {
        let out = rewrite_version(MANIFEST, "sha256:2222").unwrap();
        let before: Vec<&str> = MANIFEST.lines().collect();
        let after: Vec<&str> = out.lines().collect();
        assert_eq!(before.len(), after.len());
        let changed: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        assert_eq!(changed, [9]);
        assert_eq!(
            after[9],
            "    version: \"sha256:2222\"   # written back by CI"
        );
        assert!(out.ends_with("enabled: true\n"));
    }

    #[test]
    fn plain_and_single_quoted_scalars_keep_their_style() {
        let plain = "spec:\n  source:\n    version: sha256:1111\n    signers: []\n";
        assert_eq!(
            rewrite_version(plain, "sha256:2").unwrap(),
            "spec:\n  source:\n    version: sha256:2\n    signers: []\n"
        );
        let single = "spec:\n  source:\n    version: 'sha256:1' # c\n";
        assert_eq!(
            rewrite_version(single, "sha256:2").unwrap(),
            "spec:\n  source:\n    version: 'sha256:2' # c\n"
        );
    }

    #[test]
    fn a_manifest_it_cannot_prove_is_never_rewritten() {
        // Flow style: refused, not reformatted.
        assert!(rewrite_version("spec: { source: { version: a } }\n", "b").is_err());
        // No version line to replace.
        assert!(rewrite_version("spec:\n  source:\n    signers: []\n", "b").is_err());
        // A `version` elsewhere is not the one.
        let elsewhere = "metadata:\n  version: x\nspec:\n  runtime: js-source/v1\n";
        assert!(rewrite_version(elsewhere, "b").is_err());
    }

    #[test]
    fn the_file_is_replaced_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("function.yaml");
        std::fs::write(&path, MANIFEST).unwrap();
        write_back(&path, "sha256:3333").unwrap();
        let v: Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(version_of(&v), Some("sha256:3333"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[cfg(test)]
mod signer_tests {
    use super::rewrite_signers;
    use serde_json::json;

    const COMPACT: &str = "apiVersion: airdress.co/v1alpha1\nkind: Function\nmetadata:\n  name: e2e-hello\nspec:\n  capabilities:\n    log: {}\n  # who may sign\n  source:\n    signers:\n    - key: aa\n    version: sha256:1\n  enabled: true\n";

    #[test]
    fn a_member_is_added_and_every_other_byte_stays() {
        let out =
            rewrite_signers(COMPACT, &[json!({"key": "aa"}), json!({"machine": "m-1"})]).unwrap();
        assert_eq!(
            out,
            COMPACT.replace("    - key: aa\n", "    - key: aa\n    - machine: m-1\n")
        );
    }

    #[test]
    fn a_member_is_removed() {
        let two = COMPACT.replace("    - key: aa\n", "    - key: aa\n    - machine: m-1\n");
        assert_eq!(
            rewrite_signers(&two, &[json!({"key": "aa"})]).unwrap(),
            COMPACT
        );
    }

    #[test]
    fn a_single_signer_becomes_the_set_in_its_place() {
        let single = "spec:\n  source:\n    version: \"sha256:1\"  # pinned\n    signer: aa\n";
        let out =
            rewrite_signers(single, &[json!({"key": "aa"}), json!({"machine": "m"})]).unwrap();
        assert_eq!(
            out,
            "spec:\n  source:\n    version: \"sha256:1\"  # pinned\n    signers:\n    - key: aa\n    - machine: m\n"
        );
    }

    #[test]
    fn indented_items_keep_their_style() {
        let text = "spec:\n  source:\n    signers:\n      - key: aa\n    version: v\n";
        let out = rewrite_signers(text, &[json!({"key": "bb"})]).unwrap();
        assert_eq!(
            out,
            "spec:\n  source:\n    signers:\n      - key: bb\n    version: v\n"
        );
    }

    #[test]
    fn flow_style_is_refused_not_reformatted() {
        assert!(rewrite_signers("spec: {source: {version: v}}\n", &[json!({"key": "a"})]).is_err());
    }
}
