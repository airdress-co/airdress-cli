//! Multi-doc YAML / JSON manifest parser per SPEC-033 §8.5.
//!
//! Detection heuristic: if the trimmed input starts with `{` or `[`,
//! treat the whole file as one JSON document. Otherwise parse as a
//! YAML stream, dropping null docs (blank `---` separators in the
//! middle of a file).

use anyhow::{Context, Result};
use serde::Deserialize;

/// Parse a manifest file's contents into N JSON values. Each value
/// is a single manifest (apiVersion + kind + metadata + spec).
///
/// # Errors
///
/// Returns an error if neither JSON nor YAML parses, or if any
/// document is malformed.
pub fn parse_multi_doc(input: &str) -> Result<Vec<serde_json::Value>> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let v: serde_json::Value =
            serde_json::from_str(input).context("manifest is not valid JSON")?;
        return Ok(unwrap_array(v));
    }
    let mut out = Vec::new();
    for de in serde_yaml::Deserializer::from_str(input) {
        let v = serde_json::Value::deserialize(de).context("YAML document is not parseable")?;
        if v.is_null() {
            continue;
        }
        out.push(v);
    }
    Ok(out)
}

/// Read a manifest file from path, then [`parse_multi_doc`] it.
///
/// # Errors
///
/// Returns an error if the file is unreadable or any document fails
/// to parse.
pub fn read_and_parse(path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read manifest file {}", path.display()))?;
    parse_multi_doc(&raw)
}

fn unwrap_array(v: serde_json::Value) -> Vec<serde_json::Value> {
    match v {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_yaml_doc() {
        let docs = parse_multi_doc(
            "apiVersion: airdress.co/v1alpha1\nkind: Test\nmetadata:\n  name: x\nspec: {}\n",
        )
        .unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0]["kind"], "Test");
    }

    #[test]
    fn parses_multi_yaml_doc() {
        let input = "\
---
apiVersion: airdress.co/v1alpha1
kind: Test
metadata: { name: a }
spec: {}
---
apiVersion: airdress.co/v1alpha1
kind: Test
metadata: { name: b }
spec: {}
";
        let docs = parse_multi_doc(input).unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0]["metadata"]["name"], "a");
        assert_eq!(docs[1]["metadata"]["name"], "b");
    }

    #[test]
    fn skips_null_yaml_docs() {
        let input = "\
---
---
apiVersion: airdress.co/v1alpha1
kind: Test
metadata: { name: x }
spec: {}
---
---
";
        let docs = parse_multi_doc(input).unwrap();
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn parses_single_json_object() {
        let input = r#"{"apiVersion":"airdress.co/v1alpha1","kind":"Test","metadata":{"name":"x"},"spec":{}}"#;
        let docs = parse_multi_doc(input).unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0]["kind"], "Test");
    }

    #[test]
    fn parses_json_array() {
        let input = r#"[
            {"apiVersion":"airdress.co/v1alpha1","kind":"Test","metadata":{"name":"a"},"spec":{}},
            {"apiVersion":"airdress.co/v1alpha1","kind":"Test","metadata":{"name":"b"},"spec":{}}
        ]"#;
        let docs = parse_multi_doc(input).unwrap();
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn rejects_garbage() {
        let err = parse_multi_doc("{ broken json").unwrap_err();
        assert!(err.to_string().contains("JSON"));
    }
}
