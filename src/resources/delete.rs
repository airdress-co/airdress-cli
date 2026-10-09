//! `airdress delete <Kind>/<name>` (or `-f <file>`) — hard-delete one
//! or more resources.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::ui;

use super::apply::build_client;
use super::client::{parse_ref, DeleteResponse, OperatorResourcesClient};
use super::parse::read_and_parse;

#[derive(Debug)]
pub struct DeleteArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub reference: Option<&'a str>,
    pub file: Option<&'a Path>,
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: DeleteArgs<'_>) -> Result<()> {
    if args.reference.is_some() && args.file.is_some() {
        bail!("--file and a positional reference cannot both be set");
    }
    let refs = resolve_refs(args.reference, args.file)?;
    if refs.is_empty() {
        bail!("nothing to delete — pass a `<Kind>/<name>` argument or `-f <file>`");
    }

    let op = build_client(
        args.paths,
        args.profile,
        args.explicit_airdress,
        args.operator_url,
        args.json,
        args.quiet,
    )
    .await?;

    let mut results: Vec<DeleteResponse> = Vec::with_capacity(refs.len());
    for (kind, name) in refs {
        let r = delete_one(&op, &kind, &name).await?;
        if !args.json {
            let label = if r.action == "deleted" {
                "deleted"
            } else {
                "noop (not found)"
            };
            ui::ok(format!("{}/{} {label}", r.kind, r.name));
        }
        results.push(r);
    }

    if args.json {
        let envelope = serde_json::json!({"deleted": results});
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    }

    Ok(())
}

async fn delete_one(
    op: &OperatorResourcesClient,
    kind: &str,
    name: &str,
) -> Result<DeleteResponse> {
    op.delete(kind, name)
        .await
        .with_context(|| format!("deleting {kind}/{name}"))
}

/// Build the list of `(Kind, name)` pairs to delete. Either a single
/// positional ref or every manifest in a file. File-mode requires both
/// `kind` and `metadata.name` on each document.
fn resolve_refs(reference: Option<&str>, file: Option<&Path>) -> Result<Vec<(String, String)>> {
    if let Some(s) = reference {
        let (kind, name) = parse_ref(s)?;
        let name = name.ok_or_else(|| {
            anyhow::anyhow!(
                "delete requires '<Kind>/<name>' — got '{s}' (Kind-only is too dangerous)"
            )
        })?;
        return Ok(vec![(kind, name)]);
    }
    if let Some(path) = file {
        let docs = read_and_parse(path)?;
        let mut out = Vec::with_capacity(docs.len());
        for (idx, d) in docs.iter().enumerate() {
            let kind = d
                .get("kind")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "document #{} in {}: missing 'kind'",
                        idx + 1,
                        path.display()
                    )
                })?
                .to_owned();
            let name = d
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "document #{} in {}: missing 'metadata.name'",
                        idx + 1,
                        path.display()
                    )
                })?
                .to_owned();
            out.push((kind, name));
        }
        return Ok(out);
    }
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn resolve_refs_positional() {
        let r = resolve_refs(Some("InferencePoolMember/my-nas"), None).unwrap();
        assert_eq!(r, vec![("InferencePoolMember".into(), "my-nas".into())]);
    }

    #[test]
    fn resolve_refs_rejects_kind_only() {
        let err = resolve_refs(Some("InferencePoolMember"), None).unwrap_err();
        assert!(err.to_string().contains("Kind-only"));
    }

    #[test]
    fn resolve_refs_from_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(
            b"\
apiVersion: airdress.co/v1alpha1
kind: InferencePoolMember
metadata: { name: my-nas }
spec: {}
---
apiVersion: airdress.co/v1alpha1
kind: InferencePoolMember
metadata: { name: ai-nas-1 }
spec: {}
",
        )
        .unwrap();
        let r = resolve_refs(None, Some(&path)).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].1, "ai-nas-1");
    }

    #[test]
    fn resolve_refs_rejects_doc_missing_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"apiVersion: airdress.co/v1alpha1\nkind: K\nmetadata: {}\nspec: {}\n")
            .unwrap();
        let err = resolve_refs(None, Some(&path)).unwrap_err();
        assert!(err.to_string().contains("metadata.name"));
    }
}
