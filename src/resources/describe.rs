//! `airdress describe <Kind>/<name>` — read one resource plus the
//! computed phase from its status subresource. The output mirrors
//! `kubectl describe` shape: top-line summary, conditions table, then
//! the spec/status payload as YAML.

use anyhow::{bail, Result};

use super::apply::build_client;
use super::client::{parse_ref, OperatorResourcesClient, ResourceView, StatusResponse};

#[derive(Debug)]
pub struct DescribeArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub reference: &'a str,
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: DescribeArgs<'_>) -> Result<()> {
    let (kind, name) = parse_ref(args.reference)?;
    let name = name.ok_or_else(|| {
        anyhow::anyhow!(
            "describe requires '<Kind>/<name>' — got '{}'",
            args.reference
        )
    })?;

    let op = build_client(
        args.paths,
        args.profile,
        args.explicit_airdress,
        args.operator_url,
        args.json,
        args.quiet,
    )
    .await?;

    let (view, status) = fetch(&op, &kind, &name).await?;

    if args.json {
        let envelope = serde_json::json!({
            "resource": serde_json::to_value(serde_json::json!({
                "apiVersion": view.api_version,
                "kind": view.kind,
                "metadata": {
                    "name": view.metadata.name,
                    "generation": view.metadata.generation,
                    "observedGeneration": view.metadata.observed_generation,
                    "resourceVersion": view.metadata.resource_version,
                    "labels": view.metadata.labels,
                    "createdAt": view.metadata.created_at,
                    "updatedAt": view.metadata.updated_at,
                    "lastReconciledAt": view.metadata.last_reconciled_at,
                },
                "spec": view.spec,
                "status": view.status,
            }))?,
            "phase": status.phase,
            "conditions": status.conditions,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    render_text(&view, &status);
    Ok(())
}

async fn fetch(
    op: &OperatorResourcesClient,
    kind: &str,
    name: &str,
) -> Result<(ResourceView, StatusResponse)> {
    let view = op.get_one(kind, name).await?;
    let status = op.get_status(kind, name).await?;
    if view.kind != status.kind || view.metadata.name != status.name {
        // Defensive: route mounts differ → bail loudly rather than
        // print a misleading object.
        bail!(
            "operator returned mismatched view vs status: {}/{} != {}/{}",
            view.kind,
            view.metadata.name,
            status.kind,
            status.name
        );
    }
    Ok((view, status))
}

fn render_text(view: &ResourceView, status: &StatusResponse) {
    println!("Name:        {}", view.metadata.name);
    println!("Kind:        {}", view.kind);
    println!("APIVersion:  {}", view.api_version);
    println!("Phase:       {}", status.phase);
    println!("Generation:  {}", view.metadata.generation);
    println!(
        "ObservedGen: {}",
        view.metadata
            .observed_generation
            .map_or_else(|| "—".to_string(), |g| g.to_string())
    );
    println!("RV:          {}", view.metadata.resource_version);
    println!(
        "LastRecon:   {}",
        view.metadata
            .last_reconciled_at
            .map_or_else(|| "—".to_string(), |t| t.to_rfc3339())
    );
    println!();
    if status.conditions.is_empty() {
        println!("Conditions:  (none)");
    } else {
        println!("Conditions:");
        let w_type = status
            .conditions
            .iter()
            .map(|c| c.ty.len())
            .max()
            .unwrap_or(4)
            .max(4);
        let w_status = status
            .conditions
            .iter()
            .map(|c| c.status.len())
            .max()
            .unwrap_or(6)
            .max(6);
        let w_reason = status
            .conditions
            .iter()
            .map(|c| c.reason.len())
            .max()
            .unwrap_or(6)
            .max(6);
        println!(
            "  {:<t$}  {:<s$}  {:<r$}  MESSAGE",
            "TYPE",
            "STATUS",
            "REASON",
            t = w_type,
            s = w_status,
            r = w_reason
        );
        for c in &status.conditions {
            println!(
                "  {:<t$}  {:<s$}  {:<r$}  {}",
                c.ty,
                c.status,
                c.reason,
                c.message,
                t = w_type,
                s = w_status,
                r = w_reason
            );
        }
    }

    println!();
    println!("Spec:");
    print_yaml_indented(&view.spec, "  ");
    println!();
    println!("Status:");
    print_yaml_indented(&view.status, "  ");
}

fn print_yaml_indented(v: &serde_json::Value, indent: &str) {
    let yaml = serde_yaml::to_string(v).unwrap_or_else(|_| "(failed to render YAML)".into());
    for line in yaml.lines() {
        println!("{indent}{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn empty_view() -> ResourceView {
        ResourceView {
            api_version: crate::wire::API_VERSION.into(),
            kind: "Test".into(),
            metadata: super::super::client::ResourceMetadata {
                name: "x".into(),
                generation: 1,
                observed_generation: None,
                resource_version: "1".into(),
                labels: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_reconciled_at: None,
            },
            spec: serde_json::json!({}),
            status: serde_json::json!({}),
        }
    }

    #[test]
    fn render_text_doesnt_panic_with_empty_status() {
        let v = empty_view();
        let s = StatusResponse {
            kind: "Test".into(),
            name: "x".into(),
            generation: 1,
            observed_generation: None,
            phase: "Pending".into(),
            conditions: vec![],
            last_reconciled_at: None,
        };
        render_text(&v, &s);
    }

    #[test]
    fn render_text_doesnt_panic_with_conditions() {
        let v = empty_view();
        let s = StatusResponse {
            kind: "Test".into(),
            name: "x".into(),
            generation: 1,
            observed_generation: Some(1),
            phase: "Failed".into(),
            conditions: vec![super::super::client::Condition {
                ty: "Healthy".into(),
                status: "False".into(),
                last_transition_time: Utc::now(),
                reason: "Unreachable".into(),
                message: "connect: timed out".into(),
            }],
            last_reconciled_at: None,
        };
        render_text(&v, &s);
    }
}
