//! `airdress functions new` — a template's files written out as ordinary
//! source, plus the two blocks of the owner's `Function` manifest the
//! template describes and cannot write itself:
//!
//! - `requires` → `spec.capabilities`: the grants the code needs. Printed,
//!   never applied: the grant is the owner's document.
//! - `config.fields` → `spec.config`: one entry per field. A `secret` field
//!   becomes `valueFrom: { secretRef: … }`, never an inline value.
//! - `events` → `spec.events`: the event source the code is written for.
//!   Binding `source: location` by the owner's apply is the owner's consent
//!   to location events (chat SPEC-114 FR-26); `locationToModels` is left
//!   out, so it stays off.
//!
//! Those blocks are written beside the files as `function.yaml`, the
//! manifest `airdress fn deploy` applies when it creates the function
//! (SPEC-113 FR-6) and shows in full before it does (FR-7). It is the only
//! place a template's `events` survives: a deploy without a `function.yaml`
//! drafts its manifest from `function.json`, which names no events.
//!
//! Nothing is added to the published tree: no marker, no reference to the
//! template. The tree is exactly the template's `files` (`function.yaml` is
//! not part of it), so it publishes like any other tree and never consults
//! the template again.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Write `files` (path → text) under `dir`. Refuses a `dir` that already
/// holds anything: a scaffold that merges into existing work overwrites it.
pub fn write_files(dir: &Path, files: &serde_json::Map<String, Value>) -> Result<Vec<String>> {
    if dir.exists() {
        let mut entries =
            std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "{} is not empty; scaffold into a new or empty directory",
                dir.display()
            );
        }
    }
    let mut written = Vec::with_capacity(files.len());
    for (path, content) in files {
        let rel = Path::new(path);
        // The operator's paths are relative and never climb; hold that
        // here too, so a hostile answer cannot write outside `dir`.
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            bail!("the template names an unsafe path: {path}");
        }
        let text = content
            .as_str()
            .with_context(|| format!("the template's {path} is not text"))?;
        let target = dir.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&target, text).with_context(|| format!("write {}", target.display()))?;
        written.push(path.clone());
    }
    Ok(written)
}

/// A JSON value as a YAML flow scalar (JSON is valid YAML).
fn scalar(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

/// `requires` as the `spec.capabilities` block, indented under `spec:`.
///
/// Each world the template names becomes a key the owner grants. The only
/// world with something to fill in is `http` when `hostsRequired`: the
/// template cannot know the hosts, so the list is left empty and says so.
/// Worlds are read off the document rather than listed here, so a world
/// the operator adds later appears without a client change.
pub fn capabilities_yaml(requires: &Value) -> String {
    let Some(worlds) = requires.as_object().filter(|m| !m.is_empty()) else {
        return "  capabilities: {}   # the template needs no grants\n".into();
    };
    let mut out = String::from("  capabilities:\n");
    for (world, detail) in worlds {
        if world == "http" && detail["hostsRequired"].as_bool() == Some(true) {
            out.push_str(
                "    http:\n      hosts: []   # name every host it may reach; the template cannot know them\n",
            );
        } else {
            out.push_str(&format!("    {world}: {{}}\n"));
        }
    }
    out
}

/// `config.fields` as the `spec.config` block, indented under `spec:`.
pub fn config_yaml(config: &Value) -> String {
    let fields = config["fields"].as_array().cloned().unwrap_or_default();
    if fields.is_empty() {
        return String::new();
    }
    let mut out = String::from("  config:\n");
    for f in &fields {
        let name = f["name"].as_str().unwrap_or("?");
        let kind = f["type"].as_str().unwrap_or("string");
        let required = f["required"].as_bool().unwrap_or(false);
        if let Some(desc) = f["description"].as_str().filter(|d| !d.is_empty()) {
            out.push_str(&format!("    # {}\n", desc.replace('\n', " ")));
        }
        out.push_str(&format!("    - name: {name}\n"));
        if kind == "secret" {
            out.push_str(
                "      valueFrom: { secretRef: <secret-name> }   # a file in the operator's secrets directory, never an inline value\n",
            );
        } else if let Some(default) = f.get("default").filter(|d| !d.is_null()) {
            out.push_str(&format!(
                "      value: {}   # the function's default\n",
                scalar(default)
            ));
        } else {
            let placeholder = match kind {
                "number" => "0",
                "boolean" => "false",
                _ => "\"\"",
            };
            let note = if required {
                "required: set it"
            } else {
                "optional: remove the entry to leave it unset"
            };
            out.push_str(&format!("      value: {placeholder}   # {note}\n"));
        }
    }
    out
}

/// `events` as the `spec.events` block, indented under `spec:`; empty when
/// the template is not written for events.
///
/// Only `source` is written. `locationToModels` is left out (off): letting
/// a location-carrying invocation reach a model is a separate choice the
/// owner makes by adding it.
pub fn events_yaml(events: &Value) -> String {
    let Some(source) = events["source"].as_str().filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let note = if source == "location" {
        "    # Binding this source is your consent: the function receives your phone's location events.\n"
    } else {
        ""
    };
    format!(
        "  events:\n{note}    source: {}\n",
        scalar(&Value::from(source))
    )
}

/// Every block under one `spec:` header, ready to merge into the manifest.
pub fn manifest_fragment(template: &Value) -> String {
    format!(
        "spec:\n{}{}{}",
        capabilities_yaml(&template["requires"]),
        config_yaml(&template["config"]),
        events_yaml(&template["events"])
    )
}

/// The `function.yaml` a scaffold writes: the fragment as a whole Function
/// manifest. `metadata.name` is left to Deploy (`--name`, else the
/// directory's name), and `spec.source` is Deploy's to fill in.
pub fn manifest_yaml(template: &Value, api_version: &str, runtime: &str) -> String {
    let fragment = manifest_fragment(template);
    let body = fragment.strip_prefix("spec:\n").unwrap_or(&fragment);
    format!("apiVersion: {api_version}\nkind: Function\nspec:\n  runtime: {runtime}\n{body}")
}

/// `spec.config` as JSON, for `--output json`.
pub fn config_json(config: &Value) -> Value {
    let fields = config["fields"].as_array().cloned().unwrap_or_default();
    Value::Array(
        fields
            .iter()
            .map(|f| {
                let name = f["name"].clone();
                if f["type"] == "secret" {
                    serde_json::json!({ "name": name, "valueFrom": { "secretRef": null } })
                } else {
                    serde_json::json!({ "name": name, "value": f.get("default").cloned().unwrap_or(Value::Null) })
                }
            })
            .collect(),
    )
}

/// The template whose function serves as a `Hook`. A hook is bound by a second resource the template cannot
/// carry — the operator's source trees hold `function.json` and `src/`
/// only — so the scaffold writes it beside them.
pub const HOOK_TEMPLATE: &str = "hook-validate";

/// The `Hook` manifest that binds a scaffolded hook function, and a README
/// that says how to apply it: `(file name, text)` pairs, written beside the
/// tree and never published. `function` is the Function's `metadata.name`,
/// which a deploy takes from `--name`, else the directory's name.
pub fn hook_companions(template: &str, function: &str) -> Vec<(&'static str, String)> {
    if template != HOOK_TEMPLATE {
        return Vec::new();
    }
    let hook = format!(
        "# Binds the function `{function}` to every apply of an InferencePoolMember.\n\
         # Deploy the function first (`airdress fn deploy`), then:\n\
         #   airdress apply -f hook.yaml\n\
         # A hook function may be granted `log` only; a grant of anything else is\n\
         # refused when this Hook is applied.\n\
         apiVersion: airdress.co/v1alpha1\n\
         kind: Hook\n\
         metadata:\n  name: {function}\n\
         spec:\n\
         \x20 point: airdress.resource.will_apply\n\
         \x20 mode: validate\n\
         \x20 # Only these applies call the function; drop the line to judge every Kind.\n\
         \x20 match: \"data.kind == 'InferencePoolMember'\"\n\
         \x20 # What a timeout or crash does: `ignore` lets the apply through, `fail` refuses it.\n\
         \x20 failurePolicy: ignore\n\
         \x20 timeoutMs: 200\n\
         \x20 handler:\n\
         \x20   function:\n\
         \x20     name: {function}\n"
    );
    let readme = format!(
        "# {function}\n\n\
         A hook function: the operator calls it before an apply and it answers\n\
         `allow`, or `deny` with a reason. Deploy it with `airdress fn deploy`, then\n\
         bind it with the `Hook` beside it: `airdress apply -f hook.yaml`.\n\n\
         `airdress events catalog --points` lists the points a `Hook` can bind.\n\
         Remove the binding with `airdress delete Hook/{function}`; that always\n\
         succeeds, even while the hook refuses everything else.\n"
    );
    vec![("hook.yaml", hook), ("README.md", readme)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> Value {
        serde_json::json!({
            "id": "webhook-relay",
            "title": "Relay a webhook to another operator",
            "entry": "src/main.ts",
            "requires": { "http": { "hostsRequired": true }, "log": {} },
            "config": { "fields": [
                { "name": "target", "type": "string", "description": "The peer URL." },
                { "name": "token", "type": "secret", "required": true, "description": "The peer's bearer." },
                { "name": "greeting", "type": "string", "default": "hello", "description": "The word." },
                { "name": "retries", "type": "number", "required": true, "description": "How often." }
            ] },
            "files": {
                "function.json": "{\"entry\":\"src/main.ts\"}",
                "src/main.ts": "export default () => new Response('a');\n"
            }
        })
    }

    #[test]
    fn requires_becomes_the_capabilities_to_grant() {
        let yaml = capabilities_yaml(&relay()["requires"]);
        assert_eq!(
            yaml,
            "  capabilities:\n    http:\n      hosts: []   # name every host it may reach; the template cannot know them\n    log: {}\n"
        );
        assert_eq!(
            capabilities_yaml(&serde_json::json!({ "kv": {} })),
            "  capabilities:\n    kv: {}\n"
        );
    }

    #[test]
    fn a_secret_field_is_a_secret_ref_never_a_value() {
        let yaml = config_yaml(&relay()["config"]);
        let token = yaml
            .split("- name: token\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap();
        assert!(
            token
                .trim_start()
                .starts_with("valueFrom: { secretRef: <secret-name> }"),
            "{token}"
        );
        assert!(!yaml.contains("token\n      value:"));
        assert!(yaml
            .contains("    - name: greeting\n      value: \"hello\"   # the function's default\n"));
        assert!(yaml.contains("    - name: retries\n      value: 0   # required: set it\n"));
        assert!(yaml.contains("    # The peer's bearer.\n"));
    }

    #[test]
    fn the_fragment_parses_as_yaml_with_the_expected_shape() {
        let text = manifest_fragment(&relay());
        let doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        assert_eq!(
            doc["spec"]["capabilities"]["http"]["hosts"],
            serde_yaml::Value::Sequence(vec![])
        );
        assert!(doc["spec"]["capabilities"]["log"].is_mapping());
        let config = doc["spec"]["config"].as_sequence().unwrap();
        assert_eq!(config.len(), 4);
        assert_eq!(config[1]["name"], "token");
        assert_eq!(config[1]["valueFrom"]["secretRef"], "<secret-name>");
        assert!(config[1].get("value").is_none());
    }

    fn location_status() -> Value {
        serde_json::json!({
            "id": "location-status",
            "title": "Keep a status from your location",
            "entry": "src/main.ts",
            "requires": { "kv": {}, "log": {} },
            "events": { "source": "location" },
            "config": { "fields": [] }
        })
    }

    #[test]
    fn a_template_for_events_writes_the_binding_and_says_it_is_consent() {
        let yaml = events_yaml(&location_status()["events"]);
        assert_eq!(
            yaml,
            "  events:\n    # Binding this source is your consent: the function receives your phone's location events.\n    source: \"location\"\n"
        );
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&manifest_fragment(&location_status())).unwrap();
        assert_eq!(doc["spec"]["events"]["source"], "location");
        // Off unless the owner adds it.
        assert!(doc["spec"]["events"].get("locationToModels").is_none());
        assert!(doc["spec"]["capabilities"]["kv"].is_mapping());
    }

    #[test]
    fn a_template_without_events_binds_none() {
        assert_eq!(events_yaml(&Value::Null), "");
        let doc: serde_yaml::Value = serde_yaml::from_str(&manifest_fragment(&relay())).unwrap();
        assert!(doc["spec"].get("events").is_none());
    }

    #[test]
    fn the_written_manifest_is_a_whole_function_manifest() {
        let text = manifest_yaml(&location_status(), crate::wire::API_VERSION, "js-source/v1");
        let doc: serde_json::Value = serde_yaml::from_str(&text).unwrap();
        assert_eq!(doc["apiVersion"], crate::wire::API_VERSION);
        assert_eq!(doc["kind"], "Function");
        assert_eq!(doc["spec"]["runtime"], "js-source/v1");
        assert_eq!(
            doc["spec"]["events"],
            serde_json::json!({ "source": "location" })
        );
        assert_eq!(
            doc["spec"]["capabilities"],
            serde_json::json!({ "kv": {}, "log": {} })
        );
        // metadata.name and spec.source are Deploy's to fill in.
        assert!(doc.get("metadata").is_none());
        assert!(doc["spec"].get("source").is_none());
        let relay: serde_json::Value =
            serde_yaml::from_str(&manifest_yaml(&relay(), "v", "js-source/v1")).unwrap();
        assert!(relay["spec"].get("events").is_none());
        assert_eq!(relay["spec"]["config"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn the_scaffold_is_exactly_the_template_files() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("fn");
        let t = relay();
        let written = write_files(&out, t["files"].as_object().unwrap()).unwrap();
        assert_eq!(written, ["function.json", "src/main.ts"]);
        let tree = super::super::tree::read_tree(&out).unwrap();
        assert_eq!(tree.len(), 2, "nothing beside the template's files");
        assert_eq!(
            tree["src/main.ts"],
            b"export default () => new Response('a');\n"
        );
    }

    #[test]
    fn a_non_empty_directory_is_not_scaffolded_into() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "mine").unwrap();
        let t = relay();
        assert!(write_files(dir.path(), t["files"].as_object().unwrap()).is_err());
    }

    #[test]
    fn a_hook_template_gets_the_hook_that_binds_it() {
        assert!(hook_companions("hello", "x").is_empty());
        let files = hook_companions(HOOK_TEMPLATE, "require-team");
        let names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["hook.yaml", "README.md"]);
        let hook: serde_json::Value = serde_yaml::from_str(&files[0].1).unwrap();
        assert_eq!(hook["kind"], "Hook");
        assert_eq!(hook["metadata"]["name"], "require-team");
        assert_eq!(hook["spec"]["point"], "airdress.resource.will_apply");
        assert_eq!(hook["spec"]["mode"], "validate");
        assert_eq!(hook["spec"]["match"], "data.kind == 'InferencePoolMember'");
        assert_eq!(hook["spec"]["handler"]["function"]["name"], "require-team");
        assert!(files[1].1.contains("airdress apply -f hook.yaml"));
    }

    #[test]
    fn a_climbing_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = serde_json::Map::new();
        files.insert("../escape.ts".into(), "x".into());
        assert!(write_files(&dir.path().join("fn"), &files).is_err());
    }
}
