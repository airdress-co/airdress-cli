//! The published JSON Schema and the Rust model agree (task 137-F.1): every
//! vector body validates against exactly one branch of the schema, and every
//! invalid body against none. The validator is the subset of draft 2020-12
//! the schema uses, written here so the crate takes no schema dependency.

use airdress_shell_proto::conformance::generate::structured_file;
use airdress_shell_proto::structured::{SCHEMA_ID, SCHEMA_JSON};
use serde_json::Value;

fn resolve<'a>(root: &'a Value, s: &'a Value) -> &'a Value {
    match s.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.strip_prefix("#/$defs/").expect("local ref");
            &root["$defs"][name]
        }
        None => s,
    }
}

fn valid(root: &Value, schema: &Value, v: &Value) -> bool {
    let s = resolve(root, schema);
    if let Some(branches) = s.get("oneOf").and_then(Value::as_array) {
        return branches.iter().filter(|b| valid(root, b, v)).count() == 1;
    }
    if let Some(c) = s.get("const") {
        return v == c;
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        return e.contains(v);
    }
    match s.get("type").and_then(Value::as_str) {
        Some("string") => {
            let Some(t) = v.as_str() else { return false };
            s.get("maxLength")
                .and_then(Value::as_u64)
                .is_none_or(|m| t.chars().count() as u64 <= m)
        }
        Some("boolean") => v.is_boolean(),
        Some("integer") => v.is_i64() || v.is_u64(),
        Some("array") => {
            let Some(a) = v.as_array() else { return false };
            let n = a.len() as u64;
            s.get("minItems")
                .and_then(Value::as_u64)
                .is_none_or(|m| n >= m)
                && s.get("maxItems")
                    .and_then(Value::as_u64)
                    .is_none_or(|m| n <= m)
                && s.get("items")
                    .is_none_or(|i| a.iter().all(|x| valid(root, i, x)))
        }
        Some("object") => {
            let Some(o) = v.as_object() else { return false };
            let props = s["properties"].as_object().expect("properties");
            let required = s["required"].as_array().expect("required");
            required.iter().all(|r| o.contains_key(r.as_str().unwrap()))
                && o.iter()
                    .all(|(k, x)| props.get(k).is_some_and(|p| valid(root, p, x)))
        }
        other => panic!("the schema uses a type this check does not know: {other:?}"),
    }
}

#[test]
fn the_schema_is_the_model() {
    let root: Value = serde_json::from_str(SCHEMA_JSON).expect("the schema is JSON");
    assert_eq!(root["title"], SCHEMA_ID);
    let f = structured_file();
    for b in &f.bodies {
        assert!(
            valid(&root, &root, b),
            "a vector body the schema refuses: {b}"
        );
    }
    for b in &f.invalid {
        assert!(
            !valid(&root, &root, b),
            "an invalid body the schema accepts: {b}"
        );
    }
    // The schema states what a v1 writer emits: a tolerated body is not one,
    // and what a v1 reader re-emits after ignoring its extra field is.
    for b in &f.tolerated {
        assert!(
            !valid(&root, &root, b),
            "the schema accepts a body with a field v1 does not know: {b}"
        );
        let written_back = airdress_shell_proto::structured::Body::from_value(b)
            .expect("a tolerated body decodes")
            .to_value();
        assert!(
            valid(&root, &root, &written_back),
            "a re-emitted body the schema refuses: {written_back}"
        );
    }
    // Every event and input the model has is a branch of the schema, and
    // the other way round.
    let mut in_vectors: Vec<String> = f
        .bodies
        .iter()
        .map(|b| {
            b.get("event")
                .or_else(|| b.get("input"))
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    in_vectors.sort();
    in_vectors.dedup();
    let mut in_schema: Vec<String> = root["$defs"].as_object().unwrap().keys().cloned().collect();
    in_schema.sort();
    assert_eq!(in_vectors, in_schema);
}
