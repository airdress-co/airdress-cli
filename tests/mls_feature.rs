//! The `mls` feature links the shared MLS engine and it works from here.
//!
//! Compiled to an empty test binary without the feature, which is why
//! CI runs it in its own step with `--features mls`. Two things are
//! checked: this crate canonicalizes the shared delegation vectors to
//! the bytes the phone and the operator expect, and two engines built
//! through `airdress::mls` can form a group and exchange a message.
#![cfg(feature = "mls")]

use airdress::mls::canonical::canonical_delegation_bytes;
use airdress::mls::MlsEngine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Map, Value};

#[test]
fn delegation_vectors_canonicalize_to_the_shared_bytes() {
    let parsed: Value =
        serde_json::from_str(airdress::mls::vectors::DELEGATION).expect("vectors parse");
    let vectors = parsed["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let delegation = vector["delegation"].as_object().expect("delegation");
        let expected = URL_SAFE_NO_PAD
            .decode(vector["canonical_b64url"].as_str().expect("canonical"))
            .expect("canonical decodes");
        assert_eq!(
            canonical_delegation_bytes(delegation).expect("canonicalize"),
            expected,
            "canonical bytes diverge for {name}"
        );
    }
}

/// A root-signed delegation for `session_seed`'s public key.
fn delegation(root: &SigningKey, airdress: &str, session_seed: &[u8; 32]) -> String {
    let session_pub = SigningKey::from_bytes(session_seed)
        .verifying_key()
        .to_bytes();
    let mut obj = Map::new();
    obj.insert("airdress".into(), json!(airdress));
    obj.insert(
        "device_session_public_key".into(),
        json!(URL_SAFE_NO_PAD.encode(session_pub)),
    );
    obj.insert("device_label".into(), json!("cli test"));
    obj.insert("issued_at".into(), json!("2026-10-04T00:00:00Z"));
    obj.insert("role".into(), json!("human_held"));
    let canonical = canonical_delegation_bytes(&obj).expect("canonicalize");
    let signature = root.sign(&canonical);
    obj.insert(
        "signature".into(),
        json!(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
    );
    Value::Object(obj).to_string()
}

fn engine(airdress: &str, seed_byte: u8, dir: &std::path::Path) -> MlsEngine {
    let seed = [seed_byte; 32];
    let root = SigningKey::from_bytes(&[seed_byte.wrapping_add(100); 32]);
    MlsEngine::from_seed(
        airdress,
        &seed,
        &root.verifying_key().to_bytes(),
        &delegation(&root, airdress, &seed),
        dir.to_str().expect("utf-8 temp dir"),
        &[7u8; 32],
    )
    .expect("engine")
}

#[test]
fn two_engines_exchange_a_message() {
    let alice_dir = tempfile::tempdir().expect("dir");
    let bob_dir = tempfile::tempdir().expect("dir");
    let mut alice = engine("alice.test", 1, alice_dir.path());
    let mut bob = engine("bob.test", 2, bob_dir.path());

    let bob_kp = bob.generate_key_package().expect("key package");
    let outcome = alice
        .start_group(&bob_kp, b"hello from the cli", "")
        .expect("start group");
    bob.process_welcome(&outcome.welcome).expect("welcome");
    assert_eq!(
        bob.decrypt(&outcome.group_id, &outcome.first_application, "")
            .expect("decrypt"),
        b"hello from the cli"
    );
}
