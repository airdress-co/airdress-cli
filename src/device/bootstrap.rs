//! SPEC-056 — `airdress device bootstrap`.
//!
//! Onboards the FIRST device on a fresh operator: one with no owner
//! bound yet, so `device pair` (SPEC-044) cannot help — it mints a
//! pairing code via an already-authenticated owner, and there isn't
//! one. The only credential that can unlock a fresh operator is the
//! bootstrap token, an admin secret the release chat app is
//! deliberately built to never expose (SPEC-005 NFR-1). Until this
//! command existed, the *only* thing that could redeem it was the
//! app's own debug build.
//!
//! This performs the same enrollment ceremony as `airdress-operator
//! chat pair` (the operator's own admin binary) and the wire format
//! `spec012_round_trip_test.dart`'s `_enroll()` helper hand-rolls in
//! `airdress-chat`: load or generate the airdress's long-lived
//! Ed25519 root keypair (SPEC-054 — see [`super::root_key`]), generate
//! a fresh session keypair, sign a delegation, `POST
//! /v1/endpoints/enrollments` with the bootstrap token. All three
//! implementations now agree byte-for-byte with
//! `crates/airdress-operator/src/enrollment/routes.rs`.
//!
//! The root keypair is persisted (SPEC-054 FR-14): the operator pins
//! the root public key on first enrollment and 409s any later
//! enrollment presenting a different root, so dropping the root — the
//! pre-SPEC-054 behaviour here — would make every second run fail. A
//! freshly generated root is stored only after the operator accepts
//! the enrollment; a rejected root is never persisted.
//!
//! Deliberately does NOT write into the CLI's hub-auth profile store
//! (`src/profile/storage.rs`). That store holds a *human's* ZITADEL
//! session; the credential this command produces is a *device's*
//! operator session token, a different kind of secret with a
//! different lifecycle. Print it — same contract `chat pair` already
//! has, and the same one a script capturing stdout needs.

use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::http;
use crate::ui;

use super::client::SecretString;

#[derive(Debug)]
pub struct BootstrapArgs<'a> {
    /// Where the CLI's files are: the root key and device id live under
    /// its data directory.
    pub paths: &'a crate::paths::Paths,
    pub operator_url: &'a str,
    pub airdress: &'a str,
    pub bootstrap_token: SecretString,
    pub label: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

#[derive(Debug)]
struct Enrollment {
    enrollment_id: Uuid,
    token: SecretString,
    airdress_chat_uri: String,
}

pub async fn run(args: BootstrapArgs<'_>) -> anyhow::Result<()> {
    let label = args.label.unwrap_or("CLI-bootstrapped device");

    if !args.json && !args.quiet {
        ui::note(format!(
            "bootstrapping {:?} against {}",
            args.airdress, args.operator_url
        ));
    }

    let mut rng = rand::rngs::OsRng;

    // The ROOT keypair is the airdress's long-lived identity — reuse a
    // persisted one so the operator's pinned root matches (SPEC-054
    // FR-14). Only a fresh one needs persisting, and only after a 201.
    let (root_key, root_is_fresh) = match super::root_key::load(args.paths, args.airdress)? {
        Some(key) => {
            if !args.json && !args.quiet {
                ui::note(format!("using the stored root key for {:?}", args.airdress));
            }
            (key, false)
        }
        None => {
            let mut root_seed = [0u8; 32];
            rng.fill_bytes(&mut root_seed);
            (SigningKey::from_bytes(&root_seed), true)
        }
    };

    // The SESSION keypair is per-enrollment and stays ephemeral.
    let mut sess_seed = [0u8; 32];
    rng.fill_bytes(&mut sess_seed);
    let sess_key = SigningKey::from_bytes(&sess_seed);

    let root_pk = root_key.verifying_key().to_bytes();
    let sess_pk = sess_key.verifying_key().to_bytes();

    // SPEC-061 FR-15/FR-16: the delegation binds a STABLE per-device
    // identifier, read-or-created from durable storage. Deriving it from
    // `sess_pk` would be wrong — that key is fresh on every run, so
    // every re-bootstrap would present as a new member and
    // `valid_successor` would reject it.
    let device_id = super::device_id::load_or_create(args.paths, args.airdress)?;

    let delegation = build_delegation(&root_key, &sess_pk, args.airdress, label, &device_id);

    let url = format!(
        "{}/v1/endpoints/enrollments",
        args.operator_url.trim_end_matches('/')
    );
    let body = json!({
        "airdress": args.airdress,
        "role": "human_held",
        "key_custody": "client_held",
        "device_label": label,
        "device_session_public_key": b64(&sess_pk),
        "airdress_root_public_key": b64(&root_pk),
        "delegation": delegation,
        "transport_profile": "qr",
        "bootstrap_token": args.bootstrap_token.expose(),
    });

    let client = http::client_builder()
        .build()
        .map_err(anyhow::Error::from)?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| http::format_transport_error(&url, "POST", e))?;

    // http::handle_status's 401 message ("session expired — run `airdress
    // auth login`") is right for every other caller in this CLI, which all
    // authenticate with a hub OAuth session. Bootstrap has no session —
    // it's a shared secret configured on the operator — so that message
    // would send the user to fix a problem they don't have. Handle 401
    // here with the actually-relevant fix; defer everything else to the
    // shared handler.
    if resp.status().as_u16() == 401 {
        let body = resp.text().await.unwrap_or_default();
        let suffix = if body.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", body.trim())
        };
        return Err(crate::exit::Failure::http(
            401,
            "bootstrap_rejected",
            format!(
                "bootstrap rejected — the operator did not accept this bootstrap token{suffix}. \
                 Check enrollment.bootstrap_token in the operator's config, or that \
                 AIRDRESS_BOOTSTRAP_TOKEN / --bootstrap-token match it."
            ),
        )
        .with_hint(
            "check AIRDRESS_BOOTSTRAP_TOKEN / --bootstrap-token against the operator's config",
        )
        .into());
    }
    // 409 root_key_mismatch (SPEC-054): the operator has already pinned
    // a root key for this airdress and it differs from the one we hold.
    // handle_status's generic conflict message can't explain that, and
    // the fix is never "retry" — it's the original device or the
    // operator admin's break-glass.
    if resp.status().as_u16() == 409 {
        let body = resp.text().await.unwrap_or_default();
        let code = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v["error"]["code"].as_str().map(str::to_owned));
        if code.as_deref() == Some("root_key_mismatch") {
            return Err(crate::exit::Failure::http(
                409,
                "root_key_mismatch",
                format!(
                    "enrollment refused — {:?} already has a pinned root key on this operator, \
                 and it differs from the one this device holds. Either enroll from the \
                 device that performed the original bootstrap (it holds the pinned root \
                 key), or have the operator admin run \
                 `airdress-operator endpoint reset-root {}` (break-glass: revokes every \
                 device for this airdress) and bootstrap again.",
                    args.airdress, args.airdress
                ),
            )
            .into());
        }
        let suffix = if body.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", body.trim())
        };
        return Err(crate::exit::Failure::http(
            409,
            code.unwrap_or_else(|| "http_409".to_owned()),
            format!("bootstrap enrollment conflict (HTTP 409){suffix}"),
        )
        .into());
    }
    let resp = http::handle_status(resp, "bootstrap enrollment").await?;

    // The operator accepted this root — NOW it is safe to persist a
    // fresh one. Persisting before the 201 would wedge later runs on a
    // root the operator never pinned.
    let root_key_file = if root_is_fresh {
        match super::root_key::persist(args.paths, args.airdress, &root_key)? {
            super::root_key::Persisted::Keyring => None,
            super::root_key::Persisted::File(path) => Some(path),
        }
    } else {
        None
    };

    let payload: Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("parse enrollment response: {e}"))?;

    let enrollment = Enrollment {
        enrollment_id: payload["enrollment_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("enrollment response carried no enrollment_id"))?,
        token: SecretString::from(
            payload["token"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("enrollment response carried no token"))?
                .to_owned(),
        ),
        airdress_chat_uri: payload["airdress_chat_uri"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    };

    if args.json {
        let mut envelope = json!({
            "airdress": args.airdress,
            "operator_url": args.operator_url,
            "enrollment_id": enrollment.enrollment_id,
            "token": enrollment.token,
            "airdress_chat_uri": enrollment.airdress_chat_uri,
        });
        if let Some(path) = &root_key_file {
            // FR-14: no keyring on this host — the user must learn a
            // long-lived private key landed on disk. stdout is JSON
            // here, so it rides in the envelope.
            envelope["root_key_file"] = json!(path.display().to_string());
        }
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        if let Some(path) = &root_key_file {
            // FR-14's "loud file": no OS keyring was available, so the
            // root PRIVATE key now lives on disk. Say so on stdout — a
            // user who doesn't know it's there cannot protect it.
            println!(
                "root key stored on disk (no OS keyring available): {}",
                path.display()
            );
            println!(
                "this file is the long-lived PRIVATE key for {:?} — protect it like a password.",
                args.airdress
            );
        }
        ui::ok(format!(
            "bootstrapped as {:?} (enrollment: {})",
            label, enrollment.enrollment_id
        ));
        println!();
        println!("{}", enrollment.token.expose());
        println!();
        ui::note(
            "the line above is the device's session token — store it now, \
             it cannot be recovered after this point. Anything speaking the \
             operator's API can use it as a Bearer token from here on.",
        );
        if !enrollment.airdress_chat_uri.is_empty() {
            println!();
            ui::note(format!(
                "airdress-chat can also consume this deeplink directly: {}",
                enrollment.airdress_chat_uri
            ));
        }
    }

    Ok(())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// How long a delegation this CLI mints stays valid (SPEC-061 FR-15).
///
/// 180 days, matching `airdress-chat`'s `signDelegation` and the
/// `DEFAULT_DELEGATION_LIFETIME` the crate documents. The value is
/// inside the signed object, so it cannot be lengthened after the fact.
const DELEGATION_LIFETIME_DAYS: i64 = 180;

/// JCS-sorted delegation object signed by the airdress root key.
///
/// Field-for-field identical to `build_delegation` in
/// `airdress-operator/src/cli/chat.rs` — the operator verifies this
/// signature, so drifting from that shape fails enrollment, not this
/// function.
///
/// This mints the SPEC-061 `v: 2` form: the `v: 1` fields plus
/// `device_id` and `expires_at`. Version is inferred by the verifier
/// from the presence of both fields (`credential.rs`'s
/// `parse_identity`), so there is no explicit `v` key. Both are inside
/// the signed object — they go in *before* `sort_keys()` and before the
/// signature is computed, or `verify_chain` covers different bytes than
/// the ones on the wire and enrollment fails signature validation.
///
/// Without them the CLI cannot enroll once `chat.mls_v2_cutover` is on:
/// a `v: 1` identity is rejected with `LegacyIdentityRejected`.
fn build_delegation(
    root_key: &SigningKey,
    sess_pk: &[u8; 32],
    airdress: &str,
    device_label: &str,
    device_id: &str,
) -> Value {
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::days(DELEGATION_LIFETIME_DAYS);
    delegation_object(
        root_key,
        sess_pk,
        airdress,
        device_label,
        device_id,
        &issued_at.to_rfc3339(),
        &expires_at.to_rfc3339(),
    )
}

/// The clock-free half of [`build_delegation`], so a test can pin the
/// two timestamps and compare against the shared canonicalization
/// fixture byte for byte.
fn delegation_object(
    root_key: &SigningKey,
    sess_pk: &[u8; 32],
    airdress: &str,
    device_label: &str,
    device_id: &str,
    issued_at: &str,
    expires_at: &str,
) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("airdress".to_owned(), json!(airdress));
    obj.insert("device_id".to_owned(), json!(device_id));
    obj.insert("device_label".to_owned(), json!(device_label));
    obj.insert("device_session_public_key".to_owned(), json!(b64(sess_pk)));
    obj.insert("expires_at".to_owned(), json!(expires_at));
    obj.insert("issued_at".to_owned(), json!(issued_at));
    obj.insert("role".to_owned(), json!("human_held"));
    obj.sort_keys();

    let canonical =
        serde_json::to_vec(&Value::Object(obj.clone())).expect("serialization cannot fail");
    let sig = root_key.sign(&canonical);
    obj.insert("signature".to_owned(), json!(b64(&sig.to_bytes())));

    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The delegation body must be byte-identical in shape to the
    /// operator's own signer, or the signature the operator verifies
    /// covers different bytes than the ones actually sent.
    #[test]
    fn delegation_has_expected_keys_and_verifies() {
        use ed25519_dalek::Verifier as _;

        let mut rng = rand::rngs::OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let root_key = SigningKey::from_bytes(&seed);
        let sess_pk = [7u8; 32];

        let delegation = build_delegation(
            &root_key,
            &sess_pk,
            "alice.test",
            "test device",
            "019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0",
        );
        let obj = delegation.as_object().expect("delegation is an object");

        assert_eq!(obj["airdress"], "alice.test");
        assert_eq!(obj["device_label"], "test device");
        assert_eq!(obj["role"], "human_held");
        assert_eq!(obj["device_id"], "019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0");
        assert!(obj.contains_key("issued_at"));
        assert!(obj.contains_key("expires_at"));
        assert!(obj.contains_key("signature"));

        // Reconstruct exactly what was signed: the same object, minus the
        // signature key that was inserted after signing. The key list is
        // spelled out rather than derived, so adding a field to the
        // signed object without adding it here fails loudly.
        let mut without_sig = obj.clone();
        let sig_b64 = without_sig
            .remove("signature")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let mut sorted = serde_json::Map::new();
        for k in [
            "airdress",
            "device_id",
            "device_label",
            "device_session_public_key",
            "expires_at",
            "issued_at",
            "role",
        ] {
            sorted.insert(k.to_owned(), without_sig[k].clone());
        }
        assert_eq!(
            sorted.len(),
            without_sig.len(),
            "every signed field must be listed here — an unlisted one is \
             covered by the signature but not by this test"
        );
        let canonical = serde_json::to_vec(&Value::Object(sorted)).unwrap();

        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        root_key
            .verifying_key()
            .verify(&canonical, &sig)
            .expect("signature must verify over the canonical delegation bytes");
    }

    /// The whole point of the two new fields: byte agreement with the
    /// verifier.
    ///
    /// These are the `spec-061-v2-delegation` vector from the shared
    /// canonicalization fixture
    /// `airdress-operator/crates/airdress-common/tests/fixtures/delegation_vectors.json`,
    /// which both `airdress-common` and `airdress-mls-ffi` iterate. The
    /// fixture cannot be read from this repo, so it is pinned here
    /// instead — and the assertion is the strongest available one:
    /// Ed25519 is deterministic, so producing the fixture's exact
    /// signature from the fixture's exact inputs proves the canonical
    /// bytes agree to the byte. Nothing weaker would catch a key-order
    /// or field-name drift.
    #[test]
    fn v2_delegation_matches_the_shared_canonicalization_fixture() {
        // root_seed_b64url: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        let root_key = SigningKey::from_bytes(&[7u8; 32]);
        // device_session_public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        let mut sess_pk = [0u8; 32];
        for (i, b) in sess_pk.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("32 fits in u8");
        }

        let delegation = delegation_object(
            &root_key,
            &sess_pk,
            "alice.humans.airdress.co",
            "Alice's iPhone",
            "019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0",
            "2026-09-05T12:00:00Z",
            "2027-03-05T12:00:00Z",
        );
        let obj = delegation.as_object().expect("delegation is an object");

        let mut without_sig = obj.clone();
        let signature = without_sig
            .remove("signature")
            .expect("signature present")
            .as_str()
            .expect("signature is a string")
            .to_owned();

        const FIXTURE_CANONICAL: &str = concat!(
            r#"{"airdress":"alice.humans.airdress.co","#,
            r#""device_id":"019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0","#,
            r#""device_label":"Alice's iPhone","#,
            r#""device_session_public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","#,
            r#""expires_at":"2027-03-05T12:00:00Z","#,
            r#""issued_at":"2026-09-05T12:00:00Z","#,
            r#""role":"human_held"}"#,
        );
        const FIXTURE_SIGNATURE: &str =
            "59eSoh_vlogh1qBNgX71z6Z2NEUjBEiotQqVvH9BfBtVBo3BElx-cNs-rcHjSEwl9TdxWdwE0PRS3hOZ4oXdAQ";

        assert_eq!(
            serde_json::to_string(&Value::Object(without_sig)).expect("serialize"),
            FIXTURE_CANONICAL,
            "the signing input must equal the fixture's canonical_b64url payload"
        );
        assert_eq!(
            signature, FIXTURE_SIGNATURE,
            "Ed25519 is deterministic — a differing signature means differing \
             canonical bytes, and enrollment would fail signature validation"
        );
    }

    /// `expires_at` is 180 days after `issued_at`, and both are RFC 3339.
    #[test]
    fn expiry_is_180_days_after_issue() {
        let root_key = SigningKey::from_bytes(&[3u8; 32]);
        let delegation = build_delegation(
            &root_key,
            &[9u8; 32],
            "alice.test",
            "test device",
            "019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0",
        );
        let obj = delegation.as_object().expect("delegation is an object");

        let parse = |k: &str| {
            chrono::DateTime::parse_from_rfc3339(obj[k].as_str().expect("string"))
                .unwrap_or_else(|e| panic!("{k} is not RFC 3339: {e}"))
        };
        let issued_at = parse("issued_at");
        let expires_at = parse("expires_at");

        assert_eq!(
            expires_at - issued_at,
            chrono::Duration::days(DELEGATION_LIFETIME_DAYS),
            "the delegation must expire 180 days after issue"
        );
        assert!(
            expires_at > Utc::now(),
            "a freshly minted delegation must not already be expired"
        );
    }

    /// The delegation must carry the device id it was handed, not one
    /// derived from the session key — the trap SPEC-061 design §10 risk
    /// row 2 names, and the reason `valid_successor` has a `device_id`
    /// check at all.
    #[test]
    fn device_id_is_carried_verbatim_and_not_derived_from_the_session_key() {
        let root_key = SigningKey::from_bytes(&[5u8; 32]);
        const DEVICE_ID: &str = "019e2b8c-7f41-7a3d-9c02-2f6b5d1a44e0";

        let first = build_delegation(&root_key, &[1u8; 32], "alice.test", "laptop", DEVICE_ID);
        // A second bootstrap: fresh session keypair, same stored device id.
        let second = build_delegation(&root_key, &[2u8; 32], "alice.test", "laptop", DEVICE_ID);

        assert_eq!(first["device_id"], DEVICE_ID);
        assert_eq!(
            first["device_id"], second["device_id"],
            "a re-delegation under a new session key must keep the same \
             device_id, or valid_successor rejects it as a sibling takeover"
        );
        assert_ne!(
            first["device_session_public_key"], second["device_session_public_key"],
            "the session key DID rotate — otherwise the assertion above is vacuous"
        );
    }
}
