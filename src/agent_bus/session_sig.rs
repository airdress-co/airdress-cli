//! Replies signed per session (SPEC-166 phase G, design §11.6). Shared by
//! the MCP server, which holds the session key, and the device host,
//! which delegates to it.
//!
//! Each MCP session holds an Ed25519 key in memory. The device host
//! delegates to it, under the agent device's own key, for one session
//! name and at most a day. A chat message the session writes carries the
//! delegation and a signature over the group, the name and the text, so
//! a phone can show which session wrote it without trusting the prefix.

use anyhow::{bail, ensure, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::agent_bus::canon;

/// The domain label in front of what a session signs.
pub const LABEL: &str = "airdress.session-reply.v1";

/// The label for a message that answers another (SPEC-174 D-15): the
/// signature then covers the `reply_to` object as well as the text. The
/// version is chosen by the payload: `reply_to` present means this label
/// and only this one verifies; absent means [`LABEL`], byte for byte.
pub const LABEL_REPLY: &str = "airdress.session-reply.v2";

/// How long a delegation lasts. It is renewed on every wait.
pub const LIFETIME: Duration = Duration::hours(24);

/// The delegation's version.
const VERSION: u64 = 1;

/// A fresh session key, in memory only.
pub fn new_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// A public key as the wire carries it.
pub fn encode_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.as_bytes())
}

fn decode_key(s: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("a key that is not 32 bytes of base64url")?;
    VerifyingKey::from_bytes(&bytes).context("not an Ed25519 public key")
}

fn decode_sig(s: &str) -> Result<Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .context("a signature that is not base64url")?;
    Signature::from_slice(&bytes).context("not an Ed25519 signature")
}

/// The delegation the device `device` gives the session `name`'s key.
pub fn delegate(
    device: &SigningKey,
    airdress: &str,
    device_id: &str,
    name: &str,
    session_key: &str,
    now: DateTime<Utc>,
) -> Result<Value> {
    decode_key(session_key)?;
    let mut d = json!({
        "v": VERSION,
        "airdress": airdress,
        "device_id": device_id,
        "session_name": name,
        "session_key": session_key,
        "not_after": (now + LIFETIME).to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    let sig = device.sign(canon::jcs(&d)?.as_bytes());
    d["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    Ok(d)
}

/// What a session's delegation says, once it verifies.
#[derive(Debug, Clone)]
pub struct Delegated {
    pub name: String,
    pub key: VerifyingKey,
}

/// Check `d` was given by `device` for `airdress` and `device_id`, and is
/// in force at `now`.
pub fn verify_delegation(
    d: &Value,
    device: &VerifyingKey,
    airdress: &str,
    device_id: &str,
    now: DateTime<Utc>,
) -> Result<Delegated> {
    let obj = d.as_object().context("a delegation is an object")?;
    let field = |k: &str| obj.get(k).and_then(Value::as_str).unwrap_or_default();
    ensure!(
        obj.get("v") == Some(&json!(VERSION)),
        "an unknown delegation version"
    );
    ensure!(
        field("airdress") == airdress,
        "a delegation for another airdress"
    );
    ensure!(
        field("device_id") == device_id,
        "a delegation from another device"
    );
    let not_after =
        DateTime::parse_from_rfc3339(field("not_after")).context("a delegation with no expiry")?;
    ensure!(now <= not_after, "the delegation has expired");
    let mut unsigned: Map<String, Value> = obj.clone();
    let sig = unsigned
        .remove("signature")
        .and_then(|s| s.as_str().map(str::to_owned))
        .context("an unsigned delegation")?;
    if device
        .verify(
            canon::jcs(&Value::Object(unsigned))?.as_bytes(),
            &decode_sig(&sig)?,
        )
        .is_err()
    {
        bail!("the delegation is not this device's");
    }
    Ok(Delegated {
        name: field("session_name").to_owned(),
        key: decode_key(field("session_key"))?,
    })
}

/// `LABEL ‖ 0x1F ‖ group_id ‖ 0x1F ‖ name ‖ 0x1F ‖ SHA-256(text)`.
pub fn signing_input(group_id: &[u8], name: &str, text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(LABEL.len() + group_id.len() + name.len() + 35);
    v.extend_from_slice(LABEL.as_bytes());
    v.push(0x1F);
    v.extend_from_slice(group_id);
    v.push(0x1F);
    v.extend_from_slice(name.as_bytes());
    v.push(0x1F);
    v.extend_from_slice(&Sha256::digest(text.as_bytes()));
    v
}

/// `LABEL_REPLY ‖ 0x1F ‖ group_id ‖ 0x1F ‖ name ‖ 0x1F ‖ SHA-256(text)
/// ‖ 0x1F ‖ SHA-256(JCS(reply_to))`: what a reply is signed over. The
/// `reply_to` object is the one that travels in the payload; RFC 8785
/// makes its key order irrelevant.
///
/// # Errors
/// `reply_to` is not an object, or holds a number JSON cannot carry.
pub fn signing_input_reply(
    group_id: &[u8],
    name: &str,
    text: &str,
    reply_to: &Value,
) -> Result<Vec<u8>> {
    ensure!(reply_to.is_object(), "reply_to is an object");
    let canonical = canon::jcs(reply_to)?;
    let mut v = Vec::with_capacity(LABEL_REPLY.len() + group_id.len() + name.len() + 68);
    v.extend_from_slice(LABEL_REPLY.as_bytes());
    v.push(0x1F);
    v.extend_from_slice(group_id);
    v.push(0x1F);
    v.extend_from_slice(name.as_bytes());
    v.push(0x1F);
    v.extend_from_slice(&Sha256::digest(text.as_bytes()));
    v.push(0x1F);
    v.extend_from_slice(&Sha256::digest(canonical.as_bytes()));
    Ok(v)
}

/// The signing input for a message: the reply form when it carries
/// `reply_to`, the plain form otherwise.
///
/// # Errors
/// As [`signing_input_reply`].
pub fn signing_input_for(
    group_id: &[u8],
    name: &str,
    text: &str,
    reply_to: Option<&Value>,
) -> Result<Vec<u8>> {
    match reply_to {
        Some(r) => signing_input_reply(group_id, name, text, r),
        None => Ok(signing_input(group_id, name, text)),
    }
}

/// The session's signature over `text` (and `reply_to`, when the message
/// answers another) in the group `group_id`.
///
/// # Errors
/// As [`signing_input_reply`].
pub fn sign(
    key: &SigningKey,
    group_id: &[u8],
    name: &str,
    text: &str,
    reply_to: Option<&Value>,
) -> Result<String> {
    let input = signing_input_for(group_id, name, text, reply_to)?;
    Ok(URL_SAFE_NO_PAD.encode(key.sign(&input).to_bytes()))
}

/// Check `sig` is `d`'s session's over `text` (and `reply_to`) in
/// `group_id`. A signature over the text alone never vouches for a
/// message that carries `reply_to`.
pub fn verify(
    d: &Delegated,
    group_id: &[u8],
    text: &str,
    reply_to: Option<&Value>,
    sig: &str,
) -> Result<()> {
    let input = signing_input_for(group_id, &d.name, text, reply_to)?;
    d.key
        .verify(&input, &decode_sig(sig)?)
        .map_err(|_| anyhow::anyhow!("the session's signature does not verify"))
}

/// The session a `<name>: ` prefix names, if the text has one.
pub fn prefix_name(text: &str) -> Option<String> {
    let (head, _) = text.split_once(": ")?;
    crate::mcp::names::normalise(head).ok()
}

/// Why a session's signed send is refused: a code and a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

/// The device host's checks on a signed send (design §11.6): the
/// delegation is `device`'s and in force; the text's prefix, if any,
/// names that session and no other; and, when the conversation has a
/// group, the signature is the session's over it (and over `reply_to`,
/// for a reply). `Ok(false)` means there is no group yet, and the message
/// goes out as the device's.
#[allow(clippy::too_many_arguments)]
pub fn check_send(
    delegation: &Value,
    sig: &str,
    device: &VerifyingKey,
    airdress: &str,
    device_id: &str,
    text: &str,
    reply_to: Option<&Value>,
    group: Option<&[u8]>,
    now: DateTime<Utc>,
) -> std::result::Result<bool, Refused> {
    let invalid = |e: anyhow::Error| Refused {
        code: "session_signature_invalid",
        message: format!("{e:#}"),
    };
    let d = verify_delegation(delegation, device, airdress, device_id, now).map_err(invalid)?;
    if let Some(named) = prefix_name(text) {
        if named != d.name {
            return Err(Refused {
                code: "prefix_names_another_session",
                message: format!(
                    "this session is {}; a message it signs cannot start with {named}:",
                    d.name
                ),
            });
        }
    }
    let Some(group) = group else {
        return Ok(false);
    };
    verify(&d, group, text, reply_to, sig).map_err(invalid)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn a_delegation_verifies_against_the_device_key_and_nothing_else() {
        let now = Utc::now();
        let session = new_key();
        let d = delegate(
            &device(),
            "a.example",
            "dev-1",
            "bob",
            &encode_key(&session.verifying_key()),
            now,
        )
        .unwrap();
        let ok =
            verify_delegation(&d, &device().verifying_key(), "a.example", "dev-1", now).unwrap();
        assert_eq!(ok.name, "bob");
        assert_eq!(ok.key, session.verifying_key());

        let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(verify_delegation(&d, &other, "a.example", "dev-1", now).is_err());
        assert!(
            verify_delegation(&d, &device().verifying_key(), "a.example", "dev-2", now).is_err()
        );
        let later = now + LIFETIME + Duration::minutes(1);
        assert!(
            verify_delegation(&d, &device().verifying_key(), "a.example", "dev-1", later).is_err()
        );
        let mut renamed = d.clone();
        renamed["session_name"] = json!("alice");
        assert!(verify_delegation(
            &renamed,
            &device().verifying_key(),
            "a.example",
            "dev-1",
            now
        )
        .is_err());
    }

    #[test]
    fn a_reply_signature_binds_the_group_the_name_and_the_text() {
        let now = Utc::now();
        let session = new_key();
        let d = delegate(
            &device(),
            "a.example",
            "dev-1",
            "bob",
            &encode_key(&session.verifying_key()),
            now,
        )
        .unwrap();
        let d =
            verify_delegation(&d, &device().verifying_key(), "a.example", "dev-1", now).unwrap();
        let sig = sign(&session, b"group-1", "bob", "bob: done", None).unwrap();
        verify(&d, b"group-1", "bob: done", None, &sig).unwrap();
        assert!(verify(&d, b"group-2", "bob: done", None, &sig).is_err());
        assert!(verify(&d, b"group-1", "bob: not done", None, &sig).is_err());
        let mut alice = d.clone();
        alice.name = "alice".into();
        assert!(verify(&alice, b"group-1", "bob: done", None, &sig).is_err());
    }

    /// A restarted session makes a new key, so the old delegation does not
    /// vouch for it.
    #[test]
    fn a_restarted_session_gets_a_new_key_for_its_name() {
        let now = Utc::now();
        let first = new_key();
        let second = new_key();
        assert_ne!(first.verifying_key(), second.verifying_key());
        let d = delegate(
            &device(),
            "a.example",
            "dev-1",
            "bob",
            &encode_key(&first.verifying_key()),
            now,
        )
        .unwrap();
        let d =
            verify_delegation(&d, &device().verifying_key(), "a.example", "dev-1", now).unwrap();
        let sig = sign(&second, b"g", "bob", "bob: hi", None).unwrap();
        assert!(verify(&d, b"g", "bob: hi", None, &sig).is_err());
    }

    #[test]
    fn the_host_refuses_a_prefix_naming_another_session_and_a_bad_signature() {
        let now = Utc::now();
        let session = new_key();
        let d = delegate(
            &device(),
            "a.example",
            "dev-1",
            "bob",
            &encode_key(&session.verifying_key()),
            now,
        )
        .unwrap();
        let dk = device().verifying_key();
        let check = |text: &str, sig: &str, group: Option<&[u8]>| {
            check_send(&d, sig, &dk, "a.example", "dev-1", text, None, group, now)
        };
        let good = sign(&session, b"g", "bob", "bob: done", None).unwrap();
        assert_eq!(check("bob: done", &good, Some(b"g")), Ok(true));
        // No group yet: sent as the device.
        assert_eq!(check("bob: done", &good, None), Ok(false));
        let alice = sign(&session, b"g", "bob", "alice: done", None).unwrap();
        let r = check("alice: done", &alice, Some(b"g")).unwrap_err();
        assert_eq!(r.code, "prefix_names_another_session");
        let r = check("bob: changed", &good, Some(b"g")).unwrap_err();
        assert_eq!(r.code, "session_signature_invalid");
        let other_device = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let r = check_send(
            &d,
            &good,
            &other_device,
            "a.example",
            "dev-1",
            "bob: done",
            None,
            Some(b"g"),
            now,
        )
        .unwrap_err();
        assert_eq!(r.code, "session_signature_invalid");
    }

    #[test]
    fn a_prefix_names_a_session() {
        assert_eq!(prefix_name("bob: done").as_deref(), Some("bob"));
        assert_eq!(prefix_name("no prefix here"), None);
    }

    // ---- the shared vectors (`tests/vectors/session_reply.json`) -------

    const VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/session_reply.json"
    );

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The inputs of every case: name, what it shows, the text, the
    /// `reply_to` exactly as written (its key order is part of the case),
    /// whether the signature is made over the text alone (the forgery),
    /// and whether it must verify.
    struct Case {
        name: &'static str,
        description: &'static str,
        text: &'static str,
        reply: Option<&'static str>,
        forged: bool,
        valid: bool,
    }

    fn vector_inputs() -> Vec<Case> {
        const TEXT: &str = "bob: Option 2, after the soak. Grüße ✓";
        const REPLY: &str = r#"{"ref":"Jk2m0PZpQh6Q1wVf3n8sLg","from":"home.example","kind":"text","snippet":"Three options: 1) roll it now, 2) wait for the soak, 3) …"}"#;
        const REPLY_REORDERED: &str = r#"{"snippet":"Three options: 1) roll it now, 2) wait for the soak, 3) …","kind":"text","from":"home.example","ref":"Jk2m0PZpQh6Q1wVf3n8sLg"}"#;
        const QUOTE_ONLY: &str =
            r#"{"from":"home.example","by_session":"alice","kind":"text","snippet":"done 👋🏽 ✓"}"#;
        vec![
            Case {
                name: "v1-plain",
                description: "A message without reply_to: the v1 signing input, byte for byte what every earlier release signs.",
                text: TEXT,
                reply: None,
                forged: false,
                valid: true,
            },
            Case {
                name: "v2-reply",
                description: "A reply: the v2 signing input covers the text and SHA-256 of the JCS of reply_to.",
                text: TEXT,
                reply: Some(REPLY),
                forged: false,
                valid: true,
            },
            Case {
                name: "v2-quote-only",
                description: "A reply to a message that carried no ref: reply_to has no ref and is still covered.",
                text: TEXT,
                reply: Some(QUOTE_ONLY),
                forged: false,
                valid: true,
            },
            Case {
                name: "v2-key-order",
                description: "The v2-reply case with reply_to's keys in another order: JCS makes the signing input, and so the signature, identical.",
                text: TEXT,
                reply: Some(REPLY_REORDERED),
                forged: false,
                valid: true,
            },
            Case {
                name: "v1-signature-on-a-reply",
                description: "Forged: the v1 signature over the text alone, on a message that carries reply_to. A verifier computes the v2 input and must refuse it.",
                text: TEXT,
                reply: Some(REPLY),
                forged: true,
                valid: false,
            },
        ]
    }

    fn vector_key() -> SigningKey {
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
        SigningKey::from_bytes(&seed)
    }

    const VECTOR_GROUP: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];

    fn build_vectors() -> Value {
        let key = vector_key();
        let cases: Vec<Value> = vector_inputs()
            .into_iter()
            .map(|c| {
                let Case {
                    name,
                    description,
                    text,
                    reply,
                    forged,
                    valid,
                } = c;
                let reply_value: Option<Value> = reply.map(|r| serde_json::from_str(r).unwrap());
                let input =
                    signing_input_for(&VECTOR_GROUP, "bob", text, reply_value.as_ref()).unwrap();
                let signed_over = if forged { None } else { reply_value.as_ref() };
                let sig = sign(&key, &VECTOR_GROUP, "bob", text, signed_over).unwrap();
                json!({
                    "name": name,
                    "description": description,
                    "session_name": "bob",
                    "group_id_hex": hex(&VECTOR_GROUP),
                    "text": text,
                    "reply_to_json": reply,
                    "reply_to_jcs": reply_value.as_ref().map(|r| canon::jcs(r).unwrap()),
                    "signing_input_hex": hex(&input),
                    "signature": sig,
                    "valid": valid,
                })
            })
            .collect();
        json!({
            "description": "Session reply signatures. A message without reply_to is signed over label_v1 ‖ 0x1F ‖ group_id ‖ 0x1F ‖ session_name ‖ 0x1F ‖ SHA-256(text); one with reply_to over label_v2 ‖ 0x1F ‖ group_id ‖ 0x1F ‖ session_name ‖ 0x1F ‖ SHA-256(text) ‖ 0x1F ‖ SHA-256(JCS(reply_to)), where JCS is RFC 8785. reply_to_json is the object exactly as it travels (its key order is part of the case); signing_input_hex is what a verifier computes from text and reply_to_json; signature is base64url without padding, Ed25519 under the key from session_seed_hex; valid says whether it must verify. The same file, byte for byte, is airdress-cli's tests/vectors/session_reply.json and the app's test/features/chat/session_reply_vectors.json; change both or neither.",
            "label_v1": LABEL,
            "label_v2": LABEL_REPLY,
            "session_seed_hex": hex(&key.to_bytes()),
            "session_public_key": encode_key(&key.verifying_key()),
            "cases": cases,
        })
    }

    /// `AIRDRESS_VECTORS_WRITE=1` rewrites the file; otherwise it must be
    /// what this code computes, byte for byte.
    #[test]
    fn the_session_reply_vector_file_is_what_this_code_computes() {
        let want = format!(
            "{}\n",
            serde_json::to_string_pretty(&build_vectors()).unwrap()
        );
        if std::env::var("AIRDRESS_VECTORS_WRITE").as_deref() == Ok("1") {
            std::fs::create_dir_all(std::path::Path::new(VECTORS).parent().unwrap()).unwrap();
            std::fs::write(VECTORS, &want).unwrap();
        }
        let have = std::fs::read_to_string(VECTORS).expect("the vector file");
        assert_eq!(
            have, want,
            "tests/vectors/session_reply.json is stale: run AIRDRESS_VECTORS_WRITE=1 cargo test \
             -p airdress --lib session_sig, and copy it to the app"
        );
    }

    /// Every case verifies (or is refused) as it says, from the file alone,
    /// the way the app's verifier reads it.
    #[test]
    fn every_session_reply_vector_verifies_as_it_says() {
        let file: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let seed: [u8; 32] = from_hex(file["session_seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            file["session_public_key"],
            json!(encode_key(&key.verifying_key()))
        );
        let d = Delegated {
            name: "bob".into(),
            key: key.verifying_key(),
        };
        let cases = file["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 5);
        let mut inputs = std::collections::HashMap::new();
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let group = from_hex(c["group_id_hex"].as_str().unwrap());
            let text = c["text"].as_str().unwrap();
            let reply: Option<Value> = c["reply_to_json"]
                .as_str()
                .map(|r| serde_json::from_str(r).unwrap());
            let input = signing_input_for(&group, "bob", text, reply.as_ref()).unwrap();
            assert_eq!(hex(&input), c["signing_input_hex"], "{name}");
            if let Some(r) = &reply {
                assert_eq!(json!(canon::jcs(r).unwrap()), c["reply_to_jcs"], "{name}");
            }
            let ok = verify(
                &d,
                &group,
                text,
                reply.as_ref(),
                c["signature"].as_str().unwrap(),
            )
            .is_ok();
            assert_eq!(json!(ok), c["valid"], "{name}");
            inputs.insert(name.to_owned(), (hex(&input), c["signature"].clone()));
        }
        // The v1 case is the plain signing input every release has signed.
        let v1 = &cases[0];
        assert_eq!(v1["name"], "v1-plain");
        assert!(v1["reply_to_json"].is_null());
        assert_eq!(
            v1["signing_input_hex"],
            json!(hex(&signing_input(
                &from_hex(v1["group_id_hex"].as_str().unwrap()),
                "bob",
                v1["text"].as_str().unwrap()
            )))
        );
        assert!(hex(&signing_input(b"g", "bob", "t")).starts_with(&hex(LABEL.as_bytes())));
        // Key order is irrelevant: one input, one signature.
        assert_eq!(inputs["v2-key-order"], inputs["v2-reply"]);
        // The forgery is the v1 signature, which verifies only without
        // reply_to.
        assert_eq!(inputs["v1-signature-on-a-reply"].1, inputs["v1-plain"].1);
    }

    #[test]
    fn a_text_signature_never_vouches_for_a_reply_and_a_reply_signature_binds_reply_to() {
        let now = Utc::now();
        let session = new_key();
        let d = delegate(
            &device(),
            "a.example",
            "dev-1",
            "bob",
            &encode_key(&session.verifying_key()),
            now,
        )
        .unwrap();
        let dk = device().verifying_key();
        let reply = json!({"ref": "r1", "from": "a.example", "kind": "text", "snippet": "hi"});
        let check = |sig: &str, reply: Option<&Value>| {
            check_send(
                &d,
                sig,
                &dk,
                "a.example",
                "dev-1",
                "bob: yes",
                reply,
                Some(b"g"),
                now,
            )
        };
        let v1 = sign(&session, b"g", "bob", "bob: yes", None).unwrap();
        let v2 = sign(&session, b"g", "bob", "bob: yes", Some(&reply)).unwrap();
        assert_eq!(check(&v1, None), Ok(true));
        assert_eq!(check(&v2, Some(&reply)), Ok(true));
        let r = check(&v1, Some(&reply)).unwrap_err();
        assert_eq!(r.code, "session_signature_invalid");
        assert!(
            check(&v2, None).is_err(),
            "a reply signature on a plain message"
        );
        let mut other = reply.clone();
        other["snippet"] = json!("something bob never said");
        assert!(check(&v2, Some(&other)).is_err(), "another quote");
        assert!(signing_input_reply(b"g", "bob", "t", &json!("not an object")).is_err());
    }
}
