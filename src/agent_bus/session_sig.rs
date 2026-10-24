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

/// The session's signature over `text` in the group `group_id`.
pub fn sign(key: &SigningKey, group_id: &[u8], name: &str, text: &str) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(&signing_input(group_id, name, text)).to_bytes())
}

/// Check `sig` is `d`'s session's over `text` in `group_id`.
pub fn verify(d: &Delegated, group_id: &[u8], text: &str, sig: &str) -> Result<()> {
    d.key
        .verify(&signing_input(group_id, &d.name, text), &decode_sig(sig)?)
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
/// group, the signature is the session's over it. `Ok(false)` means there
/// is no group yet, and the message goes out as the device's.
#[allow(clippy::too_many_arguments)]
pub fn check_send(
    delegation: &Value,
    sig: &str,
    device: &VerifyingKey,
    airdress: &str,
    device_id: &str,
    text: &str,
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
    verify(&d, group, text, sig).map_err(invalid)?;
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
        let sig = sign(&session, b"group-1", "bob", "bob: done");
        verify(&d, b"group-1", "bob: done", &sig).unwrap();
        assert!(verify(&d, b"group-2", "bob: done", &sig).is_err());
        assert!(verify(&d, b"group-1", "bob: not done", &sig).is_err());
        let mut alice = d.clone();
        alice.name = "alice".into();
        assert!(verify(&alice, b"group-1", "bob: done", &sig).is_err());
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
        let sig = sign(&second, b"g", "bob", "bob: hi");
        assert!(verify(&d, b"g", "bob: hi", &sig).is_err());
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
            check_send(&d, sig, &dk, "a.example", "dev-1", text, group, now)
        };
        let good = sign(&session, b"g", "bob", "bob: done");
        assert_eq!(check("bob: done", &good, Some(b"g")), Ok(true));
        // No group yet: sent as the device.
        assert_eq!(check("bob: done", &good, None), Ok(false));
        let alice = sign(&session, b"g", "bob", "alice: done");
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
}
