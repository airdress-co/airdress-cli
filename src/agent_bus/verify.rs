//! Checking what another session wrote, before it is shown to a model.
//!
//! A device-signed item is checked against the sender's device key as the
//! operator lists it, that key against the delegation that certifies it,
//! and the delegation against the airdress's root — each pinned on first
//! sight, so a key that changes later is reported rather than followed.
//! An operator-attested item is checked against the operator's published
//! attestation key, pinned per kid. Either way the label is the point: a
//! model is told which kind of promise it is reading, and whether it held.

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{json, Map, Value};

use super::canon;
use super::state::{Pin, Pins};

/// The airdress purpose of the operator's attestation key in its
/// published key set.
pub const ATTESTATION_PURPOSE: &str = "agent_bus_attestation";

/// Decode base64 in whichever of the four alphabets it arrived in.
pub fn b64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| STANDARD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .ok()
}

fn key32(s: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = b64(s)?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// `device`, `operator`, or `none` for an item with no attestation.
    pub signed_by: String,
    pub valid: bool,
    /// What a person should hear about it (a changed key, a missing one).
    pub notes: Vec<String>,
}

impl Verdict {
    fn invalid(signed_by: &str, note: impl Into<String>) -> Self {
        Self {
            signed_by: signed_by.to_owned(),
            valid: false,
            notes: vec![note.into()],
        }
    }

    /// `device-signed` / `operator-attested`, as a result says it.
    pub fn label(&self) -> &'static str {
        match self.signed_by.as_str() {
            "device" => "device-signed",
            "operator" => "operator-attested",
            _ => "unsigned",
        }
    }

    /// `valid` / `invalid`, as channel meta carries it.
    pub fn word(&self) -> &'static str {
        if self.valid {
            "valid"
        } else {
            "invalid"
        }
    }

    /// Add the labels to an item for a model to read.
    pub fn label_item(&self, item: &mut Value) {
        if let Some(m) = item.as_object_mut() {
            m.insert("signed_by".into(), json!(self.label()));
            m.insert("signature".into(), json!(self.word()));
            if !self.notes.is_empty() {
                m.insert("signature_notes".into(), json!(self.notes));
            }
        }
    }
}

/// What a verifier knows: the airdress, the listed sessions and the
/// operator's attestation keys.
#[derive(Debug, Default, Clone)]
pub struct Known {
    pub airdress: String,
    /// `GET /sessions` rows by session id.
    pub sessions: HashMap<String, Value>,
    /// Each agent device's key material by enrollment id: the operator's
    /// `devices` list, and every listed session row that carries one.
    /// A device's key belongs to its enrollment, not to one session, so a
    /// write from a session that has since ended (an automatic ack racing
    /// its own session's end, or history read later) is still checked.
    pub devices: HashMap<String, Value>,
    /// Operator attestation keys (base64url) by kid.
    pub operator_keys: HashMap<String, String>,
}

impl Known {
    /// Index a `GET /sessions` answer.
    pub fn set_sessions(&mut self, listing: &Value) {
        self.sessions = listing["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| Some((s["id"].as_str()?.to_owned(), s.clone())))
            .collect();
        self.devices = listing["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(self.sessions.values())
            .filter(|d| d["device_public_key"].is_string())
            .filter_map(|d| Some((d["enrollment_id"].as_str()?.to_owned(), d.clone())))
            .collect();
    }

    /// Index a published key set, keeping only attestation keys.
    pub fn set_operator_keys(&mut self, keys_json: &Value) {
        self.operator_keys = keys_json["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|k| k["airdress_purpose"] == ATTESTATION_PURPOSE)
            .filter_map(|k| Some((k["kid"].as_str()?.to_owned(), k["x"].as_str()?.to_owned())))
            .collect();
    }
}

/// The body a message's signature covers, rebuilt from the item:
/// the fields the sender sent, absent ones omitted.
fn message_body(item: &Value) -> Value {
    let mut m = Map::new();
    for k in ["content", "data", "data_schema", "in_reply_to", "fence"] {
        if let Some(v) = item.get(k).filter(|v| !v.is_null()) {
            m.insert(k.into(), v.clone());
        }
    }
    Value::Object(m)
}

fn check_sig(key: &VerifyingKey, obj: &Value, sig: &str) -> bool {
    let Ok(input) = canon::signing_input(obj) else {
        return false;
    };
    let Some(sig) = b64(sig).and_then(|b| Signature::from_slice(&b).ok()) else {
        return false;
    };
    key.verify(&input, &sig).is_ok()
}

/// Check a delegation (root-signed) names `device_key`.
fn delegation_holds(delegation: &Value, device_key: &VerifyingKey, root: &VerifyingKey) -> bool {
    let Some(obj) = delegation.as_object() else {
        return false;
    };
    let named = obj
        .get("device_session_public_key")
        .and_then(Value::as_str)
        .and_then(key32);
    if named.as_ref() != Some(device_key) {
        return false;
    }
    let Some(sig) = obj.get("signature").and_then(Value::as_str) else {
        return false;
    };
    let mut unsigned = obj.clone();
    unsigned.remove("signature");
    let Ok(bytes) = canon::jcs(&Value::Object(unsigned)) else {
        return false;
    };
    b64(sig)
        .and_then(|b| Signature::from_slice(&b).ok())
        .is_some_and(|s| root.verify(bytes.as_bytes(), &s).is_ok())
}

/// Check one item. `pins` is updated on first sight of a key.
pub fn verify(item: &Value, known: &Known, pins: &mut Pins) -> Verdict {
    let a = &item["attestation"];
    let signed_by = a["signed_by"].as_str().unwrap_or("none");
    let field = |k: &str| a[k].as_str().unwrap_or_default().to_owned();
    // A message's own body must hash to what was signed.
    if item["kind"] == "message" {
        match canon::body_hash(&message_body(item)) {
            Ok(h) if h == field("body") => {}
            _ => return Verdict::invalid(signed_by, "the message does not match what was signed"),
        }
    }
    match signed_by {
        "device" => verify_device(a, known, pins),
        "operator" => verify_operator(a, known, pins),
        _ => Verdict::invalid("none", "this item carries no attestation"),
    }
}

fn verify_device(a: &Value, known: &Known, pins: &mut Pins) -> Verdict {
    let session = a["session"].as_str().unwrap_or_default();
    let enrollment = a["enrollment"].as_str().unwrap_or_default();
    let mut notes = Vec::new();
    // The key is the enrollment's. A listed session must be bound to the
    // enrollment it signed as; a session that is no longer listed (it
    // ended, perhaps a moment after it wrote) is checked through its
    // device's enrollment instead, which the operator bound it to when
    // it accepted the write.
    let row = match known.sessions.get(session) {
        Some(row) => {
            if row["enrollment_id"].as_str().unwrap_or_default() != enrollment {
                return Verdict::invalid(
                    "device",
                    "signed as a device the session is not bound to",
                );
            }
            row
        }
        None => match known.devices.get(enrollment) {
            Some(device) => {
                notes.push(
                    "the sending session has ended; its device key was checked through the \
                     device's enrollment"
                        .to_owned(),
                );
                device
            }
            None => {
                return Verdict::invalid(
                    "device",
                    "neither the sending session nor its device is listed any more, so its key \
                     cannot be checked",
                );
            }
        },
    };
    let Some(listed) = row["device_public_key"].as_str() else {
        return Verdict::invalid("device", "the sending session lists no device key");
    };
    let Some(key) = key32(listed) else {
        return Verdict::invalid("device", "the sending session's device key is malformed");
    };
    if canon::key_id(key.as_bytes()) != a["key_id"].as_str().unwrap_or_default() {
        return Verdict::invalid("device", "signed with a key the session does not list");
    }
    let canonical_key = URL_SAFE_NO_PAD.encode(key.as_bytes());
    if let Pin::Changed { .. } = pins.device(enrollment, &canonical_key) {
        return Verdict::invalid(
            "device",
            format!(
                "the device key for enrollment {enrollment} changed since this machine first \
                 saw it; treat this item as unverified and tell the user"
            ),
        );
    }
    // The key's certificate: a delegation from the airdress's root.
    match (
        row.get("delegation"),
        row["root_public_key"].as_str().and_then(key32),
    ) {
        (Some(d), Some(root)) if !d.is_null() => {
            let root_b64 = URL_SAFE_NO_PAD.encode(root.as_bytes());
            if let Pin::Changed { .. } = pins.root(&root_b64) {
                return Verdict::invalid(
                    "device",
                    "the airdress's root key changed since this machine first saw it",
                );
            }
            if !delegation_holds(d, &key, &root) {
                return Verdict::invalid(
                    "device",
                    "the device key is not certified by the airdress's root",
                );
            }
        }
        _ => notes.push("the sender's delegation was not listed; only its key was checked".into()),
    }
    let obj = json!({
        "airdress": known.airdress, "signed_by": "device", "session": session,
        "enrollment": enrollment, "op": a["op"], "target": a["target"], "body": a["body"],
        "nonce": a["nonce"], "time": a["time"],
    });
    if !check_sig(&key, &obj, a["sig"].as_str().unwrap_or_default()) {
        return Verdict::invalid("device", "the signature does not verify");
    }
    Verdict {
        signed_by: "device".into(),
        valid: true,
        notes,
    }
}

fn verify_operator(a: &Value, known: &Known, pins: &mut Pins) -> Verdict {
    let kid = a["key_id"].as_str().unwrap_or_default();
    let Some(listed) = known.operator_keys.get(kid) else {
        return Verdict::invalid(
            "operator",
            "the operator does not publish the key this was attested with",
        );
    };
    let Some(key) = key32(listed) else {
        return Verdict::invalid("operator", "the operator's attestation key is malformed");
    };
    if let Pin::Changed { .. } = pins.operator(kid, &URL_SAFE_NO_PAD.encode(key.as_bytes())) {
        return Verdict::invalid(
            "operator",
            format!("the operator's attestation key {kid} changed since this machine first saw it"),
        );
    }
    let obj = json!({
        "airdress": known.airdress, "signed_by": "operator", "session": a["session"],
        "remote": a["remote"], "op": a["op"], "target": a["target"], "body": a["body"],
        "nonce": a["nonce"], "time": a["time"],
    });
    if !check_sig(&key, &obj, a["sig"].as_str().unwrap_or_default()) {
        return Verdict::invalid("operator", "the attestation does not verify");
    }
    Verdict {
        signed_by: "operator".into(),
        valid: true,
        notes: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Items signed the way a peer signs them, for tests in this crate.
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A peer session listing row, with a root-signed delegation.
    pub fn session_row(id: &str, enrollment: &str, key: &SigningKey, root: &SigningKey) -> Value {
        let mut d = json!({
            "airdress": "a.example",
            "device_class": "agent",
            "device_session_public_key": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        });
        let sig = root.sign(canon::jcs(&d).unwrap().as_bytes());
        d["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        json!({
            "id": id, "label": "peer · repo", "attestation": "device", "enrollment_id": enrollment,
            "device_public_key": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
            "key_id": canon::key_id(key.verifying_key().as_bytes()),
            "delegation": d,
            "root_public_key": URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()),
        })
    }

    /// A device-signed message item.
    pub fn message(
        id: &str,
        cursor: i64,
        session: &str,
        enrollment: &str,
        key: &SigningKey,
        content: &str,
    ) -> Value {
        let body = json!({"content": content});
        let obj = json!({
            "airdress": "a.example", "signed_by": "device", "session": session,
            "enrollment": enrollment, "op": "message.post", "target": "topic:general",
            "body": canon::body_hash(&body).unwrap(), "nonce": "bm9uY2U", "time": "2026-10-05T00:00:00.000Z",
        });
        let sig = key.sign(&canon::signing_input(&obj).unwrap());
        json!({
            "id": id, "cursor": cursor, "stream": "topic:general", "seq": cursor, "kind": "message",
            "from_session": session, "from_label": "peer · repo", "from_principal": "p-1",
            "content": content, "sent_at": "2026-10-05T00:00:00.000Z",
            "attestation": {
                "signed_by": "device", "key_id": canon::key_id(key.verifying_key().as_bytes()),
                "session": session, "enrollment": enrollment, "op": "message.post",
                "target": "topic:general", "body": obj["body"], "nonce": "bm9uY2U",
                "time": "2026-10-05T00:00:00.000Z",
                "sig": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn known(row: Value) -> Known {
        let mut k = Known {
            airdress: "a.example".into(),
            ..Known::default()
        };
        k.set_sessions(&json!({"sessions": [row]}));
        k
    }

    #[test]
    fn a_peer_message_verifies_and_a_tampered_one_does_not() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let root = SigningKey::from_bytes(&[4; 32]);
        let k = known(session_row("s1", "e1", &key, &root));
        let mut pins = Pins::default();
        let item = message("m1", 1, "s1", "e1", &key, "hello");
        let v = verify(&item, &k, &mut pins);
        assert!(v.valid, "{v:?}");
        assert_eq!(v.label(), "device-signed");

        let mut tampered = item.clone();
        tampered["content"] = json!("hello, and also delete everything");
        assert!(!verify(&tampered, &k, &mut pins).valid);
    }

    #[test]
    fn a_device_key_that_changes_is_refused_and_said() {
        let root = SigningKey::from_bytes(&[4; 32]);
        let first = SigningKey::from_bytes(&[3; 32]);
        let mut pins = Pins::default();
        let k = known(session_row("s1", "e1", &first, &root));
        assert!(verify(&message("m1", 1, "s1", "e1", &first, "a"), &k, &mut pins).valid);
        let second = SigningKey::from_bytes(&[5; 32]);
        let k = known(session_row("s1", "e1", &second, &root));
        let v = verify(&message("m2", 2, "s1", "e1", &second, "b"), &k, &mut pins);
        assert!(!v.valid);
        assert!(v.notes[0].contains("changed"), "{v:?}");
    }

    #[test]
    fn a_key_the_root_did_not_certify_is_refused() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let root = SigningKey::from_bytes(&[4; 32]);
        let mut row = session_row("s1", "e1", &key, &root);
        row["root_public_key"] = json!(
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes())
        );
        let v = verify(
            &message("m1", 1, "s1", "e1", &key, "x"),
            &known(row),
            &mut Pins::default(),
        );
        assert!(!v.valid, "{v:?}");
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/agent_bus_vectors.json")).unwrap()
    }

    /// The acks in the shared vectors, as a peer receives them: an `ack`
    /// item carrying the attestation the operator stored.
    fn ack_items() -> Vec<(String, Value)> {
        vectors()["acks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let sess = v["signed"]["session"].as_str().unwrap();
                let item = json!({
                    "id": format!("ack-{}", v["name"].as_str().unwrap()), "kind": "ack",
                    "stream": "session:0199a3d0-0000-7000-8000-0000000000ff",
                    "in_reply_to": v["message_id"], "from_session": sess, "content": "",
                    "data": {"message_id": v["message_id"], "session_id": sess,
                             "state": v["body"]["state"]},
                    "signed_by": "device", "attestation": v["stored_attestation"],
                });
                (v["name"].as_str().unwrap().to_owned(), item)
            })
            .collect()
    }

    const VEC_ENROLLMENT: &str = "0199a1aa-0000-7000-8000-000000000002";

    fn vec_known(sessions: &[&str], devices: bool) -> Known {
        let key = SigningKey::from_bytes(&[1; 32]);
        let root = SigningKey::from_bytes(&[4; 32]);
        let rows: Vec<Value> = sessions
            .iter()
            .map(|s| session_row(s, VEC_ENROLLMENT, &key, &root))
            .collect();
        let mut listing = json!({ "sessions": rows });
        if devices {
            let mut d = session_row("unused", VEC_ENROLLMENT, &key, &root);
            d.as_object_mut().unwrap().remove("id");
            listing["devices"] = json!([d]);
        }
        let mut k = Known {
            airdress: "alice.a.airdr.es".into(),
            ..Known::default()
        };
        k.set_sessions(&listing);
        k
    }

    #[test]
    fn every_ack_vector_verifies_from_what_the_operator_stores() {
        let k = vec_known(
            &[
                "0199a3d0-0000-7000-8000-000000000001",
                "0199a3d0-0000-7000-8000-000000000003",
            ],
            false,
        );
        for (name, item) in ack_items() {
            let v = verify(&item, &k, &mut Pins::default());
            assert!(v.valid, "{name}: {v:?}");
            assert!(v.notes.is_empty(), "{name}: {v:?}");
        }
    }

    /// The live S5 case (a test operator, 2026-10-05): two sessions on one agent
    /// device ack the same message; one of them ends 5 ms after its ack is
    /// accepted, so by the time the recipient looks it is no longer
    /// listed. Its device is, through the other session.
    #[test]
    fn an_ack_from_a_session_that_has_since_ended_verifies_through_its_device() {
        let k = vec_known(&["0199a3d0-0000-7000-8000-000000000003"], false);
        let (_, item) = ack_items()
            .into_iter()
            .find(|(n, _)| n == "delivered")
            .unwrap();
        let v = verify(&item, &k, &mut Pins::default());
        assert!(v.valid, "{v:?}");
        assert!(v.notes[0].contains("has ended"), "{v:?}");

        // No session of the device is live: the operator's device list
        // vouches for the key.
        let k = vec_known(&[], true);
        let v = verify(&item, &k, &mut Pins::default());
        assert!(v.valid, "{v:?}");

        // Neither: refused, and it says why rather than "does not verify".
        let k = vec_known(&[], false);
        let v = verify(&item, &k, &mut Pins::default());
        assert!(!v.valid);
        assert!(v.notes[0].contains("listed"), "{v:?}");
    }

    #[test]
    fn a_tampered_ack_or_a_session_bound_elsewhere_is_still_refused() {
        let (_, item) = ack_items()
            .into_iter()
            .find(|(n, _)| n == "delivered")
            .unwrap();
        // The device fallback does not loosen the signature itself.
        let k = vec_known(&["0199a3d0-0000-7000-8000-000000000003"], false);
        let mut t = item.clone();
        t["attestation"]["target"] = json!("0199a3d0-0000-7000-8000-0000000000bb");
        assert!(!verify(&t, &k, &mut Pins::default()).valid);
        // A session that IS listed must be bound to the enrollment it
        // signed as; the device list never overrides that.
        let key = SigningKey::from_bytes(&[1; 32]);
        let root = SigningKey::from_bytes(&[4; 32]);
        let mut k = Known {
            airdress: "alice.a.airdr.es".into(),
            ..Known::default()
        };
        k.set_sessions(&json!({
            "sessions": [session_row("0199a3d0-0000-7000-8000-000000000001", "e-other", &key, &root)],
            "devices": [session_row("d", VEC_ENROLLMENT, &key, &root)],
        }));
        let v = verify(&item, &k, &mut Pins::default());
        assert!(!v.valid, "{v:?}");
        assert!(v.notes[0].contains("not bound"), "{v:?}");
    }

    #[test]
    fn an_operator_attestation_verifies_under_its_published_key() {
        let op = SigningKey::from_bytes(&[8; 32]);
        let mut k = Known {
            airdress: "a.example".into(),
            ..Known::default()
        };
        k.set_operator_keys(&json!({"keys": [{
            "kid": "k-0001", "x": URL_SAFE_NO_PAD.encode(op.verifying_key().as_bytes()),
            "airdress_purpose": ATTESTATION_PURPOSE, "kty": "OKP", "crv": "Ed25519"
        }]}));
        let body = json!({"content": "from the web"});
        let remote = json!({"client_id": "c", "grant_id": "g", "principal": "p"});
        let obj = json!({
            "airdress": "a.example", "signed_by": "operator", "session": "r1", "remote": remote,
            "op": "message.post", "target": "topic:general", "body": canon::body_hash(&body).unwrap(),
            "nonce": "n", "time": "t",
        });
        let sig = op.sign(&canon::signing_input(&obj).unwrap());
        let item = json!({
            "id": "m", "kind": "message", "content": "from the web",
            "attestation": {"signed_by": "operator", "key_id": "k-0001", "session": "r1",
              "remote": remote, "op": "message.post", "target": "topic:general",
              "body": obj["body"], "nonce": "n", "time": "t",
              "sig": URL_SAFE_NO_PAD.encode(sig.to_bytes())}
        });
        let v = verify(&item, &k, &mut Pins::default());
        assert!(v.valid, "{v:?}");
        assert_eq!(v.label(), "operator-attested");
    }
}
