//! The bytes a bus write is signed over (RFC 8785 JSON canonicalization
//! and the signing input), identical to the operator's.
//!
//! The vectors in `tests/fixtures/agent_bus_vectors.json` are committed in
//! both repositories; a change here that moves one byte fails both.

use anyhow::{bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// The label every signing input starts with.
pub const SIGNING_LABEL: &str = "airdress.agent_bus.write.v1";

/// RFC 8785 canonical form of `v`.
///
/// # Errors
/// A number that is not finite (JSON cannot carry one anyway).
pub fn jcs(v: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out)
}

fn write_value(out: &mut String, v: &Value) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                out.push_str(&es_number(f)?);
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x)?;
            }
            out.push(']');
        }
        Value::Object(m) => write_object(out, m)?,
    }
    Ok(())
}

fn write_object(out: &mut String, m: &Map<String, Value>) -> Result<()> {
    let mut keys: Vec<&String> = m.keys().collect();
    // UTF-16 code unit order, as the RFC says.
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, k);
        out.push(':');
        write_value(out, &m[*k])?;
    }
    out.push('}');
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString` for a finite double.
fn es_number(f: f64) -> Result<String> {
    if !f.is_finite() {
        bail!("a number that is not finite cannot be canonicalized");
    }
    if f == 0.0 {
        return Ok("0".into());
    }
    let neg = f < 0.0;
    // Rust's `{:e}` is the shortest round-trip form: `d[.ddd]e<exp>`.
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let n = exp + 1;
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if k <= n && n <= 21 {
        s.push_str(digits);
        s.extend(std::iter::repeat_n(
            '0',
            usize::try_from(n - k).unwrap_or(0),
        ));
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).unwrap_or(0);
        s.push_str(&digits[..split]);
        s.push('.');
        s.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        s.push_str("0.");
        s.extend(std::iter::repeat_n('0', usize::try_from(-n).unwrap_or(0)));
        s.push_str(digits);
    } else {
        let e = n - 1;
        s.push_str(&digits[..1]);
        if digits.len() > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        s.push(if e >= 0 { '+' } else { '-' });
        s.push_str(&e.abs().to_string());
    }
    Ok(s)
}

/// Lowercase hex SHA-256 of the canonical body, `attestation` removed.
///
/// # Errors
/// As [`jcs`].
pub fn body_hash(body: &Value) -> Result<String> {
    let mut b = body.clone();
    if let Some(m) = b.as_object_mut() {
        m.remove("attestation");
    }
    let digest = Sha256::digest(jcs(&b)?.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// `label ‖ 0x1F ‖ JCS(obj)`.
///
/// # Errors
/// As [`jcs`].
pub fn signing_input(obj: &Value) -> Result<Vec<u8>> {
    let mut out = SIGNING_LABEL.as_bytes().to_vec();
    out.push(0x1f);
    out.extend_from_slice(jcs(obj)?.as_bytes());
    Ok(out)
}

/// `ed25519:` and the base64url SHA-256 of the raw public key.
pub fn key_id(public_key: &[u8]) -> String {
    format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/agent_bus_vectors.json")).unwrap()
    }

    #[test]
    fn every_canonicalization_vector_holds() {
        for v in vectors()["jcs"].as_array().unwrap() {
            assert_eq!(
                jcs(&v["input"]).unwrap(),
                v["canonical"].as_str().unwrap(),
                "{}",
                v["name"]
            );
        }
    }

    #[test]
    fn the_signature_vector_holds() {
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
        let v = vectors()["signature"].clone();
        let seed: [u8; 32] = (0..32)
            .map(|i| {
                u8::from_str_radix(&v["seed_hex"].as_str().unwrap()[i * 2..i * 2 + 2], 16).unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&seed);
        let pk = key.verifying_key();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(pk.as_bytes()),
            v["public_key_b64url"].as_str().unwrap()
        );
        assert_eq!(key_id(pk.as_bytes()), v["key_id"].as_str().unwrap());
        assert_eq!(jcs(&v["body"]).unwrap(), v["body_jcs"].as_str().unwrap());
        assert_eq!(
            body_hash(&v["body"]).unwrap(),
            v["body_sha256"].as_str().unwrap()
        );
        let input = signing_input(&v["signed"]).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&input),
            v["signing_input_b64url"].as_str().unwrap()
        );
        let sig = key.sign(&input);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            v["signature_b64url"].as_str().unwrap()
        );
        assert!(pk.verify(&input, &sig).is_ok());
    }

    /// Acks (delivered, as the automatic one sends; handled with a note):
    /// the body, the signing input over `op: ack` with the message id as
    /// the target, and the signature, byte for byte as the operator checks.
    #[test]
    fn every_ack_vector_holds() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let key = SigningKey::from_bytes(&[1; 32]);
        let acks = vectors()["acks"].as_array().unwrap().clone();
        assert!(acks.len() >= 3);
        for v in acks {
            let name = v["name"].as_str().unwrap();
            assert_eq!(
                jcs(&v["body"]).unwrap(),
                v["body_jcs"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                body_hash(&v["body"]).unwrap(),
                v["body_sha256"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(v["signed"]["op"], "ack", "{name}");
            assert_eq!(v["signed"]["target"], v["message_id"], "{name}");
            assert_eq!(v["signed"]["body"], v["body_sha256"], "{name}");
            let input = signing_input(&v["signed"]).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD.encode(&input),
                v["signing_input_b64url"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(key.sign(&input).to_bytes()),
                v["signature_b64url"].as_str().unwrap(),
                "{name}"
            );
            // What the operator stores is the signed object without the
            // airdress, plus the key id and signature, and nothing else.
            let mut stored = v["signed"].as_object().unwrap().clone();
            stored.remove("airdress");
            stored.insert("key_id".into(), v["request_attestation"]["key_id"].clone());
            stored.insert("sig".into(), v["signature_b64url"].clone());
            assert_eq!(Value::Object(stored), v["stored_attestation"], "{name}");
        }
    }

    #[test]
    fn the_attestation_is_not_part_of_the_body_hash() {
        let a = serde_json::json!({"content": "x"});
        let b = serde_json::json!({"content": "x", "attestation": {"sig": "y"}});
        assert_eq!(body_hash(&a).unwrap(), body_hash(&b).unwrap());
    }
}
