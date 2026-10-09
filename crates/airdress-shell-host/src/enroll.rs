//! Enrolling this machine as a shell host, and renewing its approval
//! (design §5.4, FR-H3–FR-H6, SPEC-098's keypair enrollment).
//!
//! On first run the host makes its machine key and its shell key, asks the
//! operator to enroll it with purpose `shell-host`, and waits while the
//! person approves it — the owner, or a sub-user approving their own machine
//! (D-26). Whoever approves becomes the host's person. The poll that answers
//! the approval carries that person, the airdress root and the operator's
//! signing key; the host prints them with its own shell-key fingerprint and
//! writes `binding.json`, once.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::binding::{airdress_of, b64_std, Authorization, Binding, Principal};
use crate::paths::Paths;
use crate::trust::b64;

/// The purpose a shell host enrolls with.
pub const PURPOSE: &str = "shell-host";

const PROOF_DOMAIN: &[u8] = b"airdress-machine-enroll-v1\0";
const ANSWER_DOMAIN: &[u8] = b"airdress-machine-enroll-answer-v1\0";
const CODE_DOMAIN: &[u8] = b"airdress-machine-confirm-v1\0";

#[derive(Debug, Clone, Deserialize)]
struct OperatorKeyAnswer {
    public_key: String,
}

/// The operator's answer to an enrollment request.
#[derive(Debug, Clone, Deserialize)]
pub struct Started {
    pub device_code: String,
    pub user_code: String,
    pub expires_in: u64,
    pub interval: u64,
    pub fingerprint: String,
    #[serde(default)]
    pub verification_uri: Option<String>,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    operator_key: Option<OperatorKeyAnswer>,
    #[serde(default)]
    operator_proof: Option<String>,
}

/// SHA-256, the first 100 bits in base32, five groups of four: the
/// confirmation code both ends show.
pub fn confirmation_fingerprint(payload: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let d = Sha256::digest(payload);
    let mut s = String::with_capacity(24);
    for i in 0..20 {
        let bit = i * 5;
        let window = (u16::from(d[bit / 8]) << 8) | u16::from(d[bit / 8 + 1]);
        let idx = ((window >> (11 - bit % 8)) & 0x1f) as usize;
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(char::from(ALPHABET[idx]));
    }
    s
}

fn answer_message(origin: &str, user_code: &str, machine_key: &[u8; 32]) -> Vec<u8> {
    let origin = origin.trim().trim_end_matches('/').to_ascii_lowercase();
    let mut m = ANSWER_DOMAIN.to_vec();
    m.extend_from_slice(origin.as_bytes());
    m.push(0x1f);
    m.extend_from_slice(user_code.as_bytes());
    m.push(0x1f);
    m.extend_from_slice(machine_key);
    m
}

/// Check the operator's proof on its answer; returns the operator key it
/// verified and the confirmation code, or `None` when the answer was
/// unsigned.
fn confirm(
    started: &Started,
    origin: &str,
    machine: &[u8; 32],
) -> Result<Option<([u8; 32], String)>> {
    let (Some(k), Some(proof)) = (&started.operator_key, &started.operator_proof) else {
        return Ok(None);
    };
    let op: [u8; 32] = URL_SAFE_NO_PAD
        .decode(k.public_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("the operator's key in its answer is malformed")?;
    let sig = URL_SAFE_NO_PAD
        .decode(proof.trim())
        .ok()
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .context("the operator's proof is malformed")?;
    VerifyingKey::from_bytes(&op)?
        .verify_strict(&answer_message(origin, &started.user_code, machine), &sig)
        .map_err(|_| {
            anyhow::anyhow!("the operator's proof does not verify for {origin}; not continuing")
        })?;
    let mut payload = CODE_DOMAIN.to_vec();
    payload.extend_from_slice(&op);
    payload.extend_from_slice(machine);
    payload.extend_from_slice(started.user_code.as_bytes());
    Ok(Some((op, confirmation_fingerprint(&payload))))
}

fn proof(key: &SigningKey, device_code: &str) -> String {
    let mut m = PROOF_DOMAIN.to_vec();
    m.extend_from_slice(device_code.as_bytes());
    URL_SAFE_NO_PAD.encode(key.sign(&m).to_bytes())
}

async fn started_from(resp: reqwest::Response, origin: &str) -> Result<Started> {
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!("{origin} does not accept machine enrollments ([machines] is off there)");
    }
    if !status.is_success() {
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        bail!(
            "enrollment refused ({status}): {} {}",
            body["error"].as_str().unwrap_or(""),
            body["error_description"].as_str().unwrap_or("")
        );
    }
    resp.json().await.context("a malformed enrollment answer")
}

fn print_started(
    out: &mut dyn Write,
    s: &Started,
    machine: &[u8; 32],
    code: Option<&str>,
) -> Result<()> {
    writeln!(out, "This machine asks to become one of your shell hosts.")?;
    match (&s.verification_uri_complete, &s.verification_uri) {
        (Some(c), _) => writeln!(out, "Approve it at:  {c}")?,
        (None, Some(u)) => writeln!(out, "Approve it at:  {u}  with the code {}", s.user_code)?,
        (None, None) => writeln!(
            out,
            "Approve it with the code {} (`airdress machines approve`)",
            s.user_code
        )?,
    }
    writeln!(out, "User code:            {}", s.user_code)?;
    writeln!(
        out,
        "Machine fingerprint:  {}",
        crate::binding::key_fingerprint(machine)
    )?;
    if let Some(c) = code {
        writeln!(
            out,
            "Confirmation code:    {c}  (the approval page shows it too; they must match)"
        )?;
    }
    writeln!(
        out,
        "Whoever approves it becomes the person this host serves. Waiting…"
    )?;
    Ok(())
}

/// The approval, as the poll answers it.
#[derive(Debug, Clone)]
pub struct Decided {
    pub machine_id: Uuid,
    pub kid: String,
    pub authorized_until: Option<String>,
    pub body: Value,
}

async fn poll(
    http: &reqwest::Client,
    origin: &str,
    key: &SigningKey,
    s: &Started,
) -> Result<Decided> {
    let deadline = Instant::now() + Duration::from_secs(s.expires_in);
    let mut interval = Duration::from_secs(s.interval.max(1));
    let body = json!({ "device_code": s.device_code, "proof": proof(key, &s.device_code) });
    loop {
        tokio::time::sleep(interval).await;
        let resp = http
            .post(format!(
                "{}/v1/machines/enroll/poll",
                origin.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("could not reach {origin}"))?;
        let ok = resp.status().is_success();
        let v: Value = resp.json().await.context("a malformed poll answer")?;
        if ok {
            return Ok(Decided {
                machine_id: serde_json::from_value(v["machine_id"].clone())
                    .context("no machine id")?,
                kid: v["kid"].as_str().context("no kid")?.to_owned(),
                authorized_until: v["authorized_until"].as_str().map(str::to_owned),
                body: v,
            });
        }
        match v["error"].as_str().unwrap_or("") {
            "authorization_pending" => {}
            "slow_down" => interval += Duration::from_secs(5),
            "access_denied" => bail!("the approval was denied"),
            "expired_token" => bail!("the enrollment expired before anyone approved it"),
            other => bail!(
                "enrollment failed: {other} {}",
                v["error_description"].as_str().unwrap_or("")
            ),
        }
        if Instant::now() >= deadline {
            bail!("the enrollment expired before anyone approved it");
        }
    }
}

/// Enroll this machine with `origin` as `name`, wait for the approval, and
/// write the binding. Progress goes to `out`.
pub async fn enroll(
    paths: &Paths,
    http: &reqwest::Client,
    origin: &str,
    name: &str,
    out: &mut (dyn Write + Send),
) -> Result<Binding> {
    let origin = origin.trim_end_matches('/').to_owned();
    if !(origin.starts_with("https://")
        || origin.starts_with("http://127.0.0.1")
        || origin.starts_with("http://localhost"))
    {
        bail!("the operator must be an https:// origin");
    }
    let key = crate::binding::ensure_machine_key(paths)?;
    let shell = crate::binding::ensure_shell_key(paths)?;
    let public = key.verifying_key().to_bytes();
    let resp = http
        .post(format!("{origin}/v1/machines/enroll"))
        .json(&json!({ "public_key": URL_SAFE_NO_PAD.encode(public), "name": name, "purpose": PURPOSE }))
        .send()
        .await
        .with_context(|| format!("could not reach {origin}"))?;
    let started = started_from(resp, &origin).await?;
    if started.fingerprint != crate::binding::key_fingerprint(&public) {
        bail!(
            "the operator reported another fingerprint than this machine's key has; not continuing"
        );
    }
    let confirmed = confirm(&started, &origin, &public)?;
    print_started(
        out,
        &started,
        &public,
        confirmed.as_ref().map(|(_, c)| c.as_str()),
    )?;
    out.flush()?;
    let d = poll(http, &origin, &key, &started).await?;
    let principal: Principal = serde_json::from_value(d.body["principal"].clone()).context(
        "the approval names no person: this operator does not know shell hosts, or the \
         enrollment was approved as something else",
    )?;
    let op_key = d.body["operatorKey"]["publicKey"]
        .as_str()
        .context("the operator gave no frame-signing key; a host cannot verify what it is sent")?;
    let op_bytes: [u8; 32] = b64(op_key)
        .and_then(|b| b.try_into().ok())
        .context("the operator's frame-signing key is malformed")?;
    if let Some((answered, _)) = confirmed {
        if answered != op_bytes {
            bail!(
                "the operator signed its answer and its frames with different keys; not continuing"
            );
        }
    }
    let root = match &d.body["rootPublicKey"] {
        Value::String(s) => Some(
            b64(s)
                .filter(|b| b.len() == 32)
                .map(|b| b64_std(&b))
                .context("the root key is malformed")?,
        ),
        _ => None,
    };
    let binding = Binding {
        airdress: airdress_of(&origin)?,
        operator: origin,
        machine_id: d.machine_id,
        kid: d.kid,
        principal,
        root_public_key: root,
        operator_key: b64_std(&op_bytes),
        operator_kid: d.body["operatorKey"]["kid"].as_str().map(str::to_owned),
        bound_at: chrono::Utc::now(),
    };
    binding.save_new(paths)?;
    Authorization {
        authorized_until: d.authorized_until,
    }
    .save(paths)?;
    writeln!(out, "\n{}", binding.describe(shell.public()))?;
    Ok(binding)
}

/// Renew the approval before it lapses (FR-H6): the same machine key, a new
/// approval. The answer must be signed by the operator key this host pinned.
pub async fn reauth(
    paths: &Paths,
    http: &reqwest::Client,
    binding: &Binding,
    out: &mut (dyn Write + Send),
) -> Result<()> {
    let key = crate::binding::load_machine_key(paths)?;
    let public = key.verifying_key().to_bytes();
    let url = format!("{}/v1/machines/reauth", binding.operator);
    let headers = binding
        .signer(paths)?
        .headers(&http::Method::POST, &url, None, b"")
        .await?;
    let resp = http
        .post(&url)
        .headers(headers)
        .send()
        .await
        .with_context(|| format!("could not reach {}", binding.operator))?;
    let started = started_from(resp, &binding.operator).await?;
    let confirmed = confirm(&started, &binding.operator, &public)?.context(
        "the operator did not sign its answer, but this host pinned its key; not continuing",
    )?;
    let pinned: [u8; 32] = b64(&binding.operator_key)
        .and_then(|b| b.try_into().ok())
        .context("pinned key")?;
    if confirmed.0 != pinned {
        bail!("the operator answered with another key than the one this host pinned; enroll again if the operator's key really changed");
    }
    print_started(out, &started, &public, Some(&confirmed.1))?;
    let d = poll(http, &binding.operator, &key, &started).await?;
    if d.machine_id != binding.machine_id {
        bail!("the renewal answered for another machine");
    }
    Authorization {
        authorized_until: d.authorized_until.clone(),
    }
    .save(paths)?;
    writeln!(
        out,
        "Renewed{}.",
        d.authorized_until
            .map(|u| format!(" until {u}"))
            .unwrap_or_default()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_confirmation_code_is_the_operators_encoding() {
        // The operator's own test value for an empty payload.
        assert_eq!(confirmation_fingerprint(b""), "4OYM-IQUY-7QOB-JGX3-6TEJ");
    }

    #[test]
    fn the_answer_proof_binds_origin_code_and_key() {
        let op = SigningKey::from_bytes(&[5; 32]);
        let machine = [7u8; 32];
        let sig = op.sign(&answer_message("https://A.example/", "WDJB-MJHT", &machine));
        let started = |proof: &str| Started {
            device_code: "d".into(),
            user_code: "WDJB-MJHT".into(),
            expires_in: 600,
            interval: 5,
            fingerprint: String::new(),
            verification_uri: None,
            verification_uri_complete: None,
            operator_key: Some(OperatorKeyAnswer {
                public_key: URL_SAFE_NO_PAD.encode(op.verifying_key().to_bytes()),
            }),
            operator_proof: Some(proof.into()),
        };
        let good = started(&URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let (k, code) = confirm(&good, "https://a.example", &machine)
            .unwrap()
            .unwrap();
        assert_eq!(k, op.verifying_key().to_bytes());
        assert_eq!(code.len(), 24);
        assert!(confirm(&good, "https://b.example", &machine).is_err());
        assert!(confirm(&good, "https://a.example", &[8; 32]).is_err());
    }
}
