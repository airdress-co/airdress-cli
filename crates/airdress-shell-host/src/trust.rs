//! Who may reach this host's sessions: the host's own checks, which do not
//! trust the operator (design §4.4, §6.2–§6.4, FR-D3, FR-E5).
//!
//! The operator attests, in every signed `open` and `attach` frame, which
//! keys belong to which device. The host takes that as an input, never as an
//! answer:
//!
//! 2. the device's principal must be the one this host is bound to;
//! 3. the device's own statement of its shell keys must verify under its
//!    identity key, and that statement covers `presenceAlg`, so a `none` is
//!    the device's own word;
//! 4. an **owner device** must carry a delegation signed by the airdress
//!    root this host pinned at enrollment, naming that identity key, not
//!    expired, and not revoked here. Its device kind comes from inside the
//!    signed delegation;
//! 5. a **sub-user device** (operator-held, no root delegation) must already
//!    be **introduced** on this host: the first one confirmed by the person
//!    at the machine (`airdress shell host trust`), each further one by an
//!    introduction signed by a device already trusted here. Its kind comes
//!    from that introduction;
//! 6. `presenceAlg: none` is admitted only when the kind from 4 or 5 is
//!    `cli` (D-30).
//!
//! A substituted key fails 4 or 5 whatever the operator signs; a phone
//! rewritten to `none` fails 3 or 6.
//!
//! What the host learned is kept in `devices.json` (0600, nothing secret in
//! it): the devices it verified, the ones it was introduced to, the ones the
//! person confirmed, the ones it was told are revoked, and the ones that
//! knocked before they were introduced.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use airdress_shell_proto::presence::{PresenceAlg, PresenceRequirement, DEVICE_KIND_CLI};
use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::paths::Paths;

/// The device-keys statement's label (the operator's layout).
pub const DEVICE_KEYS_LABEL: &[u8] = b"airdress.shell.device-keys.v1";
/// The introduction statement's label (the operator's layout).
pub const INTRODUCTION_LABEL: &[u8] = b"airdress.shell.introduction.v1";

/// A refusal, with the code that goes back to the device (design §13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub why: &'static str,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.why)
    }
}

const fn refuse(code: &'static str, why: &'static str) -> Refusal {
    Refusal { code, why }
}

/// Base64 in any of its four spellings (the operator writes standard).
pub fn b64(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(raw).ok())
}

fn b64_32(raw: &str) -> Option<[u8; 32]> {
    b64(raw)?.try_into().ok()
}

/// `SHA256:<base64>` of an Ed25519 identity key: what the person compares.
pub fn identity_fingerprint(key: &[u8; 32]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(key)))
}

/// The longest device label shown here, in characters (the operator's
/// bound as well).
pub const LABEL_MAX_CHARS: usize = 80;

/// A device label as this host shows it: control characters dropped,
/// trimmed, at most [`LABEL_MAX_CHARS`]; `None` when nothing is left. The
/// operator cleans it the same way; the host does not rely on that, since
/// the label lands in prompts on this terminal and in every client's
/// `roles`.
pub fn clean_label(label: Option<&str>) -> Option<String> {
    let clean: String = label?
        .chars()
        .filter(|c| !c.is_control())
        .take(LABEL_MAX_CHARS)
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_owned())
}

/// The bytes a device signs to register its shell keys.
pub fn device_keys_statement(
    device: Uuid,
    dh_public: &[u8; 32],
    presence_alg: &str,
    presence_public: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEVICE_KEYS_LABEL.len() + 1 + 16 + 32 + 6 + 65);
    out.extend_from_slice(DEVICE_KEYS_LABEL);
    out.push(0);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(dh_public);
    out.extend_from_slice(presence_alg.as_bytes());
    out.push(0);
    if let Some(p) = presence_public {
        out.extend_from_slice(p);
    }
    out
}

/// The bytes a device signs to introduce another device of its person.
pub fn introduction_statement(
    introducer: Uuid,
    device: Uuid,
    identity_public: &[u8; 32],
    device_kind: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(INTRODUCTION_LABEL.len() + 1 + 16 + 16 + 32 + 8);
    out.extend_from_slice(INTRODUCTION_LABEL);
    out.push(0);
    out.extend_from_slice(introducer.as_bytes());
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(identity_public);
    out.extend_from_slice(device_kind.as_bytes());
    out
}

fn verifies(identity: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(identity) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

/// Compact JSON with keys sorted at every level: the delegation's signing
/// input, written out here rather than trusting a map's iteration order.
pub fn canonical_json(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<&String, &Value> = m.iter().collect();
            out.push(b'{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(k)
                        .expect("a string serializes")
                        .as_bytes(),
                );
                out.push(b':');
                canonical_json(v, out);
            }
            out.push(b'}');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(v, out);
            }
            out.push(b']');
        }
        other => out.extend_from_slice(
            serde_json::to_string(other)
                .expect("a scalar serializes")
                .as_bytes(),
        ),
    }
}

/// Check a root-signed delegation (design §6.3 step 4) and return the device
/// kind it carries (`device_kind`, or `unspecified`).
pub fn verify_delegation(
    delegation: &Value,
    root: &[u8; 32],
    identity: &[u8; 32],
    airdress: &str,
    now: SystemTime,
) -> Result<String, Refusal> {
    let bad = |why| refuse("shell_handshake_failed", why);
    let obj = delegation
        .as_object()
        .ok_or(bad("the delegation is not an object"))?;
    let sig = obj
        .get("signature")
        .and_then(Value::as_str)
        .and_then(b64)
        .ok_or(bad("the delegation carries no signature"))?;
    let mut body = obj.clone();
    body.remove("signature");
    let mut canonical = Vec::new();
    canonical_json(&Value::Object(body), &mut canonical);
    if !verifies(root, &canonical, &sig) {
        return Err(bad("the delegation is not signed by the pinned root"));
    }
    let named = obj
        .get("device_session_public_key")
        .and_then(Value::as_str)
        .and_then(b64_32)
        .ok_or(bad("the delegation names no key"))?;
    if &named != identity {
        return Err(bad("the delegation names another key"));
    }
    if let Some(a) = obj.get("airdress").and_then(Value::as_str) {
        if !a.eq_ignore_ascii_case(airdress) {
            return Err(bad("the delegation is for another airdress"));
        }
    }
    if let Some(exp) = obj.get("expires_at").and_then(Value::as_str) {
        let exp: SystemTime = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|_| bad("the delegation's expiry is unreadable"))?
            .with_timezone(&chrono::Utc)
            .into();
        if exp <= now {
            return Err(bad("the delegation expired"));
        }
    }
    Ok(obj
        .get("device_kind")
        .and_then(Value::as_str)
        .unwrap_or("unspecified")
        .to_owned())
}

/// What the operator vouches for in an `open` or `attach` frame (design
/// §6.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub device: Uuid,
    pub principal: Uuid,
    #[serde(default)]
    pub device_class: Option<String>,
    /// What the operator says the kind is. Never used for the presence rule.
    #[serde(default)]
    pub device_kind: Option<String>,
    pub identity_public: String,
    #[serde(default)]
    pub delegation: Option<Value>,
    pub dh_public: String,
    #[serde(default)]
    pub presence_public: Option<String>,
    pub presence_alg: String,
    pub keys_sig: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// How a device came to be trusted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    /// A root-signed delegation (an owner device).
    Delegation,
    /// Confirmed by the person at this machine.
    Confirmed,
    /// Introduced by a device already trusted here.
    Introduced,
}

/// A device the host knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownDevice {
    pub identity: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: TrustSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced_by: Option<Uuid>,
    /// The X25519 shell key last verified for it: a recording recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dh: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// A device that knocked before it was introduced, or that the operator
/// listed as the person's (`GET /v1/shells/host/devices`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDevice {
    pub identity: String,
    /// What the operator said its kind is; the person confirms it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind_claimed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// One entry of `GET /v1/shells/host/devices`: what the operator says
/// about one of the person's devices. Read, never believed: the person
/// compares `identityFingerprint` with the device in their hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListedDevice {
    pub device: Uuid,
    /// The operator's claim of the kind.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub identity_public: String,
    pub identity_fingerprint: String,
    #[serde(default)]
    pub shell_key: Option<String>,
    #[serde(default)]
    pub shell_key_public: Option<String>,
    #[serde(default)]
    pub presence_alg: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

/// `devices.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStore {
    #[serde(default)]
    pub devices: BTreeMap<Uuid, KnownDevice>,
    #[serde(default)]
    pub revoked: BTreeSet<Uuid>,
    #[serde(default)]
    pub pending: BTreeMap<Uuid, PendingDevice>,
}

impl DeviceStore {
    /// Read the store; a missing file is an empty store.
    pub fn load(paths: &Paths) -> Result<Self> {
        let p = paths.devices();
        if !p.exists() {
            return Ok(Self::default());
        }
        crate::paths::ensure_private_file(&p)?;
        let raw = std::fs::read(&p).with_context(|| format!("could not read {}", p.display()))?;
        serde_json::from_slice(&raw).with_context(|| format!("{} is malformed", p.display()))
    }

    /// Write the store, atomically, 0600.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        crate::paths::write_private_atomic(&paths.devices(), &bytes)
    }

    /// The devices' X25519 keys: who a recording is wrapped to.
    pub fn recipients(&self) -> Vec<(Uuid, [u8; 32])> {
        self.devices
            .iter()
            .filter(|(d, _)| !self.revoked.contains(d))
            .filter_map(|(d, k)| Some((*d, b64_32(k.dh.as_deref()?)?)))
            .collect()
    }

    /// Whether `device` is trusted here now.
    pub fn trusted(&self, device: &Uuid) -> bool {
        self.devices.contains_key(device) && !self.revoked.contains(device)
    }

    /// The person confirmed a pending device by its identity fingerprint
    /// (design §6.3 step 5, `airdress shell host trust`).
    pub fn confirm(&mut self, fingerprint: &str, kind: &str) -> Result<Uuid> {
        let found = self
            .pending
            .iter()
            .find(|(_, p)| {
                b64_32(&p.identity).is_some_and(|k| identity_fingerprint(&k) == fingerprint.trim())
            })
            .map(|(d, _)| *d)
            .with_context(|| {
                format!("no device with fingerprint {fingerprint} has asked this host yet")
            })?;
        anyhow::ensure!(
            !self.revoked.contains(&found),
            "that device was revoked; it cannot be trusted again"
        );
        let p = self.pending.remove(&found).expect("found");
        self.devices.insert(
            found,
            KnownDevice {
                identity: p.identity,
                kind: kind.to_owned(),
                label: p.label,
                source: TrustSource::Confirmed,
                introduced_by: None,
                dh: None,
                at: chrono::Utc::now(),
            },
        );
        Ok(found)
    }

    /// An `introduce` frame (design §6.3 step 5): `introducer` vouches for
    /// `device` with its own identity key.
    pub fn introduce(
        &mut self,
        introducer: Uuid,
        device: Uuid,
        identity: &[u8; 32],
        kind: &str,
        sig: &[u8],
    ) -> Result<(), Refusal> {
        if self.revoked.contains(&device) {
            return Err(refuse(
                "device_revoked",
                "an introduction of a revoked device",
            ));
        }
        let by = self
            .devices
            .get(&introducer)
            .filter(|_| !self.revoked.contains(&introducer))
            .ok_or(refuse(
                "shell_device_not_introduced",
                "the introducer is not trusted on this host",
            ))?;
        let by_key = b64_32(&by.identity).ok_or(refuse("shell_handshake_failed", "stored key"))?;
        if !verifies(
            &by_key,
            &introduction_statement(introducer, device, identity, kind),
            sig,
        ) {
            return Err(refuse(
                "shell_handshake_failed",
                "the introduction does not verify under the introducer's key",
            ));
        }
        if let Some(known) = self.devices.get(&device) {
            if b64_32(&known.identity).as_ref() != Some(identity) {
                return Err(refuse(
                    "shell_handshake_failed",
                    "an introduction that changes a trusted device's key",
                ));
            }
            return Ok(());
        }
        self.pending.remove(&device);
        self.devices.insert(
            device,
            KnownDevice {
                identity: STANDARD.encode(identity),
                kind: kind.to_owned(),
                label: None,
                source: TrustSource::Introduced,
                introduced_by: Some(introducer),
                dh: None,
                at: chrono::Utc::now(),
            },
        );
        Ok(())
    }

    /// Take the operator's list of the person's devices as pending ones
    /// (design §6.3, first-device trust): each becomes something the person
    /// at the machine can confirm by fingerprint, as if it had knocked. A
    /// device trusted or revoked here is left alone, and so is one whose
    /// listed fingerprint does not name its listed key. Nothing here is
    /// trusted: the kind stays the operator's claim and `trust` still asks.
    /// Returns how many were added.
    pub fn offer(&mut self, listed: &[ListedDevice]) -> usize {
        let mut added = 0;
        for d in listed {
            if self.devices.contains_key(&d.device) || self.revoked.contains(&d.device) {
                continue;
            }
            let Some(key) = b64_32(&d.identity_public) else {
                continue;
            };
            if identity_fingerprint(&key) != d.identity_fingerprint.trim() {
                tracing::warn!(device = %d.device, "the operator listed a fingerprint that does not name the key it listed");
                continue;
            }
            let label = clean_label(d.label.as_deref());
            match self.pending.get_mut(&d.device) {
                Some(p) if b64_32(&p.identity) == Some(key) => {
                    if label.is_some() {
                        p.label = label;
                    }
                    if p.kind_claimed.is_none() {
                        p.kind_claimed.clone_from(&d.kind);
                    }
                }
                _ => {
                    self.pending.insert(
                        d.device,
                        PendingDevice {
                            identity: STANDARD.encode(key),
                            kind_claimed: d.kind.clone(),
                            label,
                            at: chrono::Utc::now(),
                        },
                    );
                    added += 1;
                }
            }
        }
        added
    }

    /// `revoke_device`: the device is cut off here for good.
    pub fn revoke(&mut self, device: Uuid) {
        self.revoked.insert(device);
        self.pending.remove(&device);
    }
}

/// What this host is bound to, for the checks.
#[derive(Debug, Clone)]
pub struct BindingFacts {
    pub principal: Uuid,
    pub root: Option<[u8; 32]>,
    pub airdress: String,
}

/// A device that passed steps 2–6.
#[derive(Debug, Clone)]
pub struct Verified {
    pub device: Uuid,
    pub identity: [u8; 32],
    pub dh: [u8; 32],
    pub kind: String,
    pub label: String,
    pub requirement: PresenceRequirement,
}

/// Steps 2–6 of design §6.3. Updates `store` with what was learned: a
/// delegation-verified device and its shell key, or a device that knocked
/// before it was introduced.
pub fn check_attestation(
    att: &Attestation,
    binding: &BindingFacts,
    store: &mut DeviceStore,
    now: SystemTime,
) -> Result<Verified, Refusal> {
    let hs = |why| refuse("shell_handshake_failed", why);
    // 2. The bound person, and nobody else.
    if att.principal != binding.principal {
        return Err(hs("a device of another person"));
    }
    if att.device_class.as_deref().is_some_and(|c| c != "human") {
        return Err(hs("not a human device"));
    }
    if store.revoked.contains(&att.device) {
        return Err(refuse(
            "device_revoked",
            "this device was revoked on this host",
        ));
    }
    let identity = b64_32(&att.identity_public).ok_or(hs("identity key malformed"))?;
    let dh = b64_32(&att.dh_public).ok_or(hs("shell key malformed"))?;
    let presence_public = match att.presence_public.as_deref() {
        Some(p) => Some(b64(p).ok_or(hs("presence key malformed"))?),
        None => None,
    };
    let alg = match att.presence_alg.as_str() {
        "p256" => PresenceAlg::P256,
        "none" => PresenceAlg::None,
        _ => {
            return Err(refuse(
                "shell_presence_required",
                "unknown presence algorithm",
            ))
        }
    };
    // 3. The device's own statement, covering presenceAlg.
    let sig = b64(&att.keys_sig).ok_or(hs("keys signature malformed"))?;
    let statement = device_keys_statement(
        att.device,
        &dh,
        &att.presence_alg,
        presence_public.as_deref(),
    );
    if !verifies(&identity, &statement, &sig) {
        return Err(refuse(
            "shell_presence_required",
            "the device's key statement does not verify under its identity",
        ));
    }
    // 4 / 5. Where the kind comes from.
    let att_label = clean_label(att.label.as_deref());
    let label = att_label.clone().unwrap_or_default();
    let kind = match att.delegation.as_ref().filter(|d| !d.is_null()) {
        Some(delegation) => {
            let root = binding
                .root
                .ok_or(hs("this host pinned no root, so it admits no delegation"))?;
            let kind = verify_delegation(delegation, &root, &identity, &binding.airdress, now)?;
            let prev = store.devices.get(&att.device);
            if prev.is_some_and(|p| b64_32(&p.identity).as_ref() != Some(&identity)) {
                // A new delegation for a known device id under a new key is
                // a re-enrollment; the root signed it, so it stands.
                tracing::info!(device = %att.device, "a device's identity key changed under a root delegation");
            }
            let prev_label = prev.and_then(|p| p.label.clone());
            store.devices.insert(
                att.device,
                KnownDevice {
                    identity: STANDARD.encode(identity),
                    kind: kind.clone(),
                    label: att_label.clone().or(prev_label),
                    source: TrustSource::Delegation,
                    introduced_by: None,
                    dh: Some(STANDARD.encode(dh)),
                    at: chrono::Utc::now(),
                },
            );
            kind
        }
        None => {
            let known = store.devices.get_mut(&att.device);
            match known {
                Some(k) if b64_32(&k.identity).as_ref() == Some(&identity) => {
                    k.dh = Some(STANDARD.encode(dh));
                    // The name the device carries now, as the operator
                    // attests it; a display name, never a credential.
                    if att_label.is_some() {
                        k.label.clone_from(&att_label);
                    }
                    k.kind.clone()
                }
                Some(_) => {
                    return Err(hs(
                        "the identity key is not the one introduced on this host",
                    ));
                }
                None => {
                    store.pending.insert(
                        att.device,
                        PendingDevice {
                            identity: STANDARD.encode(identity),
                            kind_claimed: att.device_kind.clone(),
                            label: att_label.clone(),
                            at: chrono::Utc::now(),
                        },
                    );
                    return Err(refuse(
                        "shell_device_not_introduced",
                        "this device is not introduced on this host",
                    ));
                }
            }
        }
    };
    // 6. The presence rule.
    let requirement = match (alg, presence_public) {
        (PresenceAlg::P256, Some(pk)) if matches!(pk.len(), 33 | 65) => {
            PresenceRequirement::Unlock(pk)
        }
        (PresenceAlg::P256, _) => {
            return Err(refuse("shell_presence_required", "p256 without a key"))
        }
        (PresenceAlg::None, None) if kind == DEVICE_KIND_CLI => PresenceRequirement::NotRequired,
        (PresenceAlg::None, None) => {
            return Err(refuse(
                "shell_presence_required",
                "no presence key on a device that is not a CLI",
            ))
        }
        (PresenceAlg::None, Some(_)) => {
            return Err(refuse(
                "shell_presence_required",
                "none with a presence key",
            ))
        }
    };
    Ok(Verified {
        device: att.device,
        identity,
        dh,
        kind,
        label,
        requirement,
    })
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Devices, delegations and attestations for tests.
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A device: an identity key and a shell key.
    #[derive(Debug)]
    pub struct TestDevice {
        pub id: Uuid,
        pub identity: SigningKey,
        pub dh: [u8; 32],
        pub presence: Option<Vec<u8>>,
    }

    impl TestDevice {
        pub fn new(seed: u8, dh: [u8; 32], presence: Option<Vec<u8>>) -> Self {
            Self {
                id: Uuid::from_u128(u128::from(seed)),
                identity: SigningKey::from_bytes(&[seed; 32]),
                dh,
                presence,
            }
        }

        pub fn identity_public(&self) -> [u8; 32] {
            self.identity.verifying_key().to_bytes()
        }

        /// The device's attestation, signed by itself.
        pub fn attestation(&self, principal: Uuid, delegation: Option<Value>) -> Attestation {
            let alg = if self.presence.is_some() {
                "p256"
            } else {
                "none"
            };
            let st = device_keys_statement(self.id, &self.dh, alg, self.presence.as_deref());
            Attestation {
                device: self.id,
                principal,
                device_class: Some("human".into()),
                device_kind: None,
                identity_public: STANDARD.encode(self.identity_public()),
                delegation,
                dh_public: STANDARD.encode(self.dh),
                presence_public: self.presence.as_ref().map(|p| STANDARD.encode(p)),
                presence_alg: alg.into(),
                keys_sig: STANDARD.encode(self.identity.sign(&st).to_bytes()),
                label: Some(format!("device {}", self.id.as_u128())),
            }
        }

        /// An introduction of `other` by this device.
        pub fn introduce(&self, other: &TestDevice, kind: &str) -> Vec<u8> {
            self.identity
                .sign(&introduction_statement(
                    self.id,
                    other.id,
                    &other.identity_public(),
                    kind,
                ))
                .to_bytes()
                .to_vec()
        }
    }

    /// A root-signed delegation of `identity`, with `kind`.
    pub fn delegation(
        root: &SigningKey,
        identity: &[u8; 32],
        airdress: &str,
        kind: Option<&str>,
        expires: &str,
    ) -> Value {
        let mut v = serde_json::json!({
            "airdress": airdress,
            "device_session_public_key": URL_SAFE_NO_PAD.encode(identity),
            "issued_at": "2026-10-01T00:00:00Z",
            "expires_at": expires,
            "role": "human_held",
        });
        if let Some(k) = kind {
            v["device_kind"] = Value::from(k);
        }
        let mut c = Vec::new();
        canonical_json(&v, &mut c);
        v["signature"] = Value::from(URL_SAFE_NO_PAD.encode(root.sign(&c).to_bytes()));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use ed25519_dalek::SigningKey;

    const AIRDRESS: &str = "a.example";

    fn binding(root: &SigningKey) -> BindingFacts {
        BindingFacts {
            principal: Uuid::from_u128(77),
            root: Some(root.verifying_key().to_bytes()),
            airdress: AIRDRESS.into(),
        }
    }

    fn p256_point() -> Vec<u8> {
        // Any well-formed-looking SEC1 compressed point; the unlock itself is
        // checked by the protocol crate at admission.
        let mut p = vec![0x02];
        p.extend_from_slice(&[7u8; 32]);
        p
    }

    #[test]
    fn the_statement_is_the_protocol_crates() {
        let id = Uuid::from_u128(0x0199_a1b2_0000_4000_8000_0000_0000_a001);
        let point = p256_point();
        for (alg, pk) in [("p256", Some(point.clone())), ("none", None)] {
            let proto = airdress_shell_proto::presence::DeviceKeys {
                device: id.to_string(),
                principal: "anyone".into(),
                identity_public: [1; 32],
                dh_public: [9; 32],
                presence_alg: if pk.is_some() {
                    PresenceAlg::P256
                } else {
                    PresenceAlg::None
                },
                presence_public: pk.clone(),
            };
            assert_eq!(
                proto.signed_bytes().unwrap(),
                device_keys_statement(id, &[9; 32], alg, pk.as_deref())
            );
        }
    }

    #[test]
    fn the_canonical_form_is_the_operators() {
        // The shared vector `minimal-realistic` of the operator's
        // delegation fixtures.
        let v = serde_json::json!({
            "role": "human_held",
            "issued_at": "2026-04-11T09:30:00Z",
            "device_session_public_key": "Xj7fWc0lM3kQm9nHqR5tUvY1bZ2aC4dE6fG8hI0jK1w",
            "device_label": "Alice's iPhone",
            "airdress": "alice.humans.airdress.co",
        });
        let mut c = Vec::new();
        canonical_json(&v, &mut c);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&c),
            "eyJhaXJkcmVzcyI6ImFsaWNlLmh1bWFucy5haXJkcmVzcy5jbyIsImRldmljZV9sYWJlbCI6IkFsaWNlJ3MgaVBob25lIiwiZGV2aWNlX3Nlc3Npb25fcHVibGljX2tleSI6IlhqN2ZXYzBsTTNrUW05bkhxUjV0VXZZMWJaMmFDNGRFNmZHOGhJMGpLMXciLCJpc3N1ZWRfYXQiOiIyMDI2LTA0LTExVDA5OjMwOjAwWiIsInJvbGUiOiJodW1hbl9oZWxkIn0"
        );
    }

    #[test]
    fn an_owner_device_is_admitted_by_its_delegation_and_its_kind_comes_from_it() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let mut store = DeviceStore::default();
        let cli = TestDevice::new(5, [9; 32], None);
        let d = delegation(
            &root,
            &cli.identity_public(),
            AIRDRESS,
            Some("cli"),
            "2099-01-01T00:00:00Z",
        );
        let v = check_attestation(
            &cli.attestation(Uuid::from_u128(77), Some(d)),
            &binding(&root),
            &mut store,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(v.kind, "cli");
        assert_eq!(v.requirement, PresenceRequirement::NotRequired);
        assert_eq!(store.recipients(), vec![(cli.id, [9; 32])]);
    }

    #[test]
    fn a_substituted_key_fails_whatever_the_operator_signs() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let real = TestDevice::new(5, [9; 32], Some(p256_point()));
        let d = delegation(
            &root,
            &real.identity_public(),
            AIRDRESS,
            Some("phone"),
            "2099-01-01T00:00:00Z",
        );
        // The operator swaps in its own identity and shell key, signing the
        // statement itself, and keeps the real delegation.
        let evil = TestDevice::new(6, [8; 32], Some(p256_point()));
        let mut att = evil.attestation(Uuid::from_u128(77), Some(d));
        att.device = real.id;
        att.keys_sig = {
            use ed25519_dalek::Signer as _;
            let st = device_keys_statement(real.id, &evil.dh, "p256", evil.presence.as_deref());
            STANDARD.encode(evil.identity.sign(&st).to_bytes())
        };
        let err = check_attestation(
            &att,
            &binding(&root),
            &mut DeviceStore::default(),
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err.code, "shell_handshake_failed");
        assert_eq!(err.why, "the delegation names another key");
    }

    #[test]
    fn a_phone_rewritten_to_none_is_refused() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let phone = TestDevice::new(5, [9; 32], Some(p256_point()));
        let d = delegation(
            &root,
            &phone.identity_public(),
            AIRDRESS,
            Some("phone"),
            "2099-01-01T00:00:00Z",
        );
        let mut att = phone.attestation(Uuid::from_u128(77), Some(d.clone()));
        // The operator strips the presence key: the device's signature no
        // longer covers the statement.
        att.presence_alg = "none".into();
        att.presence_public = None;
        let err = check_attestation(
            &att,
            &binding(&root),
            &mut DeviceStore::default(),
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err.code, "shell_presence_required");
        // And a phone that itself said `none` is still not a CLI.
        let no_key = TestDevice::new(5, [9; 32], None);
        let err = check_attestation(
            &no_key.attestation(Uuid::from_u128(77), Some(d)),
            &binding(&root),
            &mut DeviceStore::default(),
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err.why, "no presence key on a device that is not a CLI");
        // Even when the operator claims the kind is cli.
        let mut att = no_key.attestation(
            Uuid::from_u128(77),
            Some(delegation(
                &root,
                &no_key.identity_public(),
                AIRDRESS,
                Some("phone"),
                "2099-01-01T00:00:00Z",
            )),
        );
        att.device_kind = Some("cli".into());
        assert!(check_attestation(
            &att,
            &binding(&root),
            &mut DeviceStore::default(),
            SystemTime::now()
        )
        .is_err());
    }

    #[test]
    fn another_person_another_root_or_an_expired_delegation_is_refused() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let other_root = SigningKey::from_bytes(&[2; 32]);
        let cli = TestDevice::new(5, [9; 32], None);
        let ok = delegation(
            &root,
            &cli.identity_public(),
            AIRDRESS,
            Some("cli"),
            "2099-01-01T00:00:00Z",
        );
        let mut s = DeviceStore::default();
        assert!(check_attestation(
            &cli.attestation(Uuid::from_u128(78), Some(ok)),
            &binding(&root),
            &mut s,
            SystemTime::now()
        )
        .is_err());
        let wrong = delegation(
            &other_root,
            &cli.identity_public(),
            AIRDRESS,
            Some("cli"),
            "2099-01-01T00:00:00Z",
        );
        assert!(check_attestation(
            &cli.attestation(Uuid::from_u128(77), Some(wrong)),
            &binding(&root),
            &mut s,
            SystemTime::now()
        )
        .is_err());
        let old = delegation(
            &root,
            &cli.identity_public(),
            AIRDRESS,
            Some("cli"),
            "2020-01-01T00:00:00Z",
        );
        let err = check_attestation(
            &cli.attestation(Uuid::from_u128(77), Some(old)),
            &binding(&root),
            &mut s,
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err.why, "the delegation expired");
        let elsewhere = delegation(
            &root,
            &cli.identity_public(),
            "b.example",
            Some("cli"),
            "2099-01-01T00:00:00Z",
        );
        assert!(check_attestation(
            &cli.attestation(Uuid::from_u128(77), Some(elsewhere)),
            &binding(&root),
            &mut s,
            SystemTime::now()
        )
        .is_err());
    }

    #[test]
    fn a_sub_user_device_needs_an_introduction_and_its_kind_comes_from_it() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let first = TestDevice::new(10, [1; 32], Some(p256_point()));
        let laptop = TestDevice::new(11, [2; 32], None);
        let mut s = DeviceStore::default();
        let b = binding(&root);
        // Neither is known: refused, and remembered as pending.
        let err = check_attestation(
            &first.attestation(Uuid::from_u128(77), None),
            &b,
            &mut s,
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err.code, "shell_device_not_introduced");
        assert!(s.pending.contains_key(&first.id));
        // The person at the machine confirms the first one by fingerprint.
        let fp = identity_fingerprint(&first.identity_public());
        assert!(s.confirm("SHA256:nope", "phone").is_err());
        assert_eq!(s.confirm(&fp, "phone").unwrap(), first.id);
        let v = check_attestation(
            &first.attestation(Uuid::from_u128(77), None),
            &b,
            &mut s,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(v.requirement, PresenceRequirement::Unlock(_)));
        // The first introduces the laptop as a CLI.
        let sig = first.introduce(&laptop, "cli");
        // A forged introduction (the operator's own key) does not count.
        let forged = TestDevice::new(12, [3; 32], None).introduce(&laptop, "cli");
        assert!(s
            .introduce(
                first.id,
                laptop.id,
                &laptop.identity_public(),
                "cli",
                &forged
            )
            .is_err());
        // Nor one whose kind was rewritten.
        assert!(s
            .introduce(
                first.id,
                laptop.id,
                &laptop.identity_public(),
                "phone",
                &sig
            )
            .is_err());
        s.introduce(first.id, laptop.id, &laptop.identity_public(), "cli", &sig)
            .unwrap();
        let v = check_attestation(
            &laptop.attestation(Uuid::from_u128(77), None),
            &b,
            &mut s,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(v.requirement, PresenceRequirement::NotRequired);
        // An attested key that is not the introduced one is refused.
        let impostor = TestDevice::new(13, [4; 32], None);
        let mut att = impostor.attestation(Uuid::from_u128(77), None);
        att.device = laptop.id;
        att.keys_sig = {
            use ed25519_dalek::Signer as _;
            STANDARD.encode(
                impostor
                    .identity
                    .sign(&device_keys_statement(
                        laptop.id,
                        &impostor.dh,
                        "none",
                        None,
                    ))
                    .to_bytes(),
            )
        };
        assert_eq!(
            check_attestation(&att, &b, &mut s, SystemTime::now())
                .unwrap_err()
                .code,
            "shell_handshake_failed"
        );
        // A revoked device stays out, and cannot be introduced again.
        s.revoke(laptop.id);
        assert_eq!(
            check_attestation(
                &laptop.attestation(Uuid::from_u128(77), None),
                &b,
                &mut s,
                SystemTime::now()
            )
            .unwrap_err()
            .code,
            "device_revoked"
        );
        assert!(s
            .introduce(first.id, laptop.id, &laptop.identity_public(), "cli", &sig)
            .is_err());
    }

    #[test]
    fn the_store_round_trips_as_a_private_file() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let mut s = DeviceStore::default();
        s.revoke(Uuid::from_u128(1));
        s.save(&p).unwrap();
        assert_eq!(DeviceStore::load(&p).unwrap(), s);
        crate::paths::ensure_private_file(&p.devices()).unwrap();
    }

    #[test]
    fn a_label_is_cleaned_and_bounded() {
        assert_eq!(
            clean_label(Some(" Galaxy S23 ")).as_deref(),
            Some("Galaxy S23")
        );
        assert_eq!(clean_label(Some("a\u{1b}[2Jb\n")).as_deref(), Some("a[2Jb"));
        assert_eq!(clean_label(Some(" \u{7}\n ")), None);
        assert_eq!(clean_label(None), None);
        let long = "x".repeat(LABEL_MAX_CHARS + 5);
        assert_eq!(
            clean_label(Some(&long)).unwrap().chars().count(),
            LABEL_MAX_CHARS
        );
    }

    #[test]
    fn the_operators_list_is_offered_as_pending_and_never_trusted() {
        let key = [5u8; 32];
        let listed = |device: u128, key: [u8; 32], fp: String| ListedDevice {
            device: Uuid::from_u128(device),
            kind: Some("cli".into()),
            label: Some("laptop\u{7}".into()),
            identity_public: STANDARD.encode(key),
            identity_fingerprint: fp,
            shell_key: None,
            shell_key_public: None,
            presence_alg: Some("none".into()),
            created_at: None,
            last_seen_at: None,
        };
        let mut s = DeviceStore::default();
        s.revoke(Uuid::from_u128(3));
        s.devices.insert(
            Uuid::from_u128(4),
            KnownDevice {
                identity: STANDARD.encode([4u8; 32]),
                kind: "phone".into(),
                label: None,
                source: TrustSource::Confirmed,
                introduced_by: None,
                dh: None,
                at: chrono::Utc::now(),
            },
        );
        let added = s.offer(&[
            listed(1, key, identity_fingerprint(&key)),
            // A fingerprint that names another key.
            listed(2, key, identity_fingerprint(&[6; 32])),
            listed(3, key, identity_fingerprint(&key)),
            listed(4, [9; 32], identity_fingerprint(&[9; 32])),
        ]);
        assert_eq!(added, 1);
        let p = &s.pending[&Uuid::from_u128(1)];
        assert_eq!(p.label.as_deref(), Some("laptop"));
        assert_eq!(p.kind_claimed.as_deref(), Some("cli"));
        assert!(!s.trusted(&Uuid::from_u128(1)));
        assert_eq!(s.pending.len(), 1);
        // Offering again adds nothing.
        assert_eq!(s.offer(&[listed(1, key, identity_fingerprint(&key))]), 0);
        // Confirming it is the person's act, by fingerprint.
        s.confirm(&identity_fingerprint(&key), "cli").unwrap();
        assert!(s.trusted(&Uuid::from_u128(1)));
    }
}
