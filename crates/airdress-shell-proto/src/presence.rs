//! D-14's unlock as a signature the host verifies (design §6.2–6.4).
//!
//! Three pieces:
//!
//! - **The device-key statement** ([`DeviceKeys`]): a device signs, with its
//!   Ed25519 identity key, which X25519 shell key and which presence key are
//!   its own, *including* the statement that it has no presence key
//!   (`presenceAlg: none`). The operator stores and forwards it; it cannot
//!   alter it.
//! - **The presence rule** ([`presence_rule`]): `none` is admitted only when
//!   the device kind the host verified itself (from the root-signed
//!   delegation, or a sub-user introduction) is `cli`. A compromised operator
//!   therefore cannot turn a phone into a device that needs no unlock.
//! - **The unlock signature** ([`presence_message`], [`verify_presence`]):
//!   ECDSA P-256 with SHA-256 over
//!   `"airdress.shell.presence.v1" ‖ 0x00 ‖ handshake_hash ‖ action`, sent as
//!   the first record after an open or attach handshake.

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{ProtoError, Result};
use crate::prologue::Action;

/// Domain label of the unlock signature.
pub const PRESENCE_LABEL: &[u8] = b"airdress.shell.presence.v1";
/// Domain label of the device-key statement.
pub const DEVICE_KEYS_LABEL: &[u8] = b"airdress.shell.device-keys.v1";
/// The one device kind that may go without a presence key (D-30).
pub const DEVICE_KIND_CLI: &str = "cli";

/// How a device proves a human is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceAlg {
    /// ECDSA P-256 with SHA-256, a key that needs user authentication.
    P256,
    /// No presence key. Admitted only for a CLI-kind device.
    None,
}

impl PresenceAlg {
    /// The word on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            PresenceAlg::P256 => "p256",
            PresenceAlg::None => "none",
        }
    }
}

/// The bytes a presence key signs.
///
/// Only `open` and `attach` ask for an unlock; a resume never does (D-14),
/// so a resume action is refused here rather than signed.
pub fn presence_message(handshake_hash: &[u8; 32], action: Action) -> Result<Vec<u8>> {
    if action == Action::Resume {
        return Err(ProtoError::InvalidInput("a resume asks for no unlock"));
    }
    let a = action.as_str().as_bytes();
    let mut m = Vec::with_capacity(PRESENCE_LABEL.len() + 1 + 32 + a.len());
    m.extend_from_slice(PRESENCE_LABEL);
    m.push(0x00);
    m.extend_from_slice(handshake_hash);
    m.extend_from_slice(a);
    Ok(m)
}

/// Verify an unlock signature.
///
/// `public` is the presence key as SEC1 (compressed or uncompressed), `sig`
/// an ASN.1 DER ECDSA signature, which is what Android Keystore and the
/// Secure Enclave produce. A high-S signature is accepted: Keystore does not
/// normalise S, and malleability does not matter for a signature over a
/// handshake hash that is never reused.
pub fn verify_presence(
    public: &[u8],
    handshake_hash: &[u8; 32],
    action: Action,
    sig: &[u8],
) -> Result<()> {
    let vk = P256VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| ProtoError::PresenceRequired("presence key malformed"))?;
    let sig = P256Signature::from_der(sig)
        .map_err(|_| ProtoError::PresenceRequired("signature malformed"))?;
    let msg = presence_message(handshake_hash, action)?;
    vk.verify(&msg, &sig)
        .map_err(|_| ProtoError::PresenceRequired("signature does not verify"))
}

/// A device's own statement of its shell keys (design §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeys {
    /// The device id.
    pub device: String,
    /// The principal the device belongs to.
    pub principal: String,
    /// The device's Ed25519 identity key, which signs this statement.
    #[serde(with = "crate::b64::arr32")]
    pub identity_public: [u8; 32],
    /// The device's X25519 shell key.
    #[serde(with = "crate::b64::arr32")]
    pub dh_public: [u8; 32],
    /// `p256` or `none`.
    pub presence_alg: PresenceAlg,
    /// The presence key (SEC1), present exactly when the algorithm is p256.
    #[serde(
        default,
        with = "crate::b64::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub presence_public: Option<Vec<u8>>,
}

/// Domain label for a device id that is not a UUID (the conformance kit's
/// named devices only; an operator issues UUIDs).
pub const DEVICE_NAME_LABEL: &[u8] = b"airdress.shell.device-name";

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A device id's 16 bytes: the UUID itself (`8-4-4-4-12` hex, the form the
/// operator issues), or for any other string the first 16 bytes of
/// `SHA-256("airdress.shell.device-name" ‖ 0x00 ‖ id)`, a mapping no UUID
/// can be found to collide with.
pub fn device_id_bytes(device: &str) -> [u8; 16] {
    let b = device.as_bytes();
    if b.len() == 36 && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-') {
        let hex: Vec<u8> = b.iter().copied().filter(|c| *c != b'-').collect();
        let mut out = [0u8; 16];
        let ok = hex.len() == 32
            && hex
                .chunks(2)
                .enumerate()
                .all(|(i, p)| match (hex_val(p[0]), hex_val(p[1])) {
                    (Some(h), Some(l)) => {
                        out[i] = (h << 4) | l;
                        true
                    }
                    _ => false,
                });
        if ok {
            return out;
        }
    }
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(DEVICE_NAME_LABEL);
    h.update([0x00]);
    h.update(b);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

impl DeviceKeys {
    /// The bytes the identity key signs, in the operator's layout (the one
    /// layout the device, the operator and the host share):
    /// `"airdress.shell.device-keys.v1" ‖ 0x00 ‖ device id (16 bytes) ‖
    /// dhPublic (32) ‖ presenceAlg ("p256" | "none") ‖ 0x00 ‖ presencePublic
    /// (the SEC1 point, or nothing for none)`.
    ///
    /// `principal` and `identityPublic` are not in it: the identity key is
    /// what verifies the statement, and the principal is bound by the
    /// root delegation or the introduction (design §6.3 steps 2, 4, 5).
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let alg = self.presence_alg.as_str().as_bytes();
        let pk = self.presence_public.as_deref().unwrap_or(&[]);
        let mut m =
            Vec::with_capacity(DEVICE_KEYS_LABEL.len() + 1 + 16 + 32 + alg.len() + 1 + pk.len());
        m.extend_from_slice(DEVICE_KEYS_LABEL);
        m.push(0x00);
        m.extend_from_slice(&device_id_bytes(&self.device));
        m.extend_from_slice(&self.dh_public);
        m.extend_from_slice(alg);
        m.push(0x00);
        m.extend_from_slice(pk);
        Ok(m)
    }

    /// Sign the statement with the identity key. Refuses a key that is not
    /// the one the statement names.
    pub fn sign(&self, identity: &SigningKey) -> Result<[u8; 64]> {
        if identity.verifying_key().to_bytes() != self.identity_public {
            return Err(ProtoError::InvalidInput(
                "signing key is not identityPublic",
            ));
        }
        self.check_shape()?;
        Ok(identity.sign(&self.signed_bytes()?).to_bytes())
    }

    /// Verify the statement's signature under its own identity key, and its
    /// shape: a p256 statement carries a valid key, a `none` one carries none.
    ///
    /// Whether `identityPublic` is really this device's key is a separate
    /// check (design §6.3 steps 4–5: the root delegation or an introduction).
    pub fn verify(&self, sig: &[u8]) -> Result<()> {
        self.check_shape()?;
        let vk = VerifyingKey::from_bytes(&self.identity_public)
            .map_err(|_| ProtoError::DeviceKeysInvalid("identity key malformed"))?;
        let sig = EdSignature::from_slice(sig)
            .map_err(|_| ProtoError::DeviceKeysInvalid("signature malformed"))?;
        vk.verify_strict(&self.signed_bytes()?, &sig)
            .map_err(|_| ProtoError::DeviceKeysInvalid("signature does not verify"))
    }

    fn check_shape(&self) -> Result<()> {
        match (self.presence_alg, &self.presence_public) {
            (PresenceAlg::P256, Some(pk)) => P256VerifyingKey::from_sec1_bytes(pk)
                .map(|_| ())
                .map_err(|_| ProtoError::DeviceKeysInvalid("presence key malformed")),
            (PresenceAlg::P256, None) => Err(ProtoError::DeviceKeysInvalid("p256 without a key")),
            (PresenceAlg::None, Some(_)) => {
                Err(ProtoError::DeviceKeysInvalid("none with a presence key"))
            }
            (PresenceAlg::None, None) => Ok(()),
        }
    }
}

/// What the host demands after the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceRequirement {
    /// An unlock signature under this SEC1 P-256 key.
    Unlock(Vec<u8>),
    /// No signature: a CLI-kind device with no presence key (D-30). Its
    /// first record must still be a `presence` message saying `none`, which
    /// proves the device holds the channel keys before anything is spawned.
    NotRequired,
}

/// The presence rule (design §6.3 step 6).
///
/// `keys` must already have been verified with [`DeviceKeys::verify`].
/// `verified_kind` is the device kind the host established itself, from the
/// root-signed delegation or from an introduction; never one the operator
/// merely asserts.
pub fn presence_rule(keys: &DeviceKeys, verified_kind: &str) -> Result<PresenceRequirement> {
    match (keys.presence_alg, &keys.presence_public) {
        (PresenceAlg::P256, Some(pk)) => Ok(PresenceRequirement::Unlock(pk.clone())),
        (PresenceAlg::None, None) if verified_kind == DEVICE_KIND_CLI => {
            Ok(PresenceRequirement::NotRequired)
        }
        (PresenceAlg::None, None) => Err(ProtoError::PresenceRequired(
            "no presence key on a device that is not a CLI",
        )),
        _ => Err(ProtoError::DeviceKeysInvalid(
            "inconsistent presence fields",
        )),
    }
}

/// Check the first record's `presence` message against the requirement.
pub fn admit(
    req: &PresenceRequirement,
    handshake_hash: &[u8; 32],
    expected: Action,
    action: Action,
    alg: PresenceAlg,
    sig: Option<&[u8]>,
) -> Result<()> {
    if action != expected {
        return Err(ProtoError::PresenceRequired("wrong action"));
    }
    match req {
        PresenceRequirement::Unlock(pk) => {
            if alg != PresenceAlg::P256 {
                return Err(ProtoError::PresenceRequired("unlock missing"));
            }
            let sig = sig.ok_or(ProtoError::PresenceRequired("unlock missing"))?;
            verify_presence(pk, handshake_hash, action, sig)
        }
        PresenceRequirement::NotRequired => {
            if alg == PresenceAlg::None && sig.is_none() {
                Ok(())
            } else {
                Err(ProtoError::PresenceRequired("unexpected unlock from a CLI"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey as P256SigningKey;

    fn phone_keys(id: &SigningKey, pk: &P256SigningKey) -> DeviceKeys {
        DeviceKeys {
            device: "phone".into(),
            principal: "owner".into(),
            identity_public: id.verifying_key().to_bytes(),
            dh_public: [9; 32],
            presence_alg: PresenceAlg::P256,
            presence_public: Some(
                pk.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
            ),
        }
    }

    #[test]
    fn unlock_round_trip_and_binding() {
        let pk = P256SigningKey::from_slice(&[3u8; 32]).unwrap();
        let hh = [5u8; 32];
        let sig: P256Signature = pk.sign(&presence_message(&hh, Action::Open).unwrap());
        let der = sig.to_der();
        let public = pk.verifying_key().to_encoded_point(false);
        verify_presence(public.as_bytes(), &hh, Action::Open, der.as_bytes()).unwrap();
        assert!(verify_presence(public.as_bytes(), &hh, Action::Attach, der.as_bytes()).is_err());
        assert!(
            verify_presence(public.as_bytes(), &[6u8; 32], Action::Open, der.as_bytes()).is_err()
        );
    }

    #[test]
    fn statement_signs_and_refuses_tampering() {
        let id = SigningKey::from_bytes(&[1u8; 32]);
        let pk = P256SigningKey::from_slice(&[3u8; 32]).unwrap();
        let keys = phone_keys(&id, &pk);
        let sig = keys.sign(&id).unwrap();
        keys.verify(&sig).unwrap();
        // The operator rewrites the phone to `none`: the signature no
        // longer verifies, whatever else it does.
        let mut downgraded = keys.clone();
        downgraded.presence_alg = PresenceAlg::None;
        downgraded.presence_public = None;
        assert!(downgraded.verify(&sig).is_err());
    }

    #[test]
    fn the_statement_is_the_operators_layout() {
        let id = SigningKey::from_bytes(&[4u8; 32]);
        let pk = P256SigningKey::from_slice(&[3u8; 32]).unwrap();
        let point = pk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let keys = DeviceKeys {
            device: "00000000-0000-0000-0000-000000000001".into(),
            principal: "owner".into(),
            identity_public: id.verifying_key().to_bytes(),
            dh_public: [9; 32],
            presence_alg: PresenceAlg::P256,
            presence_public: Some(point.clone()),
        };
        let mut want = b"airdress.shell.device-keys.v1\0".to_vec();
        want.extend_from_slice(&[0u8; 15]);
        want.push(1);
        want.extend_from_slice(&[9u8; 32]);
        want.extend_from_slice(b"p256\0");
        want.extend_from_slice(&point);
        assert_eq!(keys.signed_bytes().unwrap(), want);
        assert_eq!(
            want.len(),
            DEVICE_KEYS_LABEL.len() + 1 + 16 + 32 + 4 + 1 + 65
        );
        let none = DeviceKeys {
            presence_alg: PresenceAlg::None,
            presence_public: None,
            ..keys
        };
        let b = none.signed_bytes().unwrap();
        assert!(b.ends_with(b"none\0"));
        // Upper-case hex is the same UUID; a name is not a UUID.
        assert_eq!(
            device_id_bytes("ABCDEF01-0000-0000-0000-000000000001"),
            device_id_bytes("abcdef01-0000-0000-0000-000000000001")
        );
        assert_ne!(device_id_bytes("phone"), [0u8; 16]);
        assert_ne!(device_id_bytes("phone"), device_id_bytes("cli"));
    }

    #[test]
    fn none_only_for_cli() {
        let id = SigningKey::from_bytes(&[1u8; 32]);
        let keys = DeviceKeys {
            device: "cli".into(),
            principal: "owner".into(),
            identity_public: id.verifying_key().to_bytes(),
            dh_public: [9; 32],
            presence_alg: PresenceAlg::None,
            presence_public: None,
        };
        let sig = keys.sign(&id).unwrap();
        keys.verify(&sig).unwrap();
        assert_eq!(
            presence_rule(&keys, DEVICE_KIND_CLI).unwrap(),
            PresenceRequirement::NotRequired
        );
        assert_eq!(
            presence_rule(&keys, "phone").unwrap_err().code(),
            "shell_presence_required"
        );
    }

    /// A signed statement stays closed: a field the verifier would skip is
    /// a field it would vouch for unread (the crate's "Wire compatibility").
    #[test]
    fn device_keys_refuse_an_unknown_field() {
        let id = SigningKey::from_bytes(&[4u8; 32]);
        let pk = P256SigningKey::from_slice(&[3u8; 32]).unwrap();
        let mut v = serde_json::to_value(phone_keys(&id, &pk)).unwrap();
        assert!(serde_json::from_value::<DeviceKeys>(v.clone()).is_ok());
        v["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeviceKeys>(v).is_err());
    }

    #[test]
    fn admit_checks_alg_and_action() {
        let hh = [0u8; 32];
        let req = PresenceRequirement::NotRequired;
        admit(
            &req,
            &hh,
            Action::Open,
            Action::Open,
            PresenceAlg::None,
            None,
        )
        .unwrap();
        assert!(admit(
            &req,
            &hh,
            Action::Open,
            Action::Attach,
            PresenceAlg::None,
            None
        )
        .is_err());
        assert!(admit(
            &req,
            &hh,
            Action::Open,
            Action::Open,
            PresenceAlg::P256,
            Some(b"x")
        )
        .is_err());
        let req = PresenceRequirement::Unlock(vec![4; 65]);
        assert!(admit(
            &req,
            &hh,
            Action::Open,
            Action::Open,
            PresenceAlg::None,
            None
        )
        .is_err());
    }

    #[test]
    fn no_unlock_message_for_a_resume() {
        assert!(presence_message(&[0; 32], Action::Resume).is_err());
    }
}
