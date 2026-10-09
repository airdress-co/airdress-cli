//! The CLI as a delegation-only human device (design §5.2, D-30).
//!
//! Law 3 needs an enrolled device, and the CLI was not one. It becomes one
//! by asking, like a new phone does:
//!
//! 1. it makes an identity key (Ed25519) and a shell key (X25519);
//! 2. it files a device-join request, with `device_class: human`,
//!    `delegation_only: true`, `device_kind: cli` and the label
//!    "airdress CLI on <host>", authorized by a one-time enrollment token
//!    the hub mints for the signed-in account;
//! 3. a phone approves it with a **root-signed delegation** naming the
//!    identity key and the kind `cli`, instead of sealing the root seed: a
//!    terminal client never holds the root;
//! 4. it enrolls with that delegation and receives its session bearer;
//! 5. it registers its shell key with `presenceAlg: none`, signed by its
//!    identity key. The operator accepts `none` only from a delegation-only
//!    device of kind `cli`, and a host accepts it only when the delegation
//!    says `cli` (design §6.3 step 6).
//!
//! Until the approval it holds no credential at all, so every shell route
//! refuses it.

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore as _;
use serde_json::Value;

use airdress_shell_proto::keys::{fingerprint, ShellKeypair};

use super::api::{JoinApi, ShellApi};
use super::store::{CliDevice, DeviceRecord, SecretsAt, Store};
use crate::log_err::LogErr as _;
use crate::redact::Redacted;

/// The device kind every CLI (and the editor through it) declares.
pub const DEVICE_KIND: &str = "cli";

/// The device-keys statement's label (the operator's and the host's
/// contract; see `device_keys_statement`).
pub const DEVICE_KEYS_LABEL: &[u8] = b"airdress.shell.device-keys.v1";

/// The bytes the identity key signs to register the shell key:
/// `"airdress.shell.device-keys.v1" ‖ 0x00 ‖ device id (16 bytes) ‖
/// dhPublic (32) ‖ presenceAlg ‖ 0x00 ‖ presencePublic` — for this CLI the
/// algorithm is `none` and the presence key is absent. The operator verifies
/// exactly these bytes before it stores the key, and passes the signature to
/// the host, which verifies it again; the signature covers `none`, so an
/// operator cannot turn a phone into a device without a presence key.
pub fn device_keys_statement(device: &uuid::Uuid, dh_public: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEVICE_KEYS_LABEL.len() + 1 + 16 + 32 + 5);
    out.extend_from_slice(DEVICE_KEYS_LABEL);
    out.push(0);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(dh_public);
    out.extend_from_slice(b"none");
    out.push(0);
    out
}

/// What a phone is shown when this CLI asks to join.
pub fn default_label() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_owned())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this machine".to_owned());
    format!("airdress CLI on {host}")
}

/// Check the delegation a phone approved with: it names this device's
/// identity key and device id, and says the device is a CLI. The root's
/// signature is the operator's and the host's to verify against the pinned
/// root; this check stops a delegation that would enroll something other
/// than what this CLI asked to be.
pub fn check_delegation(
    delegation: &Value,
    identity_public: &[u8; 32],
    device_id: &str,
) -> Result<()> {
    let names_key = delegation["device_session_public_key"]
        .as_str()
        .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
        .is_some_and(|k| k == identity_public);
    if !names_key {
        bail!("the approval's delegation names another key than this CLI's; not enrolling");
    }
    if delegation["device_id"].as_str() != Some(device_id) {
        bail!("the approval's delegation names another device; not enrolling");
    }
    if delegation["device_kind"].as_str() != Some(DEVICE_KIND) {
        bail!(
            "the approval's delegation does not say this is a CLI (device_kind {:?}); a host \
             would refuse it without a presence key, so it is not used",
            delegation["device_kind"]
        );
    }
    if delegation["signature"].as_str().is_none_or(str::is_empty) {
        bail!("the approval's delegation is not signed");
    }
    Ok(())
}

/// How a join is driven: who asks the hub, and how long to wait.
#[derive(Debug)]
pub struct JoinPlan<'a> {
    /// The operator's base URL.
    pub operator: &'a str,
    /// The airdress FQDN.
    pub airdress: &'a str,
    /// The hub's base URL.
    pub hub: &'a str,
    /// The signed-in account's bearer (for the enrollment tokens only).
    pub account_bearer: &'a Redacted<String>,
    /// What the phone is shown.
    pub label: String,
    /// Give up after this long.
    pub wait: Duration,
}

/// Ask to join, wait for a phone's approval, enroll, and register the shell
/// key. `say` reports progress to a human.
pub async fn join(store: &Store, plan: JoinPlan<'_>, say: &dyn Fn(&str)) -> Result<CliDevice> {
    let mut rng = rand::rngs::OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let identity = SigningKey::from_bytes(&seed);
    let identity_public = identity.verifying_key().to_bytes();
    let shell = ShellKeypair::generate(&mut rng);
    // The join route wants an X25519 key for the seal-the-root ceremony;
    // a delegation approval seals nothing, so it is a throwaway.
    let ephemeral = ShellKeypair::generate(&mut rng);
    let device_id = uuid::Uuid::new_v4().to_string();

    let join = JoinApi::new(plan.operator)?;
    let token = join
        .hub_token(plan.hub, plan.account_bearer, plan.airdress)
        .await
        .context("ask the hub for an enrollment token")?;
    let request = join
        .create(
            token.expose(),
            ephemeral.public(),
            &identity_public,
            &device_id,
            &plan.label,
        )
        .await?;
    say(&format!(
        "Asked to join {} as \"{}\".\nApprove it on one of your phones (Devices → Asking to join).\n\
         This CLI's identity key: {}",
        plan.airdress,
        plan.label,
        fingerprint(&identity_public)
    ));

    let deadline = tokio::time::Instant::now() + plan.wait;
    let mut every = Duration::from_secs(2);
    let delegation = loop {
        if tokio::time::Instant::now() >= deadline {
            join.withdraw(&request)
                .await
                .log_warn("withdrawing the unanswered join request");
            bail!("nobody approved the join in time; it was withdrawn");
        }
        tokio::time::sleep(every).await;
        every = (every * 2).min(Duration::from_secs(10));
        let Some(status) = join.read(&request).await.ok().flatten() else {
            continue;
        };
        match status.state.as_str() {
            "approved" => match status.delegation {
                Some(d) => break d,
                None => bail!(
                    "the join was approved by sealing the root, which a CLI does not take; \
                     approve it as a CLI device instead"
                ),
            },
            "declined" => bail!("the join was declined"),
            "expired" => bail!("the join expired before anyone approved it"),
            "withdrawn" => bail!("the join was withdrawn"),
            "unanswerable" => {
                bail!("this airdress has no device that could approve a join; enroll a phone first")
            }
            _ => {}
        }
    };
    check_delegation(&delegation, &identity_public, &device_id)?;

    // A fresh assertion: the first one's jti is spent.
    let token = join
        .hub_token(plan.hub, plan.account_bearer, plan.airdress)
        .await?;
    let (enrollment_id, bearer) = join
        .enroll(
            token.expose(),
            plan.airdress,
            &plan.label,
            &identity_public,
            &delegation,
        )
        .await?;

    let mut dev = CliDevice {
        record: DeviceRecord {
            airdress: plan.airdress.to_owned(),
            enrollment_id,
            device_id,
            label: plan.label.clone(),
            identity_public: URL_SAFE_NO_PAD.encode(identity_public),
            shell_public: URL_SAFE_NO_PAD.encode(shell.public()),
            keys_registered: false,
            secrets_at: SecretsAt::File,
        },
        token: bearer,
        identity,
        shell,
    };
    let at = store.save(&mut dev)?;
    if at == SecretsAt::File {
        say(&format!(
            "No Secret Service here: this device's keys are in {} (mode 0600).",
            store.dir().display()
        ));
    }
    register_keys(store, &mut dev, plan.operator).await?;
    Ok(dev)
}

/// Register the shell key with `presenceAlg: none`, once.
pub async fn register_keys(store: &Store, dev: &mut CliDevice, operator: &str) -> Result<()> {
    if dev.record.keys_registered {
        return Ok(());
    }
    let device: uuid::Uuid = dev
        .record
        .enrollment_id
        .parse()
        .context("the enrollment id is not a UUID")?;
    let sig = dev
        .identity
        .sign(&device_keys_statement(&device, dev.shell.public()))
        .to_bytes();
    ShellApi::new(operator, &dev.token)?
        .register_keys(dev.shell.public(), &sig)
        .await?;
    dev.record.keys_registered = true;
    store.save_record(&dev.record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;
    use serde_json::json;

    #[test]
    fn the_statement_is_the_operators_layout_and_covers_none() {
        let sk = SigningKey::from_bytes(&[4; 32]);
        let device = uuid::Uuid::from_u128(1);
        let msg = device_keys_statement(&device, &[9; 32]);
        assert_eq!(msg.len(), DEVICE_KEYS_LABEL.len() + 1 + 16 + 32 + 4 + 1);
        assert_eq!(&msg[..DEVICE_KEYS_LABEL.len()], DEVICE_KEYS_LABEL);
        assert!(msg.ends_with(b"none\0"));
        let sig = sk.sign(&msg);
        assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
        // Another shell key is another statement.
        assert!(sk
            .verifying_key()
            .verify(&device_keys_statement(&device, &[8; 32]), &sig)
            .is_err());
    }

    #[test]
    fn a_delegation_must_name_this_key_this_device_and_the_cli_kind() {
        let key = [7u8; 32];
        let ok = json!({
            "device_session_public_key": URL_SAFE_NO_PAD.encode(key),
            "device_id": "d1", "device_kind": "cli", "signature": "sig",
        });
        check_delegation(&ok, &key, "d1").unwrap();
        let mut phone = ok.clone();
        phone["device_kind"] = json!("phone");
        assert!(check_delegation(&phone, &key, "d1").is_err());
        let mut none = ok.clone();
        none.as_object_mut().unwrap().remove("device_kind");
        assert!(check_delegation(&none, &key, "d1").is_err());
        assert!(check_delegation(&ok, &[6; 32], "d1").is_err());
        assert!(check_delegation(&ok, &key, "d2").is_err());
        let mut unsigned = ok;
        unsigned["signature"] = json!("");
        assert!(check_delegation(&unsigned, &key, "d1").is_err());
    }

    #[test]
    fn the_label_names_the_machine() {
        assert!(default_label().starts_with("airdress CLI on "));
    }
}
