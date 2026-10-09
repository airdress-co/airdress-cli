//! Joining, and renewing, as an agent device (design §9.2, FR-20–FR-24).
//!
//! 1. The device host makes an Ed25519 identity key — the key the phone's
//!    delegation names and the MLS signing key, one and the same — and a
//!    stable device id.
//! 2. It files a device-join request with `device_class: agent`, its
//!    `harness` and its label ("Claude Code on <host>"), authorized by an
//!    enrollment assertion the hub mints for the signed-in account. The
//!    operator refuses it `not_enabled` while agent devices are off.
//! 3. A phone approves it with a root-signed, thirty-day delegation minted
//!    through airdress-mls; never the root seed, and no transfer slot.
//! 4. The device checks the delegation names it, says agent and its
//!    harness, and chains to the airdress's published root, then enrolls
//!    with it and seals its MLS state under a key only it holds.
//! 5. From seven days before expiry it asks again with `renews`, and the
//!    phone's re-approval renews the same enrollment in place.

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::RngCore as _;
use reqwest::StatusCode;
use serde_json::{json, Value};

use super::store::{AgentDevice, AgentRecord, AgentStore};
use crate::log_err::LogErr as _;
use crate::redact::Redacted;
use crate::shell_client::api::{seg, JoinApi};
use crate::shell_client::store::SecretsAt;

/// How long an agent's approval lasts: airdress-mls's own constant, the one
/// the phone mints with (the operator caps it at the same thirty days).
#[allow(clippy::cast_possible_wrap)] // thirty days of seconds fits an i64
pub const LIFETIME: chrono::Duration =
    chrono::Duration::seconds(crate::mls::delegation::AGENT_DELEGATION_LIFETIME_SECS as i64);

/// From how long before expiry the device asks to be renewed (FR-24):
/// airdress-mls's own constant.
#[allow(clippy::cast_possible_wrap)]
pub const RENEW_WINDOW: chrono::Duration =
    chrono::Duration::seconds(crate::mls::delegation::AGENT_DELEGATION_RENEW_WINDOW_SECS as i64);

/// Where an approval stands, as a person reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No approval yet (none asked, or one waiting).
    NotApproved,
    /// Approved, and not yet in the renewal window.
    Approved,
    /// Approved, inside the last seven days: a renewal is due.
    RenewalDue,
    /// Past its expiry: chat and device-signed writes stop until renewed.
    Expired,
}

/// Where `expires_at` leaves a device at `now`.
pub fn standing(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Standing {
    match expires_at {
        None => Standing::NotApproved,
        Some(exp) if exp <= now => Standing::Expired,
        Some(exp) if exp - now <= RENEW_WINDOW => Standing::RenewalDue,
        Some(_) => Standing::Approved,
    }
}

/// What the phone is shown: `template` with `{host}` replaced.
pub fn label_from(template: &str) -> String {
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
    let label = template.replace("{host}", &host);
    // The operator renders at most 80 characters.
    label.chars().take(80).collect::<String>().trim().to_owned()
}

/// A harness the operator accepts: `[a-z][a-z0-9-]{0,31}`.
pub fn valid_harness(h: &str) -> bool {
    let b = h.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Check the delegation a phone approved with, before anything uses it: it
/// names this device's key and id, says agent and this harness, carries an
/// expiry no more than thirty days out, and — when `root` is known — chains
/// to the airdress root through airdress-mls's own checks.
pub fn check_delegation(
    delegation: &Value,
    rec: &AgentRecord,
    root: Option<&[u8; 32]>,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let identity: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&rec.identity_public)
        .ok()
        .and_then(|k| k.try_into().ok())
        .context("this device's identity key is malformed")?;
    let names_key = delegation["device_session_public_key"]
        .as_str()
        .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
        .is_some_and(|k| k == identity);
    if !names_key {
        bail!("the approval's delegation names another key than this device's; not using it");
    }
    if delegation["device_id"].as_str() != Some(rec.device_id.as_str()) {
        bail!("the approval's delegation names another device; not using it");
    }
    if delegation["device_class"].as_str() != Some("agent") {
        bail!("the approval's delegation does not say this is an agent; not using it");
    }
    if delegation["harness"].as_str() != Some(rec.harness.as_str()) {
        bail!("the approval's delegation names another harness; not using it");
    }
    let exp = delegation["expires_at"]
        .as_str()
        .and_then(|e| DateTime::parse_from_rfc3339(e).ok())
        .map(|e| e.with_timezone(&Utc))
        .context("the approval's delegation carries no expiry")?;
    if exp <= now || exp - now > LIFETIME + chrono::Duration::minutes(5) {
        bail!("the approval's delegation does not run the next thirty days; not using it");
    }
    if let Some(root) = root {
        let obj = delegation
            .as_object()
            .context("the delegation is not an object")?
            .clone();
        let identity_doc = crate::mls::credential::AirdressIdentity::from_delegation(
            rec.airdress.clone(),
            *root,
            obj,
        );
        let lookup = |_: &str| Some(*root);
        crate::mls::credential::verify_identity_at(
            &identity_doc,
            &identity,
            &lookup,
            None,
            u64::try_from(now.timestamp()).unwrap_or(0),
        )
        .map_err(|e| anyhow::anyhow!("the approval's delegation does not verify: {e}"))?;
    }
    Ok(exp)
}

/// The sentence for a switched-off feature (design §12.3), naming no plan.
pub fn not_enabled_sentence(airdress: &str) -> String {
    format!(
        "Agent devices are not enabled on this airdress ({airdress}). Manage this airdress: \
         https://account.airdress.co/airdresses"
    )
}

async fn refused(resp: reqwest::Response, airdress: &str) -> anyhow::Error {
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if v["error"] == "not_enabled" {
        return anyhow::anyhow!(not_enabled_sentence(airdress));
    }
    let code = v["error"]["code"].as_str().unwrap_or_default();
    let message = v["error"]["message"].as_str().unwrap_or_default();
    match code {
        "invalid_renewal" => anyhow::anyhow!(
            "the operator does not recognize this device as the agent it renews; \
             `airdress agent device leave` and join again"
        ),
        "join_request_limit" => anyhow::anyhow!("too many devices are asking to join; try later"),
        "" => anyhow::anyhow!("the operator refused ({status})"),
        _ => anyhow::anyhow!("{message} [{code}]"),
    }
}

/// The operator calls an agent device makes.
#[derive(Debug, Clone)]
pub struct AgentApi {
    operator: String,
    http: reqwest::Client,
}

impl AgentApi {
    /// Against the operator at `base`.
    pub fn new(base: &str) -> Result<Self> {
        Ok(Self {
            operator: base.trim_end_matches('/').to_owned(),
            http: crate::http::client()?,
        })
    }

    /// `POST /v1/endpoints/device-join-requests` as an agent, optionally
    /// renewing `renews`. Returns the request id.
    pub async fn ask(&self, hub_token: &str, rec: &AgentRecord, renews: bool) -> Result<String> {
        let mut ephemeral = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral);
        let mut body = json!({
            "hub_token": hub_token,
            // The join route's ceremony key; an approval by delegation seals
            // nothing to it.
            "public_key": URL_SAFE_NO_PAD.encode(ephemeral),
            "device_public_key": rec.identity_public,
            "device_id": rec.device_id,
            "device_label": rec.label,
            "device_class": "agent",
            "harness": rec.harness,
        });
        if renews {
            body["renews"] = json!(rec.enrollment_id);
        }
        let resp = self
            .http
            .post(format!(
                "{}/v1/endpoints/device-join-requests",
                self.operator
            ))
            .json(&body)
            .send()
            .await
            .context("ask to join: the operator is unreachable")?;
        if resp.status() == StatusCode::NOT_FOUND {
            bail!("this operator does not take join requests (too old, or no hub trust)");
        }
        if !resp.status().is_success() {
            return Err(refused(resp, &rec.airdress).await);
        }
        let v: Value = resp.json().await?;
        v["request_id"]
            .as_str()
            .map(str::to_owned)
            .context("the join answer carried no request_id")
    }

    /// `GET /v1/endpoints/airdresses/{fqdn}/root-key` — the published root.
    pub async fn root_key(&self, fqdn: &str) -> Result<[u8; 32]> {
        let resp = self
            .http
            .get(format!(
                "{}/v1/endpoints/airdresses/{}/root-key",
                self.operator,
                seg(fqdn)
            ))
            .send()
            .await
            .context("read the airdress root: the operator is unreachable")?;
        if !resp.status().is_success() {
            bail!(
                "the operator publishes no root for {fqdn} ({})",
                resp.status()
            );
        }
        let v: Value = resp.json().await?;
        v["root_public_key"]
            .as_str()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
            .and_then(|k| k.try_into().ok())
            .context("the published root is malformed")
    }

    /// `POST /v1/endpoints/enrollments` with the approved delegation.
    /// Returns (enrollment id, session token).
    pub async fn enroll(
        &self,
        hub_token: &str,
        rec: &AgentRecord,
        delegation: &Value,
    ) -> Result<(String, Redacted<String>)> {
        let resp = self
            .http
            .post(format!("{}/v1/endpoints/enrollments", self.operator))
            .json(&json!({
                "airdress": rec.airdress,
                "role": "human_held",
                "key_custody": "client_held",
                "device_label": rec.label,
                "device_session_public_key": rec.identity_public,
                "delegation": delegation,
                "delegation_only": true,
                "device_kind": "agent",
                "transport_profile": "qr",
                "hub_token": hub_token,
            }))
            .send()
            .await
            .context("enroll: the operator is unreachable")?;
        if !resp.status().is_success() {
            return Err(refused(resp, &rec.airdress).await);
        }
        let v: Value = resp.json().await?;
        Ok((
            v["enrollment_id"]
                .as_str()
                .context("no enrollment_id")?
                .to_owned(),
            Redacted::from(v["token"].as_str().context("no token")?),
        ))
    }

    /// `DELETE /v1/endpoints/enrollments/{own}` — sign this device out.
    pub async fn leave(&self, rec: &AgentRecord, token: &Redacted<String>) -> Result<()> {
        let resp = self
            .http
            .delete(format!(
                "{}/v1/endpoints/enrollments/{}",
                self.operator,
                seg(&rec.enrollment_id)
            ))
            .bearer_auth(token.expose())
            .send()
            .await
            .context("sign out: the operator is unreachable")?;
        // Already gone (401: revoked or expired) is what leaving wants.
        if resp.status().is_success() || resp.status() == StatusCode::UNAUTHORIZED {
            return Ok(());
        }
        Err(refused(resp, &rec.airdress).await)
    }
}

/// Who asks the hub for enrollment assertions.
#[derive(Debug)]
pub struct Hub<'a> {
    /// The hub's base URL.
    pub base: &'a str,
    /// The signed-in account's bearer.
    pub bearer: &'a Redacted<String>,
}

/// A new, unapproved device for `airdress`: keys made, nothing asked yet.
pub fn new_device(airdress: &str, operator: &str, label: String, harness: &str) -> AgentDevice {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let identity = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut state_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut state_key);
    AgentDevice {
        record: AgentRecord {
            airdress: airdress.to_owned(),
            operator: operator.trim_end_matches('/').to_owned(),
            enrollment_id: String::new(),
            device_id: uuid::Uuid::new_v4().to_string(),
            label,
            harness: harness.to_owned(),
            identity_public: URL_SAFE_NO_PAD.encode(identity.verifying_key().to_bytes()),
            root_public: String::new(),
            delegation: None,
            expires_at: None,
            pending_request: None,
            secrets_at: SecretsAt::File,
        },
        identity,
        token: Redacted::default(),
        state_key: Redacted::new(state_key),
    }
}

/// File a request — the first join, or a renewal when the device is
/// enrolled — and remember it. Returns the request id.
pub async fn request(store: &AgentStore, dev: &mut AgentDevice, hub: &Hub<'_>) -> Result<String> {
    let api = AgentApi::new(&dev.record.operator)?;
    let token = JoinApi::new(&dev.record.operator)?
        .hub_token(hub.base, hub.bearer, &dev.record.airdress)
        .await
        .context("ask the hub for an enrollment token")?;
    let renews = !dev.record.enrollment_id.is_empty();
    let id = api.ask(token.expose(), &dev.record, renews).await?;
    dev.record.pending_request = Some(id.clone());
    store.save(dev)?;
    Ok(id)
}

/// What one look at a pending request found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Nothing pending.
    Idle,
    /// Still waiting for a phone.
    Waiting,
    /// Approved and applied: enrolled (first join) or renewed.
    Done,
    /// Declined, expired or withdrawn; the reason, for a person.
    Ended(String),
}

/// Look at the pending request once, and apply an approval: check the
/// delegation, enroll (first join) or take the renewed one, open the MLS
/// engine over the sealed state, and save.
pub async fn advance(store: &AgentStore, dev: &mut AgentDevice, hub: &Hub<'_>) -> Result<Progress> {
    let Some(id) = dev.record.pending_request.clone() else {
        return Ok(Progress::Idle);
    };
    let join = JoinApi::new(&dev.record.operator)?;
    let Some(status) = join.read(&id).await? else {
        dev.record.pending_request = None;
        store.save_record(&dev.record)?;
        return Ok(Progress::Ended("the request is gone".into()));
    };
    let delegation = match status.state.as_str() {
        "approved" => status
            .delegation
            .context("the request was approved by sealing the root, which an agent never takes")?,
        "pending" => return Ok(Progress::Waiting),
        other => {
            dev.record.pending_request = None;
            store.save_record(&dev.record)?;
            return Ok(Progress::Ended(match other {
                "declined" => "it was declined on the phone".into(),
                "expired" => "nobody approved it in time".into(),
                "unanswerable" => "this airdress has no phone that could approve it".into(),
                s => s.to_owned(),
            }));
        }
    };
    let api = AgentApi::new(&dev.record.operator)?;
    let root = api.root_key(&dev.record.airdress).await?;
    let exp = check_delegation(&delegation, &dev.record, Some(&root), Utc::now())?;
    if dev.record.enrollment_id.is_empty() {
        let token = join
            .hub_token(hub.base, hub.bearer, &dev.record.airdress)
            .await?;
        let (enrollment, bearer) = api.enroll(token.expose(), &dev.record, &delegation).await?;
        dev.record.enrollment_id = enrollment;
        dev.token = bearer;
    }
    dev.record.root_public = URL_SAFE_NO_PAD.encode(root);
    dev.record.delegation = Some(delegation);
    dev.record.expires_at = Some(exp);
    dev.record.pending_request = None;
    open_engine(store, dev)?;
    store.save(dev)?;
    Ok(Progress::Done)
}

/// Open the MLS engine over the sealed state, creating it on first use. The
/// engine checks the credential it is built from; the state it writes is
/// sealed under the device's state key and written beside, then renamed in.
pub fn open_engine(store: &AgentStore, dev: &AgentDevice) -> Result<crate::mls::MlsEngine> {
    let root: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&dev.record.root_public)
        .ok()
        .and_then(|k| k.try_into().ok())
        .context("this device has no airdress root yet")?;
    let delegation = dev
        .record
        .delegation
        .as_ref()
        .context("this device has no approval yet")?;
    let dir = store.mls_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        crate::fsx::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    crate::mls::MlsEngine::from_seed(
        &dev.record.airdress,
        &dev.identity.to_bytes(),
        &root,
        &serde_json::to_string(delegation)?,
        dir.to_str().context("the state dir is not UTF-8")?,
        dev.state_key.expose(),
    )
    .map_err(|e| anyhow::anyhow!("open the sealed MLS state: {e}"))
}

/// Ask and wait: `request`, then `advance` every two seconds (backing off
/// to ten) until done, ended or `wait` runs out (then withdraw).
pub async fn ask_and_wait(
    store: &AgentStore,
    dev: &mut AgentDevice,
    hub: &Hub<'_>,
    wait: Duration,
    say: &dyn Fn(&str),
) -> Result<()> {
    let id = match dev.record.pending_request.clone() {
        Some(id) => id,
        None => request(store, dev, hub).await?,
    };
    say(&format!(
        "Approve '{}' on your phone ({}).",
        dev.record.label, dev.record.airdress
    ));
    let deadline = tokio::time::Instant::now() + wait;
    let mut every = Duration::from_secs(2);
    loop {
        match advance(store, dev, hub).await? {
            Progress::Done => return Ok(()),
            Progress::Ended(why) => bail!("not approved: {why}"),
            Progress::Idle | Progress::Waiting => {}
        }
        if tokio::time::Instant::now() >= deadline {
            JoinApi::new(&dev.record.operator)?
                .withdraw(&id)
                .await
                .log_warn("withdrawing the unanswered join request");
            dev.record.pending_request = None;
            store.save_record(&dev.record)?;
            bail!("nobody approved it in time; the request was withdrawn");
        }
        tokio::time::sleep(every).await;
        every = (every * 2).min(Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    fn record(key: &[u8; 32]) -> AgentRecord {
        AgentRecord {
            airdress: "a.example".into(),
            operator: "https://a.example".into(),
            enrollment_id: String::new(),
            device_id: "d1".into(),
            label: "Agent on box".into(),
            harness: "test-harness".into(),
            identity_public: URL_SAFE_NO_PAD.encode(key),
            root_public: String::new(),
            delegation: None,
            expires_at: None,
            pending_request: None,
            secrets_at: SecretsAt::File,
        }
    }

    fn signed(root: &ed25519_dalek::SigningKey, mut obj: serde_json::Map<String, Value>) -> Value {
        obj.sort_keys();
        let canonical = serde_json::to_vec(&Value::Object(obj.clone())).unwrap();
        obj.insert(
            "signature".into(),
            json!(URL_SAFE_NO_PAD.encode(root.sign(&canonical).to_bytes())),
        );
        Value::Object(obj)
    }

    fn delegation(
        root: &ed25519_dalek::SigningKey,
        key: &[u8; 32],
        now: DateTime<Utc>,
        days: i64,
    ) -> Value {
        let fmt = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let v = json!({
            "airdress": "a.example", "device_class": "agent", "device_id": "d1",
            "device_kind": "agent", "device_label": "Agent on box",
            "device_session_public_key": URL_SAFE_NO_PAD.encode(key),
            "expires_at": fmt(now + chrono::Duration::days(days)),
            "harness": "test-harness", "issued_at": fmt(now), "role": "human_held",
        });
        signed(root, v.as_object().unwrap().clone())
    }

    #[test]
    fn standing_follows_the_expiry() {
        let now = Utc::now();
        assert_eq!(standing(None, now), Standing::NotApproved);
        assert_eq!(
            standing(Some(now + chrono::Duration::days(20)), now),
            Standing::Approved
        );
        assert_eq!(
            standing(Some(now + chrono::Duration::days(7)), now),
            Standing::RenewalDue
        );
        assert_eq!(
            standing(Some(now + chrono::Duration::hours(1)), now),
            Standing::RenewalDue
        );
        assert_eq!(standing(Some(now), now), Standing::Expired);
    }

    #[test]
    fn a_delegation_must_be_this_agent_for_thirty_days_under_the_root() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let me = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let key = me.verifying_key().to_bytes();
        let rec = record(&key);
        let now = Utc::now();
        let root_pub = root.verifying_key().to_bytes();
        let ok = delegation(&root, &key, now, 30);
        let exp = check_delegation(&ok, &rec, Some(&root_pub), now).unwrap();
        assert!(exp > now + chrono::Duration::days(29));

        // Under another root.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes();
        assert!(check_delegation(&ok, &rec, Some(&other), now).is_err());
        // Too long, already over, another harness, not an agent, another key.
        assert!(check_delegation(&delegation(&root, &key, now, 31), &rec, None, now).is_err());
        assert!(check_delegation(&ok, &rec, None, now + chrono::Duration::days(31)).is_err());
        let mut v = ok.clone();
        v["harness"] = json!("other");
        assert!(check_delegation(&v, &rec, None, now).is_err());
        let mut v = ok.clone();
        v["device_class"] = json!("human");
        assert!(check_delegation(&v, &rec, None, now).is_err());
        assert!(check_delegation(&ok, &record(&[1; 32]), None, now).is_err());
    }

    #[test]
    fn the_label_template_names_the_machine_and_fits() {
        assert!(label_from("Agent on {host}").starts_with("Agent on "));
        assert!(label_from(&"x".repeat(200)).chars().count() <= 80);
        assert!(valid_harness("claude-code"));
        assert!(!valid_harness("Claude Code"));
    }
}
