//! Where an agent device keeps itself (design §6.2, §9.4; FR-25).
//!
//! One directory per airdress under the state dir the caller names (the
//! plugin passes its own data directory; the CLI defaults to
//! `~/.local/state/airdress/agent`):
//!
//! ```text
//! ${state_dir}/device/<airdress>/
//!   device.json    0600  what is not secret: ids, label, harness, keys' public
//!                        halves, the delegation, its expiry, a pending renewal
//!   secrets.json   0600  ONLY when no OS keychain is usable (with a warning)
//!   mls/                 MLS state, sealed by airdress-mls under the state key
//!   host.lock            the device host's lock (flock)
//!   host.sock      0600  the device host's socket
//! ```
//!
//! The secrets — the identity seed (the key the delegation names, which is
//! also the MLS signing key), the session bearer and the key that seals the
//! MLS state — are one value in the OS keychain (macOS Keychain, Linux
//! Secret Service; service `airdress`, account `agent-device:<airdress>`),
//! else `secrets.json`. Every file is written beside and renamed in, so a
//! crash leaves the old file or the new one, never half of either.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::redact::Redacted;
use crate::shell_client::store::{
    delete_keyring_secret, remove_secret_file, write_private, SecretsAt,
};

const KEYRING_SERVICE: &str = "airdress";

/// The non-secret half of the agent device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRecord {
    /// The airdress (its FQDN).
    pub airdress: String,
    /// The operator's base URL this device enrolled with.
    pub operator: String,
    /// The enrollment id; empty until enrolled.
    #[serde(default)]
    pub enrollment_id: String,
    /// The stable device id the delegation binds.
    pub device_id: String,
    /// What the phone is shown ("Claude Code on <host>").
    pub label: String,
    /// Which program runs this agent (data, e.g. `claude-code`).
    pub harness: String,
    /// The identity key (Ed25519), base64url.
    pub identity_public: String,
    /// The airdress root this device's delegation chains to, base64url.
    #[serde(default)]
    pub root_public: String,
    /// The root-signed delegation, once approved.
    #[serde(default)]
    pub delegation: Option<Value>,
    /// The delegation's expiry (RFC 3339), once approved.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// A join request waiting for a phone: the first join, or a renewal.
    #[serde(default)]
    pub pending_request: Option<String>,
    /// Where the secrets are.
    pub secrets_at: SecretsAt,
}

/// The secret half, as stored: three bare strings, unchanged on disk.
#[derive(Debug, Serialize, Deserialize)]
struct SecretBlob {
    #[serde(with = "crate::redact::persist")]
    identity_seed: Redacted<String>,
    #[serde(default, with = "crate::redact::persist")]
    token: Redacted<String>,
    #[serde(with = "crate::redact::persist")]
    state_key: Redacted<String>,
}

/// The agent device, loaded.
pub struct AgentDevice {
    /// The record.
    pub record: AgentRecord,
    /// The identity key (the delegation's subject, and the MLS signing key).
    pub identity: SigningKey,
    /// The session bearer; empty until enrolled.
    pub token: Redacted<String>,
    /// The key that seals the MLS state.
    pub state_key: Redacted<[u8; 32]>,
}

impl core::fmt::Debug for AgentDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentDevice")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// One airdress's directory, and whether to try the keychain.
#[derive(Debug, Clone)]
pub struct AgentStore {
    dir: PathBuf,
    airdress: String,
    use_keyring: bool,
    /// The runtime directory a too-long socket path falls back to.
    runtime_dir: Option<PathBuf>,
}

/// The default state dir: `~/.local/state/airdress/agent`.
pub fn default_state_dir(paths: &crate::paths::Paths) -> PathBuf {
    crate::agent_bus::socket::default_state_dir(paths)
}

fn valid_airdress(a: &str) -> Result<()> {
    if a.is_empty() || a.starts_with('.') || a.chars().any(|c| c == '/' || c == '\\' || c == '\0') {
        bail!("airdress {a:?} cannot name a directory");
    }
    Ok(())
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64_32(s: &str, what: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("the stored {what} is malformed"))
}

impl AgentStore {
    /// The store for `airdress` under `state_dir`, using the keychain.
    pub fn new(state_dir: &Path, airdress: &str) -> Result<Self> {
        valid_airdress(airdress)?;
        Ok(Self {
            dir: crate::agent_bus::socket::device_dir(state_dir, airdress),
            airdress: airdress.to_owned(),
            use_keyring: true,
            runtime_dir: None,
        })
    }

    /// The runtime directory its socket falls back to ([`crate::paths::Paths::runtime_dir`]).
    #[must_use]
    pub fn with_runtime_dir(mut self, dir: Option<&Path>) -> Self {
        self.runtime_dir = dir.map(Path::to_path_buf);
        self
    }

    /// The runtime directory its socket falls back to.
    pub fn runtime_dir(&self) -> Option<&Path> {
        self.runtime_dir.as_deref()
    }

    /// A store under `state_dir`, file-only (tests; hosts without a keychain).
    pub fn file_only(state_dir: &Path, airdress: &str) -> Result<Self> {
        Ok(Self {
            use_keyring: false,
            ..Self::new(state_dir, airdress)?
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The airdress.
    pub fn airdress(&self) -> &str {
        &self.airdress
    }

    /// The device host's lock file.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("host.lock")
    }

    /// The MLS state directory (sealed by airdress-mls).
    pub fn mls_dir(&self) -> PathBuf {
        self.dir.join("mls")
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join("device.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.dir.join("secrets.json")
    }

    fn entry(&self) -> keyring::Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &format!("agent-device:{}", self.airdress))
    }

    /// Save the device, secrets and all. Returns where the secrets went.
    pub fn save(&self, dev: &mut AgentDevice) -> Result<SecretsAt> {
        let blob = Redacted::new(serde_json::to_vec(&SecretBlob {
            identity_seed: Redacted::new(b64(&dev.identity.to_bytes())),
            token: dev.token.clone(),
            state_key: Redacted::new(b64(dev.state_key.expose())),
        })?);
        let blob = blob.expose();
        let mut at = SecretsAt::File;
        if self.use_keyring {
            if let Ok(e) = self.entry() {
                if e.set_secret(blob).is_ok() {
                    at = SecretsAt::Keyring;
                }
            }
        }
        if at == SecretsAt::File {
            write_private(&self.secrets_path(), blob)?;
        } else {
            // A file left by an earlier keychain-less run must not outlive
            // the move into the keychain.
            remove_secret_file(&self.secrets_path())?;
        }
        dev.record.secrets_at = at;
        self.save_record(&dev.record)?;
        Ok(at)
    }

    /// Rewrite only the non-secret record.
    pub fn save_record(&self, rec: &AgentRecord) -> Result<()> {
        write_private(&self.record_path(), &serde_json::to_vec_pretty(rec)?)
    }

    /// Load the device, or `None` when there is none for this airdress.
    pub fn load(&self) -> Result<Option<AgentDevice>> {
        let rec: AgentRecord = match std::fs::read(self.record_path()) {
            Ok(b) => serde_json::from_slice(&b).context("read the agent device's record")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let raw = Redacted::new(match rec.secrets_at {
            SecretsAt::Keyring => self
                .entry()
                .and_then(|e| e.get_secret())
                .context("the agent device's keys are not in the keychain any more")?,
            SecretsAt::File => {
                std::fs::read(self.secrets_path()).context("read the agent device's secrets")?
            }
        });
        let blob: SecretBlob =
            serde_json::from_slice(raw.expose()).context("the secrets are malformed")?;
        let identity =
            SigningKey::from_bytes(&unb64_32(blob.identity_seed.expose(), "identity key")?);
        if b64(&identity.verifying_key().to_bytes()) != rec.identity_public {
            bail!("the stored keys do not match the agent device's record; `airdress agent device leave` and join again");
        }
        Ok(Some(AgentDevice {
            record: rec,
            identity,
            state_key: Redacted::new(unb64_32(blob.state_key.expose(), "state key")?),
            token: blob.token,
        }))
    }

    /// Delete the keys, the record and the sealed state (FR-27). The
    /// enrollment is the caller's to revoke first.
    ///
    /// Fails, naming where, when a secret could not be removed; the record
    /// goes last, so a failed run can be retried.
    pub fn forget(&self) -> Result<bool> {
        let existed = self.record_path().exists();
        let at = std::fs::read(self.record_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<AgentRecord>(&b).ok())
            .map(|r| r.secrets_at);
        if self.use_keyring {
            delete_keyring_secret(
                self.entry(),
                &format!("agent-device:{}", self.airdress),
                at == Some(SecretsAt::Keyring),
            )?;
        }
        remove_secret_file(&self.secrets_path())?;
        match std::fs::remove_file(self.record_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("remove {}", self.record_path().display()))
            }
        }
        match std::fs::remove_dir_all(self.mls_dir()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("remove the sealed MLS state"),
        }
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(airdress: &str) -> AgentDevice {
        let identity = SigningKey::from_bytes(&[5; 32]);
        AgentDevice {
            record: AgentRecord {
                airdress: airdress.into(),
                operator: "https://a.example".into(),
                enrollment_id: String::new(),
                device_id: "d".into(),
                label: "Agent on box".into(),
                harness: "test-harness".into(),
                identity_public: b64(&identity.verifying_key().to_bytes()),
                root_public: String::new(),
                delegation: None,
                expires_at: None,
                pending_request: Some("r".into()),
                secrets_at: SecretsAt::File,
            },
            identity,
            token: Redacted::default(),
            state_key: Redacted::new([6; 32]),
        }
    }

    #[test]
    fn a_device_round_trips_through_private_files_and_forgets_everything() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::file_only(dir.path(), "a.example").unwrap();
        assert!(store.load().unwrap().is_none());
        let mut dev = device("a.example");
        assert_eq!(store.save(&mut dev).unwrap(), SecretsAt::File);
        std::fs::create_dir_all(store.mls_dir()).unwrap();
        let back = store.load().unwrap().unwrap();
        assert_eq!(back.record, dev.record);
        assert_eq!(*back.state_key.expose(), [6; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for f in ["device.json", "secrets.json"] {
                let m = std::fs::metadata(store.dir().join(f))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(m & 0o777, 0o600, "{f}");
            }
        }
        assert!(store.forget().unwrap());
        assert!(store.load().unwrap().is_none());
        assert!(!store.mls_dir().exists(), "the sealed state goes too");
    }

    #[test]
    fn the_stored_secrets_keep_their_bare_form() {
        // Written before the fields were wrapped; `token` absent pre-enrolment.
        let raw = r#"{"identity_seed":"c2VlZA","token":"bearer-9","state_key":"a2V5"}"#;
        let blob: SecretBlob = serde_json::from_str(raw).unwrap();
        assert_eq!(blob.token.expose(), "bearer-9");
        assert!(!format!("{blob:?}").contains("bearer-9"));
        assert_eq!(serde_json::to_string(&blob).unwrap(), raw);
        let blob: SecretBlob =
            serde_json::from_str(r#"{"identity_seed":"c2VlZA","state_key":"a2V5"}"#).unwrap();
        assert!(blob.token.expose().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn forget_fails_naming_the_file_it_could_not_remove() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::file_only(dir.path(), "a.example").unwrap();
        let mut dev = device("a.example");
        store.save(&mut dev).unwrap();
        let d = store.dir().to_owned();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = store.forget();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the mode, so the unlink succeeds: nothing to observe.
        let Err(err) = result else { return };
        let msg = format!("{err:#}");
        assert!(msg.contains("secrets.json"), "{msg}");
        assert!(msg.contains("still on disk"), "{msg}");
        assert!(
            store.load().unwrap().is_some(),
            "the record stays for a retry"
        );
    }

    #[test]
    fn mismatched_keys_are_refused_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::file_only(dir.path(), "a.example").unwrap();
        let mut dev = device("a.example");
        store.save(&mut dev).unwrap();
        let mut rec = dev.record.clone();
        rec.identity_public = b64(&[1; 32]);
        store.save_record(&rec).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn an_airdress_cannot_escape_the_directory() {
        assert!(AgentStore::file_only(Path::new("/tmp"), "../x").is_err());
    }
}
