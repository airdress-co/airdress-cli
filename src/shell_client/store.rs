//! Where the CLI keeps its device: the Secret Service where available, else
//! a 0600 file under `~/.local/state/airdress/` (design §6.4, task D.1).
//!
//! Two records per airdress:
//!
//! - `device.json` (0600): what is not secret — the enrollment id, the label,
//!   the public keys, whether the shell keys were registered, and where the
//!   secrets went;
//! - the secrets — the device's session bearer, its identity seed (the key
//!   the delegation names) and its X25519 shell key — as one JSON value in
//!   the Secret Service (service `airdress`, account
//!   `shell-device:<airdress>`), or, with no Secret Service, `secrets.json`
//!   (0600) beside `device.json`.
//!
//! The pinned host keys (`known-hosts.json`) live beside them.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use airdress_shell_proto::keys::ShellKeypair;

use crate::redact::Redacted;

const KEYRING_SERVICE: &str = "airdress";

/// Where the secrets are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretsAt {
    /// The Secret Service (or the platform keychain).
    Keyring,
    /// `secrets.json`, 0600.
    File,
}

/// The non-secret half of the CLI's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The airdress (its FQDN).
    pub airdress: String,
    /// The enrollment id: this device's id on the shell routes.
    pub enrollment_id: String,
    /// The stable device id the delegation binds.
    pub device_id: String,
    /// What the approving phone was shown.
    pub label: String,
    /// The identity key (Ed25519), base64url.
    pub identity_public: String,
    /// The shell key (X25519), base64url.
    pub shell_public: String,
    /// Whether `POST /v1/shells/device-keys` accepted the shell key.
    #[serde(default)]
    pub keys_registered: bool,
    /// Where the secrets are.
    pub secrets_at: SecretsAt,
}

/// The secret half, as stored. The on-disk (and keyring) form is three
/// bare strings, unchanged since the store was written.
#[derive(Debug, Serialize, Deserialize)]
struct SecretBlob {
    #[serde(with = "crate::redact::persist")]
    token: Redacted<String>,
    #[serde(with = "crate::redact::persist")]
    identity_seed: Redacted<String>,
    #[serde(with = "crate::redact::persist")]
    shell_secret: Redacted<String>,
}

/// The CLI's device, loaded.
pub struct CliDevice {
    /// The record.
    pub record: DeviceRecord,
    /// The session bearer.
    pub token: Redacted<String>,
    /// The identity key.
    pub identity: SigningKey,
    /// The shell key.
    pub shell: ShellKeypair,
}

impl core::fmt::Debug for CliDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliDevice")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// One airdress's directory, and whether to try the keyring.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    airdress: String,
    use_keyring: bool,
}

fn valid_airdress(a: &str) -> Result<()> {
    if a.is_empty() || a.starts_with('.') || a.chars().any(|c| c == '/' || c == '\\' || c == '\0') {
        bail!("airdress {a:?} cannot name a directory");
    }
    Ok(())
}

/// Write `bytes` to `path` with mode 0600, creating 0700 parents.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("a path with no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        crate::fsx::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Remove a file that holds secrets. Absent is fine; anything else fails,
/// naming the path, because the secret is still on disk.
pub(crate) fn remove_secret_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| {
            format!(
                "remove {}; the secrets in it are still on disk",
                path.display()
            )
        }),
    }
}

/// Delete one keyring entry. Absent is fine. When `required` (the record
/// says the secrets live there), any other failure fails, naming the entry,
/// because the secret is still stored; otherwise it is logged, since there
/// is nothing to say the keyring ever held them.
pub(crate) fn delete_keyring_secret(
    entry: keyring::Result<keyring::Entry>,
    account: &str,
    required: bool,
) -> Result<()> {
    match entry.and_then(|e| e.delete_credential()) {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) if required => Err(anyhow!(e)).with_context(|| {
            format!(
                "remove the secrets from the keyring (service {KEYRING_SERVICE}, \
                 account {account}); they are still stored there"
            )
        }),
        Err(e) => {
            tracing::warn!(
                error = %e,
                account,
                "could not clear the keyring entry; the record does not place secrets there"
            );
            Ok(())
        }
    }
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("the stored {what} is malformed"))
}

impl Store {
    /// The store for `airdress` under the state home, using the keyring.
    pub fn for_airdress(paths: &crate::paths::Paths, airdress: &str) -> Result<Self> {
        valid_airdress(airdress)?;
        Ok(Self {
            dir: paths
                .state_home()
                .join("airdress")
                .join("shell-client")
                .join(airdress),
            airdress: airdress.to_owned(),
            use_keyring: true,
        })
    }

    /// A store in `dir`, file-only (tests, and hosts without a keyring).
    pub fn in_dir(dir: &Path, airdress: &str) -> Result<Self> {
        valid_airdress(airdress)?;
        Ok(Self {
            dir: dir.to_owned(),
            airdress: airdress.to_owned(),
            use_keyring: false,
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `known-hosts.json`.
    pub fn pins_path(&self) -> PathBuf {
        self.dir.join("known-hosts.json")
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join("device.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.dir.join("secrets.json")
    }

    fn entry(&self) -> keyring::Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &format!("shell-device:{}", self.airdress))
    }

    /// Save a newly enrolled device. Returns where the secrets went.
    pub fn save(&self, dev: &mut CliDevice) -> Result<SecretsAt> {
        let blob = Redacted::new(serde_json::to_vec(&SecretBlob {
            token: dev.token.clone(),
            identity_seed: Redacted::new(b64(&dev.identity.to_bytes())),
            shell_secret: Redacted::new(b64(dev.shell.secret())),
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
            // A file left by an earlier keyring-less run must not outlive
            // the move into the keyring.
            remove_secret_file(&self.secrets_path())?;
        }
        dev.record.secrets_at = at;
        self.save_record(&dev.record)?;
        Ok(at)
    }

    /// Rewrite only the non-secret record.
    pub fn save_record(&self, rec: &DeviceRecord) -> Result<()> {
        write_private(&self.record_path(), &serde_json::to_vec_pretty(rec)?)
    }

    /// Load the device, or `None` when this CLI has not joined the airdress.
    pub fn load(&self) -> Result<Option<CliDevice>> {
        let rec: DeviceRecord = match std::fs::read(self.record_path()) {
            Ok(b) => serde_json::from_slice(&b).context("read the CLI's device record")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let raw = Redacted::new(match rec.secrets_at {
            SecretsAt::Keyring => self
                .entry()
                .and_then(|e| e.get_secret())
                .context("the device's secrets are not in the keyring any more")?,
            SecretsAt::File => {
                std::fs::read(self.secrets_path()).context("read the device's secrets")?
            }
        });
        let blob: SecretBlob =
            serde_json::from_slice(raw.expose()).context("the secrets are malformed")?;
        let identity =
            SigningKey::from_bytes(&unb64::<32>(blob.identity_seed.expose(), "identity key")?);
        let shell =
            ShellKeypair::from_secret(unb64::<32>(blob.shell_secret.expose(), "shell key")?);
        if b64(&identity.verifying_key().to_bytes()) != rec.identity_public
            || b64(shell.public()) != rec.shell_public
        {
            bail!("the stored secrets do not match the device record; rejoin with `airdress shell device forget`");
        }
        Ok(Some(CliDevice {
            record: rec,
            token: blob.token,
            identity,
            shell,
        }))
    }

    /// Remove the device (the enrollment is untouched; revoke it from a
    /// phone).
    ///
    /// Fails, naming where, when a secret could not be removed: saying the
    /// device is forgotten while its bearer is still stored is the defect
    /// this refuses. The record goes last, so a failed run can be retried.
    pub fn forget(&self) -> Result<bool> {
        let existed = self.record_path().exists();
        // Where the record says the secrets went decides whether a keyring
        // failure matters. With no readable record, try anyway and only
        // warn: there is nothing to say the keyring ever held them.
        let at = std::fs::read(self.record_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<DeviceRecord>(&b).ok())
            .map(|r| r.secrets_at);
        if self.use_keyring {
            delete_keyring_secret(
                self.entry(),
                &format!("shell-device:{}", self.airdress),
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
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_round_trips_through_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::in_dir(dir.path(), "a.example").unwrap();
        assert!(store.load().unwrap().is_none());
        let identity = SigningKey::from_bytes(&[3; 32]);
        let shell = ShellKeypair::from_secret([4; 32]);
        let mut dev = CliDevice {
            record: DeviceRecord {
                airdress: "a.example".into(),
                enrollment_id: "e".into(),
                device_id: "d".into(),
                label: "airdress CLI on box".into(),
                identity_public: b64(&identity.verifying_key().to_bytes()),
                shell_public: b64(shell.public()),
                keys_registered: false,
                secrets_at: SecretsAt::File,
            },
            token: "tok".into(),
            identity,
            shell,
        };
        assert_eq!(store.save(&mut dev).unwrap(), SecretsAt::File);
        let back = store.load().unwrap().unwrap();
        assert_eq!(back.token.expose(), "tok");
        assert!(!format!("{back:?}").contains("tok"));
        assert_eq!(back.shell.public(), dev.shell.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for f in ["device.json", "secrets.json"] {
                let m = std::fs::metadata(dir.path().join(f))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(m & 0o777, 0o600, "{f}");
            }
        }
        assert!(store.forget().unwrap());
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn the_stored_secrets_keep_their_bare_form() {
        // Written by the store before its fields were wrapped.
        let raw = r#"{"token":"tok-1","identity_seed":"c2VlZA","shell_secret":"c2hlbGw"}"#;
        let blob: SecretBlob = serde_json::from_str(raw).unwrap();
        assert_eq!(blob.token.expose(), "tok-1");
        assert!(!format!("{blob:?}").contains("tok-1"));
        assert_eq!(serde_json::to_string(&blob).unwrap(), raw);
    }

    #[cfg(unix)]
    #[test]
    fn forget_fails_naming_the_file_it_could_not_remove() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::in_dir(dir.path(), "a.example").unwrap();
        std::fs::write(dir.path().join("secrets.json"), b"{}").unwrap();
        // A read-only directory: the unlink is refused.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = store.forget();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the mode, so the unlink succeeds: nothing to observe.
        let Err(err) = result else { return };
        let msg = format!("{err:#}");
        assert!(msg.contains("secrets.json"), "{msg}");
        assert!(msg.contains("still on disk"), "{msg}");
    }

    #[test]
    fn an_airdress_cannot_escape_the_directory() {
        assert!(Store::in_dir(Path::new("/tmp"), "../x").is_err());
        assert!(Store::in_dir(Path::new("/tmp"), ".hidden").is_err());
    }
}
