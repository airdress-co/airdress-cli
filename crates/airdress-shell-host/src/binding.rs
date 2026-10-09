//! What this host is bound to, and its own keys (design §5.4, §6.1,
//! FR-H5, D-34).
//!
//! In `~/.local/state/airdress/shell-host/`, all `0600` in a `0700`
//! directory:
//!
//! - `machine.key` — the machine identity (Ed25519 seed, base64url), the
//!   format `airdress-operator machine enroll` writes. It signs every
//!   request to the operator (RFC 9421) and the host's shell key;
//! - `shell.key` — the host's X25519 shell key, the Noise responder's
//!   static key. Separate from the identity key on purpose (design §6.1);
//! - `binding.json` — the person, the root and the operator key this host
//!   pinned when it was approved. Written once and **never rewritten**:
//!   binding to someone else is a fresh enrollment;
//! - `authorization.json` — until when the approval holds, updated on
//!   renewal.
//!
//! The identity keys are the host's own, in files only its user can read,
//! as SPEC-098 machines keep theirs; no other secret is kept on disk.

use std::os::fd::OwnedFd;
use std::time::SystemTime;

use airdress_shell_proto::keys::ShellKeypair;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::log_err::LogErr as _;
use crate::paths::{create_private_new, ensure_private_file, Paths};
use crate::trust::{b64, BindingFacts};

/// The domain of the machine identity's signature over the shell key.
pub const HOST_KEY_LABEL: &[u8] = b"airdress.shell.host-key.v1";

/// Standard base64, as the operator writes it.
pub fn b64_std(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// The person a host is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Principal {
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// `binding.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    /// The operator's origin, `https://<fqdn>`.
    pub operator: String,
    /// The airdress, as the host's prologue names it (the origin's host).
    pub airdress: String,
    pub machine_id: Uuid,
    pub kid: String,
    pub principal: Principal,
    /// The airdress root's Ed25519 key, base64; absent when the operator
    /// has none pinned (then only introduced devices are admitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_key: Option<String>,
    /// The operator's `http_signing` key, base64: every signed frame must
    /// verify under it.
    pub operator_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_kid: Option<String>,
    pub bound_at: chrono::DateTime<chrono::Utc>,
}

/// `authorization.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_until: Option<String>,
}

/// `SHA256:<base64>` of a 32-byte key, the form the operator prints.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(key)))
}

/// The airdress a binding names: the host of the operator's origin.
pub fn airdress_of(origin: &str) -> Result<String> {
    let url: reqwest::Url = origin
        .parse()
        .with_context(|| format!("`{origin}` is not a URL"))?;
    url.host_str()
        .map(str::to_ascii_lowercase)
        .context("the operator URL has no host")
}

impl Binding {
    /// Read the binding, if this host was ever approved.
    pub fn load(paths: &Paths) -> Result<Option<Self>> {
        let p = paths.binding();
        if !p.exists() {
            return Ok(None);
        }
        ensure_private_file(&p)?;
        let raw = crate::fsx::read(&p)?;
        Ok(Some(serde_json::from_slice(&raw).with_context(|| {
            format!("{} is malformed", p.display())
        })?))
    }

    /// Write the binding, once.
    pub fn save_new(&self, paths: &Paths) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        create_private_new(&paths.binding(), &bytes)
    }

    /// The facts the device checks need.
    pub fn facts(&self) -> BindingFacts {
        BindingFacts {
            principal: self.principal.id,
            root: self
                .root_public_key
                .as_deref()
                .and_then(b64)
                .and_then(|b| b.try_into().ok()),
            airdress: self.airdress.clone(),
        }
    }

    /// The pinned operator key.
    pub fn operator_verifying_key(&self) -> Result<VerifyingKey> {
        let raw: [u8; 32] = b64(&self.operator_key)
            .and_then(|b| b.try_into().ok())
            .context("the pinned operator key is malformed")?;
        VerifyingKey::from_bytes(&raw).context("the pinned operator key is not an Ed25519 key")
    }

    /// The root's fingerprint, when one is pinned.
    pub fn root_fingerprint(&self) -> Option<String> {
        let k: [u8; 32] = b64(self.root_public_key.as_deref()?)?.try_into().ok()?;
        Some(key_fingerprint(&k))
    }

    /// The operator key's fingerprint.
    pub fn operator_fingerprint(&self) -> String {
        b64(&self.operator_key)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map_or_else(|| "(malformed)".into(), |k| key_fingerprint(&k))
    }

    /// The host's X25519 shell key.
    pub fn shell_keypair(&self, paths: &Paths) -> Result<ShellKeypair> {
        load_shell_key(paths)
    }

    /// The machine identity's signature over the host's shell key:
    /// `"airdress.shell.host-key.v1" ‖ 0x00 ‖ machine id (16) ‖ key (32)`,
    /// base64url.
    pub fn sign_shell_key(&self, paths: &Paths, shell: &[u8; 32]) -> Result<String> {
        let key = load_machine_key(paths)?;
        let mut msg = HOST_KEY_LABEL.to_vec();
        msg.push(0);
        msg.extend_from_slice(self.machine_id.as_bytes());
        msg.extend_from_slice(shell);
        Ok(URL_SAFE_NO_PAD.encode(key.sign(&msg).to_bytes()))
    }

    /// The signer for this machine's requests.
    pub fn signer(&self, paths: &Paths) -> Result<MachineSigner> {
        Ok(MachineSigner {
            seed: Zeroizing::new(load_machine_key(paths)?.to_bytes()),
            keyid: format!("machine:{}#{}", self.machine_id, self.kid),
        })
    }

    /// The block design §5.4 prints, and `status` repeats.
    pub fn describe(&self, shell: &[u8; 32]) -> String {
        let who = self
            .principal
            .display_name
            .clone()
            .unwrap_or_else(|| self.principal.id.to_string());
        format!(
            "Bound to {who} ({}) on {}\n\
             Operator key  {}   Root key  {}\n\
             This host's key  {}\n\
             Your devices show this host's key the first time they connect; check it matches.",
            self.principal.id,
            self.airdress,
            self.operator_fingerprint(),
            self.root_fingerprint()
                .unwrap_or_else(|| "(none pinned)".into()),
            airdress_shell_proto::keys::fingerprint(shell),
        )
    }
}

impl Authorization {
    /// Read it; a missing file is an approval that does not expire.
    pub fn load(paths: &Paths) -> Self {
        std::fs::read(paths.host_dir().join("authorization.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write it, atomically.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        crate::paths::write_private_atomic(&paths.host_dir().join("authorization.json"), &bytes)
    }

    /// The warning to print from 14 days before the approval lapses.
    pub fn warning(&self, now: SystemTime) -> Option<String> {
        let until = self.authorized_until.as_deref()?;
        let end: SystemTime = chrono::DateTime::parse_from_rfc3339(until)
            .ok()?
            .with_timezone(&chrono::Utc)
            .into();
        if end <= now {
            return Some(format!(
                "This host's approval expired at {until}. Run `airdress shell host reauth` and approve it again."
            ));
        }
        (end.duration_since(now).ok()? <= std::time::Duration::from_secs(14 * 86_400)).then(|| {
            format!("This host's approval expires at {until}. Run `airdress shell host reauth` before then.")
        })
    }
}

/// Signs this machine's requests, over the operator's own profile.
pub struct MachineSigner {
    seed: Zeroizing<[u8; 32]>,
    keyid: String,
}

impl std::fmt::Debug for MachineSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineSigner")
            .field("keyid", &self.keyid)
            .finish_non_exhaustive()
    }
}

impl MachineSigner {
    /// A signer for `seed` under `keyid` (`machine:<id>#<kid>`).
    pub fn new(seed: [u8; 32], keyid: String) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            keyid,
        }
    }

    /// The headers that sign `method url` with `body`.
    pub async fn headers(
        &self,
        method: &http::Method,
        url: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<http::HeaderMap> {
        let uri: http::Uri = url
            .parse()
            .with_context(|| format!("`{url}` is not a URL"))?;
        let mut headers = http::HeaderMap::new();
        if let Some(ct) = content_type {
            headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_str(ct)?);
        }
        let secret = airdress_httpsig::secret_key(&self.seed)
            .map_err(|e| anyhow::anyhow!("machine key: {e}"))?;
        airdress_httpsig::sign_request(
            &secret,
            &airdress_httpsig::Profile {
                tag: airdress_httpsig::MACHINE_TAG,
                keyid: &self.keyid,
                lifetime: std::time::Duration::from_secs(60),
            },
            method,
            &uri,
            &mut headers,
            body,
            SystemTime::now(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("sign the request: {e}"))?;
        Ok(headers)
    }
}

/// Create the machine key if there is none; read it otherwise.
pub fn ensure_machine_key(paths: &Paths) -> Result<SigningKey> {
    let p = paths.machine_key();
    if p.exists() {
        return load_machine_key(paths);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed[..]);
    create_private_new(
        &p,
        format!("{}\n", URL_SAFE_NO_PAD.encode(*seed)).as_bytes(),
    )?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Read the machine key, refusing a file others can read.
pub fn load_machine_key(paths: &Paths) -> Result<SigningKey> {
    let p = paths.machine_key();
    ensure_private_file(&p)?;
    let raw = Zeroizing::new(crate::fsx::read_to_string(&p)?);
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{} is not a machine key", p.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Create the shell key if there is none; read it otherwise.
pub fn ensure_shell_key(paths: &Paths) -> Result<ShellKeypair> {
    let p = paths.shell_key();
    if p.exists() {
        return load_shell_key(paths);
    }
    let kp = ShellKeypair::generate(&mut rand::rngs::OsRng);
    create_private_new(
        &p,
        format!("{}\n", URL_SAFE_NO_PAD.encode(kp.secret())).as_bytes(),
    )?;
    Ok(kp)
}

/// Read the shell key, refusing a file others can read.
pub fn load_shell_key(paths: &Paths) -> Result<ShellKeypair> {
    let p = paths.shell_key();
    ensure_private_file(&p)?;
    let raw = Zeroizing::new(crate::fsx::read_to_string(&p)?);
    let secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{} is not a shell key", p.display()))?;
    Ok(ShellKeypair::from_secret(secret))
}

/// The single-instance lock (design §7.1): held for the life of the process.
#[derive(Debug)]
pub struct InstanceLock {
    _fd: OwnedFd,
}

/// Take the lock for `airdress`, or name the pid that holds it.
pub fn lock(paths: &Paths, airdress: &str) -> Result<InstanceLock> {
    use std::io::{Read as _, Seek as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let p = paths.lock(airdress);
    crate::paths::ensure_private_dir(p.parent().context("lock dir")?)?;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&p)
        .with_context(|| format!("could not open {}", p.display()))?;
    match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            let mut s = String::new();
            // Only to name the holder; an unreadable pid says "unknown" below.
            f.read_to_string(&mut s)
                .log_debug("reading the lock holder's pid");
            let pid = s.trim();
            bail!(
                "another `airdress shell host` is running for {airdress} (pid {}); stop it first",
                if pid.is_empty() { "unknown" } else { pid }
            );
        }
        Err(e) => return Err(e).context("could not lock"),
    }
    f.set_len(0)?;
    f.rewind()?;
    write!(f, "{}", std::process::id())?;
    f.sync_all()?;
    Ok(InstanceLock { _fd: f.into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_instance_is_refused_and_names_the_first() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let held = lock(&p, "a.example").unwrap();
        let err = lock(&p, "a.example").unwrap_err().to_string();
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "{err}"
        );
        // Another airdress is another lock.
        let _other = lock(&p, "b.example").unwrap();
        drop(held);
        // Another test's child may hold the descriptor for an instant
        // between its fork and its exec.
        let mut again = lock(&p, "a.example");
        for _ in 0..50 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            again = lock(&p, "a.example");
        }
        again.unwrap();
    }

    #[test]
    fn keys_are_private_and_kept() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let a = ensure_machine_key(&p).unwrap();
        let b = ensure_machine_key(&p).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        let s1 = ensure_shell_key(&p).unwrap();
        let s2 = ensure_shell_key(&p).unwrap();
        assert_eq!(s1.public(), s2.public());
        for f in [p.machine_key(), p.shell_key()] {
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn the_binding_is_written_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let b = Binding {
            operator: "https://a.example".into(),
            airdress: "a.example".into(),
            machine_id: Uuid::from_u128(1),
            kid: "k-1".into(),
            principal: Principal {
                id: Uuid::from_u128(2),
                display_name: Some("Anna".into()),
            },
            root_public_key: Some(b64_std(&[1; 32])),
            operator_key: b64_std(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()),
            operator_kid: None,
            bound_at: chrono::Utc::now(),
        };
        b.save_new(&p).unwrap();
        assert_eq!(
            std::fs::metadata(p.binding()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(b.save_new(&p).is_err(), "never rewritten");
        assert_eq!(Binding::load(&p).unwrap().unwrap(), b);
        let shell = [7u8; 32];
        let text = b.describe(&shell);
        assert!(text.contains("Bound to Anna"));
        assert!(text.contains(&airdress_shell_proto::keys::fingerprint(&shell)));
        assert!(b.operator_verifying_key().is_ok());
    }

    #[test]
    fn the_approval_warns_from_fourteen_days() {
        let now = SystemTime::now();
        let at = |d: i64| Authorization {
            authorized_until: Some((chrono::Utc::now() + chrono::Duration::days(d)).to_rfc3339()),
        };
        assert!(at(30).warning(now).is_none());
        assert!(at(10).warning(now).unwrap().contains("expires"));
        assert!(at(-1).warning(now).unwrap().contains("expired"));
        assert!(Authorization::default().warning(now).is_none());
    }
}
