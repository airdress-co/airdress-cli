//! Signing operator requests as an enrolled machine (SPEC-113 task 113-B.1,
//! design §9; the machine identity itself is SPEC-095 / SPEC-098).
//!
//! A CI runner holds no hub profile. It holds a machine key the owner
//! approved, and signs every operator request with it over RFC 9421, the
//! profile `airdress-operator machine request` uses. The signing is not
//! reimplemented here: it is the operator's own `airdress-httpsig` crate,
//! pinned to an operator release, so the signer and the verifier cannot
//! disagree about the covered components, the parameters or the tag.
//!
//! What this module adds is the reading of the two files that
//! `airdress-operator machine enroll` writes, side by side:
//!
//! * the key file — the Ed25519 seed, base64url without padding, `0600`;
//! * `<key file>.json` — the operator, the machine id and the kid the key
//!   was approved under, and until when. Nothing in it is secret.
//!
//! Both formats are the operator's (`crates/airdress-operator/src/machines/
//! client.rs`, `load_key_file` / `load_enrollment`); the tests below hold
//! this reader to files in exactly that shape.
//!
//! Secrets never come from arguments (process listings show arguments):
//! the key is a path given by `--machine-key`, or the environment variable
//! [`MACHINE_KEY_ENV`] holding a path or the key itself. The enrollment
//! record sits beside a key file, or comes from
//! [`MACHINE_ENROLLMENT_ENV`], holding a path or the JSON itself.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// A machine key: a path to the key file, or the key itself.
pub const MACHINE_KEY_ENV: &str = "AIRDRESS_MACHINE_KEY";

/// A machine's enrollment record: a path to it, or its JSON.
pub const MACHINE_ENROLLMENT_ENV: &str = "AIRDRESS_MACHINE_ENROLLMENT";

/// How long a signature holds: the operator's `HTTP_SIGNATURE_LIFETIME`
/// (`airdress-common` `time_policy`), which its verifier enforces.
pub const SIGNATURE_LIFETIME: Duration = Duration::from_secs(60);

/// How far ahead of a lapsing approval a machine is warned: the operator's
/// `MACHINE_AUTHORIZATION_WARN_BEFORE`.
pub const AUTHORIZATION_WARN_BEFORE: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// The response header an operator sets on every machine-signed answer,
/// naming when the owner's approval lapses (RFC 3339).
pub const AUTHORIZATION_EXPIRES_HEADER: &str = "airdress-authorization-expires";

/// The refusal an operator answers with once the approval has lapsed.
pub const AUTHORIZATION_EXPIRED_CODE: &str = "machine_authorization_expired";

/// Which operator and machine a key belongs to — the operator's
/// `machines::client::Enrollment`, read-only here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Enrollment {
    /// The operator's origin, `https://<fqdn>`.
    pub operator: String,
    pub machine_id: uuid::Uuid,
    pub kid: String,
    /// Until when the owner's approval holds, RFC 3339; absent when it does
    /// not expire.
    #[serde(default)]
    pub authorized_until: Option<String>,
}

/// An enrolled machine: its key and its enrollment record.
pub struct MachineIdentity {
    seed: crate::redact::Redacted<[u8; 32]>,
    public: [u8; 32],
    pub enrollment: Enrollment,
}

impl std::fmt::Debug for MachineIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineIdentity")
            .field("fingerprint", &self.fingerprint())
            .field("enrollment", &self.enrollment)
            .finish_non_exhaustive()
    }
}

/// `SHA256:<base64, no padding>` of an Ed25519 public key — the form the
/// operator prints and the owner compares when approving.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(public_key))
    )
}

impl MachineIdentity {
    pub(crate) fn new(seed: [u8; 32], enrollment: Enrollment) -> Self {
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        Self {
            seed: crate::redact::Redacted::new(seed),
            public,
            enrollment,
        }
    }

    /// The machine key's fingerprint.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// The `keyid` the operator looks the key up by: `machine:<id>#<kid>`.
    pub fn keyid(&self) -> String {
        format!(
            "machine:{}#{}",
            self.enrollment.machine_id, self.enrollment.kid
        )
    }

    /// The headers that sign `method target` with `body`: `Content-Digest`,
    /// `Signature-Input` and `Signature`, plus `Content-Type` when given
    /// (it is a covered component, so it is set before signing).
    pub async fn sign(
        &self,
        method: &http::Method,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
        now: SystemTime,
    ) -> Result<http::HeaderMap> {
        let uri: http::Uri = target
            .parse()
            .with_context(|| format!("`{target}` is not a URL"))?;
        let mut headers = http::HeaderMap::new();
        if let Some(ct) = content_type {
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_str(ct).context("content type")?,
            );
        }
        let secret = airdress_httpsig::secret_key(self.seed.expose())
            .map_err(|e| anyhow::anyhow!("machine key: {e}"))?;
        let keyid = self.keyid();
        airdress_httpsig::sign_request(
            &secret,
            &airdress_httpsig::Profile {
                tag: airdress_httpsig::MACHINE_TAG,
                keyid: &keyid,
                lifetime: SIGNATURE_LIFETIME,
            },
            method,
            &uri,
            &mut headers,
            body,
            now,
        )
        .await
        .map_err(|e| anyhow::anyhow!("sign the request: {e}"))?;
        Ok(headers)
    }
}

/// Parse the key file's contents: base64url, no padding, 32 bytes.
pub fn parse_key(raw: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(raw.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .context("not a machine key (a 32-byte seed, base64url, as `machine enroll` writes it)")
}

/// Refuse a key file others can read, as the operator's own reader does.
fn ensure_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("could not read {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is readable by other users (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            );
        }
    }
    // Only unix has a mode to check; elsewhere `path` is otherwise unused.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Where a key's enrollment record lives: `<key file>.json`.
pub fn enrollment_path(key_path: &Path) -> PathBuf {
    let mut name = key_path.as_os_str().to_owned();
    name.push(".json");
    PathBuf::from(name)
}

/// Where the machine key and its record were found. Never carries the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Flag,
    Env,
}

/// The machine identity this run signs with, if one is configured: the
/// `--machine-key` path, else [`MACHINE_KEY_ENV`]. `None` when neither is
/// set, which means the hub profile's bearer is used instead.
pub fn load(flag: Option<&Path>) -> Result<Option<(MachineIdentity, KeySource)>> {
    load_with(flag, |name| std::env::var(name).ok())
}

/// [`load`] with the environment given rather than read: `env` answers
/// for [`MACHINE_KEY_ENV`] and [`MACHINE_ENROLLMENT_ENV`].
pub fn load_with(
    flag: Option<&Path>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<(MachineIdentity, KeySource)>> {
    let env = |name: &str| env(name).filter(|v| !v.trim().is_empty());
    let (seed, key_path, source) = match (flag, env(MACHINE_KEY_ENV)) {
        (Some(path), _) => (
            read_key_file(path)?,
            Some(path.to_path_buf()),
            KeySource::Flag,
        ),
        (None, Some(value)) => match parse_key(&value) {
            // The variable holds the key itself (a CI secret).
            Ok(seed) => (seed, None, KeySource::Env),
            Err(_) => {
                let path = PathBuf::from(value.trim());
                if !path.is_file() {
                    bail!("{MACHINE_KEY_ENV} holds neither a machine key nor the path of one");
                }
                (read_key_file(&path)?, Some(path), KeySource::Env)
            }
        },
        (None, None) => return Ok(None),
    };
    let enrollment = match (env(MACHINE_ENROLLMENT_ENV), &key_path) {
        (Some(value), _) => parse_enrollment_value(&value)?,
        (None, Some(path)) => read_enrollment_file(&enrollment_path(path))?,
        (None, None) => bail!(
            "the machine key came from {MACHINE_KEY_ENV}, so there is no file beside it to read \
             the enrollment from; set {MACHINE_ENROLLMENT_ENV} to the record's JSON (the \
             `<key>.json` that `airdress-operator machine enroll` wrote)"
        ),
    };
    Ok(Some((MachineIdentity::new(seed, enrollment), source)))
}

fn read_key_file(path: &Path) -> Result<[u8; 32]> {
    ensure_private(path)?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    parse_key(&raw).with_context(|| format!("{}", path.display()))
}

fn read_enrollment_file(path: &Path) -> Result<Enrollment> {
    let raw = std::fs::read(path).with_context(|| {
        format!(
            "no enrollment record at {} — has this key been enrolled and approved? (or set \
             {MACHINE_ENROLLMENT_ENV})",
            path.display()
        )
    })?;
    serde_json::from_slice(&raw).with_context(|| format!("{} is malformed", path.display()))
}

/// [`MACHINE_ENROLLMENT_ENV`]: the record's JSON, or a path to it.
fn parse_enrollment_value(value: &str) -> Result<Enrollment> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed)
            .with_context(|| format!("{MACHINE_ENROLLMENT_ENV} is not an enrollment record"));
    }
    read_enrollment_file(Path::new(trimmed))
}

/// The warning to print when the approval lapses within
/// [`AUTHORIZATION_WARN_BEFORE`], or has lapsed. `None` otherwise, and for
/// a value that is not RFC 3339.
pub fn authorization_warning(authorized_until: &str, now: SystemTime) -> Option<String> {
    let end: SystemTime = chrono::DateTime::parse_from_rfc3339(authorized_until.trim())
        .ok()?
        .with_timezone(&chrono::Utc)
        .into();
    if end <= now {
        return Some(format!(
            "this machine's approval expired at {authorized_until}; run `airdress-operator \
             machine reauth` and ask the owner to approve it again"
        ));
    }
    (end.duration_since(now).unwrap_or_default() <= AUTHORIZATION_WARN_BEFORE).then(|| {
        format!(
            "this machine's approval expires at {authorized_until}; run `airdress-operator \
             machine reauth` before then"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    fn identity() -> MachineIdentity {
        MachineIdentity::new(
            SEED,
            Enrollment {
                operator: "https://op.example".into(),
                machine_id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                kid: "k-0011223344556677".into(),
                authorized_until: None,
            },
        )
    }

    /// Files in the exact shape `airdress-operator machine enroll` writes
    /// (`create_key_file`: base64url + newline, 0600; `save_enrollment`:
    /// pretty JSON with the optional fields present).
    fn write_enrolled(dir: &Path) -> PathBuf {
        let key = dir.join("ci.key");
        std::fs::write(&key, format!("{}\n", URL_SAFE_NO_PAD.encode(SEED))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            enrollment_path(&key),
            r#"{
  "operator": "https://op.example",
  "machine_id": "00000000-0000-0000-0000-000000000001",
  "kid": "k-0011223344556677",
  "authorized_until": "2027-03-15T10:00:00Z",
  "operator_key": "b3BlcmF0b3Ita2V5LWJ5dGVz"
}
"#,
        )
        .unwrap();
        key
    }

    /// An environment that holds exactly `vars`.
    fn env_of<'a>(vars: &'a [(&'a str, String)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn the_operators_files_are_read_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_enrolled(dir.path());
        let (id, source) = load_with(Some(&key), env_of(&[])).unwrap().unwrap();
        assert_eq!(source, KeySource::Flag);
        assert_eq!(id.fingerprint(), identity().fingerprint());
        assert_eq!(
            id.keyid(),
            "machine:00000000-0000-0000-0000-000000000001#k-0011223344556677"
        );
        assert_eq!(
            id.enrollment.authorized_until.as_deref(),
            Some("2027-03-15T10:00:00Z")
        );
        // The seed never shows in a debug print.
        assert!(!format!("{id:?}").contains(&URL_SAFE_NO_PAD.encode(SEED)));
    }

    #[cfg(unix)]
    #[test]
    fn a_key_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let key = write_enrolled(dir.path());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_with(Some(&key), env_of(&[])).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
    }

    #[test]
    fn the_environment_may_hold_the_contents_of_both() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_enrolled(dir.path());
        let contents = std::fs::read_to_string(&key).unwrap();
        // Without the record the key alone is not enough, and says why.
        let key_only = [(MACHINE_KEY_ENV, contents.clone())];
        let err = load_with(None, env_of(&key_only)).unwrap_err().to_string();
        assert!(err.contains(MACHINE_ENROLLMENT_ENV), "{err}");
        let both = [
            (MACHINE_KEY_ENV, contents),
            (
                MACHINE_ENROLLMENT_ENV,
                std::fs::read_to_string(enrollment_path(&key)).unwrap(),
            ),
        ];
        let (id, source) = load_with(None, env_of(&both)).unwrap().unwrap();
        assert_eq!(source, KeySource::Env);
        assert_eq!(id.enrollment.kid, "k-0011223344556677");
        // A path in the variable works as well, with its record beside it.
        let a_path = [(MACHINE_KEY_ENV, key.display().to_string())];
        assert!(load_with(None, env_of(&a_path)).unwrap().is_some());
        assert!(load_with(None, env_of(&[])).unwrap().is_none());
    }

    /// The same check the operator's `airdress-httpsig` test and its
    /// `MachineAuth` make: the request verifies under the machine's public
    /// key with `httpsig-hyper` (the verifier the operator runs, same exact
    /// pin), and carries the machine tag and keyid.
    #[tokio::test]
    async fn a_signed_request_verifies_as_the_operator_verifies_it() {
        use httpsig_hyper::prelude::{AlgorithmName, SecretKey};
        use httpsig_hyper::MessageSignatureReq as _;

        let id = identity();
        let target = "https://op.example/v1/functions/relay/promote";
        let body = br#"{"version":"sha256:bb","basedOn":"sha256:aa"}"#;
        let headers = id
            .sign(
                &http::Method::POST,
                target,
                Some("application/json"),
                body,
                SystemTime::now(),
            )
            .await
            .unwrap();
        let input = headers["signature-input"].to_str().unwrap().to_owned();
        assert!(
            input.starts_with(
                "sig1=(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\");"
            ),
            "{input}"
        );
        assert!(input.contains(";tag=\"airdress-machine\""), "{input}");
        assert!(
            input.contains(&format!(";keyid=\"{}\"", id.keyid())),
            "{input}"
        );
        assert_eq!(
            headers["content-digest"],
            airdress_httpsig::content_digest(body)
        );

        let public = SecretKey::from_bytes(&AlgorithmName::Ed25519, &SEED)
            .unwrap()
            .public_key();
        let mut req = http::Request::builder()
            .method(http::Method::POST)
            .uri(target)
            .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
            .unwrap();
        req.headers_mut().clone_from(&headers);
        assert!(req
            .verify_message_signature(&public, Some(&id.keyid()))
            .await
            .is_ok());

        // Any other body, or target, fails: the digest and the URI are covered.
        let mut other = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://op.example/v1/functions/other/promote")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
            .unwrap();
        other.headers_mut().clone_from(&headers);
        assert!(other
            .verify_message_signature(&public, Some(&id.keyid()))
            .await
            .is_err());
    }

    #[test]
    fn a_lapsing_approval_warns_and_a_lapsed_one_names_reauth() {
        let now: SystemTime = chrono::DateTime::parse_from_rfc3339("2026-09-16T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            .into();
        assert_eq!(authorization_warning("2027-03-15T00:00:00Z", now), None);
        assert!(authorization_warning("2026-09-20T00:00:00Z", now)
            .is_some_and(|w| w.contains("expires at")));
        assert!(authorization_warning("2026-09-15T00:00:00Z", now)
            .is_some_and(|w| w.contains("expired at") && w.contains("machine reauth")));
        assert_eq!(authorization_warning("not a time", now), None);
    }

    #[test]
    fn the_fingerprint_is_the_operators_form() {
        // The operator's `codes::fingerprint`: `SHA256:` and the digest in
        // standard base64 without padding (43 characters).
        let f = fingerprint(&[0u8; 32]);
        assert!(f.starts_with("SHA256:"));
        assert_eq!(f.len(), "SHA256:".len() + 43);
    }
}
