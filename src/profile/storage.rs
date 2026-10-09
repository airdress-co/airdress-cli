use std::collections::BTreeMap;
use std::fs;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::redact::Redacted;

/// Current on-disk profile schema version. Bumped from 1 → 2 in
/// SPEC-043 when `active_airdress` was added. v1 readers see the new
/// field as missing and treat it as `None`; v2 writers always emit
/// the field (Some or null). Migration is silent on the next mutating
/// write (see `write_profile`).
pub const SCHEMA_VERSION: u32 = 2;

/// Schema of a profile signed in through the hub's authorization server
/// (SPEC-133 D-36): one grant at the hub, and a separate access token per
/// resource (the hub API, and `https://<fqdn>/v1` for each operator).
/// Written only by `auth login` — a v2 profile is never upgraded in place,
/// because the move changes who issued its credential. [`write_profile`]
/// stamps it whenever the auth block is [`AuthConfig::Hub`].
pub const HUB_SCHEMA_VERSION: u32 = 3;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    pub schema_version: u32,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,
    /// SPEC-043 — name of the airdress pinned as "current" for this
    /// profile. Missing in v1 files; deserializes to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_airdress: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "method")]
pub enum AuthConfig {
    #[serde(rename = "device_flow")]
    DeviceFlow {
        #[serde(with = "crate::redact::persist")]
        access_token: Redacted<String>,
        #[serde(with = "crate::redact::persist")]
        refresh_token: Redacted<String>,
        expires_at: String,
        id_token_claims: IdTokenClaims,
        /// The raw ID token from login, kept so `auth logout` can end the
        /// IdP session it belongs to (`id_token_hint` at end_session).
        /// Absent in profiles written before it was kept.
        #[serde(
            default,
            with = "crate::redact::persist_opt",
            skip_serializing_if = "Option::is_none"
        )]
        id_token: Option<Redacted<String>>,
    },
    /// Signed in through the hub's authorization server. The refresh token
    /// is the grant; every access token is audience-bound to one resource,
    /// so the token an operator accepts is not one another operator would.
    #[serde(rename = "hub")]
    Hub {
        /// The authorization server's issuer (RFC 8414), which is the hub.
        issuer: String,
        client_id: String,
        token_endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revocation_endpoint: Option<String>,
        /// The resource indicator (RFC 8707) of the hub's own API.
        hub_resource: String,
        /// Rotates on every use; the previous one is dead once a new one
        /// is written, and presenting it again revokes the whole grant.
        #[serde(with = "crate::redact::persist")]
        refresh_token: Redacted<String>,
        id_token_claims: IdTokenClaims,
        /// Cached access tokens, keyed by resource indicator.
        #[serde(default)]
        access_tokens: BTreeMap<String, ResourceToken>,
    },
    #[serde(rename = "client_credentials")]
    ClientCredentials {
        client_id: String,
        #[serde(with = "crate::redact::persist")]
        client_secret: Redacted<String>,
    },
    #[serde(rename = "jwt_profile")]
    JwtProfile { key_file: String },
}

/// One audience-bound access token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ResourceToken {
    #[serde(with = "crate::redact::persist")]
    pub access_token: Redacted<String>,
    pub expires_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: String,
}

pub fn ensure_dirs(paths: &Paths) -> Result<()> {
    let config = paths.config_dir().to_owned();
    let profiles = paths.profiles_dir();

    for dir in [&config, &profiles] {
        if !dir.exists() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                crate::fsx::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    Ok(())
}

/// Endpoint a profile gets when nobody names one: `auth login` into a
/// profile that does not exist yet, and `profile create` without
/// `--endpoint`.
pub const DEFAULT_ENDPOINT: &str = "https://account.airdress.co";

pub fn read_profile(paths: &Paths, name: &str) -> Result<Profile> {
    let path = paths.profile_path(name);
    let data = match fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::exit::Failure::auth(
                "profile_not_found",
                format!(
                    "profile '{name}' does not exist — `airdress auth login --profile {name}` \
                     creates it (or `airdress profile create {name} --endpoint <url>` for a \
                     non-default hub)"
                ),
            )
            .with_hint(format!("run `airdress auth login --profile {name}`"))
            .into())
        }
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read profile '{name}'"));
        }
    };
    let profile: Profile =
        serde_json::from_str(&data).with_context(|| format!("invalid profile '{name}'"))?;
    Ok(profile)
}

/// Write a profile. Written to a sibling temporary file and renamed into
/// place, so a reader in another process never sees half a file — the
/// refresh token in it is single-use, and losing the new one to a torn
/// write would end the grant.
pub fn write_profile(paths: &Paths, name: &str, profile: &Profile) -> Result<()> {
    ensure_dirs(paths)?;
    let path = paths.profile_path(name);
    let mut profile = profile.clone();
    if matches!(profile.auth, Some(AuthConfig::Hub { .. })) {
        profile.schema_version = HUB_SCHEMA_VERSION;
    }
    let data = serde_json::to_string_pretty(&profile)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    {
        use std::io::Write as _;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("failed to write profile '{name}'"))?;
        f.write_all(data.as_bytes())
            .with_context(|| format!("failed to write profile '{name}'"))?;
        f.sync_all().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        crate::fsx::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, &path).with_context(|| format!("failed to write profile '{name}'"))?;
    Ok(())
}

/// An exclusive, cross-process lock on one profile, held while its
/// single-use refresh token is spent and the result written back. Two
/// `airdress` processes refreshing at once would otherwise present the
/// same refresh token twice, and the hub answers a reused refresh token
/// by revoking the whole grant. Released on drop.
#[derive(Debug)]
pub struct ProfileLock {
    #[allow(dead_code)]
    file: fs::File,
}

impl ProfileLock {
    /// Block (on a blocking thread) until the lock is ours.
    pub async fn acquire(paths: &Paths, name: &str) -> Result<Self> {
        ensure_dirs(paths)?;
        let path = paths.profiles_dir().join(format!("{name}.lock"));
        tokio::task::spawn_blocking(move || -> Result<Self> {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .with_context(|| format!("failed to open {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                // SAFETY: flock on a descriptor this function owns.
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("failed to lock {}", path.display()));
                }
            }
            Ok(Self { file })
        })
        .await
        .context("profile lock task")?
    }
}

pub fn read_active_profile(paths: &Paths) -> Result<Option<String>> {
    let path = paths.active_profile_path();
    match fs::read_to_string(&path) {
        Ok(content) => {
            let name = content.trim().to_string();
            if name.is_empty() {
                Ok(None)
            } else {
                Ok(Some(name))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("failed to read active profile"),
    }
}

pub fn write_active_profile(paths: &Paths, name: &str) -> Result<()> {
    ensure_dirs(paths)?;
    let path = paths.active_profile_path();
    fs::write(&path, format!("{name}\n")).context("failed to write active profile")?;
    Ok(())
}

pub fn list_profiles(paths: &Paths) -> Result<Vec<(String, bool)>> {
    let dir = paths.profiles_dir();
    let active = read_active_profile(paths)?.unwrap_or_default();
    let mut profiles = Vec::new();

    if !dir.exists() {
        return Ok(profiles);
    }

    let entries = fs::read_dir(&dir).context("failed to read profiles directory")?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let is_active = stem == active;
                profiles.push((stem.to_string(), is_active));
            }
        }
    }
    profiles.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(profiles)
}

pub fn redact_auth(auth: &AuthConfig) -> serde_json::Value {
    match auth {
        AuthConfig::DeviceFlow {
            id_token_claims,
            id_token,
            ..
        } => serde_json::json!({
            "method": "device_flow",
            "access_token": "****",
            "refresh_token": "****",
            "id_token": id_token.as_ref().map(|_| "****"),
            "id_token_claims": {
                "sub": id_token_claims.sub,
                "email": id_token_claims.email,
            }
        }),
        AuthConfig::Hub {
            issuer,
            client_id,
            id_token_claims,
            access_tokens,
            ..
        } => serde_json::json!({
            "method": "hub",
            "issuer": issuer,
            "client_id": client_id,
            "refresh_token": "****",
            "access_tokens": access_tokens
                .iter()
                .map(|(resource, t)| (resource.clone(), serde_json::json!({
                    "access_token": "****",
                    "expires_at": t.expires_at,
                })))
                .collect::<serde_json::Map<_, _>>(),
            "id_token_claims": {
                "sub": id_token_claims.sub,
                "email": id_token_claims.email,
            }
        }),
        AuthConfig::ClientCredentials { client_id, .. } => serde_json::json!({
            "method": "client_credentials",
            "client_id": client_id,
            "client_secret": "****"
        }),
        AuthConfig::JwtProfile { key_file } => serde_json::json!({
            "method": "jwt_profile",
            "key_file": key_file
        }),
    }
}

pub fn resolve_profile_name(paths: &Paths, explicit: Option<&str>) -> Result<String> {
    if let Some(name) = explicit {
        return Ok(name.to_string());
    }
    if let Some(active) = read_active_profile(paths)? {
        return Ok(active);
    }
    bail!("no active profile — run `airdress profile create <name>` first")
}

/// SPEC-043 — set `active_airdress` on the named profile. Loading
/// silently upgrades v1 files to v2 on the write-back. Callers must
/// validate the airdress name belongs to the user before calling this.
pub fn set_active_airdress(paths: &Paths, profile_name: &str, airdress_name: &str) -> Result<()> {
    let mut profile = read_profile(paths, profile_name)?;
    profile.schema_version = SCHEMA_VERSION;
    profile.active_airdress = Some(airdress_name.to_string());
    write_profile(paths, profile_name, &profile)
}

/// SPEC-043 — clear `active_airdress` on the named profile. Idempotent
/// (no-op if already unset). Used by the resolve-time recovery path
/// when the hub says the pinned airdress is gone.
pub fn clear_active_airdress(paths: &Paths, profile_name: &str) -> Result<()> {
    let mut profile = read_profile(paths, profile_name)?;
    if profile.active_airdress.is_none() {
        return Ok(());
    }
    profile.schema_version = SCHEMA_VERSION;
    profile.active_airdress = None;
    write_profile(paths, profile_name, &profile)
}

/// A fresh, empty home for one test: its own temporary directory, held
/// for as long as the returned guard lives. Nothing process-global moves,
/// so tests using it run in parallel.
#[cfg(test)]
pub(crate) fn temp_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    (dir, paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPEC-043: dropped the static Mutex in favor of `#[serial(env)]`
    // on every test that mutates $HOME. The static Mutex poisons on
    // panic, contaminating every subsequent test in the binary;
    // serial_test releases its lock cleanly on panic.

    /// Profiles written before the secrets were wrapped, byte for byte as
    /// `write_profile` emitted them. Each must load and write back
    /// unchanged, and no rendering of the loaded value may carry a secret.
    const PROFILES_ON_DISK: &[(&str, &[&str])] = &[
        (
            r#"{
  "schema_version": 3,
  "endpoint": "https://account.airdress.co",
  "auth": {
    "method": "hub",
    "issuer": "https://account.airdress.co",
    "client_id": "airdress-cli",
    "token_endpoint": "https://account.airdress.co/oauth/token",
    "revocation_endpoint": "https://account.airdress.co/oauth/revoke",
    "hub_resource": "https://account.airdress.co",
    "refresh_token": "rt-hub-secret",
    "id_token_claims": {
      "sub": "user-1",
      "email": "ada@example.com"
    },
    "access_tokens": {
      "https://vm2.example/v1": {
        "access_token": "at-vm2-secret",
        "expires_at": "2026-10-07T12:00:00+00:00"
      }
    }
  },
  "active_airdress": "home"
}"#,
            &["rt-hub-secret", "at-vm2-secret"],
        ),
        (
            r#"{
  "schema_version": 2,
  "endpoint": "https://account.airdress.co",
  "auth": {
    "method": "device_flow",
    "access_token": "at-df-secret",
    "refresh_token": "rt-df-secret",
    "expires_at": "2026-12-31T00:00:00Z",
    "id_token_claims": {
      "sub": "user-1",
      "email": "ada@example.com"
    },
    "id_token": "idt-df-secret"
  }
}"#,
            &["at-df-secret", "rt-df-secret", "idt-df-secret"],
        ),
        (
            r#"{
  "schema_version": 2,
  "endpoint": "https://account.airdress.co",
  "auth": {
    "method": "device_flow",
    "access_token": "at-old-secret",
    "refresh_token": "",
    "expires_at": "2026-12-31T00:00:00Z",
    "id_token_claims": {
      "sub": "user-1",
      "email": "ada@example.com"
    }
  }
}"#,
            &["at-old-secret"],
        ),
        (
            r#"{
  "schema_version": 1,
  "endpoint": "https://account.airdress.co",
  "auth": {
    "method": "client_credentials",
    "client_id": "cid",
    "client_secret": "cs-secret"
  }
}"#,
            &["cs-secret"],
        ),
    ];

    #[test]
    fn existing_profiles_load_and_write_back_byte_for_byte() {
        for (raw, _) in PROFILES_ON_DISK {
            let p: Profile = serde_json::from_str(raw).unwrap();
            assert_eq!(serde_json::to_string_pretty(&p).unwrap(), *raw);
        }
    }

    #[test]
    fn debug_of_a_profile_carries_no_secret() {
        for (raw, secrets) in PROFILES_ON_DISK {
            let p: Profile = serde_json::from_str(raw).unwrap();
            let debug = format!("{p:?}");
            let pretty = format!("{p:#?}");
            for secret in *secrets {
                assert!(!debug.contains(secret), "{secret} in {debug}");
                assert!(!pretty.contains(secret), "{secret} in {pretty}");
            }
        }
    }

    #[test]
    fn a_written_profile_reads_back_with_its_secrets() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        for (i, (raw, secrets)) in PROFILES_ON_DISK.iter().enumerate() {
            let p: Profile = serde_json::from_str(raw).unwrap();
            let name = format!("p{i}");
            write_profile(paths, &name, &p).unwrap();
            let on_disk = fs::read_to_string(paths.profile_path(&name)).unwrap();
            assert_eq!(on_disk, *raw);
            for secret in *secrets {
                assert!(on_disk.contains(secret), "{secret} lost on write");
            }
        }
    }

    #[test]
    fn test_profile_crud() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: 1,
            endpoint: "https://account.airdress.co".into(),
            auth: None,
            active_airdress: None,
        };
        write_profile(paths, "test", &profile).unwrap();
        let read_back = read_profile(paths, "test").unwrap();
        assert_eq!(read_back.endpoint, "https://account.airdress.co");
        assert_eq!(read_back.schema_version, 1);
    }

    #[test]
    fn missing_profile_error_names_the_fix() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let err = read_profile(paths, "qa").unwrap_err().to_string();
        assert!(err.contains("profile 'qa' does not exist"), "{err}");
        assert!(err.contains("airdress auth login --profile qa"), "{err}");
        assert!(!err.contains("os error"), "{err}");
    }

    #[test]
    fn test_active_profile() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        assert_eq!(read_active_profile(paths).unwrap(), None);
        ensure_dirs(paths).unwrap();
        write_active_profile(paths, "staging").unwrap();
        assert_eq!(read_active_profile(paths).unwrap(), Some("staging".into()));
    }

    #[test]
    fn test_list_profiles() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: 1,
            endpoint: "https://account.airdress.co".into(),
            auth: None,
            active_airdress: None,
        };
        write_profile(paths, "alpha", &profile).unwrap();
        write_profile(paths, "beta", &profile).unwrap();
        write_active_profile(paths, "beta").unwrap();

        let list = list_profiles(paths).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], ("alpha".into(), false));
        assert_eq!(list[1], ("beta".into(), true));
    }

    #[test]
    fn test_device_flow_roundtrip() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: 1,
            endpoint: "https://account.airdress.co".into(),
            auth: Some(AuthConfig::DeviceFlow {
                access_token: "at_123".into(),
                refresh_token: "rt_456".into(),
                expires_at: "2026-12-31T00:00:00Z".into(),
                id_token_claims: IdTokenClaims {
                    sub: "user-1".into(),
                    email: "test@example.com".into(),
                },
                id_token: None,
            }),
            active_airdress: None,
        };
        write_profile(paths, "df", &profile).unwrap();
        let read_back = read_profile(paths, "df").unwrap();
        match read_back.auth.unwrap() {
            AuthConfig::DeviceFlow {
                access_token,
                id_token_claims,
                ..
            } => {
                assert_eq!(access_token.expose(), "at_123");
                assert_eq!(id_token_claims.email, "test@example.com");
            }
            _ => panic!("wrong auth type"),
        }
    }

    #[test]
    fn test_client_credentials_roundtrip() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: 1,
            endpoint: "https://account.airdress.co".into(),
            auth: Some(AuthConfig::ClientCredentials {
                client_id: "cid".into(),
                client_secret: "csec".into(),
            }),
            active_airdress: None,
        };
        write_profile(paths, "cc", &profile).unwrap();
        let read_back = read_profile(paths, "cc").unwrap();
        match read_back.auth.unwrap() {
            AuthConfig::ClientCredentials {
                client_id,
                client_secret,
            } => {
                assert_eq!(client_id, "cid");
                assert_eq!(client_secret.expose(), "csec");
            }
            _ => panic!("wrong auth type"),
        }
    }

    #[test]
    fn test_jwt_profile_roundtrip() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        let profile = Profile {
            schema_version: 1,
            endpoint: "https://account.airdress.co".into(),
            auth: Some(AuthConfig::JwtProfile {
                key_file: "/path/to/key.json".into(),
            }),
            active_airdress: None,
        };
        write_profile(paths, "jwt", &profile).unwrap();
        let read_back = read_profile(paths, "jwt").unwrap();
        match read_back.auth.unwrap() {
            AuthConfig::JwtProfile { key_file } => {
                assert_eq!(key_file, "/path/to/key.json");
            }
            _ => panic!("wrong auth type"),
        }
    }

    #[test]
    fn device_flow_profile_without_id_token_still_parses() {
        let json = r#"{"method":"device_flow","access_token":"a","refresh_token":"r",
            "expires_at":"2026-12-31T00:00:00Z","id_token_claims":{"sub":"s","email":"e"}}"#;
        match serde_json::from_str::<AuthConfig>(json).unwrap() {
            AuthConfig::DeviceFlow { id_token, .. } => assert!(id_token.is_none()),
            _ => panic!("wrong auth type"),
        }
    }

    #[test]
    fn test_redact_device_flow() {
        let auth = AuthConfig::DeviceFlow {
            access_token: "secret_token".into(),
            refresh_token: "secret_refresh".into(),
            expires_at: "2026-12-31T00:00:00Z".into(),
            id_token_claims: IdTokenClaims {
                sub: "user-1".into(),
                email: "test@example.com".into(),
            },
            id_token: Some("secret_id_token".into()),
        };
        let redacted = redact_auth(&auth);
        assert_eq!(redacted["id_token"], "****");
        assert!(!redacted.to_string().contains("secret_id_token"));
        assert_eq!(redacted["access_token"], "****");
        assert_eq!(redacted["refresh_token"], "****");
        assert_eq!(redacted["id_token_claims"]["email"], "test@example.com");
    }

    #[test]
    fn test_redact_client_credentials() {
        let auth = AuthConfig::ClientCredentials {
            client_id: "my-id".into(),
            client_secret: "super-secret".into(),
        };
        let redacted = redact_auth(&auth);
        assert_eq!(redacted["client_id"], "my-id");
        assert_eq!(redacted["client_secret"], "****");
    }

    /// SPEC-043 — v1 profiles on disk (no `active_airdress` field)
    /// deserialize cleanly into the v2 struct with `active_airdress =
    /// None`. Hand-craft the JSON to mirror what's on disk for a user
    /// who installed the CLI before this change.
    #[test]
    fn v1_profile_reads_with_active_airdress_none() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        ensure_dirs(paths).unwrap();
        let v1_json = r#"{
                "schema_version": 1,
                "endpoint": "https://account.airdress.co"
            }"#;
        let path = paths.profile_path("legacy");
        fs::write(&path, v1_json).unwrap();
        let p = read_profile(paths, "legacy").unwrap();
        assert_eq!(p.schema_version, 1);
        assert_eq!(p.active_airdress, None);
        assert!(p.auth.is_none());
    }

    /// SPEC-043 — set/clear cycle on a v1 file silently upgrades to
    /// v2 on the first mutating write, preserving everything else.
    #[test]
    fn v1_set_clear_active_airdress_upgrades_to_v2() {
        let (_home, paths) = temp_paths();
        let paths = &paths;
        ensure_dirs(paths).unwrap();
        let v1_json = r#"{
                "schema_version": 1,
                "endpoint": "https://account.airdress.co"
            }"#;
        let path = paths.profile_path("legacy");
        fs::write(&path, v1_json).unwrap();

        set_active_airdress(paths, "legacy", "alice").unwrap();
        let p = read_profile(paths, "legacy").unwrap();
        assert_eq!(p.schema_version, SCHEMA_VERSION);
        assert_eq!(p.active_airdress.as_deref(), Some("alice"));
        assert_eq!(p.endpoint, "https://account.airdress.co");

        clear_active_airdress(paths, "legacy").unwrap();
        let p2 = read_profile(paths, "legacy").unwrap();
        assert_eq!(p2.active_airdress, None);

        // Idempotent: a second clear is a no-op.
        clear_active_airdress(paths, "legacy").unwrap();
    }
}
