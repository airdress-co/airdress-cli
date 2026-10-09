//! SPEC-054 task 1.8 — root-key persistence for `airdress device bootstrap`.
//!
//! The airdress root keypair is the airdress's long-lived identity: the
//! operator pins its public half on first enrollment (SPEC-054 FR-9) and
//! rejects any later enrollment presenting a different root. Before this
//! module, `device bootstrap` generated a fresh root per run and dropped
//! it — fine while the operator forgot roots too, fatal once it pins them.
//!
//! Storage preference (FR-14):
//!
//! 1. The OS keyring, via the `keyring` crate — service `airdress`,
//!    account `root-key:<airdress>`, value the raw 32-byte Ed25519 seed.
//! 2. Fallback when no keyring is available:
//!    `$XDG_DATA_HOME/airdress/root-keys/<airdress>.key`, mode `0600`
//!    under `0700` parents. The caller MUST tell the user on stdout when
//!    this path is taken — a user who does not know a long-lived private
//!    key landed on disk cannot protect it (FR-14's "loud file"). The
//!    path is printable; the key never is.
//!
//! Deliberately NOT the CLI's hub-auth profile store: that holds a
//! human's ZITADEL session, this is a device-lineage secret with a
//! different lifecycle (see the module comment in `bootstrap.rs`).

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

const KEYRING_SERVICE: &str = "airdress";
const SEED_LEN: usize = 32;

/// Where a freshly generated root key ended up after [`persist`].
#[derive(Debug)]
pub enum Persisted {
    /// Stored in the OS keyring — nothing landed on disk.
    Keyring,
    /// Keyring unavailable; the seed was written to this file (mode 0600).
    File(PathBuf),
}

/// Load the persisted root key for `airdress`, if one exists.
///
/// Checks the OS keyring first, then the file fallback — a key written
/// by an earlier run on a keyring-less host must still be found after a
/// keyring daemon appears. Returns `Ok(None)` when neither holds one.
pub fn load(paths: &crate::paths::Paths, airdress: &str) -> anyhow::Result<Option<SigningKey>> {
    validate_airdress_for_path(airdress)?;

    // On keyring error: NoEntry means the keyring works but holds
    // nothing; anything else means no usable keyring. Either way the
    // file fallback is still worth checking — a key written by an
    // earlier keyring-less run must not be shadowed into oblivion.
    if let Ok(secret) = keyring_entry(airdress).and_then(|e| e.get_secret()) {
        return Ok(Some(key_from_seed(&secret, "OS keyring")?));
    }

    load_from_file(paths.data_home(), airdress)
}

/// Persist a freshly generated root key for `airdress`.
///
/// Call this only after the operator accepted the enrollment (201) —
/// storing a root the server rejected would wedge every later run on a
/// key the operator never pinned.
pub fn persist(
    paths: &crate::paths::Paths,
    airdress: &str,
    key: &SigningKey,
) -> anyhow::Result<Persisted> {
    validate_airdress_for_path(airdress)?;

    let seed = key.to_bytes();
    if let Ok(entry) = keyring_entry(airdress) {
        if entry.set_secret(&seed).is_ok() {
            return Ok(Persisted::Keyring);
        }
    }

    let path = persist_to_file(paths.data_home(), airdress, &seed)?;
    Ok(Persisted::File(path))
}

fn keyring_entry(airdress: &str) -> keyring::Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("root-key:{airdress}"))
}

fn key_from_seed(bytes: &[u8], source: &str) -> anyhow::Result<SigningKey> {
    let seed: [u8; SEED_LEN] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "root key in {source} is {} bytes, expected {SEED_LEN} — refusing to use it",
            bytes.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The airdress becomes a filename component and a keyring account name;
/// refuse anything that could escape the root-keys directory.
fn validate_airdress_for_path(airdress: &str) -> anyhow::Result<()> {
    if airdress.is_empty()
        || airdress.starts_with('.')
        || airdress.chars().any(|c| c == '/' || c == '\\' || c == '\0')
    {
        anyhow::bail!("airdress name {airdress:?} cannot be used as a key identifier");
    }
    Ok(())
}

fn key_file_path(data_home: &Path, airdress: &str) -> PathBuf {
    data_home
        .join("airdress")
        .join("root-keys")
        .join(format!("{airdress}.key"))
}

fn load_from_file(data_home: &Path, airdress: &str) -> anyhow::Result<Option<SigningKey>> {
    let path = key_file_path(data_home, airdress);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("read root key {}: {e}", path.display())),
    };
    Ok(Some(key_from_seed(&bytes, &path.display().to_string())?))
}

fn persist_to_file(data_home: &Path, airdress: &str, seed: &[u8]) -> anyhow::Result<PathBuf> {
    let path = key_file_path(data_home, airdress);
    let dir = path.parent().expect("key path always has a parent");
    create_private_dir(dir)?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    let mut f = opts
        .open(&path)
        .map_err(|e| anyhow::anyhow!("write root key {}: {e}", path.display()))?;
    f.write_all(seed)
        .and_then(|()| f.sync_all())
        .map_err(|e| anyhow::anyhow!("write root key {}: {e}", path.display()))?;
    Ok(path)
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| anyhow::anyhow!("create key directory {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore as _;

    fn fresh_key() -> SigningKey {
        let mut seed = [0u8; SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// The file fallback round-trips: persist then load yields the same
    /// keypair. Exercises the file store directly under a temp data home
    /// so the test never touches the real OS keyring or the user's
    /// `$XDG_DATA_HOME`.
    #[test]
    fn file_fallback_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key = fresh_key();

        assert!(load_from_file(tmp.path(), "alice.test")
            .expect("load on empty store")
            .is_none());

        let path = persist_to_file(tmp.path(), "alice.test", &key.to_bytes()).expect("persist key");
        assert_eq!(
            path,
            tmp.path().join("airdress/root-keys/alice.test.key"),
            "key file lands at the documented XDG path"
        );

        let loaded = load_from_file(tmp.path(), "alice.test")
            .expect("load persisted key")
            .expect("key present after persist");
        assert_eq!(
            loaded.verifying_key(),
            key.verifying_key(),
            "the same root public key comes back"
        );

        // A different airdress is a different (absent) key.
        assert!(load_from_file(tmp.path(), "bob.test")
            .expect("load other airdress")
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn file_fallback_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let key = fresh_key();
        let path = persist_to_file(tmp.path(), "carol.test", &key.to_bytes()).expect("persist key");

        let file_mode = std::fs::metadata(&path)
            .expect("stat key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "key file must be 0600");

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "root-keys directory must be 0700");
    }

    #[test]
    fn corrupt_key_file_is_an_error_not_a_silent_regenerate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("airdress/root-keys");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("dave.test.key"), b"short").expect("write corrupt key");

        let err = load_from_file(tmp.path(), "dave.test").expect_err("corrupt key must error");
        assert!(err.to_string().contains("expected 32"), "{err}");
    }

    #[test]
    fn path_hostile_airdress_names_are_refused() {
        for bad in ["", "../etc", "a/b", ".hidden", "a\\b"] {
            assert!(
                validate_airdress_for_path(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        validate_airdress_for_path("alice.test").expect("normal name is fine");
    }
}
