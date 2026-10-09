//! SPEC-061 FR-15/FR-16 — the stable per-device identifier the v2
//! delegation carries.
//!
//! Under SPEC-061 an MLS member identity is `airdress ‖ 0x1F ‖ device_id`,
//! not the bare airdress, so two devices of one airdress become two leaves
//! of one group instead of colliding in tree validation. `valid_successor`
//! then requires the *same* `device_id` across a re-delegation — which is
//! the whole reason this value must be durable. Mint a fresh one on the
//! second run and the operator sees a different member, not the same
//! member with a new session key.
//!
//! It is therefore **read-or-create from durable storage**, and it is
//! explicitly NOT derived from the session public key: that key is
//! regenerated on every `device bootstrap` run (`bootstrap.rs`), so
//! deriving from it would make every re-delegation look like a new device
//! — exactly the failure `valid_successor` exists to catch.
//!
//! **Storage differs from [`super::root_key`] in two deliberate ways**,
//! and both differences are the point rather than an inconsistency:
//!
//! 1. **No OS keyring.** A `device_id` is not a secret — it travels in
//!    the clear inside the signed delegation and the operator stores it
//!    on the enrollment row. Putting it in the keyring would buy nothing
//!    and cost correctness: `root_key::load` tolerates a keyring that
//!    works on one run and not the next because it falls back to the
//!    file, but a *miss* on both stores here means minting a new
//!    identity, silently, and that is the one outcome this module exists
//!    to prevent. One store, one answer.
//! 2. **Persisted at creation, not after a 201.** The root key is stored
//!    only once the operator accepts it, because a rejected root would
//!    wedge every later run on a key the operator never pinned. A
//!    `device_id` has no such server-side pin to lose: if the enrollment
//!    fails, the right thing on retry is the *same* identifier, not a
//!    fresh one.
//!
//! The file lives at `$XDG_DATA_HOME/airdress/device-ids/<airdress>.id`,
//! mode `0600` under `0700` parents — matching `root_key`'s layout so an
//! operator finds both in one place, not because the contents are secret.

use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Load the `device_id` for `airdress`, minting and persisting one on
/// first use.
///
/// The returned value is stable for the life of the file: the caller
/// must not cache it across airdresses, and must never substitute a
/// freshly generated one when this errors.
pub fn load_or_create(paths: &crate::paths::Paths, airdress: &str) -> anyhow::Result<String> {
    load_or_create_in(paths.data_home(), airdress)
}

fn load_or_create_in(data_home: &Path, airdress: &str) -> anyhow::Result<String> {
    validate_airdress_for_path(airdress)?;
    let path = id_file_path(data_home, airdress);

    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let existing = raw.trim();
            // A corrupt file is an error, never a silent regenerate: the
            // stored identity is what makes a re-delegation the same
            // member, so quietly replacing it is the failure this module
            // is here to prevent, arrived at from the other side.
            let parsed = Uuid::parse_str(existing).map_err(|e| {
                anyhow::anyhow!(
                    "device id in {} is not a UUID ({e}) — refusing to use it. \
                     Delete the file only if you accept that this device will \
                     enroll as a NEW member of {airdress:?}.",
                    path.display()
                )
            })?;
            Ok(parsed.hyphenated().to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let fresh = Uuid::new_v4().hyphenated().to_string();
            persist_to_file(data_home, airdress, &fresh)?;
            Ok(fresh)
        }
        Err(e) => Err(anyhow::anyhow!("read device id {}: {e}", path.display())),
    }
}

fn persist_to_file(data_home: &Path, airdress: &str, device_id: &str) -> anyhow::Result<PathBuf> {
    let path = id_file_path(data_home, airdress);
    let dir = path.parent().expect("id path always has a parent");
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
        .map_err(|e| anyhow::anyhow!("write device id {}: {e}", path.display()))?;
    f.write_all(device_id.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| anyhow::anyhow!("write device id {}: {e}", path.display()))?;
    Ok(path)
}

fn id_file_path(data_home: &Path, airdress: &str) -> PathBuf {
    data_home
        .join("airdress")
        .join("device-ids")
        .join(format!("{airdress}.id"))
}

/// The airdress becomes a filename component; refuse anything that could
/// escape the `device-ids` directory. Same rule as
/// [`super::root_key`]'s, for the same reason.
fn validate_airdress_for_path(airdress: &str) -> anyhow::Result<()> {
    if airdress.is_empty()
        || airdress.starts_with('.')
        || airdress.chars().any(|c| c == '/' || c == '\\' || c == '\0')
    {
        anyhow::bail!("airdress name {airdress:?} cannot be used as a device id key");
    }
    Ok(())
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
        .map_err(|e| anyhow::anyhow!("create device id directory {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for: a second call returns
    /// the SAME identifier. If this ever regresses, every re-delegation
    /// enrolls as a new member and `valid_successor` rejects it.
    #[test]
    fn device_id_is_stable_across_calls() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let first = load_or_create_in(tmp.path(), "alice.test").expect("mint");
        let second = load_or_create_in(tmp.path(), "alice.test").expect("reload");
        assert_eq!(first, second, "the device id must survive a reload");

        Uuid::parse_str(&first).expect("a v4 UUID");
        assert_eq!(
            tmp.path().join("airdress/device-ids/alice.test.id"),
            id_file_path(tmp.path(), "alice.test"),
            "the id file lands at the documented XDG path"
        );
    }

    /// Scoped per airdress: two accounts on one machine must not hand a
    /// correspondent of both an identifier that links them.
    #[test]
    fn device_id_is_scoped_per_airdress() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let alice = load_or_create_in(tmp.path(), "alice.test").expect("mint alice");
        let bob = load_or_create_in(tmp.path(), "bob.test").expect("mint bob");
        assert_ne!(alice, bob, "distinct airdresses get distinct device ids");
    }

    #[test]
    fn corrupt_id_file_is_an_error_not_a_silent_regenerate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("airdress/device-ids");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("dave.test.id"), b"not-a-uuid").expect("write corrupt id");

        let err = load_or_create_in(tmp.path(), "dave.test").expect_err("corrupt id must error");
        assert!(err.to_string().contains("not a UUID"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn id_file_layout_matches_the_root_key_store() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        load_or_create_in(tmp.path(), "carol.test").expect("mint");
        let path = id_file_path(tmp.path(), "carol.test");

        let file_mode = std::fs::metadata(&path)
            .expect("stat id")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "id file must be 0600");

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "device-ids directory must be 0700");
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
