//! A function's source tree on disk, and the publish body built from it.
//!
//! Three things happen here and nothing else:
//!
//! 1. **Read** every regular file under the tree's root by its
//!    `/`-separated relative path — the same walk the operator's own
//!    `airdress-operator functions pack-source` does. A symlink is refused
//!    rather than followed, so what is signed is what is on disk.
//! 2. **Sign** the canonical file-set digest the operator verifies
//!    (`crates/airdress-operator/src/functions/source/digest.rs` and
//!    `signing.rs`, SPEC-112 design §5.1):
//!
//!    ```text
//!    D := SHA-256 over, for each file in byte-wise path order,
//!           u32_be(len(path)) ‖ path ‖ u64_be(len(contents)) ‖ contents
//!    canonical := SHA-256( "airdress.function.source.v1" ‖ 0x1F ‖ D )
//!    signature := Ed25519(seed, canonical)      — 128 hex characters
//!    ```
//!
//! 3. **Encode** the JSON publish form of `POST /v1/functions/sources`.
//!
//! The layout rules (only `function.json` and `src/…`, sizes, case
//! collisions) are deliberately NOT checked here: the operator checks them
//! and answers with a located refusal. A second copy of the rules in the
//! client is a second copy that drifts.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

/// Domain separation, byte for byte what the operator prepends.
pub const DIGEST_DOMAIN: &[u8] = b"airdress.function.source.v1";

/// A file set, ordered byte-wise by path (the digest's order: `BTreeMap`
/// over `String` compares the UTF-8 bytes).
pub type Files = BTreeMap<String, Vec<u8>>;

/// Read every regular file under `root`.
pub fn read_tree(root: &Path) -> Result<Files> {
    fn walk(root: &Path, dir: &Path, out: &mut Files) -> Result<()> {
        let mut entries = std::fs::read_dir(dir)
            .with_context(|| format!("read {}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry.file_type()?;
            let rel = path
                .strip_prefix(root)?
                .to_str()
                .with_context(|| format!("{} is not UTF-8", path.display()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if kind.is_symlink() {
                bail!("{rel} is a symlink; a source tree holds regular files only");
            }
            if kind.is_dir() {
                walk(root, &path, out)?;
            } else {
                let bytes = std::fs::read(&path).with_context(|| format!("read {rel}"))?;
                out.insert(rel, bytes);
            }
        }
        Ok(())
    }
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let mut files = Files::new();
    walk(root, root, &mut files)?;
    if files.is_empty() {
        bail!("{} holds no files", root.display());
    }
    Ok(files)
}

/// The canonical digest of a file set, 32 bytes.
pub fn canonical_digest(files: &Files) -> [u8; 32] {
    let mut inner = Sha256::new();
    for (path, contents) in files {
        let p = path.as_bytes();
        inner.update(u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
        inner.update(p);
        inner.update((contents.len() as u64).to_be_bytes());
        inner.update(contents);
    }
    let mut outer = Sha256::new();
    outer.update(DIGEST_DOMAIN);
    outer.update([0x1F]);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An Ed25519 signing seed: 64 hex characters, as
/// `airdress-operator functions keygen` prints after `seed=`. A leading
/// `seed=` is accepted so the keygen line can be stored as it was printed.
pub fn parse_seed(raw: &str) -> Result<[u8; 32]> {
    let s = raw.trim();
    let s = s.strip_prefix("seed=").unwrap_or(s);
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("a signing key is 64 hex characters (a 32-byte Ed25519 seed)");
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(out)
}

/// A detached signature over the tree, and the public key that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeSignature {
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

/// Sign `files` with `seed`.
pub fn sign(files: &Files, seed: &[u8; 32]) -> TreeSignature {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    TreeSignature {
        signature: key.sign(&canonical_digest(files)).to_bytes(),
        public_key: key.verifying_key().to_bytes(),
    }
}

/// Who the operator should verify the signature against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// Nobody: accepted only where the operator allows unsigned source.
    Unsigned,
    /// The literal key that signed (`signer`).
    Key(TreeSignature),
    /// An approved machine's registered source-signing key
    /// (`signerRef.machine`). The signature still travels.
    Machine {
        machine: String,
        signature: TreeSignature,
    },
}

/// The JSON form of `POST /v1/functions/sources`.
pub fn publish_body(
    name: &str,
    based_on: Option<&str>,
    signer: &Signer,
    files: &Files,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut body = serde_json::json!({
        "name": name,
        "files": files
            .iter()
            .map(|(path, bytes)| serde_json::json!({
                "path": path,
                "contentBase64": b64.encode(bytes),
            }))
            .collect::<Vec<_>>(),
    });
    if let Some(base) = based_on {
        body["basedOn"] = base.into();
    }
    match signer {
        Signer::Unsigned => {}
        Signer::Key(sig) => {
            body["signature"] = hex(&sig.signature).into();
            body["signer"] = hex(&sig.public_key).into();
        }
        Signer::Machine { machine, signature } => {
            body["signature"] = hex(&signature.signature).into();
            body["signerRef"] = serde_json::json!({ "machine": machine });
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_files() -> Files {
        let mut f = Files::new();
        f.insert(
            "function.json".into(),
            br#"{"entry":"src/main.ts"}"#.to_vec(),
        );
        f.insert(
            "src/main.ts".into(),
            b"export default () => new Response('a');".to_vec(),
        );
        f
    }

    /// Digests copied from the operator's own fixture,
    /// `crates/airdress-operator/tests/fixtures/source-digest-vectors.json`
    /// (branch `feat/code-first-functions`, commit 79f1547), which its
    /// `digest::tests::agrees_with_every_vector` holds the operator to.
    #[test]
    fn digest_agrees_with_the_operator_fixture() {
        assert_eq!(
            hex(&canonical_digest(&Files::new())),
            "456498292e89321bb29cc4b90e51710fe78d504ea418d3968e6ddd7785b2f2b8"
        );
        assert_eq!(
            hex(&canonical_digest(&two_files())),
            "d8dfeaa493ac09e5a0db5c347830428fb3887a2a2401fd5d0b31a49a718af8af"
        );
        let mut a = Files::new();
        a.insert("src/ab".into(), b"c".to_vec());
        assert_eq!(
            hex(&canonical_digest(&a)),
            "8b047fac60d415f690784ec65a00d7553ee4993ab753c19e776b7ff6195e11b3"
        );
        let mut b = Files::new();
        b.insert("src/a".into(), b"bc".to_vec());
        assert_eq!(
            hex(&canonical_digest(&b)),
            "cec3ed2f5ad4653f59e9a516dc66e9d80c9bdf42066272ec202954c802421945"
        );
        let mut utf8 = Files::new();
        utf8.insert(
            "function.json".into(),
            br#"{"entry":"src/main.ts"}"#.to_vec(),
        );
        utf8.insert(
            "src/grüße/ñ.ts".into(),
            "export const s = 'ß';".as_bytes().to_vec(),
        );
        assert_eq!(
            hex(&canonical_digest(&utf8)),
            "692d74a82a7951666ab0e563128cb9cf6ee47f591c7d0d564dc3c032c0ab5ea4"
        );
    }

    /// The signature bytes for the fixture's "two files" tree under seed
    /// `[1; 32]` — the seed the operator's `signing::tests::key(1)` uses.
    /// Computed independently of this crate with Python's `cryptography`
    /// (Ed25519 over the canonical digest, domain and layout as in the
    /// operator's `digest.rs`); the digest step reproduces the operator
    /// fixture above, and Ed25519 is deterministic, so the operator's
    /// `signing::sign` produces these same 64 bytes.
    #[test]
    fn signature_bytes_match_the_operator_scheme() {
        let sig = sign(&two_files(), &[1u8; 32]);
        assert_eq!(
            hex(&sig.public_key),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(
            hex(&sig.signature),
            "4c8443aeb87b0af225264d7e9dff2deaf36845bdaec36d0b3dee1c7fb3c514dd\
             09498b79e755d7a14db27d4db62c49681bbc06e3f799fe3fda5978ccedbca00f"
        );
    }

    #[test]
    fn seeds_parse_from_hex_or_the_keygen_line() {
        let hex_seed = "01".repeat(32);
        assert_eq!(parse_seed(&hex_seed).unwrap(), [1u8; 32]);
        assert_eq!(
            parse_seed(&format!("seed={hex_seed}\n")).unwrap(),
            [1u8; 32]
        );
        assert!(parse_seed("abc").is_err());
        assert!(parse_seed(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn the_body_carries_exactly_what_the_api_accepts() {
        let sig = sign(&two_files(), &[1u8; 32]);
        let body = publish_body(
            "hello",
            Some("sha256:ab"),
            &Signer::Key(sig.clone()),
            &two_files(),
        );
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["basedOn", "files", "name", "signature", "signer"]);
        assert_eq!(body["files"][0]["path"], "function.json");
        assert_eq!(
            body["files"][0]["contentBase64"],
            "eyJlbnRyeSI6InNyYy9tYWluLnRzIn0="
        );
        assert_eq!(body["signature"].as_str().unwrap().len(), 128);

        let machine = publish_body(
            "hello",
            None,
            &Signer::Machine {
                machine: "ci".into(),
                signature: sig,
            },
            &two_files(),
        );
        assert_eq!(machine["signerRef"]["machine"], "ci");
        assert!(machine.get("signer").is_none());
        assert!(machine.get("basedOn").is_none());

        let unsigned = publish_body("hello", None, &Signer::Unsigned, &two_files());
        assert!(unsigned.get("signature").is_none());
    }

    #[test]
    fn the_tree_is_read_by_relative_slash_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src/lib")).unwrap();
        std::fs::write(dir.path().join("function.json"), "{}").unwrap();
        std::fs::write(dir.path().join("src/lib/a.ts"), "a").unwrap();
        let files = read_tree(dir.path()).unwrap();
        let paths: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["function.json", "src/lib/a.ts"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("function.json"), "{}").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("x")).unwrap();
        let err = read_tree(dir.path()).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
    }
}
