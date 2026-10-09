//! `airdress plugins verify <name>@<version>` — check a published release
//! the way an operator does before installing it (SPEC-119 FR-100e, R-8).
//!
//! Two kinds of signer, never interchangeable (owner ruling R-8):
//!
//! - **the registry** signs `index.json` — which versions exist, which are
//!   yanked, each author's live and revoked keys, and until when that holds —
//!   and each release's `provenance.json`, what its CI built from which
//!   commit in which builder images;
//! - **the author** signs each release's `artifacts.yaml`, which pins the
//!   manifest and every artifact by SHA-256.
//!
//! So `verify` checks, in order: the index signature (against the registry
//! keys the caller pins — never keys from the registry) and that it has not
//! expired; that the version is listed and not yanked; that `artifacts.yaml`
//! is the document the signed index names; the author's signature (against
//! `--author-key` pins, or the author keys the signed index lists); the
//! provenance, signed by the registry and agreeing with the release; and the
//! manifest's and every artifact's digest.
//!
//! One signature scheme for all three documents, shared with the operator
//! (`bundle_signature.rs`) and `airdress-plugins/ci/signing.py`:
//! Ed25519 over `label ‖ 0x1F ‖ SHA-256(document)`, key id
//! `hex(SHA-256(pubkey)[..8])`; the labels are `airdress.plugin.bundle.v1`,
//! `airdress.plugin.index.v1` and `airdress.plugin.provenance.v1`.
//! `testdata/*_signature_v1.json` are the shared vectors.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The label a release is signed under, by its author.
const BUNDLE: &[u8] = b"airdress.plugin.bundle.v1";
/// The label `index.json` is signed under, by the registry.
const INDEX: &[u8] = b"airdress.plugin.index.v1";
/// The label `provenance.json` is signed under, by the registry.
const PROVENANCE: &[u8] = b"airdress.plugin.provenance.v1";

/// A pinned key.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub id: String,
    key: VerifyingKey,
}

impl TrustedKey {
    /// `ed25519:<64 hex digits>`.
    pub fn parse(s: &str) -> Result<Self> {
        let hex = s
            .trim()
            .strip_prefix("ed25519:")
            .with_context(|| format!("`{s}` is not ed25519:<64 hex digits>"))?;
        let bytes = decode_hex(hex).with_context(|| format!("`{s}` is not 64 hex digits"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("`{s}` is not 64 hex digits"))?;
        let key = VerifyingKey::from_bytes(&arr)
            .with_context(|| format!("`{s}` is not an Ed25519 key"))?;
        if key.is_weak() {
            bail!("`{s}` is a weak key");
        }
        Ok(Self {
            id: hex_string(&Sha256::digest(arr)[..8]),
            key,
        })
    }
}

/// The registry keys: `--index-key` (also spelled `--trusted-key`, its name
/// before author signing), else `AIRDRESS_PLUGIN_INDEX_KEYS`, else
/// `AIRDRESS_PLUGIN_TRUSTED_KEYS` (comma-separated). None pinned is an
/// error: nothing verifies against nothing.
pub fn index_keys(flags: &[String]) -> Result<Vec<TrustedKey>> {
    let from_env;
    let lines: Vec<&str> = if flags.is_empty() {
        from_env = std::env::var("AIRDRESS_PLUGIN_INDEX_KEYS")
            .or_else(|_| std::env::var("AIRDRESS_PLUGIN_TRUSTED_KEYS"))
            .unwrap_or_default();
        from_env
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        flags.iter().map(String::as_str).collect()
    };
    if lines.is_empty() {
        bail!(
            "no registry key pinned — pass --index-key ed25519:<hex> (the line in \
             airdress-plugins/keys/index.pub) or set AIRDRESS_PLUGIN_INDEX_KEYS"
        );
    }
    lines.into_iter().map(TrustedKey::parse).collect()
}

/// `--author-key` pins; empty means "the author keys the signed index lists".
pub fn author_keys(flags: &[String]) -> Result<Vec<TrustedKey>> {
    flags.iter().map(|k| TrustedKey::parse(k)).collect()
}

fn message(label: &[u8], document: &[u8]) -> Vec<u8> {
    let mut m = label.to_vec();
    m.push(0x1F);
    m.extend_from_slice(&Sha256::digest(document));
    m
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureDoc {
    alg: String,
    key_id: String,
    signature: String,
}

/// The key id that verifies `sig` over `body` under `label`. `what` names
/// the document in errors (`bundle`, `index`, `provenance`).
fn verify_labelled(
    label: &[u8],
    what: &str,
    trusted: &[TrustedKey],
    body: &[u8],
    sig: Option<&[u8]>,
) -> Result<String> {
    let Some(sig) = sig else {
        bail!("{what}_unsigned: not signed");
    };
    let doc: SignatureDoc = serde_json::from_slice(sig)
        .with_context(|| format!("{what}_signature_invalid: the signature file does not parse"))?;
    if doc.alg != "ed25519" {
        bail!("{what}_signature_invalid: alg `{}`", doc.alg);
    }
    let Some(key) = trusted.iter().find(|k| k.id == doc.key_id) else {
        bail!(
            "{what}_signature_invalid: signed by key {}, which is not pinned",
            doc.key_id
        );
    };
    let raw = base64::engine::general_purpose::STANDARD
        .decode(doc.signature.trim())
        .with_context(|| format!("{what}_signature_invalid: signature is not base64"))?;
    let arr: [u8; 64] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what}_signature_invalid: signature is not 64 bytes"))?;
    key.key
        .verify_strict(&message(label, body), &Signature::from_bytes(&arr))
        .map_err(|_| {
            anyhow::anyhow!(
                "{what}_signature_invalid: does not verify under key {}",
                key.id
            )
        })?;
    Ok(key.id.clone())
}

/// The key id that verifies a release signature `sig` over `body`.
pub fn verify_signature(trusted: &[TrustedKey], body: &[u8], sig: Option<&[u8]>) -> Result<String> {
    verify_labelled(BUNDLE, "bundle", trusted, body, sig)
}

fn signed_key_id(sig: Option<&[u8]>) -> Option<String> {
    serde_json::from_slice::<SignatureDoc>(sig?)
        .ok()
        .map(|d| d.key_id)
}

#[derive(Debug, Deserialize)]
struct Index {
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    authors: BTreeMap<String, Author>,
    #[serde(default)]
    bundles: BTreeMap<String, Bundle>,
}

#[derive(Debug, Deserialize, Default)]
struct Author {
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    revoked: Vec<Revoked>,
}

#[derive(Debug, Deserialize)]
struct Revoked {
    key: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
struct Bundle {
    #[serde(default)]
    author: Option<String>,
    latest: Option<String>,
    #[serde(default)]
    versions: BTreeMap<String, Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    manifest: String,
    artifacts: String,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    artifacts_sha256: Option<String>,
    #[serde(default)]
    provenance: Option<String>,
    #[serde(default)]
    provenance_sha256: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    yank_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactsDoc {
    #[serde(default)]
    metadata: Option<Meta>,
    #[serde(default)]
    author: Option<AuthorRef>,
    #[serde(default)]
    manifest: Option<Pinned>,
    #[serde(default)]
    source: Option<Source>,
    #[serde(default)]
    builder: Option<Builder>,
    #[serde(default)]
    artifacts: BTreeMap<String, Pinned>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorRef {
    id: Option<String>,
    key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Pinned {
    url: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Source {
    commit: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
struct Builder {
    #[serde(default)]
    images: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    kind: Option<String>,
    release: Option<Meta>,
    source: Option<Source>,
    #[serde(default)]
    builder: Option<Builder>,
    #[serde(default)]
    subject: BTreeMap<String, String>,
}

/// What `verify` found.
#[derive(Debug, Default, serde::Serialize)]
pub struct Report {
    pub name: String,
    pub version: String,
    /// The registry key that signed the index.
    pub index_signed_by: Option<String>,
    /// The author the index names.
    pub author: Option<String>,
    /// The author key that signed the release.
    pub signed_by: Option<String>,
    /// Where the author keys came from: `pinned` or `index`.
    pub author_keys_from: Option<&'static str>,
    /// The attested source commit.
    pub built_from: Option<String>,
    /// The attested builder images.
    pub built_in: Vec<String>,
    pub checked: Vec<String>,
    pub problems: Vec<String>,
}

fn absolute(registry: &str, url: &str) -> String {
    if url.starts_with("https://") || url.starts_with("http://") {
        url.to_owned()
    } else {
        format!(
            "{}/{}",
            registry.trim_end_matches('/'),
            url.trim_start_matches('/')
        )
    }
}

async fn fetch(http: &reqwest::Client, url: &str) -> Result<Option<Vec<u8>>> {
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        bail!("GET {url}: HTTP {}", resp.status());
    }
    Ok(Some(resp.bytes().await?.to_vec()))
}

/// Verify `name@version` (or the latest) in `registry`: the index against
/// `index_keys`, the release against `author_keys` (or, when empty, the
/// author keys the signed index lists), and the provenance against
/// `index_keys`.
pub async fn verify(
    registry: &str,
    name: &str,
    version: Option<&str>,
    index_keys: &[TrustedKey],
    author_keys: &[TrustedKey],
    now: DateTime<Utc>,
) -> Result<Report> {
    let http = crate::http::client_builder()
        .build()
        .context("build HTTP client")?;
    let mut report = Report {
        name: name.to_owned(),
        ..Report::default()
    };

    // 1. The index: signed by a registry key you pin, and not expired.
    let index_url = absolute(registry, "index.json");
    let index_raw = fetch(&http, &index_url)
        .await?
        .context("the registry has no index.json")?;
    let index_sig = fetch(&http, &format!("{index_url}.sig")).await?;
    match verify_labelled(INDEX, "index", index_keys, &index_raw, index_sig.as_deref()) {
        Ok(kid) => report.index_signed_by = Some(kid),
        Err(e) => {
            report.problems.push(format!("index: {e}"));
            return Ok(report);
        }
    }
    let index: Index = serde_json::from_slice(&index_raw).context("parse index.json")?;
    let expires = index
        .expires
        .as_deref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok());
    if expires.is_none_or(|t| t <= now) {
        report.problems.push(format!(
            "index: index_expired: expires {}",
            index.expires.as_deref().unwrap_or("never (it says none)")
        ));
        return Ok(report);
    }
    let bundle = index
        .bundles
        .get(name)
        .with_context(|| format!("`{name}` is not in the registry"))?;
    let version = match version {
        Some(v) => v.to_owned(),
        None => bundle
            .latest
            .clone()
            .with_context(|| format!("`{name}` has no latest version"))?,
    };
    report.version.clone_from(&version);
    let entry = bundle
        .versions
        .get(&version)
        .with_context(|| format!("`{name}@{version}` is not in the registry"))?;
    if entry.yanked {
        report.problems.push(format!(
            "yanked: {}",
            entry.yank_reason.as_deref().unwrap_or("no reason given")
        ));
    }

    // 2. The author's signature over the document the index names.
    let artifacts_url = absolute(registry, &entry.artifacts);
    let Some(body) = fetch(&http, &artifacts_url).await? else {
        report
            .problems
            .push("artifacts.yaml is not published".into());
        return Ok(report);
    };
    if !entry
        .artifacts_sha256
        .as_deref()
        .is_some_and(|d| digest_eq(&body, d))
    {
        report.problems.push(
            "digest_mismatch: artifacts.yaml is not the document the signed index names".into(),
        );
        return Ok(report);
    }
    let sig_url = absolute(
        registry,
        entry
            .signature
            .as_deref()
            .unwrap_or(&format!("{}.sig", entry.artifacts)),
    );
    let sig = fetch(&http, &sig_url).await?;
    report.author.clone_from(&bundle.author);
    let listed = bundle
        .author
        .as_ref()
        .and_then(|a| index.authors.get(a))
        .cloned_author();
    let (keys, from) = if author_keys.is_empty() {
        (
            listed
                .keys
                .iter()
                .map(|k| TrustedKey::parse(k))
                .collect::<Result<Vec<_>>>()?,
            "index",
        )
    } else {
        (author_keys.to_vec(), "pinned")
    };
    report.author_keys_from = Some(from);
    match verify_signature(&keys, &body, sig.as_deref()) {
        Ok(kid) => report.signed_by = Some(kid),
        Err(e) => {
            let revoked = signed_key_id(sig.as_deref()).and_then(|kid| {
                listed.revoked.iter().find_map(|r| {
                    TrustedKey::parse(&r.key)
                        .ok()
                        .filter(|k| k.id == kid)
                        .map(|_| r.kind.clone())
                })
            });
            report.problems.push(match revoked {
                Some(kind) => {
                    format!("author: the author key that signed it was revoked as {kind}")
                }
                None => format!("author: {e}"),
            });
            return Ok(report);
        }
    }
    let doc: ArtifactsDoc = serde_yaml::from_slice(&body).context("parse artifacts.yaml")?;
    let (n, v) = doc
        .metadata
        .as_ref()
        .map(|m| (m.name.as_deref(), m.version.as_deref()))
        .unwrap_or_default();
    if n != Some(name) || v != Some(version.as_str()) {
        report
            .problems
            .push("release_mismatch: the signed artifacts.yaml names another release".into());
    }
    let declared = doc.author.as_ref();
    if declared.and_then(|a| a.key_id.as_deref()) != report.signed_by.as_deref()
        || declared.and_then(|a| a.id.as_deref()) != bundle.author.as_deref()
    {
        report.problems.push(
            "author_mismatch: artifacts.yaml does not name the author and key that signed it"
                .into(),
        );
    }

    // 3. Provenance: attested by the registry, agreeing with the release.
    check_provenance(&http, registry, entry, &doc, index_keys, &mut report).await?;

    // 4. The bytes.
    match doc.manifest.as_ref().and_then(|m| m.sha256.as_deref()) {
        None => report
            .problems
            .push("artifacts.yaml pins no manifest digest".into()),
        Some(pinned) => {
            let url = absolute(
                registry,
                doc.manifest
                    .as_ref()
                    .and_then(|m| m.url.as_deref())
                    .unwrap_or(&entry.manifest),
            );
            match fetch(&http, &url).await? {
                Some(bytes) if digest_eq(&bytes, pinned) => report.checked.push("manifest".into()),
                _ => report
                    .problems
                    .push("digest_mismatch: the manifest does not match its pinned digest".into()),
            }
        }
    }
    for (key, art) in &doc.artifacts {
        let (Some(url), Some(pinned)) = (art.url.as_deref(), art.sha256.as_deref()) else {
            continue;
        };
        match fetch(&http, &absolute(registry, url)).await? {
            Some(bytes) if digest_eq(&bytes, pinned) => report.checked.push(key.clone()),
            _ => report.problems.push(format!(
                "digest_mismatch: artifact {key} does not match its pinned digest"
            )),
        }
    }
    Ok(report)
}

trait ClonedAuthor {
    fn cloned_author(self) -> Author;
}

impl ClonedAuthor for Option<&Author> {
    fn cloned_author(self) -> Author {
        self.map(|a| Author {
            keys: a.keys.clone(),
            revoked: a
                .revoked
                .iter()
                .map(|r| Revoked {
                    key: r.key.clone(),
                    kind: r.kind.clone(),
                })
                .collect(),
        })
        .unwrap_or_default()
    }
}

async fn check_provenance(
    http: &reqwest::Client,
    registry: &str,
    entry: &Entry,
    doc: &ArtifactsDoc,
    index_keys: &[TrustedKey],
    report: &mut Report,
) -> Result<()> {
    let Some(url) = entry.provenance.as_deref().map(|u| absolute(registry, u)) else {
        report
            .problems
            .push("provenance: provenance_missing: the index names none".into());
        return Ok(());
    };
    let Some(body) = fetch(http, &url).await? else {
        report
            .problems
            .push("provenance: provenance_missing: not published".into());
        return Ok(());
    };
    if !entry
        .provenance_sha256
        .as_deref()
        .is_some_and(|d| digest_eq(&body, d))
    {
        report
            .problems
            .push("provenance: not the statement the signed index names".into());
        return Ok(());
    }
    let sig = fetch(http, &format!("{url}.sig")).await?;
    if let Err(e) = verify_labelled(PROVENANCE, "provenance", index_keys, &body, sig.as_deref()) {
        report.problems.push(format!("provenance: {e}"));
        return Ok(());
    }
    let prov: Provenance = serde_json::from_slice(&body).context("parse provenance.json")?;
    let mut problems = Vec::new();
    if prov.kind.as_deref() != Some("BuildProvenance") {
        problems.push("not a BuildProvenance statement".to_owned());
    }
    let meta = doc.metadata.as_ref();
    let rel = prov.release.as_ref();
    if rel.and_then(|r| r.name.as_deref()) != meta.and_then(|m| m.name.as_deref())
        || rel.and_then(|r| r.version.as_deref()) != meta.and_then(|m| m.version.as_deref())
    {
        problems.push("it is for another release".to_owned());
    }
    let commit = doc.source.as_ref().and_then(|s| s.commit.as_deref());
    if commit.is_none() || prov.source.as_ref().and_then(|s| s.commit.as_deref()) != commit {
        problems.push("the source commit differs from artifacts.yaml".to_owned());
    }
    let images = doc.builder.as_ref().map(|b| &b.images);
    if prov.builder.as_ref().map(|b| &b.images) != images {
        problems.push("the builder images differ from artifacts.yaml".to_owned());
    }
    let pinned = std::iter::once((
        "app.yaml",
        doc.manifest.as_ref().and_then(|m| m.sha256.as_deref()),
    ))
    .chain(
        doc.artifacts
            .iter()
            .filter(|(_, a)| a.sha256.is_some())
            .map(|(k, a)| (k.as_str(), a.sha256.as_deref())),
    );
    for (file, digest) in pinned {
        if prov.subject.get(file).map(|d| normalize(d)) != digest.map(normalize) {
            problems.push(format!("{file} was not built as artifacts.yaml pins it"));
        }
    }
    if problems.is_empty() {
        report.built_from = commit.map(str::to_owned);
        report.built_in = images
            .map(|i| i.values().cloned().collect())
            .unwrap_or_default();
        report.checked.push("provenance".into());
    } else {
        for p in problems {
            report
                .problems
                .push(format!("provenance: provenance_mismatch: {p}"));
        }
    }
    Ok(())
}

fn normalize(d: &str) -> String {
    d.trim().trim_start_matches("sha256:").to_ascii_lowercase()
}

fn digest_eq(bytes: &[u8], pinned: &str) -> bool {
    hex_string(&Sha256::digest(bytes)) == normalize(pinned)
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};
    use ed25519_dalek::Signer as _;

    const VECTOR: &str = include_str!("testdata/bundle_signature_v1.json");
    const INDEX_SEED: [u8; 32] = [7; 32];
    const AUTHOR_SEED: [u8; 32] = [9; 32];

    fn sign(label: &[u8], seed: &[u8; 32], body: &[u8]) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed);
        let kid = hex_string(&Sha256::digest(sk.verifying_key().to_bytes())[..8]);
        let sig = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(&message(label, body)).to_bytes());
        serde_json::json!({ "alg": "ed25519", "keyId": kid, "signature": sig }).to_string()
    }

    fn line(seed: &[u8; 32]) -> String {
        let pk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();
        format!("ed25519:{}", hex_string(pk.as_bytes()))
    }

    fn pinned(seed: &[u8; 32]) -> Vec<TrustedKey> {
        vec![TrustedKey::parse(&line(seed)).unwrap()]
    }

    #[test]
    fn the_shared_vectors_verify() {
        let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
        let key = TrustedKey::parse(v["publicKey"].as_str().unwrap()).unwrap();
        assert_eq!(key.id, v["keyId"].as_str().unwrap());
        let body = v["artifactsYaml"].as_str().unwrap().as_bytes();
        assert_eq!(
            hex_string(&message(BUNDLE, body)),
            v["messageHex"].as_str().unwrap()
        );
        let sig = v["signatureFile"].as_str().unwrap().as_bytes();
        assert_eq!(
            verify_signature(std::slice::from_ref(&key), body, Some(sig)).unwrap(),
            v["keyId"].as_str().unwrap()
        );
        for (file, label, what) in [
            (
                include_str!("testdata/index_signature_v1.json"),
                INDEX,
                "index",
            ),
            (
                include_str!("testdata/provenance_signature_v1.json"),
                PROVENANCE,
                "provenance",
            ),
        ] {
            let v: serde_json::Value = serde_json::from_str(file).unwrap();
            let doc = v["document"].as_str().unwrap().as_bytes();
            assert_eq!(
                hex_string(&message(label, doc)),
                v["messageHex"].as_str().unwrap()
            );
            let sig = v["signatureFile"].as_str().unwrap().as_bytes();
            let keys = [TrustedKey::parse(v["publicKey"].as_str().unwrap()).unwrap()];
            assert!(verify_labelled(label, what, &keys, doc, Some(sig)).is_ok());
            // A registry signature is never a release signature.
            assert!(verify_signature(&keys, doc, Some(sig)).is_err());
        }
    }

    #[test]
    fn unsigned_unpinned_and_tampered_are_refused() {
        let body = b"doc";
        assert!(verify_signature(&pinned(&[1; 32]), body, None)
            .unwrap_err()
            .to_string()
            .starts_with("bundle_unsigned"));
        let other = sign(BUNDLE, &[2; 32], body);
        assert!(
            verify_signature(&pinned(&[1; 32]), body, Some(other.as_bytes()))
                .unwrap_err()
                .to_string()
                .contains("not pinned")
        );
        let good = sign(BUNDLE, &[1; 32], body);
        assert!(verify_signature(&pinned(&[1; 32]), b"doc!", Some(good.as_bytes())).is_err());
    }

    #[test]
    fn no_pinned_index_key_is_an_error_not_an_empty_pass() {
        assert!(
            index_keys(&[]).is_err()
                || std::env::var("AIRDRESS_PLUGIN_INDEX_KEYS").is_ok()
                || std::env::var("AIRDRESS_PLUGIN_TRUSTED_KEYS").is_ok()
        );
        assert!(index_keys(&["ed25519:zz".into()]).is_err());
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct Publish {
        tamper_artifact: bool,
        index_by: Option<[u8; 32]>,
        author_by: Option<[u8; 32]>,
        expired: bool,
        revoked_author: bool,
        other_commit: bool,
    }

    const NOW: &str = "2026-09-28T12:00:00Z";

    /// The responses, in the order `verify` fetches them.
    fn release(p: Publish) -> Vec<String> {
        let sha = |s: &[u8]| hex_string(&Sha256::digest(s));
        let manifest = "apiVersion: airdress.app/v1\n";
        let binary = "binary";
        let author = p.author_by.unwrap_or(AUTHOR_SEED);
        let author_kid = TrustedKey::parse(&line(&author)).unwrap().id;
        let artifacts = format!(
            "metadata: {{ name: hello, version: 0.1.0 }}\n\
             author: {{ id: acme, keyId: {author_kid} }}\n\
             manifest: {{ url: hello/0.1.0/app.yaml, sha256: {} }}\n\
             source: {{ commit: abc }}\n\
             builder: {{ images: {{ linux-x86_64: 'img@sha256:1' }} }}\n\
             artifacts:\n  hello-linux-x86_64: {{ url: hello/0.1.0/hello-linux-x86_64, sha256: {} }}\n",
            sha(manifest.as_bytes()),
            sha(binary.as_bytes())
        );
        let provenance = serde_json::json!({
            "kind": "BuildProvenance",
            "release": { "name": "hello", "version": "0.1.0" },
            "source": { "commit": if p.other_commit { "def" } else { "abc" } },
            "builder": { "images": { "linux-x86_64": "img@sha256:1" } },
            "subject": { "app.yaml": sha(manifest.as_bytes()), "hello-linux-x86_64": sha(binary.as_bytes()) },
        })
        .to_string();
        let revoked = if p.revoked_author {
            vec![serde_json::json!({ "key": line(&author), "kind": "compromised" })]
        } else {
            vec![]
        };
        let index = serde_json::json!({
            "generated": "2026-09-28T00:00:00Z",
            "expires": if p.expired { "2026-09-28T06:00:00Z" } else { "2026-10-05T00:00:00Z" },
            "authors": { "acme": { "keys": [line(&AUTHOR_SEED)], "revoked": revoked } },
            "bundles": { "hello": { "author": "acme", "latest": "0.1.0", "versions": {
                "0.1.0": {
                    "manifest": "hello/0.1.0/app.yaml",
                    "artifacts": "hello/0.1.0/artifacts.yaml",
                    "artifactsSha256": sha(artifacts.as_bytes()),
                    "provenance": "hello/0.1.0/provenance.json",
                    "provenanceSha256": sha(provenance.as_bytes()),
                }
            }}},
        })
        .to_string();
        let served = if p.tamper_artifact { "binary!" } else { binary };
        vec![
            response("200 OK", &index),
            response(
                "200 OK",
                &sign(INDEX, &p.index_by.unwrap_or(INDEX_SEED), index.as_bytes()),
            ),
            response("200 OK", &artifacts),
            response("200 OK", &sign(BUNDLE, &author, artifacts.as_bytes())),
            response("200 OK", &provenance),
            response(
                "200 OK",
                &sign(PROVENANCE, &INDEX_SEED, provenance.as_bytes()),
            ),
            response("200 OK", manifest),
            response("200 OK", served),
        ]
    }

    async fn run(p: Publish) -> Report {
        let (base, seen) = canned_operator(release(p)).await;
        let now = DateTime::parse_from_rfc3339(NOW)
            .unwrap()
            .with_timezone(&Utc);
        let r = verify(
            &base,
            "hello",
            Some("0.1.0"),
            &pinned(&INDEX_SEED),
            &[],
            now,
        )
        .await
        .unwrap();
        // A refusal stops before every canned response is asked for.
        seen.abort();
        r
    }

    #[tokio::test]
    async fn an_author_signed_attested_release_in_a_signed_index_verifies() {
        let (base, seen) = canned_operator(release(Publish::default())).await;
        let now = DateTime::parse_from_rfc3339(NOW)
            .unwrap()
            .with_timezone(&Utc);
        let r = verify(
            &base,
            "hello",
            Some("0.1.0"),
            &pinned(&INDEX_SEED),
            &[],
            now,
        )
        .await
        .unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert_eq!(r.author.as_deref(), Some("acme"));
        assert_eq!(r.author_keys_from, Some("index"));
        assert_eq!(
            r.signed_by.as_deref(),
            Some(TrustedKey::parse(&line(&AUTHOR_SEED)).unwrap().id.as_str())
        );
        assert_eq!(r.built_from.as_deref(), Some("abc"));
        assert_eq!(
            r.checked,
            vec!["provenance", "manifest", "hello-linux-x86_64"]
        );
        let seen = seen.await.unwrap();
        assert!(seen[1].starts_with("GET /index.json.sig "), "{}", seen[1]);
        assert!(
            seen[3].starts_with("GET /hello/0.1.0/artifacts.yaml.sig "),
            "{}",
            seen[3]
        );
        assert!(
            seen[5].starts_with("GET /hello/0.1.0/provenance.json.sig "),
            "{}",
            seen[5]
        );
    }

    #[tokio::test]
    async fn each_signer_and_the_bytes_are_checked() {
        let cases: [(Publish, &str); 6] = [
            (
                Publish {
                    tamper_artifact: true,
                    ..Publish::default()
                },
                "artifact hello-linux-x86_64",
            ),
            (
                Publish {
                    index_by: Some([3; 32]),
                    ..Publish::default()
                },
                "index: index_signature_invalid",
            ),
            (
                Publish {
                    expired: true,
                    ..Publish::default()
                },
                "index_expired",
            ),
            (
                Publish {
                    author_by: Some([4; 32]),
                    ..Publish::default()
                },
                "author: bundle_signature_invalid",
            ),
            (
                Publish {
                    author_by: Some([4; 32]),
                    revoked_author: true,
                    ..Publish::default()
                },
                "revoked as compromised",
            ),
            (
                Publish {
                    other_commit: true,
                    ..Publish::default()
                },
                "provenance_mismatch: the source commit",
            ),
        ];
        for (p, want) in cases {
            let r = run(p).await;
            assert!(
                r.problems.iter().any(|x| x.contains(want)),
                "{want}: {:?}",
                r.problems
            );
        }
    }
}
