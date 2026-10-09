use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const DOWNLOADS_BASE: &str = "https://downloads.airdress.co/airdress-cli";

#[derive(Debug, serde::Deserialize)]
pub struct Manifest {
    #[allow(dead_code)]
    pub schema_version: u32,
    #[allow(dead_code)]
    pub version: String,
    #[allow(dead_code)]
    pub pre_release: bool,
    pub artifacts: Vec<Artifact>,
    #[allow(dead_code)]
    pub published_at: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct Artifact {
    pub platform: String,
    #[allow(dead_code)]
    pub kind: String,
    pub filename: String,
    pub sha256: String,
    #[allow(dead_code)]
    pub bytes: Option<u64>,
}

pub const fn current_platform() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-amd64"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "linux-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "darwin-amd64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "darwin-arm64"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-amd64"
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        compile_error!("unsupported platform for self-update")
    }
}

pub async fn download_and_verify(
    client: &reqwest::Client,
    version: &str,
    show_progress: bool,
) -> Result<(PathBuf, String)> {
    let manifest_url = format!("{DOWNLOADS_BASE}/{version}/manifest.json");
    let manifest: Manifest = client
        .get(&manifest_url)
        .send()
        .await
        .context("failed to fetch manifest")?
        .error_for_status()
        .with_context(|| format!("manifest not found for {version}"))?
        .json()
        .await
        .context("failed to parse manifest")?;

    let platform = current_platform();
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.platform == platform && a.kind == "binary")
        .with_context(|| format!("no artifact for {platform} in version {version}"))?;

    let exe_path = std::env::current_exe()
        .context("cannot determine binary path")?
        .canonicalize()
        .context("cannot resolve binary path")?;
    let exe_dir = exe_path
        .parent()
        .context("cannot determine binary directory")?;
    let temp_path = exe_dir.join(".airdress.update.tmp");

    let mut file = match std::fs::File::create(&temp_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(
                "cannot write to {} (permission denied)\n\n\
                 The binary appears to be installed in a system directory.\n\
                 Re-run with appropriate permissions, or reinstall:\n  \
                 curl -fsSL https://get.airdress.co/cli | sh",
                exe_dir.display()
            );
        }
        Err(e) => return Err(e).context("failed to create temp file"),
    };

    let artifact_url = format!("{DOWNLOADS_BASE}/{version}/{}", artifact.filename);
    let total_bytes = artifact.bytes.unwrap_or(0);

    if show_progress {
        eprintln!("Downloading airdress {version} ({platform})...",);
    }

    let response = client
        .get(&artifact_url)
        .send()
        .await
        .context("failed to download artifact")?
        .error_for_status()
        .context("artifact download failed")?;

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;

    let mut stream = response;
    while let Some(chunk) = stream
        .chunk()
        .await
        .context("error reading download stream")?
    {
        file.write_all(&chunk)
            .context("failed to write to temp file")?;
        hasher.update(&chunk);
        downloaded += chunk.len() as u64;

        if show_progress && total_bytes > 0 {
            eprint!(
                "\r  {:.1} MB / {:.1} MB",
                downloaded as f64 / 1_048_576.0,
                total_bytes as f64 / 1_048_576.0,
            );
        }
    }

    if show_progress && total_bytes > 0 {
        eprintln!();
    }

    file.flush().context("failed to flush temp file")?;
    drop(file);

    let computed: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    if computed != artifact.sha256 {
        remove_temp(&temp_path);
        bail!(
            "checksum mismatch: expected {}, got {computed}",
            artifact.sha256,
        );
    }

    Ok((temp_path, computed))
}

pub fn atomic_replace(temp_path: &Path, exe_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_path, std::fs::Permissions::from_mode(0o755))
            .context("failed to set permissions on update binary")?;
    }

    if let Err(e) = std::fs::rename(temp_path, exe_path) {
        remove_temp(temp_path);
        return Err(e).with_context(|| format!("failed to replace {}", exe_path.display()));
    }

    Ok(())
}

/// Remove a downloaded binary that will not be installed. The update has
/// already failed; a file left behind is named so it can be removed by hand.
fn remove_temp(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, path = %path.display(), "could not remove the downloaded update");
        }
    }
}
