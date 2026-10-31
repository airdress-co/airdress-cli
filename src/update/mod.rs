pub mod apply;
pub mod check;
pub mod managed;

use anyhow::{Context, Result};

use crate::exit::{Exit, Failure};

#[derive(Debug, clap::Args)]
pub struct UpdateArgs {
    /// Check for updates without installing
    #[arg(long)]
    pub check: bool,

    /// Install a specific version
    #[arg(long)]
    pub target: Option<String>,

    /// Include pre-release versions
    #[arg(long)]
    pub prerelease: bool,
}

pub async fn run(args: &UpdateArgs, json: bool) -> Result<()> {
    let exe_path = std::env::current_exe()
        .context("cannot determine binary path")?
        .canonicalize()
        .context("cannot resolve binary path")?;
    let managed = managed::managed_by(&exe_path, &managed::SystemDb);

    // A package manager's binary is updated by that package manager; asked
    // before anything is downloaded. `--check` still answers.
    if let (Some(manager), false) = (managed, args.check) {
        let mut f = Failure::new(
            Exit::Refused,
            "managed_by_package_manager",
            format!(
                "{} belongs to the airdress package, so {} updates it",
                exe_path.display(),
                manager.name()
            ),
        )
        .with_hint(manager.update_command());
        f.extra
            .insert("managed_by".to_owned(), manager.name().into());
        return Err(f.into());
    }

    let client = crate::http::client_builder()
        .user_agent(format!("airdress/{}", crate::build_version()))
        .build()
        .context("failed to create HTTP client")?;

    let index = check::fetch_index(&client).await?;
    let current = crate::build_version();

    let target =
        check::resolve_target_version(&index, current, args.target.as_deref(), args.prerelease)?;

    if args.check {
        let platform = apply::current_platform();
        match &target {
            None => {
                if json {
                    let mut info = serde_json::json!({
                        "current_version": current,
                        "latest_version": current,
                        "update_available": false,
                        "platform": platform,
                    });
                    add_managed_by(&mut info, managed);
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    println!("Up to date ({current})");
                }
            }
            Some(v) => {
                if json {
                    let mut info = serde_json::json!({
                        "current_version": current,
                        "latest_version": v,
                        "update_available": true,
                        "platform": platform,
                    });
                    add_managed_by(&mut info, managed);
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    println!("Update available: {current} -> {v}");
                    if let Some(m) = managed {
                        println!("Installed by {}: {}", m.name(), m.update_command());
                    }
                }
                // Exit 0: `--check` is a question, and it was answered. The
                // answer is `update_available` in the output; a non-zero
                // status would be indistinguishable from a failed check
                // (docs/exit-codes.md).
            }
        }
        return Ok(());
    }

    let target_version = match target {
        None => {
            println!("Already up to date ({current})");
            return Ok(());
        }
        Some(v) => v,
    };

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let show_progress = is_tty && !json;

    let (temp_path, sha256) =
        apply::download_and_verify(&client, &target_version, show_progress).await?;

    apply::atomic_replace(&temp_path, &exe_path)?;

    let platform = apply::current_platform();
    if json {
        let info = serde_json::json!({
            "previous_version": current,
            "new_version": target_version,
            "platform": platform,
            "sha256": sha256,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Updated airdress: {current} -> {target_version}");
    }

    Ok(())
}

/// `managed_by` in `--check`'s JSON, only when a package manager owns the
/// binary: an absent field keeps the answer unchanged for every other install.
fn add_managed_by(info: &mut serde_json::Value, managed: Option<managed::Manager>) {
    if let (Some(m), Some(obj)) = (managed, info.as_object_mut()) {
        obj.insert("managed_by".to_owned(), m.name().into());
    }
}
