pub mod apply;
pub mod check;

use anyhow::{Context, Result};

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
                    let info = serde_json::json!({
                        "current_version": current,
                        "latest_version": current,
                        "update_available": false,
                        "platform": platform,
                    });
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    println!("Up to date ({current})");
                }
            }
            Some(v) => {
                if json {
                    let info = serde_json::json!({
                        "current_version": current,
                        "latest_version": v,
                        "update_available": true,
                        "platform": platform,
                    });
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    println!("Update available: {current} -> {v}");
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

    let exe_path = std::env::current_exe()
        .context("cannot determine binary path")?
        .canonicalize()
        .context("cannot resolve binary path")?;

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
