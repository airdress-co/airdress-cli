//! `airdress device revoke <ENROLLMENT_ID>` — revoke one device's
//! enrollment with the owner's own sign-in.
//!
//! SPEC-049 task 5.6. The operator's `airdress-operator endpoint revoke
//! --token` needs a device session token from a *sibling* device on the
//! same airdress. An airdress whose only device is dead has no sibling,
//! so until this command the enrollment could only be revoked with shell
//! on the operator (on 2026-09-16 a dead S23's was revoked DB-direct).
//!
//! The operator also accepts the owner's ZITADEL bearer on `DELETE
//! /v1/endpoints/enrollments/{id}` (operator PR #218), and that is the
//! bearer this CLI already holds from `airdress auth login` — the same one
//! `device pair` sends. No new credential and no new auth path.
//!
//! Every run first checks the id names an active enrollment (a revoked one
//! is refused: nothing to revoke), then asks the operator with
//! `?dry_run=true`. That call is authorized exactly like the revoke, so it
//! is both the preview (what would be revoked: id, airdress, label) and the
//! check (a 403 / 404 comes back before anything is asked of the user).
//! Then:
//!
//! - `--dry-run` stops at the preview.
//! - otherwise the user confirms on a terminal, or passes `--yes` when
//!   stdin is not one. A script never revokes by accident.

use anyhow::{bail, Result};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use super::client::{OperatorEnrollClient, RevokePreview};

#[derive(Debug)]
pub struct RevokeArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub enrollment_id: uuid::Uuid,
    pub dry_run: bool,
    pub yes: bool,
    /// Dev override, as on `device pair`.
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: RevokeArgs<'_>) -> Result<()> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;

    // The airdress resolves which operator to talk to. It is not needed
    // with --operator-url, so a missing context must not block that path.
    let op = if let Some(url) = args.operator_url {
        OperatorEnrollClient::with_base_url(url.to_owned(), hub.operator_bearer(url).await?)?
    } else {
        let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;
        if !args.json && !args.quiet && resolved.source != Source::Flag {
            ui::note(format!(
                "acting on {} (source: {})",
                resolved.name,
                resolved.source.as_str()
            ));
        }
        let fqdn = hub.resolve_fqdn(&resolved.name).await?;
        OperatorEnrollClient::new(&fqdn, hub.operator_bearer(&fqdn).await?)?
    };

    if !op.enrollment_is_active(args.enrollment_id).await? {
        bail!(
            "no active enrollment {} visible to this sign-in — already revoked, \
             never existed, or not yours to revoke; nothing was changed",
            args.enrollment_id
        );
    }
    let preview = op.preview_revoke(args.enrollment_id).await?;

    if args.dry_run {
        if args.json {
            print_json(&preview, false)?;
        } else {
            ui::say(describe(&preview, "Would revoke"));
            if let Some(warning) = last_device_warning(&preview) {
                ui::warn(warning);
            }
        }
        return Ok(());
    }

    if !args.json {
        ui::say(describe(&preview, "About to revoke"));
        if let Some(warning) = last_device_warning(&preview) {
            ui::warn(warning);
        }
    }

    ui::confirm(
        "Revoke this enrollment?",
        ui::Confirm::new(args.yes, args.json),
    )?;

    op.revoke_enrollment(args.enrollment_id).await?;

    if args.json {
        print_json(&preview, true)?;
    } else {
        ui::ok(format!(
            "revoked {} ({:?} on {})",
            preview.enrollment_id, preview.device_label, preview.airdress
        ));
    }
    Ok(())
}

fn describe(p: &RevokePreview, verb: &str) -> String {
    format!(
        "{verb} enrollment {}\n  airdress: {}\n  label:    {}",
        p.enrollment_id, p.airdress, p.device_label
    )
}

/// Revoking the last device on an airdress is sometimes exactly the point
/// (a dead single-device airdress) — but it is also the one that cannot be
/// undone from a device. Say so; don't block it.
fn last_device_warning(p: &RevokePreview) -> Option<&'static str> {
    (p.remaining_active_enrollments == Some(0)).then_some(
        "this is the last active device on that airdress — no device will be \
         able to act for it until a new one is paired",
    )
}

fn print_json(p: &RevokePreview, revoked: bool) -> Result<()> {
    let envelope = serde_json::json!({
        "enrollment_id": p.enrollment_id,
        "airdress": p.airdress,
        "device_label": p.device_label,
        "remaining_active_enrollments": p.remaining_active_enrollments,
        "dry_run": !revoked,
        "revoked": revoked,
    });
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(remaining: Option<u64>) -> RevokePreview {
        RevokePreview {
            enrollment_id: uuid::Uuid::nil(),
            airdress: "ada.a.airdr.es".to_owned(),
            device_label: "dead phone".to_owned(),
            remaining_active_enrollments: remaining,
        }
    }

    #[test]
    fn describe_names_id_airdress_and_label() {
        let text = describe(&preview(Some(1)), "Would revoke");
        assert!(text.contains("00000000-0000-0000-0000-000000000000"));
        assert!(text.contains("ada.a.airdr.es"));
        assert!(text.contains("dead phone"));
    }

    #[test]
    fn last_device_is_warned_about_only_when_known_to_be_last() {
        assert!(last_device_warning(&preview(Some(0))).is_some());
        assert!(last_device_warning(&preview(Some(2))).is_none());
        assert!(last_device_warning(&preview(None)).is_none());
    }
}
