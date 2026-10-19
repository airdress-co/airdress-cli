//! `airdress device list` — every device signed in to the airdress, and
//! which of them could still act for it.
//!
//! Read-only. Uses the owner's own sign-in (`airdress auth login`), the same
//! bearer `device pair` and `device revoke` send, so it needs neither a
//! phone nor shell on the operator.
//!
//! Written after a person could not add a phone (2026-10-20, SPEC-163): the
//! new phone waited for an approval no device could give, because the one
//! phone that had held the airdress's key had since been set up again for a
//! different airdress. Reaching that conclusion took half an hour of
//! reading logs and calling the operator by hand. The question it needed
//! answered is the one this command prints last: *which enrolled devices
//! could approve a new device, or object to a key reset?*
//!
//! A device can do either only if it holds the airdress's root key:
//!
//! - `key_custody: operator_held` — it never did;
//! - `delegation_only` (the CLI, the editor) or `device_class: agent` — it
//!   holds a delegation signed by the root, never the root;
//! - a member's device (a person other than the owner) — the owner's root
//!   reset is not theirs to hold up, and they cannot approve the owner's
//!   joins.
//!
//! Everything else is a phone or desktop app that *claims* the key. The
//! operator cannot tell whether it still has it: a phone that was wiped,
//! reinstalled or set up again keeps its row, and keeps counting, until it
//! is signed out or ages out. That is the case this command makes visible —
//! it lists who could answer and when each was last seen, so a person can
//! say "that phone was reset" and know the way forward is a key reset.

use std::collections::HashSet;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use super::client::{EnrollmentRow, OperatorEnrollClient};

/// The operator's default `[recovery] objector_window`. A device unseen for
/// longer no longer holds up a key reset. The operator does not publish its
/// own value, so this mirrors the default; a host configured otherwise
/// differs.
pub const DEFAULT_OBJECTOR_WINDOW_DAYS: i64 = 14;

#[derive(Debug)]
pub struct ListArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    /// Dev override, as on `device pair`.
    pub operator_url: Option<&'a str>,
}

/// Whether a device holds the airdress's root key, as far as the operator
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Key {
    /// A person's app that holds (or held) the root.
    Root,
    /// A delegation signed by the root: the CLI, the editor.
    Delegation,
    /// An agent device: always a delegation.
    Agent,
    /// The operator holds this device's key; it never held the root.
    Operator,
    /// `client_held`, from an operator too old to say whether it is a
    /// delegation.
    Unknown,
}

/// What one device can do for the airdress, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Assessed {
    #[serde(flatten)]
    pub row: EnrollmentRow,
    pub key: Key,
    /// The device is a member's (a person other than the owner). `None`
    /// when the operator would not say who its members are.
    pub member: Option<bool>,
    /// Could approve a new device or object to a key reset: `None` when that
    /// cannot be told from what the operator sent.
    pub can_approve: Option<bool>,
    /// Would hold a key reset up for 24 hours right now: can approve, and
    /// seen inside the objector window.
    pub objector: Option<bool>,
}

#[must_use]
pub fn key_of(row: &EnrollmentRow) -> Key {
    if row.device_class.as_deref() == Some("agent") {
        return Key::Agent;
    }
    if row.key_custody == "operator_held" {
        return Key::Operator;
    }
    match row.delegation_only {
        Some(true) => Key::Delegation,
        Some(false) => Key::Root,
        None => Key::Unknown,
    }
}

/// When the operator last saw the device, falling back to when it was
/// enrolled — the operator's own reading for the objector window.
#[must_use]
pub fn seen_at(row: &EnrollmentRow) -> DateTime<Utc> {
    row.last_seen_at.unwrap_or(row.created_at)
}

#[must_use]
pub fn assess<S: std::hash::BuildHasher>(
    row: EnrollmentRow,
    members: Option<&HashSet<uuid::Uuid, S>>,
    now: DateTime<Utc>,
) -> Assessed {
    let key = key_of(&row);
    let member = members.map(|m| row.principal_id.is_some_and(|p| m.contains(&p)));
    let can_approve = match (key, member) {
        (Key::Delegation | Key::Agent | Key::Operator, _) | (_, Some(true)) => Some(false),
        (Key::Root, Some(false)) => Some(true),
        // The key is unknown, or the device's person is: say so.
        _ => None,
    };
    let in_window = seen_at(&row) > now - Duration::days(DEFAULT_OBJECTOR_WINDOW_DAYS);
    let objector = can_approve.map(|c| c && in_window);
    Assessed {
        row,
        key,
        member,
        can_approve,
        objector,
    }
}

pub async fn run(args: ListArgs<'_>) -> Result<()> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;

    let (op, airdress) = if let Some(url) = args.operator_url {
        (
            OperatorEnrollClient::with_base_url(url.to_owned(), hub.operator_bearer(url).await?)?,
            url.to_owned(),
        )
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
        (
            OperatorEnrollClient::new(&fqdn, hub.operator_bearer(&fqdn).await?)?,
            fqdn,
        )
    };

    let rows = op.list_enrollments().await?;
    let members: Option<HashSet<uuid::Uuid>> = op.sub_user_ids().await.map(HashSet::from_iter);
    let now = Utc::now();
    let mut devices: Vec<Assessed> = rows
        .into_iter()
        .map(|r| assess(r, members.as_ref(), now))
        .collect();
    devices.sort_by_key(|d| std::cmp::Reverse(seen_at(&d.row)));

    if args.json {
        let approvers = devices
            .iter()
            .filter(|d| d.can_approve == Some(true))
            .count();
        let objectors = devices.iter().filter(|d| d.objector == Some(true)).count();
        let unknown = devices.iter().filter(|d| d.can_approve.is_none()).count();
        let envelope = serde_json::json!({
            "airdress": airdress,
            "devices": devices,
            "can_approve": approvers,
            "objectors": objectors,
            "undetermined": unknown,
            "objector_window_days": DEFAULT_OBJECTOR_WINDOW_DAYS,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    print!("{}", render(&devices, now));
    for line in verdict(&devices, now) {
        ui::say(line);
    }
    Ok(())
}

/// The table, on stdout: it is the command's payload.
#[must_use]
pub fn render(devices: &[Assessed], now: DateTime<Utc>) -> String {
    if devices.is_empty() {
        return String::new();
    }
    let width = devices
        .iter()
        .map(|d| d.row.device_label.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(5, 40);
    let mut lines = vec![format!(
        "{:<width$}  {:<10}  {:<10}  {:<12}  APPROVE / OBJECT  ID",
        "LABEL", "KIND", "KEY", "LAST SEEN"
    )];
    for d in devices {
        let label: String = d.row.device_label.chars().take(width).collect();
        let kind = match (d.key, d.member) {
            (Key::Agent, _) => d.row.harness.as_deref().unwrap_or("agent").to_owned(),
            (_, Some(true)) => "member".to_owned(),
            _ => "person".to_owned(),
        };
        let key = match d.key {
            Key::Root => "root",
            Key::Delegation | Key::Agent => "delegation",
            Key::Operator => "operator",
            Key::Unknown => "unknown",
        };
        let seen = if d.row.last_seen_at.is_some() {
            ago(seen_at(&d.row), now)
        } else {
            format!("never ({})", ago(d.row.created_at, now))
        };
        let can = match (d.can_approve, d.objector) {
            (Some(true), Some(true)) => "yes / yes",
            (Some(true), _) => "yes / no (idle)",
            (Some(false), _) => "no",
            (None, _) => "unknown",
        };
        lines.push(format!(
            "{label:<width$}  {kind:<10}  {key:<10}  {seen:<12}  {can:<16}  {}",
            d.row.id
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

/// What the table means for the person in front of it, on stderr.
#[must_use]
pub fn verdict(devices: &[Assessed], now: DateTime<Utc>) -> Vec<String> {
    let approvers: Vec<&Assessed> = devices
        .iter()
        .filter(|d| d.can_approve == Some(true))
        .collect();
    let unknown = devices.iter().filter(|d| d.can_approve.is_none()).count();
    let objectors = devices.iter().filter(|d| d.objector == Some(true)).count();
    let mut lines = Vec::new();
    if devices.is_empty() {
        lines.push(
            "No device is signed in. A new device can't be approved by anyone; \
             a key reset makes it the first, and does not wait."
                .to_owned(),
        );
        return lines;
    }
    if unknown > 0 {
        lines.push(format!(
            "{unknown} device(s) marked unknown: this operator does not say whether \
             they hold the key, or whose they are. Treat them as able to approve."
        ));
    }
    if approvers.is_empty() && unknown == 0 {
        lines.push(
            "No signed-in device holds this airdress's key, so none can approve a \
             new device. A key reset is the way forward, and it does not wait."
                .to_owned(),
        );
        return lines;
    }
    if !approvers.is_empty() {
        let named: Vec<String> = approvers
            .iter()
            .map(|d| {
                format!(
                    "{} (seen {})",
                    d.row.device_label,
                    ago(seen_at(&d.row), now)
                )
            })
            .collect();
        lines.push(format!(
            "Only these can approve a new device: {}.",
            named.join(", ")
        ));
        lines.push(
            "If each of them was wiped, reinstalled or set up again for another \
             airdress, it no longer has the key and cannot answer."
                .to_owned(),
        );
        if objectors > 0 {
            lines.push(format!(
                "A key reset would wait 24 hours for {objectors} of them to object or agree."
            ));
        } else {
            lines.push(
                "None was seen in the last 14 days, so a key reset would not wait for them."
                    .to_owned(),
            );
        }
    }
    lines
}

fn ago(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let d = now - at;
    if d < Duration::minutes(1) {
        "just now".to_owned()
    } else if d < Duration::hours(1) {
        format!("{} min ago", d.num_minutes())
    } else if d < Duration::days(2) {
        format!("{} h ago", d.num_hours())
    } else {
        format!("{} d ago", d.num_days())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(label: &str, custody: &str, delegation_only: Option<bool>) -> EnrollmentRow {
        EnrollmentRow {
            id: uuid::Uuid::new_v4(),
            device_label: label.to_owned(),
            key_custody: custody.to_owned(),
            created_at: Utc::now() - Duration::days(30),
            expires_at: None,
            last_seen_at: Some(Utc::now() - Duration::hours(1)),
            principal_id: Some(uuid::Uuid::nil()),
            device_class: Some("human".to_owned()),
            harness: None,
            suspended_at: None,
            delegation_only,
        }
    }

    fn agent() -> EnrollmentRow {
        let mut r = row("Claude Code on box", "client_held", Some(true));
        r.device_class = Some("agent".to_owned());
        r.harness = Some("claude-code".to_owned());
        r
    }

    fn none() -> HashSet<uuid::Uuid> {
        HashSet::new()
    }

    #[test]
    fn a_phone_that_claims_the_root_can_approve_and_object() {
        let a = assess(
            row("S23", "client_held", Some(false)),
            Some(&none()),
            Utc::now(),
        );
        assert_eq!(a.key, Key::Root);
        assert_eq!(a.can_approve, Some(true));
        assert_eq!(a.objector, Some(true));
    }

    #[test]
    fn a_delegation_an_agent_and_an_operator_held_device_never_can() {
        let now = Utc::now();
        for r in [
            row("cli", "client_held", Some(true)),
            agent(),
            row("member phone", "operator_held", Some(false)),
        ] {
            let a = assess(r, Some(&none()), now);
            assert_eq!(a.can_approve, Some(false), "{:?}", a.key);
            assert_eq!(a.objector, Some(false));
        }
    }

    #[test]
    fn a_member_device_cannot_approve_the_owners_join() {
        let r = row("partner", "client_held", Some(false));
        let members: HashSet<_> = [uuid::Uuid::nil()].into();
        let a = assess(r, Some(&members), Utc::now());
        assert_eq!(a.member, Some(true));
        assert_eq!(a.can_approve, Some(false));
    }

    #[test]
    fn an_older_operator_leaves_it_unknown_rather_than_guessing() {
        let a = assess(row("old", "client_held", None), Some(&none()), Utc::now());
        assert_eq!(a.key, Key::Unknown);
        assert_eq!(a.can_approve, None);
        // And an unknown membership leaves a root-holder unknown too.
        let b = assess(
            row("S23", "client_held", Some(false)),
            None::<&HashSet<uuid::Uuid>>,
            Utc::now(),
        );
        assert_eq!(b.can_approve, None);
    }

    #[test]
    fn a_device_unseen_past_the_window_can_approve_but_does_not_object() {
        let mut r = row("drawer phone", "client_held", Some(false));
        r.last_seen_at = Some(Utc::now() - Duration::days(DEFAULT_OBJECTOR_WINDOW_DAYS + 1));
        let a = assess(r, Some(&none()), Utc::now());
        assert_eq!(a.can_approve, Some(true));
        assert_eq!(a.objector, Some(false));
    }

    #[test]
    fn the_verdict_says_when_nothing_can_approve() {
        // The 2026-10-20 shape, once the dead phone was signed out: only the
        // agent device is left.
        let now = Utc::now();
        let devices = vec![assess(agent(), Some(&none()), now)];
        let v = verdict(&devices, now).join(" ");
        assert!(v.contains("No signed-in device holds"), "{v}");
        assert!(v.contains("key reset"), "{v}");
    }

    #[test]
    fn the_verdict_names_the_devices_that_could_answer() {
        // The 2026-10-20 shape before it: a phone that claims the key, and
        // an agent that never had it.
        let now = Utc::now();
        let devices = vec![
            assess(
                row("Galaxy S23", "client_held", Some(false)),
                Some(&none()),
                now,
            ),
            assess(agent(), Some(&none()), now),
        ];
        let v = verdict(&devices, now).join(" ");
        assert!(
            v.contains("Only these can approve a new device: Galaxy S23"),
            "{v}"
        );
        assert!(!v.contains("Claude Code"), "{v}");
        assert!(v.contains("wait 24 hours for 1"), "{v}");
        let table = render(&devices, now);
        assert!(table.contains("claude-code"), "{table}");
        assert!(table.contains("delegation"), "{table}");
    }
}
