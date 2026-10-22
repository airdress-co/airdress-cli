//! `airdress agent bus repin`: the way past a legitimate key change.
//!
//! A bus reader pins the airdress's root and each device key on first
//! sight (`state::Pins`). When the airdress is re-rooted, every item after
//! that reads `root_changed`, and nothing moves the pin by itself — not the
//! server, not a model, not a message on the bus. This command moves it, on
//! three conditions: the person typed the full fingerprint of the key the
//! readers have seen (read on a phone that holds the root, or on the agent
//! machine for a device key; never copied from the operator), they confirm
//! at a terminal, and the move is recorded next to the pin (who, when, from
//! what). Modelled on `airdress shell repin` (SPEC-133 133-D.10).
//!
//! Offline: the key it moves to is the one the readers recorded, so no
//! sign-in and no request is needed, and a typed fingerprint is checked
//! against exactly what was refused.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::Subcommand;

use super::state::{bus_dir, PinSlot, Pins};
use crate::ui;

/// `airdress agent bus …`.
#[derive(Debug, Subcommand)]
pub enum BusCommands {
    /// Move a changed root (or device) key pin, after checking the new key
    /// somewhere the operator cannot reach. With no fingerprint, shows the
    /// pinned and the newly seen fingerprints and changes nothing.
    Repin {
        /// The airdress, as its FQDN (the name of its directory under the
        /// state dir's `bus/`).
        airdress: String,
        /// The new key's full fingerprint (`SHA256:…`), as read on a phone
        /// that holds the airdress's root (or, with `--device`, on the
        /// agent machine).
        fingerprint: Option<String>,
        /// Re-pin this enrollment's device key instead of the root.
        #[arg(long, value_name = "ENROLLMENT")]
        device: Option<String>,
        /// The MCP server's state dir (what the editor passes as
        /// `--state-dir`). Default: ~/.local/state/airdress/agent.
        #[arg(long, value_name = "DIR")]
        state_dir: Option<PathBuf>,
    },
}

/// Run `airdress agent bus …`.
///
/// # Errors
/// The airdress has no bus state here, the fingerprint does not match, the
/// person declined, or the pins could not be written.
pub fn run(cmd: BusCommands, paths: &crate::paths::Paths, json: bool) -> Result<()> {
    match cmd {
        BusCommands::Repin {
            airdress,
            fingerprint,
            device,
            state_dir,
        } => {
            let state_dir = state_dir.unwrap_or_else(|| super::socket::default_state_dir(paths));
            let slot = device.map_or(PinSlot::Root, PinSlot::Device);
            repin(
                &state_dir,
                &airdress,
                &slot,
                fingerprint.as_deref(),
                ui::Confirm::person_only(json),
                &mut std::io::stdin().lock(),
                &mut std::io::stderr(),
            )
        }
    }
}

fn who() -> String {
    let user = ["USER", "USERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown".into());
    format!("{user}@{}", crate::mcp::session::hostname())
}

fn known_airdresses(state_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(state_dir.join("bus"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("pins.json").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    v.sort();
    v
}

/// The command, over any terminal (tests drive it).
///
/// # Errors
/// As [`run`].
pub fn repin(
    state_dir: &Path,
    airdress: &str,
    slot: &PinSlot,
    typed: Option<&str>,
    how: ui::Confirm,
    input: &mut dyn std::io::BufRead,
    prompt: &mut dyn std::io::Write,
) -> Result<()> {
    let dir = bus_dir(state_dir, airdress);
    if !dir.join("pins.json").is_file() {
        let known = known_airdresses(state_dir);
        bail!(
            "no agent-bus pins for {airdress} under {}.{}",
            state_dir.display(),
            if known.is_empty() {
                " Pass the state dir the editor's server uses with --state-dir.".to_owned()
            } else {
                format!(" Pins exist for: {}", known.join(", "))
            }
        );
    }
    let mut pins = Pins::load(&dir);
    let state = pins.state(slot);
    let pinned = state.pinned.as_deref().unwrap_or("(nothing)");
    let Some(seen) = state.seen.as_deref() else {
        ui::say(format!("{slot} for {airdress} is pinned at {pinned}; no other key has been seen. Nothing to do."));
        return Ok(());
    };
    ui::say(format!(
        "{slot} for {airdress} changed.\n  pinned: {pinned}\n  seen:   {seen}\n\n\
         A legitimate reset and a substituted key look the same from here. Only re-pin \
         after reading the new fingerprint {}.",
        match slot {
            PinSlot::Root => "on a phone that holds this airdress's root",
            PinSlot::Device(_) => "on the agent machine itself",
        }
    ));
    let Some(typed) = typed else {
        let device_flag = match slot {
            PinSlot::Root => String::new(),
            PinSlot::Device(e) => format!(" --device {e}"),
        };
        ui::note(format!(
            "to re-pin: airdress agent bus repin {airdress} <fingerprint>{device_flag} --state-dir {}",
            state_dir.display()
        ));
        return Ok(());
    };
    // Checked before asking: a wrong fingerprint never reaches the prompt.
    if typed.trim() != seen {
        bail!(
            "the fingerprint you typed is not the key seen for {slot}.\n  typed: {}\n  seen:  {seen}\n\
             Nothing was pinned.",
            typed.trim()
        );
    }
    ui::confirm_with(
        &format!("Pin {seen} for {airdress}, replacing {pinned}?"),
        how,
        input,
        prompt,
    )?;
    let record = pins.repin(slot, typed, &who())?;
    pins.save(&dir)?;
    ui::ok(format!(
        "pinned {seen} for {airdress} (was {}; by {} at {})",
        record.previous, record.by, record.at
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::state::key_fingerprint;
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    fn at_terminal() -> ui::Confirm {
        ui::Confirm {
            yes: false,
            json: false,
            stdin_is_terminal: true,
            yes_allowed: false,
        }
    }

    fn setup() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (
            URL_SAFE_NO_PAD.encode([1u8; 32]),
            URL_SAFE_NO_PAD.encode([2u8; 32]),
        );
        let mut p = Pins::default();
        p.root(&old);
        p.root(&new);
        p.save(&bus_dir(dir.path(), "a.example")).unwrap();
        (dir, old, new)
    }

    #[test]
    fn the_right_fingerprint_and_a_yes_move_the_pin_and_record_it() {
        let (dir, _, new) = setup();
        let fp = key_fingerprint(&new).unwrap();
        let mut out = Vec::new();
        repin(
            dir.path(),
            "a.example",
            &PinSlot::Root,
            Some(&fp),
            at_terminal(),
            &mut "y\n".as_bytes(),
            &mut out,
        )
        .unwrap();
        let p = Pins::load(&bus_dir(dir.path(), "a.example"));
        assert_eq!(p.root.as_deref(), Some(new.as_str()));
        assert!(p.root_repinned.unwrap().by.contains('@'));
        assert!(String::from_utf8(out).unwrap().contains(&fp));
    }

    #[test]
    fn a_wrong_fingerprint_a_no_or_no_terminal_leave_the_pin() {
        let (dir, old, new) = setup();
        let fp = key_fingerprint(&new).unwrap();
        let unchanged = |d: &Path| {
            assert_eq!(
                Pins::load(&bus_dir(d, "a.example")).root.as_deref(),
                Some(old.as_str())
            );
        };
        for typed in [key_fingerprint(&old).unwrap(), fp[..12].to_owned()] {
            assert!(repin(
                dir.path(),
                "a.example",
                &PinSlot::Root,
                Some(&typed),
                at_terminal(),
                &mut "y\n".as_bytes(),
                &mut Vec::new(),
            )
            .is_err());
            unchanged(dir.path());
        }
        assert!(repin(
            dir.path(),
            "a.example",
            &PinSlot::Root,
            Some(&fp),
            at_terminal(),
            &mut "\n".as_bytes(),
            &mut Vec::new(),
        )
        .is_err());
        unchanged(dir.path());
        // No terminal (a model running the command): refused, and no flag
        // can answer for a person.
        let mut how = ui::Confirm::person_only(false);
        how.stdin_is_terminal = false;
        how.yes = true;
        assert!(repin(
            dir.path(),
            "a.example",
            &PinSlot::Root,
            Some(&fp),
            how,
            &mut "y\n".as_bytes(),
            &mut Vec::new(),
        )
        .is_err());
        unchanged(dir.path());
        // Without a fingerprint it only shows.
        repin(
            dir.path(),
            "a.example",
            &PinSlot::Root,
            None,
            at_terminal(),
            &mut "y\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        unchanged(dir.path());
    }

    #[test]
    fn an_unknown_airdress_names_the_ones_there_are() {
        let (dir, _, _) = setup();
        let e = repin(
            dir.path(),
            "b.example",
            &PinSlot::Root,
            None,
            at_terminal(),
            &mut "".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("a.example"), "{e}");
    }
}
