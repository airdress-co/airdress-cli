//! The host's local commands, run by the person at the machine (design
//! §7.4): `status`, `trust`, `devices`, `recordings`, `reauth`, and the
//! profile file's `profile add|edit|remove|list|show|check`.
//!
//! None of these is reachable from the network: they read and write the
//! host's own files on this machine, as the user who runs them.

use std::io::{IsTerminal as _, Write};

use anyhow::{Context, Result};

use crate::binding::{Authorization, Binding};
use crate::paths::Paths;
use crate::profiles::{self, ProfileEdit};
use crate::trust::{b64, identity_fingerprint, DeviceStore, TrustSource};

/// Whether a host process holds the lock for `airdress`, and its pid.
pub fn running_pid(paths: &Paths, airdress: &str) -> Option<String> {
    match crate::binding::lock(paths, airdress) {
        Ok(_held) => None,
        Err(e) => {
            let m = e.to_string();
            m.split("(pid ")
                .nth(1)
                .and_then(|r| r.split(')').next())
                .map(str::to_owned)
        }
    }
}

/// `airdress shell host status`.
pub fn status(paths: &Paths, out: &mut dyn Write) -> Result<()> {
    let Some(b) = Binding::load(paths)? else {
        writeln!(
            out,
            "Not enrolled. Run `airdress shell host --operator https://<your airdress>`."
        )?;
        return Ok(());
    };
    let shell = crate::binding::load_shell_key(paths)?;
    writeln!(out, "{}", b.describe(shell.public()))?;
    writeln!(out, "Machine        {}", b.machine_id)?;
    match Authorization::load(paths).authorized_until {
        Some(u) => writeln!(out, "Approved until {u}")?,
        None => writeln!(out, "Approved until (no expiry)")?,
    }
    match running_pid(paths, &b.airdress) {
        Some(pid) => writeln!(out, "Running        yes (pid {pid})")?,
        None => writeln!(out, "Running        no")?,
    }
    writeln!(
        out,
        "Autostart      {}",
        if paths.install_manifest().exists() {
            "systemd user unit"
        } else {
            "none"
        }
    )?;
    if crate::root::runs_as_root() {
        writeln!(out, "{}", crate::root::banner())?;
    }
    match profiles::load(paths) {
        Ok(f) => {
            writeln!(
                out,
                "Profiles       {} (at most {} sessions)",
                f.profiles.len(),
                f.host.max_sessions
            )?;
            for p in &f.profiles {
                writeln!(out, "  {:<20} {:<30} {}", p.id, p.label, p.state_text())?;
            }
        }
        Err(e) => writeln!(out, "Profiles       refused: {e:#}")?,
    }
    let s = DeviceStore::load(paths)?;
    writeln!(
        out,
        "Devices        {} trusted, {} waiting to be trusted, {} revoked",
        s.devices.len(),
        s.pending.len(),
        s.revoked.len()
    )?;
    writeln!(
        out,
        "Recordings     {}",
        crate::recording::list(paths).len()
    )?;
    Ok(())
}

/// `airdress shell host devices`.
pub fn devices(paths: &Paths, out: &mut dyn Write) -> Result<()> {
    let s = DeviceStore::load(paths)?;
    let fp = |identity: &str| {
        b64(identity)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map_or_else(|| "(malformed)".into(), |k| identity_fingerprint(&k))
    };
    for (id, d) in &s.devices {
        let how = match d.source {
            TrustSource::Delegation => "root delegation",
            TrustSource::Confirmed => "confirmed here",
            TrustSource::Introduced => "introduced",
        };
        let state = if s.revoked.contains(id) {
            "revoked"
        } else {
            "trusted"
        };
        writeln!(
            out,
            "{state:<8} {id}  {:<6} {:<16} {}  {}",
            d.kind,
            how,
            fp(&d.identity),
            d.label.as_deref().unwrap_or("")
        )?;
    }
    for (id, p) in &s.pending {
        writeln!(
            out,
            "waiting  {id}  {:<6} {:<16} {}  {}",
            p.kind_claimed.as_deref().unwrap_or("?"),
            "not introduced",
            fp(&p.identity),
            p.label.as_deref().unwrap_or("")
        )?;
    }
    for id in s.revoked.iter().filter(|d| !s.devices.contains_key(d)) {
        writeln!(out, "revoked  {id}")?;
    }
    if s.devices.is_empty() && s.pending.is_empty() && s.revoked.is_empty() {
        writeln!(out, "No device has asked this host yet.")?;
    }
    Ok(())
}

/// `airdress shell host trust <fingerprint>`: the person at this machine
/// confirms a device that asked before it was introduced (design §6.3
/// step 5).
///
/// `confirm` asks the question and returns `Ok` only on a yes. The CLI
/// passes its one prompt (`ui::confirm`), which asks only a person at a real
/// terminal and is never answered by a flag; this crate asks nothing itself.
pub fn trust(
    paths: &Paths,
    fingerprint: &str,
    kind: Option<&str>,
    confirm: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut s = DeviceStore::load(paths)?;
    let (id, p) = s
        .pending
        .iter()
        .find(|(_, p)| {
            b64(&p.identity)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .is_some_and(|k| identity_fingerprint(&k) == fingerprint.trim())
        })
        .map(|(id, p)| (*id, p.clone()))
        .with_context(|| {
            format!(
                "neither the operator nor a device that asked names {fingerprint}; check the \
                 fingerprint, or open a session from the device and run this again \
                 (`airdress shell host devices` lists who is waiting)"
            )
        })?;
    let claimed = p.kind_claimed.as_deref();
    let kind = kind
        .map(str::to_owned)
        .or(p.kind_claimed.clone())
        .unwrap_or_else(|| "phone".into());
    let said = match claimed {
        Some(c) if c == kind => {
            format!(" (the operator says it is a `{c}`; `--kind` changes that)")
        }
        Some(c) => format!(" (the operator says `{c}`)"),
        None => String::new(),
    };
    confirm(&format!(
        "Trust {} ({id}) as a device of kind `{kind}`{said}?\nIts key: {fingerprint}\n\
         Compare it with what that device shows. A `cli` device opens sessions without an unlock.",
        p.label.as_deref().unwrap_or("this device"),
    ))?;
    s.confirm(fingerprint, &kind)?;
    s.save(paths)?;
    Ok(())
}

/// Whether stdin and stdout are both a terminal.
pub fn at_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// `trust` on the process's own terminal. A fingerprint no device that
/// knocked carries is looked up in the operator's list of the person's
/// devices first (design §6.3), so the first device can be trusted before
/// it ever connects.
pub async fn trust_here(
    paths: &Paths,
    fingerprint: &str,
    kind: Option<&str>,
    ca_file: Option<&std::path::Path>,
    confirm: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let waiting = DeviceStore::load(paths)?.pending.values().any(|p| {
        b64(&p.identity)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .is_some_and(|k| identity_fingerprint(&k) == fingerprint.trim())
    });
    if !waiting && at_terminal() {
        if let Some(b) = Binding::load(paths)? {
            let http = crate::run::http_client(ca_file)?;
            if let Err(e) = crate::roster::refresh(paths, &http, &b).await {
                eprintln!("Could not read your devices from the operator: {e:#}");
            }
        }
    }
    trust(paths, fingerprint, kind, confirm)
}

/// `airdress shell host recordings list`.
pub fn recordings_list(paths: &Paths, out: &mut dyn Write) -> Result<()> {
    let l = crate::recording::list(paths);
    if l.is_empty() {
        writeln!(out, "No recordings.")?;
    }
    for r in l {
        writeln!(
            out,
            "{}  {:<20} {}  {} segment(s)",
            r.recording, r.profile, r.started_at, r.segments
        )?;
    }
    Ok(())
}

/// `airdress shell host recordings prune`.
pub fn recordings_prune(paths: &Paths, out: &mut dyn Write) -> Result<()> {
    let n = crate::recording::prune(paths, std::time::SystemTime::now());
    writeln!(out, "Removed {n} recording(s) past their retention.")?;
    Ok(())
}

/// `airdress shell host reauth`.
pub async fn reauth(paths: &Paths, ca_file: Option<&std::path::Path>) -> Result<()> {
    let b = Binding::load(paths)?.context("not enrolled")?;
    let http = crate::run::http_client(ca_file)?;
    crate::enroll::reauth(paths, &http, &b, &mut std::io::stderr()).await
}

/// `airdress shell profile list`.
pub fn profile_list(paths: &Paths, out: &mut dyn Write) -> Result<()> {
    let f = profiles::load(paths)?;
    if f.profiles.is_empty() {
        writeln!(out, "No profiles in {}.", paths.profiles_file().display())?;
    }
    for p in &f.profiles {
        writeln!(
            out,
            "{:<20} {:<30} {:<24} {}",
            p.id,
            p.label,
            p.kind,
            p.state_text()
        )?;
    }
    Ok(())
}

/// `airdress shell profile show <id>`.
pub fn profile_show(paths: &Paths, id: &str, out: &mut dyn Write) -> Result<()> {
    write!(out, "{}", profiles::show(paths, id)?)?;
    Ok(())
}

/// `airdress shell profile add`.
pub fn profile_add(paths: &Paths, id: &str, edit: &ProfileEdit, out: &mut dyn Write) -> Result<()> {
    let path = std::env::var("PATH").ok();
    let f = profiles::add(paths, id, edit, path.as_deref())?;
    let p = f.get(id).context("added")?;
    writeln!(
        out,
        "Added `{id}` ({}). A running host offers it within a second.",
        p.state_text()
    )?;
    Ok(())
}

/// `airdress shell profile edit`.
pub fn profile_edit(
    paths: &Paths,
    id: &str,
    edit: &ProfileEdit,
    out: &mut dyn Write,
) -> Result<()> {
    let path = std::env::var("PATH").ok();
    let f = profiles::edit(paths, id, edit, path.as_deref())?;
    let p = f.get(id).context("edited")?;
    writeln!(
        out,
        "Changed `{id}` ({}). Devices are told it changed.",
        p.state_text()
    )?;
    Ok(())
}

/// `airdress shell profile remove`.
pub fn profile_remove(paths: &Paths, id: &str, out: &mut dyn Write) -> Result<()> {
    profiles::remove(paths, id)?;
    writeln!(out, "Removed `{id}`. Sessions already open keep running.")?;
    Ok(())
}

/// `airdress shell profile check`.
pub fn profile_check(paths: &Paths, out: &mut dyn Write) -> Result<bool> {
    let path = std::env::var("PATH").ok();
    let (f, resolved) = profiles::check(paths, path.as_deref())?;
    for r in resolved {
        writeln!(out, "resolved {r}")?;
    }
    let mut ok = true;
    for p in &f.profiles {
        writeln!(out, "{:<20} {}", p.id, p.state_text())?;
        ok &= p.state == profiles::State::Ready;
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    #[test]
    fn trust_needs_a_yes() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        let mut s = DeviceStore::default();
        let id = uuid::Uuid::from_u128(5);
        let key = [9u8; 32];
        s.pending.insert(
            id,
            crate::trust::PendingDevice {
                identity: crate::binding::b64_std(&key),
                kind_claimed: Some("cli".into()),
                label: Some("laptop".into()),
                at: chrono::Utc::now(),
            },
        );
        s.save(&p).unwrap();
        let fp = identity_fingerprint(&key);
        let mut asked = String::new();
        let mut no = |q: &str| -> Result<()> {
            asked = q.to_owned();
            bail!("declined")
        };
        assert!(trust(&p, &fp, None, &mut no).is_err(), "no");
        assert!(DeviceStore::load(&p).unwrap().devices.is_empty());
        assert!(asked.contains("without an unlock"), "{asked}");
        trust(&p, &fp, None, &mut |_| Ok(())).unwrap();
        let after = DeviceStore::load(&p).unwrap();
        assert_eq!(after.devices[&id].kind, "cli");
        assert!(after.pending.is_empty());
    }

    #[test]
    fn status_says_when_not_enrolled() {
        let d = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        status(&Paths::under(d.path()), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("Not enrolled"));
    }
}
