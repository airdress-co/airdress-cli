//! What this machine remembers about one airdress's bus, under the
//! server's state dir: keys it has seen (pins), topic policies it has
//! seen, and where each session's reading has got to.
//!
//! Never a token or a private key. Each file is written beside and
//! renamed in, so a crash leaves the old one rather than half a new one.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// How many pushed ids a session remembers (design §7.2).
pub const PUSHED_KEPT: usize = 500;

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path.parent().context("a state file with no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

/// The directory for one airdress's bus state.
pub fn bus_dir(state_dir: &Path, fqdn: &str) -> PathBuf {
    state_dir.join("bus").join(fqdn.replace(['/', '\\'], "_"))
}

// ---------------------------------------------------------------------
// pins
// ---------------------------------------------------------------------

/// Keys first seen, by what they speak for.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Pins {
    /// Device public key (base64url) per enrollment id.
    #[serde(default)]
    pub devices: BTreeMap<String, String>,
    /// The airdress's root public key (base64url).
    #[serde(default)]
    pub root: Option<String>,
    /// The operator's attestation keys (base64url) per kid.
    #[serde(default)]
    pub operator: BTreeMap<String, String>,
    /// The root key last seen that differs from the pin. Never trusted:
    /// it is what a person's typed fingerprint is compared against when
    /// they re-pin, and nothing else reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_seen: Option<String>,
    /// The same, per enrollment, for a device key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub devices_seen: BTreeMap<String, String>,
    /// Who re-pinned the root, when, and from what.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_repinned: Option<Repinned>,
    /// Who re-pinned each device key, when, and from what.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub devices_repinned: BTreeMap<String, Repinned>,
}

/// A re-pin, kept next to the pin it moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repinned {
    /// `<user>@<host>` that ran the command.
    pub by: String,
    /// RFC 3339.
    pub at: String,
    /// The fingerprint that was pinned before.
    pub previous: String,
}

/// What a pin check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// Seen for the first time, and now pinned.
    New,
    /// The same as last time.
    Same,
    /// Different from what was pinned. The pin is not moved.
    Changed { pinned: String },
}

/// `SHA256:<base64, no padding>` of a public key given in base64 (any
/// alphabet): the form a person compares, as for a machine or a shell host.
/// `None` when it does not decode.
pub fn key_fingerprint(key_b64: &str) -> Option<String> {
    let bytes = super::verify::b64(key_b64)?;
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(bytes))
    ))
}

/// Which pin a re-pin moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSlot {
    /// The airdress's root.
    Root,
    /// One enrollment's device key.
    Device(String),
}

impl std::fmt::Display for PinSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => f.write_str("the airdress's root key"),
            Self::Device(e) => write!(f, "the device key of enrollment {e}"),
        }
    }
}

/// Where a pin stands: what is pinned and what was last seen instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    /// Fingerprint of the pinned key, if any.
    pub pinned: Option<String>,
    /// Fingerprint of a different key last seen, if any.
    pub seen: Option<String>,
}

impl Pins {
    fn path(dir: &Path) -> PathBuf {
        dir.join("pins.json")
    }

    /// Load, or start empty.
    pub fn load(dir: &Path) -> Self {
        read_json(&Self::path(dir))
    }

    /// Save.
    ///
    /// # Errors
    /// The file could not be written.
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_json(&Self::path(dir), self)
    }

    fn check(slot: &mut Option<String>, seen: &str) -> Pin {
        match slot {
            None => {
                *slot = Some(seen.to_owned());
                Pin::New
            }
            Some(p) if p == seen => Pin::Same,
            Some(p) => Pin::Changed { pinned: p.clone() },
        }
    }

    /// Check (and on first sight pin) an enrollment's device key.
    pub fn device(&mut self, enrollment: &str, key: &str) -> Pin {
        let mut slot = self.devices.get(enrollment).cloned();
        let r = Self::check(&mut slot, key);
        match &r {
            Pin::New => {
                self.devices.insert(enrollment.to_owned(), key.to_owned());
            }
            Pin::Same => {
                self.devices_seen.remove(enrollment);
            }
            Pin::Changed { .. } => {
                self.devices_seen
                    .insert(enrollment.to_owned(), key.to_owned());
            }
        }
        r
    }

    /// Check (and on first sight pin) the airdress's root key.
    pub fn root(&mut self, key: &str) -> Pin {
        let r = Self::check(&mut self.root, key);
        match &r {
            Pin::Changed { .. } => self.root_seen = Some(key.to_owned()),
            Pin::Same => self.root_seen = None,
            Pin::New => {}
        }
        r
    }

    /// Check (and on first sight pin) an operator attestation key.
    pub fn operator(&mut self, kid: &str, key: &str) -> Pin {
        let mut slot = self.operator.get(kid).cloned();
        let r = Self::check(&mut slot, key);
        if r == Pin::New {
            self.operator.insert(kid.to_owned(), key.to_owned());
        }
        r
    }

    /// What is pinned in `slot`, and what was last seen instead.
    pub fn state(&self, slot: &PinSlot) -> PinState {
        let (pinned, seen) = match slot {
            PinSlot::Root => (self.root.as_deref(), self.root_seen.as_deref()),
            PinSlot::Device(e) => (
                self.devices.get(e).map(String::as_str),
                self.devices_seen.get(e).map(String::as_str),
            ),
        };
        PinState {
            pinned: pinned.and_then(key_fingerprint),
            seen: seen.and_then(key_fingerprint),
        }
    }

    /// Move a pin to the key last seen in its place, after a person read
    /// that key's fingerprint somewhere the operator cannot reach (a phone
    /// that holds the root; the agent machine itself for a device key).
    ///
    /// Refused unless `typed` is exactly the fingerprint of the key last
    /// seen: a typed fingerprint is the evidence, so an abbreviation, a
    /// different spelling or the old key's fingerprint moves nothing.
    /// Never called by anything but a person's command.
    ///
    /// # Errors
    /// Nothing different was seen, or `typed` is not its fingerprint.
    pub fn repin(&mut self, slot: &PinSlot, typed: &str, by: &str) -> Result<Repinned> {
        let state = self.state(slot);
        let Some(seen) = state.seen.clone() else {
            match &state.pinned {
                Some(p) if p == typed.trim() => {
                    anyhow::bail!("{slot} is already pinned at {p}; nothing to do")
                }
                Some(p) => anyhow::bail!(
                    "this machine has seen no other key for {slot} than the pinned one \
                     ({p}); nothing was pinned"
                ),
                None => {
                    anyhow::bail!("this machine has pinned no key for {slot}; nothing was pinned")
                }
            }
        };
        if typed.trim() != seen {
            anyhow::bail!(
                "the fingerprint you typed is not the key last seen for {slot}.\n  \
                 typed: {}\n  seen:  {seen}\nNothing was pinned.",
                typed.trim()
            );
        }
        let record = Repinned {
            by: by.to_owned(),
            at: chrono::Utc::now().to_rfc3339(),
            previous: state.pinned.unwrap_or_default(),
        };
        match slot {
            PinSlot::Root => {
                self.root = self.root_seen.take();
                self.root_repinned = Some(record.clone());
            }
            PinSlot::Device(e) => {
                if let Some(k) = self.devices_seen.remove(e) {
                    self.devices.insert(e.clone(), k);
                }
                self.devices_repinned.insert(e.clone(), record.clone());
            }
        }
        Ok(record)
    }
}

// ---------------------------------------------------------------------
// policies
// ---------------------------------------------------------------------

/// Each topic's `require_device_signature`, as last seen (FR-78).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Policies {
    #[serde(default)]
    pub require_device_signature: BTreeMap<String, bool>,
}

impl Policies {
    fn path(dir: &Path) -> PathBuf {
        dir.join("policies.json")
    }

    /// Load, or start empty.
    pub fn load(dir: &Path) -> Self {
        read_json(&Self::path(dir))
    }

    /// Save.
    ///
    /// # Errors
    /// The file could not be written.
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_json(&Self::path(dir), self)
    }

    /// Record what a topic's policy says now. Returns the warning to show
    /// the person when it was relaxed: a topic that accepted only
    /// device-signed writes now accepts operator-attested ones too.
    pub fn observe(&mut self, topic: &str, require_device_signature: bool) -> Option<String> {
        let before = self
            .require_device_signature
            .insert(topic.to_owned(), require_device_signature);
        (before == Some(true) && !require_device_signature).then(|| {
            format!(
                "Topic {topic} used to accept only device-signed writes and now also \
                 accepts operator-attested ones (from a hosted assistant). Only the \
                 airdress owner can change that; tell the user."
            )
        })
    }
}

// ---------------------------------------------------------------------
// delivery
// ---------------------------------------------------------------------

/// One session's reading position and what was pushed to it (§7.2).
///
/// Push never moves the cursor: an item pushed while channels are off (or
/// silently dropped by the client) is still returned by the next read,
/// marked `already_pushed` so a client that did see it can skip it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Delivery {
    #[serde(default)]
    pub cursor: i64,
    #[serde(default)]
    pub pushed: VecDeque<String>,
}

impl Delivery {
    fn path(dir: &Path, session: &str) -> PathBuf {
        dir.join("delivery").join(format!("{session}.json"))
    }

    /// Load, or start at the beginning.
    pub fn load(dir: &Path, session: &str) -> Self {
        read_json(&Self::path(dir, session))
    }

    /// Save.
    ///
    /// # Errors
    /// The file could not be written.
    pub fn save(&self, dir: &Path, session: &str) -> Result<()> {
        write_json(&Self::path(dir, session), self)
    }

    /// Remember that `id` was pushed. Returns false when it already was.
    pub fn pushed(&mut self, id: &str) -> bool {
        if self.was_pushed(id) {
            return false;
        }
        self.pushed.push_back(id.to_owned());
        while self.pushed.len() > PUSHED_KEPT {
            self.pushed.pop_front();
        }
        true
    }

    /// Whether `id` was pushed.
    pub fn was_pushed(&self, id: &str) -> bool {
        self.pushed.iter().any(|p| p == id)
    }

    /// A read reached `cursor`.
    pub fn advance(&mut self, cursor: i64) {
        self.cursor = self.cursor.max(cursor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relaxed_policy_is_said_once_and_a_tightened_one_never() {
        let mut p = Policies::default();
        assert!(p.observe("ops", false).is_none(), "first sight");
        assert!(p.observe("ops", true).is_none(), "tightened");
        let w = p.observe("ops", false).expect("relaxed");
        assert!(w.contains("ops") && w.contains("operator-attested"), "{w}");
        assert!(p.observe("ops", false).is_none(), "said once");
    }

    #[test]
    fn a_changed_key_is_reported_and_the_pin_stays() {
        let mut p = Pins::default();
        assert_eq!(p.device("e1", "k1"), Pin::New);
        assert_eq!(p.device("e1", "k1"), Pin::Same);
        assert_eq!(
            p.device("e1", "k2"),
            Pin::Changed {
                pinned: "k1".into()
            }
        );
        assert_eq!(p.devices["e1"], "k1");
        assert_eq!(p.root("r1"), Pin::New);
        assert!(matches!(p.root("r2"), Pin::Changed { .. }));
        assert_eq!(p.operator("k-1", "o1"), Pin::New);
        assert!(matches!(p.operator("k-1", "o2"), Pin::Changed { .. }));
    }

    #[test]
    fn a_repin_needs_the_exact_fingerprint_of_the_key_last_seen() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let old = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let new = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let (old_fp, new_fp) = (
            key_fingerprint(&old).unwrap(),
            key_fingerprint(&new).unwrap(),
        );
        let mut p = Pins::default();
        assert_eq!(p.root(&old), Pin::New);
        // Nothing else seen: nothing to move to.
        assert!(p.repin(&PinSlot::Root, &new_fp, "me@here").is_err());
        assert!(matches!(p.root(&new), Pin::Changed { .. }));
        let st = p.state(&PinSlot::Root);
        assert_eq!(st.pinned.as_deref(), Some(old_fp.as_str()));
        assert_eq!(st.seen.as_deref(), Some(new_fp.as_str()));
        // The old one, an abbreviation, and another spelling are refused,
        // and leave the pin where it was.
        for wrong in [
            old_fp.clone(),
            new_fp[..20].to_owned(),
            new_fp.to_lowercase(),
        ] {
            assert!(
                p.repin(&PinSlot::Root, &wrong, "me@here").is_err(),
                "{wrong}"
            );
            assert_eq!(p.root.as_deref(), Some(old.as_str()));
        }
        let r = p.repin(&PinSlot::Root, &new_fp, "me@here").unwrap();
        assert_eq!(r.previous, old_fp);
        assert_eq!(r.by, "me@here");
        assert_eq!(p.root.as_deref(), Some(new.as_str()));
        assert!(p.root_seen.is_none());
        assert_eq!(p.root(&new), Pin::Same);
        assert_eq!(p.root_repinned.as_ref().unwrap().previous, old_fp);

        // A device key, the same way.
        assert_eq!(p.device("e1", &old), Pin::New);
        assert!(matches!(p.device("e1", &new), Pin::Changed { .. }));
        let slot = PinSlot::Device("e1".into());
        assert!(p.repin(&slot, &old_fp, "me@here").is_err());
        assert_eq!(p.devices["e1"], old);
        p.repin(&slot, &new_fp, "me@here").unwrap();
        assert_eq!(p.device("e1", &new), Pin::Same);
        assert!(p.devices_repinned.contains_key("e1"));
    }

    #[test]
    fn an_old_pins_file_still_reads() {
        let p: Pins =
            serde_json::from_str(r#"{"devices":{"e":"k"},"root":"r","operator":{}}"#).unwrap();
        assert_eq!(p.root.as_deref(), Some("r"));
        assert!(p.root_seen.is_none() && p.root_repinned.is_none());
    }

    #[test]
    fn delivery_survives_a_restart_and_forgets_only_past_five_hundred() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Delivery::default();
        assert!(d.pushed("m1"));
        assert!(!d.pushed("m1"));
        d.advance(9);
        d.advance(3);
        d.save(dir.path(), "s").unwrap();
        let back = Delivery::load(dir.path(), "s");
        assert_eq!(back.cursor, 9, "never moves back");
        assert!(back.was_pushed("m1"));
        let mut d = back;
        for i in 0..PUSHED_KEPT {
            d.pushed(&format!("x{i}"));
        }
        assert!(!d.was_pushed("m1"));
        assert_eq!(d.pushed.len(), PUSHED_KEPT);
    }
}
