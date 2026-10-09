//! What this machine remembers about one airdress's bus, under the
//! server's state dir: keys it has seen (pins), topic policies it has
//! seen, and where each session's reading has got to.
//!
//! Never a token or a private key. Each file is written beside and
//! renamed in, so a crash leaves the old one rather than half a new one.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

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
        if r == Pin::New {
            self.devices.insert(enrollment.to_owned(), key.to_owned());
        }
        r
    }

    /// Check (and on first sight pin) the airdress's root key.
    pub fn root(&mut self, key: &str) -> Pin {
        Self::check(&mut self.root, key)
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
