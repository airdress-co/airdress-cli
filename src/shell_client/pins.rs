//! Host-key pinning (D-34, FR-E3, FR-C10).
//!
//! The first time this device connects to a host it shows the host's
//! shell-key fingerprint, beside the instruction to compare it with what
//! `airdress shell host` printed on that machine, and pins the key once the
//! person confirms. Every later connection uses the pinned key as the Noise
//! responder's static key, so a host presenting any other key fails the
//! handshake whatever the operator reports. A change in what the operator
//! reports is a full stop naming both fingerprints; there is no "continue".
//! The only way past it is [`Pins::repin`], with the fingerprint read on the
//! machine itself.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use airdress_shell_proto::keys::fingerprint;
use anyhow::{bail, Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// One pinned host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pin {
    /// The host's machine id when it was pinned.
    pub machine: String,
    /// The X25519 shell key, base64.
    pub key: String,
    /// Its fingerprint, as shown.
    pub fingerprint: String,
    /// When it was pinned (RFC 3339).
    pub pinned_at: String,
}

/// What a connection finds against the pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// Pinned, and the operator reports the same key.
    Pinned([u8; 32]),
    /// Never connected: show the fingerprint and ask.
    FirstUse {
        /// The key the operator reports.
        key: [u8; 32],
        /// Its fingerprint.
        fingerprint: String,
    },
    /// The operator reports another key than the one pinned.
    Changed {
        /// The pinned fingerprint.
        pinned: String,
        /// The reported fingerprint.
        reported: String,
    },
}

/// Every host this device pinned, for one airdress.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pins {
    #[serde(default)]
    hosts: BTreeMap<String, Pin>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

/// Decode a base64 X25519 key in any common spelling.
pub fn decode_key(raw: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let raw = raw.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(raw).ok())
        .and_then(|b| b.try_into().ok())
}

impl Pins {
    /// Load from `path`; a missing file is no pins.
    pub fn load(path: &Path) -> Result<Self> {
        let mut pins: Self = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .with_context(|| format!("read pinned host keys {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        pins.path = Some(path.to_owned());
        Ok(pins)
    }

    /// Write back, 0600.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        super::store::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    /// Check the key the operator reports for `host` against the pin.
    pub fn check(&self, host: &str, reported: &[u8; 32]) -> Result<PinCheck> {
        let reported_fp = fingerprint(reported);
        Ok(match self.hosts.get(host) {
            None => PinCheck::FirstUse {
                key: *reported,
                fingerprint: reported_fp,
            },
            Some(pin) => {
                let pinned = decode_key(&pin.key).context("a pinned key does not decode")?;
                if &pinned == reported {
                    PinCheck::Pinned(pinned)
                } else {
                    PinCheck::Changed {
                        pinned: pin.fingerprint.clone(),
                        reported: reported_fp,
                    }
                }
            }
        })
    }

    /// The pinned key of `host`, if any.
    pub fn get(&self, host: &str) -> Option<&Pin> {
        self.hosts.get(host)
    }

    /// Pin `key` for `host`, after the person confirmed its fingerprint.
    pub fn pin(&mut self, host: &str, machine: &str, key: &[u8; 32]) {
        self.hosts.insert(
            host.to_owned(),
            Pin {
                machine: machine.to_owned(),
                key: base64::engine::general_purpose::STANDARD.encode(key),
                fingerprint: fingerprint(key),
                pinned_at: chrono::Utc::now().to_rfc3339(),
            },
        );
    }

    /// Replace a pin, with a fingerprint the person read on the machine
    /// (`airdress shell host` prints it). Refused unless it is exactly the
    /// fingerprint of the key the operator now reports: a typed fingerprint
    /// is the evidence, not a confirmation of what is on screen.
    pub fn repin(
        &mut self,
        host: &str,
        machine: &str,
        reported: &[u8; 32],
        typed: &str,
    ) -> Result<()> {
        let fp = fingerprint(reported);
        if typed.trim() != fp {
            bail!(
                "the fingerprint you typed is not the key {host} reports now.\n  \
                 typed:    {}\n  reported: {fp}\nNothing was pinned.",
                typed.trim()
            );
        }
        self.pin(host, machine, reported);
        Ok(())
    }

    /// Forget a host.
    pub fn forget(&mut self, host: &str) -> bool {
        self.hosts.remove(host).is_some()
    }
}

/// The full stop for a changed key (design §13, client side).
pub fn changed_key_message(host: &str, pinned: &str, reported: &str) -> String {
    format!(
        "HOST KEY CHANGED for {host}\n\n  pinned:   {pinned}\n  reported: {reported}\n\n\
         This can mean the machine was re-enrolled, or someone is in the middle.\n\
         Nothing was sent to it. On the machine itself, read the key `airdress shell host` \
         prints, and if it is the reported one, pin it with:\n\n  \
         airdress shell repin {host} <fingerprint>\n"
    )
}

/// What the first connection shows (D-34).
pub fn first_use_message(host: &str, fp: &str) -> String {
    format!(
        "First connection to {host}.\n  Host key  {fp}\n\
         Compare it with what `airdress shell host` printed on that machine \
         (\"This host's key\")."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_then_pinned_then_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-hosts.json");
        let mut pins = Pins::load(&path).unwrap();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert!(matches!(
            pins.check("dev", &k1).unwrap(),
            PinCheck::FirstUse { .. }
        ));
        pins.pin("dev", "m1", &k1);
        pins.save().unwrap();
        let pins = Pins::load(&path).unwrap();
        assert_eq!(pins.check("dev", &k1).unwrap(), PinCheck::Pinned(k1));
        match pins.check("dev", &k2).unwrap() {
            PinCheck::Changed { pinned, reported } => {
                assert_eq!(pinned, fingerprint(&k1));
                assert_eq!(reported, fingerprint(&k2));
                let msg = changed_key_message("dev", &pinned, &reported);
                assert!(msg.contains(&pinned) && msg.contains(&reported));
            }
            other => panic!("{other:?}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn repin_needs_the_exact_fingerprint_of_the_reported_key() {
        let mut pins = Pins::default();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        pins.pin("dev", "m", &k1);
        assert!(pins.repin("dev", "m", &k2, &fingerprint(&k1)).is_err());
        assert_eq!(pins.check("dev", &k2).unwrap(), {
            PinCheck::Changed {
                pinned: fingerprint(&k1),
                reported: fingerprint(&k2),
            }
        });
        pins.repin("dev", "m", &k2, &fingerprint(&k2)).unwrap();
        assert_eq!(pins.check("dev", &k2).unwrap(), PinCheck::Pinned(k2));
    }
}
