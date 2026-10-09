//! The bytes every handshake is bound to (design §6.5).
//!
//! `"airdress.shell.e2e.v1" ‖ 0x00 ‖ airdress ‖ 0x1F ‖ machine_id ‖ 0x1F ‖
//! session_id ‖ 0x1F ‖ profile_id ‖ 0x1F ‖ action`
//!
//! A message for one session, profile or action never completes as another,
//! because both ends mix these bytes into the handshake hash before the
//! first DH.

use serde::{Deserialize, Serialize};

use crate::error::{ProtoError, Result};

/// The label that opens the prologue. Its `v1` is the protocol version.
pub const PROLOGUE_LABEL: &[u8] = b"airdress.shell.e2e.v1";

/// Why a handshake is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// A new session: the host spawns the profile once every check passes.
    Open,
    /// A device joins a running session again, with a full `IK` handshake.
    Attach,
    /// A device resumes a dropped leg with a ticket (`IKpsk2`).
    Resume,
}

impl Action {
    /// The ASCII word this action is written as, in the prologue and in the
    /// presence message.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Open => "open",
            Action::Attach => "attach",
            Action::Resume => "resume",
        }
    }

    /// Parse the ASCII word.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Action::Open),
            "attach" => Ok(Action::Attach),
            "resume" => Ok(Action::Resume),
            _ => Err(ProtoError::InvalidInput("unknown action")),
        }
    }
}

/// What a handshake is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prologue {
    /// The airdress the host is enrolled with.
    pub airdress: String,
    /// The host's machine id.
    pub machine_id: String,
    /// The session the leg belongs to.
    pub session_id: String,
    /// The profile id (never a program: FR-P2).
    pub profile_id: String,
    /// Open, attach or resume.
    pub action: Action,
}

impl Prologue {
    /// The prologue bytes.
    ///
    /// A field containing `0x00` or `0x1F` is refused rather than escaped:
    /// none of these identifiers can contain one legitimately, and a
    /// separator inside a field is the one way two different prologues could
    /// produce the same bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let fields = [
            self.airdress.as_bytes(),
            self.machine_id.as_bytes(),
            self.session_id.as_bytes(),
            self.profile_id.as_bytes(),
        ];
        for f in fields {
            if f.is_empty() {
                return Err(ProtoError::InvalidInput("empty prologue field"));
            }
            if f.iter().any(|b| *b == 0x00 || *b == 0x1F) {
                return Err(ProtoError::InvalidInput(
                    "separator byte in a prologue field",
                ));
            }
        }
        let mut out = Vec::with_capacity(
            PROLOGUE_LABEL.len() + 1 + fields.iter().map(|f| f.len() + 1).sum::<usize>() + 8,
        );
        out.extend_from_slice(PROLOGUE_LABEL);
        out.push(0x00);
        for f in fields {
            out.extend_from_slice(f);
            out.push(0x1F);
        }
        out.extend_from_slice(self.action.as_str().as_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Prologue {
        Prologue {
            airdress: "a1".into(),
            machine_id: "m1".into(),
            session_id: "s1".into(),
            profile_id: "p1".into(),
            action: Action::Open,
        }
    }

    #[test]
    fn layout() {
        assert_eq!(
            p().to_bytes().unwrap(),
            b"airdress.shell.e2e.v1\x00a1\x1fm1\x1fs1\x1fp1\x1fopen".to_vec()
        );
    }

    #[test]
    fn separators_in_fields_are_refused() {
        let mut q = p();
        q.session_id = "s\x1f1".into();
        assert!(q.to_bytes().is_err());
        q.session_id = "s\x001".into();
        assert!(q.to_bytes().is_err());
        q.session_id = String::new();
        assert!(q.to_bytes().is_err());
    }

    #[test]
    fn every_field_changes_the_bytes() {
        let base = p().to_bytes().unwrap();
        let mut q = p();
        q.action = Action::Attach;
        assert_ne!(q.to_bytes().unwrap(), base);
        let mut q = p();
        q.profile_id = "p2".into();
        assert_ne!(q.to_bytes().unwrap(), base);
    }
}
