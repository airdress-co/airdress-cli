//! `DeployStop`: why a deploy stopped on the client's side — one closed
//! enum, with the same codes in the CLI and the editor extension (SPEC-113
//! design §3.5). Both repositories carry `deploy-stops.txt`, and a test
//! holds each enum to its fixture; the two fixtures are compared byte for
//! byte across the repositories.
//!
//! An operator refusal is never one of these: it passes through verbatim
//! under the step that received it, and a code this client does not know is
//! shown as it arrived (FR-54).

/// Why a deploy stopped before or after its writes, on the client's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployStop {
    /// The dry run refused; the operator's refusal is attached.
    CheckFailed,
    /// The operator checked a different file set from the one held here.
    DigestMismatch,
    /// No signing key here.
    SignerUnavailable,
    /// This client's signer is not in the function's signer set.
    SignerNotThisClient,
    /// The person said no.
    ConfirmationDeclined,
    /// The promote route answers 404/405.
    OperatorPredatesPromote,
    /// The timeout passed with no verdict; the version is already promoted.
    NotLoadedInTime,
    /// `Loaded=False`, with a reason.
    LoadFailed,
    /// CI mode, and the function does not exist.
    FunctionMissing,
    /// The map file or a function directory is malformed.
    LayoutInvalid,
    /// A newer commit changes this function; this run yields (a success).
    Superseded,
    /// Promoted, but the manifest could not be rewritten.
    WriteBackFailed,
    /// The machine's approval lapsed.
    MachineAuthorizationExpired,
}

impl DeployStop {
    /// Every stop, in the fixture's order.
    pub const ALL: [Self; 13] = [
        Self::CheckFailed,
        Self::DigestMismatch,
        Self::SignerUnavailable,
        Self::SignerNotThisClient,
        Self::ConfirmationDeclined,
        Self::OperatorPredatesPromote,
        Self::NotLoadedInTime,
        Self::LoadFailed,
        Self::FunctionMissing,
        Self::LayoutInvalid,
        Self::Superseded,
        Self::WriteBackFailed,
        Self::MachineAuthorizationExpired,
    ];

    /// The wire code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::CheckFailed => "check_failed",
            Self::DigestMismatch => "digest_mismatch",
            Self::SignerUnavailable => "signer_unavailable",
            Self::SignerNotThisClient => "signer_not_this_client",
            Self::ConfirmationDeclined => "confirmation_declined",
            Self::OperatorPredatesPromote => "operator_predates_promote",
            Self::NotLoadedInTime => "not_loaded_in_time",
            Self::LoadFailed => "load_failed",
            Self::FunctionMissing => "function_missing",
            Self::LayoutInvalid => "layout_invalid",
            Self::Superseded => "superseded",
            Self::WriteBackFailed => "write_back_failed",
            Self::MachineAuthorizationExpired => "machine_authorization_expired",
        }
    }

    /// The one useful thing to do about it.
    pub const fn action(self) -> &'static str {
        match self {
            Self::CheckFailed => "fix the located line and deploy again",
            Self::DigestMismatch => "report a bug; nothing was signed",
            Self::SignerUnavailable => {
                "create a key (`airdress fn keygen --out <path>`), or point to one with \
                 --signing-key / AIRDRESS_FUNCTION_SIGNING_KEY"
            }
            Self::SignerNotThisClient => {
                "the owner adds this signer: `airdress fn signers add <name> --key <hex> | \
                 --machine <id>` (its own apply)"
            }
            Self::ConfirmationDeclined => "nothing was written",
            Self::OperatorPredatesPromote => {
                "publish, then apply the Function manifest with spec.source.version set to the \
                 version; or upgrade the operator"
            }
            Self::NotLoadedInTime => {
                "read `airdress describe Function/<name>` and `airdress fn logs <name>`; the \
                 version is already promoted"
            }
            Self::LoadFailed => "see the runbook entry for the condition's reason",
            Self::FunctionMissing => {
                "the owner creates the function once (`airdress fn deploy <dir>` from a \
                 workstation); CI never creates one"
            }
            Self::LayoutInvalid => "fix the named line",
            Self::Superseded => "nothing: a newer run deploys this function",
            Self::WriteBackFailed => "commit the printed line by hand",
            Self::MachineAuthorizationExpired => {
                "run `airdress-operator machine reauth`, then the owner approves it"
            }
        }
    }

    /// The exit status a deploy that stopped here ends with
    /// (`docs/exit-codes.md`).
    pub const fn exit(self) -> crate::exit::Exit {
        use crate::exit::Exit;
        match self {
            Self::CheckFailed
            | Self::SignerNotThisClient
            | Self::ConfirmationDeclined
            | Self::OperatorPredatesPromote
            | Self::LoadFailed
            | Self::FunctionMissing => Exit::Refused,
            Self::SignerUnavailable => Exit::Usage,
            Self::NotLoadedInTime => Exit::Network,
            Self::MachineAuthorizationExpired => Exit::Auth,
            Self::DigestMismatch
            | Self::LayoutInvalid
            | Self::WriteBackFailed
            | Self::Superseded => Exit::Internal,
        }
    }

    /// A stop that counts as success.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Superseded)
    }
}

impl std::fmt::Display for DeployStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture is the contract the extension's `stops.ts` is held to as
    /// well; a code added here and not there (or the reverse) fails one of
    /// the two tests and the cross-repository comparison.
    #[test]
    fn the_enum_equals_the_fixture() {
        let fixture = include_str!("deploy-stops.txt");
        let codes: Vec<&str> = DeployStop::ALL.iter().map(|s| s.code()).collect();
        assert_eq!(fixture, format!("{}\n", codes.join("\n")));
    }

    #[test]
    fn every_stop_names_an_action_and_only_superseded_succeeds() {
        for s in DeployStop::ALL {
            assert!(!s.action().is_empty(), "{s}");
            assert_eq!(s.is_success(), s == DeployStop::Superseded, "{s}");
        }
    }
}
