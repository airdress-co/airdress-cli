//! One error type, with the wire code each failure is reported as.

use core::fmt;

/// Everything the protocol can refuse.
///
/// [`ProtoError::code`] gives the code a host or client puts on the wire
/// (design §13). Several variants share a code on purpose: a peer learns
/// that a handshake failed, not which of its checks did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// A Noise failure: a bad message, the wrong static key, a prologue that
    /// does not match.
    Handshake(&'static str),
    /// The initiator's static key is not the one the operator attested.
    UnexpectedRemoteKey,
    /// A record that does not authenticate under any key this channel holds.
    RecordAuth,
    /// A record whose nonce is outside the replay window, or already seen.
    Replay,
    /// A record shorter than its header, or a nonce at the reserved maximum.
    RecordMalformed,
    /// The sending nonce space is exhausted; the channel must be replaced.
    NonceExhausted,
    /// The unlock signature is missing, malformed or does not verify, or a
    /// device without a presence key is not of the CLI kind.
    PresenceRequired(&'static str),
    /// The device's own statement of its keys does not verify.
    DeviceKeysInvalid(&'static str),
    /// A resumption ticket that is unknown, expired or already used.
    ResumeExpired,
    /// An inner message that does not decode.
    InnerMalformed(&'static str),
    /// A recording that does not open: no entry for this device, a bad
    /// wrap, a chunk that does not authenticate, or a truncated segment.
    Recording(&'static str),
    /// An argument the caller should not have passed (a field containing a
    /// separator byte, a key of the wrong length).
    InvalidInput(&'static str),
    /// The caller's RNG failed.
    Rng,
}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, ProtoError>;

impl ProtoError {
    /// The code this failure is reported as on the wire (design §13).
    pub fn code(&self) -> &'static str {
        match self {
            ProtoError::Handshake(_) | ProtoError::UnexpectedRemoteKey => "shell_handshake_failed",
            ProtoError::PresenceRequired(_) | ProtoError::DeviceKeysInvalid(_) => {
                "shell_presence_required"
            }
            ProtoError::ResumeExpired => "shell_resume_expired",
            ProtoError::RecordAuth
            | ProtoError::Replay
            | ProtoError::RecordMalformed
            | ProtoError::NonceExhausted => "shell_record_rejected",
            ProtoError::InnerMalformed(_) => "shell_message_malformed",
            ProtoError::Recording(_) => "shell_recording_unreadable",
            ProtoError::InvalidInput(_) => "shell_invalid_input",
            ProtoError::Rng => "shell_rng_failed",
        }
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::Handshake(why) => write!(f, "handshake failed: {why}"),
            ProtoError::UnexpectedRemoteKey => {
                write!(
                    f,
                    "handshake failed: the peer's key is not the attested one"
                )
            }
            ProtoError::RecordAuth => write!(f, "record does not authenticate"),
            ProtoError::Replay => write!(f, "record replayed or outside the window"),
            ProtoError::RecordMalformed => write!(f, "record malformed"),
            ProtoError::NonceExhausted => write!(f, "nonce space exhausted"),
            ProtoError::PresenceRequired(why) => write!(f, "presence required: {why}"),
            ProtoError::DeviceKeysInvalid(why) => write!(f, "device keys invalid: {why}"),
            ProtoError::ResumeExpired => write!(f, "resumption ticket expired or used"),
            ProtoError::InnerMalformed(why) => write!(f, "inner message malformed: {why}"),
            ProtoError::Recording(why) => write!(f, "recording: {why}"),
            ProtoError::InvalidInput(why) => write!(f, "invalid input: {why}"),
            ProtoError::Rng => write!(f, "random number generator failed"),
        }
    }
}

impl std::error::Error for ProtoError {}
