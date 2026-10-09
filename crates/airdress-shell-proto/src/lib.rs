//! The end-to-end protocol between an enrolled device and a shell host.
//!
//! One crate owns every byte the two ends must agree on, so that the host,
//! the CLI, the Android app (through the C ABI in [`ffi`]) and the editor
//! extension (through a wasm build) run the same code rather than four
//! implementations of a security protocol (design §2.3, SPEC-137).
//!
//! What lives here:
//!
//! - [`prologue`]: the bytes every handshake is bound to;
//! - [`handshake`]: Noise `IK` for an open or a reattach, and `IKpsk2` for a
//!   resume within a live leg;
//! - [`record`]: the explicit-nonce record layer, its replay window and rekey;
//! - [`ticket`]: single-use resumption tickets, valid 120 s after a leg drops;
//! - [`presence`]: the unlock signature, the device-key statement and the
//!   rule that only a CLI-kind device may go without a presence key;
//! - [`inner`]: the messages carried inside the records;
//! - [`structured`]: the structured tier's neutral event model and its
//!   JSON Schema;
//! - [`recording`]: chunk sealing, per-recipient key wrapping, segment roll
//!   and rewrap for recordings the host itself cannot read back.
//!
//! What does not: any I/O, any clock, any thread. Time is passed in as
//! milliseconds by the caller, and randomness as an RNG, so the wasm build
//! needs nothing from its environment and the vectors are reproducible.
//!
//! ## Wire compatibility
//!
//! Two rules decide whether a JSON structure tolerates a field it does not
//! know (rust guide R-API-2):
//!
//! - **Negotiation and display payloads are open.** The hellos
//!   ([`handshake::DeviceHello`], [`handshake::HostHello`]) and the
//!   structured tier's bodies ([`structured::Event`], [`structured::Input`]
//!   and what they nest) ignore unknown fields, so a newer peer can add one
//!   without breaking an older peer that is already in the field. They are
//!   read inside the AEAD, so tolerance there changes no authenticated byte.
//! - **Anything signed, hashed or bound into a transcript stays closed**
//!   (`deny_unknown_fields`): [`presence::DeviceKeys`], the recording
//!   [`recording::SegmentHeader`] and its [`recording::RecipientEntry`]. A
//!   field a verifier skipped is a field it vouched for without reading. The
//!   inner messages ([`inner::Message`]) stay closed too: their type byte is
//!   the protocol version, and an unknown one is malformed, not skippable.
//!
//! **A field added to an open structure is `Option` or `#[serde(default)]`**,
//! with `skip_serializing_if` so an older writer's bytes are unchanged and a
//! newer reader of an older peer sees the default. A field whose absence an
//! older peer would misread (one that changes meaning, not one that adds
//! information) is not an addition; it waits for version negotiation.
//!
//! `unsafe` is denied everywhere except the C ABI module.
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Every unsafe operation is spelled out and justified where it happens,
// and every unsafe fn says what its caller owes (rust guide R-UNS-2).
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]
#![allow(
    clippy::map_err_ignore,
    reason = "errors are a closed wire enum; a discarded cause is the contract"
)]
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

mod b64;
pub mod error;
pub mod handshake;
pub mod inner;
pub mod keys;
pub mod presence;
pub mod prologue;
pub mod record;
pub mod recording;
pub mod structured;
pub mod ticket;
pub mod vectors;

#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use error::{ProtoError, Result};

/// The protocol version this crate speaks. It is bound into every handshake
/// through the prologue label, so two ends of different versions fail the
/// handshake rather than misreading each other.
pub const PROTOCOL_VERSION: u32 = 1;
