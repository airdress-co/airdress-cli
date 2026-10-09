//! SPEC-033 — `airdress apply / get / describe / delete / diff`.
//!
//! Operator-direct via the existing SPEC-044 ZITADEL bearer path.
//! YAML primary, JSON accepted. Multi-doc YAML supported via `---`
//! separators per SPEC-033 §8.5.

pub mod apply;
pub mod client;
pub mod delete;
pub mod describe;
pub mod diff;
pub mod get;
pub mod parse;
pub mod thing;
