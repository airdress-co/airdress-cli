//! SPEC-044 — device pairing surface.
//!
//! `airdress device pair` mints a SPEC-011 pairing code on the
//! current airdress's operator, renders a QR + deeplink for the
//! scanning client (`airdress-chat` on a phone), and polls until the
//! code is consumed. That assumes an owner is already bound to the
//! operator — SPEC-056's `airdress device bootstrap` is the one rung
//! below it, onboarding the first device on an operator that has none.
//! `airdress device revoke` retires one, with the same owner sign-in.

pub mod bootstrap;
pub mod client;
pub mod device_id;
pub mod pair;
pub mod qr;
pub mod revoke;
pub mod root_key;
pub mod watcher;
