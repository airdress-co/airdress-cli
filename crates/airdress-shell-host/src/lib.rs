//! The shell host: `airdress shell host`, on a person's own machine.
//!
//! It runs the profiles that person wrote in `~/.config/airdress/shells.toml`
//! as sessions inside this one process, each on its own pseudo-terminal, and
//! serves them end to end to that person's enrolled devices through their
//! operator. The operator routes ciphertext; it never holds a key, and it
//! can never name a program, only a profile id.
//!
//! It runs while the person runs it (D-16, D-17): in the foreground, inside
//! their own multiplexer, or under the user unit they chose to install. It
//! never switches user and holds no privileged code (D-15).
#![deny(unsafe_code)]
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

pub mod binding;
pub mod channel;
pub mod commands;
pub mod duration;
pub mod emulator;
pub mod endpoint;
pub mod enroll;
pub mod environment;
pub mod frames;
pub(crate) mod fsx;
pub mod host;
pub mod install;
pub mod journal;
pub mod log_err;
pub mod paths;
pub mod probes;
pub mod profiles;
pub mod pty;
pub mod recording;
pub mod root;
pub mod roster;
pub mod run;
pub mod session;
pub mod structured;
pub mod trust;

#[cfg(feature = "testkit")]
pub mod testkit;
