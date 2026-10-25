//! Pure place logic for the Airdress map tools: the map address writer
//! (`map_link`), the layer catalogue snapshot its switch defaults come
//! from, and how search answers are shaped for an agent, including the
//! rule that the tools never recommend places.
//!
//! No I/O, no clock: every function is a function of its arguments, so
//! the MCP server and, later, an operator can share one implementation.
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

pub mod address;
pub mod link;
pub mod search;

pub use address::{format_address, Options, State, MAX_FRAGMENT};
pub use link::{link, options_from_catalogue, snapshot, Link, CATALOGUE_SNAPSHOT, MAP_URL};
