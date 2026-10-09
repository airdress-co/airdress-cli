//! The agent bus, client side: canonical bytes and signing, the device
//! host's socket, the operator's `/v1/agent-bus` routes, verifying what
//! other sessions wrote, and the little state this machine keeps about it
//! (pins, policies, delivery cursors).
//!
//! Not behind the `mls` feature: a bus write is signed by the device host
//! over its socket, so the MCP server needs no MLS engine to make one.
//! Nothing here holds a key or an account token of its own.

pub mod canon;
pub mod client;
pub mod socket;
pub mod sse;
pub mod state;
pub mod verify;
