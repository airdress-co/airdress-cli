//! What every target shares: the committed conformance vectors, so the keys
//! a target uses are the keys its seeds were made with.

#![allow(dead_code)]

use std::sync::OnceLock;

use rand_core::{CryptoRng, RngCore};

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("vector hex"))
        .collect()
}

pub fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("a 32-byte vector value")
}

fn parse(
    json: &'static str,
    cell: &'static OnceLock<serde_json::Value>,
) -> &'static serde_json::Value {
    cell.get_or_init(|| serde_json::from_str(json).expect("vector JSON"))
}

pub fn handshake() -> &'static serde_json::Value {
    static V: OnceLock<serde_json::Value> = OnceLock::new();
    parse(include_str!("../../tests/vectors/handshake.json"), &V)
}

pub fn records() -> &'static serde_json::Value {
    static V: OnceLock<serde_json::Value> = OnceLock::new();
    parse(include_str!("../../tests/vectors/records.json"), &V)
}

pub fn recording() -> &'static serde_json::Value {
    static V: OnceLock<serde_json::Value> = OnceLock::new();
    parse(include_str!("../../tests/vectors/recording.json"), &V)
}

/// Yields exactly the bytes it was given (a vector's ephemeral secret), then
/// zeros. Never used for a real key.
pub struct FixedRng(pub Vec<u8>, pub usize);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            *d = self.0.get(self.1).copied().unwrap_or(0);
            self.1 += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}
