//! The record layer's receiver under the vectors' key: a run of operations,
//! each either a record to open (`0 ‖ len (u16 BE) ‖ record`) or a peer
//! rekey announcement (`1 ‖ switch_at (u64 BE)`). No nonce opens twice, and
//! an opened record's plaintext is its ciphertext less the tag.
#![no_main]

#[path = "common.rs"]
mod common;

use std::collections::HashSet;

use airdress_shell_proto::record::{RecvState, NONCE_LEN, TAG_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = common::hex32(common::records()["seal"][0]["key"].as_str().unwrap());
    let mut recv = RecvState::new(key);
    let mut opened = HashSet::new();
    let mut rest = data;
    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        if op % 2 == 0 {
            if rest.len() < 2 {
                return;
            }
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
            let record = &rest[2..2 + len];
            rest = &rest[2 + len..];
            if let Ok((n, pt)) = recv.open(record) {
                assert!(opened.insert(n), "nonce {n} opened twice");
                assert_eq!(pt.len(), record.len() - NONCE_LEN - TAG_LEN);
            }
        } else {
            if rest.len() < 8 {
                return;
            }
            let at = u64::from_be_bytes(rest[..8].try_into().unwrap());
            rest = &rest[8..];
            recv.note_peer_rekey(at);
        }
    }
});
