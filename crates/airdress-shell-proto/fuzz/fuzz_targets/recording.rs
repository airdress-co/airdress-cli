//! A recording segment file, read by the first vector case's first
//! recipient: magic, header JSON, framed chunks. A header that parses
//! writes back bytes that parse to the same header.
#![no_main]

#[path = "common.rs"]
mod common;

use airdress_shell_proto::recording::{SegmentHeader, SegmentReader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let r = &common::recording()["cases"][0]["recipients"][0];
    let device = r["device"].as_str().unwrap();
    let secret = common::hex32(r["secret"].as_str().unwrap());
    if let Ok((h, _)) = SegmentHeader::parse(data) {
        let bytes = h.to_bytes().expect("a parsed header writes");
        assert_eq!(
            SegmentHeader::parse(&bytes)
                .expect("written header parses")
                .0,
            h
        );
    }
    let _ = SegmentReader::read_file(data, device, &secret);
});
