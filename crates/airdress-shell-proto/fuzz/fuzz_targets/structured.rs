//! The structured tier's body decoder: JSON in, one event or one input out.
//! What decodes writes back a body that decodes to the same thing.
#![no_main]

use airdress_shell_proto::structured::Body;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Ok(body) = Body::from_value(&v) else {
        return;
    };
    let written = body.to_value();
    assert_eq!(
        Body::from_value(&written).expect("a written body decodes"),
        body
    );
});
