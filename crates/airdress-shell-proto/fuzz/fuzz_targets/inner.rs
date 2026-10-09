//! The inner message decoder: a record's plaintext is a run of
//! `type ‖ length ‖ body`, binary or JSON by type. Whatever decodes
//! re-encodes and decodes to the same messages, in both forms.
#![no_main]

use airdress_shell_proto::inner::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(msgs) = Message::decode_all(data) else {
        return;
    };
    if let Ok(bytes) = Message::encode_all(&msgs) {
        let again = Message::decode_all(&bytes).expect("an encoding decodes");
        assert_eq!(again, msgs);
    }
    for m in &msgs {
        let json = serde_json::to_vec(m).expect("a message serializes");
        let back: Message = serde_json::from_slice(&json).expect("its JSON form decodes");
        assert_eq!(&back, m);
    }
});
