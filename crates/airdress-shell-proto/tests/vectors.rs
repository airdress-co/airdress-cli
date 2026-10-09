//! The conformance vectors (design §14.2): the committed files are exactly
//! what the generator produces, and every file verifies.
//!
//! Regenerate after a deliberate protocol change with
//! `AIRDRESS_REGEN_VECTORS=1 cargo test -p airdress-shell-proto --features conformance --test vectors`,
//! and commit the files: the app and the editor run the same ones.

use std::path::PathBuf;

use airdress_shell_proto::conformance::generate::all_files;
use airdress_shell_proto::vectors::verify;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn committed_vectors_match_the_generator() {
    let regen = std::env::var("AIRDRESS_REGEN_VECTORS").is_ok_and(|v| v == "1");
    for (name, content) in all_files() {
        let path = dir().join(name);
        if regen {
            std::fs::write(&path, &content).expect("write vector");
            continue;
        }
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{name} is missing; regenerate the vectors"));
        assert!(
            committed == content,
            "{name} differs from the generator: a protocol byte changed. \
             If deliberate, regenerate and commit."
        );
    }
}

#[test]
fn every_vector_file_verifies() {
    let mut total = 0;
    for (name, _) in all_files() {
        let bytes = std::fs::read(dir().join(name)).expect("vector file");
        let n = verify(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(n > 0, "{name} checked nothing");
        total += n;
    }
    assert!(total >= 40, "only {total} cases");
}

#[test]
fn a_flipped_byte_in_any_vector_fails() {
    // The verifier must actually compare: corrupt one expected byte string
    // in each file and it refuses.
    for (name, content) in all_files() {
        let mut v: serde_json::Value = serde_json::from_str(&content).unwrap();
        let target = match name {
            "handshake.json" => &mut v["cases"][0]["msg2"],
            "records.json" => &mut v["seal"][1]["record"],
            "presence.json" => &mut v["unlock"][0]["sig"],
            "recording.json" => &mut v["cases"][0]["file"],
            "inner.json" => &mut v["cases"][0]["bytes"],
            "structured.json" => &mut v["bodies"][0]["state"],
            _ => unreachable!(),
        };
        let s = target.as_str().unwrap().to_owned();
        let last = s.len() - 1;
        let flipped = if &s[last..] == "0" { "1" } else { "0" };
        *target = serde_json::Value::String(format!("{}{}", &s[..last], flipped));
        assert!(
            verify(serde_json::to_string(&v).unwrap().as_bytes()).is_err(),
            "{name} accepted a corrupted vector"
        );
    }
}
