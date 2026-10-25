//! The map address vectors: the page's own cases, pinned (SPEC-171 design
//! §9.4). The page's tests and this writer pass the same file, so a link
//! written here opens what the page itself would have written.
//!
//! Only `format` cases run: this crate writes links and never reads one.
//! The `parse` cases are the page's, and are kept in the copy so that the
//! pinned file stays byte for byte the page's.

use std::path::{Path, PathBuf};

use airdress_place::address::{format_address, Options, State, MAX_FRAGMENT};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of the pinned copy. Moved only together with a new copy of the
/// maps repository's `services/maps-front/web/test/fixtures/address-vectors.json`.
const PINNED_SHA256: &str = "244343370b955758a39b52d3446f635b428b8e80a428baeb9032f7f252aa92e3";

/// Where the maps repository's own file is, relative to its checkout.
const UPSTREAM: &str = "services/maps-front/web/test/fixtures/address-vectors.json";

fn pinned_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/address-vectors.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `bytes` are the pinned vectors.
fn pin_holds(bytes: &[u8]) -> bool {
    sha256_hex(bytes) == PINNED_SHA256
}

fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(pinned_path()).unwrap()).unwrap()
}

/// The file's options, read in order: `serde_json::Value` sorts object
/// keys, and the switches' order is the order differences are written in.
#[derive(serde::Deserialize)]
struct Head {
    options: Options,
}

fn page_options() -> Options {
    let text = std::fs::read_to_string(pinned_path()).unwrap();
    serde_json::from_str::<Head>(&text).unwrap().options
}

#[test]
fn the_copy_is_the_pinned_one() {
    let bytes = std::fs::read(pinned_path()).unwrap();
    assert!(
        pin_holds(&bytes),
        "tests/fixtures/address-vectors.json is not the pinned copy: a change to the grammar is \
         made in the maps repository first, then copied here with its new SHA-256"
    );
}

#[test]
fn a_changed_copy_fails_the_pin() {
    let mut bytes = std::fs::read(pinned_path()).unwrap();
    let i = bytes.iter().position(|&b| b == b'#').unwrap();
    bytes[i] = b'?';
    assert!(!pin_holds(&bytes), "a planted change went unnoticed");
}

/// The maps repository's file, when a checkout of it is beside this one
/// (`AIRDRESS_MAPS_DIR`, else `../airdress-maps` from the workspace root).
/// CI names the directory; without one the comparison is skipped, loudly.
#[test]
fn the_pinned_copy_is_the_maps_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::var_os("AIRDRESS_MAPS_DIR")
        .map_or_else(|| root.join("../airdress-maps"), PathBuf::from);
    let upstream = dir.join(UPSTREAM);
    let Ok(bytes) = std::fs::read(&upstream) else {
        eprintln!(
            "SKIPPED: no maps checkout at {} (set AIRDRESS_MAPS_DIR); the pin is checked against \
             the copy only",
            upstream.display()
        );
        return;
    };
    assert!(
        pin_holds(&bytes),
        "the maps repository's address vectors moved (sha256 {}): copy the file to \
         tests/fixtures/ and move PINNED_SHA256, then make every case pass",
        sha256_hex(&bytes)
    );
}

#[test]
fn every_format_vector_passes() {
    let v = vectors();
    assert_eq!(v["schema"], 1);
    let base = page_options();
    let mut ran = 0;
    for c in v["cases"].as_array().unwrap() {
        if c["op"] != "format" {
            continue;
        }
        // The cases override `asks` only; anything else would need reading here.
        let mut opts = base.clone();
        if let Some(o) = c.get("options").and_then(Value::as_object) {
            assert!(
                o.keys().all(|k| k == "asks"),
                "{}: an override this test does not apply",
                c["name"]
            );
            opts.asks = serde_json::from_value(o["asks"].clone()).unwrap();
        }
        let state: State = serde_json::from_value(c["state"].clone())
            .unwrap_or_else(|e| panic!("{}: state does not parse: {e}", c["name"]));
        let got = format_address(&state, &opts);
        assert_eq!(got, c["fragment"].as_str().unwrap(), "{}", c["name"]);
        assert_eq!(
            got.len() > MAX_FRAGMENT,
            c.get("over_limit")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "{}: over the limit exactly when the case says so",
            c["name"]
        );
        ran += 1;
    }
    assert!(ran >= 30, "only {ran} format cases ran");
}

#[test]
fn the_compiled_snapshot_is_the_pages_options() {
    assert_eq!(airdress_place::snapshot(), page_options());
}
