//! The reference host over a C ABI, for client tests in other languages.
//!
//! A client written in Dart (the Android app) or TypeScript (the editor)
//! must pass the same conversation suite the Rust client passes. Its tests
//! load this library and drive [`RefHost`] through one entry point that
//! takes and returns JSON, so a new operation is a match arm here and not a
//! new symbol on both sides.
//!
//! **Never shipped.** It holds deterministic keys, signs statements for any
//! device it is told about, and exists only so the suites have a host to
//! talk to.
//!
//! # Safety contract
//!
//! The callers are test suites (airdress-chat
//! `test/shells/native/mock_host.dart`, and the editor's), and owe:
//!
//! 1. **Host.** `host` is a pointer `airdress_mock_host_new` returned and
//!    `airdress_mock_host_free` has not yet freed. It is not locked: never
//!    two calls on one host at once.
//! 2. **Inputs.** `(ptr, len)` points to `len` initialised bytes that stay
//!    valid and unwritten for the call, or is null (refused). A `len` above
//!    `isize::MAX` is refused.
//! 3. **Outputs.** `out` is null (the answer is dropped) or points to
//!    writable, aligned storage for one [`MockBuf`], which may be
//!    uninitialised.
//! 4. **Buffers.** A [`MockBuf`] written here goes back to
//!    `airdress_mock_host_buf_free` exactly once, `ptr` and `len`
//!    unchanged, and never to the C allocator's `free`.
#![allow(unsafe_code)]
// Every unsafe operation is spelled out and justified where it happens, and
// every unsafe fn says what its caller owes (rust guide R-UNS-2).
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use airdress_shell_proto::conformance::{Outbound, RefHost};
use airdress_shell_proto::presence::{DeviceKeys, PresenceAlg};
use airdress_shell_proto::ticket::TicketId;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

/// Success.
pub const STATUS_OK: i32 = 0;
/// The request was not understood.
pub const STATUS_INVALID: i32 = 1;
/// The host refused the operation; the answer's `error` says why.
pub const STATUS_REFUSED: i32 = 2;
/// A panic.
pub const STATUS_INTERNAL: i32 = 99;

/// A byte buffer owned by this library.
#[repr(C)]
#[derive(Debug)]
pub struct MockBuf {
    /// The bytes.
    pub ptr: *mut u8,
    /// How many.
    pub len: usize,
}

/// The host, and the identity keys it made up for the devices it trusts.
pub struct MockHost {
    host: RefHost,
}

impl std::fmt::Debug for MockHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHost").finish_non_exhaustive()
    }
}

fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or_else(|| format!("{k} is required"))
}

fn b(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(s(v, k)?)
        .map_err(|_| format!("{k} is base64"))
}

fn now(v: &Value) -> u64 {
    v["nowMs"].as_u64().unwrap_or(0)
}

fn outbound(out: Vec<Outbound>) -> Value {
    json!({ "out": out.into_iter().map(|o| json!({
        "session": o.session,
        "device": o.device,
        "record": STANDARD.encode(o.record),
    })).collect::<Vec<_>>() })
}

impl MockHost {
    fn new(cfg: &Value) -> Result<Self, String> {
        let seed = cfg["seed"].as_str().unwrap_or("mock").as_bytes().to_vec();
        Ok(Self {
            host: RefHost::new(
                &seed,
                s(cfg, "airdress")?,
                s(cfg, "machine")?,
                s(cfg, "principal")?,
            ),
        })
    }

    fn call(&mut self, req: &Value) -> Result<Value, String> {
        let e = |err: airdress_shell_proto::ProtoError| err.to_string();
        let h = &mut self.host;
        Ok(match s(req, "op")? {
            "public" => json!({ "public": STANDARD.encode(h.public()) }),
            // Trust a device's shell keys as if its delegation or
            // introduction said `kind`. The statement is signed with an
            // identity key made up here: identity is not what these suites
            // test.
            "trust" => {
                let mut id = [0u8; 32];
                OsRng.fill_bytes(&mut id);
                let identity = SigningKey::from_bytes(&id);
                let presence_public = match req["presencePublic"].as_str() {
                    Some(p) => Some(STANDARD.decode(p).map_err(|_| "presencePublic")?),
                    None => None,
                };
                let keys = DeviceKeys {
                    device: s(req, "device")?.into(),
                    principal: s(req, "principal")?.into(),
                    identity_public: identity.verifying_key().to_bytes(),
                    dh_public: b(req, "dhPublic")?
                        .try_into()
                        .map_err(|_| "dhPublic is 32 bytes")?,
                    presence_alg: if presence_public.is_some() {
                        PresenceAlg::P256
                    } else {
                        PresenceAlg::None
                    },
                    presence_public,
                };
                let sig = keys.sign(&identity).map_err(e)?;
                h.trust(&keys, &sig, s(req, "kind")?, s(req, "label").unwrap_or(""))
                    .map_err(e)?;
                json!({})
            }
            "open" => {
                let msg2 = h
                    .open(
                        s(req, "session")?,
                        s(req, "profile")?,
                        s(req, "device")?,
                        &b(req, "msg1")?,
                        now(req),
                    )
                    .map_err(e)?;
                json!({ "msg2": STANDARD.encode(msg2) })
            }
            "attach" => {
                let msg2 = h
                    .attach(
                        s(req, "session")?,
                        s(req, "device")?,
                        &b(req, "msg1")?,
                        now(req),
                    )
                    .map_err(e)?;
                json!({ "msg2": STANDARD.encode(msg2) })
            }
            "resume" => {
                let ticket = TicketId::decode(s(req, "ticketId")?).map_err(e)?;
                let msg2 = h
                    .resume(
                        s(req, "session")?,
                        s(req, "device")?,
                        &ticket,
                        &b(req, "msg1")?,
                        now(req),
                    )
                    .map_err(e)?;
                json!({ "msg2": STANDARD.encode(msg2) })
            }
            "record" => outbound(
                h.record(
                    s(req, "session")?,
                    s(req, "device")?,
                    &b(req, "record")?,
                    now(req),
                )
                .map_err(e)?,
            ),
            "output" => outbound(
                h.output(s(req, "session")?, &b(req, "data")?, now(req))
                    .map_err(e)?,
            ),
            "legDropped" => {
                h.leg_dropped(s(req, "session")?, s(req, "device")?, now(req));
                json!({})
            }
            "detach" => {
                h.detach(s(req, "session")?, s(req, "device")?);
                json!({})
            }
            "revoke" => outbound(h.revoke(s(req, "device")?, now(req)).map_err(e)?),
            "releaseInput" => outbound(
                h.release_input(s(req, "session")?, s(req, "device")?, now(req))
                    .map_err(e)?,
            ),
            "exit" => outbound(
                h.exit(
                    s(req, "session")?,
                    req["code"].as_i64().unwrap_or(0) as i32,
                    now(req),
                )
                .map_err(e)?,
            ),
            "stop" => outbound(h.stop(now(req)).map_err(e)?),
            "inspect" => {
                let session = s(req, "session")?;
                json!({
                    "input": STANDARD.encode(h.input(session)),
                    "spawned": h.spawned(session),
                    "typist": h.typist(session),
                    "tickets": h.tickets(),
                    "unlocks": h.unlocks_verified.len(),
                })
            }
            // A P-256 key and signatures with it, standing in for a phone's
            // Keystore in tests that run off the phone.
            "presenceKey" => {
                let mut sc = [0u8; 32];
                OsRng.fill_bytes(&mut sc);
                sc[0] &= 0x7f;
                let k = P256SigningKey::from_slice(&sc).map_err(|_| "scalar")?;
                json!({
                    "secret": STANDARD.encode(sc),
                    "public": STANDARD.encode(k.verifying_key().to_encoded_point(false).as_bytes()),
                })
            }
            "presenceSign" => {
                let k = P256SigningKey::from_slice(&b(req, "secret")?).map_err(|_| "secret")?;
                let sig: P256Signature = k.sign(&b(req, "message")?);
                json!({ "sig": STANDARD.encode(sig.to_der().as_bytes()) })
            }
            other => return Err(format!("unknown op {other}")),
        })
    }
}

/// Parse a `(ptr, len)` input as JSON; `None` for null, an impossible
/// length, or JSON that does not parse.
///
/// # Safety
///
/// `p` is null or points to `len` initialised bytes that stay valid and
/// unwritten for the call (contract 2).
unsafe fn json_in(p: *const u8, len: usize) -> Option<Value> {
    if p.is_null() || isize::try_from(len).is_err() {
        return None;
    }
    // SAFETY: `p` is non-null and, per the caller's contract, points to
    // `len` initialised bytes nothing writes during the call; `u8` needs no
    // alignment; and `len <= isize::MAX` was checked above.
    let b = unsafe { std::slice::from_raw_parts(p, len) };
    serde_json::from_slice(b).ok()
}

/// Write an answer as JSON to `out`; a null or misaligned `out` drops it.
///
/// # Safety
///
/// `out` is null or valid for a write of one [`MockBuf`] (contract 3).
unsafe fn put(out: *mut MockBuf, v: &Value) {
    if out.is_null() || !out.is_aligned() {
        return;
    }
    let b = serde_json::to_vec(v).unwrap_or_default().into_boxed_slice();
    let len = b.len();
    // SAFETY: `out` is non-null and aligned (checked above) and valid for
    // one write (the caller's contract); `write` does not read or drop the
    // old contents, which may be uninitialised.
    unsafe {
        out.write(MockBuf {
            ptr: Box::into_raw(b).cast::<u8>(),
            len,
        });
    }
}

/// A host from `{"airdress", "machine", "principal", "seed"?}`; null on a
/// bad config.
///
/// # Safety
///
/// `(cfg, len)` is an input (contract 2). A non-null result is the
/// caller's, freed once with `airdress_mock_host_free` (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_mock_host_new(cfg: *const u8, len: usize) -> *mut MockHost {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `(cfg, len)` is an input per this function's contract.
        unsafe { json_in(cfg, len) }
            .and_then(|c| MockHost::new(&c).ok())
            .map(|h| Box::into_raw(Box::new(h)))
            .unwrap_or(ptr::null_mut())
    }))
    .unwrap_or(ptr::null_mut())
}

/// One operation (`{"op": …}`); the answer, or `{"error": …}`, is written
/// to `out` as JSON.
///
/// # Safety
///
/// `host` is null or a live host no other call is using (contract 1),
/// `(req, len)` an input (contract 2) and `out` an output (contract 3). The
/// answer written is the caller's to free (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_mock_host_call(
    host: *mut MockHost,
    req: *const u8,
    len: usize,
    out: *mut MockBuf,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `host` is null or a live handle from `Box::into_raw`
        // (aligned, initialised) used by this call alone, and `(req, len)`
        // an input, per this function's contract.
        let (h, r) = unsafe { (host.as_mut(), json_in(req, len)) };
        let (Some(h), Some(r)) = (h, r) else {
            return STATUS_INVALID;
        };
        let (answer, code) = match h.call(&r) {
            Ok(v) => (v, STATUS_OK),
            Err(msg) => (json!({ "error": msg }), STATUS_REFUSED),
        };
        // SAFETY: `out` is an output per this function's contract.
        unsafe { put(out, &answer) };
        code
    }))
    .unwrap_or(STATUS_INTERNAL)
}

/// Free an answer.
///
/// # Safety
///
/// `buf` was written by `airdress_mock_host_call` and not freed yet, `ptr`
/// and `len` unchanged (contract 4), or `ptr` is null.
#[no_mangle]
pub unsafe extern "C" fn airdress_mock_host_buf_free(buf: MockBuf) {
    if !buf.ptr.is_null() && buf.len > 0 {
        // SAFETY: a non-empty answer was made by `put` from a `Box<[u8]>`
        // of exactly `len` bytes; rebuilding that fat pointer and dropping
        // the box returns it to the allocator that made it, once.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}

/// Free the host.
///
/// # Safety
///
/// `host` is null or a live host (contract 1), not used again after this
/// call.
#[no_mangle]
pub unsafe extern "C" fn airdress_mock_host_free(host: *mut MockHost) {
    if !host.is_null() {
        // SAFETY: a live host is a pointer `Box::into_raw` returned in
        // `airdress_mock_host_new` and not yet reclaimed; the caller never
        // uses it again, so this is its only owner.
        drop(unsafe { Box::from_raw(host) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(h: &mut MockHost, v: Value) -> Value {
        h.call(&v).unwrap()
    }

    #[test]
    fn a_cli_device_opens_and_types_through_the_json_surface() {
        use airdress_shell_proto::handshake::{DeviceHello, InitiatorHandshake};
        use airdress_shell_proto::inner::Message;
        use airdress_shell_proto::keys::ShellKeypair;
        use airdress_shell_proto::presence::PresenceAlg;
        use airdress_shell_proto::prologue::{Action, Prologue};

        let mut h =
            MockHost::new(&json!({"airdress": "a", "machine": "m", "principal": "p"})).unwrap();
        let host_pub: [u8; 32] = STANDARD
            .decode(
                call(&mut h, json!({"op": "public"}))["public"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let kp = ShellKeypair::generate(&mut OsRng);
        call(
            &mut h,
            json!({"op": "trust", "device": "d", "principal": "p",
                   "dhPublic": STANDARD.encode(kp.public()), "kind": "cli"}),
        );
        let pro = Prologue {
            airdress: "a".into(),
            machine_id: "m".into(),
            session_id: "s".into(),
            profile_id: "sh".into(),
            action: Action::Open,
        };
        let hello = DeviceHello {
            device: "d".into(),
            cols: Some(80),
            rows: Some(24),
            client_version: None,
        };
        let (hs, m1) = InitiatorHandshake::start(&mut OsRng, &kp, &host_pub, &pro, &hello).unwrap();
        let r = call(
            &mut h,
            json!({"op": "open", "session": "s", "profile": "sh", "device": "d",
                   "msg1": STANDARD.encode(m1)}),
        );
        let (mut ch, _) = hs
            .finish(&STANDARD.decode(r["msg2"].as_str().unwrap()).unwrap(), 0)
            .unwrap();
        let first = Message::encode_all(&[
            Message::Presence {
                action: Action::Open,
                alg: PresenceAlg::None,
                sig: None,
            },
            Message::TakeInput,
            Message::In {
                data: b"ls\r".to_vec(),
            },
        ])
        .unwrap();
        let rec = ch.seal(&first, 0).unwrap();
        let out = call(
            &mut h,
            json!({"op": "record", "session": "s", "device": "d",
                   "record": STANDARD.encode(rec)}),
        );
        assert!(!out["out"].as_array().unwrap().is_empty());
        let st = call(&mut h, json!({"op": "inspect", "session": "s"}));
        assert_eq!(st["spawned"], true);
        assert_eq!(
            STANDARD.decode(st["input"].as_str().unwrap()).unwrap(),
            b"ls\r"
        );
        assert!(h.call(&json!({"op": "nope"})).is_err());
    }

    /// The C surface end to end, and an impossible length refused before it
    /// reaches `from_raw_parts` (undefined behaviour, or a process abort in
    /// a debug build).
    #[test]
    fn the_c_surface_and_an_impossible_length() {
        let cfg = br#"{"airdress":"a","machine":"m","principal":"p"}"#;
        // SAFETY: a byte-string input with its length.
        let h = unsafe { airdress_mock_host_new(cfg.as_ptr(), cfg.len()) };
        assert!(!h.is_null());
        let req = br#"{"op":"public"}"#;
        let mut out = MockBuf {
            ptr: ptr::null_mut(),
            len: 0,
        };
        // SAFETY: `h` is live; a byte-string input; a local output.
        let rc = unsafe { airdress_mock_host_call(h, req.as_ptr(), req.len(), &mut out) };
        assert_eq!(rc, STATUS_OK);
        // SAFETY: the non-empty answer the call above wrote.
        let answer: Value =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(out.ptr, out.len) })
                .unwrap();
        assert!(answer["public"].is_string());
        // SAFETY: that answer, unchanged, freed once.
        unsafe { airdress_mock_host_buf_free(out) };
        // SAFETY: `h` is live; the pointer is valid for its literal and the
        // length is the bug under test, refused before any read.
        let rc = unsafe { airdress_mock_host_call(h, req.as_ptr(), usize::MAX, ptr::null_mut()) };
        assert_eq!(rc, STATUS_INVALID);
        // SAFETY: `h` is live and freed once.
        unsafe { airdress_mock_host_free(h) };
    }
}
