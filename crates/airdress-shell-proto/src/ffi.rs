//! The C ABI the Android app loads (the `.so` of this crate's cdylib).
//!
//! Every exported symbol is listed in `ffi-symbols.txt`; a unit test holds
//! this file and the list to each other, and `scripts/shell-proto-ffi-symbols.sh`
//! holds the list to `nm` on the built Android library.
//!
//! Conventions:
//!
//! - Every function returns an `i32` status ([`STATUS_OK`] or one of the
//!   `STATUS_*` codes) unless it says otherwise. A panic never crosses the
//!   boundary; it becomes [`STATUS_INTERNAL`].
//! - Byte inputs are `(ptr, len)`; a null pointer is allowed only with a
//!   length of zero. Fixed-size keys and hashes are 32-byte pointers.
//! - Byte outputs are an [`AirdressShellBuf`] the caller frees with
//!   `airdress_shell_buf_free`.
//! - Structured inputs and outputs are UTF-8 JSON in the same forms the
//!   conformance vectors use (camelCase; binary as base64).
//! - Handles (`*mut` of an opaque type) are freed with their `_free`
//!   function. `airdress_shell_initiator_finish` consumes its handshake
//!   handle whether or not it succeeds.
//! - Randomness comes from the operating system.
//!
//! # Safety contract
//!
//! Every `unsafe extern "C"` function below relies on the caller (the Dart
//! bindings in airdress-chat, `lib/ffi/shell_proto_bindings.dart`, and the
//! test suites) for the same five things. Each function's own `# Safety`
//! section names which of its arguments they apply to.
//!
//! 1. **Inputs.** A `(ptr, len)` input is null with `len == 0`, or points
//!    to `len` initialised bytes that stay valid and unwritten for the
//!    duration of the call. A 32-byte input (`*const u8` with no length)
//!    is null or points to 32 readable bytes. The library only borrows
//!    inputs; the caller allocates and frees them (the Dart side uses an
//!    `Arena`). A `len` above `isize::MAX` is refused, not trusted.
//! 2. **Outputs.** An output pointer is null or points to writable,
//!    suitably aligned storage for one value of its type; it may be
//!    uninitialised, because the library writes it without reading or
//!    dropping what was there. A 32-byte output points to 32 writable
//!    bytes. Null and misaligned output pointers are refused. Outputs are
//!    written only on [`STATUS_OK`]; on an error they are unspecified and
//!    must not be freed.
//! 3. **Buffers.** An [`AirdressShellBuf`] written by this library is
//!    passed back to `airdress_shell_buf_free` exactly once, with `ptr` and
//!    `len` unchanged, and not read after that. It is never passed to the
//!    C allocator's `free`: it was allocated by Rust's global allocator.
//! 4. **Handles.** A handle is a pointer this library returned and has
//!    not yet freed (or consumed, for `airdress_shell_initiator_finish`),
//!    or null. Each handle is freed exactly once by its own `_free`.
//! 5. **Threads.** No handle is locked internally: a handle may be used
//!    from any thread, but never by two calls at once. The Dart bindings
//!    call synchronously from one isolate, which satisfies this.
#![allow(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use rand_core::OsRng;

use crate::error::ProtoError;
use crate::handshake::{Channel, DeviceHello, InitiatorHandshake};
use crate::inner::{seal_rekey, Message};
use crate::keys::{fingerprint, ShellKeypair};
use crate::presence::{presence_message, verify_presence, DeviceKeys};
use crate::prologue::{Action, Prologue};
use crate::recording::{rewrap, Recipient, SegmentHeader, SegmentReader};

/// Success.
pub const STATUS_OK: i32 = 0;
/// A null pointer, a bad length, or JSON that does not parse.
pub const STATUS_INVALID_ARGUMENT: i32 = 1;
/// `shell_handshake_failed`.
pub const STATUS_HANDSHAKE_FAILED: i32 = 2;
/// `shell_presence_required`.
pub const STATUS_PRESENCE_REQUIRED: i32 = 3;
/// `shell_resume_expired`.
pub const STATUS_RESUME_EXPIRED: i32 = 4;
/// A record that does not authenticate, is replayed, or is malformed.
pub const STATUS_RECORD_REJECTED: i32 = 5;
/// An inner message that does not decode.
pub const STATUS_MESSAGE_MALFORMED: i32 = 6;
/// A recording that does not open.
pub const STATUS_RECORDING_UNREADABLE: i32 = 7;
/// The OS RNG failed.
pub const STATUS_RNG: i32 = 8;
/// A panic inside the library. Never expected; reported rather than
/// unwound into the caller.
pub const STATUS_INTERNAL: i32 = 99;

fn status(e: &ProtoError) -> i32 {
    match e {
        ProtoError::Handshake(_) | ProtoError::UnexpectedRemoteKey => STATUS_HANDSHAKE_FAILED,
        ProtoError::PresenceRequired(_) | ProtoError::DeviceKeysInvalid(_) => {
            STATUS_PRESENCE_REQUIRED
        }
        ProtoError::ResumeExpired => STATUS_RESUME_EXPIRED,
        ProtoError::RecordAuth
        | ProtoError::Replay
        | ProtoError::RecordMalformed
        | ProtoError::NonceExhausted => STATUS_RECORD_REJECTED,
        ProtoError::InnerMalformed(_) => STATUS_MESSAGE_MALFORMED,
        ProtoError::Recording(_) => STATUS_RECORDING_UNREADABLE,
        ProtoError::InvalidInput(_) => STATUS_INVALID_ARGUMENT,
        ProtoError::Rng => STATUS_RNG,
    }
}

/// A byte buffer owned by this library. Free with `airdress_shell_buf_free`.
#[repr(C)]
#[derive(Debug)]
pub struct AirdressShellBuf {
    /// The bytes; null when `len` is zero.
    pub ptr: *mut u8,
    /// How many.
    pub len: usize,
}

impl AirdressShellBuf {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let b = v.into_boxed_slice();
        let len = b.len();
        Self {
            ptr: Box::into_raw(b).cast::<u8>(),
            len,
        }
    }
}

/// An `IK` or `IKpsk2` handshake in flight, on the device.
pub struct AirdressShellInitiator(InitiatorHandshake);

impl std::fmt::Debug for AirdressShellInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AirdressShellInitiator(..)")
    }
}
/// An established E2E channel.
pub struct AirdressShellChannel(Channel);

impl std::fmt::Debug for AirdressShellChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AirdressShellChannel(..)")
    }
}
/// An opened recording segment.
pub struct AirdressShellRecording(SegmentReader);

impl std::fmt::Debug for AirdressShellRecording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AirdressShellRecording(..)")
    }
}

type FfiResult = Result<(), i32>;

fn guard(f: impl FnOnce() -> FfiResult) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(code)) => code,
        Err(_) => STATUS_INTERNAL,
    }
}

/// Borrow a `(ptr, len)` input.
///
/// # Safety
///
/// `p` is null, or points to `len` initialised bytes that stay valid and
/// are not written for `'a` (contract 1).
unsafe fn bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if p.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(STATUS_INVALID_ARGUMENT);
    }
    // No allocation is larger than `isize::MAX` bytes, so such a length is
    // a caller's mistake; `from_raw_parts` would be undefined behaviour
    // (and aborts the process in a debug build) rather than an error.
    if isize::try_from(len).is_err() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: `p` is non-null; the caller guarantees it points to `len`
    // initialised bytes that live and stay unwritten for `'a`; `u8` has
    // alignment 1; and `len <= isize::MAX` was checked above.
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}

/// Copy a 32-byte input.
///
/// # Safety
///
/// `p` is null or points to 32 readable bytes (contract 1).
unsafe fn key32(p: *const u8) -> Result<[u8; 32], i32> {
    if p.is_null() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    let mut k = [0u8; 32];
    // SAFETY: `p` is non-null and the caller guarantees 32 readable bytes
    // behind it; `k` is a distinct local, so the ranges do not overlap.
    unsafe { ptr::copy_nonoverlapping(p, k.as_mut_ptr(), 32) };
    Ok(k)
}

/// Borrow a `(ptr, len)` input as UTF-8.
///
/// # Safety
///
/// As [`bytes`].
unsafe fn text<'a>(p: *const u8, len: usize) -> Result<&'a str, i32> {
    // SAFETY: the caller upholds `bytes`' contract, which is this one's.
    let b = unsafe { bytes(p, len)? };
    std::str::from_utf8(b).map_err(|_| STATUS_INVALID_ARGUMENT)
}

/// Parse a `(ptr, len)` input as JSON.
///
/// # Safety
///
/// As [`bytes`].
unsafe fn json<T: serde::de::DeserializeOwned>(p: *const u8, len: usize) -> Result<T, i32> {
    // SAFETY: the caller upholds `bytes`' contract, which is this one's.
    let b = unsafe { bytes(p, len)? };
    serde_json::from_slice(b).map_err(|_| STATUS_INVALID_ARGUMENT)
}

/// Write one value to an output pointer, without reading or dropping what
/// was there.
///
/// # Safety
///
/// `out` is null, or points to storage valid for a write of one `T`
/// (contract 2). Alignment and null are checked here.
unsafe fn put<T>(out: *mut T, v: T) -> FfiResult {
    if out.is_null() || !out.is_aligned() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: `out` is non-null and aligned (checked above) and the caller
    // guarantees it is valid for a write of one `T`. `write` does not read
    // or drop the old contents, which may be uninitialised.
    unsafe { out.write(v) };
    Ok(())
}

/// Write a byte output as a fresh [`AirdressShellBuf`].
///
/// # Safety
///
/// As [`put`].
unsafe fn put_buf(out: *mut AirdressShellBuf, v: Vec<u8>) -> FfiResult {
    // SAFETY: the caller upholds `put`'s contract, which is this one's.
    unsafe { put(out, AirdressShellBuf::from_vec(v)) }
}

/// Write a 32-byte output.
///
/// # Safety
///
/// `out` is null or points to 32 writable bytes (contract 2).
unsafe fn put32(out: *mut u8, v: &[u8; 32]) -> FfiResult {
    if out.is_null() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: `out` is non-null and the caller guarantees 32 writable bytes
    // behind it; `v` is a Rust array the caller's buffer cannot alias,
    // because the caller has no pointer into this library's values.
    unsafe { ptr::copy_nonoverlapping(v.as_ptr(), out, 32) };
    Ok(())
}

/// Borrow a handle mutably.
///
/// # Safety
///
/// `p` is null or a live handle of this type that no other call is using
/// (contracts 4 and 5).
unsafe fn handle_mut<'a, T>(p: *mut T) -> Result<&'a mut T, i32> {
    // SAFETY: a live handle came from `Box::into_raw`, so it is aligned
    // and points to an initialised `T`; contract 5 makes this the only
    // reference to it for the call. Null becomes `None`.
    unsafe { p.as_mut() }.ok_or(STATUS_INVALID_ARGUMENT)
}

/// Borrow a handle shared.
///
/// # Safety
///
/// `p` is null or a live handle of this type that no other call is
/// mutating (contracts 4 and 5).
unsafe fn handle_ref<'a, T>(p: *const T) -> Result<&'a T, i32> {
    // SAFETY: as `handle_mut`; nothing writes through the handle during
    // the call, so a shared reference is sound.
    unsafe { p.as_ref() }.ok_or(STATUS_INVALID_ARGUMENT)
}

/// Take ownership of a handle back (null is a no-op).
///
/// # Safety
///
/// `p` is null or a live handle of this type that is not used again
/// afterwards (contract 4).
unsafe fn take_handle<T>(p: *mut T) -> Option<Box<T>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a live handle is a pointer `Box::into_raw` returned for a
    // `T` and not yet reclaimed; the caller promises never to use it
    // again, so this is the only owner.
    Some(unsafe { Box::from_raw(p) })
}

/// Refuse an output pointer before doing work that cannot be undone (a
/// seal spends a nonce, an open consumes a record), so a bad output never
/// costs the caller its record.
fn check_out<T>(out: *mut T) -> FfiResult {
    if out.is_null() || !out.is_aligned() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    Ok(())
}

fn e(err: ProtoError) -> i32 {
    status(&err)
}

/// The protocol version (returns it; no status).
#[no_mangle]
pub extern "C" fn airdress_shell_protocol_version() -> u32 {
    crate::PROTOCOL_VERSION
}

/// Free a buffer this library returned. Safe to call on an empty buffer.
///
/// # Safety
///
/// `buf` was written by a function of this library and has not been freed
/// yet, with `ptr` and `len` unchanged (contract 3), or `ptr` is null. It is
/// not read after this call.
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_buf_free(buf: AirdressShellBuf) {
    if !buf.ptr.is_null() && buf.len > 0 {
        // SAFETY: a non-empty buffer was made by `from_vec` from a
        // `Box<[u8]>` of exactly `len` bytes; rebuilding the same fat
        // pointer and dropping the box returns it to the allocator that
        // made it. The caller frees it once (contract 3).
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}

/// Generate an X25519 shell key pair into two 32-byte outputs.
///
/// # Safety
///
/// `out_secret` and `out_public` each point to 32 writable bytes or are
/// null (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_keypair_generate(
    out_secret: *mut u8,
    out_public: *mut u8,
) -> i32 {
    guard(|| {
        let kp = ShellKeypair::generate(&mut OsRng);
        // SAFETY: both outputs are 32-byte outputs per this function's
        // contract.
        unsafe {
            put32(out_secret, kp.secret())?;
            put32(out_public, kp.public())
        }
    })
}

/// The public key of a 32-byte X25519 secret.
///
/// # Safety
///
/// `secret` points to 32 readable bytes and `out_public` to 32 writable
/// bytes, or either is null (contracts 1 and 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_keypair_public(
    secret: *const u8,
    out_public: *mut u8,
) -> i32 {
    guard(|| {
        // SAFETY: `secret` is a 32-byte input per this function's contract.
        let kp = ShellKeypair::from_secret(unsafe { key32(secret)? });
        // SAFETY: `out_public` is a 32-byte output per this function's
        // contract.
        unsafe { put32(out_public, kp.public()) }
    })
}

/// `SHA256:<base64>` of a public key, as UTF-8.
///
/// # Safety
///
/// `(public, len)` is an input and `out` an [`AirdressShellBuf`] output
/// (contracts 1 and 2); the buffer written is the caller's to free
/// (contract 3).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_fingerprint(
    public: *const u8,
    len: usize,
    out: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `(public, len)` is an input per this function's contract.
        let fp = fingerprint(unsafe { bytes(public, len)? });
        // SAFETY: `out` is a buffer output per this function's contract.
        unsafe { put_buf(out, fp.into_bytes()) }
    })
}

/// Start an `IK` handshake (open or attach). `prologue_json` is a
/// `Prologue`, `hello_json` a `DeviceHello`. Writes the handshake handle and
/// msg1.
///
/// # Safety
///
/// `local_secret` and `host_public` are 32-byte inputs and
/// `(prologue_json, prologue_len)`, `(hello_json, hello_len)` are inputs
/// (contract 1). `out_handshake` is an output for one handle pointer and
/// `out_msg1` a buffer output (contract 2). On success the caller owns the
/// handle (finish it or free it, contract 4) and the buffer (contract 3).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_initiator_start(
    local_secret: *const u8,
    host_public: *const u8,
    prologue_json: *const u8,
    prologue_len: usize,
    hello_json: *const u8,
    hello_len: usize,
    out_handshake: *mut *mut AirdressShellInitiator,
    out_msg1: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        check_out(out_handshake)?;
        // SAFETY: the two keys are 32-byte inputs and the two JSON
        // arguments are `(ptr, len)` inputs per this function's contract.
        let (local, host, pro, hello) = unsafe {
            (
                ShellKeypair::from_secret(key32(local_secret)?),
                key32(host_public)?,
                json::<Prologue>(prologue_json, prologue_len)?,
                json::<DeviceHello>(hello_json, hello_len)?,
            )
        };
        let (hs, m1) =
            InitiatorHandshake::start(&mut OsRng, &local, &host, &pro, &hello).map_err(e)?;
        // SAFETY: `out_msg1` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_msg1, m1)? };
        let h = Box::into_raw(Box::new(AirdressShellInitiator(hs)));
        // SAFETY: `out_handshake` is an output for one pointer per this
        // function's contract; checked non-null and aligned above, so this
        // cannot fail and leak `h`.
        unsafe { put(out_handshake, h) }
    })
}

/// Start an `IKpsk2` resume from a previous channel (its resume secret
/// never leaves the library). The prologue's action must be `resume`.
///
/// # Safety
///
/// As [`airdress_shell_initiator_start`], and `previous` is a live channel
/// handle no other call is mutating (contracts 4 and 5). `previous` is only
/// read; it stays the caller's.
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_initiator_start_resume(
    local_secret: *const u8,
    host_public: *const u8,
    prologue_json: *const u8,
    prologue_len: usize,
    previous: *const AirdressShellChannel,
    hello_json: *const u8,
    hello_len: usize,
    out_handshake: *mut *mut AirdressShellInitiator,
    out_msg1: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        check_out(out_handshake)?;
        // SAFETY: `previous` is a live channel handle per this function's
        // contract (null is refused by `handle_ref`).
        let secret = *unsafe { handle_ref(previous)? }.0.resume_secret();
        // SAFETY: the two keys are 32-byte inputs and the two JSON
        // arguments are `(ptr, len)` inputs per this function's contract.
        let (local, host, pro, hello) = unsafe {
            (
                ShellKeypair::from_secret(key32(local_secret)?),
                key32(host_public)?,
                json::<Prologue>(prologue_json, prologue_len)?,
                json::<DeviceHello>(hello_json, hello_len)?,
            )
        };
        let (hs, m1) =
            InitiatorHandshake::start_resume(&mut OsRng, &local, &host, &pro, &secret, &hello)
                .map_err(e)?;
        // SAFETY: `out_msg1` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_msg1, m1)? };
        let h = Box::into_raw(Box::new(AirdressShellInitiator(hs)));
        // SAFETY: `out_handshake` is an output for one pointer, checked
        // non-null and aligned above, so this cannot fail and leak `h`.
        unsafe { put(out_handshake, h) }
    })
}

/// Read msg2 and establish the channel. Consumes `handshake` always.
/// Writes the channel handle and the host's `HostHello` as JSON.
///
/// # Safety
///
/// `handshake` is a live initiator handle or null; it is consumed by this
/// call whatever the status, and the caller must not use or free it again
/// (contract 4). `(msg2, msg2_len)` is an input (contract 1).
/// `out_channel` is an output for one handle pointer and `out_hello_json`
/// a buffer output (contract 2); on success the caller owns both.
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_initiator_finish(
    handshake: *mut AirdressShellInitiator,
    msg2: *const u8,
    msg2_len: usize,
    now_ms: u64,
    out_channel: *mut *mut AirdressShellChannel,
    out_hello_json: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `handshake` is a live initiator handle the caller hands
        // over for good, per this function's contract.
        let hs = unsafe { take_handle(handshake) }.ok_or(STATUS_INVALID_ARGUMENT)?;
        check_out(out_channel)?;
        // SAFETY: `(msg2, msg2_len)` is an input per this function's
        // contract.
        let m2 = unsafe { bytes(msg2, msg2_len)? };
        let (ch, hello) = hs.0.finish(m2, now_ms).map_err(e)?;
        let hello = serde_json::to_vec(&hello).map_err(|_| STATUS_INTERNAL)?;
        // SAFETY: `out_hello_json` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_hello_json, hello)? };
        let c = Box::into_raw(Box::new(AirdressShellChannel(ch)));
        // SAFETY: `out_channel` is an output for one pointer, checked
        // non-null and aligned above, so this cannot fail and leak `c`.
        unsafe { put(out_channel, c) }
    })
}

/// Abandon a handshake in flight.
///
/// # Safety
///
/// `handshake` is null or a live initiator handle, not used again after
/// this call (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_initiator_free(handshake: *mut AirdressShellInitiator) {
    // SAFETY: per this function's contract.
    drop(unsafe { take_handle(handshake) });
}

/// Seal one record.
///
/// # Safety
///
/// `channel` is a live channel handle no other call is using (contracts 4
/// and 5), `(plaintext, len)` an input and `out_record` a buffer output
/// (contracts 1 and 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_seal(
    channel: *mut AirdressShellChannel,
    plaintext: *const u8,
    len: usize,
    now_ms: u64,
    out_record: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        check_out(out_record)?;
        // SAFETY: `channel` is a live handle used by this call alone, and
        // `(plaintext, len)` an input, per this function's contract. The
        // input is caller memory, so it cannot alias the channel.
        let (ch, pt) = unsafe { (handle_mut(channel)?, bytes(plaintext, len)?) };
        let rec = ch.0.seal(pt, now_ms).map_err(e)?;
        // SAFETY: `out_record` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_record, rec) }
    })
}

/// Open one record. Writes its nonce and plaintext.
///
/// # Safety
///
/// `channel` is a live channel handle no other call is using (contracts 4
/// and 5), `(record, len)` an input, `out_nonce` an output for one `u64`
/// and `out_plaintext` a buffer output (contracts 1 and 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_open(
    channel: *mut AirdressShellChannel,
    record: *const u8,
    len: usize,
    out_nonce: *mut u64,
    out_plaintext: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        check_out(out_nonce)?;
        check_out(out_plaintext)?;
        // SAFETY: `channel` is a live handle used by this call alone, and
        // `(record, len)` an input, per this function's contract.
        let (ch, rec) = unsafe { (handle_mut(channel)?, bytes(record, len)?) };
        let (n, pt) = ch.0.open(rec).map_err(e)?;
        // SAFETY: `out_plaintext` is a buffer output and `out_nonce` an
        // output for one `u64` (checked above, so it cannot fail after the
        // buffer was written), per this function's contract.
        unsafe {
            put_buf(out_plaintext, pt)?;
            put(out_nonce, n)
        }
    })
}

/// Schedule a rekey of the sending direction and seal the announcing
/// `rekey` message. `request` non-zero asks the peer to rekey too.
///
/// # Safety
///
/// `channel` is a live channel handle no other call is using (contracts 4
/// and 5), and `out_record` a buffer output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_seal_rekey(
    channel: *mut AirdressShellChannel,
    request: u8,
    now_ms: u64,
    out_record: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        check_out(out_record)?;
        // SAFETY: `channel` is a live handle used by this call alone, per
        // this function's contract.
        let ch = unsafe { handle_mut(channel)? };
        let rec = seal_rekey(&mut ch.0, request != 0, now_ms).map_err(e)?;
        // SAFETY: `out_record` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_record, rec) }
    })
}

/// The peer announced its key changes at `switch_at`.
///
/// # Safety
///
/// `channel` is a live channel handle no other call is using (contracts 4
/// and 5).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_note_peer_rekey(
    channel: *mut AirdressShellChannel,
    switch_at: u64,
) -> i32 {
    guard(|| {
        // SAFETY: `channel` is a live handle used by this call alone, per
        // this function's contract.
        let ch = unsafe { handle_mut(channel)? };
        ch.0.note_peer_rekey(switch_at);
        Ok(())
    })
}

/// 1 when the sending direction is due a rekey, 0 when not, -1 for a null
/// channel.
///
/// # Safety
///
/// `channel` is null or a live channel handle no other call is mutating
/// (contracts 4 and 5).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_rekey_due(
    channel: *const AirdressShellChannel,
    now_ms: u64,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `channel` is null or a live handle nothing else mutates,
        // per this function's contract.
        unsafe { handle_ref(channel) }
            .ok()
            .map(|c| c.0.rekey_due(now_ms))
    })) {
        Ok(Some(true)) => 1,
        Ok(Some(false)) => 0,
        Ok(None) => -1,
        Err(_) => STATUS_INTERNAL,
    }
}

/// The final handshake hash (what an unlock signs) into 32 bytes.
///
/// # Safety
///
/// `channel` is a live channel handle no other call is mutating (contracts
/// 4 and 5), and `out_hash` points to 32 writable bytes or is null
/// (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_handshake_hash(
    channel: *const AirdressShellChannel,
    out_hash: *mut u8,
) -> i32 {
    guard(|| {
        // SAFETY: `channel` is a live handle nothing else mutates, and
        // `out_hash` a 32-byte output, per this function's contract.
        unsafe {
            let ch = handle_ref(channel)?;
            put32(out_hash, ch.0.handshake_hash())
        }
    })
}

/// Close a channel; its keys are zeroed.
///
/// # Safety
///
/// `channel` is null or a live channel handle, not used again after this
/// call (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_channel_free(channel: *mut AirdressShellChannel) {
    // SAFETY: per this function's contract.
    drop(unsafe { take_handle(channel) });
}

/// The bytes a presence key signs for `action` (`open` or `attach`).
///
/// # Safety
///
/// `handshake_hash` is a 32-byte input and `(action, action_len)` an input
/// (contract 1); `out_message` is a buffer output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_presence_message(
    handshake_hash: *const u8,
    action: *const u8,
    action_len: usize,
    out_message: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: a 32-byte input and a `(ptr, len)` input per this
        // function's contract.
        let (hh, a) = unsafe { (key32(handshake_hash)?, text(action, action_len)?) };
        let a = Action::parse(a).map_err(e)?;
        let msg = presence_message(&hh, a).map_err(e)?;
        // SAFETY: `out_message` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_message, msg) }
    })
}

/// Verify an unlock signature (SEC1 key, DER signature).
///
/// # Safety
///
/// `handshake_hash` is a 32-byte input, and `(public, public_len)`,
/// `(action, action_len)` and `(sig, sig_len)` are inputs (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_presence_verify(
    public: *const u8,
    public_len: usize,
    handshake_hash: *const u8,
    action: *const u8,
    action_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: one 32-byte input and three `(ptr, len)` inputs per this
        // function's contract.
        let (hh, a, pk, s) = unsafe {
            (
                key32(handshake_hash)?,
                text(action, action_len)?,
                bytes(public, public_len)?,
                bytes(sig, sig_len)?,
            )
        };
        let a = Action::parse(a).map_err(e)?;
        verify_presence(pk, &hh, a, s).map_err(e)
    })
}

/// The bytes a device's identity key signs for its `DeviceKeys` statement
/// (given as JSON).
///
/// # Safety
///
/// `(keys_json, len)` is an input (contract 1) and `out_bytes` a buffer
/// output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_device_keys_signed_bytes(
    keys_json: *const u8,
    len: usize,
    out_bytes: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `(keys_json, len)` is an input per this function's
        // contract.
        let keys: DeviceKeys = unsafe { json(keys_json, len)? };
        let signed = keys.signed_bytes().map_err(e)?;
        // SAFETY: `out_bytes` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_bytes, signed) }
    })
}

/// Encode a JSON array of inner messages into one record's plaintext.
///
/// # Safety
///
/// `(messages_json, len)` is an input (contract 1) and `out_bytes` a buffer
/// output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_messages_encode(
    messages_json: *const u8,
    len: usize,
    out_bytes: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `(messages_json, len)` is an input per this function's
        // contract.
        let msgs: Vec<Message> = unsafe { json(messages_json, len)? };
        let encoded = Message::encode_all(&msgs).map_err(e)?;
        // SAFETY: `out_bytes` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_bytes, encoded) }
    })
}

/// Decode a record's plaintext into a JSON array of inner messages.
///
/// # Safety
///
/// `(plaintext, len)` is an input (contract 1) and `out_json` a buffer
/// output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_messages_decode(
    plaintext: *const u8,
    len: usize,
    out_json: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `(plaintext, len)` is an input per this function's
        // contract.
        let msgs = Message::decode_all(unsafe { bytes(plaintext, len)? }).map_err(e)?;
        let out = serde_json::to_vec(&msgs).map_err(|_| STATUS_INTERNAL)?;
        // SAFETY: `out_json` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_json, out) }
    })
}

/// Open a segment header (its serialized bytes) with this device's shell
/// key. Writes a handle for `airdress_shell_recording_open_chunk`.
///
/// # Safety
///
/// `(header, header_len)` and `(device, device_len)` are inputs and
/// `secret` a 32-byte input (contract 1); `out_recording` is an output for
/// one handle pointer (contract 2). On success the caller owns the handle
/// and frees it with `airdress_shell_recording_free` (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_recording_open(
    header: *const u8,
    header_len: usize,
    device: *const u8,
    device_len: usize,
    secret: *const u8,
    out_recording: *mut *mut AirdressShellRecording,
) -> i32 {
    guard(|| {
        check_out(out_recording)?;
        // SAFETY: two `(ptr, len)` inputs and one 32-byte input per this
        // function's contract.
        let (hb, dev, sk) = unsafe {
            (
                bytes(header, header_len)?,
                text(device, device_len)?,
                key32(secret)?,
            )
        };
        let (h, _) = SegmentHeader::parse(hb).map_err(e)?;
        let r = SegmentReader::open(&h, dev, &sk).map_err(e)?;
        let rp = Box::into_raw(Box::new(AirdressShellRecording(r)));
        // SAFETY: `out_recording` is an output for one pointer, checked
        // non-null and aligned above, so this cannot fail and leak `rp`.
        unsafe { put(out_recording, rp) }
    })
}

/// Open chunk `index` (framed, as stored). Writes its plaintext, and 1 in
/// `out_last` when it is the segment's final chunk.
///
/// # Safety
///
/// `recording` is a live recording handle no other call is mutating
/// (contracts 4 and 5), `(framed, len)` an input (contract 1), `out_last`
/// an output for one byte and `out_plaintext` a buffer output (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_recording_open_chunk(
    recording: *const AirdressShellRecording,
    index: u64,
    framed: *const u8,
    len: usize,
    out_last: *mut u8,
    out_plaintext: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        if out_last.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }
        // SAFETY: `recording` is a live handle nothing else mutates, and
        // `(framed, len)` an input, per this function's contract.
        let (r, f) = unsafe { (handle_ref(recording)?, bytes(framed, len)?) };
        let (pt, last) = r.0.open_chunk(index, f).map_err(e)?;
        // SAFETY: `out_plaintext` is a buffer output and `out_last` a
        // one-byte output (checked non-null above; `u8` needs no alignment,
        // so it cannot fail after the buffer was written).
        unsafe {
            put_buf(out_plaintext, pt)?;
            put(out_last, u8::from(last))
        }
    })
}

/// Free an opened segment; its content key is zeroed.
///
/// # Safety
///
/// `recording` is null or a live recording handle, not used again after
/// this call (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_recording_free(recording: *mut AirdressShellRecording) {
    // SAFETY: per this function's contract.
    drop(unsafe { take_handle(recording) });
}

/// Wrap a segment's content key to another device of the same principal.
/// Writes the `RecipientEntry` JSON for a `recording_rewrap` message.
///
/// # Safety
///
/// `(header, header_len)`, `(my_device, my_device_len)` and
/// `(to_device, to_device_len)` are inputs, and `my_secret` and `to_public`
/// 32-byte inputs (contract 1); `out_entry_json` is a buffer output
/// (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_recording_rewrap(
    header: *const u8,
    header_len: usize,
    my_device: *const u8,
    my_device_len: usize,
    my_secret: *const u8,
    to_device: *const u8,
    to_device_len: usize,
    to_public: *const u8,
    out_entry_json: *mut AirdressShellBuf,
) -> i32 {
    guard(|| {
        // SAFETY: three `(ptr, len)` inputs and two 32-byte inputs per this
        // function's contract.
        let (hb, mine, my_sk, to_dev, to_pk) = unsafe {
            (
                bytes(header, header_len)?,
                text(my_device, my_device_len)?,
                key32(my_secret)?,
                text(to_device, to_device_len)?,
                key32(to_public)?,
            )
        };
        let (h, _) = SegmentHeader::parse(hb).map_err(e)?;
        let to = Recipient {
            device: to_dev.to_owned(),
            public: to_pk,
        };
        let entry = rewrap(&mut OsRng, &h, mine, &my_sk, &to).map_err(e)?;
        let out = serde_json::to_vec(&entry).map_err(|_| STATUS_INTERNAL)?;
        // SAFETY: `out_entry_json` is a buffer output per this function's
        // contract.
        unsafe { put_buf(out_entry_json, out) }
    })
}

/// Verify one conformance vector file (`tests/vectors/*.json`) with the
/// library as built. Writes how many cases it checked.
///
/// # Safety
///
/// `(file_json, len)` is an input (contract 1) and `out_cases` an output
/// for one `u64` (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_shell_vectors_verify(
    file_json: *const u8,
    len: usize,
    out_cases: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: `(file_json, len)` is an input per this function's
        // contract.
        let n = crate::vectors::verify(unsafe { bytes(file_json, len)? }).map_err(e)?;
        // SAFETY: `out_cases` is an output for one `u64` per this
        // function's contract; null and misalignment are refused.
        unsafe { put(out_cases, n as u64) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exported names in this file, in order of appearance.
    fn exported_here() -> Vec<String> {
        let src = include_str!("ffi.rs");
        let mut out = Vec::new();
        let mut lines = src.lines().peekable();
        while let Some(l) = lines.next() {
            if l.trim() == "#[no_mangle]" {
                let sig = lines.next().unwrap_or_default();
                let name = sig
                    .split("fn ")
                    .nth(1)
                    .and_then(|r| r.split('(').next())
                    .unwrap_or_default();
                out.push(name.trim().to_owned());
            }
        }
        out
    }

    #[test]
    fn symbol_list_matches_the_source_both_ways() {
        let listed: Vec<String> = include_str!("../ffi-symbols.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        let mut here = exported_here();
        let mut want = listed.clone();
        here.sort();
        want.sort();
        assert_eq!(here, want, "ffi-symbols.txt and src/ffi.rs disagree");
        assert!(listed.iter().all(|s| s.starts_with("airdress_shell_")));
    }

    #[test]
    fn a_handshake_and_a_record_through_the_abi() {
        use crate::handshake::{HostHello, ResponderHandshake};
        let host = ShellKeypair::generate(&mut OsRng);
        let mut ds = [0u8; 32];
        let mut dp = [0u8; 32];
        // SAFETY: two 32-byte outputs, local arrays.
        unsafe {
            assert_eq!(
                airdress_shell_keypair_generate(ds.as_mut_ptr(), dp.as_mut_ptr()),
                0
            );
        }
        let pro =
            br#"{"airdress":"a","machineId":"m","sessionId":"s","profileId":"p","action":"open"}"#;
        let hello = br#"{"device":"d","cols":80,"rows":24}"#;
        let mut hs: *mut AirdressShellInitiator = ptr::null_mut();
        let mut m1 = AirdressShellBuf::empty();
        // SAFETY: 32-byte keys, byte-string inputs with their lengths, and
        // outputs that are locals of the right type.
        let rc = unsafe {
            airdress_shell_initiator_start(
                ds.as_ptr(),
                host.public().as_ptr(),
                pro.as_ptr(),
                pro.len(),
                hello.as_ptr(),
                hello.len(),
                &mut hs,
                &mut m1,
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: a non-empty buffer the call above wrote on success.
        let msg1 = unsafe { std::slice::from_raw_parts(m1.ptr, m1.len) }.to_vec();
        // SAFETY: that buffer, unchanged, freed once.
        unsafe { airdress_shell_buf_free(m1) };

        let prologue: Prologue = serde_json::from_slice(pro).unwrap();
        let (rsp, _) =
            ResponderHandshake::read(&mut OsRng, &host, &prologue, &dp, None, &msg1).unwrap();
        let (mut hch, _, msg2) = rsp
            .respond(
                &mut OsRng,
                HostHello {
                    host_version: None,
                    profile_hash: None,
                    resume_ticket: String::new(),
                },
                0,
            )
            .unwrap();

        let mut ch: *mut AirdressShellChannel = ptr::null_mut();
        let mut hj = AirdressShellBuf::empty();
        // SAFETY: `hs` is the live handle from above, consumed here; the
        // rest are a slice input and local outputs.
        let rc = unsafe {
            airdress_shell_initiator_finish(hs, msg2.as_ptr(), msg2.len(), 0, &mut ch, &mut hj)
        };
        assert_eq!(rc, 0);
        // SAFETY: the buffer the call above wrote, freed once.
        unsafe { airdress_shell_buf_free(hj) };

        let mut rec = AirdressShellBuf::empty();
        // SAFETY: `ch` is the live channel; a one-byte input; a local output.
        let rc = unsafe { airdress_shell_channel_seal(ch, b"x".as_ptr(), 1, 0, &mut rec) };
        assert_eq!(rc, 0);
        // SAFETY: a non-empty buffer the call above wrote on success.
        let r = unsafe { std::slice::from_raw_parts(rec.ptr, rec.len) }.to_vec();
        // SAFETY: that buffer, unchanged, freed once.
        unsafe { airdress_shell_buf_free(rec) };
        assert_eq!(hch.open(&r).unwrap().1, b"x");

        // A replay through the ABI is a status, not a panic.
        let back = hch.seal(b"y", 0).unwrap();
        let mut n = 0u64;
        let mut pt = AirdressShellBuf::empty();
        // SAFETY: the live channel, a slice input, local outputs.
        let rc =
            unsafe { airdress_shell_channel_open(ch, back.as_ptr(), back.len(), &mut n, &mut pt) };
        assert_eq!(rc, 0);
        // SAFETY: the buffer the call above wrote, freed once.
        unsafe { airdress_shell_buf_free(pt) };
        let mut pt = AirdressShellBuf::empty();
        // SAFETY: as above.
        let rc =
            unsafe { airdress_shell_channel_open(ch, back.as_ptr(), back.len(), &mut n, &mut pt) };
        assert_eq!(rc, STATUS_RECORD_REJECTED);
        // SAFETY: the live channel, freed once and not used again.
        unsafe { airdress_shell_channel_free(ch) };
    }

    #[test]
    fn null_arguments_are_statuses() {
        // SAFETY: every pointer is null, which each function must refuse.
        unsafe {
            assert_eq!(
                airdress_shell_keypair_generate(ptr::null_mut(), ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(
                airdress_shell_channel_seal(ptr::null_mut(), ptr::null(), 0, 0, ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(
                airdress_shell_messages_decode(ptr::null(), 3, ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
        }
    }

    /// A length no allocation can have used to reach `from_raw_parts`,
    /// which is undefined behaviour in release and aborts the host process
    /// in a debug build (a debug precondition check, not a panic, so
    /// `catch_unwind` cannot stop it). It is a status now.
    #[test]
    fn an_impossible_length_is_a_status_not_an_abort() {
        let one = [0u8; 1];
        let mut out = AirdressShellBuf::empty();
        // SAFETY: the pointer is valid for one byte; the length is the bug
        // under test and must be refused before any read.
        let rc = unsafe { airdress_shell_fingerprint(one.as_ptr(), usize::MAX, &mut out) };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
        let past = usize::try_from(isize::MAX).unwrap() + 1;
        // SAFETY: as above.
        let rc = unsafe { airdress_shell_messages_decode(one.as_ptr(), past, &mut out) };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
    }

    /// A misaligned output pointer is refused, not written through, even
    /// when every other argument is good.
    #[test]
    fn a_misaligned_output_is_a_status() {
        let host = ShellKeypair::generate(&mut OsRng);
        let local = ShellKeypair::generate(&mut OsRng);
        let pro =
            br#"{"airdress":"a","machineId":"m","sessionId":"s","profileId":"p","action":"open"}"#;
        let hello = br#"{"device":"d","cols":80,"rows":24}"#;
        let mut words = [0usize; 2];
        let odd = words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<*mut AirdressShellInitiator>();
        let mut m1 = AirdressShellBuf::empty();
        // SAFETY: good keys and inputs; `odd` lies inside `words` and must
        // be refused for its alignment before anything is written.
        let rc = unsafe {
            airdress_shell_initiator_start(
                local.secret().as_ptr(),
                host.public().as_ptr(),
                pro.as_ptr(),
                pro.len(),
                hello.as_ptr(),
                hello.len(),
                odd,
                &mut m1,
            )
        };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
        assert_eq!(words, [0, 0]);
        assert!(m1.ptr.is_null());
    }
}
