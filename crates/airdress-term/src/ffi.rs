// cspell:ignore ARGB
//! The C ABI the Android app loads (the `.so` of this crate's cdylib).
//!
//! Every exported symbol is listed in `ffi-symbols.txt`; a unit test holds
//! this file and the list to each other, and `scripts/term-ffi-symbols.sh`
//! holds the list to `nm` on the built Android library.
//!
//! Conventions, the protocol crate's:
//!
//! - Functions return an `i32` status ([`STATUS_OK`] or a `STATUS_*`)
//!   unless they say otherwise. A panic never crosses the boundary; it
//!   becomes [`STATUS_INTERNAL`].
//! - Byte inputs are `(ptr, len)`; null only with a length of zero.
//! - Byte outputs are an [`AirdressTermBuf`] freed with
//!   `airdress_term_buf_free`.
//! - The cell snapshot is written into a caller's buffer, so a painter
//!   that keeps one buffer allocates nothing per frame.
//!
//! # Safety contract
//!
//! Every `unsafe extern "C"` function below relies on the caller (the Dart
//! bindings in airdress-chat, `lib/ffi/terminal_bindings.dart`, driven by
//! `lib/features/shells/terminal/terminal_model.dart`) for the following.
//! Each function's own `# Safety` section names which apply.
//!
//! 1. **Screen.** `t` is a pointer `airdress_term_new` returned and
//!    `airdress_term_free` has not yet freed, or null (refused). No handle
//!    is locked internally: a screen may be used from any thread, but never
//!    by two calls at once. The Dart model calls synchronously from one
//!    isolate, which satisfies this.
//! 2. **Inputs.** A `(ptr, len)` input is null with `len == 0`, or points to
//!    `len` initialised bytes that stay valid and unwritten for the call.
//!    The library only borrows it. A `len` above `isize::MAX` is refused.
//! 3. **Outputs.** An output pointer is null (refused) or points to
//!    writable storage for one value of its type, aligned for it (a
//!    misaligned pointer is refused). It may be uninitialised; the library
//!    writes it without reading it. The snapshot buffer is `cap` writable,
//!    4-byte-aligned `u32`s, which may also be uninitialised.
//! 4. **Buffers.** An [`AirdressTermBuf`] written by this library is passed
//!    back to `airdress_term_buf_free` exactly once, with `ptr` and `len`
//!    unchanged, and never to the C allocator's `free`: Rust's global
//!    allocator made it.
#![allow(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::{Screen, State, TermError};

/// Success.
pub const STATUS_OK: i32 = 0;
/// A null pointer, a bad length, or a size out of range.
pub const STATUS_INVALID_ARGUMENT: i32 = 1;
/// The output buffer is smaller than the grid.
pub const STATUS_BUFFER_TOO_SMALL: i32 = 2;
/// A panic inside the library.
pub const STATUS_INTERNAL: i32 = 99;

fn status(e: TermError) -> i32 {
    match e {
        TermError::BadSize | TermError::OutOfRange => STATUS_INVALID_ARGUMENT,
        TermError::BufferTooSmall => STATUS_BUFFER_TOO_SMALL,
    }
}

/// A byte buffer owned by this library. Free with `airdress_term_buf_free`.
#[repr(C)]
#[derive(Debug)]
pub struct AirdressTermBuf {
    /// The bytes; null when `len` is zero.
    pub ptr: *mut u8,
    /// How many.
    pub len: usize,
}

impl AirdressTermBuf {
    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
        let b = v.into_boxed_slice();
        let len = b.len();
        Self {
            ptr: Box::into_raw(b).cast::<u8>(),
            len,
        }
    }
}

/// One screen.
pub struct AirdressTerm(Screen);

impl std::fmt::Debug for AirdressTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AirdressTerm(..)")
    }
}

fn guard(f: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(code)) => code,
        Err(_) => STATUS_INTERNAL,
    }
}

/// Borrow the screen behind a handle.
///
/// # Safety
///
/// `t` is null or a live screen no other call is using (contract 1).
unsafe fn screen<'a>(t: *mut AirdressTerm) -> Result<&'a mut Screen, i32> {
    // SAFETY: a live handle came from `Box::into_raw`, so it is aligned and
    // points to an initialised `AirdressTerm`; contract 1 makes this the
    // only reference for the call. Null becomes `None`.
    unsafe { t.as_mut() }
        .map(|t| &mut t.0)
        .ok_or(STATUS_INVALID_ARGUMENT)
}

/// Write one value to an output pointer, without reading what was there.
///
/// # Safety
///
/// `out` is null or valid for a write of one `T` (contract 3). Null and
/// misalignment are checked here.
unsafe fn put<T>(out: *mut T, v: T) -> Result<(), i32> {
    if out.is_null() || !out.is_aligned() {
        return Err(STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: `out` is non-null and aligned (checked above) and valid for
    // one write of `T` (the caller's contract); `write` neither reads nor
    // drops the old contents, which may be uninitialised.
    unsafe { out.write(v) };
    Ok(())
}

/// The model's version (returns it; no status).
#[no_mangle]
pub extern "C" fn airdress_term_version() -> u32 {
    crate::VERSION
}

/// Free a buffer this library returned. Safe on an empty buffer.
///
/// # Safety
///
/// `buf` was written by this library and not freed yet, with `ptr` and
/// `len` unchanged, or `ptr` is null (contract 4). It is not read after
/// this call.
#[no_mangle]
pub unsafe extern "C" fn airdress_term_buf_free(buf: AirdressTermBuf) {
    if !buf.ptr.is_null() && buf.len > 0 {
        // SAFETY: a non-empty buffer was made by `from_vec` from a
        // `Box<[u8]>` of exactly `len` bytes; rebuilding that fat pointer
        // and dropping the box returns it to the allocator that made it.
        // The caller frees it once (contract 4).
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}

/// A new `cols`×`rows` screen with `scrollback` lines; null on a bad size.
#[no_mangle]
pub extern "C" fn airdress_term_new(cols: u16, rows: u16, scrollback: u32) -> *mut AirdressTerm {
    match catch_unwind(|| Screen::new(cols, rows, scrollback)) {
        Ok(Ok(s)) => Box::into_raw(Box::new(AirdressTerm(s))),
        _ => ptr::null_mut(),
    }
}

/// Free a screen.
///
/// # Safety
///
/// `t` is null or a live screen (contract 1), not used again after this
/// call.
#[no_mangle]
pub unsafe extern "C" fn airdress_term_free(t: *mut AirdressTerm) {
    if !t.is_null() {
        // SAFETY: a live handle is a pointer `Box::into_raw` returned in
        // `airdress_term_new` and not yet reclaimed; the caller never uses
        // it again, so this is its only owner.
        drop(unsafe { Box::from_raw(t) });
    }
}

/// Start over at `cols`×`rows` (before writing a snapshot).
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_reset(t: *mut AirdressTerm, cols: u16, rows: u16) -> i32 {
    // SAFETY: `t` per this function's contract.
    guard(|| unsafe { screen(t)? }.reset(cols, rows).map_err(status))
}

/// The default foreground and background, ARGB.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_set_default_colors(
    t: *mut AirdressTerm,
    fg: u32,
    bg: u32,
) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        unsafe { screen(t)? }.set_default_colors(fg, bg);
        Ok(())
    })
}

/// Feed program output.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1), and
/// `(bytes, len)` an input (contract 2).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_feed(
    t: *mut AirdressTerm,
    bytes: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        let s = unsafe { screen(t)? };
        if bytes.is_null() {
            return if len == 0 {
                Ok(())
            } else {
                Err(STATUS_INVALID_ARGUMENT)
            };
        }
        // `from_raw_parts` on a length past `isize::MAX` is undefined
        // behaviour, and aborts the process in a debug build.
        if isize::try_from(len).is_err() {
            return Err(STATUS_INVALID_ARGUMENT);
        }
        // SAFETY: `bytes` is non-null and, per contract 2, points to `len`
        // initialised bytes nothing writes during the call; `u8` needs no
        // alignment; `len <= isize::MAX` was checked above. The bytes are
        // the caller's, so they cannot alias the screen.
        s.feed(unsafe { std::slice::from_raw_parts(bytes, len) });
        Ok(())
    })
}

/// Change the size.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_resize(t: *mut AirdressTerm, cols: u16, rows: u16) -> i32 {
    // SAFETY: `t` per this function's contract.
    guard(|| unsafe { screen(t)? }.resize(cols, rows).map_err(status))
}

/// Scroll the view by `lines` (positive is back into history).
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_scroll(t: *mut AirdressTerm, lines: i32) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        unsafe { screen(t)? }.scroll(lines);
        Ok(())
    })
}

/// Follow the bottom again.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_scroll_to_bottom(t: *mut AirdressTerm) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        unsafe { screen(t)? }.scroll_to_bottom();
        Ok(())
    })
}

/// The painter's state.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1), and `out`
/// points to writable storage for one [`State`] (`#[repr(C)]`, 8-byte
/// aligned for its `u64`; contract 3). Dart's `TermStateC` mirrors it field
/// for field.
#[no_mangle]
pub unsafe extern "C" fn airdress_term_state(t: *mut AirdressTerm, out: *mut State) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        let st = unsafe { screen(t)? }.state();
        // SAFETY: `out` is an output for one `State` per this function's
        // contract; null and misalignment are refused.
        unsafe { put(out, st) }
    })
}

/// Write the viewport's cells (`cols * rows * 4` words) into `out`, which
/// holds `cap` words.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1). `out` is null
/// (refused) or points to `cap` writable `u32`s, 4-byte aligned, that
/// nothing else reads or writes during the call (contract 3). They may be
/// uninitialised: the library zeroes them before viewing them as a slice.
#[no_mangle]
pub unsafe extern "C" fn airdress_term_snapshot(
    t: *mut AirdressTerm,
    out: *mut u32,
    cap: usize,
) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        let s = unsafe { screen(t)? };
        if out.is_null() || !out.is_aligned() {
            return Err(STATUS_INVALID_ARGUMENT);
        }
        // A slice may not span more than `isize::MAX` bytes.
        let fits = cap
            .checked_mul(std::mem::size_of::<u32>())
            .is_some_and(|b| isize::try_from(b).is_ok());
        if !fits {
            return Err(STATUS_INVALID_ARGUMENT);
        }
        // SAFETY: `out` is non-null and aligned (checked above) and valid
        // for writes of `cap` `u32`s (the caller's contract), and `cap`
        // words fit in `isize::MAX` bytes. The caller's buffer may be
        // uninitialised (the Dart model `malloc`s it), and a `&mut [u32]`
        // over uninitialised memory is undefined behaviour, so it is
        // zeroed first; then every element is an initialised `u32`, and
        // nothing else touches it during the call.
        let buf = unsafe {
            ptr::write_bytes(out, 0, cap);
            std::slice::from_raw_parts_mut(out, cap)
        };
        s.snapshot(buf).map(|_| ()).map_err(status)
    })
}

/// One cell's whole text (with combining characters), UTF-8.
///
/// # Safety
///
/// `t` is a live screen no other call is using (contract 1), and `out` an
/// output for one [`AirdressTermBuf`] (contract 3), the caller's to free
/// (contract 4).
#[no_mangle]
pub unsafe extern "C" fn airdress_term_cell_text(
    t: *mut AirdressTerm,
    row: u16,
    col: u16,
    out: *mut AirdressTermBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        let text = unsafe { screen(t)? }.cell_text(row, col).map_err(status)?;
        // SAFETY: `out` is a buffer output per this function's contract.
        unsafe { put(out, AirdressTermBuf::from_vec(text.into_bytes())) }
    })
}

/// The answers the program asked for since the last call (only the typist
/// sends them on, as input).
///
/// # Safety
///
/// As [`airdress_term_cell_text`].
#[no_mangle]
pub unsafe extern "C" fn airdress_term_take_replies(
    t: *mut AirdressTerm,
    out: *mut AirdressTermBuf,
) -> i32 {
    guard(|| {
        if out.is_null() || !out.is_aligned() {
            // Checked before taking, so a bad output does not lose replies.
            return Err(STATUS_INVALID_ARGUMENT);
        }
        // SAFETY: `t` per this function's contract.
        let r = unsafe { screen(t)? }.take_replies();
        // SAFETY: `out` is a buffer output per this function's contract,
        // checked non-null and aligned above.
        unsafe { put(out, AirdressTermBuf::from_vec(r)) }
    })
}

/// The viewport as UTF-8 text.
///
/// # Safety
///
/// As [`airdress_term_cell_text`].
#[no_mangle]
pub unsafe extern "C" fn airdress_term_screen_text(
    t: *mut AirdressTerm,
    out: *mut AirdressTermBuf,
) -> i32 {
    guard(|| {
        // SAFETY: `t` per this function's contract.
        let text = unsafe { screen(t)? }.screen_text();
        // SAFETY: `out` is a buffer output per this function's contract.
        unsafe { put(out, AirdressTermBuf::from_vec(text.into_bytes())) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exported_here() -> Vec<String> {
        let src = include_str!("ffi.rs");
        let mut out = Vec::new();
        let mut lines = src.lines();
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
        assert!(listed.iter().all(|s| s.starts_with("airdress_term_")));
    }

    #[test]
    fn a_screen_through_the_abi() {
        // SAFETY: `t` is the live screen made here and freed once at the
        // end; every input is a local with its length, every output a
        // local of the right type, and the buffer read is the one the
        // library just wrote, freed once.
        unsafe {
            let t = airdress_term_new(4, 2, 10);
            assert!(!t.is_null());
            let text = "hé";
            assert_eq!(airdress_term_feed(t, text.as_ptr(), text.len()), STATUS_OK);
            let mut st = State::default();
            assert_eq!(airdress_term_state(t, &mut st), STATUS_OK);
            assert_eq!((st.cols, st.rows, st.cursor_col), (4, 2, 2));
            let mut cells = vec![0u32; 4 * 2 * 4];
            assert_eq!(
                airdress_term_snapshot(t, cells.as_mut_ptr(), cells.len()),
                STATUS_OK
            );
            assert_eq!(cells[4], 'é' as u32);
            assert_eq!(
                airdress_term_snapshot(t, cells.as_mut_ptr(), 3),
                STATUS_BUFFER_TOO_SMALL
            );
            let mut buf = AirdressTermBuf {
                ptr: ptr::null_mut(),
                len: 0,
            };
            assert_eq!(airdress_term_screen_text(t, &mut buf), STATUS_OK);
            let s = std::slice::from_raw_parts(buf.ptr, buf.len).to_vec();
            airdress_term_buf_free(buf);
            assert_eq!(String::from_utf8(s).unwrap(), "hé\n");
            airdress_term_free(t);
        }
    }

    #[test]
    fn bad_arguments_are_statuses() {
        // SAFETY: each call either passes the live screen made here or a
        // null the function must refuse; `t` is freed once at the end.
        unsafe {
            assert!(airdress_term_new(0, 1, 0).is_null());
            assert_eq!(
                airdress_term_feed(ptr::null_mut(), ptr::null(), 0),
                STATUS_INVALID_ARGUMENT
            );
            let t = airdress_term_new(2, 2, 0);
            assert_eq!(
                airdress_term_feed(t, ptr::null(), 3),
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(airdress_term_resize(t, 0, 0), STATUS_INVALID_ARGUMENT);
            assert_eq!(
                airdress_term_cell_text(t, 9, 9, ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
            airdress_term_free(t);
        }
    }

    /// A length past `isize::MAX` used to reach `from_raw_parts`: undefined
    /// behaviour in release, and an abort of the host process in a debug
    /// build that `catch_unwind` cannot stop. It is a status now.
    #[test]
    fn an_impossible_length_is_a_status_not_an_abort() {
        let one = *b"x";
        let t = airdress_term_new(4, 2, 0);
        // SAFETY: `t` is live; the pointer is valid for one byte and the
        // length is the bug under test, refused before any read.
        let rc = unsafe { airdress_term_feed(t, one.as_ptr(), usize::MAX) };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
        let mut cells = vec![0u32; 4];
        // SAFETY: as above; `cap` words would overflow `isize::MAX` bytes.
        let rc = unsafe { airdress_term_snapshot(t, cells.as_mut_ptr(), usize::MAX / 2) };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
        // SAFETY: `t` is live and freed once.
        unsafe { airdress_term_free(t) };
    }

    /// The Dart model hands the snapshot a `malloc`ed, uninitialised
    /// buffer. Viewing that as `&mut [u32]` is undefined behaviour, so the
    /// library zeroes it first. Plain `cargo test` cannot see the UB; this
    /// pins the contract (an uninitialised buffer is accepted and the grid
    /// is filled) and is the case to run under Miri (R-UNS-5).
    #[test]
    fn a_snapshot_into_an_uninitialised_buffer() {
        let t = airdress_term_new(2, 1, 0);
        let cap = 2 * crate::WORDS_PER_CELL;
        let mut store: Vec<std::mem::MaybeUninit<u32>> = Vec::with_capacity(cap);
        let out = store.as_mut_ptr().cast::<u32>();
        // SAFETY: `t` is live; `out` points to `cap` writable, aligned,
        // uninitialised `u32`s owned by `store`, as the contract allows.
        let rc = unsafe { airdress_term_snapshot(t, out, cap) };
        assert_eq!(rc, STATUS_OK);
        // SAFETY: the call returned OK, so all `cap` words are written.
        let words = unsafe { std::slice::from_raw_parts(out, cap) };
        assert_eq!(words[0], 0, "an unwritten cell has no code point");
        // SAFETY: `t` is live and freed once.
        unsafe { airdress_term_free(t) };
    }

    /// A misaligned state pointer is refused, not written through.
    #[test]
    fn a_misaligned_state_is_a_status() {
        let t = airdress_term_new(2, 1, 0);
        let mut words = [0u64; 8];
        let odd = words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<State>();
        // SAFETY: `t` is live; `odd` lies inside `words` and must be
        // refused for its alignment before anything is written.
        let rc = unsafe { airdress_term_state(t, odd) };
        assert_eq!(rc, STATUS_INVALID_ARGUMENT);
        assert_eq!(words, [0; 8]);
        // SAFETY: `t` is live and freed once.
        unsafe { airdress_term_free(t) };
    }
}
