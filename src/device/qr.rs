//! SPEC-044 — Unicode-half-block QR rendering for the terminal.
//!
//! Uses the `qrcodegen` crate (pure Rust, MIT) at error-correction
//! level Medium with auto-version selection (smallest version that
//! fits the input). The renderer is a pure function of the input
//! string; a snapshot test pins the output so refactors can't
//! silently change rendering.
//!
//! ## Half-block encoding
//!
//! Two QR modules occupy one terminal row of one character:
//!
//! | top dark | bot dark | glyph |
//! |----------|----------|-------|
//! | yes      | yes      | `█`   |
//! | yes      | no       | `▀`   |
//! | no       | yes      | `▄`   |
//! | no       | no       | (space) |
//!
//! A 2-module-wide quiet zone surrounds the QR per the spec.

use anyhow::Result;
use qrcodegen::{QrCode, QrCodeEcc};

const QUIET_ZONE: i32 = 2;

/// Render a QR for `text` as a single string of Unicode half-blocks
/// plus newlines, ready to print to a terminal.
///
/// # Errors
///
/// Returns an error if `text` is too long to fit into any QR
/// version at ECC Medium (extremely unlikely for our < 200-byte
/// `airdress-pair://` URIs).
pub fn render(text: &str) -> Result<String> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium)
        .map_err(|e| anyhow::anyhow!("QR encode failed: {e}"))?;
    Ok(render_qr(&qr))
}

fn render_qr(qr: &QrCode) -> String {
    let size = qr.size();
    let total = size + 2 * QUIET_ZONE;
    // Each terminal row covers two QR rows (top + bot).
    let row_pairs = (total + 1) / 2;
    let mut out = String::with_capacity(((total + 1) * row_pairs) as usize);

    for row_pair in 0..row_pairs {
        let top_qy = row_pair * 2 - QUIET_ZONE;
        let bot_qy = top_qy + 1;
        for qx_zoned in 0..total {
            let qx = qx_zoned - QUIET_ZONE;
            let top = qr_module(qr, qx, top_qy);
            let bot = qr_module(qr, qx, bot_qy);
            out.push(glyph(top, bot));
        }
        out.push('\n');
    }
    out
}

/// Look up a single QR module, returning `false` for any coordinate
/// outside the QR's own grid (i.e. the quiet zone is always light).
fn qr_module(qr: &QrCode, x: i32, y: i32) -> bool {
    let size = qr.size();
    if x < 0 || y < 0 || x >= size || y >= size {
        return false;
    }
    qr.get_module(x, y)
}

const fn glyph(top: bool, bot: bool) -> char {
    match (top, bot) {
        (true, true) => '\u{2588}',  // █  full block
        (true, false) => '\u{2580}', // ▀  upper half block
        (false, true) => '\u{2584}', // ▄  lower half block
        (false, false) => ' ',
    }
}

/// Convenience: render and print to stdout.
///
/// # Errors
///
/// Same as [`render`].
pub fn render_to_stdout(text: &str) -> Result<()> {
    let out = render(text)?;
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same fixed URI is used by the snapshot fixture
    /// (`tests/fixtures/qr-snapshot.txt`). Pinning this URI means
    /// the snapshot is deterministic across runs and platforms.
    const FIXTURE_URI: &str = "airdress-pair://test.a.airdr.es/p?s=ABCDEFGH12345678";

    #[test]
    fn render_produces_nonempty_output() {
        let out = render(FIXTURE_URI).unwrap();
        assert!(!out.is_empty());
        assert!(out.contains('\n'));
        // Should contain at least one block glyph somewhere.
        assert!(out.chars().any(|c| matches!(c, '█' | '▀' | '▄')));
    }

    #[test]
    fn render_includes_quiet_zone() {
        let out = render(FIXTURE_URI).unwrap();
        let first_line = out.lines().next().unwrap();
        // The full top quiet-zone row pair is at row_pair=0, where top
        // is at y=-2 (quiet) and bot is at y=-1 (quiet). Both light →
        // a row of spaces. Width is QR-size + 2*QUIET_ZONE characters.
        assert!(first_line.chars().all(|c| c == ' '));
    }

    #[test]
    fn render_is_deterministic() {
        let a = render(FIXTURE_URI).unwrap();
        let b = render(FIXTURE_URI).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn render_changes_with_input() {
        let a = render(FIXTURE_URI).unwrap();
        let b = render("airdress-pair://test.a.airdr.es/p?s=DIFFERENT").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn glyph_table_complete() {
        assert_eq!(glyph(true, true), '\u{2588}');
        assert_eq!(glyph(true, false), '\u{2580}');
        assert_eq!(glyph(false, true), '\u{2584}');
        assert_eq!(glyph(false, false), ' ');
    }
}
