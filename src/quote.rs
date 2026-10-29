//! The words of a quoted message, as a reply carries them and as a
//! session is shown them: plain text, bidi controls removed, whitespace
//! runs one space, at most [`SNIPPET_MAX`] grapheme clusters, cut at a
//! cluster boundary with `…` (SPEC-174 design §2.1).

use unicode_segmentation::UnicodeSegmentation as _;

/// Longest snippet, in grapheme clusters, the ellipsis included.
pub const SNIPPET_MAX: usize = 140;

/// A character that reorders text around it, which a quote never keeps:
/// a quoted fragment must not reorder the line it is shown in.
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// The snippet of `text`.
pub fn snippet(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !is_bidi_control(*c)).collect();
    let collapsed = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    let clusters: Vec<&str> = collapsed.graphemes(true).collect();
    if clusters.len() <= SNIPPET_MAX {
        return collapsed;
    }
    let mut out: String = clusters[..SNIPPET_MAX - 1].concat();
    out.push('…');
    out
}

/// How many grapheme clusters `s` has.
pub fn clusters(s: &str) -> usize {
    s.graphemes(true).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snippet_is_plain_one_line_and_cut_at_a_cluster() {
        assert_eq!(snippet(" a\n\n b\u{202E} "), "a b");
        let s = snippet(&"e\u{301}".repeat(300));
        assert_eq!(clusters(&s), SNIPPET_MAX);
        assert!(s.ends_with("e\u{301}…"));
    }
}
