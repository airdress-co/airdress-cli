//! Output bounds (SPEC-133 §6.4).
//!
//! A tool result goes into a model's context whether it is useful or
//! not, so every one of them is capped, and a truncated result says
//! which argument fetches the rest. Pages are 20 items by default and
//! 100 at most, whatever the caller asks for.

use airdress_mcp_catalogue::{LIMIT_DEFAULT, LIMIT_MAX, RESULT_MAX_CHARS};
use serde_json::Value;

/// Clamp a caller's `limit` into the catalogue's bounds.
pub fn limit(requested: Option<i64>) -> usize {
    match requested {
        None => LIMIT_DEFAULT,
        Some(n) if n < 1 => 1,
        Some(n) => (n as usize).min(LIMIT_MAX),
    }
}

/// One page of a list, plus the cursor that continues it.
///
/// The cursor is the offset as a decimal string. It is opaque to the
/// caller by contract, not by obfuscation — nothing is hidden in it,
/// and a client that invents one gets a page, not an error.
#[derive(Debug)]
pub struct Page {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
    pub total: usize,
}

/// Take one page out of `items`.
pub fn page(items: Vec<Value>, cursor: Option<&str>, requested: Option<i64>) -> Page {
    let total = items.len();
    let start = cursor
        .and_then(|c| c.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(total);
    let size = limit(requested);
    let end = (start + size).min(total);
    let next = (end < total).then(|| end.to_string());
    Page {
        items: items[start..end].to_vec(),
        next_cursor: next,
        total,
    }
}

/// Cap one rendered result.
///
/// Returns the text and, when it had to be cut, a sentence naming what
/// to do about it. The cut is on a character boundary, because a
/// truncated UTF-8 sequence is not text.
pub fn cap(text: String, how_to_get_the_rest: &str) -> (String, Option<String>) {
    if text.chars().count() <= RESULT_MAX_CHARS {
        return (text, None);
    }
    let kept: String = text.chars().take(RESULT_MAX_CHARS).collect();
    (
        kept,
        Some(format!(
            "This result was cut at {RESULT_MAX_CHARS} characters. {how_to_get_the_rest}"
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn limits_are_clamped_not_rejected() {
        assert_eq!(limit(None), LIMIT_DEFAULT);
        assert_eq!(limit(Some(0)), 1);
        assert_eq!(limit(Some(-5)), 1);
        assert_eq!(limit(Some(7)), 7);
        assert_eq!(limit(Some(1_000)), LIMIT_MAX);
    }

    #[test]
    fn paging_walks_the_whole_list_once() {
        let items: Vec<Value> = (0..250).map(|i| json!(i)).collect();
        let first = page(items.clone(), None, Some(100));
        assert_eq!(first.items.len(), 100);
        assert_eq!(first.total, 250);
        let second = page(items.clone(), first.next_cursor.as_deref(), Some(100));
        assert_eq!(second.items[0], json!(100));
        let third = page(items.clone(), second.next_cursor.as_deref(), Some(100));
        assert_eq!(third.items.len(), 50);
        assert!(third.next_cursor.is_none());
        // A nonsense cursor is the start, not an error.
        assert_eq!(page(items, Some("nonsense"), Some(1)).items[0], json!(0));
    }

    #[test]
    fn a_capped_result_says_how_to_get_the_rest() {
        let (text, note) = cap("short".into(), "Pass after=<id>.");
        assert_eq!(text, "short");
        assert!(note.is_none());

        let long = "ä".repeat(RESULT_MAX_CHARS + 10);
        let (text, note) = cap(long, "Pass after=<id>.");
        assert_eq!(text.chars().count(), RESULT_MAX_CHARS);
        assert!(note.unwrap().contains("after=<id>"));
    }
}
