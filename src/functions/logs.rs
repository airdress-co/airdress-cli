//! `airdress functions logs` — reading the durable per-function log.
//!
//! Every row carries an `id`. Without `after` the route answers newest
//! first (at most `limit`), which is printed reversed; with `after=<id>` it
//! answers only the rows after that one, oldest first. Following is polling
//! with `after` set to the last id shown.

use anyhow::{bail, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::Value;

/// `--since`: an RFC 3339 instant, or a span back from now (`90s`, `15m`,
/// `2h`, `7d`).
pub fn parse_since(raw: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Ok(t.with_timezone(&Utc));
    }
    let (n, unit) = raw.split_at(raw.len().saturating_sub(1));
    let n: i64 = n
        .parse()
        .map_err(|_| anyhow::anyhow!("--since is an RFC 3339 time or a span like 15m, 2h, 7d"))?;
    let span = match unit {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        _ => bail!("--since is an RFC 3339 time or a span like 15m, 2h, 7d"),
    };
    Ok(now - span)
}

/// An instant as the route's `since` takes it.
pub fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

/// One row as a line.
pub fn format_line(row: &Value) -> String {
    let at = row["at"].as_str().unwrap_or("?");
    let level = row["level"].as_str().unwrap_or("?");
    let kind = row["kind"].as_str().unwrap_or("?");
    let inv = row["invocation"].as_str().unwrap_or("");
    let body = &row["body"];
    let text = match kind {
        "invocation" => format!(
            "status={} durationMs={}",
            scalar(&body["status"]),
            scalar(&body["durationMs"])
        ),
        "log" => {
            let msg = body["message"].as_str().unwrap_or_default().to_owned();
            match body.get("fields").filter(|f| !is_empty(f)) {
                Some(f) => format!("{msg} {f}"),
                None => msg,
            }
        }
        _ => body.to_string(),
    };
    format!("{at} {level:<5} {kind:<10} {inv} {text}")
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// Where a read of the log has got to.
#[derive(Debug, Default)]
pub struct Cursor {
    /// The last row id shown; the next poll's `after`.
    pub after: Option<i64>,
}

impl Cursor {
    /// Take one page and return its rows oldest first. A page read without
    /// a cursor comes newest first and is reversed; a page read with one
    /// is already oldest first. Advances the cursor to the last id.
    pub fn take(&mut self, page: &[Value]) -> Vec<Value> {
        let mut rows: Vec<Value> = if self.after.is_none() {
            page.iter().rev().cloned().collect()
        } else {
            page.to_vec()
        };
        // The route never answers a row at or before `after`; holding that
        // here too costs one comparison and keeps a line from printing twice.
        if let Some(after) = self.after {
            rows.retain(|r| r["id"].as_i64().is_none_or(|id| id > after));
        }
        if let Some(last) = rows.iter().filter_map(|r| r["id"].as_i64()).max() {
            self.after = Some(self.after.map_or(last, |a| a.max(last)));
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(at: &str, msg: &str) -> Value {
        serde_json::json!({
            "version": "sha256:aa", "invocation": "0123456789abcdef", "at": at,
            "level": "info", "kind": "log", "body": { "message": msg, "fields": {} }
        })
    }

    #[test]
    fn since_takes_an_instant_or_a_span() {
        let now = DateTime::parse_from_rfc3339("2026-09-25T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            rfc3339(parse_since("15m", now).unwrap()),
            "2026-09-25T11:45:00Z"
        );
        assert_eq!(
            rfc3339(parse_since("2026-09-25T10:00:00+02:00", now).unwrap()),
            "2026-09-25T08:00:00Z"
        );
        assert!(parse_since("yesterday", now).is_err());
        assert!(parse_since("5w", now).is_err());
    }

    fn with_id(mut r: Value, id: i64) -> Value {
        r["id"] = id.into();
        r
    }

    #[test]
    fn the_first_page_is_reversed_and_later_ones_are_taken_as_they_come() {
        let mut c = Cursor::default();
        // Without a cursor: newest first.
        let first = vec![
            with_id(row("2026-09-25T10:00:02Z", "b"), 11),
            with_id(row("2026-09-25T10:00:01Z", "a"), 10),
        ];
        let shown: Vec<_> = c
            .take(&first)
            .iter()
            .map(|r| r["body"]["message"].clone())
            .collect();
        assert_eq!(shown, ["a", "b"]);
        assert_eq!(c.after, Some(11));
        // With `after=11`: oldest first, same instant or not.
        let second = vec![
            with_id(row("2026-09-25T10:00:02Z", "b"), 12),
            with_id(row("2026-09-25T10:00:03Z", "c"), 13),
        ];
        let shown: Vec<_> = c
            .take(&second)
            .iter()
            .map(|r| r["body"]["message"].clone())
            .collect();
        assert_eq!(
            shown,
            ["b", "c"],
            "an identical line is a new row, and is shown"
        );
        assert_eq!(c.after, Some(13));
        assert!(c.take(&[]).is_empty());
        assert_eq!(c.after, Some(13));
    }

    #[test]
    fn lines_read_as_a_log() {
        assert_eq!(
            format_line(&row("2026-09-25T10:00:01Z", "hi")),
            "2026-09-25T10:00:01Z info  log        0123456789abcdef hi"
        );
        let inv = serde_json::json!({
            "invocation": "abc", "at": "t", "level": "info", "kind": "invocation",
            "body": { "status": 200, "durationMs": 12 }
        });
        assert_eq!(
            format_line(&inv),
            "t info  invocation abc status=200 durationMs=12"
        );
    }
}
