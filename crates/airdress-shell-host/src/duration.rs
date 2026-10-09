//! Durations as a person writes them in the profile file: `24h`, `7d`,
//! `30m`, `10s`, `500ms`. One number, one unit.

use std::time::Duration;

use anyhow::{bail, Result};

/// Parse `<n><unit>`, unit one of `ms`, `s`, `m`, `h`, `d`.
pub fn parse(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let split = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (n, unit) = raw.split_at(split);
    let Ok(n) = n.parse::<u64>() else {
        bail!("`{raw}` is not a duration (write it as 24h, 7d, 30m or 10s)");
    };
    let secs = match unit {
        "ms" => return Ok(Duration::from_millis(n)),
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => bail!("`{raw}` is not a duration (write it as 24h, 7d, 30m or 10s)"),
    };
    Ok(Duration::from_secs(secs))
}

/// The shortest exact spelling of `d` in the units [`parse`] reads.
pub fn format(d: Duration) -> String {
    let ms = d.as_millis();
    if !ms.is_multiple_of(1000) {
        return format!("{ms}ms");
    }
    let s = d.as_secs();
    if s != 0 && s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s != 0 && s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s != 0 && s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_round_trip() {
        for (raw, secs) in [("24h", 86_400), ("7d", 604_800), ("30m", 1800), ("10s", 10)] {
            assert_eq!(parse(raw).unwrap(), Duration::from_secs(secs), "{raw}");
            assert_eq!(
                parse(&format(parse(raw).unwrap())).unwrap(),
                parse(raw).unwrap()
            );
        }
        assert_eq!(format(Duration::from_secs(86_400)), "1d");
        assert_eq!(parse("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(format(Duration::from_millis(1500)), "1500ms");
        for bad in ["", "h", "1x", "1.5h", "-1h", "1 h"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
