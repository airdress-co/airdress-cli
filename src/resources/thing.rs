//! The `Thing` Kind's list table for `airdress get thing`.
//!
//! The operator does not put its list columns on the wire, so the CLI
//! mirrors them: EVENTS, COMMANDS, CHANNEL, FIRMWARE and LAST SEEN, the
//! same getters as the operator's `things::kind` (SPEC-120).

use serde_json::Value;

use super::client::ResourceView;

pub const KIND: &str = "Thing";

/// The channel a Thing has: the live state when the operator has reported
/// one, otherwise the mode its spec asks for. An unset mode is `held` when
/// the Thing declares commands and `off` when it declares none — the
/// operator's default.
fn channel(spec: &Value, status: &Value) -> String {
    if let Some(state) = status["channel"]["state"].as_str() {
        return state.to_owned();
    }
    if let Some(mode) = spec["channel"]["mode"].as_str() {
        return mode.to_owned();
    }
    if count(&spec["commands"]) > 0 {
        "held".to_owned()
    } else {
        "off".to_owned()
    }
}

fn count(v: &Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

fn or_dash(s: Option<&str>) -> String {
    s.filter(|s| !s.is_empty()).unwrap_or("—").to_owned()
}

pub fn render_table(items: &[ResourceView]) -> String {
    let header = [
        "NAME",
        "EVENTS",
        "COMMANDS",
        "CHANNEL",
        "FIRMWARE",
        "LAST SEEN",
    ];
    let rows: Vec<[String; 6]> = items
        .iter()
        .map(|v| {
            let (spec, s) = (&v.spec, &v.status);
            [
                v.metadata.name.clone(),
                count(&spec["events"]["types"]).to_string(),
                count(&spec["commands"]).to_string(),
                channel(spec, s),
                or_dash(s["firmware"].as_str()),
                or_dash(s["lastSeenAt"].as_str()),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r.iter()) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        cells
            .iter()
            .zip(widths.iter())
            .map(|(c, w)| format!("{c:<w$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut out = vec![line(header.to_vec())];
    for r in &rows {
        out.push(line(r.iter().map(String::as_str).collect()));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn view(name: &str, spec: Value, status: Value) -> ResourceView {
        serde_json::from_value(json!({
            "apiVersion": crate::wire::API_VERSION,
            "kind": "Thing",
            "metadata": {
                "name": name, "generation": 1, "resourceVersion": "3",
                "created_at": "2026-09-29T08:00:00Z", "updated_at": "2026-09-29T08:00:00Z"
            },
            "spec": spec,
            "status": status,
        }))
        .unwrap()
    }

    const MACHINE: &str = "0198a1b2-0000-4000-8000-00000000abcd";

    fn cells(line: &str) -> Vec<&str> {
        line.split_whitespace().collect()
    }

    #[test]
    fn the_table_has_the_operators_columns_and_the_live_channel() {
        let v = view(
            "roof-skywatch",
            json!({
                "machine": MACHINE,
                "events": {"types": ["position.seen", "aircraft.seen", "rid.seen", "cue.done"]},
                "commands": [{"name": "cue"}, {"name": "point"}, {"name": "record"}],
                "channel": {"mode": "held"},
                "enabled": true
            }),
            json!({
                "firmware": "skywatch-0.1.0",
                "lastSeenAt": "2026-09-29T08:05:00Z",
                "channel": {"state": "live", "since": "2026-09-29T08:01:00Z", "rotations24h": 4},
                "events": {"accepted24h": 10}
            }),
        );
        let t = render_table(&[v]);
        let mut lines = t.lines();
        assert_eq!(
            cells(lines.next().unwrap()),
            ["NAME", "EVENTS", "COMMANDS", "CHANNEL", "FIRMWARE", "LAST", "SEEN"]
        );
        assert_eq!(
            cells(lines.next().unwrap()),
            [
                "roof-skywatch",
                "4",
                "3",
                "live",
                "skywatch-0.1.0",
                "2026-09-29T08:05:00Z"
            ]
        );
    }

    #[test]
    fn a_thing_never_seen_shows_its_mode_and_dashes() {
        let held = view(
            "gate",
            json!({"machine": MACHINE, "commands": [{"name": "open"}]}),
            json!({}),
        );
        let silent = view(
            "meter",
            json!({"machine": MACHINE, "events": {"types": ["reading"]}}),
            json!({}),
        );
        let wake = view(
            "buoy",
            json!({"machine": MACHINE, "commands": [{"name": "ping"}], "channel": {"mode": "wake"}}),
            json!({}),
        );
        let t = render_table(&[held, silent, wake]);
        let rows: Vec<Vec<&str>> = t.lines().skip(1).map(cells).collect();
        assert_eq!(rows[0], ["gate", "0", "1", "held", "—", "—"]);
        assert_eq!(rows[1], ["meter", "1", "0", "off", "—", "—"]);
        assert_eq!(rows[2], ["buoy", "0", "1", "wake", "—", "—"]);
    }
}
