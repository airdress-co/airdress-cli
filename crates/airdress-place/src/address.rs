// cspell:ignore Cnchen Luitpold München dlat dlng fract
//! The map address: the URL fragment of maps.airdress.co, written exactly
//! as the page's `formatAddress` writes it (maps SPEC-153, SPEC-171 design
//! §9.4).
//!
//! ```text
//! #map=<zoom>/<lat>/<lng>[/<bearing>[/<pitch>]]&view=<v>&proj=<mode>
//!  &layers=<list>&place=<lat>,<lng>[/<name>]&ask=<answer>&area=r<id>
//! ```
//!
//! Byte for byte, including JavaScript's number formatting: `toFixed`
//! rounds an exact binary tie up (48.25 to one decimal is 48.3, where
//! Rust's own formatting gives 48.2), and `Math.round` rounds a half
//! toward +∞ (-122.5 is -122). The shared vector file holds both cases.
//! Only the writer lives here: a link is written by us and read by the
//! page, so the page's parser is the only one that matters.

use serde::{Deserialize, Serialize};

/// A fragment longer than this is ignored whole by the page, so a writer
/// refuses to hand one out.
pub const MAX_FRAGMENT: usize = 2000;

/// A camera's centre reaches the poles on the globe.
const MAX_CAMERA_LAT: f64 = 90.0;

/// The page's address options, as far as writing needs them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    /// Every switch `layers=` knows, in the page's order, with its default.
    /// Order matters: differences are written in this order.
    #[serde(with = "ordered_switches")]
    pub switches: Vec<(String, bool)>,
    /// The views `view=` may name; `map` is the default and never written.
    pub views: Vec<String>,
    /// The modes `proj=` may name.
    #[serde(default)]
    pub modes: Vec<String>,
    /// The mode `proj=` leaves unsaid.
    #[serde(default)]
    pub default_mode: String,
    /// The answers `ask=` may name.
    #[serde(default)]
    pub asks: Vec<String>,
}

/// A camera; a missing bearing or pitch is 0.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct Camera {
    pub lat: f64,
    pub lng: f64,
    pub zoom: f64,
    #[serde(default)]
    pub bearing: Option<f64>,
    #[serde(default)]
    pub pitch: Option<f64>,
}

/// An open place; an empty name is no name.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Place {
    pub lat: f64,
    pub lng: f64,
    #[serde(default)]
    pub name: String,
}

/// What a link says. Anything absent is left out.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub camera: Option<Camera>,
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    /// Switch states; only the ones that differ from their default are written.
    #[serde(default, with = "ordered_switches_opt")]
    pub layers: Option<Vec<(String, bool)>>,
    #[serde(default)]
    pub place: Option<Place>,
    #[serde(default)]
    pub ask: Option<String>,
    #[serde(default)]
    pub area: Option<f64>,
    /// Pairs passed through after the keys, as `key=value` or a bare `key`.
    #[serde(default)]
    pub extra: Vec<(String, Option<String>)>,
}

/// The fragment for `state` (`#…`), or `""` when there is nothing to say.
/// It may be longer than [`MAX_FRAGMENT`]; the caller decides what to do.
#[must_use]
pub fn format_address(state: &State, o: &Options) -> String {
    let mut pairs: Vec<String> = Vec::new();
    if let Some(c) = state
        .camera
        .filter(|c| [c.lat, c.lng, c.zoom].iter().all(|v| v.is_finite()))
    {
        let zoom = js_round(c.zoom * 100.0) / 100.0;
        let lat = c.lat.clamp(-MAX_CAMERA_LAT, MAX_CAMERA_LAT);
        let (dlat, dlng) = coord_decimals(zoom, lat);
        let mut parts = vec![
            trimmed(zoom, 2),
            trimmed(lat, dlat),
            trimmed(wrap_lng(c.lng), dlng),
        ];
        let bearing = c.bearing.filter(|b| b.is_finite()).map_or(0.0, bearing_of);
        let pitch = c
            .pitch
            .filter(|p| p.is_finite())
            .map_or(0.0, |p| js_round(p.max(0.0)));
        if bearing != 0.0 || pitch != 0.0 {
            parts.push(trimmed(bearing, 1));
        }
        if pitch != 0.0 {
            parts.push(trimmed(pitch, 0));
        }
        pairs.push(format!("map={}", parts.join("/")));
    }
    if let Some(v) = state.view.as_deref().filter(|v| !v.is_empty()) {
        if v != "map" && o.views.iter().any(|x| x == v) {
            pairs.push(format!("view={v}"));
        }
    }
    if let Some(m) = state.mode.as_deref().filter(|m| !m.is_empty()) {
        if m != o.default_mode && o.modes.iter().any(|x| x == m) {
            pairs.push(format!("proj={m}"));
        }
    }
    if let Some(layers) = &state.layers {
        let diff: Vec<String> = o
            .switches
            .iter()
            .filter_map(|(k, default)| {
                let on = layers.iter().find(|(id, _)| id == k).map(|(_, v)| *v)?;
                (on != *default).then(|| format!("{}{k}", if on { '+' } else { '-' }))
            })
            .collect();
        if !diff.is_empty() {
            pairs.push(format!("layers={}", diff.join(",")));
        }
    }
    if let Some(p) = state
        .place
        .as_ref()
        .filter(|p| p.lat.is_finite() && p.lng.is_finite())
    {
        let name = if p.name.is_empty() {
            String::new()
        } else {
            format!("/{}", encode_uri_component(&p.name))
        };
        pairs.push(format!(
            "place={},{}{name}",
            to_fixed(p.lat, 6),
            to_fixed(wrap_lng(p.lng), 6)
        ));
        if let Some(a) = state.ask.as_deref().filter(|a| !a.is_empty()) {
            if o.asks.iter().any(|x| x == a) {
                pairs.push(format!("ask={a}"));
            }
        }
    }
    if let Some(a) = state.area.and_then(safe_positive_integer) {
        pairs.push(format!("area=r{a}"));
    }
    for (k, v) in &state.extra {
        pairs.push(match v {
            Some(v) => format!("{k}={v}"),
            None => k.clone(),
        });
    }
    if pairs.is_empty() {
        String::new()
    } else {
        format!("#{}", pairs.join("&"))
    }
}

/// `Number.isSafeInteger(x) && x > 0`.
#[must_use]
pub fn safe_positive_integer(x: f64) -> Option<u64> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (x.fract() == 0.0 && x > 0.0 && x <= MAX_SAFE).then_some(x as u64)
}

/// Decimals for a camera's centre at `zoom`: MapLibre's rule, one more
/// latitude decimal past 75°.
#[must_use]
pub fn coord_decimals(zoom: f64, lat: f64) -> (usize, usize) {
    let d = ((zoom * std::f64::consts::LN_2 + (512.0_f64 / 360.0 / 0.5).ln())
        / std::f64::consts::LN_10)
        .ceil()
        .max(0.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let d = d as usize;
    (if lat.abs() > 75.0 { d + 1 } else { d }, d)
}

/// Longitude into (−180, 180]. JavaScript's `%` and Rust's are the same
/// operation on floats (the result takes the dividend's sign).
#[must_use]
pub fn wrap_lng(lng: f64) -> f64 {
    let w = (((lng + 180.0) % 360.0) + 360.0) % 360.0 - 180.0;
    if w == -180.0 {
        180.0
    } else {
        w
    }
}

fn bearing_of(b: f64) -> f64 {
    let mut x = js_round(wrap_lng(b) * 10.0) / 10.0;
    if x == -180.0 {
        x = 180.0;
    }
    if x == 0.0 {
        0.0
    } else {
        x
    }
}

/// JavaScript's `Math.round`: the nearest integer, a half toward +∞.
#[must_use]
pub fn js_round(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

/// JavaScript's `Number.prototype.toFixed(d)` for |x| < 1e21: the exact
/// binary value rounded to `d` decimals, an exact tie rounded up.
#[must_use]
pub fn to_fixed(x: f64, d: usize) -> String {
    let neg = x < 0.0;
    // Every finite f64 has a finite decimal expansion of at most 1074
    // fractional digits, and Rust prints it exactly at that precision.
    let exact = format!("{:.1074}", x.abs());
    let (int_part, frac) = exact.split_once('.').unwrap_or((exact.as_str(), ""));
    let mut digits: Vec<u8> = int_part
        .bytes()
        .chain(frac.bytes().take(d))
        .map(|b| b - b'0')
        .collect();
    let rest = frac.as_bytes().get(d..).unwrap_or(&[]);
    // Ties go up ("pick the larger n"), so a 5 or more next is a round-up.
    if rest.first().is_some_and(|&b| b >= b'5') {
        let mut i = digits.len();
        loop {
            if i == 0 {
                digits.insert(0, 1);
                break;
            }
            i -= 1;
            if digits[i] == 9 {
                digits[i] = 0;
            } else {
                digits[i] += 1;
                break;
            }
        }
    }
    let int_len = digits.len() - d;
    let mut s: String = digits[..int_len]
        .iter()
        .map(|&b| char::from(b'0' + b))
        .collect();
    if d > 0 {
        s.push('.');
        s.extend(digits[int_len..].iter().map(|&b| char::from(b'0' + b)));
    }
    if neg {
        s.insert(0, '-');
    }
    s
}

/// The page's `fixed`: `toFixed`, trailing zeros dropped, never "-0".
fn trimmed(x: f64, d: usize) -> String {
    let mut s = to_fixed(x, d);
    if s.contains('.') {
        let t = s.trim_end_matches('0').trim_end_matches('.').len();
        s.truncate(t);
    }
    if s == "-0" {
        "0".into()
    } else {
        s
    }
}

/// JavaScript's `encodeURIComponent`.
#[must_use]
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Switches as a JSON object whose key order is kept. `serde_json::Map`
/// sorts its keys unless `preserve_order` is on, and turning that on would
/// change every other crate's JSON in this workspace, so the object is
/// read entry by entry here instead.
pub(crate) mod ordered_switches {
    use serde::de::{MapAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &[(String, bool)], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(v.len()))?;
        for (k, b) in v {
            m.serialize_entry(k, b)?;
        }
        m.end()
    }

    struct InOrder;

    impl<'de> Visitor<'de> for InOrder {
        type Value = Vec<(String, bool)>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object of switch ids to booleans")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                if let Some(b) = v.as_bool() {
                    out.push((k, b));
                }
            }
            Ok(out)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(String, bool)>, D::Error> {
        d.deserialize_map(InOrder)
    }
}

mod ordered_switches_opt {
    use serde::{Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        v: &Option<Vec<(String, bool)>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::ordered_switches::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<(String, bool)>>, D::Error> {
        super::ordered_switches::deserialize(d).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_fixed_rounds_an_exact_tie_up_like_javascript() {
        assert_eq!(to_fixed(48.25, 1), "48.3");
        assert_eq!(to_fixed(-48.25, 1), "-48.3");
        assert_eq!(to_fixed(0.125, 2), "0.13");
        assert_eq!(
            to_fixed(1.005, 2),
            "1.00",
            "1.005 is below the tie in binary"
        );
        assert_eq!(to_fixed(9.999_999_9, 6), "10.000000");
        assert_eq!(to_fixed(-0.000_000_1, 6), "-0.000000");
        assert_eq!(to_fixed(50.7374, 6), "50.737400");
    }

    #[test]
    fn js_round_takes_a_half_toward_positive_infinity() {
        assert!((js_round(-122.5) - -122.0).abs() < f64::EPSILON);
        assert!((js_round(2.5) - 3.0).abs() < f64::EPSILON);
        assert!((js_round(-2.6) - -3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn encode_uri_component_matches_javascript() {
        assert_eq!(
            encode_uri_component("Café Luitpold, München"),
            "Caf%C3%A9%20Luitpold%2C%20M%C3%BCnchen"
        );
        assert_eq!(
            encode_uri_component("a-b_c.d!e~f*g'h(i)"),
            "a-b_c.d!e~f*g'h(i)"
        );
    }
}
