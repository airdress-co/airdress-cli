// cspell:ignore streetview
//! `map_link`: a tool's arguments to a link that opens the map in that
//! state, with a note for every argument that could not be honoured.
//!
//! The switch defaults come from the airdress's live layer catalogue when
//! the caller has a fresh one, and otherwise from [`snapshot`], the page's
//! defaults when this crate was built. A switch in neither is dropped with
//! a note, never guessed at.

use serde_json::{json, Value};

use crate::address::{
    format_address, safe_positive_integer, Camera, Options, Place, State, MAX_FRAGMENT,
};

/// Where the map lives.
pub const MAP_URL: &str = "https://maps.airdress.co/";

/// The answers the place card can open expanded.
pub const ASKS: &[&str] = &["today", "sky"];

/// The map's layer catalogue when this crate was built: the body of the
/// front's `GET /layers/catalogue.json`, copied from the maps repository
/// (`services/maps-front/src/layers_catalogue.json`). What `map_layers`
/// answers when the airdress cannot, and where switch defaults come from
/// without a fresh answer.
pub const CATALOGUE_SNAPSHOT: &str = include_str!("catalogue-snapshot.json");

/// The page's address options at build time, from [`CATALOGUE_SNAPSHOT`].
/// A test holds them to the pinned vector file's options, which are the
/// page's.
///
/// # Panics
///
/// Never on a release build: the snapshot is parsed by a test.
#[must_use]
pub fn snapshot() -> Options {
    options_from_catalogue(CATALOGUE_SNAPSHOT)
        .expect("the compiled catalogue snapshot has the catalogue's shape")
}

/// The parts of a layer catalogue a link needs, read in order.
#[derive(serde::Deserialize)]
struct CatalogueOptions {
    #[serde(with = "crate::address::ordered_switches")]
    switches: Vec<(String, bool)>,
    views: Vec<Named>,
    modes: Modes,
}

#[derive(serde::Deserialize)]
struct Named {
    id: String,
}

#[derive(serde::Deserialize)]
struct Modes {
    default: String,
    all: Vec<Named>,
}

/// The options from a layer catalogue answer (`GET /v1/maps/layers`, as
/// text, so the switches keep their order): its `switches`, views and
/// modes. `None` when it does not have the shape, so the caller keeps the
/// snapshot.
#[must_use]
pub fn options_from_catalogue(text: &str) -> Option<Options> {
    let c: CatalogueOptions = serde_json::from_str(text).ok()?;
    if c.switches.is_empty() || c.views.is_empty() || c.modes.all.is_empty() {
        return None;
    }
    Some(Options {
        switches: c.switches,
        views: c.views.into_iter().map(|v| v.id).collect(),
        modes: c.modes.all.into_iter().map(|v| v.id).collect(),
        default_mode: c.modes.default,
        asks: ASKS.iter().map(|s| (*s).to_owned()).collect(),
    })
}

/// A link, or why there is none.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    /// `https://maps.airdress.co/#…`; `None` when the fragment would be
    /// too long for the page to read.
    pub url: Option<String>,
    pub fragment: String,
    /// One sentence per argument dropped, and why.
    pub notes: Vec<String>,
}

impl Link {
    /// As a tool answers it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"url": self.url, "fragment": self.fragment, "notes": self.notes})
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|x| x.is_finite())
}

/// `map_link`'s arguments to a link. Pure: no call, no clock.
#[must_use]
pub fn link(args: &Value, o: &Options) -> Link {
    let mut notes = Vec::new();
    let mut state = State::default();

    if let Some(c) = args.get("camera").filter(|c| !c.is_null()) {
        let (lat, lng, zoom) = (num(c.get("lat")), num(c.get("lng")), num(c.get("zoom")));
        match (lat, lng, zoom) {
            (Some(lat), Some(lng), Some(zoom))
                if lat.abs() <= 90.0 && (0.0..=22.0).contains(&zoom) =>
            {
                let pitch = num(c.get("pitch"));
                if pitch.is_some_and(|p| p > 60.0) {
                    notes.push(
                        "pitch is at most 60 on this map; the page will tilt it no further.".into(),
                    );
                }
                state.camera = Some(Camera {
                    lat,
                    lng,
                    zoom,
                    bearing: num(c.get("bearing")),
                    pitch: pitch.map(|p| p.min(60.0)),
                });
            }
            _ => notes.push(
                "camera dropped: it needs lat (-90..90), lng and zoom (0..22) as numbers.".into(),
            ),
        }
    }
    if let Some(v) = args.get("view").and_then(Value::as_str) {
        if o.views.iter().any(|x| x == v) {
            state.view = Some(v.to_owned());
        } else {
            notes.push(format!(
                "view {v:?} dropped: the views are {}.",
                o.views.join(", ")
            ));
        }
    }
    if let Some(m) = args.get("mode").and_then(Value::as_str) {
        if o.modes.iter().any(|x| x == m) {
            state.mode = Some(m.to_owned());
        } else {
            notes.push(format!(
                "mode {m:?} dropped: the modes are {}.",
                o.modes.join(", ")
            ));
        }
    }
    if let Some(l) = args.get("layers").and_then(Value::as_object) {
        let mut on = Vec::new();
        for (k, v) in l {
            match v.as_bool() {
                Some(b) if o.switches.iter().any(|(id, _)| id == k) => on.push((k.clone(), b)),
                Some(_) => notes.push(format!("layer {k:?} dropped: this map has no such switch.")),
                None => notes.push(format!("layer {k:?} dropped: say true or false.")),
            }
        }
        if !on.is_empty() {
            state.layers = Some(on);
        }
    }
    if let Some(p) = args.get("place").filter(|p| !p.is_null()) {
        match (num(p.get("lat")), num(p.get("lng"))) {
            (Some(lat), Some(lng)) if lat.abs() <= 85.0511 => {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let name: String = name.chars().filter(|c| !c.is_control()).take(200).collect();
                state.place = Some(Place { lat, lng, name });
            }
            _ => notes
                .push("place dropped: it needs lat (-85.0511..85.0511) and lng as numbers.".into()),
        }
    }
    if let Some(a) = args.get("ask").and_then(Value::as_str) {
        if !o.asks.iter().any(|x| x == a) {
            notes.push(format!(
                "ask {a:?} dropped: the answers are {}.",
                o.asks.join(", ")
            ));
        } else if state.place.is_none() {
            notes.push(format!(
                "ask {a:?} dropped: it opens the card of a place, and no place was given."
            ));
        } else {
            state.ask = Some(a.to_owned());
        }
    }
    if let Some(a) = args.get("area").filter(|a| !a.is_null()) {
        let id = match a {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.strip_prefix('r').unwrap_or(s).parse::<f64>().ok(),
            _ => None,
        };
        #[allow(clippy::cast_precision_loss)]
        match id.and_then(safe_positive_integer) {
            Some(id) => state.area = Some(id as f64),
            None => notes.push(
                "area dropped: it is an OpenStreetMap relation id, a positive integer.".into(),
            ),
        }
    }

    let fragment = format_address(&state, o);
    let url = if fragment.len() > MAX_FRAGMENT {
        notes.push(format!(
            "no link: it would be {} characters and the map reads at most {MAX_FRAGMENT}; shorten the place name.",
            fragment.len()
        ));
        None
    } else {
        Some(format!("{MAP_URL}{fragment}"))
    };
    Link {
        url,
        fragment,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_input_at_once() {
        let l = link(
            &json!({
                "camera": {"lat": 47.999, "lng": 7.8421, "zoom": 10.25},
                "view": "satellite", "mode": "flat",
                "layers": {"counties": false, "satellites": true},
                "place": {"lat": 47.995, "lng": 7.85, "name": "Freiburg"},
                "ask": "today", "area": "r62768",
            }),
            &snapshot(),
        );
        assert!(l.notes.is_empty(), "{:?}", l.notes);
        assert_eq!(
            l.url.as_deref(),
            Some(
                "https://maps.airdress.co/#map=10.25/47.999/7.8421&view=satellite&proj=flat\
                 &layers=-counties,+satellites&place=47.995000,7.850000/Freiburg&ask=today&area=r62768"
            )
        );
    }

    #[test]
    fn every_dropped_input_says_why() {
        let l = link(
            &json!({
                "camera": {"lat": 95, "lng": 0, "zoom": 3},
                "view": "streetview", "mode": "orthographic",
                "layers": {"today-anomaly": true, "counties": "off"},
                "ask": "today", "area": 0,
            }),
            &snapshot(),
        );
        assert_eq!(l.url.as_deref(), Some("https://maps.airdress.co/"));
        let all = l.notes.join("\n");
        for word in [
            "camera",
            "streetview",
            "orthographic",
            "today-anomaly",
            "counties",
            "no place",
            "area",
        ] {
            assert!(all.contains(word), "no note for {word}: {all}");
        }
    }

    #[test]
    fn an_ask_needs_a_place_and_one_of_the_answers() {
        let l = link(
            &json!({"place": {"lat": 50.7374, "lng": 7.0982}, "ask": "weather"}),
            &snapshot(),
        );
        assert_eq!(l.fragment, "#place=50.737400,7.098200");
        assert_eq!(l.notes.len(), 1);
    }

    #[test]
    fn a_link_the_page_could_not_read_is_refused() {
        // 200 four-byte characters: 2,400 characters once encoded.
        let name = "\u{1F5FA}".repeat(200);
        let l = link(
            &json!({"place": {"lat": 1, "lng": 2, "name": name}}),
            &snapshot(),
        );
        assert!(l.url.is_none());
        assert!(l.fragment.len() > MAX_FRAGMENT);
        assert!(l.notes[0].starts_with("no link"), "{:?}", l.notes);
    }

    #[test]
    fn the_catalogue_answer_replaces_the_snapshot() {
        let c = json!({
            "schema": 1,
            "views": [{"id": "map"}, {"id": "satellite"}],
            "modes": {"default": "globe", "all": [{"id": "globe"}, {"id": "flat"}]},
            "switches": {"regions": true, "today-anomaly": false},
        });
        let o = options_from_catalogue(&c.to_string()).unwrap();
        let l = link(&json!({"layers": {"today-anomaly": true}}), &o);
        assert_eq!(l.fragment, "#layers=+today-anomaly");
        assert!(options_from_catalogue(r#"{"schema": 1}"#).is_none());
    }
}
