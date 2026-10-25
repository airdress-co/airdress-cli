// cspell:ignore Barnim Breisgau Kneipen Köln Luitpold München Nordrhein abend beste besten eine einen empfehlen empfiehl finde gehen gibt gute guten gutes günstig heute hier housenumber kann kneipe kneipen nahe nähe outlinable soll sollte welche welcher welches zeig zeige wir zum zur dem den das der die ein für mir gut bei von ich man wo was es um im zu
//! Map search answers, shaped for an agent: each result with its own link,
//! and the rule that keeps the tools from recommending places (maps
//! SPEC-171 D-6, FR-13, design §9.5).
//!
//! A category question ("where to eat in Bonn") gets no list of places:
//! the map has no reviews, ratings or opening hours, so a list would read
//! as a recommendation it cannot back. A query that names one place
//! ("Café Luitpold München") is a search like any other.

use serde_json::{json, Map, Value};

use crate::address::Options;
use crate::link::link;

/// The search layers that are areas the page can outline.
pub const AREA_LAYERS: &[&str] = &["locality", "region", "country"];

/// Words that only frame a question, dropped when looking for the town a
/// category question names. English and German.
const FRAME_WORDS: &[&str] = &[
    "where",
    "what",
    "which",
    "should",
    "could",
    "can",
    "i",
    "we",
    "to",
    "a",
    "an",
    "the",
    "in",
    "at",
    "near",
    "around",
    "nearby",
    "close",
    "by",
    "of",
    "for",
    "me",
    "my",
    "some",
    "any",
    "good",
    "best",
    "nice",
    "cheap",
    "find",
    "show",
    "recommend",
    "go",
    "is",
    "are",
    "there",
    "wo",
    "was",
    "welche",
    "welcher",
    "welches",
    "soll",
    "sollte",
    "kann",
    "ich",
    "wir",
    "man",
    "zu",
    "zum",
    "zur",
    "ein",
    "eine",
    "einen",
    "der",
    "die",
    "das",
    "den",
    "dem",
    "im",
    "in",
    "bei",
    "nahe",
    "nähe",
    "um",
    "von",
    "für",
    "mir",
    "gut",
    "gute",
    "guten",
    "gutes",
    "beste",
    "besten",
    "günstig",
    "finde",
    "zeig",
    "zeige",
    "empfiehl",
    "empfehlen",
    "gehen",
    "gibt",
    "es",
    "hier",
    "heute",
    "abend",
    "tonight",
    "today",
];

/// The words of a query, lower case, punctuation off.
fn words(q: &str) -> Vec<String> {
    q.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '\''))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// A word of the query is a category word: equal to one, or one with a
/// plural ending (`restaurants`, `cafés`, `hotels`, `kneipen`).
fn is_category_word(w: &str, categories: &[&str]) -> bool {
    categories.iter().any(|c| {
        let c = c.to_lowercase();
        w == c
            || w.strip_suffix('s') == Some(c.as_str())
            || w.strip_suffix("en") == Some(c.as_str())
            || w.strip_suffix('n') == Some(c.as_str())
    })
}

/// Whether the query asks for a kind of place rather than a place.
#[must_use]
pub fn is_category_query(q: &str, categories: &[&str]) -> bool {
    words(q).iter().any(|w| is_category_word(w, categories))
}

/// What is left of a category question once its category and framing
/// words are gone: the town or area it names, if any ("Bonn").
#[must_use]
pub fn remainder(q: &str, categories: &[&str]) -> String {
    let ws = words(q);
    q.split_whitespace()
        .zip(ws.iter().chain(std::iter::repeat(&String::new())))
        .filter_map(|(raw, _)| {
            let w = words(raw).join(" ");
            (!w.is_empty()
                && !is_category_word(&w, categories)
                && !FRAME_WORDS.contains(&w.as_str()))
            .then(|| raw.trim_matches(|c: char| !c.is_alphanumeric()).to_owned())
        })
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a category-shaped query in fact names one place: a venue among
/// the results whose name carries a word of the query that is neither a
/// category nor framing, nor the town the results are in.
#[must_use]
pub fn names_a_place(q: &str, results: &[Value], categories: &[&str]) -> bool {
    let distinctive: Vec<String> = words(q)
        .into_iter()
        .filter(|w| !is_category_word(w, categories) && !FRAME_WORDS.contains(&w.as_str()))
        .collect();
    results.iter().any(|r| {
        if r.get("layer").and_then(Value::as_str) != Some("venue") {
            return false;
        }
        let name = words(r.get("name").and_then(Value::as_str).unwrap_or(""));
        let addr = r.get("address");
        let around: Vec<String> = ["city", "district", "state", "country"]
            .iter()
            .filter_map(|k| addr.and_then(|a| a.get(*k)).and_then(Value::as_str))
            .flat_map(words)
            .collect();
        distinctive
            .iter()
            .any(|w| name.contains(w) && !around.contains(w))
    })
}

/// The zoom a result's link opens at, by its kind.
#[must_use]
pub fn zoom_for(layer: &str) -> f64 {
    match layer {
        "country" => 4.0,
        "region" => 7.0,
        "locality" => 11.0,
        "street" => 15.0,
        _ => 16.0,
    }
}

/// One address line from the front's address object.
fn address_line(a: Option<&Value>) -> String {
    let Some(a) = a.and_then(Value::as_object) else {
        return String::new();
    };
    let get = |k: &str| {
        a.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let street = [get("street"), get("housenumber")]
        .iter()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let town = [get("postcode"), get("city")]
        .iter()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    [street, town, get("state"), get("country")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The relation id of an outlinable area.
#[must_use]
pub fn relation_of(r: &Value) -> Option<u64> {
    let layer = r.get("layer").and_then(Value::as_str)?;
    let osm = r.get("osm")?;
    (AREA_LAYERS.contains(&layer) && osm.get("type").and_then(Value::as_str) == Some("relation"))
        .then(|| osm.get("id").and_then(Value::as_u64))
        .flatten()
}

/// One search result as a tool answers it: name, address line, point,
/// kind, credit, and its own link (the place with a camera; an
/// outlinable area also outlined).
#[must_use]
pub fn shape_result(r: &Value, o: &Options) -> Option<Value> {
    let point = r.get("point")?.as_array()?;
    let (lng, lat) = (point.first()?.as_f64()?, point.get(1)?.as_f64()?);
    let layer = r.get("layer").and_then(Value::as_str).unwrap_or("venue");
    let name = r
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let relation = relation_of(r);
    let mut args = json!({
        "camera": {"lat": lat, "lng": lng, "zoom": zoom_for(layer)},
        "place": {"lat": lat, "lng": lng, "name": name},
    });
    if let Some(id) = relation {
        args["area"] = json!(id);
    }
    let l = link(&args, o);
    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    out.insert("address".into(), json!(address_line(r.get("address"))));
    out.insert("point".into(), json!({"lat": lat, "lng": lng}));
    out.insert("kind".into(), json!(layer));
    out.insert(
        "credit".into(),
        r.get("credit").cloned().unwrap_or(Value::Null),
    );
    if let Some(id) = relation {
        out.insert("relation".into(), json!(id));
    }
    out.insert("map_link".into(), json!(l.url));
    Some(Value::Object(out))
}

/// An area as `map_area` answers it: the outline link has no camera, so
/// the page fits the area itself.
#[must_use]
pub fn shape_area(r: &Value, o: &Options) -> Option<Value> {
    let id = relation_of(r)?;
    let point = r.get("point")?.as_array()?;
    let (lng, lat) = (point.first()?.as_f64()?, point.get(1)?.as_f64()?);
    let l = link(&json!({"area": id}), o);
    Some(json!({
        "relation": id,
        "name": r.get("name").and_then(Value::as_str).unwrap_or(""),
        "kind": r.get("layer"),
        "point": {"lat": lat, "lng": lng},
        "credit": r.get("credit").cloned().unwrap_or(Value::Null),
        "map_link": l.url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::snapshot;

    const CATS: &[&str] = &[
        "restaurant",
        "eat",
        "food",
        "café",
        "cafe",
        "bar",
        "hotel",
        "essen",
        "kneipe",
    ];

    #[test]
    fn a_category_question_is_recognised_in_both_languages() {
        assert!(is_category_query("where should I eat in Bonn", CATS));
        assert!(is_category_query("restaurants near Bonn", CATS));
        assert!(is_category_query("Kneipen in Köln", CATS));
        assert!(is_category_query("gutes Essen in Freiburg", CATS));
        assert!(!is_category_query("Freiburg im Breisgau", CATS));
        assert!(
            !is_category_query("Barnim", CATS),
            "a word is not its prefix"
        );
    }

    #[test]
    fn the_remainder_is_the_town() {
        assert_eq!(remainder("where should I eat in Bonn?", CATS), "Bonn");
        assert_eq!(
            remainder("restaurants near Bad Godesberg", CATS),
            "Bad Godesberg"
        );
        assert_eq!(remainder("best food", CATS), "");
    }

    #[test]
    fn a_named_cafe_is_a_place_not_a_category() {
        let results = vec![
            json!({"name": "Café Luitpold", "layer": "venue", "address": {"city": "München"}}),
        ];
        assert!(names_a_place("Café Luitpold München", &results, CATS));
        let generic =
            vec![json!({"name": "Café Bonn", "layer": "venue", "address": {"city": "Bonn"}})];
        assert!(!names_a_place("cafés in Bonn", &generic, CATS));
    }

    #[test]
    fn a_result_carries_its_link_and_an_area_its_outline() {
        let r = json!({"name": "Bonn", "address": {"state": "Nordrhein-Westfalen", "country": "Deutschland"},
            "point": [7.0982, 50.7374], "layer": "locality", "credit": "© OpenStreetMap contributors",
            "osm": {"type": "relation", "id": 62508}});
        let s = shape_result(&r, &snapshot()).unwrap();
        assert_eq!(s["relation"], 62508);
        assert_eq!(
            s["map_link"],
            "https://maps.airdress.co/#map=11/50.7374/7.0982&place=50.737400,7.098200/Bonn&area=r62508"
        );
        assert_eq!(s["address"], "Nordrhein-Westfalen, Deutschland");
        let a = shape_area(&r, &snapshot()).unwrap();
        assert_eq!(a["map_link"], "https://maps.airdress.co/#area=r62508");
        let way = json!({"name": "X", "point": [1, 2], "layer": "locality", "osm": {"type": "way", "id": 1}});
        assert!(shape_area(&way, &snapshot()).is_none());
    }
}
