//! Session names: what a person writes after `@` to reach one session.
//!
//! A session's id is a UUID that changes on every bus re-registration, and
//! its label (`<host> · <repo>`) is free text that two sessions can share.
//! Neither is something a person can type into a chat. A name is: short,
//! lowercase, chosen through configuration or picked at random the way
//! Claude Code names its own sessions, and stable for the life of the
//! process (SPEC-166 phase A, design §3–§5).
//!
//! Everything here is pure: the server decides where a name comes from
//! and what to do with a mention; this module says what a name is, whom a
//! text mentions and how a message routes.

use rand::seq::SliceRandom;

/// The environment variable that names a session for one launch. It
/// outranks the plugin's setting (`--configured-session-name`), which
/// every session of that user shares, and is outranked by an explicit
/// `--session-name`.
pub const ENV: &str = "AIRDRESS_SESSION_NAME";

/// Longest name accepted.
pub const MAX_LEN: usize = 32;

/// Words that would read as addressing a group or a role, never a session.
pub const RESERVED: &[&str] = &["all", "everyone", "here", "me", "operator", "agent"];

/// Where a session's name came from, in rank order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Env,
    Plugin,
    Random,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::Plugin => "plugin",
            Source::Random => "random",
        }
    }
}

/// A resolved name: the name, its source, and why a higher-ranked value
/// was passed over, if one was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub name: String,
    pub source: Source,
    pub note: Option<String>,
}

const ADJECTIVES: &[&str] = &[
    "agile", "airy", "amber", "ample", "ancient", "apt", "arctic", "ardent", "aqua", "autumn",
    "azure", "balmy", "basil", "bold", "bouncy", "brave", "breezy", "bright", "brisk", "bronze",
    "bubbly", "busy", "calm", "candid", "carmine", "cheery", "chief", "civic", "clean", "clear",
    "clever", "cloudy", "coastal", "cobalt", "cool", "copper", "coral", "cosmic", "cozy", "crisp",
    "curious", "dapper", "daring", "dawn", "deft", "dewy", "dusky", "eager", "early", "earnest",
    "easy", "elder", "even", "fair", "fancy", "fern", "fleet", "fluent", "focal", "fond", "frank",
    "free", "fresh", "frosty", "gentle", "giant", "glad", "golden", "grand", "green", "hardy",
    "hazel", "hearty", "honest", "humble", "icy", "ideal", "indigo", "ivory", "jade", "jolly",
    "jovial", "keen", "kind", "lively", "lucid", "lucky", "lunar", "magic", "mellow", "merry",
    "mighty", "mint", "misty", "modest", "mossy", "neat", "nimble", "noble", "north", "oaken",
    "olive", "open", "orange", "patient", "peachy", "plucky", "polite", "proud", "quick", "quiet",
    "rapid", "ready", "rosy", "royal", "ruby", "rustic", "sage", "sandy", "sharp", "shiny",
    "silent", "silver", "snappy", "solar", "steady", "sunny", "swift", "tidy", "witty",
];

const NOUNS: &[&str] = &[
    "acorn", "alder", "anchor", "apple", "aspen", "atlas", "badger", "bamboo", "basin", "beacon",
    "beaver", "birch", "bison", "bluff", "breeze", "brook", "canyon", "cedar", "cliff", "clover",
    "comet", "condor", "coral", "cove", "crane", "creek", "cricket", "dahlia", "delta", "dingo",
    "dolphin", "dove", "dune", "eagle", "ember", "falcon", "fennel", "ferret", "finch", "fjord",
    "flint", "fox", "galaxy", "gecko", "geyser", "glacier", "grove", "gull", "harbor", "hare",
    "hawk", "hazel", "heron", "hill", "ibis", "island", "jaguar", "jasper", "juniper", "kayak",
    "kestrel", "kiwi", "koala", "lagoon", "lake", "lantern", "lark", "laurel", "lemur", "lily",
    "lynx", "magpie", "maple", "marlin", "marsh", "meadow", "mesa", "meteor", "moose", "moth",
    "nebula", "newt", "oak", "ocean", "orchid", "osprey", "otter", "owl", "panda", "pebble",
    "pelican", "pine", "plover", "pond", "poppy", "prairie", "puffin", "quail", "quartz", "raven",
    "reef", "ridge", "river", "robin", "rocket", "salmon", "sparrow", "spruce", "squid", "stork",
    "summit", "swan", "tern", "thistle", "tiger", "trout", "tulip", "tundra", "valley", "violet",
    "walrus", "willow", "wombat", "wren", "yak", "zebra", "badlands", "orbit", "tapir",
];

/// A fresh random name, `<adjective>-<noun>`.
pub fn random() -> String {
    let mut rng = rand::thread_rng();
    let a = ADJECTIVES.choose(&mut rng).copied().unwrap_or("quiet");
    let n = NOUNS.choose(&mut rng).copied().unwrap_or("otter");
    format!("{a}-{n}")
}

/// Check and normalise a name: trimmed, a leading `@` dropped,
/// lowercased, then held to the grammar (design §3.1). The error is a
/// short code a person can look up, with the detail beside it.
pub fn normalise(raw: &str) -> Result<String, String> {
    let n = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if n.is_empty() {
        return Err("empty".into());
    }
    if n.len() > MAX_LEN {
        return Err(format!("too_long: more than {MAX_LEN} characters"));
    }
    if let Some(c) = n
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(format!("bad_character: {c:?}"));
    }
    if n.starts_with('-') || n.ends_with('-') {
        return Err("edge_hyphen: a name cannot start or end with a hyphen".into());
    }
    if RESERVED.contains(&n.as_str()) {
        return Err(format!("reserved: {n:?} addresses a group, not a session"));
    }
    Ok(n)
}

/// Where this session's name comes from (design §4.1): `--session-name`,
/// then `AIRDRESS_SESSION_NAME`, then the plugin's setting, then a random
/// name. Empty is unset; an invalid value falls through to the next and
/// is named in the note, so a typo in a setting never stops the server.
pub fn resolve(flag: &str, env: Option<&str>, plugin: &str) -> Resolved {
    let mut notes = Vec::new();
    for (value, source, what) in [
        (Some(flag), Source::Flag, "--session-name"),
        (env, Source::Env, ENV),
        (Some(plugin), Source::Plugin, "the plugin's session_name"),
    ] {
        let Some(v) = value.filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        match normalise(v) {
            Ok(name) => {
                return Resolved {
                    name,
                    source,
                    note: (!notes.is_empty()).then(|| notes.join("; ")),
                }
            }
            Err(e) => notes.push(format!("{what} {v:?} was not used ({e})")),
        }
    }
    Resolved {
        name: random(),
        source: Source::Random,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    }
}

/// One mention: a name, and the airdress after a second `@`, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mention {
    pub name: String,
    pub remote: Option<String>,
}

/// The mentions in a text (design §5.1), in order, without repeats.
///
/// A mention starts at `@` at the start of the text or after a character
/// that is not `[A-Za-z0-9._@]`, so `alice@example.com` and `@@` mention
/// nobody. Text between backticks is skipped. Reserved words and things
/// that are not names are not mentions.
pub fn mentions(text: &str) -> Vec<Mention> {
    let chars: Vec<char> = text.chars().collect();
    let joins = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '@';
    let name_char = |c: char| c.is_ascii_alphanumeric() || c == '-';
    let mut out: Vec<Mention> = Vec::new();
    let mut in_code = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            in_code = !in_code;
            i += 1;
            continue;
        }
        if in_code || c != '@' || (i > 0 && joins(chars[i - 1])) {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < chars.len() && name_char(chars[end]) {
            end += 1;
        }
        let raw: String = chars[start..end].iter().collect();
        let raw = raw.trim_end_matches('-');
        let mut remote = None;
        let mut next = end.max(start);
        if end < chars.len() && chars[end] == '@' {
            let r_start = end + 1;
            let mut r_end = r_start;
            while r_end < chars.len()
                && (chars[r_end].is_ascii_alphanumeric()
                    || chars[r_end] == '-'
                    || chars[r_end] == '.')
            {
                r_end += 1;
            }
            let r: String = chars[r_start..r_end].iter().collect();
            let r = r.trim_end_matches('.').to_ascii_lowercase();
            if !r.is_empty() {
                remote = Some(r);
            }
            next = r_end;
        }
        if let Ok(name) = normalise(raw) {
            if !raw.is_empty() && !out.iter().any(|m| m.name == name && m.remote == remote) {
                out.push(Mention { name, remote });
            }
        }
        i = next.max(i + 1);
    }
    out
}

/// The names a text addresses on this airdress: mentions without a
/// remote part, or with this airdress's own fqdn. A mention of another
/// airdress does not count for routing yet (phase D gives it a meaning).
pub fn local_names(text: &str, fqdn: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in mentions(text) {
        let here = m
            .remote
            .as_deref()
            .is_none_or(|r| r.eq_ignore_ascii_case(fqdn));
        if here && !out.contains(&m.name) {
            out.push(m.name);
        }
    }
    out
}

/// How one message routes, seen from one session (design §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressed {
    /// It mentions nobody: every session sees it, as context (D-14).
    Nobody,
    /// It mentions this session.
    ThisSession,
    /// It mentions names no live session holds (a typo, a session that
    /// ended): every session sees it, so nothing is dropped silently.
    Unmatched,
    /// It mentions only names other live sessions hold: pushed here as
    /// context, not to be answered (D-14).
    Elsewhere,
}

impl Addressed {
    pub fn as_str(self) -> &'static str {
        match self {
            Addressed::Nobody => "none",
            Addressed::ThisSession => "this_session",
            Addressed::Unmatched => "unmatched",
            Addressed::Elsewhere => "elsewhere",
        }
    }
}

/// Route a message mentioning `mentioned` for the session `me`. `live` is
/// the names other sessions hold, when known; unknown means a mention of
/// someone else cannot be told from a typo, so it is pushed, noisy rather
/// than silent.
pub fn route(me: &str, mentioned: &[String], live: Option<&[String]>) -> Addressed {
    if mentioned.is_empty() {
        return Addressed::Nobody;
    }
    if mentioned.iter().any(|m| m == me) {
        return Addressed::ThisSession;
    }
    let held = |m: &String| live.into_iter().flatten().any(|n| n == m);
    if mentioned.iter().any(held) {
        Addressed::Elsewhere
    } else {
        Addressed::Unmatched
    }
}

/// Route a reply. A reply to a message the session `answered` wrote is
/// addressed to that session as if it mentioned it (SPEC-174 FR-32); a
/// mention in the reply addresses that session too, so a reply to bob
/// that names `@alice` is for both (D-11). A reply that mentions nobody
/// is context for every other session, never "for nobody": it is bob's
/// to answer even when bob has ended.
pub fn route_reply(
    me: &str,
    mentioned: &[String],
    answered: Option<&str>,
    live: Option<&[String]>,
) -> Addressed {
    let Some(answered) = answered else {
        return route(me, mentioned, live);
    };
    if answered == me {
        return Addressed::ThisSession;
    }
    match route(me, mentioned, live) {
        Addressed::Nobody => Addressed::Elsewhere,
        a => a,
    }
}

/// Whether `me` should answer an unmatched mention: only the session whose
/// name sorts first among `here` (the sessions on this device), so a typo
/// gets one "nobody here is called …", not one per session. With nobody
/// else known, every session answers.
pub fn answers_unmatched(me: &str, here: &[String]) -> bool {
    here.iter().all(|n| me <= n.as_str())
}

/// The live name `mention` most likely meant: the nearest within two
/// edits, where swapping two adjacent letters counts as one ("daev" is
/// one edit from "dave"). A tie goes to the name that sorts first, so every
/// session suggests the same one. Two edits only for names of five letters
/// or more, so "@al" does not suggest "bob".
pub fn closest(mention: &str, live: &[String]) -> Option<String> {
    let limit = |n: &str| {
        if n.len().min(mention.len()) >= 5 {
            2
        } else {
            1
        }
    };
    let mut best: Option<(usize, &String)> = None;
    for n in live {
        if n == mention {
            continue;
        }
        let d = edits(mention, n);
        if d <= limit(n) && best.is_none_or(|(bd, bn)| (d, n) < (bd, bn)) {
            best = Some((d, n));
        }
    }
    best.map(|(_, n)| n.clone())
}

/// Edit distance with adjacent transpositions (optimal string alignment).
fn edits(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// A bus session row's name: the operator's own `name` field where it
/// keeps names (SPEC-166 phase B), else the name a phase A label carries.
pub fn of_row(row: &serde_json::Value) -> Option<String> {
    row["name"]
        .as_str()
        .and_then(|n| normalise(n).ok())
        .or_else(|| row["label"].as_str().and_then(from_label))
}

/// The name a bus label carries, if it was written by a named session
/// (`@<name> · <host> · <repo>`).
pub fn from_label(label: &str) -> Option<String> {
    let rest = label.strip_prefix('@')?;
    let name = rest.split(" · ").next()?.trim();
    normalise(name).ok()
}

/// The first of `name`, `name-2`, `name-3`, … that `taken` does not hold,
/// shortening the base so the result stays within [`MAX_LEN`].
pub fn free(name: &str, taken: &[String]) -> String {
    if !taken.iter().any(|t| t == name) {
        return name.to_owned();
    }
    // At most one more candidate than names taken, so this ends.
    (2..=taken.len() + 2)
        .map(|n| {
            let suffix = format!("-{n}");
            let base = &name[..name.len().min(MAX_LEN - suffix.len())];
            format!("{}{suffix}", base.trim_end_matches('-'))
        })
        .find(|c| !taken.iter().any(|t| t == c))
        .unwrap_or_else(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    // cspell:ignore bobb daev alcie oter
    use super::*;

    fn names(text: &str) -> Vec<String> {
        mentions(text).into_iter().map(|m| m.name).collect()
    }

    #[test]
    fn the_word_lists_are_large_valid_and_distinct() {
        for list in [ADJECTIVES, NOUNS] {
            assert!(list.len() >= 128, "{}", list.len());
            let mut seen = std::collections::HashSet::new();
            for w in list {
                assert!(w.len() <= 10, "{w}");
                assert_eq!(normalise(w).as_deref(), Ok(*w), "{w}");
                assert!(seen.insert(w), "{w} repeats");
            }
        }
        for _ in 0..200 {
            let n = random();
            assert_eq!(normalise(&n).as_deref(), Ok(n.as_str()));
        }
    }

    #[test]
    fn a_name_is_lowercased_and_an_at_sign_dropped() {
        assert_eq!(normalise("@Bob").unwrap(), "bob");
        assert_eq!(normalise("  2nd-reviewer ").unwrap(), "2nd-reviewer");
        assert_eq!(normalise("a--b").unwrap(), "a--b");
    }

    #[test]
    fn a_name_outside_the_grammar_is_refused_with_a_code() {
        for (bad, code) in [
            ("bob smith", "bad_character"),
            ("bob_1", "bad_character"),
            ("-bob", "edge_hyphen"),
            ("bob-", "edge_hyphen"),
            ("here", "reserved"),
            ("@ALL", "reserved"),
        ] {
            let e = normalise(bad).unwrap_err();
            assert!(e.starts_with(code), "{bad:?}: {e}");
        }
        assert!(normalise(&"x".repeat(33))
            .unwrap_err()
            .starts_with("too_long"));
    }

    #[test]
    fn the_flag_beats_the_environment_which_beats_the_plugin() {
        let r = resolve("alice", Some("bob"), "carol");
        assert_eq!((r.name.as_str(), r.source), ("alice", Source::Flag));
        let r = resolve("", Some("bob"), "carol");
        assert_eq!((r.name.as_str(), r.source), ("bob", Source::Env));
        let r = resolve("", None, "carol");
        assert_eq!((r.name.as_str(), r.source), ("carol", Source::Plugin));
        assert_eq!(resolve("", Some(" "), "").source, Source::Random);
    }

    #[test]
    fn an_invalid_value_falls_through_and_is_named() {
        let r = resolve("", Some("bob smith"), "carol");
        assert_eq!((r.name.as_str(), r.source), ("carol", Source::Plugin));
        let note = r.note.unwrap();
        assert!(
            note.contains(ENV) && note.contains("bad_character"),
            "{note}"
        );
        let r = resolve("here", None, "");
        assert_eq!(r.source, Source::Random);
        assert!(r.note.unwrap().contains("reserved"));
    }

    #[test]
    fn mentions_are_found_where_a_person_writes_them() {
        assert_eq!(names("@bob what time is it?"), ["bob"]);
        assert_eq!(names("hey @Bob, and (@alice-2)."), ["bob", "alice-2"]);
        assert_eq!(names("@bob @bob"), ["bob"]);
        assert_eq!(names("@2nd-reviewer look"), ["2nd-reviewer"]);
    }

    #[test]
    fn addresses_code_and_group_words_are_not_mentions() {
        assert!(names("mail alice@example.com").is_empty());
        assert!(names("@@bob").is_empty());
        assert!(names("run `ssh @bob` here").is_empty());
        assert!(names("```\n@bob\n```").is_empty());
        assert!(names("@all please").is_empty());
        assert!(names("no one, @ 42, @-x").is_empty());
    }

    #[test]
    fn a_remote_part_is_kept_and_only_this_airdress_counts() {
        assert_eq!(
            mentions("@bob@b.example hi"),
            [Mention {
                name: "bob".into(),
                remote: Some("b.example".into())
            }]
        );
        assert!(local_names("@bob@b.example hi", "a.example").is_empty());
        assert_eq!(local_names("@bob@A.example. hi", "a.example"), ["bob"]);
        assert_eq!(local_names("@bob hi", "a.example"), ["bob"]);
    }

    #[test]
    fn a_row_is_named_by_the_operator_first_and_its_label_second() {
        use serde_json::json;
        assert_eq!(
            of_row(&json!({"name": "bob", "label": "box · repo"})).as_deref(),
            Some("bob")
        );
        assert_eq!(
            of_row(&json!({"name": null, "label": "@dave · box · repo"})).as_deref(),
            Some("dave")
        );
        assert_eq!(of_row(&json!({"label": "box · repo"})), None);
    }

    #[test]
    fn a_typo_suggests_the_name_it_was_one_or_two_edits_from() {
        let live: Vec<String> = ["bob", "dave", "alice", "quiet-otter"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(closest("daev", &live).as_deref(), Some("dave"));
        assert_eq!(closest("bobb", &live).as_deref(), Some("bob"));
        assert_eq!(closest("alcie", &live).as_deref(), Some("alice"));
        assert_eq!(closest("quiet-oter", &live).as_deref(), Some("quiet-otter"));
        // Too far, or too short to guess at.
        assert_eq!(closest("carol", &live), None);
        assert_eq!(closest("al", &live), None);
        // A tie is the same answer everywhere.
        let twins: Vec<String> = vec!["bob".into(), "rob".into()];
        assert_eq!(closest("cob", &twins).as_deref(), Some("bob"));
        assert_eq!(edits("daev", "dave"), 1);
    }

    #[test]
    fn a_reply_is_for_the_session_it_answers_and_for_whom_it_mentions() {
        let live = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let at = |me: &str, text: &str, answered: Option<&str>| {
            route_reply(me, &names(text), answered, Some(&live))
        };
        // A reply to bob's message, naming nobody: bob's alone.
        assert_eq!(at("bob", "yes", Some("bob")), Addressed::ThisSession);
        assert_eq!(at("alice", "yes", Some("bob")), Addressed::Elsewhere);
        assert_eq!(at("carol", "yes", Some("bob")), Addressed::Elsewhere);
        // And @alice besides: both, never carol.
        assert_eq!(at("bob", "@alice yes", Some("bob")), Addressed::ThisSession);
        assert_eq!(
            at("alice", "@alice yes", Some("bob")),
            Addressed::ThisSession
        );
        assert_eq!(at("carol", "@alice yes", Some("bob")), Addressed::Elsewhere);
        // Not a reply to a session's message: as any message.
        assert_eq!(at("carol", "yes", None), Addressed::Nobody);
    }

    #[test]
    fn a_message_routes_to_everyone_this_session_elsewhere_or_unmatched() {
        let live = vec!["alice".to_owned(), "bob".to_owned()];
        let r = |text: &str, live: Option<&[String]>| route("bob", &names(text), live);
        assert_eq!(r("hello all", Some(&live)), Addressed::Nobody);
        assert_eq!(r("@bob hi", Some(&live)), Addressed::ThisSession);
        assert_eq!(r("@alice @bob hi", Some(&live)), Addressed::ThisSession);
        assert_eq!(r("@alice hi", Some(&live)), Addressed::Elsewhere);
        assert_eq!(r("@bobb hi", Some(&live)), Addressed::Unmatched);
        // Unknown live names: a mention of someone else is pushed.
        assert_eq!(r("@alice hi", None), Addressed::Unmatched);
    }

    #[test]
    fn one_session_answers_a_typo() {
        let here = vec![
            "alice".to_owned(),
            "bob".to_owned(),
            "quiet-otter".to_owned(),
        ];
        assert!(answers_unmatched("alice", &here));
        assert!(!answers_unmatched("bob", &here));
        assert!(answers_unmatched("bob", &["bob".to_owned()]));
    }

    #[test]
    fn a_label_gives_back_its_name() {
        assert_eq!(
            from_label("@bob · jefe-framework · bob").as_deref(),
            Some("bob")
        );
        assert_eq!(from_label("jefe-framework · bob"), None);
    }

    #[test]
    fn a_taken_name_gets_the_first_free_suffix_within_the_limit() {
        let taken = vec!["bob".to_owned(), "bob-2".to_owned()];
        assert_eq!(free("bob", &taken), "bob-3");
        assert_eq!(free("alice", &taken), "alice");
        let long = "x".repeat(32);
        let got = free(&long, std::slice::from_ref(&long));
        assert_eq!(got.len(), 32);
        assert!(got.ends_with("-2"));
    }
}
