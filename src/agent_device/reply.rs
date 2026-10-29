//! Replies on the device host: the reference every message carries, the
//! `reply_to` object a reply carries, and how a received reply is
//! resolved against this machine's store (SPEC-174 design §2, §7.2).
//!
//! Everything here is inside the encrypted payload, as top-level keys of
//! its object form, which older decoders ignore:
//!
//! ```text
//! {"blocks": [...], "ref": "<22 chars>", "reply_to": {"ref"?, "from", "by_session"?, "kind", "snippet"}}
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use unicode_segmentation::UnicodeSegmentation as _;

use airdress_mls_client::{LanePayload, ReplyTo};

use super::chat_store::{ChatStore, Message, Reply};
use crate::quote::is_bidi_control;
pub use crate::quote::{snippet, SNIPPET_MAX};

/// The kinds a quote can name.
pub const KINDS: &[&str] = &["text", "code", "image", "audio", "place", "live", "other"];

/// A fresh reference, as the shared client mints it.
pub use airdress_mls_client::mint_message_ref as mint_ref;

/// Whether `s` is a reference as minted: 22 base64url characters that
/// decode to 16 bytes. Anything else is ignored.
pub fn is_ref(s: &str) -> bool {
    s.len() == 22 && URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == 16)
}

/// What a block array holds, for a quote: the first block that is not
/// padding decides.
pub fn kind_of(blocks: &Value) -> &'static str {
    let first = blocks
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|b| b["type"].as_str().filter(|t| *t != "pad"));
    match first {
        Some("text" | "rich_text") | None => "text",
        Some("code") => "code",
        Some("image") => "image",
        Some("audio_burst" | "audio") => "audio",
        Some("place") => "place",
        Some("live_share") => "live",
        Some(_) => "other",
    }
}

/// The text and code of a block array, joined as the app's copy text is:
/// what a quote of it is cut from.
pub fn quotable_text(blocks: &Value) -> String {
    blocks
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|b| match b["type"].as_str() {
            Some("text") => b["text"].as_str(),
            Some("code") => b["code"].as_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// A received `reply_to`, checked. A malformed one is `None` and the
/// message is shown unquoted (design §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireReply {
    pub msg_ref: Option<String>,
    pub from: String,
    pub by_session: Option<String>,
    pub kind: String,
    pub snippet: String,
}

/// Read a `reply_to` object as it arrived.
pub fn parse(v: &Value) -> Option<WireReply> {
    let o = v.as_object()?;
    let opt_str = |k: &str| match o.get(k) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => None,
    };
    let from = o.get("from")?.as_str()?.to_owned();
    if from.is_empty() {
        return None;
    }
    let snippet = match o.get("snippet") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return None,
    };
    if snippet.graphemes(true).count() > SNIPPET_MAX {
        return None;
    }
    let kind = match opt_str("kind")? {
        Some(k) if KINDS.contains(&k.as_str()) => k,
        Some(_) => "other".to_owned(),
        None => "text".to_owned(),
    };
    Some(WireReply {
        // A malformed reference is no reference: a quote-only reply.
        msg_ref: opt_str("ref")?.filter(|r| is_ref(r)),
        from,
        by_session: opt_str("by_session")?.and_then(|n| crate::mcp::names::normalise(&n).ok()),
        kind,
        snippet: snippet.chars().filter(|c| !is_bidi_control(*c)).collect(),
    })
}

/// Resolve a received reply in `conversation` against the store: the
/// original's id, words and session when it is held, else the snippet.
pub fn resolve(store: &ChatStore, conversation: &str, wire: &WireReply) -> Reply {
    let original = wire
        .msg_ref
        .as_deref()
        .and_then(|r| store.find_ref(conversation, &wire.from, r));
    match original {
        Some(m) => Reply {
            message_id: Some(m.message_id.clone()),
            from: wire.from.clone(),
            // The host's own record of who wrote it, never the claim.
            by_session: m.by_session.clone(),
            kind: m.kind.clone().unwrap_or_else(|| "text".into()),
            text: m.quotable.clone().unwrap_or_else(|| m.text.clone()),
            resolved: true,
        },
        None => Reply {
            message_id: None,
            from: wire.from.clone(),
            by_session: wire.by_session.clone(),
            kind: wire.kind.clone(),
            text: wire.snippet.clone(),
            resolved: false,
        },
    }
}

/// The `reply_to` object this host sends to answer `original`: its
/// reference (none for a quote-only reply), its sender, the session of
/// this machine that wrote it, its kind and its snippet. Deterministic, so
/// the host can rebuild it and compare (`reply_mismatch`).
pub fn wire_of(original: &Message) -> Value {
    let source = original.quotable.as_deref().unwrap_or(&original.text);
    let typed = ReplyTo {
        r#ref: original.msg_ref.clone().filter(|r| is_ref(r)),
        from: original.from.clone(),
        by_session: original.by_session.clone(),
        kind: original.kind.clone().unwrap_or_else(|| "text".into()),
        snippet: snippet(source),
    };
    // Through the shared type, so what is signed is what it sends.
    serde_json::to_value(&typed).unwrap_or(Value::Null)
}

/// The plaintext this host sends: the shared client's object form, with
/// the blocks, this message's reference and, for a reply, `reply_to`. The
/// `reply_to` sent is the one given, byte for byte in meaning, or nothing
/// is sent: a session signed exactly that object.
///
/// # Errors
/// `reply_to` is not one the shared type carries unchanged.
pub fn payload(blocks: &Value, msg_ref: &str, reply_to: Option<&Value>) -> anyhow::Result<Vec<u8>> {
    let typed = match reply_to {
        Some(v) => {
            let t = ReplyTo::from_value(v)
                .filter(|t| serde_json::to_value(t).ok().as_ref() == Some(v))
                .ok_or_else(|| anyhow::anyhow!("a reply_to the payload cannot carry unchanged"))?;
            Some(t)
        }
        None => None,
    };
    LanePayload::encode_message(blocks, msg_ref, typed.as_ref()).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn stored(id: &str, from: &str, msg_ref: Option<&str>, text: &str) -> Message {
        Message {
            seq: 0,
            message_id: id.into(),
            conversation_id: "c1".into(),
            from: from.into(),
            lane: "assigned".into(),
            from_self: false,
            text: text.into(),
            at: Utc::now(),
            for_session: None,
            msg_ref: msg_ref.map(str::to_owned),
            reply_to: None,
            by_session: None,
            kind: None,
            quotable: None,
        }
    }

    #[test]
    fn a_reference_is_sixteen_random_bytes_in_base64url() {
        let a = mint_ref();
        assert_eq!(a.len(), 22);
        assert!(is_ref(&a));
        assert_ne!(a, mint_ref());
        assert!(!is_ref("short"));
        assert!(!is_ref("!!!!!!!!!!!!!!!!!!!!!!"));
    }

    #[test]
    fn a_snippet_collapses_whitespace_strips_bidi_and_cuts_at_a_cluster() {
        assert_eq!(snippet("  a\n\n b\t c "), "a b c");
        assert_eq!(snippet("x\u{202E}y\u{2066}z"), "xyz");
        let long = "👋🏽".repeat(200);
        let s = snippet(&long);
        assert_eq!(s.graphemes(true).count(), SNIPPET_MAX);
        assert!(s.ends_with('…'));
        assert!(s.trim_end_matches('…').graphemes(true).all(|g| g == "👋🏽"));
        let exact = "e\u{301}".repeat(SNIPPET_MAX);
        assert_eq!(snippet(&exact), exact, "140 clusters fit");
    }

    #[test]
    fn kinds_and_quotable_text_follow_the_blocks() {
        let b = json!([{"type": "text", "text": "a"}, {"type": "code", "code": "ls"}]);
        assert_eq!(kind_of(&b), "text");
        assert_eq!(quotable_text(&b), "a\n\nls");
        assert_eq!(
            kind_of(&json!([{"type": "pad"}, {"type": "image"}])),
            "image"
        );
        assert_eq!(kind_of(&json!([{"type": "audio_burst"}])), "audio");
        assert_eq!(kind_of(&json!([{"type": "live_share"}])), "live");
        assert_eq!(kind_of(&json!([{"type": "place"}])), "place");
        assert_eq!(kind_of(&json!([{"type": "tool_use"}])), "other");
    }

    #[test]
    fn a_malformed_reply_to_is_ignored_and_a_malformed_ref_makes_it_quote_only() {
        assert!(parse(&json!("x")).is_none());
        assert!(
            parse(&json!({"kind": "text", "snippet": "a"})).is_none(),
            "no from"
        );
        assert!(parse(&json!({"from": "a.example", "snippet": 3})).is_none());
        let over = "x".repeat(SNIPPET_MAX + 1);
        assert!(parse(&json!({"from": "a.example", "snippet": over})).is_none());
        let w =
            parse(&json!({"from": "a.example", "ref": "nope", "kind": "weird", "snippet": "hi"}))
                .unwrap();
        assert_eq!(w.msg_ref, None);
        assert_eq!(w.kind, "other");
        let w = parse(
            &json!({"from": "a.example", "ref": mint_ref(), "kind": "text",
                              "snippet": "hi", "by_session": "Bob", "extra": 1}),
        )
        .unwrap();
        assert!(w.msg_ref.is_some());
        assert_eq!(w.by_session.as_deref(), Some("bob"));
    }

    #[test]
    fn a_reply_resolves_only_against_its_sender_and_the_oldest_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ChatStore::open(dir.path(), [3; 32]).unwrap();
        let now = Utc::now();
        let r = mint_ref();
        s.append(stored("e-a", "a.example", Some(&r), "from a"), now)
            .unwrap();
        s.append(stored("e-b", "b.example", Some(&r), "from b"), now)
            .unwrap();
        s.append(stored("e-a2", "a.example", Some(&r), "a again"), now)
            .unwrap();
        let wire = |from: &str| WireReply {
            msg_ref: Some(r.clone()),
            from: from.into(),
            by_session: Some("claimed".into()),
            kind: "text".into(),
            snippet: "what the sender says it said".into(),
        };
        let got = resolve(&s, "c1", &wire("b.example"));
        assert_eq!(got.message_id.as_deref(), Some("e-b"));
        assert_eq!(got.text, "from b", "the host's copy over the snippet");
        assert_eq!(got.by_session, None, "the claim is not the record");
        assert!(got.resolved);
        assert_eq!(
            resolve(&s, "c1", &wire("a.example")).message_id.as_deref(),
            Some("e-a")
        );
        let missing = resolve(&s, "c1", &wire("c.example"));
        assert!(!missing.resolved);
        assert_eq!(missing.message_id, None);
        assert_eq!(missing.text, "what the sender says it said");
        assert_eq!(missing.by_session.as_deref(), Some("claimed"));
        assert!(!resolve(&s, "other-conversation", &wire("a.example")).resolved);
    }

    #[test]
    fn the_host_builds_the_same_reply_to_every_time() {
        let mut m = stored("e-1", "home.example", Some(&mint_ref()), "  two\n words ");
        m.by_session = Some("bob".into());
        let w = wire_of(&m);
        assert_eq!(w, wire_of(&m));
        assert_eq!(w["snippet"], "two words");
        assert_eq!(w["by_session"], "bob");
        assert_eq!(w["kind"], "text");
        assert!(w["ref"].is_string());
        m.msg_ref = None;
        assert!(wire_of(&m).get("ref").is_none(), "quote-only");
        // What it builds, it reads back.
        assert!(parse(&w).is_some());
    }

    /// What this host sends is read by the decoder every device shares:
    /// the blocks, the reference and the reply as sent.
    #[test]
    fn the_hosts_payload_decodes_with_the_shared_decoder() {
        let r = mint_ref();
        let quote = json!({"from": "home.example", "kind": "text", "snippet": "hi"});
        let blocks = json!([{"type": "text", "text": "bob: yes"}]);
        let bytes = payload(&blocks, &r, Some(&quote)).unwrap();
        let d = LanePayload::decode(&bytes).unwrap();
        assert_eq!(d.blocks, blocks);
        assert_eq!(d.origin, None);
        assert_eq!(d.r#ref.as_deref(), Some(r.as_str()));
        assert_eq!(serde_json::to_value(d.reply_to.unwrap()).unwrap(), quote);
        let plain = LanePayload::decode(&payload(&blocks, &r, None).unwrap()).unwrap();
        assert_eq!(plain.blocks, blocks);
        assert_eq!(plain.reply_to, None);
        // A reply_to the shared type would change is never sent.
        let odd = json!({"from": "home.example", "kind": "text", "snippet": "hi", "x": 1});
        assert!(payload(&blocks, &r, Some(&odd)).is_err());
    }
}
