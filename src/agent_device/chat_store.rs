//! The agent device's local message store: sealed, bounded, ordered.
//!
//! What the device host decrypted is kept here so that `chat_read` can
//! answer from this machine and a channel push is never the only copy.
//! Two bounds, whichever bites first (FR-35): the last 1,000 messages per
//! conversation, and nothing older than 30 days. The file is one JSON
//! document sealed with ChaCha20-Poly1305 under the device's state key
//! (the key that seals the MLS state), written beside and renamed in, so a
//! crash leaves the previous version rather than half of a new one.
//!
//! Every message gets a local sequence number, increasing across all
//! conversations. It is this machine's cursor, never sent anywhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Most messages kept per conversation.
pub const KEEP_PER_CONVERSATION: usize = 1_000;
/// Oldest message kept.
pub const KEEP_DAYS: i64 = 30;

const FILE: &str = "messages.sealed";
/// Domain separation for the AEAD: the same state key seals the MLS state.
const AAD: &[u8] = b"airdress.agent_chat.messages.v1";

/// One message, as stored and as `chat_read` returns it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    /// This machine's sequence number.
    pub seq: i64,
    /// The operator's envelope id, or a local id for what this device sent.
    pub message_id: String,
    pub conversation_id: String,
    /// Who wrote it: an airdress, or "operator" for the operator's agent.
    pub from: String,
    /// `own` (this device's lane with the operator's agent) or `assigned`.
    pub lane: String,
    /// Whether this device sent it.
    pub from_self: bool,
    pub text: String,
    pub at: DateTime<Utc>,
    /// The one session this message is for, when it was written in a
    /// conversation with a named session (SPEC-166 phase C): every message
    /// there is for that name, whatever it mentions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_session: Option<String>,
    /// The sender's reference for this message (SPEC-174 FR-4), what a
    /// reply names it by. Absent on a message from an older client and on
    /// everything stored before replies existed.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub msg_ref: Option<String>,
    /// The message this one answers, as this host resolved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Reply>,
    /// The session on this machine that wrote it, when one did and its
    /// signature was checked: what makes a reply to it addressed to that
    /// session (FR-32).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_session: Option<String>,
    /// What the message holds (`text`, `code`, `image`, `audio`, `place`,
    /// `live`, `other`), for a quote of it. Absent means text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Its text and code, as a quote of it is cut from (the app's copy
    /// text). Absent means `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotable: Option<String>,
}

/// The message a reply answers, as `chat_read` returns it: the original's
/// id on this machine when the host holds it, who wrote it, and the quoted
/// words — the host's own copy when it has one, else the sender's snippet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reply {
    pub message_id: Option<String>,
    /// The original's sending airdress.
    pub from: String,
    /// The session that wrote the original: this host's record when
    /// resolved, else what the reply says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_session: Option<String>,
    pub kind: String,
    pub text: String,
    pub resolved: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Doc {
    head: i64,
    /// conversation id → messages, oldest first.
    conversations: BTreeMap<String, Vec<Message>>,
    /// Envelope ids already stored, so a replayed envelope is one message.
    #[serde(default)]
    seen: Vec<String>,
    /// Session name → the highest `seq` of a message for that name a
    /// session of that name has been handed, so what arrived while nobody
    /// of that name waited is handed at its next wait, once.
    #[serde(default)]
    delivered: BTreeMap<String, i64>,
}

/// The store, open.
pub struct ChatStore {
    path: PathBuf,
    key: [u8; 32],
    doc: Doc,
}

impl std::fmt::Debug for ChatStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatStore")
            .field("path", &self.path)
            .field("head", &self.doc.head)
            .finish_non_exhaustive()
    }
}

fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plain,
                aad: AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("seal the message store"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

fn unseal(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 12 {
        bail!("the message store is truncated");
    }
    let (nonce, ct) = sealed.split_at(12);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            chacha20poly1305::aead::Payload { msg: ct, aad: AAD },
        )
        .map_err(|_| anyhow::anyhow!("the message store does not open with this device's key"))
}

impl ChatStore {
    /// Open (or start) the store in `dir`. A store that does not unseal is
    /// an error, never silently replaced: it would be this device's history.
    pub fn open(dir: &Path, key: [u8; 32]) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(FILE);
        let doc = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&unseal(&key, &bytes)?)
                .context("the message store is not readable")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Doc::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        Ok(Self { path, key, doc })
    }

    fn save(&self) -> Result<()> {
        let plain = serde_json::to_vec(&self.doc)?;
        let sealed = seal(&self.key, &plain)?;
        crate::shell_client::store::write_private(&self.path, &sealed)
    }

    /// The highest sequence number given out.
    pub fn head(&self) -> i64 {
        self.doc.head
    }

    /// Store one message (its `seq` is assigned here), apply both bounds and
    /// persist. A message whose id is already stored is not stored twice;
    /// `None` then.
    pub fn append(&mut self, mut m: Message, now: DateTime<Utc>) -> Result<Option<Message>> {
        if self.doc.seen.iter().any(|s| s == &m.message_id) {
            return Ok(None);
        }
        self.doc.head += 1;
        m.seq = self.doc.head;
        self.doc.seen.push(m.message_id.clone());
        self.doc
            .conversations
            .entry(m.conversation_id.clone())
            .or_default()
            .push(m.clone());
        self.prune(now);
        self.save()?;
        Ok(Some(m))
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let oldest = now - Duration::days(KEEP_DAYS);
        for list in self.doc.conversations.values_mut() {
            list.retain(|m| m.at >= oldest);
            if list.len() > KEEP_PER_CONVERSATION {
                let drop = list.len() - KEEP_PER_CONVERSATION;
                list.drain(..drop);
            }
        }
        self.doc.conversations.retain(|_, l| !l.is_empty());
        // The replay guard only needs to outlive the operator's own replay
        // window; keep it bounded by what is stored plus a margin.
        let cap = 4 * KEEP_PER_CONVERSATION;
        if self.doc.seen.len() > cap {
            let drop = self.doc.seen.len() - cap;
            self.doc.seen.drain(..drop);
        }
    }

    /// Messages for session `name` it has not been handed yet, oldest
    /// first, at most `limit`: what arrived while no session of that name
    /// waited. Bounded by what the store keeps (the last thousand per
    /// conversation, thirty days).
    pub fn undelivered_for(&self, name: &str, limit: usize) -> Vec<Message> {
        let since = self.doc.delivered.get(name).copied().unwrap_or(0);
        let mut out: Vec<Message> = self
            .doc
            .conversations
            .values()
            .flatten()
            .filter(|m| m.seq > since && !m.from_self && m.for_session.as_deref() == Some(name))
            .cloned()
            .collect();
        out.sort_by_key(|m| m.seq);
        out.truncate(limit);
        out
    }

    /// Record that a session named `name` was handed `messages`: those for
    /// it no longer wait for its next start.
    pub fn handed(&mut self, name: &str, messages: &[Message]) -> Result<()> {
        let Some(top) = messages
            .iter()
            .filter(|m| m.for_session.as_deref() == Some(name))
            .map(|m| m.seq)
            .max()
        else {
            return Ok(());
        };
        let at = self.doc.delivered.entry(name.to_owned()).or_insert(0);
        if top <= *at {
            return Ok(());
        }
        *at = top;
        self.save()
    }

    /// The oldest message in `conversation` from `from` with the reference
    /// `msg_ref`: what a reply naming them answers. Scoped to the sender,
    /// so one sender's reference cannot point a quote at another's message
    /// (FR-9).
    pub fn find_ref(&self, conversation: &str, from: &str, msg_ref: &str) -> Option<&Message> {
        self.doc
            .conversations
            .get(conversation)?
            .iter()
            .find(|m| m.from == from && m.msg_ref.as_deref() == Some(msg_ref))
    }

    /// The message `message_id` in `conversation`.
    pub fn get(&self, conversation: &str, message_id: &str) -> Option<&Message> {
        self.doc
            .conversations
            .get(conversation)?
            .iter()
            .find(|m| m.message_id == message_id)
    }

    /// Messages after `after` (exclusive), in one conversation or all,
    /// oldest first, at most `limit`.
    pub fn read(&self, conversation: Option<&str>, after: i64, limit: usize) -> Vec<Message> {
        let mut out: Vec<Message> = match conversation {
            Some(c) => self
                .doc
                .conversations
                .get(c)
                .map(|l| l.iter().filter(|m| m.seq > after).cloned().collect())
                .unwrap_or_default(),
            None => self
                .doc
                .conversations
                .values()
                .flatten()
                .filter(|m| m.seq > after)
                .cloned()
                .collect(),
        };
        out.sort_by_key(|m| m.seq);
        out.truncate(limit);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, conversation_row: &str, at: DateTime<Utc>) -> Message {
        Message {
            seq: 0,
            message_id: id.into(),
            conversation_id: conversation_row.into(),
            from: "bob.a.airdr.es".into(),
            lane: "own".into(),
            from_self: false,
            text: format!("text {id}"),
            at,
            for_session: None,
            msg_ref: None,
            reply_to: None,
            by_session: None,
            kind: None,
            quotable: None,
        }
    }

    #[test]
    fn sealed_on_disk_and_reopened_with_the_key_only() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut s = ChatStore::open(dir.path(), [7; 32]).unwrap();
        s.append(msg("e1", "c1", now), now).unwrap();
        let raw = std::fs::read(dir.path().join(FILE)).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("text e1"),
            "plaintext on disk"
        );
        let again = ChatStore::open(dir.path(), [7; 32]).unwrap();
        assert_eq!(again.read(None, 0, 10).len(), 1);
        assert!(
            ChatStore::open(dir.path(), [8; 32]).is_err(),
            "opened with another key"
        );
    }

    #[test]
    fn a_replayed_envelope_is_one_message_and_seq_increases_across_conversations() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut s = ChatStore::open(dir.path(), [1; 32]).unwrap();
        assert_eq!(s.append(msg("e1", "c1", now), now).unwrap().unwrap().seq, 1);
        assert!(s.append(msg("e1", "c1", now), now).unwrap().is_none());
        assert_eq!(s.append(msg("e2", "c2", now), now).unwrap().unwrap().seq, 2);
        assert_eq!(s.head(), 2);
        assert_eq!(s.read(Some("c2"), 0, 10)[0].message_id, "e2");
        assert_eq!(s.read(None, 1, 10).len(), 1);
    }

    #[test]
    fn keeps_the_last_thousand_per_conversation_and_thirty_days() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut s = ChatStore::open(dir.path(), [2; 32]).unwrap();
        s.append(
            msg("old", "c1", now - Duration::days(31)),
            now - Duration::days(31),
        )
        .unwrap();
        s.append(msg("recent", "c1", now), now).unwrap();
        let ids: Vec<String> = s
            .read(Some("c1"), 0, 10)
            .into_iter()
            .map(|m| m.message_id)
            .collect();
        assert_eq!(ids, vec!["recent"]);
        for i in 0..(KEEP_PER_CONVERSATION + 5) {
            s.append(msg(&format!("m{i}"), "c2", now), now).unwrap();
        }
        let c2 = s.read(Some("c2"), 0, usize::MAX);
        assert_eq!(c2.len(), KEEP_PER_CONVERSATION);
        assert_eq!(c2[0].message_id, "m5");
    }

    /// A store sealed by a release from before replies (no `ref`,
    /// `reply_to`, `by_session`, `kind` or `quotable`) opens, and its
    /// messages read as having none.
    #[test]
    fn a_store_written_before_replies_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let old = serde_json::json!({
            "head": 1,
            "conversations": {"c1": [{
                "seq": 1, "message_id": "e1", "conversation_id": "c1",
                "from": "bob.example", "lane": "assigned", "from_self": false,
                "text": "hello", "at": "2026-10-20T10:00:00Z",
            }]},
            "seen": ["e1"],
            "delivered": {},
        });
        let key = [5; 32];
        let sealed = seal(&key, &serde_json::to_vec(&old).unwrap()).unwrap();
        std::fs::write(dir.path().join(FILE), sealed).unwrap();
        let s = ChatStore::open(dir.path(), key).unwrap();
        let m = &s.read(None, 0, 10)[0];
        assert_eq!(m.text, "hello");
        assert_eq!(m.msg_ref, None);
        assert_eq!(m.reply_to, None);
        assert_eq!(m.by_session, None);
        // And it serialises as it did: no new keys on an old message.
        let v = serde_json::to_value(m).unwrap();
        for k in ["ref", "reply_to", "by_session", "kind", "quotable"] {
            assert!(v.get(k).is_none(), "{k}");
        }
    }

    #[test]
    fn what_was_written_for_a_name_waits_for_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ChatStore::open(dir.path(), [7; 32]).unwrap();
        let now = Utc::now();
        let for_ = |id: &str, name: Option<&str>| Message {
            for_session: name.map(str::to_owned),
            ..msg(id, "c-bob", now)
        };
        s.append(for_("e1", Some("bob")), now).unwrap();
        s.append(for_("e2", Some("dave")), now).unwrap();
        s.append(for_("e3", None), now).unwrap();
        let waiting = s.undelivered_for("bob", 100);
        assert_eq!(
            waiting
                .iter()
                .map(|m| m.message_id.as_str())
                .collect::<Vec<_>>(),
            ["e1"]
        );
        s.handed("bob", &waiting).unwrap();
        assert!(s.undelivered_for("bob", 100).is_empty(), "handed once");
        // Reopened: the record survives a restart of the host.
        let mut s = ChatStore::open(dir.path(), [7; 32]).unwrap();
        assert!(s.undelivered_for("bob", 100).is_empty());
        s.append(for_("e4", Some("bob")), now).unwrap();
        assert_eq!(s.undelivered_for("bob", 100).len(), 1, "a newer one waits");
        assert_eq!(s.undelivered_for("dave", 100).len(), 1);
    }
}
