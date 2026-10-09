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
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Doc {
    head: i64,
    /// conversation id → messages, oldest first.
    conversations: BTreeMap<String, Vec<Message>>,
    /// Envelope ids already stored, so a replayed envelope is one message.
    #[serde(default)]
    seen: Vec<String>,
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
            from: "qa.a.airdr.es".into(),
            lane: "own".into(),
            from_self: false,
            text: format!("text {id}"),
            at,
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
}
