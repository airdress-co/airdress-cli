//! The messages inside the E2E channel and on the desk socket (design §7.10).
//!
//! Each message is a one-byte type, a 32-bit big-endian body length, and
//! the body. One record may carry several messages back to back.
//!
//! Bodies are of two kinds:
//!
//! - **binary**, for the hot path and for bulk data: `out`, `snapshot`,
//!   `in` and `recording_chunk`, laid out as documented on each variant;
//! - **JSON**, for every control message. They are inside the AEAD, so
//!   canonical form does not matter.
//!
//! Every message also has a **JSON form** (`{"type": "out", "offset": 0,
//! "data": "<base64>"}`), the one the conformance vectors and the C ABI use,
//! so that a Dart or Node test can state a message without a byte layout.
//!
//! The type byte is part of the protocol version: an unknown type is a
//! malformed message, not one to skip.

use serde::{Deserialize, Serialize};

use crate::error::{ProtoError, Result};
use crate::handshake::Channel;
use crate::presence::PresenceAlg;
use crate::prologue::Action;
use crate::record::MAX_PLAINTEXT;
use crate::recording::RecipientEntry;

/// Bytes before every body: the type and the length.
pub const HEADER_LEN: usize = 5;

/// The PTY control characters a client may ask for (design §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// `c_cc[VINTR]`.
    Interrupt,
    /// `c_cc[VSUSP]`.
    Suspend,
    /// `c_cc[VQUIT]`.
    Quit,
    /// `c_cc[VEOF]`.
    Eof,
}

/// One attached client, as `roles` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Viewer {
    /// A device id, or `desk`.
    pub client: String,
    /// What a human calls it ("Galaxy S23").
    pub label: String,
}

/// One inner message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    /// host → client. Binary: `offset (u64) ‖ bytes`. PTY output from the
    /// journal, starting at stream offset `offset`.
    Out {
        /// Stream offset of the first byte.
        offset: u64,
        /// The output.
        #[serde(with = "crate::b64::bytes")]
        data: Vec<u8>,
    },
    /// host → client. Binary: `offset (u64) ‖ cols (u16) ‖ rows (u16) ‖
    /// bytes`. A VT sequence that redraws the screen, then scrollback.
    Snapshot {
        /// The stream offset the snapshot stands for.
        offset: u64,
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
        /// The redraw.
        #[serde(with = "crate::b64::bytes")]
        data: Vec<u8>,
    },
    /// client → host. Binary: the bytes. From the typist only.
    In {
        /// Text or key sequences.
        #[serde(with = "crate::b64::bytes")]
        data: Vec<u8>,
    },
    /// client → host.
    Signal {
        /// Which control character.
        signal: SignalKind,
    },
    /// client → host. Applied only from the typist.
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
    /// client → host. The offset received.
    Ack {
        /// Stream offset.
        offset: u64,
    },
    /// client → host. Bytes the client accepts beyond `ack`.
    Credit {
        /// Bytes.
        bytes: u64,
    },
    /// client → host. The first record after an open or attach handshake,
    /// always: a phone's unlock signature, or a CLI's `none`.
    Presence {
        /// `open` or `attach`.
        action: Action,
        /// `p256` or `none`.
        alg: PresenceAlg,
        /// DER ECDSA signature, absent for `none`.
        #[serde(
            default,
            with = "crate::b64::opt",
            skip_serializing_if = "Option::is_none"
        )]
        sig: Option<Vec<u8>>,
    },
    /// client → host. Ask for the typist role.
    TakeInput,
    /// host → client. Sent on every change.
    Roles {
        /// The typist, if any.
        typist: Option<String>,
        /// Every attached client.
        viewers: Vec<Viewer>,
        /// Why it changed.
        reason: String,
    },
    /// host → client. The session's program exited.
    Exit {
        /// Exit code, if it exited.
        code: Option<i32>,
        /// Signal number, if it was killed.
        signal: Option<i32>,
    },
    /// host → client.
    HostStopping {
        /// Seconds until the host stops.
        in_seconds: u32,
    },
    /// both. Structured-tier events and inputs; the body is the adapter's.
    Structured {
        /// The event or input.
        body: serde_json::Value,
    },
    /// client → host. List the session's recordings.
    RecordingList,
    /// host → client. The recordings this host holds for the principal.
    RecordingListing {
        /// One entry per recording.
        recordings: Vec<RecordingInfo>,
    },
    /// client → host. Fetch one segment from chunk `from_chunk` on.
    RecordingFetch {
        /// The recording (a session id).
        recording: String,
        /// The segment number.
        segment: u32,
        /// The first chunk wanted.
        from_chunk: u64,
    },
    /// host → client. A segment's header, before its chunks.
    RecordingHeader {
        /// The recording.
        recording: String,
        /// The segment number.
        segment: u32,
        /// The serialized [`crate::recording::SegmentHeader`].
        #[serde(with = "crate::b64::bytes")]
        header: Vec<u8>,
    },
    /// host → client. Binary: `segment (u32) ‖ index (u64) ‖ sealed chunk`.
    /// Belongs to the most recent `recording_header`.
    RecordingChunk {
        /// The segment number.
        segment: u32,
        /// The chunk index.
        index: u64,
        /// The sealed chunk, as stored.
        #[serde(with = "crate::b64::bytes")]
        sealed: Vec<u8>,
    },
    /// client → host. Add a recipient to a segment header.
    RecordingRewrap {
        /// The recording.
        recording: String,
        /// The segment number.
        segment: u32,
        /// The new recipient's wrapped key.
        entry: RecipientEntry,
    },
    /// both. The sender's key changes at `switch_at` (design §6.5). With
    /// `request`, the receiver rekeys its own direction too (design §6.7).
    Rekey {
        /// The first nonce under the new key.
        switch_at: u64,
        /// Ask the peer to rekey its sending direction as well.
        request: bool,
    },
    /// host → client.
    Error {
        /// A design §13 code.
        code: String,
        /// For a human.
        message: String,
    },
}

/// One recording in a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingInfo {
    /// The recording (a session id).
    pub recording: String,
    /// The profile it ran.
    pub profile: String,
    /// When it started, RFC 3339.
    pub started_at: String,
    /// How many segments it has.
    pub segments: u32,
}

const T_OUT: u8 = 0x01;
const T_SNAPSHOT: u8 = 0x02;
const T_IN: u8 = 0x03;
const T_SIGNAL: u8 = 0x04;
const T_RESIZE: u8 = 0x05;
const T_ACK: u8 = 0x06;
const T_CREDIT: u8 = 0x07;
const T_PRESENCE: u8 = 0x08;
const T_TAKE_INPUT: u8 = 0x09;
const T_ROLES: u8 = 0x0A;
const T_EXIT: u8 = 0x0B;
const T_HOST_STOPPING: u8 = 0x0C;
const T_STRUCTURED: u8 = 0x0D;
const T_RECORDING_LIST: u8 = 0x0E;
const T_RECORDING_LISTING: u8 = 0x0F;
const T_RECORDING_FETCH: u8 = 0x10;
const T_RECORDING_HEADER: u8 = 0x11;
const T_RECORDING_CHUNK: u8 = 0x12;
const T_RECORDING_REWRAP: u8 = 0x13;
const T_REKEY: u8 = 0x14;
const T_ERROR: u8 = 0x15;

/// Every type byte and its name, for the vectors and the other drivers.
pub const TYPE_TABLE: &[(u8, &str)] = &[
    (T_OUT, "out"),
    (T_SNAPSHOT, "snapshot"),
    (T_IN, "in"),
    (T_SIGNAL, "signal"),
    (T_RESIZE, "resize"),
    (T_ACK, "ack"),
    (T_CREDIT, "credit"),
    (T_PRESENCE, "presence"),
    (T_TAKE_INPUT, "take_input"),
    (T_ROLES, "roles"),
    (T_EXIT, "exit"),
    (T_HOST_STOPPING, "host_stopping"),
    (T_STRUCTURED, "structured"),
    (T_RECORDING_LIST, "recording_list"),
    (T_RECORDING_LISTING, "recording_listing"),
    (T_RECORDING_FETCH, "recording_fetch"),
    (T_RECORDING_HEADER, "recording_header"),
    (T_RECORDING_CHUNK, "recording_chunk"),
    (T_RECORDING_REWRAP, "recording_rewrap"),
    (T_REKEY, "rekey"),
    (T_ERROR, "error"),
];

impl Message {
    /// The type byte.
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Out { .. } => T_OUT,
            Message::Snapshot { .. } => T_SNAPSHOT,
            Message::In { .. } => T_IN,
            Message::Signal { .. } => T_SIGNAL,
            Message::Resize { .. } => T_RESIZE,
            Message::Ack { .. } => T_ACK,
            Message::Credit { .. } => T_CREDIT,
            Message::Presence { .. } => T_PRESENCE,
            Message::TakeInput => T_TAKE_INPUT,
            Message::Roles { .. } => T_ROLES,
            Message::Exit { .. } => T_EXIT,
            Message::HostStopping { .. } => T_HOST_STOPPING,
            Message::Structured { .. } => T_STRUCTURED,
            Message::RecordingList => T_RECORDING_LIST,
            Message::RecordingListing { .. } => T_RECORDING_LISTING,
            Message::RecordingFetch { .. } => T_RECORDING_FETCH,
            Message::RecordingHeader { .. } => T_RECORDING_HEADER,
            Message::RecordingChunk { .. } => T_RECORDING_CHUNK,
            Message::RecordingRewrap { .. } => T_RECORDING_REWRAP,
            Message::Rekey { .. } => T_REKEY,
            Message::Error { .. } => T_ERROR,
        }
    }

    fn name_of(t: u8) -> Option<&'static str> {
        TYPE_TABLE.iter().find(|(b, _)| *b == t).map(|(_, n)| *n)
    }

    /// Encode one message.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = match self {
            Message::Out { offset, data } => {
                let mut b = Vec::with_capacity(8 + data.len());
                b.extend_from_slice(&offset.to_be_bytes());
                b.extend_from_slice(data);
                b
            }
            Message::Snapshot {
                offset,
                cols,
                rows,
                data,
            } => {
                let mut b = Vec::with_capacity(12 + data.len());
                b.extend_from_slice(&offset.to_be_bytes());
                b.extend_from_slice(&cols.to_be_bytes());
                b.extend_from_slice(&rows.to_be_bytes());
                b.extend_from_slice(data);
                b
            }
            Message::In { data } => data.clone(),
            Message::RecordingChunk {
                segment,
                index,
                sealed,
            } => {
                let mut b = Vec::with_capacity(12 + sealed.len());
                b.extend_from_slice(&segment.to_be_bytes());
                b.extend_from_slice(&index.to_be_bytes());
                b.extend_from_slice(sealed);
                b
            }
            _ => {
                let mut v = serde_json::to_value(self)
                    .map_err(|_| ProtoError::InvalidInput("message does not serialize"))?;
                if let Some(o) = v.as_object_mut() {
                    o.remove("type");
                }
                serde_json::to_vec(&v)
                    .map_err(|_| ProtoError::InvalidInput("message does not serialize"))?
            }
        };
        if body.len() > MAX_PLAINTEXT - HEADER_LEN {
            return Err(ProtoError::InvalidInput("message too large"));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(self.type_byte());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn decode_body(t: u8, body: &[u8]) -> Result<Message> {
        let need = |n: usize| {
            if body.len() < n {
                Err(ProtoError::InnerMalformed("body too short"))
            } else {
                Ok(())
            }
        };
        let u64_at = |i: usize| u64::from_be_bytes(body[i..i + 8].try_into().expect("8 bytes"));
        let u16_at = |i: usize| u16::from_be_bytes(body[i..i + 2].try_into().expect("2 bytes"));
        match t {
            T_OUT => {
                need(8)?;
                Ok(Message::Out {
                    offset: u64_at(0),
                    data: body[8..].to_vec(),
                })
            }
            T_SNAPSHOT => {
                need(12)?;
                Ok(Message::Snapshot {
                    offset: u64_at(0),
                    cols: u16_at(8),
                    rows: u16_at(10),
                    data: body[12..].to_vec(),
                })
            }
            T_IN => Ok(Message::In {
                data: body.to_vec(),
            }),
            T_RECORDING_CHUNK => {
                need(12)?;
                Ok(Message::RecordingChunk {
                    segment: u32::from_be_bytes(body[0..4].try_into().expect("4 bytes")),
                    index: u64_at(4),
                    sealed: body[12..].to_vec(),
                })
            }
            _ => {
                let name = Self::name_of(t).ok_or(ProtoError::InnerMalformed("unknown type"))?;
                let mut v: serde_json::Value = serde_json::from_slice(body)
                    .map_err(|_| ProtoError::InnerMalformed("body is not JSON"))?;
                let o = v
                    .as_object_mut()
                    .ok_or(ProtoError::InnerMalformed("body is not an object"))?;
                if o.contains_key("type") {
                    return Err(ProtoError::InnerMalformed("type inside the body"));
                }
                o.insert("type".into(), serde_json::Value::String(name.into()));
                serde_json::from_value(v).map_err(|_| ProtoError::InnerMalformed("body fields"))
            }
        }
    }

    /// Decode every message in a record's plaintext.
    pub fn decode_all(mut bytes: &[u8]) -> Result<Vec<Message>> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            if bytes.len() < HEADER_LEN {
                return Err(ProtoError::InnerMalformed("truncated header"));
            }
            let t = bytes[0];
            let len = u32::from_be_bytes(bytes[1..5].try_into().expect("4 bytes")) as usize;
            if bytes.len() - HEADER_LEN < len {
                return Err(ProtoError::InnerMalformed("truncated body"));
            }
            out.push(Self::decode_body(t, &bytes[HEADER_LEN..HEADER_LEN + len])?);
            bytes = &bytes[HEADER_LEN + len..];
        }
        Ok(out)
    }

    /// Encode several messages into one plaintext.
    pub fn encode_all(msgs: &[Message]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for m in msgs {
            out.extend_from_slice(&m.encode()?);
        }
        if out.len() > MAX_PLAINTEXT {
            return Err(ProtoError::InvalidInput("messages exceed one record"));
        }
        Ok(out)
    }
}

/// Schedule a rekey of `ch`'s sending direction and seal the announcing
/// `rekey` message: the returned record is the last one under the old key.
pub fn seal_rekey(ch: &mut Channel, request: bool, now_ms: u64) -> Result<Vec<u8>> {
    let switch_at = ch.schedule_rekey();
    let msg = Message::Rekey { switch_at, request }.encode()?;
    ch.seal(&msg, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Message> {
        vec![
            Message::Out {
                offset: 7,
                data: b"hi\r\n".to_vec(),
            },
            Message::Snapshot {
                offset: 9,
                cols: 80,
                rows: 24,
                data: b"\x1b[H".to_vec(),
            },
            Message::In { data: vec![3] },
            Message::Signal {
                signal: SignalKind::Interrupt,
            },
            Message::Resize {
                cols: 100,
                rows: 40,
            },
            Message::Ack { offset: 1 },
            Message::Credit { bytes: 262_144 },
            Message::Presence {
                action: Action::Open,
                alg: PresenceAlg::None,
                sig: None,
            },
            Message::Presence {
                action: Action::Attach,
                alg: PresenceAlg::P256,
                sig: Some(vec![0x30, 1, 2]),
            },
            Message::TakeInput,
            Message::Roles {
                typist: Some("d1".into()),
                viewers: vec![Viewer {
                    client: "d1".into(),
                    label: "phone".into(),
                }],
                reason: "attached".into(),
            },
            Message::Exit {
                code: Some(0),
                signal: None,
            },
            Message::HostStopping { in_seconds: 10 },
            Message::Structured {
                body: serde_json::json!({"k": "v"}),
            },
            Message::RecordingList,
            Message::RecordingFetch {
                recording: "s".into(),
                segment: 0,
                from_chunk: 0,
            },
            Message::RecordingChunk {
                segment: 1,
                index: 2,
                sealed: vec![1, 2, 3],
            },
            Message::Rekey {
                switch_at: 5,
                request: true,
            },
            Message::Error {
                code: "shell_input_not_held".into(),
                message: "Input is on another device".into(),
            },
        ]
    }

    /// A structured body's numbers survive a decode and a re-encode exactly
    /// (found by the `inner` fuzz target: without serde_json's
    /// `float_roundtrip` this one came back one ulp away).
    #[test]
    fn a_structured_number_round_trips_exactly() {
        let body = br#"{"body":{"kind":133333333300000000324448120}}"#;
        let mut bytes = vec![T_STRUCTURED];
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        let first = Message::decode_all(&bytes).unwrap();
        let again = Message::decode_all(&Message::encode_all(&first).unwrap()).unwrap();
        assert_eq!(again, first);
    }

    #[test]
    fn every_sample_round_trips_alone_and_together() {
        for m in samples() {
            let b = m.encode().unwrap();
            assert_eq!(Message::decode_all(&b).unwrap(), vec![m.clone()]);
            let j = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<Message>(&j).unwrap(), m);
        }
        let all = samples();
        let b = Message::encode_all(&all).unwrap();
        assert_eq!(Message::decode_all(&b).unwrap(), all);
    }

    #[test]
    fn type_table_covers_every_variant_once() {
        let mut seen: Vec<u8> = samples().iter().map(Message::type_byte).collect();
        seen.sort();
        seen.dedup();
        for b in seen {
            assert_eq!(TYPE_TABLE.iter().filter(|(t, _)| *t == b).count(), 1);
        }
        let mut bytes: Vec<u8> = TYPE_TABLE.iter().map(|(b, _)| *b).collect();
        bytes.dedup();
        assert_eq!(bytes.len(), TYPE_TABLE.len());
    }

    #[test]
    fn unknown_and_truncated_are_malformed() {
        assert!(Message::decode_all(&[0xEE, 0, 0, 0, 2, b'{', b'}']).is_err());
        assert!(Message::decode_all(&[T_OUT, 0, 0, 0, 9, 1]).is_err());
        assert!(Message::decode_all(&[T_OUT, 0, 0]).is_err());
        assert!(Message::decode_all(&[T_ACK, 0, 0, 0, 2, b'{', b'}']).is_err());
    }
}
