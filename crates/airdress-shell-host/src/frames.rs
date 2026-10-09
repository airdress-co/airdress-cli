//! The host channel's frames, from the host's side (design §8.2–§8.3).
//!
//! **Operator → host frames are signed**: `{"type", "frame", "sig"}`, the
//! signature Ed25519 by the operator's `http_signing` key — the key this host
//! pinned at enrollment — over `"airdress-shell-" ‖ type ‖ "-v1" ‖ 0x00 ‖
//! frame`. The host checks, in order: the signature; that `session` names
//! this channel; that `seq` is new (a long-poll's rotation may repeat a
//! frame, which is dropped, never applied twice); that `notAfter` has not
//! passed. That is step 1 of design §6.3 for `open` and `attach`.
//!
//! **Host → operator frames are unsigned**; they ride a channel whose every
//! request carried the machine's signature.
//!
//! **`data`** on the WebSocket is one binary message per record, with the
//! operator's fixed header; on the long-poll, a frame whose records are
//! base64.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::trust::{b64, Attestation};

/// The signing domain.
pub const DOMAIN: &str = "airdress-shell-";
/// The host channel's WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "airdress.shell-host.v1";
/// The binary `data` frame's version and type.
pub const DATA_VERSION: u8 = 1;
pub const DATA_TYPE: u8 = 1;
/// version, type, session, leg, length.
pub const DATA_HEADER_LEN: usize = 1 + 1 + 16 + 16 + 4;
/// How far a peer's clock may be behind ours before a frame counts as stale.
pub const SKEW_SECS: u64 = 30;

/// The bytes an operator frame's signature covers.
pub fn signed_bytes(frame_type: &str, frame: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 5 + frame_type.len() + frame.len());
    out.extend_from_slice(DOMAIN.as_bytes());
    out.extend_from_slice(frame_type.as_bytes());
    out.extend_from_slice(b"-v1\0");
    out.extend_from_slice(frame.as_bytes());
    out
}

/// A binary `data` frame: header, then one record.
pub fn data_frame(session: Uuid, leg: Uuid, record: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HEADER_LEN + record.len());
    out.push(DATA_VERSION);
    out.push(DATA_TYPE);
    out.extend_from_slice(session.as_bytes());
    out.extend_from_slice(leg.as_bytes());
    out.extend_from_slice(&(record.len() as u32).to_be_bytes());
    out.extend_from_slice(record);
    out
}

/// Read a binary `data` frame's header; the record is returned untouched.
pub fn parse_data_frame(frame: &[u8]) -> Option<(Uuid, Uuid, &[u8])> {
    if frame.len() < DATA_HEADER_LEN || frame[0] != DATA_VERSION || frame[1] != DATA_TYPE {
        return None;
    }
    let session = Uuid::from_slice(&frame[2..18]).ok()?;
    let leg = Uuid::from_slice(&frame[18..34]).ok()?;
    let len = u32::from_be_bytes(frame[34..38].try_into().ok()?) as usize;
    let record = &frame[DATA_HEADER_LEN..];
    (record.len() == len).then_some((session, leg, record))
}

/// The resume half of an `attach`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resume {
    pub ticket_id: String,
    pub handshake: String,
}

/// Operator → host frames (design §8.3).
#[derive(Debug, Clone)]
pub enum OpFrame {
    Hello {
        machine: Option<Uuid>,
        shell_host: Option<String>,
        frame_max_bytes: Option<usize>,
        idle_secs: Option<u64>,
        rotate_secs: Option<u64>,
    },
    Config {
        enabled: bool,
        max_viewers: Option<u32>,
    },
    Open {
        session_id: Uuid,
        leg: Uuid,
        profile: String,
        cols: Option<u16>,
        rows: Option<u16>,
        attestation: Box<Attestation>,
        handshake: Vec<u8>,
    },
    Attach {
        session_id: Uuid,
        leg: Uuid,
        attestation: Box<Attestation>,
        /// A full handshake (a reattach), or a resume.
        handshake: Option<Vec<u8>>,
        resume: Option<(String, Vec<u8>)>,
    },
    Data {
        session_id: Uuid,
        leg: Uuid,
        records: Vec<Vec<u8>>,
    },
    Detach {
        session_id: Uuid,
        leg: Uuid,
        reason: String,
    },
    Close {
        session_id: Uuid,
        device: Uuid,
    },
    ReleaseInput {
        session_id: Uuid,
        device: Uuid,
    },
    RevokeDevice {
        device: Uuid,
    },
    Introduce {
        device: Uuid,
        device_kind: String,
        identity_public: [u8; 32],
        introduced_by: Uuid,
        sig: Vec<u8>,
    },
}

impl OpFrame {
    /// The type, for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Config { .. } => "config",
            Self::Open { .. } => "open",
            Self::Attach { .. } => "attach",
            Self::Data { .. } => "data",
            Self::Detach { .. } => "detach",
            Self::Close { .. } => "close",
            Self::ReleaseInput { .. } => "release_input",
            Self::RevokeDevice { .. } => "revoke_device",
            Self::Introduce { .. } => "introduce",
        }
    }
}

/// Why a line from the operator was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// Not signed by the pinned key, or not a frame at all: the channel is
    /// not to be trusted further.
    Forged(String),
    /// A frame for another channel.
    OtherChannel,
    /// Already applied (a long-poll's overlap).
    Duplicate,
    /// Past its `notAfter`.
    Stale,
    /// A frame of a type the host does not know, or a malformed body.
    Malformed(String),
}

/// What one line from the operator turned out to be.
#[derive(Debug, Clone)]
pub enum Line {
    /// A verified frame, with its `seq`.
    Frame(u64, Box<OpFrame>),
    /// The long-poll's keepalive.
    Keepalive,
    /// The long-poll's end of channel: the code and reason a WebSocket close
    /// would carry.
    Closed(u16, String),
    /// The operator holds the host's frames up to `seq`.
    Ack(u64),
}

/// A verifier for one channel.
#[derive(Debug, Clone)]
pub struct Verifier {
    key: VerifyingKey,
    channel: Option<Uuid>,
    last_seq: u64,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    frame_type: String,
    frame: String,
    sig: String,
}

fn field<T: serde::de::DeserializeOwned>(v: &Value, name: &str) -> Result<T, Reject> {
    serde_json::from_value(v.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|e| Reject::Malformed(format!("{name}: {e}")))
}

fn bytes_field(v: &Value, name: &str) -> Result<Vec<u8>, Reject> {
    let s: String = field(v, name)?;
    b64(&s).ok_or_else(|| Reject::Malformed(format!("{name} is not base64")))
}

impl Verifier {
    /// Verify frames under the pinned operator key.
    pub fn new(key: VerifyingKey) -> Self {
        Self {
            key,
            channel: None,
            last_seq: 0,
        }
    }

    /// The channel this verifier is bound to, once a frame named it.
    pub fn channel(&self) -> Option<Uuid> {
        self.channel
    }

    /// The highest `seq` applied.
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// A new channel: forget the previous one's session and numbering.
    pub fn reset(&mut self) {
        self.channel = None;
        self.last_seq = 0;
    }

    /// Check and parse one text line.
    pub fn line(&mut self, raw: &str, now_unix: u64) -> Result<Line, Reject> {
        let v: Value =
            serde_json::from_str(raw.trim()).map_err(|_| Reject::Forged("not JSON".into()))?;
        if v.get("sig").is_none() {
            // The long-poll's unsigned transport lines carry no frame.
            return match v.get("type").and_then(Value::as_str) {
                Some("keepalive") => Ok(Line::Keepalive),
                Some("ack") => Ok(Line::Ack(field(&v, "seq")?)),
                Some("closed") => Ok(Line::Closed(field(&v, "code")?, field(&v, "reason")?)),
                _ => Err(Reject::Forged("an unsigned frame".into())),
            };
        }
        let env: Envelope =
            serde_json::from_value(v).map_err(|_| Reject::Forged("not an envelope".into()))?;
        let sig = URL_SAFE_NO_PAD
            .decode(env.sig.trim())
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(|| Reject::Forged("signature malformed".into()))?;
        self.key
            .verify_strict(&signed_bytes(&env.frame_type, &env.frame), &sig)
            .map_err(|_| Reject::Forged("not signed by the pinned operator key".into()))?;
        let f: Value = serde_json::from_str(&env.frame)
            .map_err(|_| Reject::Malformed("the frame is not JSON".into()))?;
        let session: Uuid = field(&f, "session")?;
        match self.channel {
            Some(c) if c != session => return Err(Reject::OtherChannel),
            None => self.channel = Some(session),
            _ => {}
        }
        let seq: u64 = field(&f, "seq")?;
        if seq <= self.last_seq {
            return Err(Reject::Duplicate);
        }
        let not_after: u64 = field(&f, "notAfter")?;
        if not_after + SKEW_SECS < now_unix {
            // Numbered, so it is not applied again; past its time, so it is
            // not applied at all.
            self.last_seq = seq;
            return Err(Reject::Stale);
        }
        let frame = parse_frame(&env.frame_type, &f)?;
        self.last_seq = seq;
        Ok(Line::Frame(seq, Box::new(frame)))
    }
}

/// Parse a verified frame's body by its type.
pub fn parse_frame(frame_type: &str, f: &Value) -> Result<OpFrame, Reject> {
    Ok(match frame_type {
        "hello" => OpFrame::Hello {
            machine: field(f, "machine")?,
            shell_host: field(f, "shellHost")?,
            frame_max_bytes: field(f, "frameMaxBytes")?,
            idle_secs: field(f, "idleSecs")?,
            rotate_secs: field(f, "rotateSecs")?,
        },
        "config" => OpFrame::Config {
            enabled: field(f, "enabled")?,
            max_viewers: f
                .get("limits")
                .and_then(|l| l.get("maxViewers"))
                .and_then(Value::as_u64)
                .map(|n| n.min(u64::from(u32::MAX)) as u32),
        },
        "open" => OpFrame::Open {
            session_id: field(f, "sessionId")?,
            leg: field(f, "leg")?,
            profile: field(f, "profile")?,
            cols: field(f, "cols")?,
            rows: field(f, "rows")?,
            attestation: Box::new(field(f, "attestation")?),
            handshake: bytes_field(f, "handshake")?,
        },
        "attach" => {
            let resume: Option<Resume> = field(f, "resume")?;
            let handshake = match f.get("handshake") {
                Some(Value::String(_)) => Some(bytes_field(f, "handshake")?),
                _ => None,
            };
            let resume = match resume {
                Some(r) => Some((
                    r.ticket_id,
                    b64(&r.handshake)
                        .ok_or_else(|| Reject::Malformed("resume handshake".into()))?,
                )),
                None => None,
            };
            if handshake.is_some() == resume.is_some() {
                return Err(Reject::Malformed(
                    "an attach carries a handshake or a resume".into(),
                ));
            }
            OpFrame::Attach {
                session_id: field(f, "sessionId")?,
                leg: field(f, "leg")?,
                attestation: Box::new(field(f, "attestation")?),
                handshake,
                resume,
            }
        }
        "data" => {
            let records: Vec<String> = field(f, "records")?;
            OpFrame::Data {
                session_id: field(f, "sessionId")?,
                leg: field(f, "leg")?,
                records: records
                    .iter()
                    .map(|r| {
                        b64(r).ok_or_else(|| Reject::Malformed("a record is not base64".into()))
                    })
                    .collect::<Result<_, _>>()?,
            }
        }
        "detach" => OpFrame::Detach {
            session_id: field(f, "sessionId")?,
            leg: field(f, "leg")?,
            reason: field::<Option<String>>(f, "reason")?.unwrap_or_default(),
        },
        "close" => OpFrame::Close {
            session_id: field(f, "sessionId")?,
            device: field(f, "device")?,
        },
        "release_input" => OpFrame::ReleaseInput {
            session_id: field(f, "sessionId")?,
            device: field(f, "device")?,
        },
        "revoke_device" => OpFrame::RevokeDevice {
            device: field(f, "device")?,
        },
        "introduce" => OpFrame::Introduce {
            device: field(f, "device")?,
            device_kind: field(f, "deviceKind")?,
            identity_public: bytes_field(f, "identityPublic")?
                .try_into()
                .map_err(|_| Reject::Malformed("identityPublic is not 32 bytes".into()))?,
            introduced_by: field(f, "introducedBy")?,
            sig: bytes_field(f, "sig")?,
        },
        other => {
            return Err(Reject::Malformed(format!(
                "an unknown frame type `{other}`"
            )))
        }
    })
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// Sign `fields` as the operator does: `session`, `seq` and `notAfter`
    /// added, the frame serialized once.
    pub fn envelope(
        key: &SigningKey,
        channel: Uuid,
        seq: u64,
        not_after: u64,
        frame_type: &str,
        mut fields: Value,
    ) -> String {
        fields["session"] = Value::from(channel.to_string());
        fields["seq"] = Value::from(seq);
        fields["notAfter"] = Value::from(not_after);
        let frame = fields.to_string();
        let sig = URL_SAFE_NO_PAD.encode(key.sign(&signed_bytes(frame_type, &frame)).to_bytes());
        serde_json::json!({ "type": frame_type, "frame": frame, "sig": sig }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::envelope;
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn the_signed_bytes_are_the_operators() {
        assert_eq!(
            signed_bytes("open", "{}"),
            b"airdress-shell-open-v1\0{}".to_vec()
        );
    }

    #[test]
    fn only_the_pinned_key_in_this_domain_on_this_channel_once_and_in_time() {
        let op = SigningKey::from_bytes(&[3; 32]);
        let mut v = Verifier::new(op.verifying_key());
        let ch = Uuid::from_u128(1);
        let hello = envelope(
            &op,
            ch,
            1,
            100,
            "hello",
            serde_json::json!({"machine": Uuid::from_u128(2), "frameMaxBytes": 65536}),
        );
        assert!(matches!(v.line(&hello, 50).unwrap(), Line::Frame(1, _)));
        assert_eq!(v.channel(), Some(ch));
        // Again: a long-poll's overlap, dropped.
        assert_eq!(v.line(&hello, 50).unwrap_err(), Reject::Duplicate);
        // Another key.
        let evil = SigningKey::from_bytes(&[4; 32]);
        let forged = envelope(
            &evil,
            ch,
            2,
            100,
            "revoke_device",
            serde_json::json!({"device": Uuid::nil()}),
        );
        assert!(matches!(v.line(&forged, 50), Err(Reject::Forged(_))));
        // Another channel.
        let other = envelope(
            &op,
            Uuid::from_u128(9),
            3,
            100,
            "config",
            serde_json::json!({"enabled": true}),
        );
        assert_eq!(v.line(&other, 50).unwrap_err(), Reject::OtherChannel);
        // Too late.
        let late = envelope(
            &op,
            ch,
            4,
            10,
            "config",
            serde_json::json!({"enabled": true}),
        );
        assert_eq!(v.line(&late, 100).unwrap_err(), Reject::Stale);
        // A home frame signed by the same key does not verify as a shell one.
        let home = {
            use ed25519_dalek::Signer as _;
            let frame = serde_json::json!({"session": ch, "seq": 5, "notAfter": 100}).to_string();
            let mut m = b"airdress-home-config-v1\0".to_vec();
            m.extend_from_slice(frame.as_bytes());
            serde_json::json!({"type": "config", "frame": frame, "sig": URL_SAFE_NO_PAD.encode(op.sign(&m).to_bytes())}).to_string()
        };
        assert!(matches!(v.line(&home, 50), Err(Reject::Forged(_))));
        // An unsigned frame is not a frame.
        assert!(matches!(
            v.line(r#"{"type":"revoke_device","device":"x"}"#, 50),
            Err(Reject::Forged(_))
        ));
        // The long-poll's transport lines.
        assert!(matches!(
            v.line(r#"{"type":"keepalive","ts":1}"#, 50).unwrap(),
            Line::Keepalive
        ));
        assert!(matches!(
            v.line(
                r#"{"type":"closed","code":4003,"reason":"host_revoked"}"#,
                50
            )
            .unwrap(),
            Line::Closed(4003, _)
        ));
    }

    #[test]
    fn an_attach_is_a_handshake_or_a_resume_never_both() {
        let att = serde_json::json!({"device": Uuid::nil(), "principal": Uuid::nil(), "identityPublic": "AA", "dhPublic": "AA", "presenceAlg": "none", "keysSig": "AA"});
        let base =
            serde_json::json!({"sessionId": Uuid::nil(), "leg": Uuid::nil(), "attestation": att});
        let mut both = base.clone();
        both["handshake"] = Value::from("AAAA");
        both["resume"] = serde_json::json!({"ticketId": "x", "handshake": "AAAA"});
        assert!(parse_frame("attach", &both).is_err());
        assert!(parse_frame("attach", &base).is_err());
        let mut hs = base.clone();
        hs["handshake"] = Value::from("AAAA");
        assert!(matches!(
            parse_frame("attach", &hs).unwrap(),
            OpFrame::Attach {
                handshake: Some(_),
                ..
            }
        ));
        assert!(parse_frame("exec", &base).is_err());
    }

    #[test]
    fn the_data_header_round_trips() {
        let (s, l) = (Uuid::from_u128(5), Uuid::from_u128(6));
        let f = data_frame(s, l, b"record");
        assert_eq!(parse_data_frame(&f), Some((s, l, &b"record"[..])));
        let mut bad = f.clone();
        bad.pop();
        assert_eq!(parse_data_frame(&bad), None);
        bad = f.clone();
        bad[0] = 2;
        assert_eq!(parse_data_frame(&bad), None);
    }
}
