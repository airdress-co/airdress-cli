//! Conformance vectors: their format, and the verifier every target runs.
//!
//! The files live in `tests/vectors/*.json` (design §14.2). Each states
//! inputs and the exact bytes this crate must produce from them. The
//! verifier is part of the shipped library, not of the tests, so that the
//! very build a client ships runs it: natively in `cargo test`, through the
//! C ABI (`airdress_shell_vectors_verify`) in the app's Dart test, and
//! through the wasm build under Node.
//!
//! Randomness in a vector is explicit. A handshake states its ephemeral
//! secrets and the ticket id (the only random draws a handshake makes, in
//! that order), which keeps those vectors meaningful to any Noise
//! implementation. A recording states a seed for [`DetRng`], because HPKE
//! and the chunk nonces draw more than is worth spelling out.
//!
//! Byte strings are lowercase hex.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ProtoError, Result};
use crate::handshake::{
    ticket_from_hello, DeviceHello, HostHello, InitiatorHandshake, ResponderHandshake,
};
use crate::inner::Message;
use crate::keys::ShellKeypair;
use crate::presence::{presence_rule, verify_presence, DeviceKeys, PresenceRequirement};
use crate::prologue::{Action, Prologue};
use crate::record::{noise_encrypt, rekey, RecvState};
use crate::recording::{Recipient, SegmentHeader, SegmentReader, SegmentWriter};

/// Lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Parse hex.
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(ProtoError::InvalidInput("odd hex"));
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ProtoError::InvalidInput("hex digit")),
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Ok((v(p[0])? << 4) | v(p[1])?))
        .collect()
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    from_hex(s)?
        .try_into()
        .map_err(|_| ProtoError::InvalidInput("expected 32 bytes"))
}

/// Yields exactly the bytes it was given, in order; panics when asked for
/// more. For replaying a vector's stated draws.
pub(crate) struct ScriptedRng {
    bytes: Vec<u8>,
    at: usize,
}

impl ScriptedRng {
    pub(crate) fn new(parts: &[&[u8]]) -> Self {
        Self {
            bytes: parts.concat(),
            at: 0,
        }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.at == self.bytes.len()
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.at + dest.len();
        assert!(end <= self.bytes.len(), "vector RNG exhausted");
        dest.copy_from_slice(&self.bytes[self.at..end]);
        self.at = end;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Only ever fed bytes a vector states; never used for a real key.
impl CryptoRng for ScriptedRng {}

/// A deterministic byte stream, `SHA-256(seed ‖ counter)`. For vectors
/// only: anyone with the seed has every key it produced.
pub struct DetRng {
    seed: Vec<u8>,
    counter: u64,
    buf: [u8; 32],
    used: usize,
}

impl std::fmt::Debug for DetRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetRng")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl DetRng {
    /// A stream from `seed`.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }
}

impl RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            if self.used == 32 {
                let mut h = Sha256::new();
                h.update(&self.seed);
                h.update(self.counter.to_be_bytes());
                self.buf.copy_from_slice(&h.finalize());
                self.counter += 1;
                self.used = 0;
            }
            *d = self.buf[self.used];
            self.used += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Deterministic by design, for vectors; see the type's documentation.
impl CryptoRng for DetRng {}

// ---------------------------------------------------------------------------
// Handshakes

/// One record in a handshake vector: sealed by `from`, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordCase {
    /// `device` or `host`.
    pub from: String,
    /// Plaintext, hex.
    pub plaintext: String,
    /// The record, hex.
    pub record: String,
}

/// One handshake, with the records that follow it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeCase {
    /// What it shows.
    pub name: String,
    /// `IK` or `IKpsk2`.
    pub pattern: String,
    /// The prologue's fields.
    pub prologue: Prologue,
    /// The prologue's bytes, hex.
    pub prologue_bytes: String,
    /// The device's X25519 static secret.
    pub device_static_secret: String,
    /// The host's X25519 static secret.
    pub host_static_secret: String,
    /// The device's ephemeral secret (its one RNG draw).
    pub device_ephemeral_secret: String,
    /// The host's ephemeral secret (its first RNG draw).
    pub host_ephemeral_secret: String,
    /// The ticket id the host issues (its second RNG draw).
    pub ticket_id: String,
    /// For `IKpsk2`: the pre-shared key (the previous resume secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    /// msg1's payload.
    pub device_hello: DeviceHello,
    /// msg2's payload as the host passes it (the ticket is filled in).
    pub host_hello: HostHello,
    /// msg1, hex.
    pub msg1: String,
    /// msg2, hex.
    pub msg2: String,
    /// The final handshake hash.
    pub handshake_hash: String,
    /// The resume secret both ends derive.
    pub resume_secret: String,
    /// Records after the handshake.
    pub records: Vec<RecordCase>,
}

/// A handshake that must fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeRefusal {
    /// What it shows.
    pub name: String,
    /// The host's prologue (may differ from the one msg1 was made with).
    pub prologue: Prologue,
    /// The host's static secret.
    pub host_static_secret: String,
    /// The device static key the attestation names.
    pub expected_device_static: String,
    /// The host's ephemeral secret.
    pub host_ephemeral_secret: String,
    /// For a resume: the secret the host's ticket holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    /// msg1, hex.
    pub msg1: String,
    /// The code the host reports.
    pub code: String,
}

/// `handshake.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeFile {
    /// What the file is.
    pub description: String,
    /// Cases that complete.
    pub cases: Vec<HandshakeCase>,
    /// Cases the host refuses at msg1.
    pub refusals: Vec<HandshakeRefusal>,
}

fn verify_handshake_case(c: &HandshakeCase) -> Result<()> {
    let mismatch = |what: &'static str| ProtoError::InvalidInput(what);
    if to_hex(&c.prologue.to_bytes()?) != c.prologue_bytes {
        return Err(mismatch("prologue bytes"));
    }
    let dev = ShellKeypair::from_secret(hex32(&c.device_static_secret)?);
    let host = ShellKeypair::from_secret(hex32(&c.host_static_secret)?);
    let de = hex32(&c.device_ephemeral_secret)?;
    let he = hex32(&c.host_ephemeral_secret)?;
    let tid = from_hex(&c.ticket_id)?;
    let psk = c.psk.as_deref().map(hex32).transpose()?;

    let mut drng = ScriptedRng::new(&[&de]);
    let (ini, m1) = match (&psk, c.pattern.as_str()) {
        (None, "IK") => {
            InitiatorHandshake::start(&mut drng, &dev, host.public(), &c.prologue, &c.device_hello)?
        }
        (Some(k), "IKpsk2") => InitiatorHandshake::start_resume(
            &mut drng,
            &dev,
            host.public(),
            &c.prologue,
            k,
            &c.device_hello,
        )?,
        _ => return Err(mismatch("pattern")),
    };
    if to_hex(&m1) != c.msg1 {
        return Err(mismatch("msg1"));
    }
    let mut hrng = ScriptedRng::new(&[&he, &tid]);
    let (rsp, hello) = ResponderHandshake::read(
        &mut hrng,
        &host,
        &c.prologue,
        dev.public(),
        psk.as_ref(),
        &m1,
    )?;
    if hello != c.device_hello {
        return Err(mismatch("device hello"));
    }
    let (mut hch, ticket, m2) = rsp.respond(&mut hrng, c.host_hello.clone(), 0)?;
    if !hrng.exhausted() || to_hex(&ticket.0) != c.ticket_id {
        return Err(mismatch("ticket id"));
    }
    if to_hex(&m2) != c.msg2 {
        return Err(mismatch("msg2"));
    }
    let (mut dch, got) = ini.finish(&m2, 0)?;
    if ticket_from_hello(&got)? != ticket {
        return Err(mismatch("ticket in hello"));
    }
    for (ch, name) in [(&dch, "device"), (&hch, "host")] {
        if to_hex(ch.handshake_hash()) != c.handshake_hash {
            return Err(ProtoError::InvalidInput(if name == "device" {
                "device handshake hash"
            } else {
                "host handshake hash"
            }));
        }
        if to_hex(ch.resume_secret()) != c.resume_secret {
            return Err(mismatch("resume secret"));
        }
    }
    for r in &c.records {
        let pt = from_hex(&r.plaintext)?;
        let (tx, rx) = match r.from.as_str() {
            "device" => (&mut dch, &mut hch),
            "host" => (&mut hch, &mut dch),
            _ => return Err(mismatch("record sender")),
        };
        let rec = tx.seal(&pt, 0)?;
        if to_hex(&rec) != r.record {
            return Err(mismatch("record bytes"));
        }
        if rx.open(&rec)?.1 != pt {
            return Err(mismatch("record plaintext"));
        }
    }
    Ok(())
}

fn verify_refusal(r: &HandshakeRefusal) -> Result<()> {
    let host = ShellKeypair::from_secret(hex32(&r.host_static_secret)?);
    let he = hex32(&r.host_ephemeral_secret)?;
    let psk = r.psk.as_deref().map(hex32).transpose()?;
    let mut rng = ScriptedRng::new(&[&he]);
    match ResponderHandshake::read(
        &mut rng,
        &host,
        &r.prologue,
        &hex32(&r.expected_device_static)?,
        psk.as_ref(),
        &from_hex(&r.msg1)?,
    ) {
        Ok(_) => Err(ProtoError::InvalidInput("a refusal vector was accepted")),
        Err(e) if e.code() == r.code => Ok(()),
        Err(_) => Err(ProtoError::InvalidInput("refused with another code")),
    }
}

// ---------------------------------------------------------------------------
// Records

/// One sealed record under a stated key and nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealCase {
    /// The key.
    pub key: String,
    /// The nonce.
    pub nonce: u64,
    /// Plaintext.
    pub plaintext: String,
    /// `n (u64 BE) ‖ ciphertext`.
    pub record: String,
}

/// One application of Noise `REKEY`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RekeyCase {
    /// The key before.
    pub key: String,
    /// `REKEY(key)`.
    pub next: String,
}

/// A receiver fed records in a stated order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowCase {
    /// What it shows.
    pub name: String,
    /// The receiver's initial key.
    pub key: String,
    /// `(nonce, key generation)` of each record, in arrival order; the
    /// generation is how many times `REKEY` was applied to the key.
    pub arrivals: Vec<(u64, u32)>,
    /// When to call `note_peer_rekey(n)`: before arrival `i`.
    #[serde(default)]
    pub announcements: Vec<(usize, u64)>,
    /// `ok`, or the error code, per arrival.
    pub expect: Vec<String>,
}

/// `records.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordFile {
    /// What the file is.
    pub description: String,
    /// Seal cases.
    pub seal: Vec<SealCase>,
    /// Rekey cases.
    pub rekey: Vec<RekeyCase>,
    /// Replay window and rekey ordering cases.
    pub window: Vec<WindowCase>,
}

fn verify_records(f: &RecordFile) -> Result<usize> {
    let mismatch = ProtoError::InvalidInput;
    for c in &f.seal {
        let key = hex32(&c.key)?;
        let mut rec = c.nonce.to_be_bytes().to_vec();
        rec.extend(noise_encrypt(&key, c.nonce, &[], &from_hex(&c.plaintext)?));
        if to_hex(&rec) != c.record {
            return Err(mismatch("seal record"));
        }
        let mut r = RecvState::new(key);
        if to_hex(&r.open(&rec)?.1) != c.plaintext {
            return Err(mismatch("seal plaintext"));
        }
    }
    for c in &f.rekey {
        if to_hex(&rekey(&hex32(&c.key)?)[..]) != c.next {
            return Err(mismatch("rekey"));
        }
    }
    for c in &f.window {
        let base = hex32(&c.key)?;
        let mut r = RecvState::new(base);
        if c.arrivals.len() != c.expect.len() {
            return Err(mismatch("window case shape"));
        }
        for (i, ((n, generation), want)) in c.arrivals.iter().zip(&c.expect).enumerate() {
            for (at, switch) in &c.announcements {
                if *at == i {
                    r.note_peer_rekey(*switch);
                }
            }
            let mut k = zeroize::Zeroizing::new(base);
            for _ in 0..*generation {
                k = rekey(&k);
            }
            let mut rec = n.to_be_bytes().to_vec();
            rec.extend(noise_encrypt(&k, *n, &[], b"w"));
            let got = match r.open(&rec) {
                Ok(_) => "ok".to_owned(),
                Err(ProtoError::Replay) => "replay".to_owned(),
                Err(ProtoError::RecordAuth) => "auth".to_owned(),
                Err(e) => e.code().to_owned(),
            };
            if &got != want {
                return Err(mismatch("window outcome"));
            }
        }
    }
    Ok(f.seal.len() + f.rekey.len() + f.window.len())
}

// ---------------------------------------------------------------------------
// Presence

/// An unlock signature to verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockCase {
    /// What it shows.
    pub name: String,
    /// The presence key, SEC1 hex.
    pub presence_public: String,
    /// The handshake hash the host holds.
    pub handshake_hash: String,
    /// The action the host expects.
    pub action: Action,
    /// The DER signature, hex.
    pub sig: String,
    /// `ok` or the error code.
    pub expect: String,
}

/// A device-key statement, the device kind the host verified, and what the
/// host must demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeysCase {
    /// What it shows.
    pub name: String,
    /// The statement.
    pub keys: DeviceKeys,
    /// Its signed bytes, hex.
    pub signed_bytes: String,
    /// The Ed25519 signature, hex.
    pub sig: String,
    /// The kind from the delegation or introduction.
    pub verified_kind: String,
    /// `unlock`, `not_required`, or the error code.
    pub expect: String,
}

/// `presence.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceFile {
    /// What the file is.
    pub description: String,
    /// Unlock signatures.
    pub unlock: Vec<UnlockCase>,
    /// Device-key statements and the presence rule.
    pub device_keys: Vec<DeviceKeysCase>,
}

fn verify_presence_file(f: &PresenceFile) -> Result<usize> {
    let mismatch = ProtoError::InvalidInput;
    for c in &f.unlock {
        let got = match verify_presence(
            &from_hex(&c.presence_public)?,
            &hex32(&c.handshake_hash)?,
            c.action,
            &from_hex(&c.sig)?,
        ) {
            Ok(()) => "ok".to_owned(),
            Err(e) => e.code().to_owned(),
        };
        if got != c.expect {
            return Err(mismatch("unlock outcome"));
        }
    }
    for c in &f.device_keys {
        if to_hex(&c.keys.signed_bytes()?) != c.signed_bytes {
            return Err(mismatch("device keys signed bytes"));
        }
        let got = match c
            .keys
            .verify(&from_hex(&c.sig)?)
            .and_then(|()| presence_rule(&c.keys, &c.verified_kind))
        {
            Ok(PresenceRequirement::Unlock(_)) => "unlock".to_owned(),
            Ok(PresenceRequirement::NotRequired) => "not_required".to_owned(),
            Err(e) => e.code().to_owned(),
        };
        if got != c.expect {
            return Err(mismatch("device keys outcome"));
        }
    }
    Ok(f.unlock.len() + f.device_keys.len())
}

// ---------------------------------------------------------------------------
// Recordings

/// A recipient in a recording vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingRecipient {
    /// The device id.
    pub device: String,
    /// Its X25519 secret (so the verifier can open the segment).
    pub secret: String,
}

/// One segment, written from a seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingCase {
    /// What it shows.
    pub name: String,
    /// The [`DetRng`] seed, hex.
    pub seed: String,
    /// The session.
    pub session: String,
    /// The segment number.
    pub segment: u32,
    /// Who it is wrapped to.
    pub recipients: Vec<RecordingRecipient>,
    /// A device that must not open it, with its secret.
    pub outsider: RecordingRecipient,
    /// Chunk plaintexts, hex; the last is sealed as final.
    pub chunks: Vec<String>,
    /// The whole file, hex.
    pub file: String,
}

/// `recording.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingFile {
    /// What the file is.
    pub description: String,
    /// Segments.
    pub cases: Vec<RecordingCase>,
}

/// Write a recording case's file from its inputs. Shared by the verifier
/// and the generator, so the two cannot drift.
pub fn write_recording(c: &RecordingCase) -> Result<Vec<u8>> {
    let mut rng = DetRng::new(&from_hex(&c.seed)?);
    let recipients = c
        .recipients
        .iter()
        .map(|r| {
            Ok(Recipient {
                device: r.device.clone(),
                public: *ShellKeypair::from_secret(hex32(&r.secret)?).public(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut w = SegmentWriter::start(&mut rng, &c.session, c.segment, &recipients)?;
    let mut file = w.header().to_bytes()?;
    let (last, rest) = c
        .chunks
        .split_last()
        .ok_or(ProtoError::InvalidInput("no chunks"))?;
    for ch in rest {
        file.extend(w.seal_chunk(&mut rng, &from_hex(ch)?)?);
    }
    file.extend(w.finish(&mut rng, &from_hex(last)?)?);
    Ok(file)
}

fn verify_recordings(f: &RecordingFile) -> Result<usize> {
    let mismatch = ProtoError::InvalidInput;
    for c in &f.cases {
        let file = write_recording(c)?;
        if to_hex(&file) != c.file {
            return Err(mismatch("recording file"));
        }
        let want: Vec<u8> = c
            .chunks
            .iter()
            .map(|h| from_hex(h))
            .collect::<Result<Vec<_>>>()?
            .concat();
        for r in &c.recipients {
            let got = SegmentReader::read_file(&file, &r.device, &hex32(&r.secret)?)?;
            if got.data != want || !got.complete {
                return Err(mismatch("recording plaintext"));
            }
        }
        if SegmentReader::read_file(&file, &c.outsider.device, &hex32(&c.outsider.secret)?).is_ok()
        {
            return Err(mismatch("an outsider opened the recording"));
        }
        SegmentHeader::parse(&file)?;
    }
    Ok(f.cases.len())
}

// ---------------------------------------------------------------------------
// Inner messages

/// One message in both forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InnerCase {
    /// The JSON form.
    pub message: Message,
    /// The wire bytes, hex.
    pub bytes: String,
}

/// `inner.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InnerFile {
    /// What the file is.
    pub description: String,
    /// The type byte of every message name.
    pub types: Vec<(u8, String)>,
    /// Messages.
    pub cases: Vec<InnerCase>,
    /// Byte strings that must not decode, hex.
    pub malformed: Vec<String>,
}

fn verify_inner(f: &InnerFile) -> Result<usize> {
    let mismatch = ProtoError::InvalidInput;
    let table: Vec<(u8, String)> = crate::inner::TYPE_TABLE
        .iter()
        .map(|(b, n)| (*b, (*n).to_owned()))
        .collect();
    if table != f.types {
        return Err(mismatch("type table"));
    }
    for c in &f.cases {
        if to_hex(&c.message.encode()?) != c.bytes {
            return Err(mismatch("inner encode"));
        }
        if Message::decode_all(&from_hex(&c.bytes)?)? != vec![c.message.clone()] {
            return Err(mismatch("inner decode"));
        }
    }
    for m in &f.malformed {
        if Message::decode_all(&from_hex(m)?).is_ok() {
            return Err(mismatch("malformed message decoded"));
        }
    }
    Ok(f.cases.len() + f.malformed.len())
}

/// `structured.json`: the neutral event model (design §9.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuredFile {
    /// The schema id, [`crate::structured::SCHEMA_ID`].
    pub schema: String,
    /// What the file is.
    pub description: String,
    /// Bodies in their canonical JSON: each decodes, and encodes back to
    /// exactly itself.
    pub bodies: Vec<serde_json::Value>,
    /// Bodies that must not decode.
    pub invalid: Vec<serde_json::Value>,
    /// Bodies a newer writer might send: each carries a field v1 does not
    /// know, and each decodes, the unknown field ignored. Not v1 bodies, so
    /// they do not re-encode to themselves (the crate's "Wire
    /// compatibility").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerated: Vec<serde_json::Value>,
}

fn verify_structured(f: &StructuredFile) -> Result<usize> {
    use crate::structured::{Body, SCHEMA_ID};
    let mismatch = ProtoError::InvalidInput;
    if f.schema != SCHEMA_ID {
        return Err(mismatch("structured schema id"));
    }
    for b in &f.bodies {
        if Body::from_value(b)?.to_value() != *b {
            return Err(mismatch("structured round trip"));
        }
    }
    for b in &f.invalid {
        if Body::from_value(b).is_ok() {
            return Err(mismatch("invalid structured body decoded"));
        }
    }
    for b in &f.tolerated {
        if Body::from_value(b).is_err() {
            return Err(mismatch("tolerated structured body refused"));
        }
    }
    Ok(f.bodies.len() + f.invalid.len() + f.tolerated.len())
}

// ---------------------------------------------------------------------------

/// Verify one vector file, whichever kind it is (told apart by its keys).
/// Returns how many cases it checked.
pub fn verify(file_json: &[u8]) -> Result<usize> {
    let v: serde_json::Value =
        serde_json::from_slice(file_json).map_err(|_| ProtoError::InvalidInput("vector JSON"))?;
    let has = |k: &str| v.get(k).is_some();
    let parse_err = |_| ProtoError::InvalidInput("vector shape");
    if has("refusals") {
        let f: HandshakeFile = serde_json::from_value(v).map_err(parse_err)?;
        for c in &f.cases {
            verify_handshake_case(c)?;
        }
        for r in &f.refusals {
            verify_refusal(r)?;
        }
        Ok(f.cases.len() + f.refusals.len())
    } else if has("window") {
        verify_records(&serde_json::from_value(v).map_err(parse_err)?)
    } else if has("unlock") {
        verify_presence_file(&serde_json::from_value(v).map_err(parse_err)?)
    } else if has("schema") {
        verify_structured(&serde_json::from_value(v).map_err(parse_err)?)
    } else if has("types") {
        verify_inner(&serde_json::from_value(v).map_err(parse_err)?)
    } else if has("cases") {
        verify_recordings(&serde_json::from_value(v).map_err(parse_err)?)
    } else {
        Err(ProtoError::InvalidInput("unknown vector file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(
            from_hex(&to_hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn det_rng_is_deterministic() {
        let mut a = DetRng::new(b"x");
        let mut b = DetRng::new(b"x");
        let (mut x, mut y) = ([0u8; 70], [0u8; 70]);
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);
        assert_ne!(x[..32], x[32..64]);
    }
}
