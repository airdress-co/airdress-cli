//! Noise `IK` for an open or a reattach, `IKpsk2` for a resume (design §6.5).
//!
//! The device is the initiator and knows the host's static key from the
//! pinned status. One round trip:
//!
//! 1. device → host, msg1, payload [`DeviceHello`] `{device, cols, rows,
//!    clientVersion}` (a resume sends `{device}` only);
//! 2. host → device, msg2, payload [`HostHello`] `{hostVersion, profileHash,
//!    resumeTicket}` (a resume sends `{resumeTicket}` only).
//!
//! Both ends then hold a [`Channel`]: one key per direction for the record
//! layer, the final handshake hash (what an unlock signs), and a 32-byte
//! resume secret, the pre-shared key of the next resume.
//!
//! **The resume secret** is `HKDF-SHA256(salt = handshake_hash, ikm = k_i2r ‖
//! k_r2i, info = "airdress.shell.resume.v1")`. The design wrote
//! `HKDF(handshake_hash, …)`; the handshake hash alone is computable by
//! anyone who saw the handshake, the operator included, so the secret is
//! taken from the split keys and the hash is the salt. DESIGN-NOTES.md N-1.
//!
//! **Randomness** comes from the caller: each handshake draws exactly one
//! 32-byte ephemeral secret from the RNG it is given. snow is handed a
//! resolver whose RNG yields those 32 bytes and nothing else, so the crate
//! needs no entropy source of its own (the wasm build) and a vector can fix
//! the ephemeral.

use core::cell::RefCell;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use snow::HandshakeState;
use zeroize::Zeroizing;

use crate::error::{ProtoError, Result};
use crate::keys::{ShellKeypair, KEY_LEN};
use crate::prologue::{Action, Prologue};
use crate::record::{RecvState, SendState};
use crate::ticket::{TicketId, TICKET_ID_LEN};

/// The open and reattach handshake.
pub const PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// The resume handshake.
pub const PATTERN_IKPSK2: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// HKDF info for the resume secret.
pub const RESUME_LABEL: &[u8] = b"airdress.shell.resume.v1";
/// The largest handshake payload either side accepts.
pub const MAX_HANDSHAKE_PAYLOAD: usize = 4096;
/// Noise's message size bound.
const NOISE_MAX: usize = 65535;

/// msg1's payload.
///
/// Open to unknown fields: a newer device may say more than this host reads
/// (see the crate's "Wire compatibility"). A new field is `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHello {
    /// The device id (the enrollment).
    pub device: String,
    /// Terminal columns at open or attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    /// Terminal rows at open or attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    /// The client's version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

/// msg2's payload.
///
/// Open to unknown fields, like [`DeviceHello`]. A new field is `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostHello {
    /// The host's version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_version: Option<String>,
    /// A hash of the profile the session runs, so a client can tell that a
    /// profile changed under a running session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_hash: Option<String>,
    /// The id of the ticket for the next resume, base64. Filled in by
    /// [`ResponderHandshake::respond`]; whatever the caller put here is
    /// replaced.
    #[serde(default)]
    pub resume_ticket: String,
}

/// Which end of the channel this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The device.
    Initiator,
    /// The host.
    Responder,
}

/// One end of an established E2E channel.
pub struct Channel {
    role: Role,
    send: SendState,
    recv: RecvState,
    handshake_hash: [u8; 32],
    resume_secret: Zeroizing<[u8; 32]>,
    peer_static: [u8; KEY_LEN],
}

impl Channel {
    fn from_split(
        hs: &mut HandshakeState,
        role: Role,
        peer_static: [u8; KEY_LEN],
        now_ms: u64,
    ) -> Result<Self> {
        if !hs.is_handshake_finished() {
            return Err(ProtoError::Handshake("handshake not finished"));
        }
        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(hs.get_handshake_hash());
        let (k1, k2) = hs.dangerously_get_raw_split();
        let (k1, k2) = (Zeroizing::new(k1), Zeroizing::new(k2));
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(&k1[..]);
        ikm[32..].copy_from_slice(&k2[..]);
        let mut resume_secret = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&handshake_hash), &ikm[..])
            .expand(RESUME_LABEL, &mut resume_secret[..])
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let (send_key, recv_key) = match role {
            Role::Initiator => (*k1, *k2),
            Role::Responder => (*k2, *k1),
        };
        Ok(Self {
            role,
            send: SendState::new(send_key, now_ms),
            recv: RecvState::new(recv_key),
            handshake_hash,
            resume_secret,
            peer_static,
        })
    }

    /// Seal one record.
    pub fn seal(&mut self, plaintext: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.send.seal(plaintext, now_ms)
    }

    /// Open one record. Returns the nonce and the plaintext.
    pub fn open(&mut self, record: &[u8]) -> Result<(u64, Vec<u8>)> {
        self.recv.open(record)
    }

    /// Whether this end's sending direction is due a rekey (an hour or
    /// 1 GiB under one key).
    pub fn rekey_due(&self, now_ms: u64) -> bool {
        self.send.rekey_due(now_ms)
    }

    /// Arrange a rekey of the sending direction and return the switch-over
    /// nonce. The very next record sealed must be the inner `rekey` message
    /// announcing it; [`crate::inner::seal_rekey`] does both.
    pub fn schedule_rekey(&mut self) -> u64 {
        self.send.schedule_rekey()
    }

    /// The peer announced that its sending key changes at `switch_at`.
    pub fn note_peer_rekey(&mut self, switch_at: u64) {
        self.recv.note_peer_rekey(switch_at)
    }

    /// The final handshake hash: what a presence signature covers.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// The pre-shared key of the next resume. Keep it in memory only.
    pub fn resume_secret(&self) -> &[u8; 32] {
        &self.resume_secret
    }

    /// The peer's static key, as the handshake authenticated it.
    pub fn peer_static(&self) -> &[u8; KEY_LEN] {
        &self.peer_static
    }

    /// Initiator or responder.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The nonce of the next record this end will send.
    pub fn next_send_nonce(&self) -> u64 {
        self.send.next_nonce()
    }

    /// How many receive-key generations are held.
    pub fn recv_generations(&self) -> usize {
        self.recv.generations()
    }
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("next_send_nonce", &self.send.next_nonce())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// snow plumbing: a resolver whose RNG yields one ephemeral from the caller.

struct OneEphemeral(Option<Zeroizing<[u8; 32]>>);

impl Random for OneEphemeral {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), snow::Error> {
        match self.0.take() {
            Some(e) if dest.len() == 32 => {
                dest.copy_from_slice(&e[..]);
                Ok(())
            }
            _ => Err(snow::Error::Rng),
        }
    }
}

struct ShellResolver {
    ephemeral: RefCell<Option<Zeroizing<[u8; 32]>>>,
    inner: DefaultResolver,
}

impl CryptoResolver for ShellResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(OneEphemeral(self.ephemeral.borrow_mut().take())))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.inner.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.inner.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.inner.resolve_cipher(choice)
    }
}

fn resolver<R: RngCore + CryptoRng>(rng: &mut R) -> BoxedCryptoResolver {
    let mut e = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut e[..]);
    Box::new(ShellResolver {
        ephemeral: RefCell::new(Some(e)),
        inner: DefaultResolver,
    })
}

#[cfg(test)]
pub(crate) fn test_resolver() -> impl Fn() -> BoxedCryptoResolver {
    || {
        Box::new(ShellResolver {
            ephemeral: RefCell::new(Some(Zeroizing::new([0x42; 32]))),
            inner: DefaultResolver,
        })
    }
}

fn snow_err(e: snow::Error) -> ProtoError {
    match e {
        snow::Error::Decrypt => ProtoError::Handshake("decrypt"),
        snow::Error::Rng => ProtoError::Rng,
        _ => ProtoError::Handshake("noise"),
    }
}

fn builder<'a>(
    pattern: &str,
    rng_resolver: BoxedCryptoResolver,
    local: &'a ShellKeypair,
    prologue: &'a [u8],
) -> Result<snow::Builder<'a>> {
    let params = pattern
        .parse()
        .map_err(|_| ProtoError::Handshake("pattern"))?;
    snow::Builder::with_resolver(params, rng_resolver)
        .local_private_key(local.secret())
        .map_err(snow_err)?
        .prologue(prologue)
        .map_err(snow_err)
}

fn payload_json<T: Serialize>(p: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_vec(p).map_err(|_| ProtoError::InvalidInput("payload"))?;
    if v.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(ProtoError::InvalidInput("handshake payload too large"));
    }
    Ok(v)
}

fn write(hs: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; NOISE_MAX];
    let n = hs.write_message(payload, &mut buf).map_err(snow_err)?;
    buf.truncate(n);
    Ok(buf)
}

fn read(hs: &mut HandshakeState, msg: &[u8]) -> Result<Vec<u8>> {
    if msg.len() > NOISE_MAX {
        return Err(ProtoError::Handshake("message too large"));
    }
    let mut buf = vec![0u8; NOISE_MAX];
    let n = hs.read_message(msg, &mut buf).map_err(snow_err)?;
    buf.truncate(n);
    if buf.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(ProtoError::Handshake("payload too large"));
    }
    Ok(buf)
}

/// The device's half of a handshake in flight.
pub struct InitiatorHandshake {
    hs: HandshakeState,
    remote: [u8; KEY_LEN],
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorHandshake").finish_non_exhaustive()
    }
}

impl InitiatorHandshake {
    /// Start an `IK` handshake for an open or an attach. Returns msg1.
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        local: &ShellKeypair,
        host_static: &[u8; KEY_LEN],
        prologue: &Prologue,
        hello: &DeviceHello,
    ) -> Result<(Self, Vec<u8>)> {
        if prologue.action == Action::Resume {
            return Err(ProtoError::InvalidInput("a resume uses start_resume"));
        }
        let pro = prologue.to_bytes()?;
        let mut hs = builder(PATTERN_IK, resolver(rng), local, &pro)?
            .remote_public_key(host_static)
            .map_err(snow_err)?
            .build_initiator()
            .map_err(snow_err)?;
        let msg1 = write(&mut hs, &payload_json(hello)?)?;
        Ok((
            Self {
                hs,
                remote: *host_static,
            },
            msg1,
        ))
    }

    /// Start an `IKpsk2` resume with the previous channel's resume secret.
    /// Returns msg1; the ticket id travels beside it in the clear.
    pub fn start_resume<R: RngCore + CryptoRng>(
        rng: &mut R,
        local: &ShellKeypair,
        host_static: &[u8; KEY_LEN],
        prologue: &Prologue,
        resume_secret: &[u8; 32],
        hello: &DeviceHello,
    ) -> Result<(Self, Vec<u8>)> {
        if prologue.action != Action::Resume {
            return Err(ProtoError::InvalidInput(
                "start_resume needs the resume action",
            ));
        }
        let pro = prologue.to_bytes()?;
        let mut hs = builder(PATTERN_IKPSK2, resolver(rng), local, &pro)?
            .remote_public_key(host_static)
            .map_err(snow_err)?
            .psk(2, resume_secret)
            .map_err(snow_err)?
            .build_initiator()
            .map_err(snow_err)?;
        let msg1 = write(&mut hs, &payload_json(hello)?)?;
        Ok((
            Self {
                hs,
                remote: *host_static,
            },
            msg1,
        ))
    }

    /// Read msg2 and establish the channel.
    pub fn finish(mut self, msg2: &[u8], now_ms: u64) -> Result<(Channel, HostHello)> {
        let payload = read(&mut self.hs, msg2)?;
        let hello: HostHello =
            serde_json::from_slice(&payload).map_err(|_| ProtoError::Handshake("host payload"))?;
        let ch = Channel::from_split(&mut self.hs, Role::Initiator, self.remote, now_ms)?;
        Ok((ch, hello))
    }
}

/// The host's half of a handshake in flight: msg1 read, msg2 not yet sent.
pub struct ResponderHandshake {
    hs: HandshakeState,
    remote: [u8; KEY_LEN],
}

impl std::fmt::Debug for ResponderHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderHandshake").finish_non_exhaustive()
    }
}

impl ResponderHandshake {
    /// Read msg1.
    ///
    /// `expected_device_static` is the `dhPublic` from the attestation the
    /// host has already checked (design §6.3 steps 1–6); a handshake from
    /// any other static key is refused (step 7). `resume_secret` is the
    /// redeemed ticket's secret for a resume, and `None` otherwise; it must
    /// agree with the prologue's action.
    pub fn read<R: RngCore + CryptoRng>(
        rng: &mut R,
        local: &ShellKeypair,
        prologue: &Prologue,
        expected_device_static: &[u8; KEY_LEN],
        resume_secret: Option<&[u8; 32]>,
        msg1: &[u8],
    ) -> Result<(Self, DeviceHello)> {
        let pro = prologue.to_bytes()?;
        let mut hs = match (prologue.action, resume_secret) {
            (Action::Resume, Some(psk)) => builder(PATTERN_IKPSK2, resolver(rng), local, &pro)?
                .psk(2, psk)
                .map_err(snow_err)?
                .build_responder()
                .map_err(snow_err)?,
            (Action::Resume, None) => {
                return Err(ProtoError::ResumeExpired);
            }
            (_, None) => builder(PATTERN_IK, resolver(rng), local, &pro)?
                .build_responder()
                .map_err(snow_err)?,
            (_, Some(_)) => {
                return Err(ProtoError::InvalidInput("only a resume carries a secret"));
            }
        };
        let payload = read(&mut hs, msg1)?;
        let remote: [u8; KEY_LEN] = hs
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(ProtoError::Handshake("no remote static"))?;
        if &remote != expected_device_static {
            return Err(ProtoError::UnexpectedRemoteKey);
        }
        let hello: DeviceHello = serde_json::from_slice(&payload)
            .map_err(|_| ProtoError::Handshake("device payload"))?;
        Ok((Self { hs, remote }, hello))
    }

    /// The device's static key, as msg1 authenticated it.
    pub fn remote_static(&self) -> &[u8; KEY_LEN] {
        &self.remote
    }

    /// Write msg2 with a fresh ticket id, and establish the channel.
    /// Returns the channel, the ticket to file in the host's
    /// [`crate::ticket::TicketBook`], and msg2.
    pub fn respond<R: RngCore + CryptoRng>(
        mut self,
        rng: &mut R,
        mut hello: HostHello,
        now_ms: u64,
    ) -> Result<(Channel, TicketId, Vec<u8>)> {
        let mut id = [0u8; TICKET_ID_LEN];
        rng.fill_bytes(&mut id);
        let ticket = TicketId(id);
        hello.resume_ticket = ticket.encode();
        let msg2 = write(&mut self.hs, &payload_json(&hello)?)?;
        let ch = Channel::from_split(&mut self.hs, Role::Responder, self.remote, now_ms)?;
        Ok((ch, ticket, msg2))
    }
}

/// Decode the ticket id a [`HostHello`] carries.
pub fn ticket_from_hello(hello: &HostHello) -> Result<TicketId> {
    let raw = STANDARD
        .decode(&hello.resume_ticket)
        .map_err(|_| ProtoError::Handshake("ticket id"))?;
    let id: [u8; TICKET_ID_LEN] = raw
        .try_into()
        .map_err(|_| ProtoError::Handshake("ticket id length"))?;
    Ok(TicketId(id))
}

/// Entry points for the fuzz targets (`fuzz/`), compiled only under
/// `--cfg fuzzing`: they drive a real Noise handshake whose payloads are
/// arbitrary bytes, which the public API (typed hellos) cannot produce, so
/// the payload decode is reached through an authenticated message.
#[cfg(fuzzing)]
pub mod fuzzing {
    use super::*;

    /// An `IK` open whose msg1 carries `device_payload` and whose msg2
    /// carries `host_payload`, both as given. Returns what each side read,
    /// as far as it got.
    pub fn exchange<R: RngCore + CryptoRng>(
        rng: &mut R,
        device_payload: &[u8],
        host_payload: &[u8],
    ) -> (Result<DeviceHello>, Option<Result<HostHello>>) {
        let dev = ShellKeypair::generate(rng);
        let host = ShellKeypair::generate(rng);
        let pro = Prologue {
            airdress: "a".into(),
            machine_id: "m".into(),
            session_id: "s".into(),
            profile_id: "p".into(),
            action: Action::Open,
        };
        let pro_bytes = pro.to_bytes().expect("a fixed prologue encodes");
        let mut hs = builder(PATTERN_IK, resolver(rng), &dev, &pro_bytes)
            .and_then(|b| b.remote_public_key(host.public()).map_err(snow_err))
            .and_then(|b| b.build_initiator().map_err(snow_err))
            .expect("a fixed IK initiator builds");
        let m1 = match write(&mut hs, device_payload) {
            Ok(m) => m,
            Err(e) => return (Err(e), None),
        };
        let ini = InitiatorHandshake {
            hs,
            remote: *host.public(),
        };
        let (mut rsp, hello) =
            match ResponderHandshake::read(rng, &host, &pro, dev.public(), None, &m1) {
                Ok(r) => r,
                Err(e) => return (Err(e), None),
            };
        let m2 = match write(&mut rsp.hs, host_payload) {
            Ok(m) => m,
            Err(e) => return (Ok(hello), Some(Err(e))),
        };
        let hch = Channel::from_split(&mut rsp.hs, Role::Responder, rsp.remote, 0)
            .expect("the responder finished");
        let got = ini.finish(&m2, 0).map(|(dch, hh)| {
            assert_eq!(dch.handshake_hash(), hch.handshake_hash());
            hh
        });
        (Ok(hello), Some(got))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn prologue(action: Action) -> Prologue {
        Prologue {
            airdress: "a".into(),
            machine_id: "m".into(),
            session_id: "s".into(),
            profile_id: "p".into(),
            action,
        }
    }

    fn hello() -> DeviceHello {
        DeviceHello {
            device: "d1".into(),
            cols: Some(80),
            rows: Some(24),
            client_version: Some("t".into()),
        }
    }

    fn open_pair() -> (Channel, Channel, TicketId) {
        let dev = ShellKeypair::generate(&mut OsRng);
        let host = ShellKeypair::generate(&mut OsRng);
        let pro = prologue(Action::Open);
        let (ini, m1) =
            InitiatorHandshake::start(&mut OsRng, &dev, host.public(), &pro, &hello()).unwrap();
        let (rsp, got) =
            ResponderHandshake::read(&mut OsRng, &host, &pro, dev.public(), None, &m1).unwrap();
        assert_eq!(got, hello());
        let (hch, tid, m2) = rsp
            .respond(
                &mut OsRng,
                HostHello {
                    host_version: Some("h".into()),
                    profile_hash: None,
                    resume_ticket: String::new(),
                },
                0,
            )
            .unwrap();
        let (dch, hh) = ini.finish(&m2, 0).unwrap();
        assert_eq!(ticket_from_hello(&hh).unwrap(), tid);
        (dch, hch, tid)
    }

    /// Both hellos are open: an older host reads a newer device's msg1, and
    /// an older device reads a newer host's msg2, each ignoring the field it
    /// does not know. The handshake still binds the bytes as sent.
    #[test]
    fn hellos_ignore_a_newer_peers_fields() {
        let dev = ShellKeypair::generate(&mut OsRng);
        let host = ShellKeypair::generate(&mut OsRng);
        let pro = prologue(Action::Open);
        let pro_bytes = pro.to_bytes().unwrap();

        let mut newer_device = serde_json::to_value(hello()).unwrap();
        newer_device["futureField"] = serde_json::json!({"nested": [1, 2]});
        let mut hs = builder(PATTERN_IK, resolver(&mut OsRng), &dev, &pro_bytes)
            .unwrap()
            .remote_public_key(host.public())
            .unwrap()
            .build_initiator()
            .unwrap();
        let m1 = write(&mut hs, &serde_json::to_vec(&newer_device).unwrap()).unwrap();
        let ini = InitiatorHandshake {
            hs,
            remote: *host.public(),
        };
        let (mut rsp, got) =
            ResponderHandshake::read(&mut OsRng, &host, &pro, dev.public(), None, &m1).unwrap();
        assert_eq!(got, hello());

        let newer_host = serde_json::json!({
            "hostVersion": "h2",
            "resumeTicket": STANDARD.encode([7u8; TICKET_ID_LEN]),
            "capabilities": ["future"],
        });
        let m2 = write(&mut rsp.hs, &serde_json::to_vec(&newer_host).unwrap()).unwrap();
        let hch = Channel::from_split(&mut rsp.hs, Role::Responder, rsp.remote, 0).unwrap();
        let (dch, hh) = ini.finish(&m2, 0).unwrap();
        assert_eq!(hh.host_version.as_deref(), Some("h2"));
        assert_eq!(
            ticket_from_hello(&hh).unwrap(),
            TicketId([7u8; TICKET_ID_LEN])
        );
        assert_eq!(dch.handshake_hash(), hch.handshake_hash());
    }

    #[test]
    fn ik_establishes_matching_channels() {
        let (mut d, mut h, _) = open_pair();
        assert_eq!(d.handshake_hash(), h.handshake_hash());
        assert_eq!(d.resume_secret(), h.resume_secret());
        let r = d.seal(b"ls\n", 0).unwrap();
        assert_eq!(h.open(&r).unwrap().1, b"ls\n");
        let r = h.seal(b"out", 0).unwrap();
        assert_eq!(d.open(&r).unwrap().1, b"out");
    }

    #[test]
    fn a_different_device_key_is_refused() {
        let dev = ShellKeypair::generate(&mut OsRng);
        let other = ShellKeypair::generate(&mut OsRng);
        let host = ShellKeypair::generate(&mut OsRng);
        let pro = prologue(Action::Open);
        let (_, m1) =
            InitiatorHandshake::start(&mut OsRng, &dev, host.public(), &pro, &hello()).unwrap();
        let err = ResponderHandshake::read(&mut OsRng, &host, &pro, other.public(), None, &m1)
            .err()
            .unwrap();
        assert_eq!(err, ProtoError::UnexpectedRemoteKey);
    }

    #[test]
    fn a_different_prologue_fails() {
        let dev = ShellKeypair::generate(&mut OsRng);
        let host = ShellKeypair::generate(&mut OsRng);
        let (_, m1) = InitiatorHandshake::start(
            &mut OsRng,
            &dev,
            host.public(),
            &prologue(Action::Open),
            &hello(),
        )
        .unwrap();
        let err = ResponderHandshake::read(
            &mut OsRng,
            &host,
            &prologue(Action::Attach),
            dev.public(),
            None,
            &m1,
        )
        .err()
        .unwrap();
        assert_eq!(err.code(), "shell_handshake_failed");
    }

    #[test]
    fn resume_with_the_secret_and_not_without() {
        let dev = ShellKeypair::generate(&mut OsRng);
        let host = ShellKeypair::generate(&mut OsRng);
        let pro = prologue(Action::Open);
        let (ini, m1) =
            InitiatorHandshake::start(&mut OsRng, &dev, host.public(), &pro, &hello()).unwrap();
        let (rsp, _) =
            ResponderHandshake::read(&mut OsRng, &host, &pro, dev.public(), None, &m1).unwrap();
        let (h1, _, m2) = rsp
            .respond(
                &mut OsRng,
                HostHello {
                    host_version: None,
                    profile_hash: None,
                    resume_ticket: String::new(),
                },
                0,
            )
            .unwrap();
        let (d1, _) = ini.finish(&m2, 0).unwrap();

        let rp = prologue(Action::Resume);
        let rh = DeviceHello {
            device: "d1".into(),
            cols: None,
            rows: None,
            client_version: None,
        };
        let (ini, m1) = InitiatorHandshake::start_resume(
            &mut OsRng,
            &dev,
            host.public(),
            &rp,
            d1.resume_secret(),
            &rh,
        )
        .unwrap();
        // psk2 mixes the secret into msg2, so a host holding the wrong
        // secret reads msg1 and the device then refuses its msg2.
        let (wrong, _) =
            ResponderHandshake::read(&mut OsRng, &host, &rp, dev.public(), Some(&[0u8; 32]), &m1)
                .unwrap();
        let (_, _, bad_m2) = wrong
            .respond(
                &mut OsRng,
                HostHello {
                    host_version: None,
                    profile_hash: None,
                    resume_ticket: String::new(),
                },
                0,
            )
            .unwrap();
        let (ini_again, _) = InitiatorHandshake::start_resume(
            &mut OsRng,
            &dev,
            host.public(),
            &rp,
            d1.resume_secret(),
            &rh,
        )
        .unwrap();
        assert!(ini_again.finish(&bad_m2, 0).is_err());
        let (rsp, _) = ResponderHandshake::read(
            &mut OsRng,
            &host,
            &rp,
            dev.public(),
            Some(h1.resume_secret()),
            &m1,
        )
        .unwrap();
        let (h2, _, m2) = rsp
            .respond(
                &mut OsRng,
                HostHello {
                    host_version: None,
                    profile_hash: None,
                    resume_ticket: String::new(),
                },
                0,
            )
            .unwrap();
        let (d2, _) = ini.finish(&m2, 0).unwrap();
        assert_eq!(d2.resume_secret(), h2.resume_secret());
        assert_ne!(d2.resume_secret(), d1.resume_secret(), "rotated on resume");
        assert_ne!(d2.handshake_hash(), d1.handshake_hash());
    }

    #[test]
    fn the_resume_secret_is_not_a_function_of_the_public_transcript() {
        // Two channels that share a handshake hash cannot exist, so check
        // the construction directly: the secret differs from HKDF over the
        // hash alone, which is what anyone on the path could compute.
        let (d, _, _) = open_pair();
        let mut naive = [0u8; 32];
        Hkdf::<Sha256>::new(None, d.handshake_hash())
            .expand(RESUME_LABEL, &mut naive)
            .unwrap();
        assert_ne!(&naive, d.resume_secret());
    }
}
