//! Recordings the host writes and cannot read back (design §7.9, FR-R2).
//!
//! A recording is one or more **segments**, one file each
//! (`<session>.<n>.cast.enc`). A segment file is:
//!
//! ```text
//! "ADSHREC\x01" ‖ header_len (u32 BE) ‖ header (JSON)
//! ‖ { chunk_len (u32 BE) ‖ nonce (24) ‖ XChaCha20-Poly1305(content_key, nonce,
//!       ad = index (u64 BE) ‖ final (u8), chunk) }*
//! ```
//!
//! - The **content key** is random per segment. The header wraps it with HPKE
//!   (RFC 9180: `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
//!   `ChaCha20Poly1305`, base mode) to each recipient's X25519 shell key,
//!   with `info = "airdress.shell.recording.v1" ‖ 0x00 ‖ session ‖ 0x1F ‖
//!   segment (u32 BE)` and `aad = device id`.
//! - A **chunk** holds at most [`MAX_CHUNK`] bytes of asciicast event lines.
//!   Its AD is its index and whether it is the segment's last, so chunks
//!   cannot be reordered, and a reader can tell a segment that was closed
//!   from one cut short.
//! - The **writer** ([`SegmentWriter`]) holds the content key only while the
//!   segment is open; [`SegmentWriter::finish`] consumes it and the key is
//!   zeroed. Nothing in this module hands the key out.
//! - **Rewrap** ([`rewrap`]) runs on a device that can unwrap: it adds an
//!   entry for another device of the same principal, and the host appends it
//!   to the header without being able to check or read it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ProtoError, Result};

/// The file magic, with the format version in its last byte.
pub const MAGIC: &[u8; 8] = b"ADSHREC\x01";
/// The largest chunk of plaintext.
pub const MAX_CHUNK: usize = 64 * 1024;
/// HPKE `info` label.
pub const WRAP_LABEL: &[u8] = b"airdress.shell.recording.v1";
/// The largest header accepted.
pub const MAX_HEADER: usize = 64 * 1024;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

type Kem = X25519HkdfSha256;

/// A device a segment is wrapped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// The device id.
    pub device: String,
    /// Its X25519 shell key, as attested and verified (design §6.3).
    pub public: [u8; 32],
}

/// One recipient's wrapped content key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientEntry {
    /// The device id.
    pub device: String,
    /// HPKE encapsulated key (32 bytes).
    #[serde(with = "crate::b64::bytes")]
    pub enc: Vec<u8>,
    /// The content key sealed to the device (48 bytes).
    #[serde(with = "crate::b64::bytes")]
    pub wrapped: Vec<u8>,
}

/// A segment's header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentHeader {
    /// Format version, 1.
    pub version: u32,
    /// The session recorded.
    pub session: String,
    /// The segment number, from 0.
    pub segment: u32,
    /// Who can read it.
    pub recipients: Vec<RecipientEntry>,
}

fn wrap_info(session: &str, segment: u32) -> Vec<u8> {
    let mut i = Vec::with_capacity(WRAP_LABEL.len() + session.len() + 6);
    i.extend_from_slice(WRAP_LABEL);
    i.push(0x00);
    i.extend_from_slice(session.as_bytes());
    i.push(0x1F);
    i.extend_from_slice(&segment.to_be_bytes());
    i
}

fn wrap_to<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &[u8; 32],
    session: &str,
    segment: u32,
    r: &Recipient,
) -> Result<RecipientEntry> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&r.public)
        .map_err(|_| ProtoError::Recording("recipient key malformed"))?;
    let (enc, wrapped) = hpke::single_shot_seal::<HpkeChaCha, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        &wrap_info(session, segment),
        key,
        r.device.as_bytes(),
        rng,
    )
    .map_err(|_| ProtoError::Recording("wrap failed"))?;
    Ok(RecipientEntry {
        device: r.device.clone(),
        enc: enc.to_bytes().to_vec(),
        wrapped,
    })
}

fn unwrap_for(
    header: &SegmentHeader,
    device: &str,
    secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let entry = header
        .recipients
        .iter()
        .find(|e| e.device == device)
        .ok_or(ProtoError::Recording("no entry for this device"))?;
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(secret)
        .map_err(|_| ProtoError::Recording("device key malformed"))?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&entry.enc)
        .map_err(|_| ProtoError::Recording("enc malformed"))?;
    let pt = Zeroizing::new(
        hpke::single_shot_open::<HpkeChaCha, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &wrap_info(&header.session, header.segment),
            &entry.wrapped,
            device.as_bytes(),
        )
        .map_err(|_| ProtoError::Recording("unwrap failed"))?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    if pt.len() != 32 {
        return Err(ProtoError::Recording("content key length"));
    }
    key.copy_from_slice(&pt);
    Ok(key)
}

impl SegmentHeader {
    /// `MAGIC ‖ len ‖ JSON`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|_| ProtoError::Recording("header"))?;
        if json.len() > MAX_HEADER {
            return Err(ProtoError::Recording("header too large"));
        }
        let mut out = Vec::with_capacity(12 + json.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(json.len() as u32).to_be_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Parse a header from the front of a segment file. Returns it and the
    /// number of bytes it took.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 12 || &bytes[..8] != MAGIC {
            return Err(ProtoError::Recording("not a segment file"));
        }
        let len = u32::from_be_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
        if len > MAX_HEADER || bytes.len() < 12 + len {
            return Err(ProtoError::Recording("header truncated"));
        }
        let h: SegmentHeader = serde_json::from_slice(&bytes[12..12 + len])
            .map_err(|_| ProtoError::Recording("header malformed"))?;
        if h.version != 1 {
            return Err(ProtoError::Recording("unknown version"));
        }
        Ok((h, 12 + len))
    }

    /// Append a recipient (the host's half of a rewrap). Refuses a device
    /// that already has an entry, so a rewrap cannot replace a good entry
    /// with a bad one.
    pub fn add_recipient(&mut self, entry: RecipientEntry) -> Result<()> {
        if self.recipients.iter().any(|e| e.device == entry.device) {
            return Err(ProtoError::Recording("device already a recipient"));
        }
        if entry.enc.len() != 32 || entry.wrapped.len() != 32 + TAG_LEN {
            return Err(ProtoError::Recording("entry malformed"));
        }
        self.recipients.push(entry);
        Ok(())
    }
}

fn chunk_ad(index: u64, last: bool) -> [u8; 9] {
    let mut ad = [0u8; 9];
    ad[..8].copy_from_slice(&index.to_be_bytes());
    ad[8] = last as u8;
    ad
}

/// An open segment on the host.
pub struct SegmentWriter {
    header: SegmentHeader,
    key: Zeroizing<[u8; 32]>,
    next: u64,
}

impl std::fmt::Debug for SegmentWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentWriter")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl SegmentWriter {
    /// Start a segment wrapped to `recipients`. Refuses an empty list: a
    /// recording nobody can read is not written.
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        session: &str,
        segment: u32,
        recipients: &[Recipient],
    ) -> Result<Self> {
        if recipients.is_empty() {
            return Err(ProtoError::Recording("no recipients"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut key[..]);
        let mut entries = Vec::with_capacity(recipients.len());
        for r in recipients {
            if entries
                .iter()
                .any(|e: &RecipientEntry| e.device == r.device)
            {
                return Err(ProtoError::Recording("duplicate recipient"));
            }
            entries.push(wrap_to(rng, &key, session, segment, r)?);
        }
        Ok(Self {
            header: SegmentHeader {
                version: 1,
                session: session.to_owned(),
                segment,
                recipients: entries,
            },
            key,
            next: 0,
        })
    }

    /// The header to write at the front of the file.
    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    fn seal(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        data: &[u8],
        last: bool,
    ) -> Result<Vec<u8>> {
        if data.len() > MAX_CHUNK {
            return Err(ProtoError::Recording("chunk too large"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let ct = XChaCha20Poly1305::new((&*self.key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: &chunk_ad(self.next, last),
                },
            )
            .map_err(|_| ProtoError::Recording("seal failed"))?;
        self.next += 1;
        let len = (NONCE_LEN + ct.len()) as u32;
        let mut out = Vec::with_capacity(4 + len as usize);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Seal a chunk; the bytes to append to the file.
    pub fn seal_chunk<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.seal(rng, data, false)
    }

    /// Seal the last chunk (possibly empty) and close the segment. The
    /// writer is consumed, and the content key zeroed with it.
    pub fn finish<R: RngCore + CryptoRng>(mut self, rng: &mut R, data: &[u8]) -> Result<Vec<u8>> {
        self.seal(rng, data, true)
    }

    /// Close this segment and start the next, wrapped to `recipients`: the
    /// segment roll of a revocation (design §6.7 step 4). Returns the final
    /// chunk of the old segment and the new writer.
    pub fn roll<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        last: &[u8],
        recipients: &[Recipient],
    ) -> Result<(Vec<u8>, SegmentWriter)> {
        let session = self.header.session.clone();
        let next = self.header.segment + 1;
        let tail = self.finish(rng, last)?;
        Ok((tail, SegmentWriter::start(rng, &session, next, recipients)?))
    }
}

/// A segment opened on a device.
pub struct SegmentReader {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SegmentReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentReader").finish_non_exhaustive()
    }
}

/// What reading a whole segment found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentContents {
    /// The concatenated plaintext of every chunk.
    pub data: Vec<u8>,
    /// How many chunks.
    pub chunks: u64,
    /// Whether the segment ends with its final chunk. `false` means the host
    /// stopped without closing it, or the file was cut.
    pub complete: bool,
}

impl SegmentReader {
    /// Unwrap the content key with this device's shell key.
    pub fn open(header: &SegmentHeader, device: &str, secret: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            key: unwrap_for(header, device, secret)?,
        })
    }

    /// Open the chunk at `index` (`framed` includes its length prefix).
    /// Returns its plaintext and whether it is the last.
    pub fn open_chunk(&self, index: u64, framed: &[u8]) -> Result<(Vec<u8>, bool)> {
        if framed.len() < 4 + NONCE_LEN + TAG_LEN {
            return Err(ProtoError::Recording("chunk truncated"));
        }
        let len = u32::from_be_bytes(framed[..4].try_into().expect("4 bytes")) as usize;
        if framed.len() != 4 + len {
            return Err(ProtoError::Recording("chunk length"));
        }
        let nonce = XNonce::from_slice(&framed[4..4 + NONCE_LEN]);
        let ct = &framed[4 + NONCE_LEN..];
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        for last in [false, true] {
            if let Ok(pt) = cipher.decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: &chunk_ad(index, last),
                },
            ) {
                return Ok((pt, last));
            }
        }
        Err(ProtoError::Recording("chunk does not authenticate"))
    }

    /// Open a whole segment file.
    pub fn read_file(bytes: &[u8], device: &str, secret: &[u8; 32]) -> Result<SegmentContents> {
        let (header, at) = SegmentHeader::parse(bytes)?;
        let reader = Self::open(&header, device, secret)?;
        let mut out = SegmentContents {
            data: Vec::new(),
            chunks: 0,
            complete: false,
        };
        for framed in split_chunks(&bytes[at..])? {
            if out.complete {
                return Err(ProtoError::Recording("data after the final chunk"));
            }
            let (pt, last) = reader.open_chunk(out.chunks, framed)?;
            out.data.extend_from_slice(&pt);
            out.chunks += 1;
            out.complete = last;
        }
        Ok(out)
    }
}

/// Split the bytes after a header into framed chunks. A trailing partial
/// chunk (a write cut short) is dropped, not an error: what was written
/// whole stays readable.
pub fn split_chunks(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes")) as usize;
        if len > NONCE_LEN + MAX_CHUNK + TAG_LEN {
            return Err(ProtoError::Recording("chunk length"));
        }
        if bytes.len() < 4 + len {
            break;
        }
        out.push(&bytes[..4 + len]);
        bytes = &bytes[4 + len..];
    }
    Ok(out)
}

/// On a device that can read `header`: wrap its content key to another
/// device of the same principal. The host appends the entry with
/// [`SegmentHeader::add_recipient`].
pub fn rewrap<R: RngCore + CryptoRng>(
    rng: &mut R,
    header: &SegmentHeader,
    my_device: &str,
    my_secret: &[u8; 32],
    to: &Recipient,
) -> Result<RecipientEntry> {
    let key = unwrap_for(header, my_device, my_secret)?;
    wrap_to(rng, &key, &header.session, header.segment, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ShellKeypair;
    use rand_core::OsRng;

    fn recipient(name: &str, kp: &ShellKeypair) -> Recipient {
        Recipient {
            device: name.into(),
            public: *kp.public(),
        }
    }

    /// The segment header is the wrap's input and stays closed: an unknown
    /// field, at the top or in a recipient, refuses the file (the crate's
    /// "Wire compatibility").
    #[test]
    fn a_header_refuses_an_unknown_field() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let w = SegmentWriter::start(&mut OsRng, "s1", 0, &[recipient("phone", &phone)]).unwrap();
        let reframe = |v: &serde_json::Value| {
            let json = serde_json::to_vec(v).unwrap();
            let mut out = MAGIC.to_vec();
            out.extend_from_slice(&u32::try_from(json.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&json);
            out
        };
        let v = serde_json::to_value(w.header()).unwrap();
        assert!(SegmentHeader::parse(&reframe(&v)).is_ok());
        let mut top = v.clone();
        top["extra"] = serde_json::json!(1);
        assert!(SegmentHeader::parse(&reframe(&top)).is_err());
        let mut nested = v;
        nested["recipients"][0]["extra"] = serde_json::json!(1);
        assert!(SegmentHeader::parse(&reframe(&nested)).is_err());
    }

    #[test]
    fn write_read_and_complete() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let mut w =
            SegmentWriter::start(&mut OsRng, "s1", 0, &[recipient("phone", &phone)]).unwrap();
        let mut file = w.header().to_bytes().unwrap();
        file.extend(w.seal_chunk(&mut OsRng, b"[0.1, \"o\", \"a\"]\n").unwrap());
        file.extend(w.finish(&mut OsRng, b"[0.2, \"o\", \"b\"]\n").unwrap());
        let got = SegmentReader::read_file(&file, "phone", phone.secret()).unwrap();
        assert!(got.complete);
        assert_eq!(got.chunks, 2);
        assert_eq!(got.data, b"[0.1, \"o\", \"a\"]\n[0.2, \"o\", \"b\"]\n");
    }

    #[test]
    fn a_cut_segment_reads_as_incomplete() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let mut w =
            SegmentWriter::start(&mut OsRng, "s1", 0, &[recipient("phone", &phone)]).unwrap();
        let mut file = w.header().to_bytes().unwrap();
        file.extend(w.seal_chunk(&mut OsRng, b"a").unwrap());
        let c2 = w.seal_chunk(&mut OsRng, b"b").unwrap();
        file.extend(&c2[..c2.len() - 3]);
        let got = SegmentReader::read_file(&file, "phone", phone.secret()).unwrap();
        assert!(!got.complete);
        assert_eq!(got.data, b"a");
    }

    #[test]
    fn chunks_cannot_be_reordered() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let mut w =
            SegmentWriter::start(&mut OsRng, "s1", 0, &[recipient("phone", &phone)]).unwrap();
        let mut file = w.header().to_bytes().unwrap();
        let a = w.seal_chunk(&mut OsRng, b"a").unwrap();
        let b = w.seal_chunk(&mut OsRng, b"b").unwrap();
        file.extend(&b);
        file.extend(&a);
        assert!(SegmentReader::read_file(&file, "phone", phone.secret()).is_err());
    }

    #[test]
    fn the_writer_cannot_read_a_closed_segment() {
        // Everything the host keeps after the segment closes: the file, the
        // recipients' public keys, and its own shell key pair. None of it
        // opens the segment.
        let host = ShellKeypair::generate(&mut OsRng);
        let phone = ShellKeypair::generate(&mut OsRng);
        let recipients = [recipient("phone", &phone)];
        let w = SegmentWriter::start(&mut OsRng, "s1", 0, &recipients).unwrap();
        let mut file = w.header().to_bytes().unwrap();
        file.extend(w.finish(&mut OsRng, b"secret output").unwrap());

        for device in ["phone", "host", "desk"] {
            assert!(SegmentReader::read_file(&file, device, host.secret()).is_err());
        }
        // The public key interpreted as a secret is no better.
        assert!(SegmentReader::read_file(&file, "phone", &recipients[0].public).is_err());
        // Nor is any key the host could derive from what it holds.
        let (header, _) = SegmentHeader::parse(&file).unwrap();
        assert!(rewrap(
            &mut OsRng,
            &header,
            "phone",
            host.secret(),
            &recipient("x", &host)
        )
        .is_err());
        // And the plaintext is not in the file.
        assert!(!file.windows(13).any(|w| w == b"secret output"));
    }

    #[test]
    fn rewrap_adds_a_reader_and_roll_drops_one() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let cli = ShellKeypair::generate(&mut OsRng);
        let tablet = ShellKeypair::generate(&mut OsRng);
        let mut w = SegmentWriter::start(
            &mut OsRng,
            "s1",
            0,
            &[recipient("phone", &phone), recipient("cli", &cli)],
        )
        .unwrap();
        let mut header = w.header().clone();
        let body = w.seal_chunk(&mut OsRng, b"seg0").unwrap();

        // The tablet is added by the phone.
        let entry = rewrap(
            &mut OsRng,
            &header,
            "phone",
            phone.secret(),
            &recipient("tablet", &tablet),
        )
        .unwrap();
        header.add_recipient(entry.clone()).unwrap();
        assert!(header.add_recipient(entry).is_err());
        let mut f0 = header.to_bytes().unwrap();
        f0.extend(&body);

        // The cli is revoked: the segment rolls, wrapped to the rest only.
        let (tail, w2) = w
            .roll(
                &mut OsRng,
                b"",
                &[recipient("phone", &phone), recipient("tablet", &tablet)],
            )
            .unwrap();
        f0.extend(tail);
        let mut f1 = w2.header().to_bytes().unwrap();
        f1.extend(w2.finish(&mut OsRng, b"seg1").unwrap());

        assert_eq!(
            SegmentReader::read_file(&f0, "tablet", tablet.secret())
                .unwrap()
                .data,
            b"seg0"
        );
        assert_eq!(
            SegmentReader::read_file(&f0, "cli", cli.secret())
                .unwrap()
                .data,
            b"seg0"
        );
        assert!(SegmentReader::read_file(&f1, "cli", cli.secret()).is_err());
        assert_eq!(
            SegmentReader::read_file(&f1, "phone", phone.secret())
                .unwrap()
                .data,
            b"seg1"
        );
    }

    #[test]
    fn an_entry_moved_to_another_segment_does_not_open() {
        let phone = ShellKeypair::generate(&mut OsRng);
        let r = [recipient("phone", &phone)];
        let w0 = SegmentWriter::start(&mut OsRng, "s1", 0, &r).unwrap();
        let w1 = SegmentWriter::start(&mut OsRng, "s1", 1, &r).unwrap();
        let mut h1 = w1.header().clone();
        h1.recipients = w0.header().recipients.clone();
        assert!(SegmentReader::open(&h1, "phone", phone.secret()).is_err());
    }
}
