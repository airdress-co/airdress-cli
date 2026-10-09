//! Recordings, written on the host and readable only on the person's devices
//! (D-4, design §7.9, FR-R1–FR-R6).
//!
//! A profile with `record = true` records its sessions' output (and input
//! with `record_input = true`) as asciicast v2 event lines, sealed in chunks
//! under a content key that is wrapped, per segment, to the shell keys of
//! the person's devices this host has verified. The host forgets each
//! segment's key when the segment closes: it cannot read its own recordings
//! back. A device revocation closes the segment and starts the next one
//! wrapped to the remaining devices only (design §6.7 step 4).
//!
//! Files: `~/.local/state/airdress/shells/recordings/<yyyy-mm-dd>/
//! <session>.<n>.cast.enc` (0600), and beside them `<session>.json`, the
//! listing's metadata (profile id, start, segments, retention): nothing in
//! it is content.
//!
//! Chunks are sealed at 32 KiB of plaintext, half the format's ceiling, so
//! a fetched chunk travels inside one record under the operator's frame
//! ceiling.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use airdress_shell_proto::inner::RecordingInfo;
use airdress_shell_proto::recording::{
    split_chunks, Recipient, RecipientEntry, SegmentHeader, SegmentWriter,
};
use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::log_err::LogErr as _;
use crate::paths::Paths;

/// Plaintext per chunk.
pub const CHUNK: usize = 32 * 1024;
/// A chunk is sealed after this long even when it is not full, so a host
/// that dies loses at most this much.
pub const FLUSH_EVERY: Duration = Duration::from_secs(5);
/// Chunks sent per `recording_fetch`; the device asks again from the next.
pub const FETCH_CHUNKS: usize = 16;

/// The listing's metadata for one recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub recording: Uuid,
    pub profile: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub segments: u32,
    pub retention_secs: u64,
}

fn segment_path(dir: &Path, session: Uuid, n: u32) -> PathBuf {
    dir.join(format!("{session}.{n}.cast.enc"))
}

fn write_meta(dir: &Path, meta: &Meta) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(meta)?;
    bytes.push(b'\n');
    crate::paths::write_private_atomic(&dir.join(format!("{}.json", meta.recording)), &bytes)
}

fn open_segment(path: &Path, header: &SegmentHeader) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    f.write_all(&header.to_bytes().map_err(|e| anyhow::anyhow!("{e}"))?)?;
    Ok(f)
}

/// One session's recording, while it runs.
pub struct Recorder {
    session: Uuid,
    dir: PathBuf,
    meta: Meta,
    writer: Option<SegmentWriter>,
    file: File,
    buf: Vec<u8>,
    carry: Vec<u8>,
    started: Instant,
    last_seal: Instant,
    record_input: bool,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("session", &self.session)
            .field("segments", &self.meta.segments)
            .finish_non_exhaustive()
    }
}

fn recipients(list: &[(Uuid, [u8; 32])]) -> Vec<Recipient> {
    list.iter()
        .map(|(d, k)| Recipient {
            device: d.to_string(),
            public: *k,
        })
        .collect()
}

/// The longest prefix of `bytes` that is whole UTF-8, and the rest.
fn split_utf8(bytes: &[u8]) -> (&[u8], &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(_) => (bytes, &[]),
        Err(e) if e.error_len().is_none() => bytes.split_at(e.valid_up_to()),
        Err(_) => (bytes, &[]),
    }
}

impl Recorder {
    /// Start recording `session` of `profile`, wrapped to `to`.
    pub fn start(
        paths: &Paths,
        session: Uuid,
        profile: &str,
        retention: Duration,
        record_input: bool,
        (cols, rows): (u16, u16),
        to: &[(Uuid, [u8; 32])],
    ) -> Result<Self> {
        if to.is_empty() {
            bail!("no verified device to wrap a recording to");
        }
        let now = chrono::Utc::now();
        let dir = paths
            .recordings_dir()
            .join(now.format("%Y-%m-%d").to_string());
        crate::paths::ensure_private_dir(&dir)?;
        let writer = SegmentWriter::start(&mut OsRng, &session.to_string(), 0, &recipients(to))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let file = open_segment(&segment_path(&dir, session, 0), writer.header())?;
        let meta = Meta {
            recording: session,
            profile: profile.to_owned(),
            started_at: now,
            segments: 1,
            retention_secs: retention.as_secs(),
        };
        write_meta(&dir, &meta)?;
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": now.timestamp(),
            "env": { "TERM": crate::environment::TERM },
        });
        let mut r = Self {
            session,
            dir,
            meta,
            writer: Some(writer),
            file,
            buf: Vec::new(),
            carry: Vec::new(),
            started: Instant::now(),
            last_seal: Instant::now(),
            record_input,
        };
        r.buf.extend_from_slice(header.to_string().as_bytes());
        r.buf.push(b'\n');
        Ok(r)
    }

    fn event(&mut self, kind: &str, data: &[u8]) -> Result<()> {
        let mut all = std::mem::take(&mut self.carry);
        all.extend_from_slice(data);
        let (whole, rest) = split_utf8(&all);
        let text = String::from_utf8_lossy(whole);
        self.carry = rest.to_vec();
        if text.is_empty() {
            return Ok(());
        }
        let t = self.started.elapsed().as_secs_f64();
        let line =
            serde_json::to_string(&serde_json::json!([(t * 1e6).round() / 1e6, kind, text]))?;
        self.buf.extend_from_slice(line.as_bytes());
        self.buf.push(b'\n');
        while self.buf.len() >= CHUNK {
            let rest = self.buf.split_off(CHUNK);
            let chunk = std::mem::replace(&mut self.buf, rest);
            self.seal(&chunk)?;
        }
        Ok(())
    }

    fn seal(&mut self, chunk: &[u8]) -> Result<()> {
        let w = self.writer.as_mut().context("the recording is closed")?;
        let sealed = w
            .seal_chunk(&mut OsRng, chunk)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.file.write_all(&sealed)?;
        self.last_seal = Instant::now();
        Ok(())
    }

    /// The program wrote `data`.
    pub fn output(&mut self, data: &[u8]) -> Result<()> {
        self.event("o", data)
    }

    /// The typist typed `data`; recorded only with `record_input`.
    pub fn input(&mut self, data: &[u8]) -> Result<()> {
        if self.record_input {
            self.event("i", data)
        } else {
            Ok(())
        }
    }

    /// Seal what is buffered if it has waited [`FLUSH_EVERY`].
    pub fn flush_if_due(&mut self) -> Result<()> {
        if !self.buf.is_empty() && self.last_seal.elapsed() >= FLUSH_EVERY {
            let chunk = std::mem::take(&mut self.buf);
            self.seal(&chunk)?;
        }
        Ok(())
    }

    /// Close this segment and start the next, wrapped only to `to` (design
    /// §6.7 step 4). With nobody left to wrap to, the recording stops.
    pub fn roll(&mut self, to: &[(Uuid, [u8; 32])]) -> Result<bool> {
        let w = self.writer.take().context("the recording is closed")?;
        let tail = std::mem::take(&mut self.buf);
        if to.is_empty() {
            let last = w
                .finish(&mut OsRng, &tail)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            self.file.write_all(&last)?;
            self.file.sync_all()?;
            return Ok(false);
        }
        let (last, next) = w
            .roll(&mut OsRng, &tail, &recipients(to))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.file.write_all(&last)?;
        self.file.sync_all()?;
        let n = next.header().segment;
        self.file = open_segment(&segment_path(&self.dir, self.session, n), next.header())?;
        self.writer = Some(next);
        self.meta.segments = n + 1;
        write_meta(&self.dir, &self.meta)?;
        Ok(true)
    }

    /// Close the recording: the last chunk is sealed and the key forgotten.
    pub fn finish(mut self) -> Result<()> {
        if let Some(w) = self.writer.take() {
            let mut tail = std::mem::take(&mut self.buf);
            tail.extend_from_slice(&self.carry);
            let last = w
                .finish(&mut OsRng, &tail)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            self.file.write_all(&last)?;
            self.file.sync_all()?;
        }
        Ok(())
    }

    /// Whether a segment is open.
    pub fn is_open(&self) -> bool {
        self.writer.is_some()
    }

    /// The path of segment `n`.
    pub fn segment_file(&self, n: u32) -> PathBuf {
        segment_path(&self.dir, self.session, n)
    }
}

fn day_dirs(paths: &Paths) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(paths.recordings_dir()) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

fn metas(paths: &Paths) -> Vec<(PathBuf, Meta)> {
    let mut out = Vec::new();
    for dir in day_dirs(paths) {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Some(m) = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
            {
                out.push((dir.clone(), m));
            }
        }
    }
    out.sort_by_key(|(_, m)| m.started_at);
    out
}

/// Every recording this host holds (they are all its person's).
pub fn list(paths: &Paths) -> Vec<RecordingInfo> {
    metas(paths)
        .into_iter()
        .map(|(_, m)| RecordingInfo {
            recording: m.recording.to_string(),
            profile: m.profile,
            started_at: m.started_at.to_rfc3339(),
            segments: m.segments,
        })
        .collect()
}

fn find(paths: &Paths, recording: &str) -> Result<(PathBuf, Meta)> {
    let id: Uuid = recording.parse().context("not a recording id")?;
    metas(paths)
        .into_iter()
        .find(|(_, m)| m.recording == id)
        .context("no such recording")
}

/// A segment's header bytes, and its sealed chunks by index.
pub type Fetched = (Vec<u8>, Vec<(u64, Vec<u8>)>);

/// A segment's header bytes and up to [`FETCH_CHUNKS`] sealed chunks from
/// `from_chunk`, as stored: ciphertext the host cannot open.
pub fn fetch(paths: &Paths, recording: &str, segment: u32, from_chunk: u64) -> Result<Fetched> {
    let (dir, m) = find(paths, recording)?;
    let bytes =
        std::fs::read(segment_path(&dir, m.recording, segment)).context("no such segment")?;
    let (_, at) = SegmentHeader::parse(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let header = bytes[..at].to_vec();
    let chunks = split_chunks(&bytes[at..])
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .into_iter()
        .enumerate()
        .skip(from_chunk as usize)
        .take(FETCH_CHUNKS)
        .map(|(i, c)| (i as u64, c.to_vec()))
        .collect();
    Ok((header, chunks))
}

/// A device that can read a segment added `entry` for another device of the
/// same person: rewrite the header with it (design §7.9). The host cannot
/// check the entry; it refuses a duplicate or a malformed one.
pub fn rewrap(paths: &Paths, recording: &str, segment: u32, entry: RecipientEntry) -> Result<()> {
    let (dir, m) = find(paths, recording)?;
    let path = segment_path(&dir, m.recording, segment);
    let bytes = std::fs::read(&path).context("no such segment")?;
    let (mut header, at) = SegmentHeader::parse(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    header
        .add_recipient(entry)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = header.to_bytes().map_err(|e| anyhow::anyhow!("{e}"))?;
    out.extend_from_slice(&bytes[at..]);
    crate::paths::write_private_atomic(&path, &out)
}

/// Remove recordings past their retention. Returns how many went.
pub fn prune(paths: &Paths, now: SystemTime) -> usize {
    let now: chrono::DateTime<chrono::Utc> = now.into();
    let mut removed = 0;
    for (dir, m) in metas(paths) {
        let age = now.signed_duration_since(m.started_at);
        if age.num_seconds() < 0 || (age.num_seconds() as u64) < m.retention_secs {
            continue;
        }
        for n in 0..m.segments {
            std::fs::remove_file(segment_path(&dir, m.recording, n))
                .log_warn("removing an expired recording segment");
        }
        std::fs::remove_file(dir.join(format!("{}.json", m.recording)))
            .log_warn("removing an expired recording's manifest");
        removed += 1;
        if std::fs::read_dir(&dir).is_ok_and(|mut d| d.next().is_none()) {
            std::fs::remove_dir(&dir).log_debug("removing an empty recordings directory");
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use airdress_shell_proto::keys::ShellKeypair;
    use airdress_shell_proto::recording::SegmentReader;

    fn setup() -> (tempfile::TempDir, Paths, ShellKeypair, ShellKeypair) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        (
            d,
            p,
            ShellKeypair::generate(&mut OsRng),
            ShellKeypair::generate(&mut OsRng),
        )
    }

    fn read(
        path: &Path,
        device: Uuid,
        kp: &ShellKeypair,
    ) -> Result<String, airdress_shell_proto::ProtoError> {
        let bytes = std::fs::read(path).unwrap();
        SegmentReader::read_file(&bytes, &device.to_string(), kp.secret())
            .map(|c| String::from_utf8(c.data).unwrap())
    }

    #[test]
    fn a_recording_is_asciicast_for_its_devices_only() {
        let (_d, p, phone, other) = setup();
        let (dev, s) = (Uuid::from_u128(1), Uuid::from_u128(9));
        let mut r = Recorder::start(
            &p,
            s,
            "home",
            Duration::from_secs(60),
            false,
            (80, 24),
            &[(dev, *phone.public())],
        )
        .unwrap();
        r.output(b"hello \xe2\x82").unwrap();
        r.output(b"\xac world\r\n").unwrap();
        r.input(b"secret typing").unwrap();
        let file = r.segment_file(0);
        r.finish().unwrap();
        let text = read(&file, dev, &phone).unwrap();
        let mut lines = text.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 80);
        let all: String = lines.collect();
        assert!(all.contains("hello"), "{all}");
        assert!(
            all.contains("€ world"),
            "a character split across reads survives: {all}"
        );
        assert!(!all.contains("secret typing"), "input is off by default");
        assert!(read(&file, Uuid::from_u128(2), &other).is_err());
        let listed = list(&p);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].profile, "home");
        assert_eq!(listed[0].segments, 1);
    }

    #[test]
    fn a_roll_leaves_the_revoked_device_out_of_the_next_segment() {
        let (_d, p, phone, laptop) = setup();
        let (a, b, s) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(9));
        let mut r = Recorder::start(
            &p,
            s,
            "home",
            Duration::from_secs(60),
            true,
            (80, 24),
            &[(a, *phone.public()), (b, *laptop.public())],
        )
        .unwrap();
        r.output(b"before").unwrap();
        assert!(r.roll(&[(b, *laptop.public())]).unwrap());
        r.output(b"after").unwrap();
        let (seg0, seg1) = (r.segment_file(0), r.segment_file(1));
        r.finish().unwrap();
        assert!(read(&seg0, a, &phone).unwrap().contains("before"));
        assert!(
            read(&seg1, a, &phone).is_err(),
            "the revoked device reads nothing after"
        );
        assert!(read(&seg1, b, &laptop).unwrap().contains("after"));
        assert_eq!(list(&p)[0].segments, 2);
    }

    #[test]
    fn fetch_returns_ciphertext_and_rewrap_adds_a_reader() {
        let (_d, p, phone, laptop) = setup();
        let (a, b, s) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(9));
        let mut r = Recorder::start(
            &p,
            s,
            "home",
            Duration::from_secs(60),
            false,
            (80, 24),
            &[(a, *phone.public())],
        )
        .unwrap();
        for _ in 0..3000 {
            r.output(b"0123456789abcdefghij\r\n").unwrap();
        }
        let file = r.segment_file(0);
        r.finish().unwrap();
        let (header, chunks) = fetch(&p, &s.to_string(), 0, 0).unwrap();
        let (h, _) = SegmentHeader::parse(&header).unwrap();
        let reader = SegmentReader::open(&h, &a.to_string(), phone.secret()).unwrap();
        let (first, _) = reader.open_chunk(0, &chunks[0].1).unwrap();
        assert!(first.starts_with(b"{"));
        assert!(chunks.iter().all(|(_, c)| c.len() < 64 * 1024 - 64));
        // The phone wraps the key to the laptop; the host appends it.
        let entry = airdress_shell_proto::recording::rewrap(
            &mut OsRng,
            &h,
            &a.to_string(),
            phone.secret(),
            &Recipient {
                device: b.to_string(),
                public: *laptop.public(),
            },
        )
        .unwrap();
        rewrap(&p, &s.to_string(), 0, entry.clone()).unwrap();
        assert!(read(&file, b, &laptop).is_ok());
        assert!(
            rewrap(&p, &s.to_string(), 0, entry).is_err(),
            "a duplicate is refused"
        );
    }

    #[test]
    fn the_host_keeps_nothing_that_opens_a_closed_segment() {
        let (_d, p, phone, _) = setup();
        let mut r = Recorder::start(
            &p,
            Uuid::from_u128(9),
            "home",
            Duration::from_secs(60),
            false,
            (80, 24),
            &[(Uuid::from_u128(1), *phone.public())],
        )
        .unwrap();
        r.output(b"x").unwrap();
        r.finish().unwrap();
        // What the host keeps on disk next to the segment holds no key.
        let meta =
            std::fs::read_to_string(metas(&p)[0].0.join(format!("{}.json", Uuid::from_u128(9))))
                .unwrap();
        assert!(!meta.contains("key"), "{meta}");
    }

    #[test]
    fn prune_removes_what_is_past_retention() {
        let (_d, p, phone, _) = setup();
        let r = Recorder::start(
            &p,
            Uuid::from_u128(9),
            "home",
            Duration::from_secs(60),
            false,
            (80, 24),
            &[(Uuid::from_u128(1), *phone.public())],
        )
        .unwrap();
        r.finish().unwrap();
        assert_eq!(prune(&p, SystemTime::now()), 0);
        assert_eq!(prune(&p, SystemTime::now() + Duration::from_secs(120)), 1);
        assert!(list(&p).is_empty());
    }
}
