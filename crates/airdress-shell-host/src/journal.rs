//! A session's output journal (design §7.1, FR-E7, FR-S7, FR-S9).
//!
//! Every byte the PTY writes gets a stream **offset**. A client acks
//! offsets; a client that resumes asks for everything after its last ack,
//! and gets it if the journal still holds it, else a snapshot.
//!
//! The journal keeps the newest `journal_bytes` in memory. Older output
//! **spills** to disk, encrypted, up to `journal_spill_bytes`; beyond that
//! the oldest is dropped. The spill key is random per session and lives
//! only in this process's memory (FR-E7): after the host stops, nothing on
//! disk can be read, and the spill directory is removed anyway. A device
//! revocation rotates the key and re-encrypts what is on disk (design §6.7
//! step 3).
//!
//! Spill files are `<n>.spill` under the session's own `0700` directory, each
//! a run of `u32 len ‖ nonce (24) ‖ XChaCha20-Poly1305(key, nonce, ad =
//! start offset (u64 BE), bytes)`.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use crate::log_err::LogErr as _;
use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore as _;
use zeroize::Zeroizing;

/// In-memory appends are merged up to this size.
const CHUNK: usize = 32 * 1024;
/// A spill file is closed at this size.
const SPILL_FILE: u64 = 1 << 20;
const NONCE: usize = 24;

#[derive(Debug)]
struct SpillEntry {
    start: u64,
    len: usize,
    file: u32,
    at: u64,
}

/// One session's journal.
pub struct Journal {
    mem: VecDeque<(u64, Vec<u8>)>,
    mem_bytes: usize,
    mem_cap: usize,
    end: u64,
    spill: VecDeque<SpillEntry>,
    spill_bytes: u64,
    spill_cap: u64,
    dir: Option<PathBuf>,
    file_no: u32,
    file_len: u64,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("end", &self.end)
            .field("earliest", &self.earliest())
            .field("mem_bytes", &self.mem_bytes)
            .field("spill_bytes", &self.spill_bytes)
            .finish_non_exhaustive()
    }
}

fn new_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut k[..]);
    k
}

fn seal(key: &[u8; 32], start: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: data,
                aad: &start.to_be_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("spill seal failed"))?;
    let mut out = Vec::with_capacity(4 + NONCE + ct.len());
    out.extend_from_slice(&((NONCE + ct.len()) as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open(key: &[u8; 32], start: u64, framed: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(framed.len() > 4 + NONCE, "spill entry truncated");
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&framed[4..4 + NONCE]),
            Payload {
                msg: &framed[4 + NONCE..],
                aad: &start.to_be_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("spill entry does not open"))
}

impl Journal {
    /// A journal keeping `mem_cap` bytes in memory and spilling up to
    /// `spill_cap` more into `dir` (created `0700`; `None` or a cap of 0
    /// spills nothing).
    pub fn new(mem_cap: usize, spill_cap: u64, dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(d) if spill_cap > 0 => {
                crate::paths::ensure_private_dir(&d)?;
                Some(d)
            }
            _ => None,
        };
        Ok(Self {
            mem: VecDeque::new(),
            mem_bytes: 0,
            mem_cap: mem_cap.max(CHUNK),
            end: 0,
            spill: VecDeque::new(),
            spill_bytes: 0,
            spill_cap,
            dir,
            file_no: 0,
            file_len: 0,
            key: new_key(),
        })
    }

    /// The offset after the last byte.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The oldest offset still held.
    pub fn earliest(&self) -> u64 {
        self.spill
            .front()
            .map(|e| e.start)
            .or_else(|| self.mem.front().map(|(s, _)| *s))
            .unwrap_or(self.end)
    }

    /// Bytes on disk.
    pub fn spilled(&self) -> u64 {
        self.spill_bytes
    }

    fn file_path(&self, n: u32) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(format!("{n}.spill")))
    }

    /// Append output.
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self.mem.back_mut() {
            Some((_, last)) if last.len() + data.len() <= CHUNK => last.extend_from_slice(data),
            _ => self.mem.push_back((self.end, data.to_vec())),
        }
        self.end += data.len() as u64;
        self.mem_bytes += data.len();
        while self.mem_bytes > self.mem_cap && self.mem.len() > 1 {
            let (start, chunk) = self.mem.pop_front().expect("non-empty");
            self.mem_bytes -= chunk.len();
            self.spill_chunk(start, &chunk)?;
        }
        Ok(())
    }

    fn spill_chunk(&mut self, start: u64, chunk: &[u8]) -> Result<()> {
        if self.dir.is_none() {
            return Ok(());
        }
        if self.file_len >= SPILL_FILE {
            self.file_no += 1;
            self.file_len = 0;
        }
        let path = self.file_path(self.file_no).expect("dir");
        let framed = seal(&self.key, start, chunk)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("could not write {}", path.display()))?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&framed)?;
        self.spill.push_back(SpillEntry {
            start,
            len: chunk.len(),
            file: self.file_no,
            at: self.file_len,
        });
        self.file_len += framed.len() as u64;
        self.spill_bytes += chunk.len() as u64;
        while self.spill_bytes > self.spill_cap {
            let gone = self
                .spill
                .pop_front()
                .expect("over the cap means non-empty");
            self.spill_bytes -= gone.len as u64;
            if !self.spill.iter().any(|e| e.file == gone.file) && gone.file != self.file_no {
                if let Some(p) = self.file_path(gone.file) {
                    // Its key died with the entry: a file left behind is
                    // unreadable, and the next start removes the directory.
                    std::fs::remove_file(p).log_warn("removing a spilled journal file");
                }
            }
        }
        Ok(())
    }

    fn read_spill(&self, e: &SpillEntry) -> Result<Vec<u8>> {
        let path = self.file_path(e.file).context("no spill directory")?;
        let mut f = File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        f.seek(SeekFrom::Start(e.at))?;
        let mut len = [0u8; 4];
        f.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        let mut framed = vec![0u8; 4 + n];
        framed[..4].copy_from_slice(&len);
        f.read_exact(&mut framed[4..])?;
        open(&self.key, e.start, &framed)
    }

    /// Up to `max` bytes from `from`. `None` when `from` is older than what
    /// the journal holds: the caller sends a snapshot instead.
    pub fn read(&self, from: u64, max: usize) -> Option<Vec<u8>> {
        if from < self.earliest() || from > self.end {
            return None;
        }
        let want_end = self.end.min(from.saturating_add(max as u64));
        let mut out = Vec::with_capacity((want_end - from) as usize);
        for e in &self.spill {
            let (s, t) = (e.start, e.start + e.len as u64);
            if t <= from || s >= want_end {
                continue;
            }
            let data = self.read_spill(e).ok()?;
            let a = (from.max(s) - s) as usize;
            let b = (want_end.min(t) - s) as usize;
            out.extend_from_slice(&data[a..b]);
        }
        for (s, chunk) in &self.mem {
            let (s, t) = (*s, *s + chunk.len() as u64);
            if t <= from || s >= want_end {
                continue;
            }
            let a = (from.max(s) - s) as usize;
            let b = (want_end.min(t) - s) as usize;
            out.extend_from_slice(&chunk[a..b]);
        }
        Some(out)
    }

    /// A new key for the spill, and everything on disk re-encrypted under
    /// it at once (design §6.7 step 3).
    pub fn rotate_key(&mut self) -> Result<()> {
        let new = new_key();
        let Some(dir) = self.dir.clone() else {
            self.key = new;
            return Ok(());
        };
        let files: std::collections::BTreeSet<u32> = self.spill.iter().map(|e| e.file).collect();
        for n in files {
            let path = dir.join(format!("{n}.spill"));
            let tmp = dir.join(format!("{n}.spill.tmp"));
            let mut buf = Vec::new();
            let mut at = 0u64;
            let mut moved = Vec::new();
            for (i, e) in self.spill.iter().enumerate().filter(|(_, e)| e.file == n) {
                let plain = Zeroizing::new(self.read_spill(e)?);
                let framed = seal(&new, e.start, &plain)?;
                moved.push((i, at));
                at += framed.len() as u64;
                buf.extend_from_slice(&framed);
            }
            crate::paths::write_private_atomic(&tmp, &buf)?;
            crate::fsx::rename(&tmp, &path)?;
            for (i, at) in moved {
                self.spill[i].at = at;
            }
            if n == self.file_no {
                self.file_len = at;
            }
        }
        self.key = new;
        Ok(())
    }

    /// Remove everything on disk.
    pub fn destroy(&mut self) {
        if let Some(d) = self.dir.take() {
            std::fs::remove_dir_all(d).log_warn("removing the session's journal");
        }
        self.spill.clear();
        self.spill_bytes = 0;
    }

    /// The spill directory, if any.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn reads_from_any_held_offset_across_memory_and_spill() {
        let d = tempfile::tempdir().unwrap();
        let mut j = Journal::new(64 * 1024, 1 << 20, Some(d.path().join("s"))).unwrap();
        let mut all = Vec::new();
        for i in 0..20 {
            let b = bytes(10_000 + i, i as u8);
            j.append(&b).unwrap();
            all.extend_from_slice(&b);
        }
        assert!(j.spilled() > 0, "older output went to disk");
        assert_eq!(j.earliest(), 0);
        for from in [0u64, 1, 9_999, 50_000, 150_000, j.end() - 1] {
            assert_eq!(
                j.read(from, 1 << 30).unwrap(),
                all[from as usize..],
                "from {from}"
            );
        }
        assert_eq!(j.read(100, 10).unwrap(), all[100..110]);
        assert_eq!(j.read(j.end(), 10).unwrap(), Vec::<u8>::new());
        assert!(j.read(j.end() + 1, 10).is_none());
    }

    #[test]
    fn the_spill_is_bounded_and_encrypted() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        let mut j = Journal::new(32 * 1024, 100_000, Some(dir.clone())).unwrap();
        let marker = b"VISIBLE-PLAINTEXT-MARKER";
        for _ in 0..200 {
            let mut b = bytes(4000, 1);
            b.extend_from_slice(marker);
            j.append(&b).unwrap();
        }
        assert!(j.spilled() <= 100_000);
        assert!(j.earliest() > 0, "the oldest was dropped");
        assert!(j.read(0, 10).is_none(), "and is a snapshot now");
        for f in std::fs::read_dir(&dir).unwrap() {
            let raw = std::fs::read(f.unwrap().path()).unwrap();
            assert!(!raw.windows(marker.len()).any(|w| w == marker));
        }
    }

    #[test]
    fn a_rotated_key_re_encrypts_what_is_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        let mut j = Journal::new(32 * 1024, 1 << 20, Some(dir.clone())).unwrap();
        let mut all = Vec::new();
        for i in 0..40 {
            let b = bytes(5000, i);
            j.append(&b).unwrap();
            all.extend_from_slice(&b);
        }
        let before: Vec<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|f| std::fs::read(f.unwrap().path()).unwrap())
            .collect();
        let old_key = *j.key;
        j.rotate_key().unwrap();
        assert_ne!(old_key, *j.key);
        assert_eq!(j.read(0, 1 << 30).unwrap(), all);
        let after: Vec<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|f| std::fs::read(f.unwrap().path()).unwrap())
            .collect();
        for a in &after {
            assert!(!before.contains(a), "every file was rewritten");
        }
        // The old key opens nothing that is on disk now.
        let e = &j.spill[0];
        let framed = {
            let mut f = File::open(j.file_path(e.file).unwrap()).unwrap();
            f.seek(SeekFrom::Start(e.at)).unwrap();
            let mut len = [0u8; 4];
            f.read_exact(&mut len).unwrap();
            let mut v = vec![0u8; 4 + u32::from_be_bytes(len) as usize];
            v[..4].copy_from_slice(&len);
            f.read_exact(&mut v[4..]).unwrap();
            v
        };
        assert!(open(&old_key, e.start, &framed).is_err());
        // Appending after a rotation keeps working.
        j.append(b"more").unwrap();
        all.extend_from_slice(b"more");
        assert_eq!(j.read(0, 1 << 30).unwrap(), all);
    }

    #[test]
    fn dropping_the_journal_removes_the_spill() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        {
            let mut j = Journal::new(32 * 1024, 1 << 20, Some(dir.clone())).unwrap();
            j.append(&bytes(100_000, 3)).unwrap();
            j.append(&bytes(100_000, 3)).unwrap();
            assert!(dir.exists());
        }
        assert!(!dir.exists());
    }
}
