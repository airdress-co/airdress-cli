//! The explicit-nonce record layer, its replay window, and rekey (design §6.5).
//!
//! Noise's own transport assumes ordered, lossless delivery, and a reconnect
//! loses records in flight. So each record carries its nonce in the clear:
//!
//! ```text
//! record = n (u64, big-endian) ‖ ChaChaPoly(k, n, ad = "", payload)
//! ```
//!
//! The AEAD is exactly Noise's `ENCRYPT(k, n, ad, plaintext)` for
//! `ChaChaPoly` (a 96-bit nonce of four zero bytes and `n` little-endian), so
//! a record is byte-for-byte what snow's stateless transport would produce
//! for the same key and nonce; a test holds that. The receiver accepts each
//! nonce once, within a window of [`REPLAY_WINDOW`] behind the highest seen.
//!
//! **Rekey** is Noise's `REKEY(k)`, per direction, at [`REKEY_INTERVAL_MS`]
//! or [`REKEY_BYTES`], and on demand. Nonces keep counting across a rekey;
//! the sender announces the first nonce under the new key in an inner
//! `rekey` message (sealed under the old key, at the nonce just before it).
//! Because records may arrive reordered, the receiver does not depend on
//! seeing that message first: a record that fails under its newest key is
//! tried once under `REKEY` of it, and an older key is kept until the window
//! has moved past the switch.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::error::{ProtoError, Result};

/// Bytes of clear nonce at the front of every record.
pub const NONCE_LEN: usize = 8;
/// Bytes of AEAD tag at the end of every record.
pub const TAG_LEN: usize = 16;
/// The receiver accepts a nonce at most this far behind the highest seen.
pub const REPLAY_WINDOW: u64 = 1024;
/// The largest plaintext one record may carry. Terminal output arrives in
/// far smaller pieces; the bound exists so a receiver can size its buffers.
pub const MAX_PLAINTEXT: usize = 256 * 1024;
/// Rekey a direction after this long under one key.
pub const REKEY_INTERVAL_MS: u64 = 60 * 60 * 1000;
/// Rekey a direction after this many plaintext bytes under one key.
pub const REKEY_BYTES: u64 = 1 << 30;
/// Noise reserves the maximum nonce for `REKEY`.
const RESERVED_NONCE: u64 = u64::MAX;
/// At most this many key generations are held for receiving.
const MAX_RECV_GENERATIONS: usize = 3;

fn noise_nonce(n: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(nonce)
}

/// Noise `ENCRYPT(k, n, ad, plaintext)` with ChaChaPoly.
pub(crate) fn noise_encrypt(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            &noise_nonce(n),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("ChaCha20Poly1305 encryption of an in-memory buffer cannot fail")
}

/// Noise `DECRYPT(k, n, ad, ciphertext)` with ChaChaPoly.
pub(crate) fn noise_decrypt(key: &[u8; 32], n: u64, ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(&noise_nonce(n), Payload { msg: ct, aad: ad })
        .ok()
}

/// Noise `REKEY(k)`: the first 32 bytes of `ENCRYPT(k, 2^64-1, "", zeros)`.
/// A one-way function of the old key.
pub fn rekey(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let ct = Zeroizing::new(noise_encrypt(key, RESERVED_NONCE, &[], &[0u8; 32]));
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&ct[..32]);
    out
}

/// The sending half of a channel.
pub struct SendState {
    key: Zeroizing<[u8; 32]>,
    next: u64,
    switch_at: Option<u64>,
    bytes_under_key: u64,
    keyed_at_ms: u64,
}

impl std::fmt::Debug for SendState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendState")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl SendState {
    /// A sender starting at nonce 0 under `key`, keyed at `now_ms`.
    pub fn new(key: [u8; 32], now_ms: u64) -> Self {
        Self {
            key: Zeroizing::new(key),
            next: 0,
            switch_at: None,
            bytes_under_key: 0,
            keyed_at_ms: now_ms,
        }
    }

    /// Seal one record at the next nonce.
    pub fn seal(&mut self, plaintext: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(ProtoError::InvalidInput("record plaintext too large"));
        }
        if self.switch_at == Some(self.next) {
            self.key = rekey(&self.key);
            self.switch_at = None;
            self.bytes_under_key = 0;
            self.keyed_at_ms = now_ms;
        }
        let n = self.next;
        if n >= RESERVED_NONCE - 1 {
            return Err(ProtoError::NonceExhausted);
        }
        self.next += 1;
        self.bytes_under_key = self.bytes_under_key.saturating_add(plaintext.len() as u64);
        let ct = noise_encrypt(&self.key, n, &[], plaintext);
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Whether this direction has been under one key for an hour or 1 GiB.
    pub fn rekey_due(&self, now_ms: u64) -> bool {
        self.switch_at.is_none()
            && (now_ms.saturating_sub(self.keyed_at_ms) >= REKEY_INTERVAL_MS
                || self.bytes_under_key >= REKEY_BYTES)
    }

    /// Arrange a rekey: the next record is sealed under the current key, and
    /// every record after it under `REKEY(k)`. Returns the switch-over nonce,
    /// which the caller announces in that next record (an inner `rekey`).
    pub fn schedule_rekey(&mut self) -> u64 {
        let at = self.next + 1;
        self.switch_at = Some(at);
        at
    }

    /// The nonce the next record will carry.
    pub fn next_nonce(&self) -> u64 {
        self.next
    }
}

/// A sliding window over the last [`REPLAY_WINDOW`] nonces.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bits: [0; (REPLAY_WINDOW / 64) as usize],
        }
    }
}

impl ReplayWindow {
    fn bit(n: u64) -> (usize, u64) {
        let i = n % REPLAY_WINDOW;
        ((i / 64) as usize, 1u64 << (i % 64))
    }

    /// Whether `n` would be accepted. Does not record it.
    pub fn check(&self, n: u64) -> Result<()> {
        match self.highest {
            None => Ok(()),
            Some(h) if n > h => Ok(()),
            Some(h) if h - n >= REPLAY_WINDOW => Err(ProtoError::Replay),
            Some(_) => {
                let (w, m) = Self::bit(n);
                if self.bits[w] & m != 0 {
                    Err(ProtoError::Replay)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Record `n` as seen. Call only after the record authenticated.
    pub fn mark(&mut self, n: u64) {
        match self.highest {
            Some(h) if n <= h => {}
            Some(h) => {
                if n - h >= REPLAY_WINDOW {
                    self.bits = [0; (REPLAY_WINDOW / 64) as usize];
                } else {
                    for k in (h + 1)..=n {
                        let (w, m) = Self::bit(k);
                        self.bits[w] &= !m;
                    }
                }
                self.highest = Some(n);
            }
            None => {
                self.highest = Some(n);
            }
        }
        let (w, m) = Self::bit(n);
        self.bits[w] |= m;
    }

    /// The highest nonce accepted so far.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }
}

struct RecvGeneration {
    key: Zeroizing<[u8; 32]>,
    /// The first nonce under this key: announced by the peer, or the lowest
    /// one seen to authenticate under it.
    start: u64,
    announced: bool,
}

/// The receiving half of a channel.
pub struct RecvState {
    gens: Vec<RecvGeneration>,
    window: ReplayWindow,
}

impl std::fmt::Debug for RecvState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvState").finish_non_exhaustive()
    }
}

impl RecvState {
    /// A receiver for a peer starting at nonce 0 under `key`.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            gens: vec![RecvGeneration {
                key: Zeroizing::new(key),
                start: 0,
                announced: true,
            }],
            window: ReplayWindow::default(),
        }
    }

    /// Open one record: check the window, authenticate, then mark the nonce.
    /// Returns the nonce and the plaintext.
    pub fn open(&mut self, record: &[u8]) -> Result<(u64, Vec<u8>)> {
        if record.len() < NONCE_LEN + TAG_LEN {
            return Err(ProtoError::RecordMalformed);
        }
        let mut nb = [0u8; NONCE_LEN];
        nb.copy_from_slice(&record[..NONCE_LEN]);
        let n = u64::from_be_bytes(nb);
        if n >= RESERVED_NONCE - 1 {
            return Err(ProtoError::RecordMalformed);
        }
        let ct = &record[NONCE_LEN..];
        if ct.len() - TAG_LEN > MAX_PLAINTEXT {
            return Err(ProtoError::RecordMalformed);
        }
        self.window.check(n)?;

        // Newest generation first: steady state is one AEAD per record.
        for i in (0..self.gens.len()).rev() {
            let g = &self.gens[i];
            if g.announced && n < g.start {
                continue;
            }
            // An announced switch is a boundary: the old key opens nothing
            // at or past it.
            if let Some(succ) = self.gens.get(i + 1) {
                if succ.announced && n >= succ.start {
                    continue;
                }
            }
            if let Some(pt) = noise_decrypt(&g.key, n, &[], ct) {
                if !self.gens[i].announced && n < self.gens[i].start {
                    self.gens[i].start = n;
                }
                self.accept(n);
                return Ok((n, pt));
            }
        }
        // A record from the peer's next key, overtaking its announcement.
        let newest = self.gens.last().expect("at least one generation");
        if n > newest.start {
            let next = rekey(&newest.key);
            if let Some(pt) = noise_decrypt(&next, n, &[], ct) {
                self.push_generation(next, n, false);
                self.accept(n);
                return Ok((n, pt));
            }
        }
        Err(ProtoError::RecordAuth)
    }

    /// The peer announced (in an inner `rekey`) that its key changes at
    /// `switch_at`. Records from `switch_at` on are opened under the next
    /// key only.
    pub fn note_peer_rekey(&mut self, switch_at: u64) {
        let newest = self.gens.last_mut().expect("at least one generation");
        if !newest.announced && newest.start >= switch_at {
            // Already derived from a record that overtook the announcement.
            newest.start = switch_at;
            newest.announced = true;
            return;
        }
        if newest.announced && newest.start >= switch_at {
            return; // a repeat of an announcement already applied
        }
        let next = rekey(&newest.key);
        self.push_generation(next, switch_at, true);
    }

    fn push_generation(&mut self, key: Zeroizing<[u8; 32]>, start: u64, announced: bool) {
        self.gens.push(RecvGeneration {
            key,
            start,
            announced,
        });
        while self.gens.len() > MAX_RECV_GENERATIONS {
            self.gens.remove(0);
        }
    }

    fn accept(&mut self, n: u64) {
        self.window.mark(n);
        // Drop generations no record inside the window can still need.
        if let Some(h) = self.window.highest() {
            while self.gens.len() > 1 && h.saturating_sub(REPLAY_WINDOW) >= self.gens[1].start {
                self.gens.remove(0);
            }
        }
    }

    /// How many key generations are held. For tests and for the rekey
    /// bound on revocation (design §6.7).
    pub fn generations(&self) -> usize {
        self.gens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_replay() {
        let mut s = SendState::new([1; 32], 0);
        let mut r = RecvState::new([1; 32]);
        let a = s.seal(b"one", 0).unwrap();
        let b = s.seal(b"two", 0).unwrap();
        assert_eq!(r.open(&b).unwrap(), (1, b"two".to_vec()));
        assert_eq!(r.open(&a).unwrap(), (0, b"one".to_vec()));
        assert_eq!(r.open(&a), Err(ProtoError::Replay));
        assert_eq!(r.open(&b), Err(ProtoError::Replay));
    }

    #[test]
    fn a_failed_record_does_not_burn_its_nonce() {
        let mut s = SendState::new([1; 32], 0);
        let mut r = RecvState::new([1; 32]);
        let a = s.seal(b"one", 0).unwrap();
        let mut forged = a.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(r.open(&forged), Err(ProtoError::RecordAuth));
        assert!(r.open(&a).is_ok());
    }

    #[test]
    fn window_edge() {
        let mut w = ReplayWindow::default();
        w.mark(2000);
        assert!(w.check(2000 - REPLAY_WINDOW + 1).is_ok());
        assert_eq!(w.check(2000 - REPLAY_WINDOW), Err(ProtoError::Replay));
        assert!(w.check(2001).is_ok());
        w.mark(2000 + REPLAY_WINDOW * 3);
        assert_eq!(w.check(2000), Err(ProtoError::Replay));
    }

    #[test]
    fn scheduled_rekey_in_order() {
        let mut s = SendState::new([9; 32], 0);
        let mut r = RecvState::new([9; 32]);
        let first = s.seal(b"before", 0).unwrap();
        let at = s.schedule_rekey();
        let notice = s.seal(b"notice", 0).unwrap();
        let after = s.seal(b"after", 0).unwrap();
        assert_eq!(at, 2);
        r.open(&first).unwrap();
        r.open(&notice).unwrap();
        r.note_peer_rekey(at);
        assert_eq!(r.open(&after).unwrap().1, b"after");
    }

    #[test]
    fn rekey_survives_reordering_past_the_announcement() {
        let mut s = SendState::new([9; 32], 0);
        let mut r = RecvState::new([9; 32]);
        let at = s.schedule_rekey();
        let notice = s.seal(b"notice", 0).unwrap();
        let after1 = s.seal(b"a1", 0).unwrap();
        let after2 = s.seal(b"a2", 0).unwrap();
        // The new-key records overtake the notice.
        assert_eq!(r.open(&after2).unwrap().1, b"a2");
        assert_eq!(r.open(&after1).unwrap().1, b"a1");
        assert_eq!(r.open(&notice).unwrap().1, b"notice");
        r.note_peer_rekey(at);
        assert!(r.generations() <= 2);
    }

    #[test]
    fn old_key_records_are_refused_after_the_switch() {
        // A record forged under the old key at a nonce past the switch
        // must not open: the switch is a boundary, not a suggestion.
        let mut s = SendState::new([5; 32], 0);
        let mut r = RecvState::new([5; 32]);
        let at = s.schedule_rekey();
        let notice = s.seal(b"n", 0).unwrap();
        r.open(&notice).unwrap();
        r.note_peer_rekey(at);
        let mut old = vec![];
        old.extend_from_slice(&5u64.to_be_bytes());
        old.extend_from_slice(&noise_encrypt(&[5; 32], 5, &[], b"stale"));
        assert_eq!(r.open(&old), Err(ProtoError::RecordAuth));
    }

    #[test]
    fn rekey_due_by_time_and_bytes() {
        let mut s = SendState::new([1; 32], 1000);
        assert!(!s.rekey_due(1000));
        assert!(s.rekey_due(1000 + REKEY_INTERVAL_MS));
        s.bytes_under_key = REKEY_BYTES;
        assert!(s.rekey_due(1001));
        s.schedule_rekey();
        assert!(!s.rekey_due(1001), "a scheduled rekey is not due twice");
        s.seal(b"notice", 2000).unwrap();
        s.seal(b"first under the new key", 2000).unwrap();
        assert!(!s.rekey_due(2001));
    }

    #[test]
    fn matches_snow_stateless_transport_and_its_rekey() {
        // The record AEAD is Noise's own; snow, given the same key, must
        // produce the same ciphertext, before and after REKEY.
        use snow::params::NoiseParams;
        let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let resolver = crate::handshake::test_resolver();
        let mut i = snow::Builder::with_resolver(params.clone(), resolver())
            .build_initiator()
            .unwrap();
        let mut rsp = snow::Builder::with_resolver(params, resolver())
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 256];
        let mut pl = [0u8; 256];
        let n = i.write_message(&[], &mut buf).unwrap();
        rsp.read_message(&buf[..n], &mut pl).unwrap();
        let n = rsp.write_message(&[], &mut buf).unwrap();
        i.read_message(&buf[..n], &mut pl).unwrap();
        let (k_i2r, _) = i.dangerously_get_raw_split();
        let mut t = i.into_stateless_transport_mode().unwrap();

        let mut out = [0u8; 64];
        let len = t.write_message(7, b"hello", &mut out).unwrap();
        assert_eq!(
            &out[..len],
            noise_encrypt(&k_i2r, 7, &[], b"hello").as_slice()
        );

        t.rekey_outgoing();
        let len = t.write_message(8, b"hello", &mut out).unwrap();
        let k2 = rekey(&k_i2r);
        assert_eq!(&out[..len], noise_encrypt(&k2, 8, &[], b"hello").as_slice());
    }
}
