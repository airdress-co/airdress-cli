//! A device's leg to one session, over the operator's P transport (design
//! §5.1, §8.4): server-sent events down, `POST …/frames` up.
//!
//! **Why P, not W, for the CLI.** The operator's W route (`…/stream`)
//! attaches a writer without replaying what the leg already buffered, so a
//! host's message 2 that arrives before the WebSocket is up is lost, and the
//! open stalls. The SSE route replays everything after `Last-Event-ID`, so
//! the first connection asks from 0 and nothing is lost, however quickly the
//! host answers. Records go up the moment they are typed: there is no
//! batching window, only what is already queued (at most 16 per request).
//!
//! **A network change** first reconnects the same leg: the operator keeps a
//! P leg while its idle timer runs, and `Last-Event-ID` picks up after the
//! last record this device saw. Only when the leg itself is gone (`404`)
//! does the session resume on a new leg with its ticket (`Lost`).

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::api::{seg, ShellApi};
use crate::log_err::LogErr as _;

/// Most records one upstream request carries.
pub const MAX_RECORDS_PER_POST: usize = 16;
/// Most records waiting to go up (R-ASY-5): four full requests. A record
/// is one sealed inner message (a keystroke batch of at most 4 KiB from
/// the terminal reader), so this holds at most about 256 KiB. When it is
/// full [`Leg::send`] waits, the session loop stops reading the terminal,
/// and the terminal reader blocks: typing slows to what the operator takes.
pub const UP_QUEUE: usize = 4 * MAX_RECORDS_PER_POST;
/// How often a broken event stream is retried on the same leg before the
/// leg is reported lost.
const SAME_LEG_RETRIES: u32 = 3;

/// What happens on a leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegEvent {
    /// One end-to-end record from the host.
    Record(Vec<u8>),
    /// The operator closed the leg, with a code and a reason (design §13).
    Closed {
        /// The close code (4001, 4003, …).
        code: u16,
        /// The reason: a design §13 code.
        reason: String,
    },
    /// The leg is unreachable: the network, or the operator forgot it.
    Lost(String),
}

/// A connected leg.
pub struct Leg {
    /// The leg id.
    pub id: String,
    up: mpsc::Sender<Vec<u8>>,
    down: mpsc::Receiver<LegEvent>,
    tasks: Vec<JoinHandle<()>>,
}

impl core::fmt::Debug for Leg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Leg").field("id", &self.id).finish()
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sse {
    /// `id:`.
    pub id: Option<String>,
    /// `event:`.
    pub event: Option<String>,
    /// `data:` lines, joined with `\n`.
    pub data: String,
}

/// Splits a byte stream into events; comments (keepalives) are dropped.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: String,
}

impl SseParser {
    /// Feed bytes; returns every complete event.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Sse> {
        self.buf
            .push_str(&String::from_utf8_lossy(bytes).replace('\r', ""));
        let mut out = Vec::new();
        while let Some(end) = self.buf.find("\n\n") {
            let block: String = self.buf.drain(..end + 2).collect();
            let mut ev = Sse::default();
            let mut any = false;
            for line in block.lines() {
                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                let (k, v) = line.split_once(':').unwrap_or((line, ""));
                let v = v.strip_prefix(' ').unwrap_or(v);
                any = true;
                match k {
                    "id" => ev.id = Some(v.to_owned()),
                    "event" => ev.event = Some(v.to_owned()),
                    "data" => {
                        if !ev.data.is_empty() {
                            ev.data.push('\n');
                        }
                        ev.data.push_str(v);
                    }
                    _ => {}
                }
            }
            if any {
                out.push(ev);
            }
        }
        out
    }
}

fn decode(data: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let d = data.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(d).ok())
}

impl Leg {
    /// Connect to `leg` on the operator `api` speaks to.
    pub fn connect(api: &ShellApi, leg: &str) -> Self {
        let (down_tx, down) = mpsc::channel(1024);
        let (up, up_rx) = mpsc::channel(UP_QUEUE);
        let reader = tokio::spawn(read_events(api.clone(), leg.to_owned(), down_tx.clone()));
        let writer = tokio::spawn(write_frames(api.clone(), leg.to_owned(), up_rx, down_tx));
        Self {
            id: leg.to_owned(),
            up,
            down,
            tasks: vec![reader, writer],
        }
    }

    /// Queue one record for the host, waiting while [`UP_QUEUE`] records
    /// are already waiting. A leg whose writer has ended (it reported the
    /// leg lost, and the loss arrives on [`Leg::recv`]) takes nothing.
    ///
    /// Not cancel-safe: a record is dropped if this is cancelled while it
    /// waits. Call it from an arm's body, never as a `select!` branch.
    pub async fn send(&self, record: Vec<u8>) {
        // Closed: the writer ended and has said why on the down channel.
        self.up
            .send(record)
            .await
            .log_debug("queueing a record for the host");
    }

    /// The next event; `None` once both directions have ended.
    pub async fn recv(&mut self) -> Option<LegEvent> {
        self.down.recv().await
    }
}

async fn read_events(api: ShellApi, leg: String, tx: mpsc::Sender<LegEvent>) {
    let url = format!("{}/v1/shells/legs/{}/events", api.base(), seg(&leg));
    let mut last = "0".to_owned();
    let mut failures = 0u32;
    // A held stream: no request deadline, and a silence of
    // SHELL_STREAM_IDLE ends it (then the same leg again, from `last`).
    let stream = match crate::http::client_with(crate::http::Timeouts::stream(
        crate::http::SHELL_STREAM_IDLE,
    ))
    .tcp_nodelay(true)
    .build()
    {
        Ok(c) => c,
        Err(e) => {
            tx.send(LegEvent::Lost(e.to_string()))
                .await
                .log_debug("telling the session the leg ended");
            return;
        }
    };
    loop {
        let resp = stream
            .get(&url)
            .bearer_auth(api.bearer().expose())
            .header("accept", "text/event-stream")
            .header("last-event-id", &last)
            .send()
            .await;
        let mut resp = match resp {
            Ok(r) if r.status().is_success() => r,
            Ok(r) if r.status().as_u16() == 404 => {
                tx.send(LegEvent::Lost("shell_leg_not_found".into()))
                    .await
                    .log_debug("telling the session the leg ended");
                return;
            }
            Ok(r) => {
                let code = r.status().as_u16();
                let body: Value = r.json().await.unwrap_or(Value::Null);
                let reason = body["error"]["code"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("http_{code}"));
                if code == 401 || code == 403 {
                    tx.send(LegEvent::Closed { code, reason })
                        .await
                        .log_debug("telling the session the leg ended");
                    return;
                }
                failures += 1;
                if failures > SAME_LEG_RETRIES {
                    tx.send(LegEvent::Lost(reason))
                        .await
                        .log_debug("telling the session the leg ended");
                    return;
                }
                tokio::time::sleep(backoff(failures)).await;
                continue;
            }
            Err(e) => {
                failures += 1;
                if failures > SAME_LEG_RETRIES {
                    tx.send(LegEvent::Lost(e.to_string()))
                        .await
                        .log_debug("telling the session the leg ended");
                    return;
                }
                tokio::time::sleep(backoff(failures)).await;
                continue;
            }
        };
        let mut parser = SseParser::default();
        // Until the stream ends or breaks: then the same leg again, from
        // `last`.
        while let Ok(Some(bytes)) = resp.chunk().await {
            failures = 0;
            for ev in parser.feed(&bytes) {
                if ev.event.as_deref() == Some("closed") {
                    let v: Value = serde_json::from_str(&ev.data).unwrap_or(Value::Null);
                    tx.send(LegEvent::Closed {
                        code: v["code"].as_u64().unwrap_or(4001) as u16,
                        reason: v["reason"].as_str().unwrap_or("closed").to_owned(),
                    })
                    .await
                    .log_debug("telling the session the leg ended");
                    return;
                }
                if let Some(id) = ev.id {
                    last = id;
                }
                if let Some(rec) = decode(&ev.data) {
                    if tx.send(LegEvent::Record(rec)).await.is_err() {
                        return;
                    }
                }
            }
        }
        failures += 1;
        if failures > SAME_LEG_RETRIES {
            tx.send(LegEvent::Lost("event stream ended".into()))
                .await
                .log_debug("telling the session the leg ended");
            return;
        }
        tokio::time::sleep(backoff(failures)).await;
    }
}

fn backoff(n: u32) -> Duration {
    jitter(Duration::from_millis(100 * (1 << n.min(4)) as u64))
}

/// `d` with full-range jitter in its upper half: somewhere in `[d/2, d]`.
/// Devices that lost the same host at the same instant then do not come
/// back in step.
pub fn jitter(d: Duration) -> Duration {
    use rand::Rng as _;
    let half = d / 2;
    half + half.mul_f64(rand::thread_rng().gen::<f64>())
}

/// Exponential backoff with jitter, for every path that reconnects to a
/// session (design §6.5, §7.3).
///
/// Found live on VM3 (2026-10-04): after a host restart two CLIs retried
/// with no wait at all between a refused resume and the reattach that
/// followed it, 373 refusals in about 15 s. Every attempt now waits
/// [`Backoff::wait`], which doubles from `base` to `cap`; a leg that comes
/// back live resets it.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    /// Doubling from `base`, never above `cap`.
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    /// The wait before the next attempt; each call counts one attempt.
    pub fn wait(&mut self) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32 << self.attempt.min(16))
            .min(self.cap);
        self.attempt = self.attempt.saturating_add(1);
        jitter(exp)
    }

    /// Attempts made since the last reset.
    pub fn attempts(&self) -> u32 {
        self.attempt
    }

    /// The connection is back: the next loss starts from `base` again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

async fn write_frames(
    api: ShellApi,
    leg: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<LegEvent>,
) {
    let url = format!("{}/v1/shells/legs/{}/frames", api.base(), seg(&leg));
    while let Some(first) = rx.recv().await {
        let mut batch = vec![STANDARD.encode(first)];
        while batch.len() < MAX_RECORDS_PER_POST {
            match rx.try_recv() {
                Ok(r) => batch.push(STANDARD.encode(r)),
                Err(_) => break,
            }
        }
        let mut sent = false;
        for attempt in 0..=SAME_LEG_RETRIES {
            let r = api
                .http()
                .post(&url)
                .bearer_auth(api.bearer().expose())
                .json(&json!({ "records": batch }))
                .send()
                .await;
            match r {
                Ok(r) if r.status().is_success() => {
                    sent = true;
                    break;
                }
                Ok(r) if r.status().as_u16() == 404 => break,
                Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 403 => break,
                _ => tokio::time::sleep(backoff(attempt + 1)).await,
            }
        }
        if !sent {
            // Close the up queue first: a sender waiting for room wakes and
            // takes nothing, rather than waiting on a writer that is itself
            // waiting for room on the down queue.
            drop(rx);
            tx.send(LegEvent::Lost("records could not reach the host".into()))
                .await
                .log_debug("telling the session the leg ended");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_split_across_reads_and_keepalives_are_dropped() {
        let mut p = SseParser::default();
        assert!(p.feed(b": keepalive\n\nid: 1\ndata: AAE").is_empty());
        let evs = p.feed(b"C\n\nevent: closed\ndata: {\"code\":4003}\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].id.as_deref(), Some("1"));
        assert_eq!(decode(&evs[0].data), Some(vec![0, 1, 2]));
        assert_eq!(evs[1].event.as_deref(), Some("closed"));
    }

    #[test]
    fn backoff_doubles_to_its_cap_with_jitter_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(200), Duration::from_secs(5));
        let waits: Vec<Duration> = (0..10).map(|_| b.wait()).collect();
        for (i, w) in waits.iter().enumerate() {
            let exp = Duration::from_millis(200 * (1u64 << i)).min(Duration::from_secs(5));
            assert!(
                *w >= exp / 2 && *w <= exp,
                "attempt {i}: {w:?} not in [{:?}, {exp:?}]",
                exp / 2
            );
        }
        assert_eq!(b.attempts(), 10);
        b.reset();
        assert!(b.wait() <= Duration::from_millis(200));
        // Jitter: a hundred devices do not all pick the same instant.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..100 {
            seen.insert(Backoff::new(Duration::from_secs(1), Duration::from_secs(1)).wait());
        }
        assert!(seen.len() > 50, "{}", seen.len());
    }

    #[test]
    fn carriage_returns_are_tolerated() {
        let mut p = SseParser::default();
        let evs = p.feed(b"id: 7\r\ndata: AA==\r\n\r\n");
        assert_eq!(evs[0].id.as_deref(), Some("7"));
        assert_eq!(decode(&evs[0].data), Some(vec![0]));
    }
}
