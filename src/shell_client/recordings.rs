//! `airdress shell recordings ls|play` (design §7.9, §10.2, task D.5).
//!
//! A recording is sealed on the host to the shell keys of its person's
//! devices, and the host forgets each segment's content key when the
//! segment ends: it cannot read its own file. This device lists and
//! fetches recordings **over its end-to-end channel** with the host — the
//! operator relays the records and never sees a byte of them — unwraps its
//! own key, and plays them here at their own pace.
//!
//! A channel exists only on a session, so listing and fetching attach to a
//! running session on that host as a viewer (never taking input). On the
//! host machine itself, `play --file` reads a segment file directly.

use std::io::Write;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use serde_json::Value;

use airdress_shell_proto::inner::{Message, RecordingInfo};
use airdress_shell_proto::recording::{SegmentHeader, SegmentReader};

use super::leg::LegEvent;
use super::run::Conn;
use super::session::Event;

/// How long to wait for the host to answer a recording request.
const ANSWER_WAIT: Duration = Duration::from_secs(20);
/// After a segment's header, how long to wait for a chunk that does not
/// come: the host sends every chunk it has at once, so a pause this long
/// means a segment still being written (or one cut short).
const MORE_WAIT: Duration = Duration::from_secs(3);

/// One output event of an asciicast stream.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Seconds since the start.
    pub time: f64,
    /// The bytes written.
    pub data: Vec<u8>,
}

/// Parse asciicast v2 event lines (`[time, "o", data]`). The header line,
/// input (`"i"`) and other event kinds are skipped; a malformed line is an
/// error, since a sealed chunk that opened is not expected to hold one.
pub fn parse_cast(text: &[u8]) -> Result<Vec<Frame>> {
    let mut out = Vec::new();
    for (n, line) in String::from_utf8_lossy(text).lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("recording line {} is not JSON", n + 1))?;
        let Some(ev) = v.as_array() else {
            continue; // the header object
        };
        if ev.len() < 3 || ev[1].as_str() != Some("o") {
            continue;
        }
        let time = ev[0]
            .as_f64()
            .with_context(|| format!("recording line {} has no time", n + 1))?;
        let data = ev[2].as_str().unwrap_or_default().as_bytes().to_vec();
        out.push(Frame { time, data });
    }
    Ok(out)
}

/// Play frames to `out`: each pause scaled by `speed` and capped at
/// `max_idle`, so a recording left idle overnight does not take a night.
pub async fn play(
    frames: &[Frame],
    out: &mut dyn Write,
    speed: f64,
    max_idle: Duration,
) -> Result<()> {
    let speed = if speed > 0.0 { speed } else { 1.0 };
    let mut prev = 0.0f64;
    for f in frames {
        let dt = ((f.time - prev).max(0.0) / speed).min(max_idle.as_secs_f64());
        prev = f.time;
        if dt > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(dt)).await;
        }
        out.write_all(&f.data)?;
        out.flush()?;
    }
    Ok(())
}

/// Decrypt one segment file on disk with this device's key.
pub fn open_file(bytes: &[u8], device: &str, secret: &[u8; 32]) -> Result<(Vec<u8>, bool)> {
    let c = SegmentReader::read_file(bytes, device, secret).map_err(|e| {
        anyhow!("this device cannot open that recording ({e}); it was not a recipient")
    })?;
    Ok((c.data, c.complete))
}

/// Drive the connection until it is live (the handshake done and the host
/// heard), then until `want` returns a value.
async fn until<T>(
    conn: &mut Conn,
    epoch: std::time::Instant,
    wait: Duration,
    mut want: impl FnMut(&Event) -> Option<T>,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let leg = conn.leg.as_mut().context("no connection to the session")?;
        let ev = tokio::time::timeout_at(deadline, leg.recv())
            .await
            .map_err(|_| anyhow!("the host did not answer in time"))?
            .unwrap_or_else(|| LegEvent::Lost("leg ended".into()));
        let now = epoch.elapsed().as_millis() as u64;
        match ev {
            LegEvent::Record(rec) if conn.cs.awaiting_msg2() => {
                let (_, out) = conn.cs.finish(&rec, now)?;
                for r in out {
                    conn.leg.as_ref().expect("present").send(r).await;
                }
            }
            LegEvent::Record(rec) => {
                let (events, replies) = match conn.cs.receive(&rec, now) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                for r in replies {
                    conn.leg.as_ref().expect("present").send(r).await;
                }
                for e in &events {
                    if let Event::Error { code, message } = e {
                        if code.starts_with("shell_recording") {
                            bail!("{}", super::api::explain(code, message));
                        }
                    }
                    if let Some(t) = want(e) {
                        return Ok(t);
                    }
                }
            }
            LegEvent::Closed { reason, .. } | LegEvent::Lost(reason) => {
                bail!(
                    "the connection to the session ended: {}",
                    super::api::explain(&reason, "")
                );
            }
        }
    }
}

/// Wait until the channel is live: the host admitted this attach and sent
/// its snapshot. Once only: a connection that is already live is not sent
/// another snapshot, and waiting for one is what made `recordings play`
/// time out with a live session (found live on VM3, 2026-10-04: `ls`
/// answered, `play` — which lists first on the same connection — never did,
/// and the host logged nothing, because the fetch was never sent).
async fn live(conn: &mut Conn, epoch: std::time::Instant) -> Result<()> {
    if conn.cs.is_live() {
        return Ok(());
    }
    until(conn, epoch, ANSWER_WAIT, |e| {
        matches!(e, Event::Redraw { .. }).then_some(())
    })
    .await
}

async fn send(conn: &mut Conn, m: Message, epoch: std::time::Instant) -> Result<()> {
    let rec = conn.cs.seal(&[m], epoch.elapsed().as_millis() as u64)?;
    conn.leg.as_ref().context("no leg")?.send(rec).await;
    Ok(())
}

/// List the host's recordings for this person.
pub async fn list(conn: &mut Conn) -> Result<Vec<RecordingInfo>> {
    let epoch = std::time::Instant::now();
    live(conn, epoch).await?;
    send(conn, Message::RecordingList, epoch).await?;
    until(conn, epoch, ANSWER_WAIT, |e| match e {
        Event::RecordingListing(r) => Some(r.clone()),
        _ => None,
    })
    .await
}

/// Fetch one recording's segments and open them with this device's key.
/// Returns the plaintext and whether every segment was complete.
pub async fn fetch(
    conn: &mut Conn,
    recording: &str,
    segments: u32,
    device: &str,
    secret: &[u8; 32],
) -> Result<(Vec<u8>, bool)> {
    let epoch = std::time::Instant::now();
    live(conn, epoch).await?;
    let mut data = Vec::new();
    let mut complete = true;
    for segment in 0..segments.max(1) {
        send(
            conn,
            Message::RecordingFetch {
                recording: recording.to_owned(),
                segment,
                from_chunk: 0,
            },
            epoch,
        )
        .await?;
        let header = until(conn, epoch, ANSWER_WAIT, |e| match e {
            Event::RecordingHeader {
                recording: r,
                segment: s,
                header,
            } if r == recording && *s == segment => Some(header.clone()),
            _ => None,
        })
        .await?;
        let (header, _) = SegmentHeader::parse(&header)
            .map_err(|e| anyhow!("the segment header does not read: {e}"))?;
        let reader = SegmentReader::open(&header, device, secret).map_err(|e| {
            anyhow!("this device cannot open segment {segment} ({e}); it was not a recipient")
        })?;
        let mut next = 0u64;
        loop {
            let got = until(conn, epoch, MORE_WAIT, |e| match e {
                Event::RecordingChunk {
                    segment: s,
                    index,
                    sealed,
                } if *s == segment => Some((*index, sealed.clone())),
                _ => None,
            })
            .await;
            let Ok((index, sealed)) = got else {
                // No more chunks within the wait: a segment still being
                // written, or cut short.
                complete = false;
                break;
            };
            if index != next {
                bail!("chunk {index} arrived where {next} was expected");
            }
            let (pt, last) = reader
                .open_chunk(index, &sealed)
                .map_err(|e| anyhow!("chunk {index} does not open: {e}"))?;
            data.extend_from_slice(&pt);
            next += 1;
            if last {
                break;
            }
        }
    }
    Ok((data, complete))
}

#[cfg(test)]
mod tests {
    use super::*;
    use airdress_shell_proto::keys::ShellKeypair;
    use airdress_shell_proto::recording::{Recipient, SegmentWriter};

    #[test]
    fn asciicast_events_are_read_and_the_header_skipped() {
        let text = b"{\"version\": 2, \"width\": 80, \"height\": 24}\n\
                     [0.5, \"o\", \"hello \"]\n[0.6, \"i\", \"x\"]\n[1.25, \"o\", \"world\\r\\n\"]\n";
        let f = parse_cast(text).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].data, b"hello ");
        assert_eq!(f[1].time, 1.25);
        assert_eq!(f[1].data, b"world\r\n");
        assert!(parse_cast(b"[1, \"o\"\n").is_err());
    }

    #[tokio::test]
    async fn play_caps_long_pauses() {
        let frames = vec![
            Frame {
                time: 0.0,
                data: b"a".to_vec(),
            },
            Frame {
                time: 3600.0,
                data: b"b".to_vec(),
            },
        ];
        let mut out = Vec::new();
        let t = std::time::Instant::now();
        play(&frames, &mut out, 1.0, Duration::from_millis(20))
            .await
            .unwrap();
        assert_eq!(out, b"ab");
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_file_opens_only_for_a_recipient() {
        let me = ShellKeypair::from_secret([5; 32]);
        let other = ShellKeypair::from_secret([6; 32]);
        let mut rng = rand::rngs::OsRng;
        let w = SegmentWriter::start(
            &mut rng,
            "s1",
            0,
            &[Recipient {
                device: "me".into(),
                public: *me.public(),
            }],
        )
        .unwrap();
        let mut file = w.header().to_bytes().unwrap();
        file.extend(w.finish(&mut rng, b"[0.1, \"o\", \"hi\"]\n").unwrap());
        let (data, complete) = open_file(&file, "me", me.secret()).unwrap();
        assert!(complete);
        assert_eq!(parse_cast(&data).unwrap()[0].data, b"hi");
        assert!(open_file(&file, "other", other.secret()).is_err());
    }
}
