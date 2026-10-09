//! Fault injection over real sockets (design §14.3), for a Linux runner
//! with `tc netem` on the loopback interface.
//!
//! ```text
//! client ──TCP──▶ proxy (the operator's place: cuts, idle cut) ──TCP──▶ host
//! ```
//!
//! The reference host and client speak the real protocol over TCP; the
//! proxy injects hard cuts (it closes both sides and refuses connections
//! for the outage), and closes a leg idle for longer than its idle limit
//! (the relay's 300 s cut, scaled down). `netem`, set up by CI, adds delay,
//! jitter, loss and reordering underneath. Every reconnect is a new TCP
//! connection from a new source port: an address change.
//!
//! Ignored by default (it takes half a minute of wall time). CI runs it with
//! `cargo test --features conformance --test netem -- --ignored` after
//! `tc qdisc add dev lo root netem …`.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use airdress_shell_proto::conformance::{Outbound, RefClient, RefHost};
use airdress_shell_proto::prologue::Action;
use airdress_shell_proto::ticket::TicketId;

const S: &str = "s1";
const P: &str = "api";
const DEVICE: &str = "phone";

const T_HELLO: u8 = 1;
const T_MSG2: u8 = 3;
const T_REFUSED: u8 = 4;
const T_RECORD: u8 = 5;

fn write_frame(s: &mut TcpStream, t: u8, body: &[u8]) -> std::io::Result<()> {
    let mut f = Vec::with_capacity(5 + body.len());
    f.push(t);
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    s.write_all(&f)
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    s.read_exact(&mut h)?;
    let len = u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize;
    if len > 1 << 20 {
        return Err(ErrorKind::InvalidData.into());
    }
    let mut b = vec![0u8; len];
    s.read_exact(&mut b)?;
    Ok((h[0], b))
}

struct Clock(Instant);
impl Clock {
    fn ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

// --------------------------------------------------------------------------
// The host side.

/// The live leg of each (session, device): its connection id and writer.
type Legs = HashMap<(String, String), (u64, Sender<Vec<u8>>)>;

struct HostState {
    host: RefHost,
    legs: Legs,
}

fn dispatch(st: &mut HostState, out: Vec<Outbound>) {
    for o in out {
        if let Some((_, tx)) = st.legs.get(&(o.session.clone(), o.device.clone())) {
            if let Err(e) = tx.send(o.record) {
                eprintln!("best effort, the peer may have gone: {e}");
            }
        }
    }
}

fn host_conn(mut s: TcpStream, st: Arc<Mutex<HostState>>, clock: Arc<Clock>, id: u64) {
    s.set_nodelay(true).ok();
    let Ok((T_HELLO, hello)) = read_frame(&mut s) else {
        return;
    };
    let hello: serde_json::Value = serde_json::from_slice(&hello).unwrap();
    let Ok((_, msg1)) = read_frame(&mut s) else {
        return;
    };
    let kind = hello["kind"].as_str().unwrap().to_owned();
    let now = clock.ms();
    let (tx, rx) = channel::<Vec<u8>>();
    let reply = {
        let mut g = st.lock().unwrap();
        let r = match kind.as_str() {
            "open" => g.host.open(S, P, DEVICE, &msg1, now),
            "attach" => g.host.attach(S, DEVICE, &msg1, now),
            _ => {
                let t = TicketId::decode(hello["ticket"].as_str().unwrap()).unwrap();
                g.host.resume(S, DEVICE, &t, &msg1, now)
            }
        };
        if r.is_ok() {
            g.legs.insert((S.into(), DEVICE.into()), (id, tx));
        }
        r
    };
    match reply {
        Ok(m2) => {
            if write_frame(&mut s, T_MSG2, &m2).is_err() {
                return;
            }
        }
        Err(e) => {
            if let Err(e) = write_frame(&mut s, T_REFUSED, e.code().as_bytes()) {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            return;
        }
    }
    // Writer: records the host sends on this leg.
    let mut w = s.try_clone().unwrap();
    thread::spawn(move || {
        while let Ok(r) = rx.recv() {
            if write_frame(&mut w, T_RECORD, &r).is_err() {
                break;
            }
        }
        if let Err(e) = w.shutdown(Shutdown::Both) {
            eprintln!("best effort, the peer may have gone: {e}");
        }
    });
    // Reader: records from the device.
    while let Ok((T_RECORD, rec)) = read_frame(&mut s) {
        let mut g = st.lock().unwrap();
        let now = clock.ms();
        if let Ok(out) = g.host.record(S, DEVICE, &rec, now) {
            dispatch(&mut g, out);
        }
    }
    let mut g = st.lock().unwrap();
    if g.legs
        .get(&(S.to_owned(), DEVICE.to_owned()))
        .is_some_and(|(i, _)| *i == id)
    {
        g.legs.remove(&(S.to_owned(), DEVICE.to_owned()));
        let now = clock.ms();
        g.host.leg_dropped(S, DEVICE, now);
    }
}

// --------------------------------------------------------------------------
// The proxy: the operator's place on the path.

struct Proxy {
    down: AtomicBool,
    generation: AtomicU64,
    idle_ms: u64,
}

fn pipe(mut from: TcpStream, mut to: TcpStream, last: Arc<AtomicU64>, clock: Arc<Clock>) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                last.store(clock.ms(), Ordering::Relaxed);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    if let Err(e) = from.shutdown(Shutdown::Both) {
        eprintln!("best effort, the peer may have gone: {e}");
    }
    if let Err(e) = to.shutdown(Shutdown::Both) {
        eprintln!("best effort, the peer may have gone: {e}");
    }
}

fn run_proxy(
    listener: TcpListener,
    host_addr: std::net::SocketAddr,
    px: Arc<Proxy>,
    clock: Arc<Clock>,
) {
    for c in listener.incoming() {
        let Ok(c) = c else { continue };
        if px.down.load(Ordering::SeqCst) {
            if let Err(e) = c.shutdown(Shutdown::Both) {
                eprintln!("best effort, the peer may have gone: {e}");
            }
            continue;
        }
        let Ok(h) = TcpStream::connect(host_addr) else {
            continue;
        };
        c.set_nodelay(true).ok();
        h.set_nodelay(true).ok();
        let generation = px.generation.load(Ordering::SeqCst);
        let last = Arc::new(AtomicU64::new(clock.ms()));
        let (c2, h2) = (c.try_clone().unwrap(), h.try_clone().unwrap());
        let (cw, hw) = (c.try_clone().unwrap(), h.try_clone().unwrap());
        let (l1, l2, k1, k2) = (last.clone(), last.clone(), clock.clone(), clock.clone());
        thread::spawn(move || pipe(c2, h2, l1, k1));
        thread::spawn(move || pipe(h, c, l2, k2));
        let (px2, k3) = (px.clone(), clock.clone());
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(50));
            let cut = px2.generation.load(Ordering::SeqCst) != generation;
            let idle = k3.ms().saturating_sub(last.load(Ordering::Relaxed)) > px2.idle_ms;
            if cut || idle {
                if let Err(e) = cw.shutdown(Shutdown::Both) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
                if let Err(e) = hw.shutdown(Shutdown::Both) {
                    eprintln!("best effort, the peer may have gone: {e}");
                }
                break;
            }
        });
    }
}

// --------------------------------------------------------------------------
// The client.

struct ClientReport {
    stream: Vec<u8>,
    unlocks: u32,
    resume_ms: Vec<u64>,
    reattaches: u32,
}

fn client_loop(
    proxy_addr: std::net::SocketAddr,
    host_pin: [u8; 32],
    stop: Arc<AtomicBool>,
    clock: Arc<Clock>,
    report: Arc<Mutex<ClientReport>>,
) {
    let mut c = RefClient::new(
        b"netem phone",
        DEVICE,
        "principal-1",
        true,
        host_pin,
        "airdress-test",
        "machine-1",
    );
    let mut first = true;
    let mut fallback = false;
    let mut force_attach = false;
    while !stop.load(Ordering::SeqCst) {
        let Ok(mut s) = TcpStream::connect(proxy_addr) else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        s.set_nodelay(true).ok();
        let connected_at = clock.ms();
        let (hello, m1) = if first {
            (
                serde_json::json!({"kind": "open"}),
                c.begin(S, P, Action::Open).unwrap(),
            )
        } else if force_attach {
            (
                serde_json::json!({"kind": "attach"}),
                c.begin(S, P, Action::Attach).unwrap(),
            )
        } else {
            let r = if fallback {
                c.fallback_resume(S)
            } else {
                c.begin_resume(S)
            };
            match r {
                Ok((t, m1)) => (
                    serde_json::json!({"kind": "resume", "ticket": t.encode()}),
                    m1,
                ),
                Err(_) => {
                    report.lock().unwrap().reattaches += 1;
                    (
                        serde_json::json!({"kind": "attach"}),
                        c.begin(S, P, Action::Attach).unwrap(),
                    )
                }
            }
        };
        let resuming = !first;
        if write_frame(&mut s, T_HELLO, hello.to_string().as_bytes()).is_err()
            || write_frame(&mut s, 2, &m1).is_err()
        {
            continue;
        }
        match read_frame(&mut s) {
            Ok((T_MSG2, m2)) => {
                fallback = false;
                force_attach = false;
                let Ok(rec) = c.finish(S, &m2, clock.ms()) else {
                    continue;
                };
                first = false;
                if write_frame(&mut s, T_RECORD, &rec).is_err() {
                    continue;
                }
            }
            Ok((T_REFUSED, code)) => {
                if code == b"shell_resume_expired" {
                    if fallback {
                        force_attach = true;
                    }
                    fallback = !fallback;
                }
                continue;
            }
            _ => continue,
        }
        s.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let mut measured = !resuming;
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            match read_frame(&mut s) {
                Ok((T_RECORD, rec)) => {
                    if !measured {
                        report
                            .lock()
                            .unwrap()
                            .resume_ms
                            .push(clock.ms() - connected_at);
                        measured = true;
                    }
                    if let Ok(replies) = c.receive(S, &rec, clock.ms()) {
                        for r in replies {
                            if let Err(e) = write_frame(&mut s, T_RECORD, &r) {
                                eprintln!("best effort, the peer may have gone: {e}");
                            }
                        }
                    }
                    let mut g = report.lock().unwrap();
                    g.stream = c.leg(S).unwrap().stream.clone();
                    g.unlocks = c.unlocks;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    continue
                }
                _ => break,
            }
        }
    }
}

#[test]
#[ignore = "wall-clock harness; CI runs it under tc netem"]
fn real_sockets_with_cuts_idle_cut_and_netem() {
    let clock = Arc::new(Clock(Instant::now()));
    let host_l = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_addr = host_l.local_addr().unwrap();
    let proxy_l = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_l.local_addr().unwrap();

    let mut host = RefHost::new(b"netem host", "airdress-test", "machine-1", "principal-1");
    let probe = RefClient::new(
        b"netem phone",
        DEVICE,
        "principal-1",
        true,
        host.public(),
        "airdress-test",
        "machine-1",
    );
    let (keys, sig) = probe.statement();
    host.trust(keys, sig, "phone", "Galaxy S23").unwrap();
    let pin = host.public();
    let st = Arc::new(Mutex::new(HostState {
        host,
        legs: HashMap::new(),
    }));

    {
        let (st, clock) = (st.clone(), clock.clone());
        thread::spawn(move || {
            for (id, c) in host_l.incoming().enumerate() {
                if let Ok(c) = c {
                    let (st, clock) = (st.clone(), clock.clone());
                    thread::spawn(move || host_conn(c, st, clock, id as u64));
                }
            }
        });
    }
    // The relay's 300 s idle cut, scaled to 3 s.
    let px = Arc::new(Proxy {
        down: AtomicBool::new(false),
        generation: AtomicU64::new(0),
        idle_ms: 3_000,
    });
    {
        let (px, clock) = (px.clone(), clock.clone());
        thread::spawn(move || run_proxy(proxy_l, host_addr, px, clock));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let report = Arc::new(Mutex::new(ClientReport {
        stream: vec![],
        unlocks: 0,
        resume_ms: vec![],
        reattaches: 0,
    }));
    {
        let (stop, clock, report) = (stop.clone(), clock.clone(), report.clone());
        thread::spawn(move || client_loop(proxy_addr, pin, stop, clock, report));
    }

    // Wait for the session.
    let t0 = Instant::now();
    while !st.lock().unwrap().host.spawned(S) {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "the session never opened"
        );
        thread::sleep(Duration::from_millis(20));
    }

    // (start s, outage ms): hard cuts from 0.5 s to 4.5 s; then a quiet
    // spell long enough for the idle cut.
    let cuts = [
        (2.0, 500u64),
        (5.0, 1_500),
        (9.0, 4_500),
        (16.0, 800),
        (19.0, 2_500),
    ];
    let quiet = (24.0, 4.0);
    let end = 32.0;
    let start = Instant::now();
    let mut n = 0u64;
    let mut next_cut = 0;
    while start.elapsed().as_secs_f64() < end {
        let t = start.elapsed().as_secs_f64();
        if next_cut < cuts.len() && t >= cuts[next_cut].0 {
            px.down.store(true, Ordering::SeqCst);
            px.generation.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(cuts[next_cut].1));
            px.down.store(false, Ordering::SeqCst);
            next_cut += 1;
        }
        if !(t >= quiet.0 && t < quiet.0 + quiet.1) {
            n += 1;
            let mut g = st.lock().unwrap();
            let now = clock.ms();
            let out = g
                .host
                .output(S, format!("line {n:05}\r\n").as_bytes(), now)
                .unwrap();
            dispatch(&mut g, out);
        }
        thread::sleep(Duration::from_millis(20));
    }
    // Let the client catch up.
    let journal = st.lock().unwrap().host.journal(S);
    let t1 = Instant::now();
    while report.lock().unwrap().stream.len() < journal.len()
        && t1.elapsed() < Duration::from_secs(15)
    {
        thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::SeqCst);
    let r = report.lock().unwrap();
    assert_eq!(r.stream.len(), journal.len(), "bytes lost");
    assert!(r.stream == journal, "stream differs from the journal");
    assert_eq!(
        r.unlocks, 1,
        "a cut under 120 s asked for an unlock ({} reattaches)",
        r.reattaches
    );
    let mut v = r.resume_ms.clone();
    assert!(v.len() >= cuts.len(), "only {} resumes", v.len());
    v.sort();
    let p95 = v[((v.len() as f64) * 0.95).ceil() as usize - 1];
    eprintln!("resumes {}: {:?} ms, p95 {p95} ms", v.len(), v);
    assert!(p95 < 2_000, "resume p95 {p95} ms");
}
