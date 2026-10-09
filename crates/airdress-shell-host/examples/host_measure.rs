//! Measures a real `airdress shell host` process against the test kit's
//! mock operator: its idle cost with one held channel (NFR-3), and its
//! memory and responsiveness through a 50 MiB flood to a viewer that does
//! not keep up (NFR-4). Prints numbers; asserts nothing.
#![allow(
    clippy::print_stdout,
    reason = "a measurement tool that reports on stdout"
)]

use std::time::{Duration, Instant};

use airdress_shell_host::testkit::{delegation, Client, Device, FromHost, Inbox, MockOperator};
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::prologue::Action;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::json;
use uuid::Uuid;

fn status_kib(pid: u32, field: &str) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn cpu_ticks(pid: u32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let after = s.rsplit(')').next().unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    f.get(11).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        + f.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let bin = std::env::args().nth(1).expect("the airdress binary");
    let idle_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".config/airdress")).unwrap();
    let big = dir.path().join("big.txt");
    {
        let line = format!("{}\n", "0123456789abcdef".repeat(7));
        let mut s = String::with_capacity(50 << 20);
        while s.len() < 50 << 20 {
            s.push_str(&line);
        }
        std::fs::write(&big, s).unwrap();
    }
    let profiles = home.join(".config/airdress/shells.toml");
    std::fs::write(
        &profiles,
        "[[profile]]\nid = \"sh\"\nprogram = \"/bin/sh\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (mock, rx) = MockOperator::start([42; 32]).await;
    let (machine, principal) = (Uuid::new_v4(), Uuid::new_v4());
    let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    mock.approve(machine, principal, Some(root.verifying_key().to_bytes()));
    let mut child = std::process::Command::new(&bin)
        .args(["shell", "host", "--operator", &mock.origin])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut inbox = Inbox::new(rx);
    let info = inbox.frame("host_info").await.expect("host_info");
    let pin: [u8; 32] = STANDARD
        .decode(info["shellKeyPublic"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    // NFR-3: idle, one channel, pinged every 30 s.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (t0, c0) = (Instant::now(), cpu_ticks(pid));
    tokio::time::sleep(Duration::from_secs(idle_secs)).await;
    let cpu = (cpu_ticks(pid) - c0) as f64 / 100.0 / t0.elapsed().as_secs_f64() * 100.0;
    println!(
        "idle, no session: RSS {} KiB, CPU {cpu:.3} % over {idle_secs} s",
        status_kib(pid, "VmRSS:")
    );

    // A session, then 50 MiB to a viewer that never acks.
    let dev = Device::cli(1, "measure");
    let deleg = delegation(&root, &dev.identity_public(), "127.0.0.1", "cli");
    let mut c = Client::new(dev, pin, "127.0.0.1", machine, Uuid::new_v4(), "sh");
    let leg = Uuid::new_v4();
    let msg1 = c.begin(Action::Open);
    mock.send("open", json!({ "sessionId": c.session, "leg": leg, "profile": "sh", "cols": 120, "rows": 40, "attestation": c.dev.attestation(principal, Some(deleg)), "handshake": STANDARD.encode(msg1) }));
    let msg2 = inbox.record(leg).await.unwrap();
    let first = c.finish(&msg2);
    mock.send_data(c.session, leg, &first);
    inbox.frame("opened").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("one idle session: RSS {} KiB", status_kib(pid, "VmRSS:"));
    let r = c.send(&[Message::In {
        data: format!("cat {}; echo MARK-$((6*7))\n", big.display()).into_bytes(),
    }]);
    mock.send_data(c.session, leg, &r);
    let flood = Instant::now();
    let mut peak = 0;
    // The viewer reads nothing back; the host must drain the PTY anyway.
    loop {
        peak = peak.max(status_kib(pid, "VmRSS:"));
        if flood.elapsed() > Duration::from_secs(60) {
            break;
        }
        // Done when the shell has printed its mark: catch up (an ack past
        // the end gets the lagging viewer a snapshot) and look.
        let r = c.send(&[Message::Ack {
            offset: u64::MAX / 2,
        }]);
        mock.send_data(c.session, leg, &r);
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            if let Some(rec) = inbox
                .take(Duration::from_millis(50), |m| match m {
                    FromHost::Data { leg: l, record, .. } if *l == leg => Some(record.clone()),
                    _ => None,
                })
                .await
            {
                if let Err(e) = c.receive(&rec) {
                    eprintln!("a record did not open: {e}");
                }
            }
        }
        if c.text().contains("MARK-42") {
            break;
        }
    }
    println!(
        "50 MiB flood to a lagging viewer: drained in {:.1} s, peak RSS {} KiB (VmHWM {} KiB)",
        flood.elapsed().as_secs_f64(),
        peak,
        status_kib(pid, "VmHWM:")
    );
    // A keystroke after the flood: time to its echo.
    let r = c.send(&[Message::In {
        data: b"x".to_vec(),
    }]);
    let t = Instant::now();
    mock.send_data(c.session, leg, &r);
    let mut echoed = false;
    while t.elapsed() < Duration::from_secs(5) && !echoed {
        if let Some(rec) = inbox
            .take(Duration::from_millis(100), |m| match m {
                FromHost::Data { leg: l, record, .. } if *l == leg => Some(record.clone()),
                _ => None,
            })
            .await
        {
            if let Err(e) = c.receive(&rec) {
                eprintln!("a record did not open: {e}");
            }
            echoed =
                c.text().contains("$ x") || c.text().lines().any(|l| l.trim_end().ends_with('x'));
        }
    }
    println!(
        "echo of a keystroke after the flood: {} ms (echoed: {echoed})",
        t.elapsed().as_millis()
    );
    let stop = Instant::now();
    if let Err(e) = std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
    {
        eprintln!("could not run kill: {e}");
    }
    if inbox.closed(Duration::from_secs(15)).await.is_none() {
        eprintln!("the channel did not close within 15 s");
    }
    println!(
        "Ctrl-C to channel closed: {} ms",
        stop.elapsed().as_millis()
    );
    if let Err(e) = child.wait() {
        eprintln!("could not reap the host: {e}");
    }
}
