//! Measures the snapshot emulator for docs/terminal-emulator.md: a program
//! is run on a 120x40 PTY, its output fed to the emulator, and the snapshot
//! replayed into a fresh one; the two screens are compared. Not a test:
//! `cargo run -p airdress-shell-host --example emulator_measure -- <program> [args…]`.
#![allow(
    clippy::print_stdout,
    reason = "a measurement tool that reports on stdout"
)]
use std::time::Duration;

use airdress_shell_host::emulator::Emulator;
use airdress_shell_host::environment::SessionEnv;
use airdress_shell_host::profiles::ProcessSpec;
use airdress_shell_host::pty::{spawn, PtyEvent};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let program = args.next().expect("a program");
    if program == "--memory" {
        let before = rss_kib();
        let mut v: Vec<Emulator> = (0..10).map(|_| Emulator::new(120, 40, 2000)).collect();
        let empty = rss_kib();
        let line = format!("{}\r\n", "x".repeat(119));
        for e in &mut v {
            for _ in 0..2100 {
                e.process(line.as_bytes());
            }
        }
        let full = rss_kib();
        println!(
            "per 120x40 session: empty ≈ {} KiB, with 2,000 lines of scrollback ≈ {} KiB",
            (empty - before) / 10,
            (full - before) / 10
        );
        return;
    }
    let rest: Vec<String> = args.collect();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut env = SessionEnv::default();
    env.vars.insert("TERM".into(), "xterm-256color".into());
    env.vars
        .insert("HOME".into(), std::env::var_os("HOME").unwrap());
    env.vars
        .insert("PATH".into(), std::env::var_os("PATH").unwrap());
    let spec = ProcessSpec {
        program: program.into(),
        args: rest,
        cwd: "/".into(),
        env_allow: vec![],
        env_set: Default::default(),
    };
    let pty = spawn(&spec, &env, 120, 40, tx).unwrap();
    let mut e = Emulator::new(120, 40, 2000);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if let PtyEvent::Output(b) = ev {
            e.process(&b);
        }
    }
    let snap = e.snapshot(60 * 1024);
    let mut r = Emulator::new(120, 40, 2000);
    r.process(&snap);
    let same_text = r.text() == e.text();
    let same_cursor = r.cursor() == e.cursor();
    println!(
        "{}: snapshot {} bytes, text equal: {same_text}, cursor equal: {same_cursor}, grid+scrollback ≈ {} KiB",
        spec.program.display(),
        snap.len(),
        e.approx_bytes() / 1024
    );
    pty.kill();
}

/// Resident memory of ten 120x40 emulators, empty and with their 2,000
/// lines of scrollback full: `--example emulator_measure -- --memory`.
#[allow(dead_code)]
fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = s.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4
}
