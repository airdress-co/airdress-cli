//! Fault injection at the record level (design §14.3), on simulated time.
//!
//! The network between the reference host and its clients delays each
//! message by 50–400 ms (which reorders them), duplicates some records,
//! and cuts legs: hard cuts of 0.5–10 s, an address change (a cut with an
//! immediate reconnect), the relay's 300 s idle cut, and cuts past the
//! 120 s ticket life. The pass criteria are the design's:
//!
//! - no lost or duplicated output bytes after a resume (the client's stream
//!   against the host's journal);
//! - resume < 2 s p95 for cuts under 5 s;
//! - no unlock prompt for cuts under 120 s;
//! - an unlock prompt (phone) for cuts over 120 s.
//!
//! `tests/netem.rs` runs the same shape over real sockets under `tc netem`.

use airdress_shell_proto::conformance::world::{FaultPlan, World};
use proptest::prelude::*;

const S: &str = "s1";
const P: &str = "api";

fn world(seed: &[u8], plan: FaultPlan) -> World {
    let mut w = World::new(seed, plan);
    w.add_device("phone", true, "phone", "Galaxy S23").unwrap();
    w.add_device("cli", false, "cli", "airdress CLI").unwrap();
    w
}

fn faulty() -> FaultPlan {
    FaultPlan {
        delay_min_ms: 50,
        delay_max_ms: 400,
        duplicate_per_mille: 30,
    }
}

/// Stream output every `tick` ms for `ms`, cutting `device` at the given
/// (start offset, outage) pairs.
fn drive(w: &mut World, device: &str, ms: u64, tick: u64, cuts: &[(u64, u64)]) {
    let start = w.now;
    let mut n = 0u64;
    let mut pending: Vec<(u64, u64)> = cuts.iter().map(|(at, len)| (start + at, *len)).collect();
    pending.sort();
    let mut reconnect_at: Option<u64> = None;
    let mut t = start;
    while t < start + ms {
        t += tick;
        w.run_until(t);
        n += 1;
        w.output(
            S,
            format!("line {n:05} {}\r\n", "x".repeat((n % 37) as usize)).as_bytes(),
        );
        if let Some(&(at, len)) = pending.first() {
            if t >= at && reconnect_at.is_none() {
                w.cut(device, S);
                reconnect_at = Some(t + len);
                pending.remove(0);
            }
        }
        if let Some(r) = reconnect_at {
            if t >= r {
                w.reconnect(device, S, P);
                reconnect_at = None;
            }
        }
    }
    if reconnect_at.is_some() {
        w.reconnect(device, S, P);
    }
    w.settle();
}

fn stream_ok(w: &World, device: &str) {
    let got = &w.clients[device].leg(S).unwrap().stream;
    let want = w.host.journal(S);
    assert_eq!(got.len(), want.len(), "{device}: byte count differs");
    assert!(got == &want, "{device}: stream differs from the journal");
}

fn p95(mut v: Vec<u64>) -> u64 {
    assert!(!v.is_empty());
    v.sort();
    v[((v.len() as f64) * 0.95).ceil() as usize - 1]
}

fn opened(seed: &[u8]) -> World {
    let mut w = world(seed, faulty());
    w.open("phone", S, P);
    w.settle();
    w.attach("cli", S, P);
    w.settle();
    assert_eq!(w.clients["phone"].unlocks, 1);
    w
}

#[test]
fn short_cuts_resume_fast_with_no_unlock_and_no_byte_lost() {
    let mut latencies = Vec::new();
    for seed in 0..12u8 {
        let mut w = opened(&[b'a', seed]);
        let cuts: Vec<(u64, u64)> = (0..6)
            .map(|i| (2_000 + i * 6_000, 500 + (i * 900) % 4_500))
            .collect();
        drive(&mut w, "phone", 40_000, 20, &cuts);
        stream_ok(&w, "phone");
        stream_ok(&w, "cli");
        assert_eq!(
            w.clients["phone"].unlocks, 1,
            "seed {seed}: a cut under 120 s asked for an unlock"
        );
        let st = &w.stats[&(S.to_owned(), "phone".to_owned())];
        assert_eq!(st.reattached, 0, "seed {seed}: fell back to a reattach");
        latencies.extend(st.reconnect_ms.iter().copied());
    }
    assert!(latencies.len() >= 60);
    let p = p95(latencies);
    assert!(p < 2_000, "resume p95 {p} ms");
}

#[test]
fn long_cuts_up_to_ten_seconds_still_resume() {
    let mut w = opened(b"long");
    drive(
        &mut w,
        "phone",
        60_000,
        50,
        &[(1_000, 10_000), (20_000, 7_500), (40_000, 9_999)],
    );
    stream_ok(&w, "phone");
    assert_eq!(w.clients["phone"].unlocks, 1);
}

#[test]
fn address_change_is_an_immediate_reconnect() {
    let mut w = opened(b"addr");
    drive(
        &mut w,
        "phone",
        20_000,
        20,
        &[(1_000, 0), (1_500, 0), (5_000, 0)],
    );
    stream_ok(&w, "phone");
    assert_eq!(w.clients["phone"].unlocks, 1);
}

#[test]
fn the_relay_idle_cut_after_300_s_resumes() {
    // No output for 300 s, the relay cuts the idle leg, the client comes
    // straight back: a resume, not an unlock.
    let mut w = opened(b"idle");
    let t = w.now + 300_000;
    w.run_until(t);
    w.cut("phone", S);
    w.reconnect("phone", S, P);
    w.settle();
    w.output(S, b"after the idle cut\r\n");
    w.settle();
    stream_ok(&w, "phone");
    assert_eq!(w.clients["phone"].unlocks, 1);
}

#[test]
fn a_cut_past_120_s_asks_for_an_unlock_and_the_cli_does_not() {
    let mut w = opened(b"long-cut");
    drive(&mut w, "phone", 130_000, 100, &[(1_000, 121_000)]);
    stream_ok(&w, "phone");
    assert_eq!(
        w.clients["phone"].unlocks, 2,
        "the reattach after 121 s asks once"
    );
    assert_eq!(w.stats[&(S.to_owned(), "phone".to_owned())].reattached, 1);

    drive(&mut w, "cli", 130_000, 100, &[(1_000, 121_000)]);
    stream_ok(&w, "cli");
    assert_eq!(w.clients["cli"].unlocks, 0, "a Linux CLI never asks (D-30)");
}

#[test]
fn a_cut_in_the_middle_of_a_resume_costs_no_unlock() {
    // Cut again while the resume handshake is in flight, many times over.
    for seed in 0..8u8 {
        let mut w = opened(&[b'm', seed]);
        let cuts: Vec<(u64, u64)> = (0..10)
            .map(|i| (1_000 + i * 1_200, 300 + (seed as u64 * 70) % 500))
            .collect();
        drive(&mut w, "phone", 20_000, 20, &cuts);
        stream_ok(&w, "phone");
        assert_eq!(w.clients["phone"].unlocks, 1, "seed {seed}");
    }
}

#[test]
fn a_handshake_without_its_unlock_cannot_be_resumed() {
    // The phone completes the open handshake, but its presence record is
    // lost with the leg. Its ticket was never admitted, so coming back is a
    // full handshake with an unlock, and nothing was spawned before it.
    let mut w = world(
        b"no-unlock",
        FaultPlan {
            delay_min_ms: 100,
            delay_max_ms: 100,
            duplicate_per_mille: 0,
        },
    );
    w.open("phone", S, P);
    w.run_until(250); // msg2 arrived at 200; the presence record lands at 300
    assert!(!w.host.spawned(S));
    w.cut("phone", S);
    w.settle();
    assert!(!w.host.spawned(S), "spawned without an unlock");
    w.reconnect("phone", S, P);
    w.settle();
    // The open's session never started, so the reattach is refused too;
    // what matters is that no resume was admitted.
    assert!(w.host.unlocks_verified.is_empty());
    assert!(!w.host.spawned(S));
}

#[test]
fn duplicates_are_refused_not_doubled() {
    let mut w = world(
        b"dups",
        FaultPlan {
            delay_min_ms: 10,
            delay_max_ms: 300,
            duplicate_per_mille: 400,
        },
    );
    w.open("phone", S, P);
    w.settle();
    drive(&mut w, "phone", 10_000, 10, &[]);
    stream_ok(&w, "phone");
    let refused = w.clients["phone"].leg(S).unwrap().refused_records;
    assert!(refused > 50, "only {refused} duplicates were refused");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn any_schedule_of_short_cuts_loses_and_doubles_nothing(
        seed in any::<u64>(),
        cuts in prop::collection::vec((500u64..4_000, 0u64..4_999), 0..8),
        dup in 0u32..200,
    ) {
        let mut w = World::new(&seed.to_be_bytes(), FaultPlan { delay_min_ms: 50, delay_max_ms: 400, duplicate_per_mille: dup });
        w.add_device("phone", true, "phone", "Galaxy S23").unwrap();
        w.open("phone", S, P);
        w.settle();
        let mut at = 0;
        let sched: Vec<(u64, u64)> = cuts.iter().map(|(gap, len)| { at += gap + len; (at - len, *len) }).collect();
        drive(&mut w, "phone", at + 2_000, 25, &sched);
        let got = &w.clients["phone"].leg(S).unwrap().stream;
        prop_assert_eq!(got, &w.host.journal(S));
        prop_assert_eq!(w.clients["phone"].unlocks, 1);
    }
}
