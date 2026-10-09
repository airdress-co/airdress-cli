//! A real host, enrolled with a mock operator over the WebSocket, driven by
//! devices that speak the end-to-end protocol: the host role's tasks C.1 and
//! C.3–C.11 end to end, AC-16 included.

mod common;

use std::time::Duration;

use airdress_shell_host::testkit::{Device, FromHost};
use airdress_shell_proto::inner::Message;
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::prologue::Action;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::{rig, rig_with};
use serde_json::json;
use uuid::Uuid;

const PROFILES: &str = r#"
[[profile]]
id = "cat"
label = "cat"
program = "/bin/cat"

[[profile]]
id = "env"
label = "env"
program = "/usr/bin/env"
env_allow = ["LANG"]

[[profile]]
id = "ticker"
label = "ticker"
program = "/bin/sh"
args = ["-c", "i=0; while [ $i -lt 400 ]; do i=$((i+1)); echo tick $i; sleep 0.02; done; sleep 30"]

[[profile]]
id = "stubborn"
label = "ignores SIGHUP"
program = "/bin/sh"
args = ["-c", "trap '' HUP; echo trapped; while :; do sleep 1; done"]

[[profile]]
id = "brief"
label = "short-lived"
program = "/bin/cat"
idle_timeout = "1s"
max_lifetime = "3s"

[[profile]]
id = "rec"
label = "recorded"
program = "/bin/cat"
record = true
"#;

#[tokio::test]
async fn it_enrolls_as_a_shell_host_and_publishes_hashes_not_definitions() {
    let r = rig(PROFILES, true).await;
    assert_eq!(r.mock.purpose().as_deref(), Some("shell-host"));
    assert_eq!(r.mock.transport(), Some("ws"));
    assert!(
        r.mock
            .keyids()
            .iter()
            .all(|k| k.starts_with(&format!("machine:{}#", r.machine))),
        "{:?}",
        r.mock.keyids()
    );
    // The binding: 0600, the person, the pins.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let m = std::fs::metadata(r.paths.binding())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o600);
    }
    let b = airdress_shell_host::binding::Binding::load(&r.paths)
        .unwrap()
        .unwrap();
    assert_eq!(b.principal.id, r.principal);
    assert_eq!(r.host_info["principalPin"], r.principal.to_string());
    assert_eq!(r.host_info["runsAsRoot"], false);
    assert_eq!(
        r.host_info["shellKey"],
        airdress_shell_proto::keys::fingerprint(&r.host_pin)
    );
    assert!(
        r.host_info["sig"].is_string(),
        "the machine signs its shell key"
    );
    // Profiles: ids, labels, states and hashes — no program, argument,
    // directory or environment, anywhere in the frame.
    let text = r.profiles.to_string();
    for word in [
        "/bin/cat",
        "/usr/bin/env",
        "program",
        "args",
        "cwd",
        "env_allow",
        "LANG",
        "trap",
    ] {
        assert!(!text.contains(word), "{word} leaked: {text}");
    }
    let ids: Vec<&str> = r.profiles["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["cat", "env", "ticker", "stubborn", "brief", "rec"]);
    assert!(r.profiles["profiles"][0]["definitionHash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    // A second host on the same machine refuses and names the first.
    let err = airdress_shell_host::binding::lock(&r.paths, &r.airdress)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!("pid {}", std::process::id())),
        "{err}"
    );
}

#[tokio::test]
async fn a_cli_opens_types_and_reads_its_echo_and_the_environment_is_only_the_profiles() {
    let mut r = rig(PROFILES, true).await;
    let dev = Device::cli(1, "laptop");
    let deleg = r.delegation(&dev, "cli");
    let mut c = r.client(dev, "cat");
    let leg = r.open(&mut c, "cat", Some(deleg.clone())).await;
    let opened = r.inbox.frame("opened").await.unwrap();
    assert_eq!(opened["sessionId"], c.session.to_string());
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    assert_eq!(c.typist.as_deref(), Some(c.dev.id.to_string().as_str()));
    r.say(
        &mut c,
        leg,
        &[Message::In {
            data: b"hello\n".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, leg, |c| c.text().matches("hello").count() >= 2)
            .await,
        "{}",
        c.text()
    );

    // `env` prints exactly what the session was given (FR-P7).
    let dev = Device::cli(2, "laptop 2");
    let deleg = r.delegation(&dev, "cli");
    let mut e = r.client(dev, "env");
    let leg = r.open(&mut e, "env", Some(deleg)).await;
    assert!(r.pump(&mut e, leg, |c| c.exit.is_some()).await);
    let mut names: Vec<String> = e
        .text()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_owned()))
        .collect();
    names.sort();
    let mut want = vec!["AIRDRESS_SHELL_SESSION", "COLORTERM", "TERM"];
    for n in ["HOME", "USER", "SHELL"] {
        if std::env::var_os(n).is_some() {
            want.push(n);
        }
    }
    // The locale is inherited without being allowed, and a session always
    // has one that decides the encoding.
    let set = |n: &str| std::env::var_os(n).is_some_and(|v| !v.is_empty());
    for n in airdress_shell_host::environment::LOCALE_VARS {
        if set(n) {
            want.push(n);
        }
    }
    if !["LANG", "LC_ALL", "LC_CTYPE"].iter().any(|n| set(n)) {
        want.push("LANG");
    }
    want.sort();
    assert_eq!(names, want, "{}", e.text());
}

#[tokio::test]
async fn a_resume_within_a_live_leg_needs_no_handshake_and_loses_nothing() {
    let mut r = rig(PROFILES, true).await;
    let dev = Device::cli(3, "laptop");
    let deleg = r.delegation(&dev, "cli");
    let mut c = r.client(dev, "ticker");
    let leg = r.open(&mut c, "ticker", Some(deleg.clone())).await;
    assert!(r.pump(&mut c, leg, |c| c.text().contains("tick 20")).await);
    // The leg drops (a network change): the operator says peer_gone.
    r.mock.send(
        "detach",
        json!({ "sessionId": c.session, "leg": leg, "reason": "peer_gone" }),
    );
    r.inbox.frame("detached").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let leg2 = r.resume(&mut c, Some(deleg)).await;
    assert!(
        r.pump(&mut c, leg2, |c| c.text().contains("tick 300"))
            .await
    );
    assert_eq!(c.snapshots, 0, "the journal had it all: no snapshot");
    // Contiguous: every tick that scrolled past was seen in order, so the
    // last screen lines count up by one.
    let nums: Vec<u32> = c
        .text()
        .lines()
        .filter_map(|l| l.strip_prefix("tick ")?.trim().parse().ok())
        .collect();
    assert!(nums.windows(2).all(|w| w[1] == w[0] + 1), "{nums:?}");
}

/// An idle session resumed (an operator restart under it, found live on
/// VM3 v0.1.119, 2026-10-05): the host has no new output, so it says who
/// has input, to the resumed device alone. Without it a client waiting to
/// hear the host before it counts the leg live waits for ever.
#[tokio::test]
async fn a_resumed_device_is_told_the_roles_even_when_nothing_is_new() {
    let mut r = rig(PROFILES, true).await;
    let dev = Device::cli(9, "laptop");
    let deleg = r.delegation(&dev, "cli");
    let mut c = r.client(dev, "cat");
    let leg = r.open(&mut c, "cat", Some(deleg.clone())).await;
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    r.say(
        &mut c,
        leg,
        &[Message::In {
            data: b"idle\n".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, leg, |c| c.text().matches("idle").count() >= 2)
            .await
    );
    let offset = c.offset;
    r.say(&mut c, leg, &[Message::Ack { offset }]);
    r.mock.send(
        "detach",
        json!({ "sessionId": c.session, "leg": leg, "reason": "peer_gone" }),
    );
    r.inbox.frame("detached").await.unwrap();
    c.typist = None;
    let leg2 = r.resume(&mut c, Some(deleg)).await;
    assert!(
        r.pump(&mut c, leg2, |c| c.reasons.last().map(String::as_str)
            == Some("resumed"))
            .await,
        "{:?}",
        c.reasons
    );
    assert_eq!(c.typist.as_deref(), Some(&*c.dev.id.to_string()));
    assert_eq!(c.snapshots, 0, "a resume replays, it does not redraw");
}

#[tokio::test]
async fn a_phone_attaches_with_its_unlock_takes_input_and_the_viewer_cannot_type() {
    let mut r = rig(PROFILES, true).await;
    let cli = Device::cli(4, "laptop");
    let cli_deleg = r.delegation(&cli, "cli");
    let mut c = r.client(cli, "cat");
    let cleg = r.open(&mut c, "cat", Some(cli_deleg)).await;
    r.say(
        &mut c,
        cleg,
        &[Message::In {
            data: b"before\n".to_vec(),
        }],
    );
    assert!(r.pump(&mut c, cleg, |c| c.text().contains("before")).await);

    let phone = Device::phone(5, "Galaxy");
    let phone_deleg = r.delegation(&phone, "phone");
    let mut p = r.client_for(phone, c.session, "cat");
    let pleg = r.attach(&mut p, Some(phone_deleg), true).await;
    assert!(r.pump(&mut p, pleg, |p| p.snapshots == 1).await);
    assert!(
        p.text().contains("before"),
        "the snapshot holds the screen: {}",
        p.text()
    );
    r.inbox.frame("attached").await.unwrap();
    // The phone is a viewer: its input is refused.
    r.say(
        &mut p,
        pleg,
        &[Message::In {
            data: b"x".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut p, pleg, |p| p
            .errors
            .contains(&"shell_input_not_held".to_owned()))
            .await
    );
    // It takes input; the laptop is told and becomes the viewer.
    r.say(&mut p, pleg, &[Message::TakeInput]);
    assert!(
        r.pump(&mut c, cleg, |c| c.typist.as_deref()
            == Some(&*p.dev.id.to_string()))
            .await
    );
    let moved = r
        .inbox
        .frame_where("input_moved", |v| v["client"] == p.dev.id.to_string())
        .await
        .unwrap();
    assert_eq!(moved["sessionId"], c.session.to_string());
    r.say(
        &mut p,
        pleg,
        &[Message::In {
            data: b"from phone\n".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c.text().contains("from phone"))
            .await
    );
    r.say(
        &mut c,
        cleg,
        &[Message::In {
            data: b"y".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c
            .errors
            .contains(&"shell_input_not_held".to_owned()))
            .await
    );
    // release_input (D-25) clears the typist.
    r.mock.send(
        "release_input",
        json!({ "sessionId": c.session, "device": p.dev.id }),
    );
    assert!(r.pump(&mut c, cleg, |c| c.typist.is_none()).await);
}

#[tokio::test]
async fn a_phone_that_does_not_unlock_is_never_attached() {
    let mut r = rig(PROFILES, true).await;
    let phone = Device::phone(6, "Galaxy");
    let deleg = r.delegation(&phone, "phone");
    let mut p = r.client(phone, "cat");
    let leg = r.open(&mut p, "cat", Some(deleg.clone())).await;
    let ok = r.inbox.frame("opened").await;
    assert!(ok.is_some(), "with the unlock it opens");
    // A second phone completes the handshake but sends `none`.
    let other = Device::phone(7, "other");
    let odeleg = r.delegation(&other, "phone");
    let mut o = r.client(other, "cat");
    let oleg = Uuid::new_v4();
    let msg1 = o.begin(Action::Open);
    r.mock.send("open", json!({
        "sessionId": o.session, "leg": oleg, "profile": "cat", "cols": 80, "rows": 24,
        "attestation": o.dev.attestation(r.principal, Some(odeleg)), "handshake": STANDARD.encode(msg1),
    }));
    let msg2 = r.inbox.record(oleg).await.unwrap();
    let first = o.finish_with(&msg2, false);
    r.mock.send_data(o.session, oleg, &first);
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == oleg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_presence_required");
    let rest = r.inbox.drain(Duration::from_millis(300)).await;
    assert!(!rest.iter().any(|m| matches!(m, FromHost::Frame(v) if v["type"] == "opened" && v["sessionId"] == o.session.to_string())), "nothing was spawned");
    let _ = leg;
}

#[tokio::test]
async fn a_doctored_operator_substituting_a_key_or_stripping_an_unlock_is_refused() {
    let mut r = rig(PROFILES, true).await;
    // (a) The operator keeps the real phone's delegation and substitutes its
    // own identity and shell keys, signing the statement itself.
    let phone = Device::phone(8, "Galaxy");
    let deleg = r.delegation(&phone, "phone");
    let evil = Device::phone(9, "evil");
    let mut c = r.client(evil, "cat");
    let leg = Uuid::new_v4();
    let msg1 = c.begin(Action::Open);
    let mut att = c.dev.attestation(r.principal, Some(deleg.clone()));
    att["device"] = json!(phone.id);
    r.mock.send("open", json!({ "sessionId": c.session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": att, "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert!(
        matches!(
            refused["code"].as_str(),
            Some("shell_handshake_failed" | "shell_presence_required")
        ),
        "{refused}"
    );
    // (b) The operator rewrites the real phone's registration to `none`.
    let mut p = r.client(phone, "cat");
    let leg = Uuid::new_v4();
    let msg1 = p.begin(Action::Open);
    let mut att = p.dev.attestation(r.principal, Some(deleg));
    att["presenceAlg"] = json!("none");
    att["presencePublic"] = serde_json::Value::Null;
    r.mock.send("open", json!({ "sessionId": p.session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": att, "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_presence_required");
    // Neither answered a handshake, nor spawned anything.
    let rest = r.inbox.drain(Duration::from_millis(300)).await;
    assert!(
        !rest.iter().any(|m| matches!(m, FromHost::Data { .. })),
        "no msg2 went out"
    );
    assert!(!rest
        .iter()
        .any(|m| matches!(m, FromHost::Frame(v) if v["type"] == "opened")));
}

#[tokio::test]
async fn revoking_a_device_cuts_it_off_rekeys_the_rest_and_keeps_the_session() {
    let mut r = rig(PROFILES, true).await;
    let cli = Device::cli(10, "laptop");
    let cd = r.delegation(&cli, "cli");
    let mut c = r.client(cli, "rec");
    let cleg = r.open(&mut c, "rec", Some(cd)).await;
    let phone = Device::phone(11, "Galaxy");
    let pd = r.delegation(&phone, "phone");
    let mut p = r.client_for(phone, c.session, "rec");
    let pleg = r.attach(&mut p, Some(pd.clone()), true).await;
    assert!(r.pump(&mut p, pleg, |p| p.snapshots == 1).await);
    // Whatever the phone was sent before the revoke.
    let _ = r.inbox.records(pleg, Duration::from_millis(300)).await;
    r.mock.send("revoke_device", json!({ "device": p.dev.id }));
    let d = r
        .inbox
        .frame_where("detached", |v| v["reason"] == "device_revoked")
        .await
        .unwrap();
    assert_eq!(d["client"], p.dev.id.to_string());
    assert!(
        r.pump(&mut c, cleg, |c| c.rekeys_seen >= 1
            && c.reasons.iter().any(|x| x == "Galaxy was signed out"))
            .await
    );
    // The session goes on for the laptop, under the new keys.
    r.say(
        &mut c,
        cleg,
        &[Message::In {
            data: b"still here\n".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, cleg, |c| c.text().matches("still here").count()
            >= 2)
            .await
    );
    // Nothing reaches the phone's leg any more, and it cannot come back.
    let after = r.inbox.records(pleg, Duration::from_millis(300)).await;
    assert!(after.is_empty());
    let leg = Uuid::new_v4();
    let msg1 = p.begin(Action::Attach);
    r.mock.send("attach", json!({ "sessionId": c.session, "leg": leg, "attestation": p.dev.attestation(r.principal, Some(pd)), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "device_revoked");
    let store = airdress_shell_host::trust::DeviceStore::load(&r.paths).unwrap();
    assert!(store.revoked.contains(&p.dev.id));
}

#[tokio::test]
async fn a_sub_user_device_needs_to_be_introduced_and_its_kind_comes_from_the_introduction() {
    let mut r = rig(PROFILES, true).await;
    // Operator-held devices of a sub-user carry no delegation.
    let phone = Device::phone(12, "Anna's phone");
    let mut p = r.client(phone, "cat");
    let leg = Uuid::new_v4();
    let msg1 = p.begin(Action::Open);
    r.mock.send("open", json!({ "sessionId": p.session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": p.dev.attestation(r.principal, None), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_device_not_introduced");
    // The person at the machine confirms it by fingerprint.
    let fp = airdress_shell_host::trust::identity_fingerprint(&p.dev.identity_public());
    airdress_shell_host::commands::trust(&r.paths, &fp, Some("phone"), &mut |_| Ok(())).unwrap();
    let mut p = r.client(Device::phone(12, "Anna's phone"), "cat");
    let pleg = r.open(&mut p, "cat", None).await;
    assert!(r.pump(&mut p, pleg, |p| p.typist.is_some()).await);
    // The phone introduces her laptop as a CLI; the laptop then opens with
    // no unlock.
    let laptop = Device::cli(13, "Anna's laptop");
    let intro = p.dev.introduce(&laptop, "cli");
    r.mock.send("introduce", intro);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut l = r.client(laptop, "cat");
    let lleg = r.open(&mut l, "cat", None).await;
    assert!(r.pump(&mut l, lleg, |l| l.typist.is_some()).await);
    // An introduction the operator forged is refused: a third device stays out.
    let forged = Device::cli(14, "forged");
    let mut intro = Device::cli(15, "not trusted").introduce(&forged, "cli");
    intro["introducedBy"] = json!(p.dev.id);
    r.mock.send("introduce", intro);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut f = r.client(forged, "cat");
    let leg = Uuid::new_v4();
    let msg1 = f.begin(Action::Open);
    r.mock.send("open", json!({ "sessionId": f.session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": f.dev.attestation(r.principal, None), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_device_not_introduced");
}

#[tokio::test]
async fn the_ninth_open_is_refused_at_the_default_limit() {
    let mut r = rig(PROFILES, true).await;
    for i in 0..8u8 {
        let d = Device::cli(20 + i, "laptop");
        let deleg = r.delegation(&d, "cli");
        let mut c = r.client(d, "cat");
        let leg = r.open(&mut c, "cat", Some(deleg)).await;
        assert!(
            r.pump(&mut c, leg, |c| c.typist.is_some()).await,
            "open {i}"
        );
    }
    let d = Device::cli(40, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let leg = Uuid::new_v4();
    let msg1 = c.begin(Action::Open);
    r.mock.send("open", json!({ "sessionId": c.session, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": c.dev.attestation(r.principal, Some(deleg)), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_session_limit");
    // An unknown profile is its own refusal.
    let leg = Uuid::new_v4();
    r.mock.send("open", json!({ "sessionId": Uuid::new_v4(), "leg": leg, "profile": "nope", "cols": 80, "rows": 24, "attestation": c.dev.attestation(r.principal, None), "handshake": STANDARD.encode([0u8; 48]) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_profile_unknown");
}

#[tokio::test]
async fn idle_starts_at_the_last_detach_and_the_lifetime_warns_first() {
    let mut r = rig(PROFILES, true).await;
    let d = Device::cli(50, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "brief");
    let leg = r.open(&mut c, "brief", Some(deleg.clone())).await;
    // Attached: no idle end, but the lifetime warning comes (3 s - 1 s).
    assert!(
        r.pump(&mut c, leg, |c| c
            .errors
            .contains(&"shell_lifetime_warning".to_owned()))
            .await
    );
    let ex = r
        .inbox
        .frame_where("exited", |v| v["sessionId"] == c.session.to_string())
        .await
        .unwrap();
    assert_eq!(ex["reason"], "lifetime");

    let d = Device::cli(51, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "brief");
    let leg = r.open(&mut c, "brief", Some(deleg)).await;
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    r.mock.send(
        "detach",
        json!({ "sessionId": c.session, "leg": leg, "reason": "closed" }),
    );
    let ex = r
        .inbox
        .frame_where("exited", |v| v["sessionId"] == c.session.to_string())
        .await
        .unwrap();
    assert_eq!(ex["reason"], "idle");
}

#[tokio::test]
async fn a_close_ends_the_session_and_the_exit_is_reported() {
    let mut r = rig(PROFILES, true).await;
    let d = Device::cli(52, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let leg = r.open(&mut c, "cat", Some(deleg)).await;
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    r.mock.send(
        "close",
        json!({ "sessionId": c.session, "device": c.dev.id }),
    );
    let ex = r
        .inbox
        .frame_where("exited", |v| v["sessionId"] == c.session.to_string())
        .await
        .unwrap();
    assert_eq!(ex["reason"], "closed");
    assert_eq!(ex["signal"], 1, "SIGHUP");
}

#[tokio::test]
async fn stopping_tells_everyone_kills_within_the_grace_and_closes_4001() {
    let mut r = rig(PROFILES, true).await;
    let d = Device::cli(53, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "stubborn");
    let leg = r.open(&mut c, "stubborn", Some(deleg)).await;
    assert!(r.pump(&mut c, leg, |c| c.text().contains("trapped")).await);
    let started = std::time::Instant::now();
    r.stop.send(()).await.unwrap();
    let hs = r.inbox.frame("host_stopping").await.unwrap();
    assert!(hs["inSeconds"].as_u64().unwrap() >= 1);
    assert!(r.pump(&mut c, leg, |c| c.host_stopping).await);
    let ex = r
        .inbox
        .frame_where("exited", |v| v["sessionId"] == c.session.to_string())
        .await
        .unwrap();
    assert_eq!(ex["reason"], "host_stopped");
    assert_eq!(ex["signal"], 9, "it ignored SIGHUP, so SIGKILL");
    assert!(started.elapsed() < Duration::from_secs(1 + 3));
    assert_eq!(
        r.inbox.closed(Duration::from_secs(5)).await,
        Some(Some(4001))
    );
    assert_eq!(r.task.await.unwrap().unwrap(), 0);
}

/// AC-13: the operator ends every leg of a host the moment it reads the
/// host's `host_stopping` frame, so the clients' own `host_stopping` must
/// already be ahead of it on the channel. Live on VM3 (2026-10-04) it was
/// not, and both clients said "connection lost; reconnecting…".
#[tokio::test]
async fn the_clients_hear_the_host_is_stopping_before_the_operator_does() {
    let mut r = rig(PROFILES, true).await;
    let d = Device::cli(54, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let leg = r.open(&mut c, "cat", Some(deleg)).await;
    let _ = r.inbox.drain(Duration::from_millis(300)).await;
    r.stop.send(()).await.unwrap();
    let all = r.inbox.drain(Duration::from_secs(3)).await;
    let frame_at = all
        .iter()
        .position(|m| matches!(m, FromHost::Frame(v) if v["type"] == "host_stopping"))
        .expect("the host_stopping frame");
    let before: Vec<&Vec<u8>> = all[..frame_at]
        .iter()
        .filter_map(|m| match m {
            FromHost::Data { leg: l, record, .. } if *l == leg => Some(record),
            _ => None,
        })
        .collect();
    for rec in before {
        c.receive(rec).expect("a record from the host opens");
    }
    assert!(
        c.host_stopping,
        "the client's `host_stopping` is on the channel ahead of the operator's"
    );
    // And the audit still gets its `exited … host_stopped`.
    assert!(all.iter().any(|m| matches!(m, FromHost::Frame(v)
        if v["type"] == "exited" && v["reason"] == "host_stopped")));
}

/// A device that comes back to a session this host does not hold (it ended,
/// or the host restarted) is told the session ended, a final answer, and
/// not `shell_resume_expired`, which a client follows with another try.
#[tokio::test]
async fn an_attach_to_a_session_the_host_does_not_hold_is_told_it_ended() {
    let mut r = rig(PROFILES, true).await;
    let d = Device::cli(55, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let leg = Uuid::new_v4();
    let msg1 = c.begin(Action::Attach);
    r.mock.send(
        "attach",
        json!({
            "sessionId": c.session, "leg": leg,
            "attestation": c.dev.attestation(r.principal, Some(deleg)),
            "handshake": STANDARD.encode(msg1),
        }),
    );
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "session_ended");
}

#[tokio::test]
async fn a_recording_is_ciphertext_on_the_host_and_opens_on_the_device() {
    let mut r = rig(PROFILES, true).await;
    let cli = Device::cli(60, "laptop");
    let secret = *cli.shell.secret();
    let id = cli.id;
    let deleg = r.delegation(&cli, "cli");
    let mut c = r.client(cli, "rec");
    let leg = r.open(&mut c, "rec", Some(deleg.clone())).await;
    r.say(
        &mut c,
        leg,
        &[Message::In {
            data: b"recorded words\n".to_vec(),
        }],
    );
    assert!(
        r.pump(&mut c, leg, |c| c.text().contains("recorded words"))
            .await
    );
    r.mock
        .send("close", json!({ "sessionId": c.session, "device": id }));
    r.inbox
        .frame_where("exited", |v| v["sessionId"] == c.session.to_string())
        .await
        .unwrap();
    let recorded = c.session;
    // On disk the words are nowhere in the clear.
    for day in std::fs::read_dir(r.paths.recordings_dir()).unwrap() {
        for f in std::fs::read_dir(day.unwrap().path()).unwrap() {
            let bytes = std::fs::read(f.unwrap().path()).unwrap();
            assert!(!bytes.windows(14).any(|w| w == b"recorded words"));
        }
    }
    // Through a live session, the device lists and fetches it.
    let mut c2 = r.client(Device::cli(60, "laptop"), "cat");
    let leg2 = r.open(&mut c2, "cat", Some(deleg)).await;
    r.say(&mut c2, leg2, &[Message::RecordingList]);
    assert!(
        r.pump(&mut c2, leg2, |c| c
            .other
            .iter()
            .any(|m| matches!(m, Message::RecordingListing { .. })))
            .await
    );
    r.say(
        &mut c2,
        leg2,
        &[Message::RecordingFetch {
            recording: recorded.to_string(),
            segment: 0,
            from_chunk: 0,
        }],
    );
    assert!(
        r.pump(&mut c2, leg2, |c| c
            .other
            .iter()
            .any(|m| matches!(m, Message::RecordingChunk { .. })))
            .await
    );
    let header = c2
        .other
        .iter()
        .find_map(|m| match m {
            Message::RecordingHeader { header, .. } => Some(header.clone()),
            _ => None,
        })
        .unwrap();
    let (h, _) = airdress_shell_proto::recording::SegmentHeader::parse(&header).unwrap();
    let reader =
        airdress_shell_proto::recording::SegmentReader::open(&h, &id.to_string(), &secret).unwrap();
    let mut text = Vec::new();
    for m in &c2.other {
        if let Message::RecordingChunk { index, sealed, .. } = m {
            text.extend(reader.open_chunk(*index, sealed).unwrap().0);
        }
    }
    assert!(String::from_utf8_lossy(&text).contains("recorded words"));
    // Another device's key opens nothing.
    let other = ShellKeypair::from_secret([3; 32]);
    assert!(airdress_shell_proto::recording::SegmentReader::open(
        &h,
        &id.to_string(),
        other.secret()
    )
    .is_err());
}

#[tokio::test]
async fn the_session_id_bound_is_the_one_the_device_proposed() {
    let mut r = rig(PROFILES, true).await;
    // The operator forwards the device's proposed id: the handshake binds it.
    let d = Device::cli(70, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let proposed = c.session;
    let leg = r.open(&mut c, "cat", Some(deleg.clone())).await;
    let opened = r.inbox.frame("opened").await.unwrap();
    assert_eq!(opened["sessionId"], proposed.to_string());
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    // An operator that put another id in the frame: the prologue differs,
    // the handshake fails, nothing is spawned.
    let d = Device::cli(71, "laptop");
    let deleg2 = r.delegation(&d, "cli");
    let mut o = r.client(d, "cat");
    let (other, leg) = (Uuid::new_v4(), Uuid::new_v4());
    let msg1 = o.begin(Action::Open);
    r.mock.send("open", json!({ "sessionId": other, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": o.dev.attestation(r.principal, Some(deleg2)), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_handshake_failed");
    // A second open of a live session's id is refused too.
    let mut again = r.client_for(Device::cli(70, "laptop"), proposed, "cat");
    let leg = Uuid::new_v4();
    let msg1 = again.begin(Action::Open);
    r.mock.send("open", json!({ "sessionId": proposed, "leg": leg, "profile": "cat", "cols": 80, "rows": 24, "attestation": again.dev.attestation(r.principal, Some(deleg)), "handshake": STANDARD.encode(msg1) }));
    let refused = r
        .inbox
        .frame_where("refused", |v| v["leg"] == leg.to_string())
        .await
        .unwrap();
    assert_eq!(refused["code"], "shell_handshake_failed");
}

#[tokio::test]
async fn host_info_is_signed_and_a_profile_reason_is_its_own_field() {
    let profiles = format!(
        "{PROFILES}\n[[profile]]\nid = \"gone\"\nlabel = \"gone\"\nprogram = \"/nonexistent/bin/x\"\n"
    );
    let mut r = rig(&profiles, true).await;
    // The mock checks both as the operator does and closes 4009 on either;
    // the host was neither refused nor closed.
    let gone = r.profiles["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "gone")
        .unwrap()
        .clone();
    assert_eq!(gone["state"], "invalid");
    assert_eq!(gone["reason"], "program_missing");
    let ready = &r.profiles["profiles"][0];
    assert_eq!(ready["state"], "ready");
    assert!(ready.get("reason").is_none());
    assert!(r.host_info["sig"].is_string());
    let seen = r.inbox.drain(Duration::from_millis(300)).await;
    assert!(
        !seen
            .iter()
            .any(|m| matches!(m, FromHost::Protocol(_) | FromHost::Closed(_))),
        "{seen:?}"
    );
}

#[tokio::test]
async fn the_first_device_is_trusted_from_the_operators_list_before_it_knocks() {
    let phone = Device::phone(80, "Galaxy S23");
    let lying = Device::cli(81, "lying");
    let mut lie = lying.listing("cli");
    lie["identityFingerprint"] = json!(airdress_shell_host::trust::identity_fingerprint(&[1; 32]));
    let listed = vec![phone.listing("phone"), lie];
    let mut r = rig_with(PROFILES, true, move |m| m.set_devices(listed)).await;
    assert!(r.mock.devices_asked() >= 1);
    // Pending on first start, with the operator's label and kind claim; the
    // entry whose fingerprint does not name its key is not offered.
    let store = airdress_shell_host::trust::DeviceStore::load(&r.paths).unwrap();
    assert!(store.devices.is_empty());
    let p = &store.pending[&phone.id];
    assert_eq!(p.label.as_deref(), Some("Galaxy S23"));
    assert_eq!(p.kind_claimed.as_deref(), Some("phone"));
    assert!(!store.pending.contains_key(&lying.id));
    // The person confirms it at the terminal, with a `y`, before it ever
    // connected.
    let fp = airdress_shell_host::trust::identity_fingerprint(&phone.identity_public());
    let mut text = String::new();
    assert!(
        airdress_shell_host::commands::trust(&r.paths, &fp, None, &mut |q| {
            text = q.to_owned();
            anyhow::bail!("declined")
        })
        .is_err()
    );
    airdress_shell_host::commands::trust(&r.paths, &fp, None, &mut |_| Ok(())).unwrap();
    assert!(text.contains("Trust Galaxy S23"), "{text}");
    assert!(text.contains("the operator says it is a `phone`"), "{text}");
    // It opens with no delegation and no introduction.
    let mut c = r.client(Device::phone(80, "Galaxy S23"), "cat");
    let leg = r.open(&mut c, "cat", None).await;
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    let store = airdress_shell_host::trust::DeviceStore::load(&r.paths).unwrap();
    assert_eq!(
        store.devices[&phone.id].label.as_deref(),
        Some("Galaxy S23")
    );
    assert_eq!(store.devices[&phone.id].kind, "phone");
}
