//! The scripted conversation suite (design §14.2), run against the
//! reference host. The script is `tests/vectors/conversation.json`; the
//! Dart and Node drivers run the same file.

use airdress_shell_proto::conformance::script::{run, Expect, Step};

fn script() -> Vec<Step> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/conversation.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("script")).expect("script parses")
}

#[test]
fn the_conversation_passes() {
    if let Err(f) = run(&script()) {
        panic!("step {} failed: {}", f.step, f.why);
    }
}

#[test]
fn the_script_covers_every_flow_the_design_names() {
    let s = script();
    let has = |f: &dyn Fn(&Step) -> bool| s.iter().any(f);
    assert!(has(&|x| matches!(x, Step::Open { .. })), "open");
    assert!(has(&|x| matches!(x, Step::Output { .. })), "stream");
    assert!(has(&|x| matches!(x, Step::Detach { .. })), "detach");
    assert!(
        has(&|x| matches!(x, Step::Reconnect { .. })),
        "resume and reattach"
    );
    assert!(has(&|x| matches!(x, Step::Attach { .. })), "attach");
    assert!(has(&|x| matches!(x, Step::TakeInput { .. })), "take-over");
    assert!(
        has(&|x| matches!(x, Step::Revoke { .. })),
        "revoke-with-rekey"
    );
    assert!(
        has(&|x| matches!(x, Step::ReleaseInput { .. })),
        "release_input"
    );
    assert!(has(&|x| matches!(x, Step::Stop)), "host stop");
    assert!(has(&|x| matches!(x, Step::Exit { .. })), "exit");
    assert!(
        has(&|x| matches!(x, Step::Expect(Expect::Refused { .. }))),
        "an expired resume"
    );
}

#[test]
fn a_wrong_expectation_fails_the_script() {
    // The driver must check, not just run: flip one expectation.
    let mut s = script();
    let i = s
        .iter()
        .position(|x| matches!(x, Step::Expect(Expect::Unlocks { .. })))
        .unwrap();
    if let Step::Expect(Expect::Unlocks { count, .. }) = &mut s[i] {
        *count += 1;
    }
    let f = run(&s).expect_err("the flipped expectation must fail");
    assert_eq!(f.step, i);
}

#[test]
fn an_operator_cannot_open_on_a_cli_registration_for_a_phone() {
    // The host verified kind `phone`; a statement saying `none` is refused
    // at introduction, so nothing is ever spawned for it.
    let s: Vec<Step> = serde_json::from_value(serde_json::json!([
        {"step": "device", "name": "p", "phone": false, "kind": "phone", "label": "x",
         "refused": "shell_presence_required"}
    ]))
    .unwrap();
    run(&s).unwrap();
}
