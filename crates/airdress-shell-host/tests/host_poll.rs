//! The long-poll (P): where the WebSocket upgrade is refused, the host falls
//! back to it, remembers that for the network, and carries a session across
//! the poll's rotations without losing or doubling output.

mod common;

use std::time::Duration;

use airdress_shell_host::channel::hints::HintFile;
use airdress_shell_host::channel::negotiate::Transport;
use airdress_shell_host::testkit::Device;
use airdress_shell_proto::inner::Message;
use common::rig;

const PROFILES: &str = r#"
[[profile]]
id = "cat"
program = "/bin/cat"
"#;

#[tokio::test]
async fn a_refused_upgrade_falls_back_to_the_long_poll_and_is_remembered() {
    let mut r = rig(PROFILES, false).await;
    assert_eq!(r.mock.transport(), Some("poll"));
    let hints = HintFile::at(r.paths.hints()).load();
    assert_eq!(hints.len(), 1, "one network remembered");
    let h = hints.values().next().unwrap();
    assert_eq!(h.transport, Transport::Poll);
    assert!(h.preferred_failed.is_some());
    // The file holds no address.
    let raw = std::fs::read_to_string(r.paths.hints()).unwrap();
    assert!(!raw.contains("127.0.0.1"), "{raw}");

    let d = Device::cli(1, "laptop");
    let deleg = r.delegation(&d, "cli");
    let mut c = r.client(d, "cat");
    let leg = r.open(&mut c, "cat", Some(deleg)).await;
    assert!(r.pump(&mut c, leg, |c| c.typist.is_some()).await);
    // Across several rotations (every 2 s here), input and echo keep going.
    for i in 0..5 {
        r.say(
            &mut c,
            leg,
            &[Message::In {
                data: format!("line {i}\n").into_bytes(),
            }],
        );
        let want = format!("line {i}");
        assert!(
            r.pump(&mut c, leg, |c| c.text().matches(&want).count() >= 2)
                .await,
            "{}",
            c.text()
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    let text = c.text();
    for i in 0..5 {
        assert_eq!(text.matches(&format!("line {i}")).count(), 2, "{text}");
    }
    assert_eq!(r.mock.transport(), Some("poll"), "still one channel");
}

#[tokio::test]
async fn the_operator_ending_the_channel_is_dialled_again_and_said_hello_to() {
    let mut r = rig(PROFILES, true).await;
    r.mock.close(4001, "lifetime");
    // The host dials again and says who it is.
    let again = r.inbox.frame("host_info").await;
    assert!(again.is_some());
    assert!(r.inbox.frame("profiles").await.is_some());
    assert!(r.inbox.frame("sessions").await.is_some());
}
