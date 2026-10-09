//! A host enrolled with a mock operator, and the helpers that drive it.
#![allow(dead_code)]

use std::time::Duration;

use airdress_shell_host::channel::LinkTimings;
use airdress_shell_host::host::Timings;
use airdress_shell_host::paths::Paths;
use airdress_shell_host::run::{run_until, RunOptions};
use airdress_shell_host::testkit::{delegation, Client, Device, Inbox, MockOperator};
use airdress_shell_proto::prologue::Action;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct Rig {
    pub mock: MockOperator,
    pub inbox: Inbox,
    pub paths: Paths,
    pub stop: mpsc::Sender<()>,
    pub task: tokio::task::JoinHandle<anyhow::Result<i32>>,
    pub principal: Uuid,
    pub root: SigningKey,
    pub machine: Uuid,
    pub airdress: String,
    pub host_pin: [u8; 32],
    pub host_info: Value,
    pub profiles: Value,
    pub dir: tempfile::TempDir,
}

pub fn timings() -> Timings {
    Timings {
        tick: Duration::from_millis(50),
        kill_after: Duration::from_secs(1),
        exit_readable: Duration::from_secs(2),
        lifetime_warning: Duration::from_secs(1),
        open_timeout: Duration::from_secs(5),
        input_stall: Duration::from_secs(10),
    }
}

pub fn link_timings() -> LinkTimings {
    LinkTimings {
        ping: Duration::from_secs(1),
        idle: Duration::from_secs(10),
        rotate: Duration::from_secs(2),
        batch: Duration::from_millis(10),
        retry_min: Duration::from_millis(100),
        retry_max: Duration::from_secs(1),
    }
}

/// A host with `profiles` as its file, enrolled and connected.
pub async fn rig(profiles: &str, ws: bool) -> Rig {
    rig_with(profiles, ws, |_| {}).await
}

/// As [`rig`], with the mock operator set up by `setup` before the host
/// starts.
pub async fn rig_with(profiles: &str, ws: bool, setup: impl FnOnce(&MockOperator)) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    std::fs::create_dir_all(&paths.home).unwrap();
    std::fs::create_dir_all(paths.config_dir()).unwrap();
    std::fs::write(paths.profiles_file(), profiles).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            paths.profiles_file(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let (mock, rx) = MockOperator::start([42; 32]).await;
    mock.refuse_ws(!ws);
    setup(&mock);
    let machine = Uuid::new_v4();
    let principal = Uuid::new_v4();
    let root = SigningKey::from_bytes(&[7; 32]);
    mock.approve(machine, principal, Some(root.verifying_key().to_bytes()));
    let (stop, stop_rx) = mpsc::channel(4);
    let opts = RunOptions {
        paths: paths.clone(),
        operator: Some(mock.origin.clone()),
        name: Some("test box".into()),
        ca_file: None,
        host_version: "test".into(),
        timings: timings(),
        link: link_timings(),
    };
    let task = tokio::spawn(run_until(opts, stop_rx));
    let mut inbox = Inbox::new(rx);
    let host_info = inbox.frame("host_info").await.expect("host_info");
    let profiles = inbox.frame("profiles").await.expect("profiles");
    let host_pin: [u8; 32] = STANDARD
        .decode(host_info["shellKeyPublic"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    Rig {
        airdress: "127.0.0.1".into(),
        mock,
        inbox,
        paths,
        stop,
        task,
        principal,
        root,
        machine,
        host_pin,
        host_info,
        profiles,
        dir,
    }
}

impl Rig {
    /// A client of `dev` for a new session of `profile`.
    pub fn client(&self, dev: Device, profile: &str) -> Client {
        Client::new(
            dev,
            self.host_pin,
            &self.airdress,
            self.machine,
            Uuid::new_v4(),
            profile,
        )
    }

    /// A client of `dev` for an existing `session`.
    pub fn client_for(&self, dev: Device, session: Uuid, profile: &str) -> Client {
        Client::new(
            dev,
            self.host_pin,
            &self.airdress,
            self.machine,
            session,
            profile,
        )
    }

    /// The root's delegation of `dev` as `kind`.
    pub fn delegation(&self, dev: &Device, kind: &str) -> Value {
        delegation(&self.root, &dev.identity_public(), &self.airdress, kind)
    }

    /// Open the client's session; returns the leg once the device's first
    /// record went to the host.
    pub async fn open(&mut self, c: &mut Client, profile: &str, deleg: Option<Value>) -> Uuid {
        let leg = Uuid::new_v4();
        let msg1 = c.begin(Action::Open);
        self.mock.send(
            "open",
            json!({
                "sessionId": c.session, "leg": leg, "profile": profile, "cols": 80, "rows": 24,
                "attestation": c.dev.attestation(self.principal, deleg),
                "handshake": STANDARD.encode(msg1),
            }),
        );
        let msg2 = self.inbox.record(leg).await.expect("msg2");
        let first = c.finish(&msg2);
        self.mock.send_data(c.session, leg, &first);
        leg
    }

    /// Attach the client to its session with a full handshake.
    pub async fn attach(&mut self, c: &mut Client, deleg: Option<Value>, unlock: bool) -> Uuid {
        let leg = Uuid::new_v4();
        let msg1 = c.begin(Action::Attach);
        self.mock.send(
            "attach",
            json!({
                "sessionId": c.session, "leg": leg,
                "attestation": c.dev.attestation(self.principal, deleg),
                "handshake": STANDARD.encode(msg1),
            }),
        );
        let msg2 = self.inbox.record(leg).await.expect("msg2");
        let first = c.finish_with(&msg2, unlock);
        self.mock.send_data(c.session, leg, &first);
        leg
    }

    /// Resume the client's dropped leg with its ticket.
    pub async fn resume(&mut self, c: &mut Client, deleg: Option<Value>) -> Uuid {
        let leg = Uuid::new_v4();
        let (ticket, msg1) = c.begin_resume();
        self.mock.send(
            "attach",
            json!({
                "sessionId": c.session, "leg": leg,
                "attestation": c.dev.attestation(self.principal, deleg),
                "resume": { "ticketId": ticket, "handshake": STANDARD.encode(msg1) },
            }),
        );
        let msg2 = self.inbox.record(leg).await.expect("msg2");
        let first = c.finish(&msg2);
        self.mock.send_data(c.session, leg, &first);
        leg
    }

    /// Send the client's messages on `leg`.
    pub fn say(&self, c: &mut Client, leg: Uuid, msgs: &[airdress_shell_proto::inner::Message]) {
        let r = c.send(msgs);
        self.mock.send_data(c.session, leg, &r);
    }

    /// Read records for `leg` into the client until `done` holds.
    pub async fn pump(
        &mut self,
        c: &mut Client,
        leg: Uuid,
        done: impl Fn(&Client) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !done(c) {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            let Some(rec) = self
                .inbox
                .take(left, |m| match m {
                    airdress_shell_host::testkit::FromHost::Data { leg: l, record, .. }
                        if *l == leg =>
                    {
                        Some(record.clone())
                    }
                    _ => None,
                })
                .await
            else {
                return false;
            };
            if let Ok(replies) = c.receive(&rec) {
                for r in replies {
                    self.mock.send_data(c.session, leg, &r);
                }
            }
        }
        true
    }
}
