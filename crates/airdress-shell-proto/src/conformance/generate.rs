//! The vector generator. Every input derives from a fixed label through
//! [`DetRng`], so a regeneration reproduces the committed files exactly; a
//! test fails when they differ (`tests/vectors.rs`).

use ed25519_dalek::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::handshake::{DeviceHello, HostHello, InitiatorHandshake, ResponderHandshake};
use crate::inner::{Message, SignalKind, Viewer, TYPE_TABLE};
use crate::keys::ShellKeypair;
use crate::presence::{presence_message, DeviceKeys, PresenceAlg};
use crate::prologue::{Action, Prologue};
use crate::record::{noise_encrypt, rekey};
use crate::vectors::*;

fn bytes32(label: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    DetRng::new(label.as_bytes()).fill_bytes(&mut b);
    b
}

fn bytes16(label: &str) -> [u8; 16] {
    let mut b = [0u8; 16];
    DetRng::new(label.as_bytes()).fill_bytes(&mut b);
    b
}

fn prologue(action: Action) -> Prologue {
    Prologue {
        airdress: "0192b7c4-5e1a-7d3f-9a42-6c1e8b2f4d01".into(),
        machine_id: "6f0c2a91-3b7d-4e58-a1c9-2d8e7f4b6a13".into(),
        session_id: "01J9Z3K7Q8R2T5V6W8X9Y0ZA1B".into(),
        profile_id: "api".into(),
        action,
    }
}

struct Built {
    case: HandshakeCase,
    resume_secret: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn handshake_case(
    name: &str,
    tag: &str,
    action: Action,
    psk: Option<[u8; 32]>,
    device_hello: DeviceHello,
    host_hello: HostHello,
    records: &[(&str, Vec<u8>)],
) -> Built {
    let dev = ShellKeypair::from_secret(bytes32("device static"));
    let host = ShellKeypair::from_secret(bytes32("host static"));
    let de = bytes32(&format!("{tag} device ephemeral"));
    let he = bytes32(&format!("{tag} host ephemeral"));
    let tid = bytes16(&format!("{tag} ticket"));
    let pro = prologue(action);

    let mut drng = ScriptedRng::new(&[&de]);
    let (ini, m1) = match psk {
        None => InitiatorHandshake::start(&mut drng, &dev, host.public(), &pro, &device_hello),
        Some(k) => InitiatorHandshake::start_resume(
            &mut drng,
            &dev,
            host.public(),
            &pro,
            &k,
            &device_hello,
        ),
    }
    .expect("initiator");
    let mut hrng = ScriptedRng::new(&[&he, &tid]);
    let (rsp, _) =
        ResponderHandshake::read(&mut hrng, &host, &pro, dev.public(), psk.as_ref(), &m1)
            .expect("read");
    let (mut hch, _, m2) = rsp
        .respond(&mut hrng, host_hello.clone(), 0)
        .expect("respond");
    let (mut dch, _) = ini.finish(&m2, 0).expect("finish");

    let mut recs = Vec::new();
    for (from, pt) in records {
        let rec = if *from == "device" {
            let r = dch.seal(pt, 0).expect("seal");
            hch.open(&r).expect("open");
            r
        } else {
            let r = hch.seal(pt, 0).expect("seal");
            dch.open(&r).expect("open");
            r
        };
        recs.push(RecordCase {
            from: (*from).into(),
            plaintext: to_hex(pt),
            record: to_hex(&rec),
        });
    }
    Built {
        resume_secret: *dch.resume_secret(),
        case: HandshakeCase {
            name: name.into(),
            pattern: if psk.is_some() { "IKpsk2" } else { "IK" }.into(),
            prologue_bytes: to_hex(&pro.to_bytes().expect("prologue")),
            prologue: pro,
            device_static_secret: to_hex(dev.secret()),
            host_static_secret: to_hex(host.secret()),
            device_ephemeral_secret: to_hex(&de),
            host_ephemeral_secret: to_hex(&he),
            ticket_id: to_hex(&tid),
            psk: psk.map(|k| to_hex(&k)),
            device_hello,
            host_hello,
            msg1: to_hex(&m1),
            msg2: to_hex(&m2),
            handshake_hash: to_hex(dch.handshake_hash()),
            resume_secret: to_hex(dch.resume_secret()),
            records: recs,
        },
    }
}

fn host_hello() -> HostHello {
    HostHello {
        host_version: Some("0.1.0".into()),
        profile_hash: Some("sha256:6d1f".into()),
        resume_ticket: String::new(),
    }
}

/// `handshake.json`.
pub fn handshake_file() -> HandshakeFile {
    let open_hello = DeviceHello {
        device: "device-phone".into(),
        cols: Some(80),
        rows: Some(24),
        client_version: Some("1.0.0".into()),
    };
    let none_presence = Message::Presence {
        action: Action::Open,
        alg: PresenceAlg::None,
        sig: None,
    }
    .encode()
    .expect("encode");
    let typed = Message::In {
        data: b"ls\r".to_vec(),
    }
    .encode()
    .expect("encode");
    let out = Message::Out {
        offset: 0,
        data: b"README.md\r\n".to_vec(),
    }
    .encode()
    .expect("encode");

    let open = handshake_case(
        "open: IK, then the presence record, input and output",
        "open",
        Action::Open,
        None,
        open_hello.clone(),
        host_hello(),
        &[
            ("device", none_presence),
            ("device", typed.clone()),
            ("host", out.clone()),
        ],
    );
    let attach = handshake_case(
        "attach: IK with the attach action",
        "attach",
        Action::Attach,
        None,
        open_hello.clone(),
        host_hello(),
        &[("host", out.clone())],
    );
    let resume_hello = DeviceHello {
        device: "device-phone".into(),
        cols: None,
        rows: None,
        client_version: None,
    };
    let resume = handshake_case(
        "resume: IKpsk2 under the open's resume secret",
        "resume",
        Action::Resume,
        Some(open.resume_secret),
        resume_hello.clone(),
        HostHello {
            host_version: None,
            profile_hash: None,
            resume_ticket: String::new(),
        },
        &[
            (
                "device",
                Message::Ack { offset: 11 }.encode().expect("encode"),
            ),
            ("host", out),
        ],
    );

    // Refusals at msg1.
    let host_secret = to_hex(&bytes32("host static"));
    let dev = ShellKeypair::from_secret(bytes32("device static"));
    let other = ShellKeypair::from_secret(bytes32("another device static"));
    let he = to_hex(&bytes32("refusal host ephemeral"));
    let refusals = vec![
        HandshakeRefusal {
            name: "an open msg1 presented as an attach".into(),
            prologue: prologue(Action::Attach),
            host_static_secret: host_secret.clone(),
            expected_device_static: to_hex(dev.public()),
            host_ephemeral_secret: he.clone(),
            psk: None,
            msg1: open.case.msg1.clone(),
            code: "shell_handshake_failed".into(),
        },
        HandshakeRefusal {
            name: "the operator attests another device key".into(),
            prologue: prologue(Action::Open),
            host_static_secret: host_secret.clone(),
            expected_device_static: to_hex(other.public()),
            host_ephemeral_secret: he.clone(),
            psk: None,
            msg1: open.case.msg1.clone(),
            code: "shell_handshake_failed".into(),
        },
        HandshakeRefusal {
            name: "a resume with no live ticket".into(),
            prologue: prologue(Action::Resume),
            host_static_secret: host_secret.clone(),
            expected_device_static: to_hex(dev.public()),
            host_ephemeral_secret: he.clone(),
            psk: None,
            msg1: resume.case.msg1.clone(),
            code: "shell_resume_expired".into(),
        },
        HandshakeRefusal {
            name: "the same session under another profile".into(),
            prologue: Prologue {
                profile_id: "shell".into(),
                ..prologue(Action::Open)
            },
            host_static_secret: host_secret,
            expected_device_static: to_hex(dev.public()),
            host_ephemeral_secret: he,
            psk: None,
            msg1: open.case.msg1.clone(),
            code: "shell_handshake_failed".into(),
        },
    ];
    HandshakeFile {
        description: "Noise IK (open, attach) and IKpsk2 (resume) with fixed statics, ephemerals and ticket ids; records after each; msg1s the host must refuse.".into(),
        cases: vec![open.case, attach.case, resume.case],
        refusals,
    }
}

/// `records.json`.
pub fn record_file() -> RecordFile {
    let key = bytes32("record key");
    let seal = [
        (0u64, &b""[..]),
        (1, b"hello"),
        (1023, b"x"),
        (u64::MAX - 2, b"last usable nonce"),
    ]
    .iter()
    .map(|(n, pt)| {
        let mut rec = n.to_be_bytes().to_vec();
        rec.extend(noise_encrypt(&key, *n, &[], pt));
        SealCase {
            key: to_hex(&key),
            nonce: *n,
            plaintext: to_hex(pt),
            record: to_hex(&rec),
        }
    })
    .collect();
    let k1 = rekey(&key);
    let k2 = rekey(&k1);
    let rekey_cases = vec![
        RekeyCase {
            key: to_hex(&key),
            next: to_hex(&k1[..]),
        },
        RekeyCase {
            key: to_hex(&k1[..]),
            next: to_hex(&k2[..]),
        },
    ];
    let w = |name: &str,
             arrivals: Vec<(u64, u32)>,
             announcements: Vec<(usize, u64)>,
             expect: &[&str]| WindowCase {
        name: name.into(),
        key: to_hex(&key),
        arrivals,
        announcements,
        expect: expect.iter().map(|s| (*s).to_owned()).collect(),
    };
    let window = vec![
        w(
            "in order",
            vec![(0, 0), (1, 0), (2, 0)],
            vec![],
            &["ok", "ok", "ok"],
        ),
        w(
            "a duplicate",
            vec![(0, 0), (0, 0)],
            vec![],
            &["ok", "replay"],
        ),
        w(
            "reordered within the window, then a duplicate",
            vec![(5, 0), (3, 0), (4, 0), (3, 0)],
            vec![],
            &["ok", "ok", "ok", "replay"],
        ),
        w(
            "1024 behind is outside, 1023 inside",
            vec![(2000, 0), (976, 0), (977, 0)],
            vec![],
            &["ok", "replay", "ok"],
        ),
        w(
            "an announced rekey at 3; the old key is refused past it",
            vec![(0, 0), (1, 0), (2, 0), (3, 1), (4, 1), (5, 0)],
            vec![(3, 3)],
            &["ok", "ok", "ok", "ok", "ok", "auth"],
        ),
        w(
            "new-key records overtake the announcement",
            vec![(3, 1), (4, 1), (1, 0), (2, 0)],
            vec![(3, 3)],
            &["ok", "ok", "ok", "ok"],
        ),
        w(
            "two rekeys ahead with no announcement is not guessed",
            vec![(0, 0), (1, 2)],
            vec![],
            &["ok", "auth"],
        ),
        w(
            "the reserved nonce",
            vec![(u64::MAX, 0)],
            vec![],
            &["shell_record_rejected"],
        ),
    ];
    RecordFile {
        description: "Records: n (u64 BE) ‖ ChaChaPoly(k, n, ad=\"\", p) with Noise nonce encoding; Noise REKEY; the 1,024-record replay window and rekey switch-over.".into(),
        seal,
        rekey: rekey_cases,
        window,
    }
}

fn high_s(sig: &P256Signature) -> P256Signature {
    let s = sig.s();
    let neg = -*s.as_ref();
    let flipped = P256Signature::from_scalars(sig.r().to_bytes(), neg.to_bytes()).expect("valid");
    // Whichever of the two is high-S.
    if flipped.normalize_s().is_some() {
        flipped
    } else {
        *sig
    }
}

/// `presence.json`.
pub fn presence_file() -> PresenceFile {
    let mut scalar = bytes32("presence key");
    scalar[0] &= 0x7f;
    let pk = P256SigningKey::from_slice(&scalar).expect("scalar");
    let compressed = pk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let uncompressed = pk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let hh: [u8; 32] = Sha256::digest(b"handshake hash").into();
    let stale: [u8; 32] = Sha256::digest(b"an earlier handshake hash").into();
    let low = |s: P256Signature| s.normalize_s().unwrap_or(s);
    let sig = low(pk.sign(&presence_message(&hh, Action::Open).expect("message")));
    let attach_sig = low(pk.sign(&presence_message(&hh, Action::Attach).expect("message")));
    let u =
        |name: &str, public: &[u8], h: &[u8; 32], action, sig: Vec<u8>, expect: &str| UnlockCase {
            name: name.into(),
            presence_public: to_hex(public),
            handshake_hash: to_hex(h),
            action,
            sig: to_hex(&sig),
            expect: expect.into(),
        };
    let der = |s: &P256Signature| s.to_der().as_bytes().to_vec();
    let unlock = vec![
        u(
            "a valid low-S unlock for open",
            &compressed,
            &hh,
            Action::Open,
            der(&sig),
            "ok",
        ),
        u(
            "the same key, uncompressed",
            &uncompressed,
            &hh,
            Action::Open,
            der(&sig),
            "ok",
        ),
        u(
            "a valid unlock for attach",
            &compressed,
            &hh,
            Action::Attach,
            der(&attach_sig),
            "ok",
        ),
        u(
            "high-S, as Keystore may produce it",
            &compressed,
            &hh,
            Action::Open,
            der(&high_s(&sig)),
            "ok",
        ),
        u(
            "an open signature presented for attach",
            &compressed,
            &hh,
            Action::Attach,
            der(&sig),
            "shell_presence_required",
        ),
        u(
            "a stale handshake hash",
            &compressed,
            &stale,
            Action::Open,
            der(&sig),
            "shell_presence_required",
        ),
        u(
            "a raw r‖s signature instead of DER",
            &compressed,
            &hh,
            Action::Open,
            sig.to_bytes().to_vec(),
            "shell_presence_required",
        ),
    ];

    let id = SigningKey::from_bytes(&bytes32("phone identity"));
    let cli_id = SigningKey::from_bytes(&bytes32("cli identity"));
    let phone = DeviceKeys {
        device: "0199a1b2-0000-4000-8000-00000000a001".into(),
        principal: "principal-owner".into(),
        identity_public: id.verifying_key().to_bytes(),
        dh_public: *ShellKeypair::from_secret(bytes32("phone shell")).public(),
        presence_alg: PresenceAlg::P256,
        presence_public: Some(compressed.clone()),
    };
    let phone_sig = phone.sign(&id).expect("sign");
    let cli = DeviceKeys {
        device: "0199a1b2-0000-4000-8000-00000000c011".into(),
        principal: "principal-owner".into(),
        identity_public: cli_id.verifying_key().to_bytes(),
        dh_public: *ShellKeypair::from_secret(bytes32("cli shell")).public(),
        presence_alg: PresenceAlg::None,
        presence_public: None,
    };
    let cli_sig = cli.sign(&cli_id).expect("sign");
    let phone_none = DeviceKeys {
        presence_alg: PresenceAlg::None,
        presence_public: None,
        ..phone.clone()
    };
    let phone_none_sig = phone_none.sign(&id).expect("sign");
    let d =
        |name: &str, keys: &DeviceKeys, sig: &[u8; 64], kind: &str, expect: &str| DeviceKeysCase {
            name: name.into(),
            signed_bytes: to_hex(&keys.signed_bytes().expect("bytes")),
            keys: keys.clone(),
            sig: to_hex(sig),
            verified_kind: kind.into(),
            expect: expect.into(),
        };
    let device_keys = vec![
        d(
            "a phone with a presence key",
            &phone,
            &phone_sig,
            "phone",
            "unlock",
        ),
        d(
            "a CLI with none, of kind cli: accepted",
            &cli,
            &cli_sig,
            "cli",
            "not_required",
        ),
        d(
            "a device that signed none, of kind phone: refused",
            &phone_none,
            &phone_none_sig,
            "phone",
            "shell_presence_required",
        ),
        d(
            "the operator rewrote a phone's statement to none",
            &phone_none,
            &phone_sig,
            "phone",
            "shell_presence_required",
        ),
        d(
            "the operator rewrote it and claims cli: the signature still fails",
            &phone_none,
            &phone_sig,
            "cli",
            "shell_presence_required",
        ),
        d(
            "a CLI-kind device with a presence key still unlocks",
            &phone,
            &phone_sig,
            "cli",
            "unlock",
        ),
    ];
    PresenceFile {
        description: "Unlock signatures (ECDSA P-256, SHA-256, DER) over \"airdress.shell.presence.v1\" ‖ 0x00 ‖ handshake_hash ‖ action, and device-key statements under the presence rule: none only for a cli kind.".into(),
        unlock,
        device_keys,
    }
}

/// `recording.json`.
pub fn recording_file() -> RecordingFile {
    let r = |device: &str| RecordingRecipient {
        device: device.into(),
        secret: to_hex(&bytes32(&format!("{device} recording secret"))),
    };
    let mut cases = vec![
        RecordingCase {
            name: "two recipients, three chunks".into(),
            seed: to_hex(b"recording one"),
            session: "01J9Z3K7Q8R2T5V6W8X9Y0ZA1B".into(),
            segment: 0,
            recipients: vec![r("device-phone"), r("device-cli")],
            outsider: r("device-revoked"),
            chunks: vec![
                to_hex(b"[0.000, \"o\", \"$ \"]\n"),
                to_hex(b"[0.512, \"o\", \"ls\\r\\n\"]\n"),
                to_hex(b"[0.530, \"o\", \"README.md\\r\\n$ \"]\n"),
            ],
            file: String::new(),
        },
        RecordingCase {
            name: "after a revocation: segment 1, one recipient, an empty final chunk".into(),
            seed: to_hex(b"recording two"),
            session: "01J9Z3K7Q8R2T5V6W8X9Y0ZA1B".into(),
            segment: 1,
            recipients: vec![r("device-phone")],
            outsider: r("device-cli"),
            chunks: vec![to_hex(b"[1.000, \"o\", \"x\"]\n"), String::new()],
            file: String::new(),
        },
    ];
    for c in &mut cases {
        c.file = to_hex(&write_recording(c).expect("write"));
    }
    RecordingFile {
        description: "Recording segments: HPKE (X25519, HKDF-SHA256, ChaCha20Poly1305, base) wraps per recipient; XChaCha20-Poly1305 chunks with AD = index ‖ final. Written from a DetRng seed.".into(),
        cases,
    }
}

/// `structured.json`.
pub fn structured_file() -> StructuredFile {
    use crate::structured::{
        ApprovalOption, ApprovalOutcome, Event, Input, OptionKind, PlanEntry, PlanStatus, Role,
        SessionState, ToolKind, ToolStatus, SCHEMA_ID,
    };
    use serde_json::json;
    let events = vec![
        Event::Status { state: SessionState::Working },
        Event::Status { state: SessionState::WaitingForApproval },
        Event::Message {
            id: "m1".into(),
            role: Role::User,
            text: "Add a test for the ä/ß parser".into(),
            append: false,
            done: true,
        },
        Event::Message {
            id: "m2".into(),
            role: Role::Assistant,
            text: "I'll add".into(),
            append: true,
            done: false,
        },
        Event::Thought {
            id: "t1".into(),
            text: "The test belongs next to the parser.".into(),
            append: false,
        },
        Event::ToolCall {
            id: "c1".into(),
            title: "Edit src/parse.rs".into(),
            kind: ToolKind::Edit,
            status: ToolStatus::Pending,
            input: "src/parse.rs".into(),
        },
        Event::ToolCall {
            id: "c2".into(),
            title: "cargo test".into(),
            kind: ToolKind::Execute,
            status: ToolStatus::Done,
            input: String::new(),
        },
        Event::ToolResult {
            id: "c2".into(),
            text: "test result: ok. 3 passed".into(),
            exit_code: Some(0),
            truncated: false,
        },
        Event::Diff {
            tool_call_id: "c1".into(),
            path: "src/parse.rs".into(),
            unified: "--- a/src/parse.rs\n+++ b/src/parse.rs\n@@ -1 +1,2 @@\n fn parse() {}\n+#[test] fn t() {}\n".into(),
            truncated: false,
        },
        Event::Plan {
            entries: vec![
                PlanEntry { text: "Read the parser".into(), status: PlanStatus::Completed },
                PlanEntry { text: "Add a test".into(), status: PlanStatus::InProgress },
                PlanEntry { text: "Run the suite".into(), status: PlanStatus::Pending },
            ],
        },
        Event::ApprovalRequest {
            id: "a1".into(),
            title: "Run cargo test?".into(),
            detail: "cargo test -p parser".into(),
            options: vec![
                ApprovalOption { id: "once".into(), label: "Allow once".into(), kind: OptionKind::AllowOnce },
                ApprovalOption { id: "always".into(), label: "Always allow".into(), kind: OptionKind::AllowAlways },
                ApprovalOption { id: "reject".into(), label: "Deny".into(), kind: OptionKind::Deny },
            ],
        },
        Event::ApprovalResolved { id: "a1".into(), outcome: ApprovalOutcome::Answered },
        Event::Error { text: "The harness stopped answering".into() },
    ];
    let inputs = [
        Input::Prompt {
            text: "Run the tests again".into(),
            attachments: vec![],
        },
        Input::ApprovalAnswer {
            id: "a1".into(),
            option: "once".into(),
        },
        Input::Cancel,
    ];
    let mut bodies: Vec<serde_json::Value> = events.iter().map(Event::to_value).collect();
    bodies.extend(
        inputs
            .iter()
            .map(|i| serde_json::to_value(i).expect("json")),
    );
    StructuredFile {
        schema: SCHEMA_ID.into(),
        description: "The structured tier's neutral event model: host-to-client events keyed `event`, client-to-host inputs keyed `input`. Each body decodes and re-encodes to itself; each invalid one is refused.".into(),
        bodies,
        invalid: vec![
            json!({}),
            json!({"event": "status", "state": "sleeping"}),
            json!({"event": "tool_call", "id": "c", "title": "t", "kind": "launch", "status": "done"}),
            json!({"event": "approval_request", "id": "a", "title": "t", "detail": "d", "options": [{"id": "x", "label": "X", "kind": "maybe"}]}),
            json!({"input": "approval_answer", "id": "a1"}),
            json!({"input": "auto_approve"}),
        ],
        tolerated: vec![
            json!({"event": "status", "state": "idle", "extra": true}),
            json!({"event": "status", "input": "cancel", "state": "idle"}),
            json!({"event": "approval_request", "id": "a", "title": "t", "detail": "d", "options": [{"id": "x", "label": "X", "kind": "deny", "hotkey": "n"}]}),
            json!({"input": "prompt", "text": "go", "voice": true}),
        ],
    }
}

/// `inner.json`.
pub fn inner_file() -> InnerFile {
    let msgs = vec![
        Message::Out {
            offset: 1024,
            data: b"\x1b[1mhi\x1b[0m\r\n".to_vec(),
        },
        Message::Snapshot {
            offset: 4096,
            cols: 80,
            rows: 24,
            data: b"\x1b[H\x1b[2J$ ".to_vec(),
        },
        Message::In {
            data: b"ls\r".to_vec(),
        },
        Message::Signal {
            signal: SignalKind::Interrupt,
        },
        Message::Resize {
            cols: 120,
            rows: 40,
        },
        Message::Ack { offset: 4096 },
        Message::Credit { bytes: 262_144 },
        Message::Presence {
            action: Action::Open,
            alg: PresenceAlg::None,
            sig: None,
        },
        Message::Presence {
            action: Action::Attach,
            alg: PresenceAlg::P256,
            sig: Some(vec![0x30, 0x44, 0x02, 0x20]),
        },
        Message::TakeInput,
        Message::Roles {
            typist: Some("device-phone".into()),
            viewers: vec![
                Viewer {
                    client: "device-cli".into(),
                    label: "airdress CLI on dev-box".into(),
                },
                Viewer {
                    client: "device-phone".into(),
                    label: "Galaxy S23".into(),
                },
            ],
            reason: "Input moved to Galaxy S23".into(),
        },
        Message::Exit {
            code: Some(0),
            signal: None,
        },
        Message::HostStopping { in_seconds: 10 },
        Message::Structured {
            body: serde_json::json!({"kind": "state", "state": "needs_you"}),
        },
        Message::RecordingList,
        Message::RecordingFetch {
            recording: "01J9Z3K7Q8R2T5V6W8X9Y0ZA1B".into(),
            segment: 0,
            from_chunk: 0,
        },
        Message::RecordingChunk {
            segment: 0,
            index: 2,
            sealed: vec![0, 0, 0, 1, 0xff],
        },
        Message::Rekey {
            switch_at: 7,
            request: true,
        },
        Message::Error {
            code: "shell_input_not_held".into(),
            message: "Input is on my-laptop. Take input?".into(),
        },
    ];
    InnerFile {
        description: "Inner messages: type (u8) ‖ length (u32 BE) ‖ body; binary bodies for out, snapshot, in and recording_chunk, JSON for the rest.".into(),
        types: TYPE_TABLE.iter().map(|(b, n)| (*b, (*n).to_owned())).collect(),
        cases: msgs
            .into_iter()
            .map(|m| InnerCase {
                bytes: to_hex(&m.encode().expect("encode")),
                message: m,
            })
            .collect(),
        malformed: vec![
            // an unknown type
            "ee000000027b7d".into(),
            // a body shorter than its length
            "0100000009".into(),
            // a truncated header
            "010000".into(),
            // ack without its offset
            "06000000027b7d".into(),
            {
                // a type inside a JSON body
                let body = br#"{"type":"in","offset":1}"#;
                format!("06{:08x}{}", body.len(), to_hex(body))
            },
        ],
    }
}

/// Every file, by name, as pretty JSON with a trailing newline.
pub fn all_files() -> Vec<(&'static str, String)> {
    let pretty = |v: serde_json::Value| serde_json::to_string_pretty(&v).expect("json") + "\n";
    vec![
        (
            "handshake.json",
            pretty(serde_json::to_value(handshake_file()).expect("json")),
        ),
        (
            "records.json",
            pretty(serde_json::to_value(record_file()).expect("json")),
        ),
        (
            "presence.json",
            pretty(serde_json::to_value(presence_file()).expect("json")),
        ),
        (
            "recording.json",
            pretty(serde_json::to_value(recording_file()).expect("json")),
        ),
        (
            "inner.json",
            pretty(serde_json::to_value(inner_file()).expect("json")),
        ),
        (
            "structured.json",
            pretty(serde_json::to_value(structured_file()).expect("json")),
        ),
    ]
}
