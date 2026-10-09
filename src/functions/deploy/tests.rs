//! The deploy loop against a canned operator: the order of the calls, what
//! each carries, and where each stop falls. One scripted answer per
//! request, in order, so a call the loop must not make finds no answer and
//! fails the test.

use super::*;
use crate::functions::client::OperatorAuth;
use crate::functions::test_support::{canned_operator, response};
use crate::machine::{Enrollment, MachineIdentity};

/// `function.json` + `src/main.ts`: the operator fixture's "two files"
/// tree, whose canonical digest is known (see `tree.rs`).
const DIGEST: &str = "sha256:d8dfeaa493ac09e5a0db5c347830428fb3887a2a2401fd5d0b31a49a718af8af";
/// The public key of seed `[1; 32]`.
const OWN_KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const OTHER_KEY: &str = "5c1e00000000000000000000000000000000000000000000000000000000a07b";
const BASE: &str = "sha256:aaaa";
const NEW: &str = "sha256:9f2c";
const MACHINE: &str = "0b7e3c1a-0000-4000-8000-000000009d2f";

fn tree_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("function.json"),
        r#"{"entry":"src/main.ts"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/main.ts"),
        "export default () => new Response('a');",
    )
    .unwrap();
    // Not part of the tree: the selection leaves it out.
    std::fs::write(dir.path().join("README.md"), "not deployed").unwrap();
    dir
}

fn opts(ci: bool) -> DeployOpts {
    DeployOpts {
        dir: None,
        name: None,
        yes: true,
        plan: false,
        ci,
        all: false,
        since: None,
        map: None,
        branch: None,
        wait_timeout: 5,
        signing_key: None,
        signer_machine: None,
    }
}

fn own_key() -> OwnSigner {
    OwnSigner::Key {
        public_hex: OWN_KEY.into(),
    }
}

fn live(signers: &Value) -> String {
    serde_json::json!({
        "apiVersion": crate::wire::API_VERSION, "kind": "Function",
        "metadata": { "name": "relay", "generation": 4, "resourceVersion": "7",
                      "created_at": "2026-09-25T10:00:00Z", "updated_at": "2026-09-25T10:00:00Z" },
        "spec": { "runtime": "js-source/v1",
                  "source": { "version": BASE, "signers": signers },
                  "capabilities": { "log": {} }, "enabled": true },
        "status": {}
    })
    .to_string()
}

fn checked(digest: &str) -> String {
    serde_json::json!({ "version": NEW, "sourceDigest": digest, "files": [],
                        "entry": "src/main.ts", "unreachable": [], "dryRun": true, "created": true })
    .to_string()
}

fn published() -> String {
    serde_json::json!({ "version": NEW, "sourceDigest": DIGEST, "created": true }).to_string()
}

fn loaded(generation: i64) -> String {
    serde_json::json!({ "kind": "Function", "name": "relay", "generation": generation,
        "observed_generation": generation, "phase": "Healthy",
        "conditions": [{ "type": "Loaded", "status": "True", "reason": "Loaded", "message": "",
                         "lastTransitionTime": "2026-09-25T10:00:00Z" }] })
    .to_string()
}

async fn go(
    responses: Vec<String>,
    auth: impl FnOnce(&str) -> OperatorAuth,
    t: impl FnOnce(Arc<OperatorFunctionsClient>) -> Target,
    opts: DeployOpts,
    own: OwnSigner,
) -> (Report, Vec<String>) {
    let (base, server) = canned_operator(responses).await;
    let conn = Connection::for_test(&base, auth(&base));
    let target = t(conn.client_for(None).await.unwrap());
    let run = Run {
        conn: &conn,
        opts: &opts,
        own,
        seed: Some([1u8; 32]),
        json: true,
        verbose: false,
    };
    let report = deploy_one(&run, &target).await;
    drop(conn);
    // Fewer calls than scripted leave the server waiting: fail, not hang.
    let seen = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap_or_else(|_| panic!("the loop made fewer calls than scripted: {report:?}"))
        .unwrap();
    (report, seen)
}

fn owner(_: &str) -> OperatorAuth {
    OperatorAuth::Bearer("owner.jwt".into())
}

fn target(
    dir: &Path,
    local: Option<Value>,
) -> impl FnOnce(Arc<OperatorFunctionsClient>) -> Target + '_ {
    move |client| Target {
        name: "relay".into(),
        dir: dir.to_path_buf(),
        manifest_path: local.as_ref().map(|_| dir.join("function.yaml")),
        local,
        committed: None,
        client,
    }
}

fn first_line(req: &str) -> &str {
    req.lines().next().unwrap_or_default()
}

fn body_of(req: &str) -> Value {
    serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap_or("null")).unwrap_or(Value::Null)
}

#[tokio::test]
async fn an_existing_function_is_checked_published_promoted_and_waited_for() {
    let dir = tree_dir();
    let (report, seen) = go(
        vec![
            response("200 OK", &live(&serde_json::json!([{ "key": OWN_KEY }]))),
            response("200 OK", &checked(DIGEST)),
            response("200 OK", r#"{"deployments":[{"version":"sha256:aaaa","at":"2026-09-25T13:29:00Z","actor":"owner"}]}"#),
            response("200 OK", &format!(r#"{{"version":"{BASE}","signer":"{OTHER_KEY}"}}"#)),
            response("201 Created", &published()),
            response("200 OK", &format!(r#"{{"name":"relay","version":"{NEW}","previous":"{BASE}","generation":5,"changed":true}}"#)),
            response("200 OK", &loaded(5)),
            response("200 OK", &format!(r#"{{"current":"{NEW}"}}"#)),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "deployed", "{report:?}");
    assert_eq!(report.previous.as_deref(), Some(BASE));
    assert_eq!(report.version.as_deref(), Some(NEW));

    let lines: Vec<&str> = seen.iter().map(|r| first_line(r)).collect();
    assert_eq!(
        lines,
        [
            "GET /v1/kinds/Function/relay HTTP/1.1",
            "POST /v1/functions/sources?dry-run=true HTTP/1.1",
            "GET /v1/functions/relay/versions HTTP/1.1",
            "GET /v1/functions/sources/sha256:aaaa HTTP/1.1",
            "POST /v1/functions/sources HTTP/1.1",
            "POST /v1/functions/relay/promote HTTP/1.1",
            "GET /v1/kinds/Function/relay/status HTTP/1.1",
            "GET /v1/functions/relay/versions HTTP/1.1",
        ]
    );
    // The check is unsigned and carries the base; the publish is signed.
    let check = body_of(&seen[1]);
    assert_eq!(check["basedOn"], BASE);
    assert!(check.get("signature").is_none());
    let paths: Vec<&str> = check["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        ["function.json", "src/main.ts"],
        "README.md is left out"
    );
    let publish = body_of(&seen[4]);
    assert_eq!(publish["signer"], OWN_KEY);
    assert_eq!(publish["signature"].as_str().unwrap().len(), 128);
    // Promote carries exactly the version and the base; no apply is sent.
    assert_eq!(
        body_of(&seen[5]),
        serde_json::json!({ "version": NEW, "basedOn": BASE })
    );
    assert!(seen.iter().all(|r| !r.starts_with("POST /v1/apply")));
    assert!(
        seen[0].contains("authorization: Bearer owner.jwt")
            || seen[0].contains("Authorization: Bearer owner.jwt")
    );
}

#[tokio::test]
async fn a_retry_after_a_promote_that_landed_is_unchanged_not_a_stop() {
    let dir = tree_dir();
    let (report, seen) = go(
        vec![
            response("200 OK", &live(&serde_json::json!([{ "key": OWN_KEY }]))),
            response("200 OK", &checked(DIGEST)),
            response("404 Not Found", ""),
            response("404 Not Found", ""),
            response("200 OK", &published()),
            response(
                "409 Conflict",
                &format!(r#"{{"error":"source_base_stale","message":"m","basedOn":"{BASE}","current":"{NEW}"}}"#),
            ),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "unchanged", "{report:?}");
    assert_eq!(
        seen.len(),
        6,
        "no status is polled for a version already serving"
    );
}

#[tokio::test]
async fn a_signer_outside_the_set_stops_before_anything_is_sent() {
    let dir = tree_dir();
    let (report, seen) = go(
        vec![response(
            "200 OK",
            &live(&serde_json::json!([{ "key": OTHER_KEY }, { "machine": MACHINE }])),
        )],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "signer_not_this_client");
    let msg = report.message.unwrap();
    assert!(
        msg.contains("key 5c1e…a07b") && msg.contains(MACHINE),
        "{msg}"
    );
    assert!(msg.contains("fn signers add"), "{msg}");
    assert_eq!(seen.len(), 1);
}

#[tokio::test]
async fn a_single_form_is_read_as_a_set_of_one() {
    let dir = tree_dir();
    let mut single: Value = serde_json::from_str(&live(&Value::Null)).unwrap();
    single["spec"]["source"] = serde_json::json!({ "version": BASE, "signer": OWN_KEY });
    let (report, seen) = go(
        vec![
            response("200 OK", &single.to_string()),
            response(
                "422 Unprocessable Entity",
                r#"{"error":"transpile_failed","reason":"TranspileFailed","message":"Expected ';'","locations":[{"path":"src/main.ts","line":1,"column":9}]}"#,
            ),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    // Past the membership test, stopped at the check with the refusal.
    assert_eq!(report.outcome, "check_failed", "{report:?}");
    assert_eq!(report.step, Some("check"));
    assert_eq!(
        refusal::format(report.refusal.as_ref().unwrap()),
        ["src/main.ts:1:9: TranspileFailed: Expected ';'"]
    );
    assert_eq!(seen.len(), 2, "nothing is published after a refused check");
}

#[tokio::test]
async fn a_digest_the_client_did_not_compute_is_never_signed() {
    let dir = tree_dir();
    let (report, seen) = go(
        vec![
            response("200 OK", &live(&serde_json::json!([{ "key": OWN_KEY }]))),
            response("200 OK", &checked("sha256:0000")),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "digest_mismatch");
    assert_eq!(seen.len(), 2);
}

#[tokio::test]
async fn an_operator_without_promote_is_named() {
    let dir = tree_dir();
    let (report, _) = go(
        vec![
            response("200 OK", &live(&serde_json::json!([{ "key": OWN_KEY }]))),
            response("200 OK", &checked(DIGEST)),
            response("404 Not Found", ""),
            response("404 Not Found", ""),
            response("201 Created", &published()),
            response("404 Not Found", ""),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "operator_predates_promote");
    assert!(report
        .message
        .unwrap()
        .contains("spec.source.version: sha256:9f2c"));
}

#[tokio::test]
async fn a_new_function_is_published_then_applied_with_the_set_form() {
    let dir = tree_dir();
    std::fs::write(
        dir.path().join("function.json"),
        r#"{"entry":"src/main.ts","capabilities":[{"name":"airdress:fn/log@0.1.0"}]}"#,
    )
    .unwrap();
    let digest = format!(
        "sha256:{}",
        tree::hex(&tree::canonical_digest(
            &layout::select(dir.path()).unwrap().0
        ))
    );
    let (report, seen) = go(
        vec![
            response(
                "404 Not Found",
                r#"{"error":{"code":"not_found","message":"no"}}"#,
            ),
            response("200 OK", &checked(&digest)),
            response(
                "201 Created",
                &serde_json::json!({ "version": NEW, "sourceDigest": digest }).to_string(),
            ),
            response(
                "201 Created",
                r#"{"kind":"Function","name":"relay","action":"created","generation":1}"#,
            ),
            response("200 OK", &loaded(1)),
            response("200 OK", &format!(r#"{{"current":"{NEW}"}}"#)),
        ],
        owner,
        target(dir.path(), None),
        opts(false),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "deployed", "{report:?}");
    // The publish names no base: there is nothing yet to be based on.
    assert!(body_of(&seen[2]).get("basedOn").is_none());
    let applied = body_of(&seen[3]);
    assert!(first_line(&seen[3]).starts_with("POST /v1/apply "));
    assert_eq!(
        applied["spec"]["source"],
        serde_json::json!({ "version": NEW, "signers": [{ "key": OWN_KEY }] })
    );
    assert_eq!(
        applied["spec"]["capabilities"],
        serde_json::json!({ "log": {} })
    );
    assert_eq!(applied["metadata"]["name"], "relay");
    // The manifest a repository needs is written beside the tree.
    let written: Value =
        serde_yaml::from_str(&std::fs::read_to_string(dir.path().join("function.yaml")).unwrap())
            .unwrap();
    assert_eq!(written, applied);
}

#[tokio::test]
async fn ci_never_creates_a_function() {
    let dir = tree_dir();
    let committed = serde_json::json!({ "metadata": { "name": "relay" },
                                        "spec": { "source": { "signers": [{ "key": OWN_KEY }] } } });
    let d = dir.path().to_path_buf();
    let (report, seen) = go(
        vec![],
        owner,
        move |client| Target {
            name: "relay".into(),
            dir: d,
            manifest_path: None,
            local: Some(committed.clone()),
            committed: Some(committed),
            client,
        },
        opts(true),
        own_key(),
    )
    .await;
    assert_eq!(report.outcome, "function_missing");
    assert!(seen.is_empty());
}

fn machine_identity() -> Arc<MachineIdentity> {
    Arc::new(MachineIdentity::new(
        [7u8; 32],
        Enrollment {
            operator: "https://op.example".into(),
            machine_id: MACHINE.parse().unwrap(),
            kid: "k-0011223344556677".into(),
            authorized_until: None,
        },
    ))
}

fn ci_manifest() -> &'static str {
    "apiVersion: airdress.co/v1alpha1\n\
     kind: Function\n\
     metadata:\n\
    \x20 name: relay\n\
     spec:\n\
    \x20 runtime: js-source/v1\n\
    \x20 source:\n\
    \x20   version: \"sha256:aaaa\"   # the serving version\n\
    \x20   signers:\n\
    \x20     - key: \"5c1e00000000000000000000000000000000000000000000000000000000a07b\"\n\
    \x20     - machine: \"0b7e3c1a-0000-4000-8000-000000009d2f\"\n\
    \x20 capabilities:\n\
    \x20   log: {}\n"
}

#[tokio::test]
async fn ci_signs_every_request_as_the_machine_and_writes_the_version_back() {
    let dir = tree_dir();
    let manifest_path = dir.path().join("function.yaml");
    std::fs::write(&manifest_path, ci_manifest()).unwrap();
    let committed: Value = serde_yaml::from_str(ci_manifest()).unwrap();
    let id = machine_identity();
    let own = OwnSigner::Machine {
        machine: MACHINE.into(),
        public_hex: OWN_KEY.into(),
    };
    let path = manifest_path.clone();
    let d = dir.path().to_path_buf();
    let (report, seen) = go(
        vec![
            // FR-41: no Get on the function — the drift note is skipped.
            response("403 Forbidden", r#"{"error":{"code":"resource_forbidden","message":"no"}}"#),
            response("200 OK", &checked(DIGEST)),
            response("200 OK", r#"{"deployments":[]}"#),
            response("403 Forbidden", r#"{"error":{"code":"resource_forbidden","message":"no"}}"#),
            response("201 Created", &published()),
            response("200 OK", &format!(r#"{{"name":"relay","version":"{NEW}","previous":"{BASE}","generation":9,"changed":true}}"#)),
            response("200 OK", &loaded(9)),
            response("200 OK", &format!(r#"{{"current":"{NEW}"}}"#)),
        ],
        |_| OperatorAuth::Machine(Arc::clone(&id)),
        move |client| Target {
            name: "relay".into(),
            dir: d,
            manifest_path: Some(path),
            local: Some(committed.clone()),
            committed: Some(committed),
            client,
        },
        opts(true),
        own,
    )
    .await;
    assert_eq!(report.outcome, "deployed", "{report:?}");
    for req in &seen {
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("signature-input: sig1="), "{req}");
        assert!(lower.contains("tag=\"airdress-machine\""), "{req}");
        assert!(
            !lower.contains("authorization:"),
            "a machine sends no bearer: {req}"
        );
    }
    let publish = body_of(&seen[4]);
    assert_eq!(publish["signerRef"]["machine"], MACHINE);
    assert!(publish.get("signer").is_none());
    assert_eq!(body_of(&seen[5])["basedOn"], BASE);
    // Exactly one scalar moved in the committed manifest.
    let after = std::fs::read_to_string(&manifest_path).unwrap();
    assert_eq!(
        after,
        ci_manifest().replace("\"sha256:aaaa\"   #", "\"sha256:9f2c\"   #")
    );
    assert!(report.write_back.is_some());
}

#[tokio::test]
async fn ci_names_who_moved_the_function_and_does_not_retry() {
    let dir = tree_dir();
    let committed: Value = serde_yaml::from_str(ci_manifest()).unwrap();
    let id = machine_identity();
    let own = OwnSigner::Machine {
        machine: MACHINE.into(),
        public_hex: OWN_KEY.into(),
    };
    let d = dir.path().to_path_buf();
    let (report, seen) = go(
        vec![
            response("403 Forbidden", r#"{"error":{"code":"resource_forbidden","message":"no"}}"#),
            response("200 OK", &checked(DIGEST)),
            response("200 OK", r#"{"deployments":[]}"#),
            response("200 OK", "{}"),
            response("201 Created", &published()),
            response(
                "409 Conflict",
                &format!(r#"{{"error":"source_base_stale","message":"moved","basedOn":"{BASE}","current":"sha256:e1e1"}}"#),
            ),
            response(
                "200 OK",
                r#"{"current":"sha256:e1e1","deployments":[{"version":"sha256:e1e1","actor":"owner@workstation","at":"2026-09-25T14:00:00Z"}]}"#,
            ),
        ],
        |_| OperatorAuth::Machine(Arc::clone(&id)),
        move |client| Target {
            name: "relay".into(),
            dir: d,
            manifest_path: None,
            local: Some(committed.clone()),
            committed: Some(committed),
            client,
        },
        opts(true),
        own,
    )
    .await;
    assert_eq!(report.outcome, "source_base_stale");
    assert_eq!(report.step, Some("promote"));
    assert!(
        report
            .notes
            .iter()
            .any(|n| n == "sha256:e1e1 was deployed by owner@workstation at 2026-09-25T14:00:00Z"),
        "{:?}",
        report.notes
    );
    assert_eq!(seen.len(), 7, "one promote, never a second");
}

#[tokio::test]
async fn a_lapsed_machine_approval_is_its_own_stop() {
    let dir = tree_dir();
    let committed: Value = serde_yaml::from_str(ci_manifest()).unwrap();
    let id = machine_identity();
    let d = dir.path().to_path_buf();
    let (report, _) = go(
        vec![response(
            "401 Unauthorized",
            r#"{"error":{"code":"machine_authorization_expired","message":"re-authenticate"}}"#,
        )],
        |_| OperatorAuth::Machine(Arc::clone(&id)),
        move |client| Target {
            name: "relay".into(),
            dir: d,
            manifest_path: None,
            local: Some(committed.clone()),
            committed: Some(committed),
            client,
        },
        opts(true),
        OwnSigner::Machine {
            machine: MACHINE.into(),
            public_hex: OWN_KEY.into(),
        },
    )
    .await;
    assert_eq!(
        report.outcome, "machine_authorization_expired",
        "{report:?}"
    );
    assert!(report.message.unwrap().contains("machine reauth"));
}

#[test]
fn the_confirmations_say_what_design_section_three_three_says() {
    let replace = replace_text(
        "019e2b8c.a.airdr.es",
        "relay-v2",
        Some(BASE),
        Some("serving since 2026-09-25T13:29:00Z, signed by machine ci"),
        Some(NEW),
        3,
        1,
        &own_key(),
    );
    assert_eq!(
        replace,
        "Deploy relay-v2 on 019e2b8c.a.airdr.es\n\
         \x20 replace  sha256:aaaa  (serving since 2026-09-25T13:29:00Z, signed by machine ci)\n\
         \x20 with     sha256:9f2c  (3 files; 1 not reached by an import)\n\
         \x20 signed by key 8a88…6f5c (this workstation) — a member of this function's signers\n\
         \x20 The grant does not change."
    );
    let files: Files = [("function.json".to_owned(), b"{}".to_vec())].into();
    let manifest =
        draft_manifest("relay-v2", NEW, &Member::Key(OWN_KEY.into()), None, &files).unwrap();
    let create = create_text("h", "relay-v2", Some(NEW), &files, &own_key(), &manifest);
    assert!(create.starts_with("Create relay-v2 on h\n  version  sha256:9f2c  (1 file)\n"));
    assert!(create.contains("    spec:\n"), "{create}");
    assert!(create.contains(&format!("- key: {OWN_KEY}")), "{create}");
}

#[test]
fn a_create_from_an_owners_manifest_keeps_the_grant_and_writes_the_set() {
    let local: Value = serde_yaml::from_str(
        "apiVersion: airdress.co/v1alpha1\nkind: Function\nmetadata:\n  name: relay\nspec:\n  \
         runtime: js-source/v1\n  source:\n    signer: 5c1e00000000000000000000000000000000000000000000000000000000a07b\n  \
         capabilities:\n    http: { hosts: [peer.example] }\n  config:\n    - name: target\n      value: x\n",
    )
    .unwrap();
    let files: Files = Files::new();
    let m = draft_manifest(
        "relay",
        NEW,
        &Member::Key(OWN_KEY.into()),
        Some(&local),
        &files,
    )
    .unwrap();
    // The single form is never written; this client's key is the set.
    assert_eq!(
        m["spec"]["source"],
        serde_json::json!({ "version": NEW, "signers": [{ "key": OWN_KEY }] })
    );
    assert_eq!(m["spec"]["capabilities"], local["spec"]["capabilities"]);
    assert_eq!(m["spec"]["config"], local["spec"]["config"]);
    // A set that already holds this key is kept as it is.
    let mut with_set = local.clone();
    with_set["spec"]["source"] =
        serde_json::json!({ "signers": [{ "machine": MACHINE }, { "key": OWN_KEY }] });
    let m = draft_manifest(
        "relay",
        NEW,
        &Member::Key(OWN_KEY.into()),
        Some(&with_set),
        &files,
    )
    .unwrap();
    assert_eq!(m["spec"]["source"]["signers"].as_array().unwrap().len(), 2);
}

#[test]
fn a_create_keeps_the_event_binding_and_its_confirmation_says_so() {
    // What `airdress fn new location-status` writes.
    let local: Value = serde_yaml::from_str(&crate::functions::scaffold::manifest_yaml(
        &serde_json::json!({
            "requires": { "kv": {}, "log": {} },
            "events": { "source": "location" },
            "config": { "fields": [] }
        }),
        FUNCTION_API_VERSION,
        layout::SOURCE_RUNTIME,
    ))
    .unwrap();
    let files: Files = [("function.json".to_owned(), b"{}".to_vec())].into();
    let m = draft_manifest(
        "where",
        NEW,
        &Member::Key(OWN_KEY.into()),
        Some(&local),
        &files,
    )
    .unwrap();
    assert_eq!(
        m["spec"]["events"],
        serde_json::json!({ "source": "location" })
    );
    let create = create_text("h", "where", Some(NEW), &files, &own_key(), &m);
    assert!(
        create.contains("\n  It will receive: your location events (source: location)\n"),
        "{create}"
    );
    assert!(create.contains("      source: location\n"), "{create}");
    assert!(!create.contains("locationToModels"), "{create}");

    // Consent to models is named when the owner has added it.
    let mut to_models = m.clone();
    to_models["spec"]["events"]["locationToModels"] = true.into();
    assert_eq!(
        events_line(&to_models).unwrap(),
        "  It will receive: your location events (source: location), and may pass them to a \
         model (locationToModels: true)"
    );

    // No function.yaml: the draft from function.json binds no events, and
    // the confirmation has no such line.
    let drafted = draft_manifest("where", NEW, &Member::Key(OWN_KEY.into()), None, &files).unwrap();
    assert!(drafted["spec"].get("events").is_none());
    assert!(events_line(&drafted).is_none());
    let create = create_text("h", "where", Some(NEW), &files, &own_key(), &drafted);
    assert!(!create.contains("It will receive"), "{create}");
}

#[test]
fn drift_names_what_ci_will_not_change() {
    let committed = serde_json::json!({
        "runtime": "js-source/v1",
        "source": { "version": "sha256:old", "signers": [{ "key": OWN_KEY }] },
        "capabilities": { "log": {} },
    });
    let live = serde_json::json!({
        "runtime": "js-source/v1",
        "source": { "version": "sha256:new", "signer": OWN_KEY },
        "capabilities": { "log": {}, "http": { "hosts": ["x"] } },
        "enabled": true,
    });
    // The version is expected to differ, a single form equals its set,
    // and a default the operator filled in is not drift.
    assert_eq!(drift(&committed, &live), ["capabilities"]);
}

#[tokio::test]
async fn a_stale_check_whose_current_is_this_tree_is_unchanged_and_written_back() {
    // The deploy that landed lost its write-back: git still names BASE,
    // the function runs NEW, and NEW is this very tree.
    let dir = tree_dir();
    let manifest_path = dir.path().join("function.yaml");
    std::fs::write(&manifest_path, ci_manifest()).unwrap();
    let committed: Value = serde_yaml::from_str(ci_manifest()).unwrap();
    let id = machine_identity();
    let d = dir.path().to_path_buf();
    let path = manifest_path.clone();
    let (report, seen) = go(
        vec![
            response("403 Forbidden", r#"{"error":{"code":"resource_forbidden","message":"no"}}"#),
            response(
                "409 Conflict",
                &format!(r#"{{"error":"source_base_stale","message":"moved","basedOn":"{BASE}","current":"{NEW}"}}"#),
            ),
            // The second check, based on what runs, names this tree's version.
            response("200 OK", &checked(DIGEST)),
        ],
        |_| OperatorAuth::Machine(Arc::clone(&id)),
        move |client| Target {
            name: "relay".into(),
            dir: d,
            manifest_path: Some(path),
            local: Some(committed.clone()),
            committed: Some(committed),
            client,
        },
        opts(true),
        OwnSigner::Machine {
            machine: MACHINE.into(),
            public_hex: OWN_KEY.into(),
        },
    )
    .await;
    assert_eq!(report.outcome, "unchanged", "{report:?}");
    assert_eq!(body_of(&seen[2])["basedOn"], NEW);
    assert!(seen.iter().all(|r| !first_line(r).contains("promote")));
    assert!(std::fs::read_to_string(&manifest_path)
        .unwrap()
        .contains("\"sha256:9f2c\""));
}
