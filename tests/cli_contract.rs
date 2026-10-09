//! The exit-code contract (`docs/exit-codes.md`), driven through the real
//! binary: one case per code reachable without a network (a loopback mock
//! stands in for the hub), and the shape of the `--output json` failure.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

/// A hub that answers every request with `status` and `body`.
fn mock_hub(status: &'static str, body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut sink = vec![0; length];
            reader.read_exact(&mut sink).ok();
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).ok();
        }
    });
    port
}

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

/// A home with one profile `t`, signed in through a hub at `port`, holding a
/// live access token for the hub API (so nothing refreshes).
fn home_with_profile(port: u16) -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("tempdir");
    let base = format!("http://127.0.0.1:{port}");
    let profiles = home.path().join(".airdress/profiles");
    std::fs::create_dir_all(&profiles).expect("profiles dir");
    let profile = serde_json::json!({
        "schema_version": 3,
        "endpoint": base,
        "auth": {
            "method": "hub",
            "issuer": base,
            "client_id": "cli",
            "token_endpoint": format!("{base}/oauth/token"),
            "hub_resource": format!("{base}/api"),
            "refresh_token": "r",
            "id_token_claims": { "sub": "s", "email": "e@example.test" },
            "access_tokens": {
                format!("{base}/api"): { "access_token": "t", "expires_at": "2099-01-01T00:00:00Z" }
            }
        }
    });
    std::fs::write(profiles.join("t.json"), profile.to_string()).expect("write profile");
    home
}

fn airdress(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_airdress"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("AIRDRESS_TIMEOUT", "10")
        .output()
        .expect("run airdress")
}

/// The failure object of a `--output json` run: stderr is exactly one JSON
/// object and nothing else.
fn json_failure(out: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "stderr is one line: {stderr}");
    let v: Value = serde_json::from_str(lines[0]).expect("stderr is JSON");
    let obj = v.as_object().expect("an object");
    for key in obj.keys() {
        assert!(
            ["code", "message", "hint", "status"].contains(&key.as_str()),
            "unexpected field {key}: {v}"
        );
    }
    assert!(v["code"].is_string(), "{v}");
    assert!(v["message"].is_string(), "{v}");
    v
}

fn list_against(port: u16, json: bool) -> Output {
    let home = home_with_profile(port);
    let mut args = vec!["a", "list", "-p", "t"];
    if json {
        args.splice(0..0, ["-o", "json"]);
    }
    airdress(home.path(), &args)
}

#[test]
fn zero_on_success() {
    let home = tempfile::tempdir().unwrap();
    let out = airdress(home.path(), &["version"]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn help_is_not_a_failure() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(airdress(home.path(), &["--help"]).status.code(), Some(0));
}

#[test]
fn one_on_an_unexpected_server_error() {
    let out = list_against(mock_hub("500 Internal Server Error", "{}"), true);
    assert_eq!(out.status.code(), Some(1));
    let v = json_failure(&out);
    assert_eq!(v["status"], 500);
}

#[test]
fn two_on_usage() {
    let home = tempfile::tempdir().unwrap();
    let out = airdress(home.path(), &["no-such-command"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));

    let out = airdress(home.path(), &["--output", "json", "no-such-command"]);
    assert_eq!(out.status.code(), Some(2));
    let v = json_failure(&out);
    assert_eq!(v["code"], "usage");
}

#[test]
fn three_on_a_refusal() {
    let out = list_against(
        mock_hub(
            "403 Forbidden",
            r#"{"error":{"code":"not_owner","message":"not yours"}}"#,
        ),
        true,
    );
    assert_eq!(out.status.code(), Some(3));
    let v = json_failure(&out);
    assert_eq!(v["code"], "not_owner");
    assert_eq!(v["status"], 403);
}

#[test]
fn four_when_not_signed_in() {
    let home = tempfile::tempdir().unwrap();
    let out = airdress(home.path(), &["-o", "json", "auth", "token", "-p", "ghost"]);
    assert_eq!(out.status.code(), Some(4));
    let v = json_failure(&out);
    assert_eq!(v["code"], "profile_not_found");
    assert!(v["hint"].as_str().unwrap().contains("auth login"), "{v}");

    // Human mode: `Error: …`, then the hint.
    let out = airdress(home.path(), &["auth", "token", "-p", "ghost"]);
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("Error: "), "{stderr}");
    assert!(
        stderr.contains("hint: run `airdress auth login --profile ghost`"),
        "{stderr}"
    );
}

#[test]
fn four_when_the_server_says_unauthenticated() {
    let out = list_against(mock_hub("401 Unauthorized", ""), true);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(json_failure(&out)["status"], 401);
}

#[test]
fn five_when_unreachable() {
    let out = list_against(closed_port(), true);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(json_failure(&out)["code"], "unreachable");
}

#[test]
fn five_when_a_proxy_says_unavailable() {
    let out = list_against(mock_hub("503 Service Unavailable", ""), false);
    assert_eq!(out.status.code(), Some(5));
}

#[test]
fn six_on_a_conflict() {
    let out = list_against(
        mock_hub(
            "409 Conflict",
            r#"{"error":"epoch_conflict","message":"lost the race"}"#,
        ),
        true,
    );
    assert_eq!(out.status.code(), Some(6));
    let v = json_failure(&out);
    assert_eq!(v["code"], "epoch_conflict");
    assert_eq!(v["status"], 409);
}

#[test]
fn the_code_decides_before_the_status() {
    let out = list_against(
        mock_hub(
            "400 Bad Request",
            r#"{"error":"source_base_stale","message":"moved"}"#,
        ),
        true,
    );
    assert_eq!(out.status.code(), Some(6));
}

#[test]
fn text_mode_failure_is_error_then_message() {
    let out = list_against(mock_hub("403 Forbidden", ""), false);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("Error: "), "{stderr}");
    assert!(serde_json::from_str::<Value>(stderr.trim()).is_err());
}

// ---------------------------------------------------------------------------
// The one confirmation prompt (CLI-4): `shell device forget` asks before it
// touches anything, so it is reached with only a mock hub to resolve the
// airdress.
// ---------------------------------------------------------------------------

const ONE_AIRDRESS: &str = r#"{"items":[{"id":"0190","name":"x","fqdn":"x.a.airdr.es","ipv4_address":"192.0.2.1","status":"active","created_at":"2026-10-07T00:00:00Z"}],"next_cursor":null}"#;

fn forget(json: bool, yes: bool) -> Output {
    let home = home_with_profile(mock_hub("200 OK", ONE_AIRDRESS));
    std::fs::write(home.path().join(".airdress/config"), "t\n").expect("active profile");
    let mut args = vec!["-A", "x", "shell", "device", "forget"];
    if json {
        args.splice(0..0, ["-o", "json"]);
    }
    if yes {
        args.push("--yes");
    }
    airdress(home.path(), &args)
}

#[test]
fn seven_when_a_confirmation_cannot_be_asked() {
    // stdin is not a terminal here (the harness gives the child none).
    let out = forget(false, false);
    assert_eq!(out.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("[y/N]"), "never asked: {stderr}");
    assert!(stderr.contains("stdin is not a terminal"), "{stderr}");
    assert!(stderr.contains("hint: pass `--yes`"), "{stderr}");
}

#[test]
fn json_mode_never_prompts_and_names_the_flag() {
    let out = forget(true, false);
    assert_eq!(out.status.code(), Some(7));
    let v = json_failure_with_extra(&out);
    assert_eq!(v["code"], "confirmation_required");
    assert_eq!(v["flag"], "--yes");
    assert!(v["hint"].as_str().unwrap().contains("--yes"), "{v}");
}

#[test]
fn yes_confirms_without_asking() {
    let out = forget(false, true);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("[y/N]"), "{stderr}");
}

/// [`json_failure`], allowing the fields a refusal carries beyond the four.
fn json_failure_with_extra(out: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "stderr is one line: {stderr}");
    serde_json::from_str(lines[0]).expect("stderr is JSON")
}

/// A hub that accepts and never answers.
fn silent_hub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    port
}

/// CLI-14: `--timeout` beats `AIRDRESS_TIMEOUT` (the harness sets it to
/// 10), and the deadline it sets is the one that fires: exit 5 after one
/// second, not ten.
#[test]
fn the_timeout_flag_beats_the_env() {
    let home = home_with_profile(silent_hub());
    let started = std::time::Instant::now();
    let out = airdress(
        home.path(),
        &["--timeout", "1", "-o", "json", "a", "list", "-p", "t"],
    );
    assert_eq!(out.status.code(), Some(5));
    let v = json_failure(&out);
    assert_eq!(v["code"], "timeout");
    assert!(v["message"].as_str().unwrap().contains("after 1s"), "{v}");
    assert!(started.elapsed() < std::time::Duration::from_secs(8));
}
