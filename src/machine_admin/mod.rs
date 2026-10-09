//! `airdress machines …` — the owner decides on machines from a terminal.
//!
//! The owner's half of machine enrollment (SPEC-098; the approve-time link
//! is SPEC-116 task 116-S.2): list what is waiting, approve one after
//! comparing what the machine printed, deny one, and — for machines already
//! approved — list and revoke. The same operator routes the VS Code
//! extension and the approve page call, with the owner's hub sign-in.
//!
//! **No approval without a comparison.** `approve` takes the fingerprint or
//! the confirmation code the machine printed, and the operator compares it
//! with the key it holds. There is no flag that approves without one.
//!
//! **A link is only sent when it was offered.** `--link-home` asks the
//! operator to also bind the machine as a `Home`. The enrollment listing says
//! which kinds this operator will link it as; when `Home` is not among them
//! (or the operator predates the field) the CLI refuses locally, before
//! anything is sent — an older operator would reject the unknown field, and a
//! newer one would refuse it anyway.

pub mod client;

use anyhow::{bail, Result};
use clap::{ArgGroup, Subcommand};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use client::{ApproveBody, Approved, Comparison, Link, MachineAdminClient, PendingEnrollment};

/// The link kind `--link-home` asks for.
pub const HOME_KIND: &str = "Home";

/// The name a Home link takes when `--link-home` is given without one.
pub const DEFAULT_HOME_NAME: &str = "home";

/// User-code alphabet and length — the operator's `machines::codes`.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

#[derive(Debug, Subcommand)]
pub enum MachinesCommands {
    /// List enrollments waiting for your decision: user code, name, purpose,
    /// fingerprint, confirmation code and expiry.
    Pending,
    /// Approve one enrollment, after comparing what the machine printed.
    ///
    /// Give the fingerprint (`SHA256:…`) or the confirmation code the machine
    /// showed; the operator approves only if it matches the key it holds.
    #[command(group(ArgGroup::new("comparison").required(true).args(["fingerprint", "confirmation_code"])))]
    Approve {
        /// The user code the machine printed, like WDJB-MJHT.
        user_code: String,
        /// The fingerprint the machine printed, `SHA256:…`.
        #[arg(long, value_name = "SHA256:…")]
        fingerprint: Option<String>,
        /// The confirmation code the machine printed.
        #[arg(long, value_name = "CODE")]
        confirmation_code: Option<String>,
        /// Also link the machine as a Home of this name (default `home`).
        /// Only offered for enrollments the operator lists as linkable.
        #[arg(long, value_name = "NAME", num_args = 0..=1, default_missing_value = DEFAULT_HOME_NAME)]
        link_home: Option<String>,
    },
    /// Deny one enrollment. The machine has to start again.
    Deny {
        /// The user code the machine printed.
        user_code: String,
    },
    /// List approved machines, revoked ones included.
    List,
    /// Revoke an approved machine. Takes effect on its next request.
    Revoke {
        /// Machine id, as `airdress machines list` prints it.
        machine_id: uuid::Uuid,
        /// Why, for the audit record.
        #[arg(long)]
        reason: String,
        /// For a machine that signs function source: `rotated` keeps what it
        /// signed running, `compromised` quarantines it.
        #[arg(long, value_parser = ["rotated", "compromised"])]
        source_signing: Option<String>,
    },
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

pub async fn run(command: MachinesCommands, args: RunArgs<'_>) -> Result<()> {
    // Local checks first: nothing is resolved or sent for a malformed call.
    let prepared = prepare(&command)?;
    let op = connect(&args).await?;
    match (command, prepared) {
        (MachinesCommands::Pending, _) => {
            let rows = op.pending().await?;
            if args.json {
                print_json(&serde_json::json!({ "enrollments": rows }))?;
            } else if rows.is_empty() {
                ui::say("no pending enrollments");
            } else {
                println!("{}", render_pending(&rows));
            }
        }
        (
            MachinesCommands::Approve { .. },
            Prepared::Approve {
                code,
                comparison,
                link,
            },
        ) => {
            let approved = approve(&op, &code, &comparison, link.as_ref()).await?;
            if args.json {
                print_json(&approved)?;
            } else {
                println!("{}", render_approved(&approved));
            }
        }
        (MachinesCommands::Deny { .. }, Prepared::Code(code)) => {
            op.deny(&code).await?;
            if args.json {
                print_json(&serde_json::json!({ "user_code": code, "denied": true }))?;
            } else {
                ui::ok(format!("denied enrollment {code}"));
            }
        }
        (MachinesCommands::List, _) => {
            let list = op.list().await?;
            if args.json {
                print_json(&list)?;
            } else {
                println!("{}", render_list(&list));
            }
        }
        (
            MachinesCommands::Revoke {
                machine_id,
                reason,
                source_signing,
            },
            _,
        ) => {
            let revoked = op
                .revoke(machine_id, &reason, source_signing.as_deref())
                .await?;
            if args.json {
                print_json(&revoked)?;
            } else {
                ui::ok(format!("revoked machine {machine_id}"));
            }
        }
        _ => unreachable!("prepare matches the command"),
    }
    Ok(())
}

/// A command's arguments, checked before anything is sent.
#[derive(Debug, PartialEq, Eq)]
enum Prepared {
    None,
    Code(String),
    Approve {
        code: String,
        comparison: Comparison,
        link: Option<Link>,
    },
}

fn prepare(command: &MachinesCommands) -> Result<Prepared> {
    Ok(match command {
        MachinesCommands::Approve {
            user_code,
            fingerprint,
            confirmation_code,
            link_home,
        } => {
            let code = normalize_user_code(user_code)?;
            let comparison = match (fingerprint, confirmation_code) {
                (Some(f), None) => Comparison::Fingerprint(f.trim().to_owned()),
                (None, Some(c)) => Comparison::ConfirmationCode(c.trim().to_owned()),
                _ => bail!(
                    "give exactly one of --fingerprint or --confirmation-code — nothing is \
                     approved without comparing what the machine printed"
                ),
            };
            let link = match link_home {
                None => None,
                Some(name) => Some(Link {
                    kind: HOME_KIND.to_owned(),
                    name: valid_link_name(name)?,
                }),
            };
            Prepared::Approve {
                code,
                comparison,
                link,
            }
        }
        MachinesCommands::Deny { user_code } => Prepared::Code(normalize_user_code(user_code)?),
        MachinesCommands::Revoke { reason, .. } if reason.trim().is_empty() => {
            bail!("--reason must say why; it is kept with the revocation")
        }
        _ => Prepared::None,
    })
}

/// Read the enrollment first — to show what is being approved and to know
/// whether a link may be asked for — then approve.
async fn approve(
    op: &MachineAdminClient,
    code: &str,
    comparison: &Comparison,
    link: Option<&Link>,
) -> Result<Approved> {
    let pending = op.pending().await?;
    let Some(enrollment) = pending.iter().find(|e| e.user_code == code) else {
        bail!(
            "approve: no pending enrollment has user code {code} — it was already decided, \
             or the code is mistyped. `airdress machines pending` lists what is waiting"
        );
    };
    if let Some(link) = link {
        check_link_offered(enrollment, link)?;
    }
    ui::say(render_one(enrollment));
    op.approve(code, &ApproveBody::new(comparison, link)).await
}

fn check_link_offered(enrollment: &PendingEnrollment, link: &Link) -> Result<()> {
    if enrollment.links.iter().any(|k| k == &link.kind) {
        return Ok(());
    }
    bail!(
        "enrollment {} cannot be linked as a {} on this operator{} — approve it without \
         --link-home, or update the operator. Nothing was sent",
        enrollment.user_code,
        link.kind,
        if enrollment.links.is_empty() {
            String::from(" (it offers no links)")
        } else {
            format!(" (it offers: {})", enrollment.links.join(", "))
        }
    )
}

/// `WDJB-MJHT`, `wdjbmjht` and `wdjb mjht` are one code; the operator's own
/// normalization, so a typo is caught before a round trip.
fn normalize_user_code(input: &str) -> Result<String> {
    let raw: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if raw.len() == USER_CODE_LEN && raw.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)) {
        Ok(format!("{}-{}", &raw[..4], &raw[4..]))
    } else {
        bail!("`{input}` is not a user code (8 letters, like WDJB-MJHT)")
    }
}

/// A link name: lowercase letters, digits and inner hyphens, 1–63
/// characters — the operator's rule.
fn valid_link_name(name: &str) -> Result<String> {
    let b = name.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = !b.is_empty()
        && b.len() <= 63
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| edge(c) || c == b'-');
    if ok {
        Ok(name.to_owned())
    } else {
        bail!(
            "`{name}` is not a Home name: lowercase letters, digits and inner hyphens, \
             at most 63 characters (like `home`)"
        )
    }
}

async fn connect(args: &RunArgs<'_>) -> Result<MachineAdminClient> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(url) = args.operator_url {
        let bearer = hub.operator_bearer(url).await?;
        return MachineAdminClient::with_base_url(url.to_owned(), bearer);
    }
    let resolved = context::resolve(paths, &profile_name, args.explicit_airdress)?;
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }
    let fqdn = hub.resolve_fqdn(&resolved.name).await?;
    MachineAdminClient::new(&fqdn, hub.operator_bearer(&fqdn).await?)
}

fn render_one(e: &PendingEnrollment) -> String {
    let mut out = format!("{}  {}", e.user_code, e.name);
    if let Some(purpose) = &e.purpose {
        out.push_str(&format!("  ({purpose})"));
    }
    if e.kind.as_deref() == Some("reauth") {
        out.push_str("  [re-authentication]");
    }
    out.push_str(&format!("\n  fingerprint:  {}", e.fingerprint));
    if let Some(code) = &e.confirmation_code {
        out.push_str(&format!("\n  code:         {code}"));
    }
    out.push_str(&format!("\n  expires:      {}", e.expires_at));
    if !e.links.is_empty() {
        out.push_str(&format!("\n  can link as:  {}", e.links.join(", ")));
    }
    out
}

fn render_pending(rows: &[PendingEnrollment]) -> String {
    rows.iter().map(render_one).collect::<Vec<_>>().join("\n\n")
}

fn render_approved(a: &Approved) -> String {
    let mut out = format!("approved machine {} `{}`", a.machine_id, a.name);
    if let Some(link) = &a.link {
        out.push_str(&format!("\nlinked as {} `{}`", link.kind, link.name));
    }
    if a.kind.as_deref() != Some("reauth") {
        if a.grants.is_empty() && a.link.is_none() {
            out.push_str("\nit can reach nothing until a grant says so");
        } else if !a.grants.is_empty() {
            out.push_str(&format!("\ngranted: {}", a.grants.join(" ")));
        }
    }
    out
}

fn render_list(list: &serde_json::Value) -> String {
    let rows = list
        .get("machines")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return "no machines".to_owned();
    }
    let s = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let mut out = format!(
        "{:<36}  {:<24}  {:<51}  state",
        "machine_id", "name", "fingerprint"
    );
    for m in rows {
        let state = match m.get("revoked_at").and_then(serde_json::Value::as_str) {
            Some(at) => format!("revoked {at}"),
            None => match m
                .pointer("/authorization/expires_at")
                .and_then(serde_json::Value::as_str)
            {
                Some(until) => format!("live, approved until {until}"),
                None => "live".to_owned(),
            },
        };
        out.push_str(&format!(
            "\n{:<36}  {:<24}  {:<51}  {state}",
            s(&m, "machine_id"),
            s(&m, "name"),
            s(&m, "fingerprint")
        ));
    }
    out
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};

    fn approve_cmd(link_home: Option<&str>, fp: bool) -> MachinesCommands {
        MachinesCommands::Approve {
            user_code: "wdjb-mjht".into(),
            fingerprint: fp.then(|| "SHA256:abc".into()),
            confirmation_code: (!fp).then(|| "KXQZ-7F2M".into()),
            link_home: link_home.map(str::to_owned),
        }
    }

    #[test]
    fn user_codes_normalize_like_the_operator() {
        assert_eq!(normalize_user_code("wdjb-mjht").unwrap(), "WDJB-MJHT");
        assert_eq!(normalize_user_code("WDJBMJHT").unwrap(), "WDJB-MJHT");
        assert_eq!(normalize_user_code("wdjb mjht").unwrap(), "WDJB-MJHT");
        // Vowels and digits are not in the alphabet; length is exact.
        for bad in ["WDJB-MJHA", "WDJB-MJH1", "WDJB-MJH", "WDJB-MJHTT", ""] {
            assert!(normalize_user_code(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn link_names_follow_the_operator_rule() {
        for ok in ["home", "h", "my-home-2", &"a".repeat(63)] {
            assert!(valid_link_name(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "Home",
            "-home",
            "home-",
            "my_home",
            "hé",
            &"a".repeat(64),
        ] {
            assert!(valid_link_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn approve_is_prepared_with_one_comparison_and_the_link() {
        let p = prepare(&approve_cmd(Some("home"), true)).unwrap();
        assert_eq!(
            p,
            Prepared::Approve {
                code: "WDJB-MJHT".into(),
                comparison: Comparison::Fingerprint("SHA256:abc".into()),
                link: Some(Link {
                    kind: "Home".into(),
                    name: "home".into()
                }),
            }
        );
        assert!(prepare(&approve_cmd(Some("Bad Name"), true)).is_err());
    }

    #[test]
    fn the_command_line_requires_exactly_one_comparison() {
        use clap::Parser as _;
        #[derive(Debug, clap::Parser)]
        struct T {
            #[command(subcommand)]
            c: MachinesCommands,
        }
        assert!(T::try_parse_from(["t", "approve", "WDJB-MJHT"]).is_err());
        assert!(T::try_parse_from([
            "t",
            "approve",
            "WDJB-MJHT",
            "--fingerprint",
            "SHA256:a",
            "--confirmation-code",
            "X"
        ])
        .is_err());
        let t = T::try_parse_from([
            "t",
            "approve",
            "WDJB-MJHT",
            "--fingerprint",
            "SHA256:a",
            "--link-home",
        ])
        .unwrap();
        match t.c {
            MachinesCommands::Approve { link_home, .. } => {
                assert_eq!(link_home.as_deref(), Some(DEFAULT_HOME_NAME));
            }
            _ => panic!(),
        }
        let t = T::try_parse_from([
            "t",
            "approve",
            "WDJB-MJHT",
            "--confirmation-code",
            "X",
            "--link-home",
            "cabin",
        ])
        .unwrap();
        match t.c {
            MachinesCommands::Approve { link_home, .. } => {
                assert_eq!(link_home.as_deref(), Some("cabin"));
            }
            _ => panic!(),
        }
        assert!(T::try_parse_from(["t", "revoke", "not-a-uuid", "--reason", "x"]).is_err());
        assert!(T::try_parse_from([
            "t",
            "revoke",
            "6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11",
            "--reason",
            "x",
            "--source-signing",
            "maybe"
        ])
        .is_err());
    }

    fn pending_body(links: Option<&str>) -> String {
        let links = links.map_or(String::new(), |l| format!(r#","links":{l}"#));
        format!(
            r#"{{"enrollments":[{{"user_code":"WDJB-MJHT","name":"ha-kitchen","fingerprint":"SHA256:abc","kind":"new","machine_id":null,"preauth_key_id":null,"purpose":"home-assistant","confirmation_code":"KXQZ-7F2M","created_at":"2026-09-27T10:00:00Z","expires_at":"2026-09-27T10:10:00Z"{links}}}]}}"#
        )
    }

    const APPROVED: &str = r#"{"machine_id":"6f1c2a8e-0d4b-4c43-9a51-2f7d8e9b0c11","name":"ha-kitchen","kid":"k-1","fingerprint":"SHA256:abc","kind":"new","authorization":{"expires_at":null,"expiry":"disabled"},"grants":[]}"#;

    fn body_of(request: &str) -> serde_json::Value {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap()
    }

    #[tokio::test]
    async fn approve_without_a_link_sends_only_the_comparison() {
        let (base, seen) = canned_operator(vec![
            response("200 OK", &pending_body(None)),
            response("200 OK", APPROVED),
        ])
        .await;
        let op = MachineAdminClient::with_base_url(base, "tok").unwrap();
        let fp = Comparison::Fingerprint("SHA256:abc".into());
        let a = approve(&op, "WDJB-MJHT", &fp, None).await.unwrap();
        assert!(a.link.is_none());
        let seen = seen.await.unwrap();
        assert!(seen[1].starts_with("POST /v1/admin/machines/enrollments/WDJB-MJHT/approve "));
        assert!(seen[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer tok"));
        assert_eq!(
            body_of(&seen[1]),
            serde_json::json!({ "fingerprint": "SHA256:abc" })
        );
    }

    #[tokio::test]
    async fn approve_with_a_link_sends_it_when_the_listing_offers_home() {
        let approved = APPROVED.replace(
            r#""grants":[]"#,
            r#""grants":[],"link":{"kind":"Home","name":"cabin"}"#,
        );
        let (base, seen) = canned_operator(vec![
            response("200 OK", &pending_body(Some(r#"["Home"]"#))),
            response("200 OK", &approved),
        ])
        .await;
        let op = MachineAdminClient::with_base_url(base, "tok").unwrap();
        let code = Comparison::ConfirmationCode("KXQZ-7F2M".into());
        let link = Link {
            kind: "Home".into(),
            name: "cabin".into(),
        };
        let a = approve(&op, "WDJB-MJHT", &code, Some(&link)).await.unwrap();
        assert_eq!(a.link, Some(link));
        assert!(render_approved(&a).contains("linked as Home `cabin`"));
        let seen = seen.await.unwrap();
        assert_eq!(
            body_of(&seen[1]),
            serde_json::json!({
                "confirmation_code": "KXQZ-7F2M",
                "link": { "kind": "Home", "name": "cabin" },
            })
        );
    }

    #[tokio::test]
    async fn a_link_not_offered_is_refused_before_anything_is_sent() {
        for links in [None, Some("[]")] {
            // One canned response: the listing. A second request would hang
            // the server's accept and never be recorded.
            let (base, seen) =
                canned_operator(vec![response("200 OK", &pending_body(links))]).await;
            let op = MachineAdminClient::with_base_url(base, "tok").unwrap();
            let fp = Comparison::Fingerprint("SHA256:abc".into());
            let link = Link {
                kind: "Home".into(),
                name: "home".into(),
            };
            let err = approve(&op, "WDJB-MJHT", &fp, Some(&link))
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("cannot be linked as a Home"), "{err}");
            assert!(err.contains("Nothing was sent"), "{err}");
            let seen = seen.await.unwrap();
            assert_eq!(seen.len(), 1);
            assert!(seen[0].starts_with("GET /v1/admin/machines/enrollments "));
        }
    }

    #[tokio::test]
    async fn an_operator_refusal_is_said_plainly() {
        let (base, _seen) = canned_operator(vec![
            response("200 OK", &pending_body(None)),
            response(
                "422 Unprocessable Entity",
                r#"{"error":{"code":"confirmation_mismatch","message":"the fingerprint does not match"}}"#,
            ),
        ])
        .await;
        let op = MachineAdminClient::with_base_url(base, "tok").unwrap();
        let fp = Comparison::Fingerprint("SHA256:wrong".into());
        let err = approve(&op, "WDJB-MJHT", &fp, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not match what this enrollment holds"),
            "{err}"
        );
        assert!(err.contains("Nothing was approved"), "{err}");
    }

    #[tokio::test]
    async fn an_unknown_user_code_is_not_sent_to_approve() {
        let (base, seen) = canned_operator(vec![response("200 OK", r#"{"enrollments":[]}"#)]).await;
        let op = MachineAdminClient::with_base_url(base, "tok").unwrap();
        let fp = Comparison::Fingerprint("SHA256:abc".into());
        let err = approve(&op, "WDJB-MJHT", &fp, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no pending enrollment has user code WDJB-MJHT"),
            "{err}"
        );
        assert_eq!(seen.await.unwrap().len(), 1);
    }

    #[test]
    fn pending_shows_purpose_code_expiry_and_links() {
        let rows: Vec<PendingEnrollment> = serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(&pending_body(Some(r#"["Home"]"#))).unwrap()
                ["enrollments"]
                .clone(),
        )
        .unwrap();
        let text = render_pending(&rows);
        for want in [
            "WDJB-MJHT",
            "ha-kitchen",
            "(home-assistant)",
            "SHA256:abc",
            "KXQZ-7F2M",
            "2026-09-27T10:10:00Z",
            "can link as:  Home",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
    }
}
