//! The exit-code contract, and the one failure shape the binary reports.
//!
//! Scripts, CI (`deploy-functions`), the editor extension and the MCP client
//! read `airdress`'s exit status, so the codes are an API. They are listed
//! in `docs/exit-codes.md` and never renumbered:
//!
//! | Code | [`Exit`] | Meaning |
//! |------|----------|---------|
//! | 0 | — | success |
//! | 1 | [`Exit::Internal`] | internal or unexpected failure |
//! | 2 | [`Exit::Usage`] | usage: the command line is wrong (clap's own) |
//! | 3 | [`Exit::Refused`] | refused or forbidden |
//! | 4 | [`Exit::Auth`] | authentication needed, or expired |
//! | 5 | [`Exit::Network`] | network: unreachable, or timed out |
//! | 6 | [`Exit::Conflict`] | conflict, or a stale base |
//! | 7 | [`Exit::ConfirmationRequired`] | a confirmation was needed and could not be asked |
//!
//! Inside a command, errors stay `anyhow`. A site that knows what kind of
//! failure it has raises a [`Failure`] (which is an `Error`, so it travels
//! inside `anyhow` with any context added on top); everything else is
//! classified at the boundary by [`classify`], which reads the typed causes
//! it knows: [`Failure`], `reqwest::Error`, the operator refusals of the
//! shell and agent-bus clients, and I/O errors of a socket.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// What kind of failure ended the process. The discriminant is the exit
/// status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Exit {
    /// Something this CLI did not expect: a bug, a malformed answer, a file
    /// that could not be written.
    Internal = 1,
    /// The command line is wrong. clap exits with this too.
    Usage = 2,
    /// The operator or hub refused the request (403, 404, 422, …), or a
    /// person declined at a prompt.
    Refused = 3,
    /// Sign-in needed, or expired: run `airdress auth login`.
    Auth = 4,
    /// The other end could not be reached, or did not answer in time
    /// (including a 502, 503 or 504 from a proxy in front of it).
    Network = 5,
    /// The request lost a race: a stale base, an epoch conflict, a 409.
    Conflict = 6,
    /// A confirmation was needed and could not be asked (no terminal, or
    /// `--output json`); pass `--yes` to give it.
    ConfirmationRequired = 7,
}

impl Exit {
    /// The process exit status.
    pub const fn status(self) -> u8 {
        self as u8
    }

    /// The code a failure of this kind reports when nothing more specific
    /// is known.
    pub const fn default_code(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Usage => "usage",
            Self::Refused => "refused",
            Self::Auth => "auth_required",
            Self::Network => "unreachable",
            Self::Conflict => "conflict",
            Self::ConfirmationRequired => "confirmation_required",
        }
    }

    /// The kind of failure an HTTP status means, from this CLI's side.
    pub const fn for_status(status: u16) -> Self {
        match status {
            401 => Self::Auth,
            409 | 412 => Self::Conflict,
            408 | 502..=504 => Self::Network,
            400..=499 => Self::Refused,
            _ => Self::Internal,
        }
    }

    /// The kind of failure an operator or client code means, when the code
    /// alone decides it (a stale base is a conflict whatever the status).
    pub fn for_code(code: &str) -> Option<Self> {
        Some(match code {
            "source_base_stale" | "epoch_conflict" | "conflict" => Self::Conflict,
            "machine_authorization_expired"
            | "auth_required"
            | "sign_in_expired"
            | "not_signed_in"
            | "profile_not_found"
            | "unauthenticated" => Self::Auth,
            "confirmation_required" => Self::ConfirmationRequired,
            "timeout" | "unreachable" => Self::Network,
            "usage" => Self::Usage,
            c if c.ends_with("_conflict") || c.ends_with("_stale") => Self::Conflict,
            _ => return None,
        })
    }
}

/// A failure, as it leaves the process: an exit kind, a stable snake-case
/// `code`, a `message` for a person, what to do about it (`hint`), and the
/// HTTP `status` when an operator or hub answered one.
///
/// Under `--output json` this is the one object written to stderr, the same
/// shape the CLI's refusal readers use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// The exit status this failure ends the process with.
    #[serde(skip)]
    pub exit: Exit,
    /// A stable identifier: an operator's own code verbatim, or this CLI's.
    pub code: String,
    /// For a person.
    pub message: String,
    /// The one useful next step, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// The HTTP status the operator or hub answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Everything else the operator answered (`reason`, `locations`,
    /// `denials`, `basedOn`, `current` …), carried through unchanged.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Failure {
    /// A failure of kind `exit` with its code and message.
    pub fn new(exit: Exit, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exit,
            code: code.into(),
            message: message.into(),
            hint: None,
            status: None,
            extra: BTreeMap::new(),
        }
    }

    /// Authentication needed or expired, with the usual next step.
    pub fn auth(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Exit::Auth, code, message).with_hint("run `airdress auth login`")
    }

    /// The command line is wrong.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Exit::Usage, Exit::Usage.default_code(), message)
    }

    /// An operator's or hub's refusal: classified by its code first, then
    /// its status.
    pub fn http(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let exit = Exit::for_code(&code).unwrap_or_else(|| Exit::for_status(status));
        let mut f = Self::new(exit, code, message);
        f.status = Some(status);
        if exit == Exit::Auth {
            f.hint = Some("run `airdress auth login`".to_owned());
        }
        f
    }

    /// The next step.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Carry the fields of an operator's answer, other than its code and
    /// message (and the members this shape already has), through unchanged.
    #[must_use]
    pub fn with_answer(mut self, answer: &Value) -> Self {
        let mut carry = |o: &serde_json::Map<String, Value>| {
            for (k, v) in o {
                if !matches!(k.as_str(), "error" | "code" | "message" | "hint" | "status")
                    && !v.is_null()
                    && !v.as_array().is_some_and(Vec::is_empty)
                {
                    self.extra.insert(k.clone(), v.clone());
                }
            }
        };
        if let Some(o) = answer.as_object() {
            carry(o);
            if let Some(nested) = o.get("error").and_then(Value::as_object) {
                carry(nested);
            }
        }
        self
    }

    /// The exit status.
    pub const fn exit_status(&self) -> u8 {
        self.exit.status()
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// The code in an operator's or hub's refusal body, in either of its two
/// shapes: flat `{"error": "<code>"}` or nested `{"error": {"code"}}`.
pub fn body_code(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    match &v["error"] {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o
            .get("code")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

/// Classify a command's error at the boundary. The message is the whole
/// chain (`context: cause`), so nothing a command added is lost.
pub fn classify(err: &anyhow::Error) -> Failure {
    let message = format!("{err:#}");
    let mut found = None;
    for cause in err.chain() {
        if let Some(f) = classify_one(cause) {
            found = Some(f);
            break;
        }
    }
    let mut f = found.unwrap_or_else(|| {
        Failure::new(Exit::Internal, Exit::Internal.default_code(), String::new())
    });
    f.message = message;
    f
}

fn classify_one(cause: &(dyn std::error::Error + 'static)) -> Option<Failure> {
    if let Some(f) = cause.downcast_ref::<Failure>() {
        return Some(f.clone());
    }
    if let Some(r) = cause.downcast_ref::<crate::shell_client::api::Refusal>() {
        return Some(Failure::http(r.status, r.code.clone(), r.message.clone()));
    }
    if let Some(r) = cause.downcast_ref::<crate::agent_bus::client::Refusal>() {
        return Some(Failure::http(r.status, r.code.clone(), r.message.clone()));
    }
    if cause
        .downcast_ref::<crate::functions::client::MachineAuthorizationExpired>()
        .is_some()
    {
        return Some(
            Failure::new(
                Exit::Auth,
                "machine_authorization_expired",
                "the machine's approval lapsed",
            )
            .with_hint("run `airdress-operator machine reauth`, then the owner approves it"),
        );
    }
    if let Some(e) = cause.downcast_ref::<reqwest::Error>() {
        if e.is_timeout() {
            return Some(Failure::new(Exit::Network, "timeout", String::new()));
        }
        if e.is_connect() || e.is_request() {
            return Some(Failure::new(Exit::Network, "unreachable", String::new()));
        }
        if let Some(s) = e.status() {
            return Some(Failure::http(
                s.as_u16(),
                format!("http_{}", s.as_u16()),
                "",
            ));
        }
        return None;
    }
    if cause
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        return Some(Failure::new(Exit::Network, "timeout", String::new()));
    }
    if let Some(e) = cause.downcast_ref::<std::io::Error>() {
        use std::io::ErrorKind as K;
        return match e.kind() {
            K::TimedOut => Some(Failure::new(Exit::Network, "timeout", String::new())),
            K::ConnectionRefused
            | K::ConnectionReset
            | K::ConnectionAborted
            | K::NotConnected
            | K::HostUnreachable
            | K::NetworkUnreachable => {
                Some(Failure::new(Exit::Network, "unreachable", String::new()))
            }
            _ => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;

    /// `docs/exit-codes.md` is the published contract; its table and the
    /// enum say the same thing.
    #[test]
    fn the_documented_table_is_the_enum() {
        let doc = include_str!("../docs/exit-codes.md");
        let rows: Vec<(u8, String)> = doc
            .lines()
            .filter_map(|l| {
                let mut cells = l.split('|').map(str::trim).skip(1);
                let code = cells.next()?.trim_matches('`').parse::<u8>().ok()?;
                Some((code, cells.next()?.to_owned()))
            })
            .collect();
        let expected = [
            (0, "ok"),
            (Exit::Internal.status(), "internal"),
            (Exit::Usage.status(), "usage"),
            (Exit::Refused.status(), "refused"),
            (Exit::Auth.status(), "auth"),
            (Exit::Network.status(), "network"),
            (Exit::Conflict.status(), "conflict"),
            (Exit::ConfirmationRequired.status(), "confirmation required"),
        ];
        let expected: Vec<(u8, String)> = expected
            .iter()
            .map(|(c, n)| (*c, (*n).to_owned()))
            .collect();
        assert_eq!(rows, expected);
    }

    #[test]
    fn an_answer_is_carried_through() {
        let f = Failure::http(409, "source_base_stale", "moved").with_answer(&serde_json::json!({
            "error": "source_base_stale", "message": "moved",
            "basedOn": "sha256:a", "current": "sha256:b", "reason": null
        }));
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({"code":"source_base_stale","message":"moved","status":409,
                               "basedOn":"sha256:a","current":"sha256:b"})
        );
    }

    #[test]
    fn statuses_classify() {
        assert_eq!(Exit::for_status(401), Exit::Auth);
        assert_eq!(Exit::for_status(403), Exit::Refused);
        assert_eq!(Exit::for_status(404), Exit::Refused);
        assert_eq!(Exit::for_status(409), Exit::Conflict);
        assert_eq!(Exit::for_status(503), Exit::Network);
        assert_eq!(Exit::for_status(500), Exit::Internal);
    }

    #[test]
    fn the_code_beats_the_status() {
        assert_eq!(
            Failure::http(400, "source_base_stale", "m").exit,
            Exit::Conflict
        );
        assert_eq!(
            Failure::http(422, "epoch_conflict", "m").exit,
            Exit::Conflict
        );
        assert_eq!(Failure::http(403, "nope", "m").exit, Exit::Refused);
        assert_eq!(
            Failure::http(401, "x", "m").hint.as_deref(),
            Some("run `airdress auth login`")
        );
    }

    #[test]
    fn a_failure_survives_context_and_keeps_the_chain() {
        let e = Err::<(), _>(Failure::http(409, "epoch_conflict", "lost the race"))
            .context("send message")
            .unwrap_err();
        let f = classify(&e);
        assert_eq!(f.exit, Exit::Conflict);
        assert_eq!(f.code, "epoch_conflict");
        assert_eq!(f.message, "send message: lost the race");
        assert_eq!(f.status, Some(409));
    }

    #[test]
    fn anything_else_is_internal() {
        let f = classify(&anyhow::anyhow!("boom"));
        assert_eq!((f.exit, f.code.as_str()), (Exit::Internal, "internal"));
    }

    #[test]
    fn a_socket_error_is_network() {
        let e = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(classify(&e).exit, Exit::Network);
        let e = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(classify(&e).exit, Exit::Internal);
    }

    #[test]
    fn the_json_shape_is_the_refusal_shape() {
        let f = Failure::http(403, "forbidden", "no").with_hint("ask the owner");
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({"code":"forbidden","message":"no","hint":"ask the owner","status":403})
        );
        let f = Failure::new(Exit::Internal, "internal", "x");
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({"code":"internal","message":"x"})
        );
    }
}
