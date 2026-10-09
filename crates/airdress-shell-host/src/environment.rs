//! A session's process environment (FR-P7, design §7.5).
//!
//! Built from nothing, never inherited:
//!
//! 1. a fixed base: `TERM`, `HOME`, `USER`, `SHELL`, the locale (`LANG`
//!    and the `LC_*` categories, inherited from the host process, with
//!    `LANG=C.UTF-8` when the host sets none — a terminal without a UTF-8
//!    locale shows every non-ASCII character as `?`, found live on a phone),
//!    and `PATH` only if the profile allows it;
//! 2. the profile's `env_allow` names, copied from the host's own
//!    environment;
//! 3. the profile's `env_set`;
//! 4. the session's own variables: `AIRDRESS_SHELL_SESSION`, `COLORTERM`,
//!    and for an `opencode-server` profile a fresh `OPENCODE_SERVER_PASSWORD`
//!    (the third-party program's own variable, which protects its loopback
//!    server from other local users; it lives in memory and in the child's
//!    environment only).
//!
//! Nothing else: no credential of the host, no `SSH_AUTH_SOCK`, no
//! `DBUS_SESSION_BUS_ADDRESS`, unless the person named it in `env_allow`.

use std::collections::BTreeMap;
use std::ffi::OsString;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::profiles::Profile;

/// The terminal type every session gets.
pub const TERM: &str = "xterm-256color";

/// The locale variables a session inherits from the host process. A
/// locale names a language and an encoding, never a credential, so it is
/// part of the base rather than something each profile has to allow.
pub const LOCALE_VARS: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_ADDRESS",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_NAME",
    "LC_PAPER",
    "LC_TELEPHONE",
];

/// The locale a session gets when the host process names none: one whose
/// character encoding is UTF-8, present on every system the host ships for.
#[cfg(target_os = "macos")]
pub const FALLBACK_LANG: &str = "en_US.UTF-8";
/// The locale a session gets when the host process names none: one whose
/// character encoding is UTF-8, present on every system the host ships for.
#[cfg(not(target_os = "macos"))]
pub const FALLBACK_LANG: &str = "C.UTF-8";

/// The variable naming the session (design §7.5).
pub const SESSION_VAR: &str = "AIRDRESS_SHELL_SESSION";

/// A built environment. The password, when there is one, is zeroed on drop.
#[derive(Default)]
pub struct SessionEnv {
    pub vars: BTreeMap<OsString, OsString>,
    secret: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for SessionEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEnv")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SessionEnv {
    /// Whether a per-session server password was set.
    /// The per-session loopback password, for the session's adapter only.
    pub fn server_password(&self) -> Option<Zeroizing<String>> {
        self.secret.clone()
    }

    pub fn has_secret(&self) -> bool {
        self.secret.is_some()
    }
}

/// Build the environment for `profile`'s session `session`, reading the
/// host's own variables through `host_env`.
pub fn build(
    profile: &Profile,
    session: Uuid,
    host_env: &dyn Fn(&str) -> Option<OsString>,
) -> SessionEnv {
    let mut env = SessionEnv::default();
    let Some(spec) = profile.process() else {
        return env;
    };
    let allowed = |n: &str| spec.env_allow.iter().any(|a| a == n);
    let mut put = |k: &str, v: OsString| {
        env.vars.insert(OsString::from(k), v);
    };
    put("TERM", OsString::from(TERM));
    for name in ["HOME", "USER", "SHELL"] {
        if let Some(v) = host_env(name) {
            put(name, v);
        }
    }
    let mut has_ctype = false;
    for name in LOCALE_VARS {
        if let Some(v) = host_env(name).filter(|v| !v.is_empty()) {
            // `LANGUAGE` orders message translations; it decides no encoding.
            has_ctype |= matches!(*name, "LANG" | "LC_ALL" | "LC_CTYPE");
            put(name, v);
        }
    }
    if !has_ctype {
        put("LANG", OsString::from(FALLBACK_LANG));
    }
    if allowed("PATH") {
        if let Some(v) = host_env("PATH") {
            put("PATH", v);
        }
    }
    for name in &spec.env_allow {
        if let Some(v) = host_env(name) {
            put(name, v);
        }
    }
    for (k, v) in &spec.env_set {
        put(k, OsString::from(v));
    }
    put(SESSION_VAR, OsString::from(session.to_string()));
    put("COLORTERM", OsString::from("truecolor"));
    put("TERM", OsString::from(TERM));
    if profile.structured.as_deref() == Some("opencode-server") {
        let mut raw = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let pw = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw));
        env.vars.insert(
            OsString::from("OPENCODE_SERVER_PASSWORD"),
            OsString::from(pw.as_str()),
        );
        env.secret = Some(pw);
    }
    env
}

/// The real environment of this process.
pub fn host_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use crate::profiles::parse_str;

    fn fake(name: &str) -> Option<OsString> {
        match name {
            "HOME" => Some("/home/a".into()),
            "USER" => Some("a".into()),
            "SHELL" => Some("/bin/bash".into()),
            "PATH" => Some("/usr/bin".into()),
            "LANG" => Some("C.UTF-8".into()),
            "EDITOR" => Some("vi".into()),
            "SSH_AUTH_SOCK" => Some("/run/agent".into()),
            "AWS_SECRET_ACCESS_KEY" => Some("leak".into()),
            _ => None,
        }
    }

    fn profile(extra: &str) -> Profile {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        std::fs::create_dir_all(&p.home).unwrap();
        let text = format!("[[profile]]\nid = \"p\"\nprogram = \"/bin/sh\"\n{extra}");
        parse_str(&text, &p).unwrap().profiles.remove(0)
    }

    #[test]
    fn nothing_but_the_base_and_what_the_profile_names() {
        let env = build(&profile(""), Uuid::nil(), &fake);
        let names: Vec<_> = env
            .vars
            .keys()
            .map(|k| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "AIRDRESS_SHELL_SESSION",
                "COLORTERM",
                "HOME",
                "LANG",
                "SHELL",
                "TERM",
                "USER"
            ]
        );
        let env = build(
            &profile("env_allow = [\"PATH\", \"EDITOR\"]\nenv_set = { FOO = \"bar\" }\n"),
            Uuid::nil(),
            &fake,
        );
        assert_eq!(env.vars[&OsString::from("PATH")], "/usr/bin");
        assert_eq!(env.vars[&OsString::from("EDITOR")], "vi");
        assert_eq!(env.vars[&OsString::from("FOO")], "bar");
        assert_eq!(env.vars[&OsString::from("LANG")], "C.UTF-8");
        assert!(!env.vars.contains_key(&OsString::from("SSH_AUTH_SOCK")));
        assert!(!env
            .vars
            .contains_key(&OsString::from("AWS_SECRET_ACCESS_KEY")));
    }

    #[test]
    fn the_locale_is_inherited_without_being_allowed() {
        let host = |name: &str| match name {
            "LANG" => Some("de_DE.UTF-8".into()),
            "LC_TIME" => Some("en_GB.UTF-8".into()),
            "LC_PAPER" => Some(OsString::new()),
            other => fake(other),
        };
        let env = build(&profile(""), Uuid::nil(), &host);
        assert_eq!(env.vars[&OsString::from("LANG")], "de_DE.UTF-8");
        assert_eq!(env.vars[&OsString::from("LC_TIME")], "en_GB.UTF-8");
        assert!(
            !env.vars.contains_key(&OsString::from("LC_PAPER")),
            "an empty variable is not a locale"
        );
        // The allowlist still holds everything else back.
        assert!(!env.vars.contains_key(&OsString::from("PATH")));
        assert!(!env.vars.contains_key(&OsString::from("EDITOR")));
    }

    #[test]
    fn no_host_locale_means_a_utf8_one() {
        let bare = |name: &str| match name {
            "LANG" => None,
            other => fake(other),
        };
        let env = build(&profile(""), Uuid::nil(), &bare);
        assert_eq!(env.vars[&OsString::from("LANG")], FALLBACK_LANG);
        assert!(FALLBACK_LANG.ends_with(".UTF-8"));

        // LC_ALL decides the encoding on its own; no LANG is invented.
        let all = |name: &str| match name {
            "LANG" => None,
            "LC_ALL" => Some("sv_SE.UTF-8".into()),
            other => fake(other),
        };
        let env = build(&profile(""), Uuid::nil(), &all);
        assert_eq!(env.vars[&OsString::from("LC_ALL")], "sv_SE.UTF-8");
        assert!(!env.vars.contains_key(&OsString::from("LANG")));

        // A profile's own setting still wins.
        let env = build(
            &profile("env_set = { LANG = \"fr_FR.UTF-8\" }\n"),
            Uuid::nil(),
            &bare,
        );
        assert_eq!(env.vars[&OsString::from("LANG")], "fr_FR.UTF-8");
    }

    #[test]
    fn an_opencode_server_profile_gets_a_fresh_password_per_session() {
        let p = profile("kind = \"harness:opencode\"\nstructured = \"opencode-server\"\n");
        let a = build(&p, Uuid::nil(), &fake);
        let b = build(&p, Uuid::nil(), &fake);
        let k = OsString::from("OPENCODE_SERVER_PASSWORD");
        assert!(a.has_secret());
        assert_ne!(a.vars[&k], b.vars[&k]);
        assert!(!format!("{a:?}").contains(a.vars[&k].to_str().unwrap()));
    }
}
