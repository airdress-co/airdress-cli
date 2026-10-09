//! `Redacted<T>` — one wrapper for every secret this crate holds.
//!
//! The rule it exists to keep (SPEC-133 FR-10): no tool result, no
//! notification, no error and no log line carries an account token, a
//! refresh token, a device code, a device or MLS private key, or a
//! function signing key.
//!
//! A secret kept in a `Redacted<T>` cannot be printed by accident:
//! `Debug` and `Serialize` render the placeholder, there is no `Display`
//! at all, and the value itself only comes out of [`Redacted::expose`],
//! which is grep-able.
//!
//! The name of the call site is the audit trail. If you find yourself
//! writing `.expose()` into a format string, that is the bug.
//!
//! The value is zeroized when the wrapper is dropped, so a secret does
//! not outlive its last holder in freed memory.
//!
//! **Persisting one.** `Redacted` deliberately has no `Deserialize`, and
//! its `Serialize` writes the placeholder: a struct that is written to
//! disk and read back cannot hold one by accident and silently replace a
//! token with `[redacted]`. A field that genuinely belongs in a file
//! says so with `#[serde(with = "crate::redact::persist")]` (or
//! [`persist_opt`] for an `Option`), which is grep-able in the same way
//! `.expose()` is. A field read off the wire and never written uses
//! `deserialize_with` from the same module.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// What every rendering of a secret looks like.
pub const PLACEHOLDER: &str = "[redacted]";

/// A value that must never reach a log, an error or a tool result.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T: Zeroize>(T);

impl<T: Zeroize> Redacted<T> {
    /// Wrap a secret.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Hand the secret to code that genuinely needs it — an
    /// `Authorization` header, a signature, a keychain write.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper. Same contract as [`Self::expose`].
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        std::mem::take(&mut self.0)
    }
}

impl<T: Zeroize + Default> Default for Redacted<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Zeroize> Drop for Redacted<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

// No `Display`, deliberately. `reqwest::RequestBuilder::bearer_auth` (and
// anything else generic over `Display`) would otherwise take a `Redacted`
// and send `Bearer [redacted]` with no compile error. Without it, a
// `Redacted` handed to such an API, or to `format!("{}")`, does not compile.

impl<T: Zeroize> Serialize for Redacted<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(PLACEHOLDER)
    }
}

impl<T: Zeroize> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Redacted<String> {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

/// `#[serde(with = "crate::redact::persist")]` — the secret itself, for
/// the one file it lives in (a profile, a credential store). The on-disk
/// form is exactly the bare value, so a file written before the field
/// was wrapped reads back unchanged.
pub mod persist {
    use super::*;

    pub fn serialize<T, S>(value: &Redacted<T>, s: S) -> Result<S::Ok, S::Error>
    where
        T: Zeroize + Serialize,
        S: Serializer,
    {
        value.expose().serialize(s)
    }

    pub fn deserialize<'de, T, D>(d: D) -> Result<Redacted<T>, D::Error>
    where
        T: Zeroize + Deserialize<'de>,
        D: Deserializer<'de>,
    {
        T::deserialize(d).map(Redacted::new)
    }
}

/// [`persist`] for an `Option<Redacted<T>>`.
pub mod persist_opt {
    use super::*;

    pub fn serialize<T, S>(value: &Option<Redacted<T>>, s: S) -> Result<S::Ok, S::Error>
    where
        T: Zeroize + Serialize,
        S: Serializer,
    {
        value.as_ref().map(Redacted::expose).serialize(s)
    }

    pub fn deserialize<'de, T, D>(d: D) -> Result<Option<Redacted<T>>, D::Error>
    where
        T: Zeroize + Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(d).map(|v| v.map(Redacted::new))
    }
}

/// How much of a secret a *deliberate* hint may show: nothing.
///
/// Some surfaces want to say "there is a token and it ends in …" to
/// help somebody tell two profiles apart. They may not: a suffix is
/// still key material. This returns the shape instead — the kind of
/// thing it is and how long it is — which distinguishes a profile
/// without leaking a byte of it.
pub fn shape(secret: &str) -> String {
    format!("{} characters", secret.chars().count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rendering_is_the_placeholder() {
        let r = Redacted::new("ya29.a-very-real-looking-access-token".to_string());
        assert_eq!(format!("{r:?}"), PLACEHOLDER);
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"[redacted]\"");
        // Inside a struct, too — the derive uses our Debug.
        #[derive(Debug, Serialize)]
        struct Profile {
            name: String,
            token: Redacted<String>,
        }
        let p = Profile {
            name: "default".into(),
            token: Redacted::new("secret".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("[redacted]"), "{json}");
        assert!(!json.contains("secret"), "{json}");
        assert!(!format!("{p:?}").contains("secret"));
    }

    #[test]
    fn expose_is_the_only_way_out() {
        let r = Redacted::new(42u8);
        assert_eq!(*r.expose(), 42);
        assert_eq!(r.into_inner(), 42);
    }

    #[test]
    fn persist_writes_the_value_and_reads_it_back() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Stored {
            #[serde(with = "persist")]
            token: Redacted<String>,
            #[serde(default, with = "persist_opt", skip_serializing_if = "Option::is_none")]
            id: Option<Redacted<String>>,
        }
        let raw = r#"{"token":"tok-123","id":"idt-456"}"#;
        let s: Stored = serde_json::from_str(raw).unwrap();
        assert_eq!(s.token.expose(), "tok-123");
        assert!(!format!("{s:?}").contains("tok-123"));
        assert_eq!(serde_json::to_string(&s).unwrap(), raw);
        let s: Stored = serde_json::from_str(r#"{"token":"t"}"#).unwrap();
        assert!(s.id.is_none());
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"token":"t"}"#);
    }

    #[test]
    fn shape_shows_no_bytes() {
        let s = shape("abcdef");
        assert_eq!(s, "6 characters");
        assert!(!s.contains("abc"));
    }
}
