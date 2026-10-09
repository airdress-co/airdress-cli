//! A function's set of allowed signers, as the client reads and edits it
//! (SPEC-113 D-5, design §7).
//!
//! `spec.source.signers: [ { key: <64 hex> } | { machine: <id> } ]`. The
//! single forms (`signer: <hex>`, `signerRef: { machine }`) still validate
//! and each means a set of one; this client reads them that way and never
//! writes them (FR-63).
//!
//! The membership test here is the client's early answer (step 0 of the
//! deploy loop). The operator stays the authority: it applies the same
//! rules again at publish, promote and admission, and additionally checks
//! that a machine's key is one registered to it — which a client cannot see.

use anyhow::{bail, Result};
use serde_json::Value;

use crate::machine::fingerprint;

/// Most members a set may have (the operator's validation limit).
pub const MAX_MEMBERS: usize = 16;

/// One member of a signer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    /// An Ed25519 public key, 64 hex characters (kept lowercase).
    Key(String),
    /// An approved machine, by id (or name, which the operator resolves).
    Machine(String),
}

impl Member {
    /// `{ key: … }` or `{ machine: … }`.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Key(k) => serde_json::json!({ "key": k }),
            Self::Machine(m) => serde_json::json!({ "machine": m }),
        }
    }

    /// Case-folded equality: a key's hex and a machine uuid compare
    /// without regard to case, as the operator's duplicate check does.
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Key(a), Self::Key(b)) | (Self::Machine(a), Self::Machine(b)) => {
                a.eq_ignore_ascii_case(b)
            }
            _ => false,
        }
    }

    /// What a person reads: a key's short hex and its fingerprint, or the
    /// machine.
    pub fn describe(&self) -> String {
        match self {
            Self::Key(k) => match parse_key_hex(k) {
                Some(bytes) => format!("key {} ({})", short_hex(k), fingerprint(&bytes)),
                None => format!("key {k}"),
            },
            Self::Machine(m) => format!("machine {m}"),
        }
    }
}

/// `5c1e…a07b`.
pub fn short_hex(hex: &str) -> String {
    if hex.len() <= 8 {
        return hex.to_owned();
    }
    format!("{}…{}", &hex[..4], &hex[hex.len() - 4..])
}

/// 64 hex characters → 32 bytes.
pub fn parse_key_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// A key member from user input: 64 hex, lowercased.
pub fn key_member(hex: &str) -> Result<Member> {
    let hex = hex.trim();
    if parse_key_hex(hex).is_none() {
        bail!("a key is an Ed25519 public key, 64 hex characters");
    }
    Ok(Member::Key(hex.to_ascii_lowercase()))
}

/// A machine member from user input: a machine id (uuid).
pub fn machine_member(id: &str) -> Result<Member> {
    let id = id.trim();
    let uuid: uuid::Uuid = id
        .parse()
        .map_err(|_| anyhow::anyhow!("`{id}` is not a machine id (a uuid)"))?;
    Ok(Member::Machine(uuid.to_string()))
}

/// The set a `spec.source` names, normalized: `signers` as written, a
/// single `signer` or `signerRef` as a set of one, and none of these as the
/// empty set (unsigned — admissible only where the operator allows it).
pub fn allowed(source: &Value) -> Result<Vec<Member>> {
    let signers = source.get("signers").filter(|v| !v.is_null());
    let signer = source.get("signer").and_then(Value::as_str);
    let signer_ref = source
        .get("signerRef")
        .and_then(|r| r.get("machine"))
        .and_then(Value::as_str);
    if let Some(list) = signers {
        if signer.is_some() || signer_ref.is_some() {
            bail!("spec.source names signers together with signer or signerRef");
        }
        let items = list
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("spec.source.signers is not a list"))?;
        return items
            .iter()
            .enumerate()
            .map(|(i, m)| {
                match (
                    m.get("key").and_then(Value::as_str),
                    m.get("machine").and_then(Value::as_str),
                ) {
                    (Some(k), None) => Ok(Member::Key(k.to_ascii_lowercase())),
                    (None, Some(id)) => Ok(Member::Machine(id.to_owned())),
                    _ => bail!("spec.source.signers[{i}] names neither or both of key and machine"),
                }
            })
            .collect();
    }
    Ok(match (signer, signer_ref) {
        (Some(k), _) => vec![Member::Key(k.to_ascii_lowercase())],
        (None, Some(m)) => vec![Member::Machine(m.to_owned())],
        (None, None) => Vec::new(),
    })
}

/// Who this client signs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnSigner {
    /// No signing key here.
    Unsigned,
    /// A literal key (the workstation's seed).
    Key { public_hex: String },
    /// An approved machine, with the source-signing key registered to it.
    Machine { machine: String, public_hex: String },
}

impl OwnSigner {
    /// The member this client adds when it creates a function (FR-63).
    pub fn member(&self) -> Option<Member> {
        match self {
            Self::Unsigned => None,
            Self::Key { public_hex } => Some(Member::Key(public_hex.clone())),
            Self::Machine { machine, .. } => Some(Member::Machine(machine.clone())),
        }
    }

    /// For the confirmation: `key 5c1e…a07b (this workstation)`.
    pub fn describe(&self) -> String {
        match self {
            Self::Unsigned => "nobody (unsigned)".to_owned(),
            Self::Key { public_hex } => format!("key {} (this workstation)", short_hex(public_hex)),
            Self::Machine {
                machine,
                public_hex,
            } => format!(
                "machine {machine} (its source key {})",
                short_hex(public_hex)
            ),
        }
    }
}

/// Whether `own` may sign for a function whose set is `set` — design §3.6:
/// a key member matches the key; a machine member matches a client signing
/// as that machine (its key's registration is the operator's to check). A
/// machine's source key named literally matches as well, since the version
/// carries that key. The empty set admits only the unsigned.
pub fn is_member(set: &[Member], own: &OwnSigner) -> bool {
    match own {
        OwnSigner::Unsigned => set.is_empty(),
        OwnSigner::Key { public_hex } => {
            set.iter().any(|m| m.same(&Member::Key(public_hex.clone())))
        }
        OwnSigner::Machine {
            machine,
            public_hex,
        } => set.iter().any(|m| {
            m.same(&Member::Machine(machine.clone())) || m.same(&Member::Key(public_hex.clone()))
        }),
    }
}

/// The members, one per line, for a refusal or a confirmation.
pub fn describe_set(set: &[Member]) -> Vec<String> {
    if set.is_empty() {
        return vec!["(no signer: only unsigned source, where the operator allows it)".to_owned()];
    }
    set.iter().map(Member::describe).collect()
}

/// A change to a set: exactly one member added or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Add,
    Remove,
}

/// `spec.source` with `member` added or removed: the single forms are
/// converted to the set form, exactly one member changes, and nothing else
/// in `source` moves.
pub fn change(source: &Value, change: Change, member: &Member) -> Result<(Value, Vec<Member>)> {
    let mut set = allowed(source)?;
    match change {
        Change::Add => {
            if set.iter().any(|m| m.same(member)) {
                bail!(
                    "{} is already a member of this function's signers",
                    member.describe()
                );
            }
            if set.len() >= MAX_MEMBERS {
                bail!(
                    "a function has at most {MAX_MEMBERS} signers; this one has {}",
                    set.len()
                );
            }
            set.push(member.clone());
        }
        Change::Remove => {
            let before = set.len();
            set.retain(|m| !m.same(member));
            if set.len() == before {
                bail!(
                    "{} is not a member of this function's signers",
                    member.describe()
                );
            }
            if set.is_empty() {
                bail!(
                    "{} is the only signer; a function's set cannot be empty (add the \
                     replacement first)",
                    member.describe()
                );
            }
        }
    }
    let mut out = source.clone();
    let obj = out
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("spec.source is not an object"))?;
    obj.remove("signer");
    obj.remove("signerRef");
    obj.insert(
        "signers".into(),
        Value::Array(set.iter().map(Member::to_json).collect()),
    );
    Ok((out, set))
}

/// Whether `member` signed the version described by `version_info` (the
/// `GET /v1/functions/sources/{version}` answer: `signer`, `signerRef`).
pub fn signed(member: &Member, version_info: &Value) -> bool {
    match member {
        Member::Key(k) => version_info["signer"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(k)),
        Member::Machine(m) => version_info["signerRef"]
            .as_str()
            .or_else(|| version_info["signerRef"]["machine"].as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case(m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "5c1e00000000000000000000000000000000000000000000000000000000a07b";
    const K2: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const M: &str = "0b7e3c1a-0000-4000-8000-000000009d2f";

    #[test]
    fn single_forms_are_sets_of_one() {
        let k = serde_json::json!({ "version": "sha256:a", "signer": K1.to_uppercase() });
        assert_eq!(allowed(&k).unwrap(), [Member::Key(K1.into())]);
        let m = serde_json::json!({ "version": "sha256:a", "signerRef": { "machine": M } });
        assert_eq!(allowed(&m).unwrap(), [Member::Machine(M.into())]);
        let none = serde_json::json!({ "version": "sha256:a" });
        assert!(allowed(&none).unwrap().is_empty());
        let set = serde_json::json!({ "signers": [{ "key": K1 }, { "machine": M }] });
        assert_eq!(
            allowed(&set).unwrap(),
            [Member::Key(K1.into()), Member::Machine(M.into())]
        );
        let both = serde_json::json!({ "signers": [{ "key": K1 }], "signer": K1 });
        assert!(allowed(&both).is_err());
    }

    #[test]
    fn membership_follows_the_operators_rules() {
        let set = vec![Member::Key(K1.into()), Member::Machine(M.into())];
        let key = |h: &str| OwnSigner::Key {
            public_hex: h.into(),
        };
        assert!(is_member(&set, &key(K1)));
        assert!(!is_member(&set, &key(K2)));
        let machine = OwnSigner::Machine {
            machine: M.to_uppercase(),
            public_hex: K2.into(),
        };
        assert!(is_member(&set, &machine));
        // A machine named nowhere, whose key is named literally, matches.
        let other = OwnSigner::Machine {
            machine: "ffffffff-0000-4000-8000-000000000000".into(),
            public_hex: K1.into(),
        };
        assert!(is_member(&set, &other));
        assert!(!is_member(&set, &OwnSigner::Unsigned));
        assert!(is_member(&[], &OwnSigner::Unsigned));
        assert!(!is_member(&[], &key(K1)));
    }

    #[test]
    fn a_change_converts_a_single_form_and_moves_exactly_one_member() {
        let single = serde_json::json!({ "version": "sha256:a", "signer": K1 });
        let (out, set) = change(&single, Change::Add, &Member::Machine(M.into())).unwrap();
        assert_eq!(
            out,
            serde_json::json!({
                "version": "sha256:a",
                "signers": [{ "key": K1 }, { "machine": M }]
            })
        );
        assert_eq!(set.len(), 2);

        let (back, set) = change(&out, Change::Remove, &Member::Key(K1.into())).unwrap();
        assert_eq!(
            back,
            serde_json::json!({ "version": "sha256:a", "signers": [{ "machine": M }] })
        );
        assert_eq!(set, [Member::Machine(M.into())]);

        // The last member cannot go, a duplicate cannot come, and an
        // absent one cannot be removed.
        assert!(change(&back, Change::Remove, &Member::Machine(M.into())).is_err());
        assert!(change(&back, Change::Add, &Member::Machine(M.to_uppercase())).is_err());
        assert!(change(&back, Change::Remove, &Member::Key(K2.into())).is_err());
    }

    #[test]
    fn the_limit_is_the_operators() {
        let set: Vec<Value> = (0..MAX_MEMBERS)
            .map(|i| serde_json::json!({ "key": format!("{i:064x}") }))
            .collect();
        let source = serde_json::json!({ "signers": set });
        let err = change(&source, Change::Add, &Member::Key(K2.into()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("at most 16"), "{err}");
    }

    #[test]
    fn who_signed_a_version_is_read_from_its_answer() {
        let info = serde_json::json!({ "signer": K1, "signerRef": M });
        assert!(signed(&Member::Key(K1.into()), &info));
        assert!(signed(&Member::Machine(M.into()), &info));
        assert!(!signed(&Member::Key(K2.into()), &info));
    }

    #[test]
    fn input_is_checked_and_normalized() {
        assert_eq!(
            key_member(&K1.to_uppercase()).unwrap(),
            Member::Key(K1.into())
        );
        assert!(key_member("abc").is_err());
        assert!(machine_member("ci-functions").is_err());
        assert_eq!(
            machine_member(&M.to_uppercase()).unwrap(),
            Member::Machine(M.into())
        );
        assert!(Member::Key(K2.into())
            .describe()
            .starts_with("key 8a88…6f5c (SHA256:"));
    }
}
