//! `airdress peers …` — pair this airdress's operator with another one, so
//! their agent sessions can reach each other by `name@airdress`.
//!
//! Trust is one-way and needs a person on both sides: `offer` prints this
//! operator's invite and its fingerprint; the other airdress's owner runs
//! `accept` with the invite and the fingerprint they were read out. Then the
//! same the other way round. The operator records nothing unless the
//! fingerprint matches. Owner sign-in only.
//!
//! ```text
//! airdress peers offer
//! airdress peers accept '<invite>' --fingerprint ABCD-EFGH-…
//! airdress peers list
//! ```

use anyhow::Result;
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::chat_assign::{Operator, RunArgs};

/// `airdress peers …`.
#[derive(Debug, Subcommand)]
pub enum PeersCommands {
    /// Print this operator's invite (valid 15 minutes) and its fingerprint.
    Offer,
    /// Trust another operator's keys, after comparing its fingerprint.
    Accept {
        /// The invite line the other owner gave you.
        invite: String,
        /// The fingerprint the other owner read out to you.
        #[arg(long)]
        fingerprint: String,
    },
    /// The other operators this one trusts, and for what.
    List,
}

/// Run one `peers` command.
///
/// # Errors
/// Sign-in, the airdress lookup, or the operator's refusal.
pub async fn run(cmd: PeersCommands, args: RunArgs<'_>) -> Result<()> {
    let op = Operator::connect(&args).await?;
    let (v, words) = match cmd {
        PeersCommands::Offer => {
            let v = op
                .request(Method::POST, "/v1/admin/peers/offer", Some(&json!({})))
                .await?;
            let words = format!(
                "{}\nfingerprint: {}\nairdress root: {}\n\nGive the line above to the other \
                 owner and read them the fingerprint. It expires in 15 minutes.",
                v["invite"].as_str().unwrap_or_default(),
                v["fingerprint"].as_str().unwrap_or("?"),
                if v["roots"].as_array().is_some_and(|r| !r.is_empty()) {
                    "included"
                } else {
                    "NOT included: this airdress has no pinned root yet, so its agents \
                     cannot be reached from the other side"
                },
            );
            (v, words)
        }
        PeersCommands::Accept {
            invite,
            fingerprint,
        } => {
            let v = op
                .request(
                    Method::POST,
                    "/v1/admin/peers/accept",
                    Some(&json!({"invite": invite, "confirm_fingerprint": fingerprint})),
                )
                .await?;
            let words = format!(
                "trusted {}: {}",
                v["operator"].as_str().unwrap_or("?"),
                purposes(&v["trusted"])
            );
            (v, words)
        }
        PeersCommands::List => {
            let v = op.request(Method::GET, "/v1/admin/peers", None).await?;
            let rows = v["keys"].as_array().cloned().unwrap_or_default();
            let words = if rows.is_empty() {
                "no peers".to_owned()
            } else {
                rows.iter()
                    .map(|r| {
                        format!(
                            "{}  {}  {}",
                            r["operator"].as_str().unwrap_or("?"),
                            r["purpose"].as_str().unwrap_or("?"),
                            r["kid"].as_str().unwrap_or("?"),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            (v, words)
        }
    };
    if args.json {
        println!("{v}");
    } else {
        println!("{words}");
    }
    Ok(())
}

fn purposes(trusted: &Value) -> String {
    trusted
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["purpose"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_was_trusted_is_named() {
        let v = json!([{"purpose": "http_signing"}, {"purpose": "airdress_root"}]);
        assert_eq!(purposes(&v), "http_signing, airdress_root");
        assert_eq!(purposes(&Value::Null), "");
    }
}
