//! `airdress chat …` — give a conversation to an agent device, and take
//! it back.
//!
//! Assigning is the owner's decision and is made with the owner's sign-in:
//! the operator records the assignment as `pending_add`, starts delivering
//! that conversation to the agent device, and the owner's next phone that
//! is a member of the conversation adds the agent's leaf (an MLS Add) and
//! marks it active. Taking it back stops delivery at once; the next member
//! phone removes the leaf. Nothing here needs MLS: the CLI never holds a
//! leaf of the conversation it assigns.
//!
//! ```text
//! airdress chat agents                          agent devices of this airdress
//! airdress chat assign   <conversation> <device>
//! airdress chat unassign <conversation> [<device>]
//! airdress chat assignments <conversation>
//! ```

use anyhow::{bail, Context as _, Result};
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::airdresses::client::HubClient;
use crate::context;
use crate::profile::storage;
use crate::redact::Redacted;

/// `airdress chat …`.
#[derive(Debug, Subcommand)]
pub enum ChatCommands {
    /// The agent devices of this airdress, and their standing.
    Agents,
    /// Assign a conversation to an agent device. A phone of yours that is
    /// in the conversation then adds the device to it.
    Assign {
        /// The conversation id.
        conversation: String,
        /// The agent device: its enrollment id, or its label ("Claude Code on laptop").
        device: String,
    },
    /// Take a conversation back from an agent device (all of them when
    /// none is named). Delivery stops at once.
    Unassign {
        /// The conversation id.
        conversation: String,
        /// The agent device; omitted: every agent assigned to it.
        device: Option<String>,
    },
    /// Who a conversation is assigned to, and in which state.
    Assignments {
        /// The conversation id.
        conversation: String,
    },
}

/// What `run` needs from the global flags.
#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
}

/// The owner's operator, and a bearer for it.
#[derive(Debug)]
pub struct Operator {
    base: String,
    bearer: Redacted<String>,
    http: reqwest::Client,
}

impl Operator {
    async fn connect(args: &RunArgs<'_>) -> Result<Self> {
        let paths = args.paths;
        let profile = storage::resolve_profile_name(paths, args.profile)?;
        let hub = HubClient::from_profile(paths, &profile).await?;
        let named = context::resolve(paths, &profile, args.explicit_airdress)?;
        let fqdn = hub.resolve_fqdn(&named.name).await?;
        let base = args.operator_url.map_or_else(
            || format!("https://{fqdn}"),
            |u| u.trim_end_matches('/').to_owned(),
        );
        let bearer = hub.operator_bearer(&base).await?;
        Self::new(base, bearer)
    }

    /// A client for `base` with `bearer` (tests point it at a mock).
    pub fn new(base: String, bearer: impl Into<Redacted<String>>) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            bearer: bearer.into(),
            http: crate::http::client()?,
        })
    }

    async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.base))
            .bearer_auth(self.bearer.expose());
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("{method} {path}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let code = v["error"]["code"].as_str().unwrap_or("");
            let message = v["error"]["message"].as_str().unwrap_or(&text);
            return Err(crate::exit::Failure::http(
                status.as_u16(),
                if code.is_empty() {
                    format!("http_{}", status.as_u16())
                } else {
                    code.to_owned()
                },
                format!("{method} {path} answered {status} {code}: {message}"),
            )
            .into());
        }
        Ok(if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        })
    }

    /// The agent devices of this airdress.
    pub async fn agents(&self) -> Result<Vec<Value>> {
        let v = self
            .request(Method::GET, "/v1/endpoints/enrollments", None)
            .await?;
        let list = v["enrollments"]
            .as_array()
            .cloned()
            .or_else(|| v.as_array().cloned());
        Ok(list
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e["device_class"] == "agent")
            .collect())
    }

    /// Resolve an agent device named by enrollment id or label.
    pub async fn agent(&self, named: &str) -> Result<Value> {
        let agents = self.agents().await?;
        let hits: Vec<&Value> = agents
            .iter()
            .filter(|e| {
                e["id"].as_str() == Some(named)
                    || e["enrollment_id"].as_str() == Some(named)
                    || e["label"].as_str() == Some(named)
                    || e["device_label"].as_str() == Some(named)
            })
            .collect();
        match hits.as_slice() {
            [one] => Ok((*one).clone()),
            [] => bail!(
                "no agent device of this airdress is called {named:?}; see `airdress chat agents`"
            ),
            _ => bail!("{named:?} names more than one agent device; use its enrollment id"),
        }
    }

    pub async fn assign(&self, conversation: &str, enrollment: &str) -> Result<Value> {
        self.request(
            Method::POST,
            &format!("/v1/chat/conversations/{conversation}/agent-assignments"),
            Some(&json!({"enrollment_id": enrollment})),
        )
        .await
    }

    pub async fn assignments(&self, conversation: &str) -> Result<Vec<Value>> {
        let v = self
            .request(
                Method::GET,
                &format!("/v1/chat/conversations/{conversation}/agent-assignments"),
                None,
            )
            .await?;
        Ok(v["assignments"]
            .as_array()
            .cloned()
            .or_else(|| v.as_array().cloned())
            .unwrap_or_default())
    }

    pub async fn unassign(&self, conversation: &str, assignment: &str) -> Result<()> {
        self.request(
            Method::DELETE,
            &format!("/v1/chat/conversations/{conversation}/agent-assignments/{assignment}"),
            None,
        )
        .await
        .map(|_| ())
    }
}

fn enrollment_id(e: &Value) -> Option<&str> {
    e["id"].as_str().or_else(|| e["enrollment_id"].as_str())
}

fn live(a: &Value) -> bool {
    a["state"] != "ended"
}

/// Run `airdress chat …`.
pub async fn run(cmd: ChatCommands, args: RunArgs<'_>) -> Result<()> {
    let op = Operator::connect(&args).await?;
    let out = |v: Value, words: String| {
        if args.json {
            println!("{v}");
        } else {
            println!("{words}");
        }
    };
    match cmd {
        ChatCommands::Agents => {
            let agents = op.agents().await?;
            let words = if agents.is_empty() {
                "no agent devices".to_owned()
            } else {
                agents
                    .iter()
                    .map(|e| {
                        format!(
                            "{}  {}{}",
                            enrollment_id(e).unwrap_or("?"),
                            e["label"]
                                .as_str()
                                .or(e["device_label"].as_str())
                                .unwrap_or("?"),
                            if e["suspended_at"].is_null() {
                                ""
                            } else {
                                "  (suspended)"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            out(json!({"agents": agents}), words);
        }
        ChatCommands::Assign {
            conversation,
            device,
        } => {
            let agent = op.agent(&device).await?;
            let id = enrollment_id(&agent).context("the agent device has no id")?;
            let a = op.assign(&conversation, id).await?;
            out(
                a.clone(),
                format!(
                    "assigned; a phone of yours in the conversation will add the device \
                     (state {})",
                    a["state"]
                        .as_str()
                        .or(a["assignment"]["state"].as_str())
                        .unwrap_or("pending_add")
                ),
            );
        }
        ChatCommands::Unassign {
            conversation,
            device,
        } => {
            let wanted = match &device {
                Some(d) => Some(
                    enrollment_id(&op.agent(d).await?)
                        .context("the agent device has no id")?
                        .to_owned(),
                ),
                None => None,
            };
            let mut ended = Vec::new();
            for a in op
                .assignments(&conversation)
                .await?
                .iter()
                .filter(|a| live(a))
            {
                if let Some(w) = &wanted {
                    if a["enrollment_id"].as_str() != Some(w.as_str()) {
                        continue;
                    }
                }
                let id = a["id"].as_str().context("an assignment without an id")?;
                op.unassign(&conversation, id).await?;
                ended.push(id.to_owned());
            }
            if ended.is_empty() {
                bail!("nothing to unassign: no agent device is assigned to that conversation");
            }
            out(
                json!({"ended": ended}),
                format!(
                    "unassigned ({}); delivery stopped, a phone in the conversation removes \
                     the device",
                    ended.len()
                ),
            );
        }
        ChatCommands::Assignments { conversation } => {
            let list = op.assignments(&conversation).await?;
            let words = if list.is_empty() {
                "not assigned to any agent device".to_owned()
            } else {
                list.iter()
                    .map(|a| {
                        format!(
                            "{}  {}  {}",
                            a["id"].as_str().unwrap_or("?"),
                            a["enrollment_id"].as_str().unwrap_or("?"),
                            a["state"].as_str().unwrap_or("?")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            out(json!({"assignments": list}), words);
        }
    }
    Ok(())
}
