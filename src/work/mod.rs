//! `airdress work …` — tasks and RFIs on your airdress (SPEC-182 182-B.7).
//!
//! The operator's `/v1/work/items` routes, for scripting and for checking a
//! phone by hand: list what waits on you, read an item, hand out a task, ask
//! an RFI, move an item, answer an RFI, read its history. Who may do what is
//! the operator's to decide; this only says it plainly.
//!
//! People are named by their display name (`--to Ana`) or their id. A name
//! is looked up in the airdress's people (`GET /v1/admin/sub-users`), which
//! only the owner can read; anyone else passes ids.

pub mod client;

use anyhow::{bail, Context as _, Result};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Map, Value};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::profile::storage;
use crate::ui;

use client::WorkClient;

#[derive(Debug, Subcommand)]
pub enum WorkCommands {
    /// List work items: what waits on you, what is assigned to you, what you
    /// asked, or everything you can read.
    List {
        /// Which list.
        #[arg(long, value_enum, default_value_t = View::Waiting)]
        view: View,
        /// The most items to show (1–200).
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Show one work item: its fields, its people and, for an RFI, its
    /// question and answer.
    Show {
        /// The item's id.
        id: uuid::Uuid,
    },
    /// Hand out a task.
    Task {
        /// One line: what is to be done.
        title: String,
        /// Who does it: a person's name or id. Repeat for several.
        #[arg(long = "to", required = true, value_name = "PERSON")]
        to: Vec<String>,
        /// Who is kept informed. Repeatable.
        #[arg(long = "watch", value_name = "PERSON")]
        watch: Vec<String>,
        /// More detail.
        #[arg(long)]
        description: Option<String>,
        /// When it is due, as a date (2026-11-06).
        #[arg(long, value_name = "DATE")]
        due: Option<chrono::NaiveDate>,
        /// How urgent.
        #[arg(long, value_enum, default_value_t = Priority::Normal)]
        priority: Priority,
        /// Where: the place's name.
        #[arg(long = "at", value_name = "PLACE")]
        at: Option<String>,
    },
    /// Ask an RFI: a question that holds up work until it has one official
    /// answer.
    Rfi {
        /// One line, for lists.
        title: String,
        /// The question in full.
        #[arg(long)]
        question: String,
        /// Who answers: a person's name or id. Repeatable.
        #[arg(long = "to", required = true, value_name = "PERSON")]
        to: Vec<String>,
        /// What it refers to (a drawing, a spec section). Repeatable.
        #[arg(long = "ref", value_name = "REFERENCE")]
        refs: Vec<String>,
        /// Your own suggestion.
        #[arg(long)]
        propose: Option<String>,
        /// When the answer is needed, as a date.
        #[arg(long, value_name = "DATE")]
        reply_by: Option<chrono::NaiveDate>,
        /// Who is kept informed. Repeatable.
        #[arg(long = "watch", value_name = "PERSON")]
        watch: Vec<String>,
    },
    /// Move an item: start, finish, fail, cancel or reopen a task; close or
    /// withdraw an RFI.
    Status {
        /// The item's id.
        id: uuid::Uuid,
        /// The new status.
        #[arg(value_enum)]
        to: StatusArg,
    },
    /// Give an RFI its one official answer.
    Answer {
        /// The RFI's id.
        id: uuid::Uuid,
        /// The answer.
        text: String,
        /// Whether it may cost more.
        #[arg(long, value_enum, default_value_t = Impact::None)]
        cost: Impact,
        /// Whether it may take longer.
        #[arg(long, value_enum, default_value_t = Impact::None)]
        schedule: Impact,
    },
    /// Show an item's history: who changed what, when.
    History {
        /// The item's id.
        id: uuid::Uuid,
    },
}

/// Which list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum View {
    /// Open items assigned to you, oldest first.
    Waiting,
    /// Everything assigned to you.
    Mine,
    /// Everything you asked.
    Asked,
    /// Everything you can read.
    All,
}

impl View {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Mine => "mine",
            Self::Asked => "asked",
            Self::All => "all",
        }
    }
}

/// How urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Priority {
    Low,
    Normal,
    High,
}

/// A status, on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StatusArg {
    /// Task: not started (reopen).
    NeedsAction,
    /// Task: being worked on.
    InProcess,
    /// Task: done.
    Completed,
    /// Task: could not be done.
    Failed,
    /// Task: withdrawn.
    Cancelled,
    /// RFI: the asker accepts the answer.
    Closed,
    /// RFI: the asker withdraws it.
    Void,
}

impl StatusArg {
    const fn wire(self) -> &'static str {
        match self {
            Self::NeedsAction => "needs-action",
            Self::InProcess => "in-process",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Closed => "closed",
            Self::Void => "void",
        }
    }
}

/// A cost or schedule flag on an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Impact {
    None,
    Possible,
    Yes,
}

impl Impact {
    const fn wire(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Possible => "possible",
            Self::Yes => "yes",
        }
    }
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub operator_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

pub async fn run(command: WorkCommands, args: RunArgs<'_>) -> Result<()> {
    let op = connect(&args).await?;
    run_with(&op, command, args.json).await
}

/// The verbs, against a client already pointed at an operator.
pub async fn run_with(op: &WorkClient, command: WorkCommands, json_out: bool) -> Result<()> {
    match command {
        WorkCommands::List { view, limit } => {
            if !(1..=200).contains(&limit) {
                bail!("--limit is 1 to 200");
            }
            let list = op.list(view.as_str(), limit).await?;
            let items = list["items"].as_array().cloned().unwrap_or_default();
            if json_out {
                return print_json(&json!({ "items": items }));
            }
            if items.is_empty() {
                ui::say(match view {
                    View::Waiting => "nothing waits on you",
                    _ => "no work items",
                });
            } else {
                println!("{}", render_table(&items));
            }
        }
        WorkCommands::Show { id } => {
            let item = op.get(id).await?;
            if json_out {
                return print_json(&item);
            }
            println!("{}", render_item(&item));
        }
        WorkCommands::Task {
            title,
            to,
            watch,
            description,
            due,
            priority,
            at,
        } => {
            let assignees = op.resolve_people(&to).await?;
            let watchers = op.resolve_people(&watch).await?;
            let mut body = json!({
                "profile": "task",
                "title": title,
                "assignees": assignees.iter().map(|id| json!({ "kind": "principal", "id": id })).collect::<Vec<_>>(),
                "watchers": watchers,
                "priority": format!("{priority:?}").to_lowercase(),
            });
            if let Some(d) = description {
                body["description"] = json!(d);
            }
            if let Some(d) = due {
                body["due"] = json!({ "date": d });
            }
            if let Some(name) = at {
                body["place"] = json!({ "name": name });
            }
            created(&op.create(&body).await?, json_out)?;
        }
        WorkCommands::Rfi {
            title,
            question,
            to,
            refs,
            propose,
            reply_by,
            watch,
        } => {
            let assignees = op.resolve_people(&to).await?;
            let watchers = op.resolve_people(&watch).await?;
            let mut rfi = json!({ "question": question, "references": refs });
            if let Some(p) = propose {
                rfi["proposedAnswer"] = json!(p);
            }
            if let Some(d) = reply_by {
                rfi["replyBy"] = json!({ "date": d });
            }
            let body = json!({
                "profile": "rfi",
                "title": title,
                "assignees": assignees.iter().map(|id| json!({ "kind": "principal", "id": id })).collect::<Vec<_>>(),
                "watchers": watchers,
                "rfi": rfi,
            });
            created(&op.create(&body).await?, json_out)?;
        }
        WorkCommands::Status { id, to } => {
            let item = op.set_status(id, to.wire()).await?;
            if json_out {
                return print_json(&item);
            }
            ui::say(format!(
                "{} is now {}",
                label(&item),
                item["status"].as_str().unwrap_or("?")
            ));
        }
        WorkCommands::Answer {
            id,
            text,
            cost,
            schedule,
        } => {
            let item = op.answer(id, &text, cost.wire(), schedule.wire()).await?;
            if json_out {
                return print_json(&item);
            }
            ui::say(format!("{} answered", label(&item)));
            if cost != Impact::None || schedule != Impact::None {
                ui::note("An answer is not approval of extra cost or time.");
            }
        }
        WorkCommands::History { id } => {
            let h = op.history(id).await?;
            if json_out {
                return print_json(&h);
            }
            for e in h["entries"].as_array().cloned().unwrap_or_default() {
                println!("{}", render_history_entry(&e));
            }
        }
    }
    Ok(())
}

fn created(item: &Value, json_out: bool) -> Result<()> {
    if json_out {
        return print_json(item);
    }
    ui::say(format!(
        "created {} ({})",
        label(item),
        item["id"].as_str().unwrap_or("?")
    ));
    Ok(())
}

async fn connect(args: &RunArgs<'_>) -> Result<WorkClient> {
    let profile_name = storage::resolve_profile_name(args.paths, args.profile)?;
    let hub = HubClient::from_profile(args.paths, &profile_name).await?;
    if let Some(url) = args.operator_url {
        let bearer = hub.operator_bearer(url).await?;
        return WorkClient::with_base_url(url, bearer);
    }
    let resolved = context::resolve(args.paths, &profile_name, args.explicit_airdress)?;
    if !args.json && !args.quiet && resolved.source != Source::Flag {
        ui::note(format!(
            "acting on {} (source: {})",
            resolved.name,
            resolved.source.as_str()
        ));
    }
    let fqdn = hub.resolve_fqdn(&resolved.name).await?;
    let bearer = hub.operator_bearer(&fqdn).await?;
    WorkClient::with_base_url(&format!("https://{}", fqdn.trim_matches('/')), bearer)
}

/// `Task #12` or `RFI #7`.
pub fn label(item: &Value) -> String {
    let n = item["number"].as_u64().unwrap_or(0);
    if item["profile"] == "rfi" {
        format!("RFI #{n}")
    } else {
        format!("Task #{n}")
    }
}

fn due_of(item: &Value) -> String {
    let due = if item["profile"] == "rfi" {
        &item["rfi"]["replyBy"]
    } else {
        &item["due"]
    };
    due["date"]
        .as_str()
        .or_else(|| due["at"].as_str())
        .unwrap_or("")
        .to_owned()
}

/// The list as a table.
pub fn render_table(items: &[Value]) -> String {
    let rows: Vec<[String; 4]> = items
        .iter()
        .map(|i| {
            [
                label(i),
                i["status"].as_str().unwrap_or("").to_owned(),
                due_of(i),
                i["title"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    let mut w = [4, 6, 3, 5];
    for r in &rows {
        for (k, cell) in r.iter().enumerate() {
            w[k] = w[k].max(cell.chars().count());
        }
    }
    let mut out = format!(
        "{:<a$}  {:<b$}  {:<c$}  TITLE",
        "ITEM",
        "STATUS",
        "DUE",
        a = w[0],
        b = w[1],
        c = w[2]
    );
    for r in rows {
        out.push_str(&format!(
            "\n{:<a$}  {:<b$}  {:<c$}  {}",
            r[0],
            r[1],
            r[2],
            r[3],
            a = w[0],
            b = w[1],
            c = w[2]
        ));
    }
    out
}

/// One item, for a person to read.
pub fn render_item(item: &Value) -> String {
    let mut out = format!(
        "{} — {}\nstatus: {}",
        label(item),
        item["title"].as_str().unwrap_or(""),
        item["status"].as_str().unwrap_or("")
    );
    let due = due_of(item);
    if !due.is_empty() {
        out.push_str(&format!(
            "\n{}: {due}",
            if item["profile"] == "rfi" {
                "reply by"
            } else {
                "due"
            }
        ));
    }
    if let Some(d) = item["description"].as_str() {
        out.push_str(&format!("\n\n{d}"));
    }
    if let Some(p) = item["place"]["name"].as_str() {
        out.push_str(&format!("\nat: {p}"));
        if let Some(a) = item["place"]["access"].as_str() {
            out.push_str(&format!("\naccess: {a}"));
        }
    }
    let rfi = &item["rfi"];
    if let Some(q) = rfi["question"].as_str() {
        out.push_str(&format!("\n\nquestion: {q}"));
        for r in rfi["references"].as_array().into_iter().flatten() {
            out.push_str(&format!("\n  ref: {}", r.as_str().unwrap_or("")));
        }
        if let Some(p) = rfi["proposedAnswer"].as_str() {
            out.push_str(&format!("\nproposed: {p}"));
        }
        let a = &rfi["officialAnswer"];
        if let Some(t) = a["text"].as_str() {
            out.push_str(&format!(
                "\nanswer: {t} (cost: {}, schedule: {})",
                a["costImpact"].as_str().unwrap_or("none"),
                a["scheduleImpact"].as_str().unwrap_or("none")
            ));
            if a["costImpact"] != "none" || a["scheduleImpact"] != "none" {
                out.push_str("\nAn answer is not approval of extra cost or time.");
            }
        }
    }
    out.push_str("\n\nKept by your company's airdress; not end to end.");
    out
}

fn render_history_entry(e: &Value) -> String {
    let at = e["at"].as_str().unwrap_or("");
    let by = e["by"].as_str().unwrap_or("");
    let change = &e["change"];
    let what = match change["op"].as_str().unwrap_or("") {
        "status" => format!(
            "{} → {}",
            change["from"].as_str().unwrap_or(""),
            change["to"].as_str().unwrap_or("")
        ),
        "changed" => format!(
            "changed {}",
            change["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.to_owned(),
    };
    format!("{:>3}  {at}  {by}  {what}", e["seq"].as_i64().unwrap_or(0))
}

fn print_json(v: &Value) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(v).context("render JSON")?
    );
    Ok(())
}

/// A people map for name lookups: display name → id.
pub(crate) fn match_person(name: &str, people: &Map<String, Value>) -> Result<uuid::Uuid> {
    let matches: Vec<&String> = people
        .keys()
        .filter(|k| k.eq_ignore_ascii_case(name))
        .collect();
    match matches.as_slice() {
        [one] => people[*one]
            .as_str()
            .and_then(|s| s.parse().ok())
            .with_context(|| format!("{name}: the operator listed no id")),
        [] => bail!("no person called {name:?} on this airdress (pass their id instead)"),
        _ => bail!("more than one person is called {name:?}; pass their id"),
    }
}

#[cfg(test)]
mod tests;
