//! `airdress geo …` — thin commands against the geo plugin at
//! `geo.<airdress>`, and against the operator's grant routes for sharing.
//!
//! SPEC-117 117-1.9 (collections, items, usage: a round trip), the CLI half
//! of 117-2.1 (`share grant|revoke|list`, over the operator's
//! `/v1/plugin-grants`) and of 117-2.2 (`share link create|list|revoke`,
//! over geo's `/collections/{c}/share-links`).
//!
//! A collection itself is a `GeoCollection` resource: `airdress apply -f`
//! makes and changes it, `airdress delete` removes it. Nothing here does.
//!
//! **Collection ids.** Geo names a collection `<name>~<tag>`, the tag being
//! the first six bytes of SHA-256 over the namespace it lives in
//! (`person:<id>` or `install:<install id>`), so two people's `trips` are
//! two collections. Every command takes the full id or the bare name; a bare
//! name that matches more than one collection the caller can read is
//! refused, naming them. A grant needs the namespace and the name
//! separately, and the tag is what tells the CLI which namespace it is.

pub mod client;

use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::airdresses::client::HubClient;
use crate::context::{self, Source};
use crate::plugins::client::{Install, PluginsClient};
use crate::profile::storage;
use crate::ui;

use client::{GeoClient, Grant, GrantBody, GrantsClient, ItemQuery, MintBody};

/// The resource type geo's manifest declares for its collections.
pub const RESOURCE_TYPE: &str = "GeoCollection";

/// The plugin's name, as an install's `app_type` and its default subdomain.
pub const PLUGIN: &str = "geo";

#[derive(Debug, Subcommand)]
pub enum GeoCommands {
    /// The geo collections you may read: id, title, scope, storage.
    /// `show <collection>` reads one.
    Collections {
        #[command(subcommand)]
        command: Option<CollectionsCommands>,
    },
    /// Read and write a collection's items as GeoJSON.
    Items {
        #[command(subcommand)]
        command: ItemsCommands,
    },
    /// Share a collection: with someone on your airdress (`grant`,
    /// `revoke`, `list`) or by link (`link create|list|revoke`).
    Share {
        #[command(subcommand)]
        command: ShareCommands,
    },
    /// What you hold in geo and may hold: collections, items, bytes,
    /// observations. The airdress owner also sees the household's.
    Usage,
}

#[derive(Debug, Subcommand)]
pub enum CollectionsCommands {
    /// List the collections you may read.
    List,
    /// Show one collection.
    Show {
        /// The collection's id (`trips~3f9a2c1b0d4e`) or its name.
        collection: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ItemsCommands {
    /// List a collection's items: id, geometry type and properties. With
    /// `-o json`, the GeoJSON FeatureCollection as geo sent it.
    List {
        /// The collection's id or name.
        collection: String,
        /// The most items in one page.
        #[arg(long)]
        limit: Option<u32>,
        /// `minLon,minLat,maxLon,maxLat`, in CRS84.
        #[arg(long)]
        bbox: Option<String>,
        /// An instant or an interval (`2026-01-01T00:00:00Z/..`).
        #[arg(long)]
        datetime: Option<String>,
        /// A CQL2 text filter (`bed = 'north'`).
        #[arg(long)]
        filter: Option<String>,
        /// Continue where the last page stopped, as it printed.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Print one item as a GeoJSON Feature; its ETag goes to stderr (with
    /// `-o json`: `{"etag", "feature"}`).
    Get {
        /// The collection's id or name.
        collection: String,
        /// The item's id.
        id: String,
    },
    /// Write a GeoJSON Feature: a new item, or with an id the item it
    /// replaces.
    Put {
        /// The collection's id or name.
        collection: String,
        /// Replace this item instead of creating one.
        id: Option<String>,
        /// The Feature, from a file or `-` for stdin.
        #[arg(short = 'f', long = "file", default_value = "-")]
        file: String,
        /// Replace only if the item still has this ETag (as `get` printed).
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
    },
    /// Delete one item. Asks first; pass `--yes` to skip the prompt
    /// (required when stdin is not a terminal).
    Delete {
        /// The collection's id or name.
        collection: String,
        /// The item's id.
        id: String,
        /// Delete only if the item still has this ETag.
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
        /// Delete without asking for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

/// What a grant lets its holder do with a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DataAction {
    /// Read the collection and its items.
    #[value(name = "ReadData")]
    ReadData,
    /// Write items. Shows nothing back without `ReadData` too.
    #[value(name = "WriteData")]
    WriteData,
}

impl DataAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadData => "ReadData",
            Self::WriteData => "WriteData",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ShareCommands {
    /// Let someone on your airdress (a person or a machine) read or write
    /// one of your collections. A household collection is the owner's to
    /// share.
    Grant {
        /// The collection's id or name.
        collection: String,
        /// The principal id of whom it is shared with.
        #[arg(long = "to", value_name = "PRINCIPAL")]
        to: String,
        /// `ReadData` and/or `WriteData` (repeatable).
        #[arg(
            long = "action",
            value_name = "ACTION",
            required = true,
            ignore_case = true
        )]
        actions: Vec<DataAction>,
        /// The geo install's id. Default: the one install of geo the
        /// airdress owner's `airdress plugins list` shows.
        #[arg(long)]
        install: Option<String>,
    },
    /// Take back what a grant gave. Without `--action`, the whole grant.
    Revoke {
        /// The collection's id or name.
        collection: String,
        /// The principal id it was shared with.
        #[arg(long = "to", value_name = "PRINCIPAL")]
        to: String,
        /// Take back only this (repeatable); the rest stays granted.
        #[arg(long = "action", value_name = "ACTION", ignore_case = true)]
        actions: Vec<DataAction>,
        /// The geo install's id (as for `grant`).
        #[arg(long)]
        install: Option<String>,
    },
    /// The grants on one collection: who, and what they may do.
    List {
        /// The collection's id or name.
        collection: String,
        /// The geo install's id (as for `grant`).
        #[arg(long)]
        install: Option<String>,
    },
    /// Share links: read-only, coarsened, expiring.
    Link {
        #[command(subcommand)]
        command: LinkCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum LinkCommands {
    /// Mint a read-only link to a collection; prints the link. Whoever
    /// holds it can read the collection at that precision until it expires.
    Create {
        /// The collection's id or name.
        collection: String,
        /// How finely points are shown: `exact`, `100m`, `1km`,
        /// `approximate`, `20km`, `100km`, or metres. Default: approximate
        /// (exact for a public collection).
        #[arg(long)]
        precision: Option<String>,
        /// How long it lasts: `<n>h`, `<n>d`, `<n>w`. Default: the longest
        /// the collection allows.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Your links to a collection: id, precision, expiry, state. Never the
    /// link itself.
    List {
        /// The collection's id or name.
        collection: String,
    },
    /// Revoke a link, and every narrower link made from it.
    Revoke {
        /// The collection's id or name.
        collection: String,
        /// The link's id, as `link list` prints it.
        rid: String,
    },
}

#[derive(Debug)]
pub struct RunArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    /// Dev-only: the operator at this URL instead of `https://<fqdn>`.
    pub operator_url: Option<&'a str>,
    /// Dev-only: geo at this URL instead of `https://geo.<fqdn>`.
    pub geo_url: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
}

/// Both halves a verb may talk to, with one bearer.
#[derive(Debug)]
pub struct Clients {
    pub geo: GeoClient,
    pub grants: GrantsClient,
}

pub async fn run(command: GeoCommands, args: RunArgs<'_>) -> Result<()> {
    check_locally(&command)?;
    let c = connect(&args).await?;
    dispatch(&c, command, args.json).await
}

/// A checked command over connected clients.
async fn dispatch(c: &Clients, command: GeoCommands, json: bool) -> Result<()> {
    match command {
        GeoCommands::Collections { command } => match command {
            None | Some(CollectionsCommands::List) => collections_list(&c.geo, json).await,
            Some(CollectionsCommands::Show { collection }) => {
                let id = resolve_collection(&c.geo, &collection).await?;
                let v = c.geo.collection(&id).await?;
                if json {
                    print_json(&v)
                } else {
                    println!("{}", render_collection(&v));
                    Ok(())
                }
            }
        },
        GeoCommands::Items { command } => items(&c.geo, command, json).await,
        GeoCommands::Usage => {
            let v = c.geo.usage().await?;
            if json {
                print_json(&v)
            } else {
                println!("{}", render_usage(&v));
                Ok(())
            }
        }
        GeoCommands::Share { command } => share(c, command, json).await,
    }
}

/// Everything that can be refused without a network call.
fn check_locally(command: &GeoCommands) -> Result<()> {
    let coll = |c: &str| valid_collection(c).map(|_| ());
    match command {
        GeoCommands::Collections {
            command: Some(CollectionsCommands::Show { collection }),
        } => coll(collection),
        GeoCommands::Collections { .. } | GeoCommands::Usage => Ok(()),
        GeoCommands::Items { command } => match command {
            ItemsCommands::List { collection, .. } => coll(collection),
            ItemsCommands::Get { collection, id }
            | ItemsCommands::Delete { collection, id, .. } => {
                coll(collection)?;
                valid_item(id).map(|_| ())
            }
            ItemsCommands::Put { collection, id, .. } => {
                coll(collection)?;
                id.as_deref().map_or(Ok(()), |i| valid_item(i).map(|_| ()))
            }
        },
        GeoCommands::Share { command } => match command {
            ShareCommands::Grant {
                collection,
                to,
                install,
                ..
            }
            | ShareCommands::Revoke {
                collection,
                to,
                install,
                ..
            } => {
                coll(collection)?;
                valid_principal(to)?;
                install
                    .as_deref()
                    .map_or(Ok(()), |i| crate::plugins::client::valid_id(i).map(|_| ()))
            }
            ShareCommands::List {
                collection,
                install,
            } => {
                coll(collection)?;
                install
                    .as_deref()
                    .map_or(Ok(()), |i| crate::plugins::client::valid_id(i).map(|_| ()))
            }
            ShareCommands::Link { command } => match command {
                LinkCommands::Create {
                    collection,
                    precision,
                    ttl,
                } => {
                    coll(collection)?;
                    if let Some(p) = precision {
                        precision_m(p)?;
                    }
                    if let Some(t) = ttl {
                        valid_ttl(t)?;
                    }
                    Ok(())
                }
                LinkCommands::List { collection } => coll(collection),
                LinkCommands::Revoke { collection, rid } => {
                    coll(collection)?;
                    valid_rid(rid).map(|_| ())
                }
            },
        },
    }
}

async fn connect(args: &RunArgs<'_>) -> Result<Clients> {
    let paths = args.paths;
    let profile_name = storage::resolve_profile_name(paths, args.profile)?;
    let hub = HubClient::from_profile(paths, &profile_name).await?;
    if let Some(op) = args.operator_url {
        let Some(geo) = args.geo_url else {
            bail!("--operator-url needs --geo-url beside it: geo is served on its own host");
        };
        let bearer = hub.operator_bearer(op).await?;
        return Ok(Clients {
            geo: GeoClient::with_base_url(geo.to_owned(), bearer.clone())?,
            grants: GrantsClient::with_base_url(op.to_owned(), bearer)?,
        });
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
    // The plugin proxy in front of geo takes the operator's own bearer.
    let bearer = hub.operator_bearer(&fqdn).await?;
    let geo = match args.geo_url {
        Some(u) => GeoClient::with_base_url(u.to_owned(), bearer.clone())?,
        None => GeoClient::new(&format!("{PLUGIN}.{fqdn}"), bearer.clone())?,
    };
    Ok(Clients {
        geo,
        grants: GrantsClient::with_base_url(format!("https://{fqdn}"), bearer)?,
    })
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

async fn collections_list(geo: &GeoClient, json: bool) -> Result<()> {
    let v = geo.collections().await?;
    if json {
        return print_json(&v);
    }
    let list = v
        .get("collections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        ui::say("no geo collections you may read — `airdress apply -f` makes one");
    } else {
        println!("{}", render_collections(&list));
    }
    Ok(())
}

/// The collection `input` names: a full id as given, or the one readable
/// collection whose name it is.
pub async fn resolve_collection(geo: &GeoClient, input: &str) -> Result<String> {
    if input.contains('~') {
        return Ok(input.to_owned());
    }
    let v = geo.collections().await?;
    let ids: Vec<String> = v
        .get("collections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .filter(|id| id.split('~').next() == Some(input))
        .map(str::to_owned)
        .collect();
    match ids.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!(
            "no geo collection named `{input}` that you may read — \
             `airdress geo collections` lists them"
        ),
        many => bail!(
            "`{input}` names {} collections you may read: {} — pass the full id",
            many.len(),
            many.join(", ")
        ),
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return "-",
        }
    }
    cur.as_str().unwrap_or("-")
}

fn render_collections(list: &[Value]) -> String {
    let mut out = format!("{:<32}  {:<9}  {:<10}  title", "id", "scope", "storage");
    for c in list {
        out.push_str(&format!(
            "\n{:<32}  {:<9}  {:<10}  {}",
            str_at(c, &["id"]),
            str_at(c, &["scope"]),
            str_at(c, &["storage", "mode"]),
            str_at(c, &["title"]),
        ));
    }
    out
}

fn render_collection(c: &Value) -> String {
    let mut out = format!(
        "collection {}\n  title:    {}\n  scope:    {}\n  storage:  {} ({})",
        str_at(c, &["id"]),
        str_at(c, &["title"]),
        str_at(c, &["scope"]),
        str_at(c, &["storage", "mode"]),
        str_at(c, &["storage", "atRest"]),
    );
    if let Some(d) = c.get("description").and_then(Value::as_str) {
        out.push_str(&format!("\n  about:    {d}"));
    }
    if let Some(b) = c
        .pointer("/extent/spatial/bbox/0")
        .and_then(Value::as_array)
    {
        let b: Vec<String> = b.iter().map(Value::to_string).collect();
        out.push_str(&format!("\n  extent:   {} (rounded outward)", b.join(", ")));
    }
    out
}

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

async fn items(geo: &GeoClient, command: ItemsCommands, json: bool) -> Result<()> {
    match command {
        ItemsCommands::List {
            collection,
            limit,
            bbox,
            datetime,
            filter,
            cursor,
        } => {
            let c = resolve_collection(geo, &collection).await?;
            let q = ItemQuery {
                limit,
                bbox,
                datetime,
                filter,
                cursor,
            };
            let v = geo.items(&c, &q).await?;
            if json {
                return print_json(&v);
            }
            let features = v
                .get("features")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if features.is_empty() {
                ui::say(format!("no items in {c}"));
            } else {
                println!("{}", render_items(&features));
            }
            if let Some(next) = next_cursor(&v) {
                ui::note(format!(
                    "more: airdress geo items list {c} --cursor '{next}'"
                ));
            }
            Ok(())
        }
        ItemsCommands::Get { collection, id } => {
            let c = resolve_collection(geo, &collection).await?;
            let (feature, etag) = geo.item(&c, &id).await?;
            if json {
                print_json(&json!({ "etag": etag, "feature": feature }))
            } else {
                if let Some(e) = &etag {
                    ui::note(format!("etag {e}"));
                }
                print_json(&feature)
            }
        }
        ItemsCommands::Put {
            collection,
            id,
            file,
            if_match,
        } => {
            let feature = read_feature(&file)?;
            let c = resolve_collection(geo, &collection).await?;
            let (w, created) = match id {
                Some(id) => (
                    geo.replace(&c, &id, &feature, if_match.as_deref()).await?,
                    false,
                ),
                None => {
                    if if_match.is_some() {
                        bail!("--if-match guards a replace; name the item to replace");
                    }
                    (geo.create(&c, &feature).await?, true)
                }
            };
            if json {
                print_json(&json!({ "id": w.id, "etag": w.etag, "created": created }))
            } else {
                let verb = if created { "created" } else { "replaced" };
                let etag = w.etag.as_deref().unwrap_or("-");
                ui::ok(format!("{verb} item {} in {c} (etag {etag})", w.id));
                Ok(())
            }
        }
        ItemsCommands::Delete {
            collection,
            id,
            if_match,
            yes,
        } => {
            let c = resolve_collection(geo, &collection).await?;
            ui::confirm(
                &format!("Delete item {id} from {c}?"),
                ui::Confirm::new(yes, json),
            )?;
            geo.delete(&c, &id, if_match.as_deref()).await?;
            if json {
                print_json(&json!({ "collection": c, "id": id, "deleted": true }))
            } else {
                ui::ok(format!("deleted item {id} from {c}"));
                Ok(())
            }
        }
    }
}

/// A GeoJSON Feature from a file, or stdin for `-`.
fn read_feature(file: &str) -> Result<Value> {
    let text = if file == "-" {
        std::io::read_to_string(std::io::stdin()).context("read the Feature from stdin")?
    } else {
        std::fs::read_to_string(file).with_context(|| format!("read {file}"))?
    };
    parse_feature(&text)
}

fn parse_feature(text: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(text).context("the Feature is not JSON")?;
    if v.get("type").and_then(Value::as_str) != Some("Feature") {
        bail!("expected one GeoJSON Feature (`\"type\": \"Feature\"`); write items one at a time");
    }
    Ok(v)
}

/// The `cursor` of the items answer's `next` link.
fn next_cursor(v: &Value) -> Option<String> {
    let href = v
        .get("links")?
        .as_array()?
        .iter()
        .find(|l| l.get("rel").and_then(Value::as_str) == Some("next"))?
        .get("href")?
        .as_str()?;
    let url = reqwest::Url::parse(href).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == "cursor")
        .map(|(_, v)| v.into_owned())
}

fn render_items(features: &[Value]) -> String {
    let mut out = format!("{:<36}  {:<18}  properties", "id", "geometry");
    for f in features {
        let id = match f.get("id") {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => "-".to_owned(),
        };
        let mut props = f
            .get("properties")
            .map(Value::to_string)
            .unwrap_or_default();
        if props.chars().count() > 60 {
            props = props.chars().take(59).collect::<String>() + "…";
        }
        out.push_str(&format!(
            "\n{:<36}  {:<18}  {props}",
            id,
            str_at(f, &["geometry", "type"]),
        ));
    }
    out
}

fn render_usage(v: &Value) -> String {
    let mut out = String::new();
    let block = |label: &str, a: &Value, out: &mut String| {
        out.push_str(label);
        for k in ["collections", "items", "bytes", "observations"] {
            let used = a
                .pointer(&format!("/usage/{k}"))
                .map_or_else(|| "-".to_owned(), Value::to_string);
            let limit = a
                .pointer(&format!("/limits/{k}"))
                .map_or_else(|| "-".to_owned(), Value::to_string);
            out.push_str(&format!("\n  {k:<13} {used} of {limit}"));
        }
    };
    if let Some(p) = v.get("personal") {
        block("yours:", p, &mut out);
    }
    if let Some(a) = v.get("airdress") {
        out.push('\n');
        block("household:", a, &mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------

async fn share(c: &Clients, command: ShareCommands, json: bool) -> Result<()> {
    match command {
        ShareCommands::Grant {
            collection,
            to,
            actions,
            install,
        } => {
            let target = target(c, &collection, install.as_deref()).await?;
            let g = grant(&c.grants, &target, &to, &actions).await?;
            if json {
                print_json(&g)
            } else {
                ui::ok(format!(
                    "{to} may now {} {} ({})",
                    describe_actions(&g.actions),
                    target.id,
                    g.id
                ));
                Ok(())
            }
        }
        ShareCommands::Revoke {
            collection,
            to,
            actions,
            install,
        } => {
            let target = target(c, &collection, install.as_deref()).await?;
            let left = revoke(&c.grants, &target, &to, &actions).await?;
            if json {
                return print_json(&json!({
                    "collection": target.id,
                    "principal": to,
                    "remaining": left.as_ref().map(|g| &g.actions),
                }));
            }
            match left {
                Some(g) => ui::ok(format!(
                    "{to} may now only {} {}",
                    describe_actions(&g.actions),
                    target.id
                )),
                None => ui::ok(format!("{to} no longer has a grant on {}", target.id)),
            }
            Ok(())
        }
        ShareCommands::List {
            collection,
            install,
        } => {
            let target = target(c, &collection, install.as_deref()).await?;
            let grants = grants_on(&c.grants, &target).await?;
            if json {
                print_json(&json!({ "collection": target.id, "grants": grants }))
            } else if grants.is_empty() {
                ui::say(format!("{} is shared with nobody", target.id));
                Ok(())
            } else {
                println!("{}", render_grants(&grants));
                Ok(())
            }
        }
        ShareCommands::Link { command } => links(&c.geo, command, json).await,
    }
}

/// A collection as the grant routes address it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Geo's id, `<name>~<tag>`.
    pub id: String,
    pub install: String,
    /// `person:<id>` or `install:<id>`.
    pub namespace: String,
    /// The `GeoCollection`'s name in its namespace.
    pub name: String,
}

/// Geo's tag for a namespace: the first six bytes of its SHA-256, in hex.
/// The same derivation as geo's own `collection_id`.
pub fn namespace_tag(namespace: &str) -> String {
    Sha256::digest(namespace.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn target(c: &Clients, collection: &str, install: Option<&str>) -> Result<Target> {
    let id = resolve_collection(&c.geo, collection).await?;
    let install = match install {
        Some(i) => i.to_owned(),
        None => {
            let ops = PluginsClient::with_base_url(
                c.grants.base_url().to_owned(),
                c.grants.bearer().clone(),
            )?;
            geo_install(&ops.list().await.map_err(|e| {
                e.context(
                    "find the geo install (only the airdress owner may list installs; \
                     anyone else passes --install <id>)",
                )
            })?)?
        }
    };
    let (name, tag) = id
        .split_once('~')
        .map(|(n, t)| (n.to_owned(), t.to_owned()))
        .with_context(|| format!("`{id}` is not a geo collection id"))?;
    let tag = tag.as_str();
    let household = format!("install:{install}");
    let namespace = if namespace_tag(&household) == tag {
        household
    } else {
        let me = c.geo.usage().await?;
        let me = me
            .get("principal")
            .and_then(Value::as_str)
            .context("geo did not say who you are (/me/usage has no principal)")?;
        let mine = format!("person:{me}");
        if namespace_tag(&mine) != tag {
            bail!(
                "`{id}` is someone else's collection: only its person may share it \
                 (or, if it is a household collection, the install is not {install})"
            );
        }
        mine
    };
    Ok(Target {
        id,
        install,
        namespace,
        name,
    })
}

/// The one geo install among `installs`.
fn geo_install(installs: &[Install]) -> Result<String> {
    let geo: Vec<&Install> = installs.iter().filter(|i| i.app_type == PLUGIN).collect();
    match geo.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => bail!("geo is not installed on this airdress (`airdress plugins list`)"),
        many => bail!(
            "geo is installed {} times ({}) — pass --install <id>",
            many.len(),
            many.iter()
                .map(|i| format!("{} at {}", i.id, i.subdomain))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

async fn grants_on(grants: &GrantsClient, t: &Target) -> Result<Vec<Grant>> {
    Ok(grants
        .list(&t.install)
        .await?
        .into_iter()
        .filter(|g| {
            g.resource_type == RESOURCE_TYPE && g.namespace == t.namespace && g.resource == t.name
        })
        .collect())
}

fn sorted(actions: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = actions.into_iter().collect();
    v.sort();
    v.dedup();
    v
}

async fn create(
    grants: &GrantsClient,
    t: &Target,
    to: &str,
    actions: Vec<String>,
) -> Result<Grant> {
    grants
        .create(&GrantBody {
            install: &t.install,
            resource_type: RESOURCE_TYPE,
            namespace: &t.namespace,
            resource: &t.name,
            principal: to,
            actions,
        })
        .await
}

/// Revoke `old` and grant `actions` in its place. The routes hold one
/// grant per principal and collection and have no update, so changing one
/// is a revoke and a create; if the create fails the principal is left
/// with less, never more, and the error says so.
async fn replace(
    grants: &GrantsClient,
    t: &Target,
    to: &str,
    old: &Grant,
    actions: Vec<String>,
) -> Result<Grant> {
    grants.revoke(&old.id).await?;
    create(grants, t, to, actions).await.map_err(|e| {
        e.context(format!(
            "the earlier grant ({}) was revoked and its replacement refused: \
             {to} now has no access to {}",
            describe_actions(&old.actions),
            t.id
        ))
    })
}

/// Grant `actions`; an existing grant to `to` is widened to cover them.
pub async fn grant(
    grants: &GrantsClient,
    t: &Target,
    to: &str,
    actions: &[DataAction],
) -> Result<Grant> {
    let want = sorted(actions.iter().map(|a| a.as_str().to_owned()));
    let existing = grants_on(grants, t)
        .await?
        .into_iter()
        .find(|g| g.principal == to);
    match existing {
        None => create(grants, t, to, want).await,
        Some(g) if want.iter().all(|a| g.actions.contains(a)) => {
            ui::note(format!(
                "{to} could already {} {}; nothing was changed",
                describe_actions(&g.actions),
                t.id
            ));
            Ok(g)
        }
        Some(g) => {
            let union = sorted(g.actions.iter().cloned().chain(want));
            replace(grants, t, to, &g, union).await
        }
    }
}

/// Take back `actions` (all of the grant when empty). The grant left
/// standing, if any.
pub async fn revoke(
    grants: &GrantsClient,
    t: &Target,
    to: &str,
    actions: &[DataAction],
) -> Result<Option<Grant>> {
    let Some(g) = grants_on(grants, t)
        .await?
        .into_iter()
        .find(|g| g.principal == to)
    else {
        bail!("{to} has no grant on {}; nothing was changed", t.id);
    };
    let drop: Vec<&str> = actions.iter().map(|a| a.as_str()).collect();
    let left: Vec<String> = if drop.is_empty() {
        Vec::new()
    } else {
        g.actions
            .iter()
            .filter(|a| !drop.contains(&a.as_str()))
            .cloned()
            .collect()
    };
    if left.len() == g.actions.len() {
        ui::note(format!(
            "{to} could only {} {}; nothing was changed",
            describe_actions(&g.actions),
            t.id
        ));
        return Ok(Some(g));
    }
    if left.is_empty() {
        grants.revoke(&g.id).await?;
        return Ok(None);
    }
    replace(grants, t, to, &g, left).await.map(Some)
}

fn describe_actions(actions: &[String]) -> String {
    let read = actions.iter().any(|a| a == "ReadData");
    let write = actions.iter().any(|a| a == "WriteData");
    match (read, write) {
        (true, true) => "read and write".to_owned(),
        (true, false) => "read".to_owned(),
        (false, true) => "write (without reading)".to_owned(),
        _ => actions.join(", "),
    }
}

fn render_grants(grants: &[Grant]) -> String {
    let mut out = format!(
        "{:<36}  {:<20}  {:<36}  since",
        "principal", "actions", "grant"
    );
    for g in grants {
        out.push_str(&format!(
            "\n{:<36}  {:<20}  {:<36}  {}",
            g.principal,
            g.actions.join(","),
            g.id,
            g.created_at.as_deref().unwrap_or("-")
        ));
    }
    out
}

async fn links(geo: &GeoClient, command: LinkCommands, json: bool) -> Result<()> {
    match command {
        LinkCommands::Create {
            collection,
            precision,
            ttl,
        } => {
            let c = resolve_collection(geo, &collection).await?;
            let body = MintBody {
                precision_m: precision.as_deref().map(precision_m).transpose()?,
                ttl,
            };
            let v = geo.link_create(&c, &body).await?;
            let url = v
                .get("url")
                .and_then(Value::as_str)
                .context("geo minted a link but sent no url")?;
            if json {
                // The token is in the url; it is not repeated on its own.
                return print_json(&json!({
                    "collection": c,
                    "url": url,
                    "rid": v.get("rid"),
                    "expiresAt": v.get("expiresAt"),
                    "precisionM": v.get("precisionM"),
                    "precision": v.get("precision"),
                }));
            }
            ui::ok(format!(
                "a read-only link to {c}, points shown {}, until {} (id {}). \
                 Anyone holding it can read; `airdress geo share link revoke {c} <id>` ends it",
                str_at(&v, &["precision"]),
                str_at(&v, &["expiresAt"]),
                str_at(&v, &["rid"]),
            ));
            println!("{url}");
            Ok(())
        }
        LinkCommands::List { collection } => {
            let c = resolve_collection(geo, &collection).await?;
            let v = geo.links(&c).await?;
            if json {
                return print_json(&v);
            }
            let list = v
                .get("links")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                ui::say(format!("you have no links to {c}"));
            } else {
                println!("{}", render_links(&list));
            }
            Ok(())
        }
        LinkCommands::Revoke { collection, rid } => {
            let c = resolve_collection(geo, &collection).await?;
            geo.link_revoke(&c, &rid).await?;
            if json {
                print_json(&json!({ "collection": c, "rid": rid, "revoked": true }))
            } else {
                ui::ok(format!(
                    "revoked link {rid} to {c}, and every link made from it"
                ));
                Ok(())
            }
        }
    }
}

fn render_links(list: &[Value]) -> String {
    let mut out = format!("{:<28}  {:<12}  {:<8}  expires", "id", "precision", "state");
    for l in list {
        out.push_str(&format!(
            "\n{:<28}  {:<12}  {:<8}  {}",
            str_at(l, &["rid"]),
            str_at(l, &["precision"]),
            str_at(l, &["state"]),
            str_at(l, &["expiresAt"]),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Local checks
// ---------------------------------------------------------------------------

/// A collection id or name as one path segment.
fn valid_collection(c: &str) -> Result<&str> {
    let ok = !c.is_empty()
        && c.len() <= 300
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        && c != "."
        && c != "..";
    if ok {
        Ok(c)
    } else {
        bail!("`{c}` is not a geo collection — `airdress geo collections` lists them")
    }
}

/// An item id: geo's are UUIDs.
fn valid_item(id: &str) -> Result<&str> {
    if uuid::Uuid::parse_str(id).is_ok() {
        Ok(id)
    } else {
        bail!("`{id}` is not an item id — `airdress geo items list` shows them")
    }
}

/// A link's revocation id, as one path segment.
fn valid_rid(rid: &str) -> Result<&str> {
    if !rid.is_empty()
        && rid.len() <= 256
        && rid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        Ok(rid)
    } else {
        bail!("`{rid}` is not a link id — `airdress geo share link list` shows them")
    }
}

fn valid_principal(p: &str) -> Result<&str> {
    if !p.trim().is_empty() && p.len() <= 128 && !p.chars().any(char::is_whitespace) {
        Ok(p)
    } else {
        bail!("`{p}` is not a principal id")
    }
}

/// `--precision`: a rung of geo's ladder by name, or metres.
fn precision_m(p: &str) -> Result<u32> {
    let named = match p.to_ascii_lowercase().replace(' ', "").as_str() {
        "exact" => Some(0),
        "100m" => Some(100),
        "1km" => Some(1_000),
        "approximate" => Some(2_300),
        "20km" => Some(20_000),
        "100km" => Some(100_000),
        _ => None,
    };
    if let Some(m) = named {
        return Ok(m);
    }
    p.parse::<u32>().map_err(|_| {
        anyhow::anyhow!(
            "`{p}` is not a precision — exact, 100m, 1km, approximate, 20km, 100km, or metres"
        )
    })
}

/// `--ttl`: `<n>h`, `<n>d`, `<n>w` or `<n>y`, as geo reads it.
fn valid_ttl(t: &str) -> Result<&str> {
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (n, unit) = t.split_at(split);
    if !n.is_empty() && n.parse::<u64>().is_ok() && matches!(unit, "h" | "d" | "w" | "y") {
        Ok(t)
    } else {
        bail!("`{t}` is not a lifetime — `<n>h`, `<n>d` or `<n>w`, e.g. 7d")
    }
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};
    use crate::redact::Redacted;

    const INSTALL: &str = "01JABCDEFGHJKMNPQRSTVWXYZ0";
    const ME: &str = "4b0c7c7e-0000-4000-8000-000000000001";
    const ITEM: &str = "0b6a1f0e-2c3d-4e5f-8a9b-0c1d2e3f4a5b";

    fn geo(base: String) -> GeoClient {
        GeoClient::with_base_url(base, Redacted::new("tok".to_owned())).unwrap()
    }

    fn ops(base: String) -> GrantsClient {
        GrantsClient::with_base_url(base, Redacted::new("tok".to_owned())).unwrap()
    }

    fn with_headers(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn body_of(request: &str) -> Value {
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap()
    }

    fn mine(name: &str) -> String {
        format!("{name}~{}", namespace_tag(&format!("person:{ME}")))
    }

    fn household(name: &str) -> String {
        format!("{name}~{}", namespace_tag(&format!("install:{INSTALL}")))
    }

    fn grant_json(id: &str, ns: &str, actions: &[&str]) -> String {
        json!({
            "id": id, "install": INSTALL, "type": "GeoCollection", "namespace": ns,
            "resource": "trips", "principal": "p2", "actions": actions,
            "granted_by": ME, "created_at": "2026-11-11T00:00:00Z"
        })
        .to_string()
    }

    #[test]
    fn the_tag_is_geos_derivation() {
        // Geo's `collection_id`: the first six bytes of SHA-256 over the
        // namespace, in hex.
        let t = namespace_tag("person:alice");
        assert_eq!(t.len(), 12);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(t, namespace_tag("person:bob"));
        assert_eq!(
            namespace_tag(""),
            "e3b0c44298fc",
            "SHA-256 of the empty string"
        );
    }

    #[test]
    fn local_checks_refuse_what_cannot_be_a_path_segment() {
        for ok in ["trips", "trips~3f9a2c1b0d4e", "my-plots_v2.2"] {
            assert!(valid_collection(ok).is_ok(), "{ok}");
        }
        for bad in ["", "..", "a/b", "a?b", "a b", "a%2f"] {
            assert!(valid_collection(bad).is_err(), "{bad}");
        }
        assert!(valid_item(ITEM).is_ok());
        assert!(valid_item("../x").is_err());
        assert!(valid_rid("r-1_x").is_ok());
        assert!(valid_rid("a/b").is_err());
        assert!(valid_principal("p2").is_ok());
        assert!(valid_principal(" ").is_err());
    }

    #[test]
    fn precision_and_lifetime_read_as_geo_does() {
        assert_eq!(precision_m("exact").unwrap(), 0);
        assert_eq!(precision_m("1 km").unwrap(), 1_000);
        assert_eq!(precision_m("Approximate").unwrap(), 2_300);
        assert_eq!(precision_m("500").unwrap(), 500);
        assert!(precision_m("fine").is_err());
        for ok in ["7d", "12h", "2w"] {
            assert!(valid_ttl(ok).is_ok(), "{ok}");
        }
        for bad in ["", "d", "7", "7m", "-1d"] {
            assert!(valid_ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_write_takes_one_feature() {
        assert!(parse_feature(r#"{"type":"Feature","geometry":null,"properties":{}}"#).is_ok());
        let err = parse_feature(r#"{"type":"FeatureCollection","features":[]}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("one GeoJSON Feature"), "{err}");
        assert!(parse_feature("nope").is_err());
    }

    #[test]
    fn the_next_page_is_its_cursor() {
        let v = json!({ "links": [
            { "rel": "self", "href": "https://geo.x/collections/c/items" },
            { "rel": "next", "href": "https://geo.x/collections/c/items?limit=2&cursor=ab%2Bc" }
        ]});
        assert_eq!(next_cursor(&v).as_deref(), Some("ab+c"));
        assert!(next_cursor(&json!({ "links": [] })).is_none());
    }

    #[tokio::test]
    async fn a_bare_name_resolves_to_the_one_readable_collection() {
        let list = json!({ "collections": [
            { "id": mine("trips") }, { "id": household("plots") }
        ]})
        .to_string();
        let (base, seen) = canned_operator(vec![response("200 OK", &list)]).await;
        assert_eq!(
            resolve_collection(&geo(base), "trips").await.unwrap(),
            mine("trips")
        );
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("GET /collections "));
        assert!(seen[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer tok"));
    }

    #[tokio::test]
    async fn an_ambiguous_name_is_refused_naming_both() {
        let list = json!({ "collections": [
            { "id": "trips~aaaaaaaaaaaa" }, { "id": "trips~bbbbbbbbbbbb" }
        ]})
        .to_string();
        let (base, _) = canned_operator(vec![response("200 OK", &list)]).await;
        let err = resolve_collection(&geo(base), "trips")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("trips~aaaaaaaaaaaa") && err.contains("trips~bbbbbbbbbbbb"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_full_id_is_used_without_asking() {
        // No canned response: a request would hang on accept.
        let (base, _) = canned_operator(vec![]).await;
        assert_eq!(
            resolve_collection(&geo(base), "trips~abc").await.unwrap(),
            "trips~abc"
        );
    }

    #[tokio::test]
    async fn items_round_trip_with_etags() {
        let feature = json!({ "type": "Feature", "geometry": { "type": "Point", "coordinates": [11.5, 48.1] }, "properties": { "bed": "north" } });
        let c = mine("trips");
        let (base, seen) = canned_operator(vec![
            with_headers(
                "201 Created",
                &format!(
                    "Location: https://geo.x/collections/{c}/items/{ITEM}\r\nETag: \"e1\"\r\n"
                ),
                "",
            ),
            with_headers(
                "200 OK",
                "ETag: \"e1\"\r\n",
                &json!({ "type": "Feature", "id": ITEM }).to_string(),
            ),
            with_headers("204 No Content", "ETag: \"e2\"\r\n", ""),
            response("204 No Content", ""),
        ])
        .await;
        let g = geo(base);
        let w = g.create(&c, &feature).await.unwrap();
        assert_eq!((w.id.as_str(), w.etag.as_deref()), (ITEM, Some("\"e1\"")));
        let (got, etag) = g.item(&c, ITEM).await.unwrap();
        assert_eq!(got["id"], ITEM);
        assert_eq!(etag.as_deref(), Some("\"e1\""));
        let w = g.replace(&c, ITEM, &feature, Some("\"e1\"")).await.unwrap();
        assert_eq!(w.etag.as_deref(), Some("\"e2\""));
        g.delete(&c, ITEM, None).await.unwrap();

        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with(&format!("POST /collections/{c}/items ")));
        assert!(seen[0]
            .to_ascii_lowercase()
            .contains("content-type: application/geo+json"));
        assert_eq!(body_of(&seen[0]), feature);
        assert!(seen[1].starts_with(&format!("GET /collections/{c}/items/{ITEM} ")));
        assert!(seen[2].starts_with(&format!("PUT /collections/{c}/items/{ITEM} ")));
        assert!(seen[2].to_ascii_lowercase().contains("if-match: \"e1\""));
        assert!(seen[3].starts_with(&format!("DELETE /collections/{c}/items/{ITEM} ")));
        assert!(!seen[3].to_ascii_lowercase().contains("if-match"));
    }

    #[tokio::test]
    async fn a_stale_etag_says_to_read_again() {
        let (base, _) = canned_operator(vec![response(
            "412 Precondition Failed",
            r#"{"type":"about:blank","title":"The item changed","status":412,"code":"precondition_failed"}"#,
        )])
        .await;
        let err = geo(base)
            .replace(
                "trips~abc",
                ITEM,
                &json!({ "type": "Feature" }),
                Some("\"old\""),
            )
            .await
            .unwrap_err();
        let f = crate::exit::classify(&err);
        assert_eq!(f.code, "precondition_failed");
        assert_eq!(f.status, Some(412));
        assert!(f.message.contains("read it again"), "{}", f.message);
    }

    #[tokio::test]
    async fn a_refusal_names_its_path() {
        let (base, _) = canned_operator(vec![response(
            "422 Unprocessable Entity",
            r#"{"type":"about:blank","title":"The geometry is not valid","status":422,"code":"geometry_invalid","path":"/geometry"}"#,
        )])
        .await;
        let err = geo(base)
            .create("trips~abc", &json!({ "type": "Feature" }))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("The geometry is not valid (geometry_invalid) at /geometry"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn items_list_sends_the_query_encoded() {
        let (base, seen) = canned_operator(vec![response(
            "200 OK",
            r#"{"type":"FeatureCollection","features":[]}"#,
        )])
        .await;
        let q = ItemQuery {
            limit: Some(5),
            filter: Some("bed = 'north'".into()),
            ..ItemQuery::default()
        };
        geo(base).items("trips~abc", &q).await.unwrap();
        let seen = seen.await.unwrap();
        assert!(
            seen[0].starts_with(
                "GET /collections/trips~abc/items?limit=5&filter=bed+%3D+%27north%27 "
            ),
            "{}",
            seen[0].lines().next().unwrap_or("")
        );
    }

    #[tokio::test]
    async fn a_personal_collection_is_shared_in_the_callers_namespace() {
        let c = mine("trips");
        let (g_base, g_seen) = canned_operator(vec![response(
            "200 OK",
            &json!({ "principal": ME, "personal": {} }).to_string(),
        )])
        .await;
        let (o_base, o_seen) = canned_operator(vec![
            response("200 OK", r#"{"grants":[]}"#),
            response(
                "201 Created",
                &grant_json(
                    "7a1d0000-0000-4000-8000-000000000001",
                    &format!("person:{ME}"),
                    &["ReadData"],
                ),
            ),
        ])
        .await;
        let clients = Clients {
            geo: geo(g_base),
            grants: ops(o_base),
        };
        let t = target(&clients, &c, Some(INSTALL)).await.unwrap();
        assert_eq!(t.namespace, format!("person:{ME}"));
        assert_eq!(t.name, "trips");
        let g = grant(&clients.grants, &t, "p2", &[DataAction::ReadData])
            .await
            .unwrap();
        assert_eq!(g.actions, ["ReadData"]);
        assert!(g_seen.await.unwrap()[0].starts_with("GET /me/usage "));
        let o = o_seen.await.unwrap();
        assert!(o[0].starts_with(&format!("GET /v1/plugin-grants?install={INSTALL} ")));
        assert!(o[1].starts_with("POST /v1/plugin-grants "));
        assert_eq!(
            body_of(&o[1]),
            json!({
                "install": INSTALL, "type": "GeoCollection", "namespace": format!("person:{ME}"),
                "resource": "trips", "principal": "p2", "actions": ["ReadData"]
            })
        );
    }

    #[tokio::test]
    async fn a_household_collection_is_known_by_its_tag_and_the_install_is_looked_up() {
        let c = household("plots");
        let installs = json!([{ "id": INSTALL, "airdress": "ada.a.airdr.es", "subdomain": "geo", "app_type": "geo" },
                              { "id": "01JABCDEFGHJKMNPQRSTVWXYZ1", "airdress": "ada.a.airdr.es", "subdomain": "forms", "app_type": "forms" }])
        .to_string();
        // Geo is not asked who the caller is: the tag says household.
        let (g_base, _) = canned_operator(vec![]).await;
        let (o_base, o_seen) = canned_operator(vec![response("200 OK", &installs)]).await;
        let clients = Clients {
            geo: geo(g_base),
            grants: ops(o_base),
        };
        let t = target(&clients, &c, None).await.unwrap();
        assert_eq!(t.install, INSTALL);
        assert_eq!(t.namespace, format!("install:{INSTALL}"));
        assert_eq!(t.name, "plots");
        assert!(o_seen.await.unwrap()[0].starts_with("GET /v1/plugins/installs "));
    }

    #[tokio::test]
    async fn someone_elses_collection_is_refused_before_any_grant() {
        let (g_base, _) = canned_operator(vec![response(
            "200 OK",
            &json!({ "principal": ME }).to_string(),
        )])
        .await;
        let (o_base, o_seen) = canned_operator(vec![]).await;
        let clients = Clients {
            geo: geo(g_base),
            grants: ops(o_base),
        };
        let err = target(&clients, "trips~aaaaaaaaaaaa", Some(INSTALL))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("someone else's collection"), "{err}");
        drop(clients);
        assert!(o_seen.await.unwrap().is_empty());
    }

    fn household_target() -> Target {
        Target {
            id: household("trips"),
            install: INSTALL.to_owned(),
            namespace: format!("install:{INSTALL}"),
            name: "trips".to_owned(),
        }
    }

    #[tokio::test]
    async fn granting_what_is_held_changes_nothing() {
        let ns = format!("install:{INSTALL}");
        let held = format!(
            r#"{{"grants":[{}]}}"#,
            grant_json(
                "7a1d0000-0000-4000-8000-000000000001",
                &ns,
                &["ReadData", "WriteData"]
            )
        );
        let (base, seen) = canned_operator(vec![response("200 OK", &held)]).await;
        let g = grant(
            &ops(base),
            &household_target(),
            "p2",
            &[DataAction::ReadData],
        )
        .await
        .unwrap();
        assert_eq!(g.actions, ["ReadData", "WriteData"]);
        assert_eq!(seen.await.unwrap().len(), 1, "only the read");
    }

    #[tokio::test]
    async fn widening_a_grant_replaces_it_with_the_union() {
        let ns = format!("install:{INSTALL}");
        let old = "7a1d0000-0000-4000-8000-000000000001";
        let held = format!(r#"{{"grants":[{}]}}"#, grant_json(old, &ns, &["ReadData"]));
        let (base, seen) = canned_operator(vec![
            response("200 OK", &held),
            response("204 No Content", ""),
            response(
                "201 Created",
                &grant_json(
                    "7a1d0000-0000-4000-8000-000000000002",
                    &ns,
                    &["ReadData", "WriteData"],
                ),
            ),
        ])
        .await;
        grant(
            &ops(base),
            &household_target(),
            "p2",
            &[DataAction::WriteData],
        )
        .await
        .unwrap();
        let seen = seen.await.unwrap();
        assert!(seen[1].starts_with(&format!("DELETE /v1/plugin-grants/{old} ")));
        assert_eq!(
            body_of(&seen[2])["actions"],
            json!(["ReadData", "WriteData"])
        );
    }

    #[tokio::test]
    async fn a_failed_replacement_says_access_is_gone() {
        let ns = format!("install:{INSTALL}");
        let held = format!(
            r#"{{"grants":[{}]}}"#,
            grant_json("7a1d0000-0000-4000-8000-000000000001", &ns, &["ReadData"])
        );
        let (base, _) = canned_operator(vec![
            response("200 OK", &held),
            response("204 No Content", ""),
            response(
                "503 Service Unavailable",
                r#"{"type":"about:blank","status":503,"code":"store_unavailable"}"#,
            ),
        ])
        .await;
        let err = grant(
            &ops(base),
            &household_target(),
            "p2",
            &[DataAction::WriteData],
        )
        .await
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("now has no access"), "{text}");
        assert!(text.contains("store_unavailable"), "{text}");
    }

    #[tokio::test]
    async fn revoking_one_action_keeps_the_other() {
        let ns = format!("install:{INSTALL}");
        let held = format!(
            r#"{{"grants":[{}]}}"#,
            grant_json(
                "7a1d0000-0000-4000-8000-000000000001",
                &ns,
                &["ReadData", "WriteData"]
            )
        );
        let (base, seen) = canned_operator(vec![
            response("200 OK", &held),
            response("204 No Content", ""),
            response(
                "201 Created",
                &grant_json("7a1d0000-0000-4000-8000-000000000002", &ns, &["ReadData"]),
            ),
        ])
        .await;
        let left = revoke(
            &ops(base),
            &household_target(),
            "p2",
            &[DataAction::WriteData],
        )
        .await
        .unwrap();
        assert_eq!(left.unwrap().actions, ["ReadData"]);
        assert_eq!(
            body_of(&seen.await.unwrap()[2])["actions"],
            json!(["ReadData"])
        );
    }

    #[tokio::test]
    async fn revoking_the_whole_grant_deletes_it_and_nothing_else() {
        let ns = format!("install:{INSTALL}");
        let id = "7a1d0000-0000-4000-8000-000000000001";
        let held = format!(
            r#"{{"grants":[{}]}}"#,
            grant_json(id, &ns, &["ReadData", "WriteData"])
        );
        let (base, seen) = canned_operator(vec![
            response("200 OK", &held),
            response("204 No Content", ""),
        ])
        .await;
        assert!(revoke(&ops(base), &household_target(), "p2", &[])
            .await
            .unwrap()
            .is_none());
        let seen = seen.await.unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].starts_with(&format!("DELETE /v1/plugin-grants/{id} ")));
    }

    #[tokio::test]
    async fn revoking_what_was_never_granted_says_so() {
        let (base, _) = canned_operator(vec![response("200 OK", r#"{"grants":[]}"#)]).await;
        let err = revoke(&ops(base), &household_target(), "p2", &[])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no grant") && err.contains("nothing was changed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_grant_refusal_is_said_in_words() {
        let (base, _) = canned_operator(vec![
            response("200 OK", r#"{"grants":[]}"#),
            response(
                "403 Forbidden",
                r#"{"type":"about:blank","status":403,"code":"not_governor"}"#,
            ),
        ])
        .await;
        let err = grant(
            &ops(base),
            &household_target(),
            "p2",
            &[DataAction::ReadData],
        )
        .await
        .unwrap_err();
        let f = crate::exit::classify(&err);
        assert_eq!(f.code, "not_governor");
        assert!(
            f.message
                .contains("only a collection's person may share it"),
            "{}",
            f.message
        );
    }

    #[test]
    fn several_geo_installs_ask_which() {
        let i = |id: &str, sub: &str| Install {
            id: id.into(),
            airdress: "ada".into(),
            subdomain: sub.into(),
            app_type: "geo".into(),
            runtime_state: None,
            last_request_age_seconds: None,
            db_access: None,
            version: None,
            source: None,
            signed_by: None,
            consent: None,
            author: None,
        };
        assert_eq!(geo_install(&[i("A", "geo")]).unwrap(), "A");
        let err = geo_install(&[i("A", "geo"), i("B", "maps")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("--install") && err.contains("B at maps"),
            "{err}"
        );
        assert!(geo_install(&[])
            .unwrap_err()
            .to_string()
            .contains("not installed"));
    }

    #[tokio::test]
    async fn a_link_is_minted_with_its_floor_and_listed_without_tokens() {
        let minted = r#"{"url":"https://geo.x/shared/biscuit:abc/","token":"biscuit:abc","rid":"r1","expiresAt":"2026-11-18T00:00:00Z","precisionM":1000,"precision":"1 km"}"#;
        let (base, seen) = canned_operator(vec![
            response("201 Created", minted),
            response("200 OK", r#"{"links":[{"rid":"r1","precisionM":1000,"precision":"1 km","expiresAt":"2026-11-18T00:00:00Z","state":"active"}]}"#),
            response("204 No Content", ""),
        ])
        .await;
        let g = geo(base);
        let v = g
            .link_create(
                "trips~abc",
                &MintBody {
                    precision_m: Some(precision_m("1km").unwrap()),
                    ttl: Some("7d".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(v["rid"], "r1");
        let listed = g.links("trips~abc").await.unwrap();
        assert!(render_links(listed["links"].as_array().unwrap()).contains("1 km"));
        g.link_revoke("trips~abc", "r1").await.unwrap();
        let seen = seen.await.unwrap();
        assert!(seen[0].starts_with("POST /collections/trips~abc/share-links "));
        assert_eq!(
            body_of(&seen[0]),
            json!({ "precisionM": 1000, "ttl": "7d" })
        );
        assert!(seen[1].starts_with("GET /collections/trips~abc/share-links "));
        assert!(seen[2].starts_with("DELETE /collections/trips~abc/share-links/r1 "));
    }

    #[test]
    fn usage_shows_each_scope_against_its_limit() {
        let v = json!({
            "principal": ME,
            "personal": { "usage": { "collections": 2, "items": 10, "bytes": 512, "observations": 0 },
                          "limits": { "collections": 32, "items": 1000000, "bytes": 1073741824, "observations": 10000000 } },
            "airdress": { "usage": { "collections": 1, "items": 3, "bytes": 64, "observations": 0 },
                          "limits": { "collections": 32, "items": 1000000, "bytes": 1073741824, "observations": 10000000 } }
        });
        let text = render_usage(&v);
        assert!(
            text.contains("yours:") && text.contains("household:"),
            "{text}"
        );
        assert!(text.contains("collections   2 of 32"), "{text}");
    }

    #[test]
    fn a_listing_shows_id_scope_and_storage() {
        let text = render_collections(&[json!({
            "id": "trips~3f9a2c1b0d4e", "title": "Trips", "scope": "personal",
            "storage": { "mode": "sealed", "atRest": "person-key" }
        })]);
        for want in ["trips~3f9a2c1b0d4e", "personal", "sealed", "Trips"] {
            assert!(text.contains(want), "{want}: {text}");
        }
    }
}

/// The verbs end to end over canned answers: what each sends, in what
/// order, and what it refuses before sending anything.
#[cfg(test)]
mod verb_tests {
    use super::*;
    use crate::functions::test_support::{canned_operator, response};
    use crate::redact::Redacted;

    const INSTALL: &str = "01JABCDEFGHJKMNPQRSTVWXYZ0";
    const ITEM: &str = "0b6a1f0e-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
    const GRANT: &str = "7a1d0000-0000-4000-8000-000000000001";

    fn bearer() -> Redacted<String> {
        Redacted::new("tok".to_owned())
    }

    fn household(name: &str) -> String {
        format!("{name}~{}", namespace_tag(&format!("install:{INSTALL}")))
    }

    fn with_headers(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn body_of(request: &str) -> Value {
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap()
    }

    fn first_line(request: &str) -> &str {
        request.lines().next().unwrap_or("")
    }

    async fn geo_with(responses: Vec<String>) -> (GeoClient, tokio::task::JoinHandle<Vec<String>>) {
        let (base, seen) = canned_operator(responses).await;
        (GeoClient::with_base_url(base, bearer()).unwrap(), seen)
    }

    /// Geo and the operator, each with its own canned answers.
    async fn clients_with(
        geo: Vec<String>,
        ops: Vec<String>,
    ) -> (
        Clients,
        tokio::task::JoinHandle<Vec<String>>,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let (g, g_seen) = canned_operator(geo).await;
        let (o, o_seen) = canned_operator(ops).await;
        (
            Clients {
                geo: GeoClient::with_base_url(g, bearer()).unwrap(),
                grants: GrantsClient::with_base_url(o, bearer()).unwrap(),
            },
            g_seen,
            o_seen,
        )
    }

    fn grant_json(actions: &[&str]) -> String {
        json!({
            "id": GRANT, "install": INSTALL, "type": "GeoCollection",
            "namespace": format!("install:{INSTALL}"), "resource": "plots",
            "principal": "p2", "actions": actions, "created_at": "2026-11-11T00:00:00Z"
        })
        .to_string()
    }

    fn grants_json(actions: &[&str]) -> String {
        format!(r#"{{"grants":[{}]}}"#, grant_json(actions))
    }

    const COLLECTION: &str = r#"{"id":"plots~aaaaaaaaaaaa","title":"Plots","scope":"airdress","storage":{"mode":"queryable","atRest":"plain"},"description":"The allotment","extent":{"spatial":{"bbox":[[11.0,48.0,12.0,49.0]],"crs":"x"}}}"#;

    // --- collections and usage ------------------------------------------

    #[tokio::test]
    async fn collections_list_and_show_in_both_formats() {
        let list = format!(r#"{{"collections":[{COLLECTION}]}}"#);
        for json in [false, true] {
            let (c, g_seen, _) = clients_with(
                vec![
                    response("200 OK", &list),
                    response("200 OK", &list),
                    response("200 OK", COLLECTION),
                ],
                vec![],
            )
            .await;
            dispatch(&c, GeoCommands::Collections { command: None }, json)
                .await
                .unwrap();
            dispatch(
                &c,
                GeoCommands::Collections {
                    command: Some(CollectionsCommands::Show {
                        collection: "plots".into(),
                    }),
                },
                json,
            )
            .await
            .unwrap();
            let seen = g_seen.await.unwrap();
            assert!(first_line(&seen[2]).starts_with("GET /collections/plots~aaaaaaaaaaaa "));
        }
    }

    #[tokio::test]
    async fn an_empty_listing_is_said_not_failed() {
        let (geo, _) = geo_with(vec![response("200 OK", r#"{"collections":[]}"#)]).await;
        collections_list(&geo, false).await.unwrap();
    }

    #[test]
    fn a_collection_shows_its_description_and_rounded_extent() {
        let text = render_collection(&serde_json::from_str(COLLECTION).unwrap());
        for want in [
            "collection plots~aaaaaaaaaaaa",
            "queryable (plain)",
            "The allotment",
            "11.0, 48.0, 12.0, 49.0",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        let bare = render_collection(&json!({ "id": "x~1" }));
        assert!(
            bare.contains("title:    -") && !bare.contains("extent"),
            "{bare}"
        );
    }

    #[tokio::test]
    async fn usage_in_both_formats() {
        let usage = r#"{"principal":"me","personal":{"usage":{"items":1},"limits":{"items":2}}}"#;
        for json in [false, true] {
            let (c, g_seen, _) = clients_with(vec![response("200 OK", usage)], vec![]).await;
            dispatch(&c, GeoCommands::Usage, json).await.unwrap();
            assert!(first_line(&g_seen.await.unwrap()[0]).starts_with("GET /me/usage "));
        }
        let text = render_usage(&serde_json::from_str(usage).unwrap());
        assert!(
            text.contains("items         1 of 2") && !text.contains("household"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn no_readable_collection_by_that_name_says_where_to_look() {
        let (geo, _) = geo_with(vec![response(
            "200 OK",
            r#"{"collections":[{"id":"trips~a"}]}"#,
        )])
        .await;
        let err = resolve_collection(&geo, "plots")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no geo collection named `plots`"), "{err}");
    }

    // --- items ----------------------------------------------------------

    #[tokio::test]
    async fn items_list_prints_a_table_and_the_next_cursor() {
        let page = json!({
            "type": "FeatureCollection",
            "features": [
                { "type": "Feature", "id": ITEM, "geometry": { "type": "Point" }, "properties": { "note": "x".repeat(80) } },
                { "type": "Feature", "id": 7, "geometry": null }
            ],
            "links": [{ "rel": "next", "href": "https://geo.x/collections/c/items?cursor=n1" }]
        })
        .to_string();
        for json in [false, true] {
            let (geo, seen) = geo_with(vec![response("200 OK", &page)]).await;
            items(
                &geo,
                ItemsCommands::List {
                    collection: "plots~a".into(),
                    limit: Some(2),
                    bbox: None,
                    datetime: Some("2026-01-01T00:00:00Z/..".into()),
                    filter: None,
                    cursor: Some("n0".into()),
                },
                json,
            )
            .await
            .unwrap();
            let line = first_line(&seen.await.unwrap()[0]).to_owned();
            assert!(
                line.contains("limit=2")
                    && line.contains("cursor=n0")
                    && line.contains("datetime="),
                "{line}"
            );
        }
        let v: Value = serde_json::from_str(&page).unwrap();
        let text = render_items(v["features"].as_array().unwrap());
        assert!(
            text.contains(ITEM) && text.contains("Point") && text.contains('…'),
            "{text}"
        );
        assert!(
            text.contains("\n7 "),
            "a numeric id is shown as written: {text}"
        );
    }

    #[tokio::test]
    async fn an_empty_page_is_said() {
        let (geo, _) = geo_with(vec![response("200 OK", r#"{"features":[]}"#)]).await;
        items(
            &geo,
            ItemsCommands::List {
                collection: "plots~a".into(),
                limit: None,
                bbox: None,
                datetime: None,
                filter: None,
                cursor: None,
            },
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn items_get_in_both_formats() {
        let feature = json!({ "type": "Feature", "id": ITEM }).to_string();
        for json in [false, true] {
            let (geo, seen) =
                geo_with(vec![with_headers("200 OK", "ETag: \"e1\"\r\n", &feature)]).await;
            items(
                &geo,
                ItemsCommands::Get {
                    collection: "plots~a".into(),
                    id: ITEM.into(),
                },
                json,
            )
            .await
            .unwrap();
            assert!(first_line(&seen.await.unwrap()[0])
                .starts_with(&format!("GET /collections/plots~a/items/{ITEM} ")));
        }
    }

    fn feature_file() -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"{"type":"Feature","geometry":{"type":"Point","coordinates":[11.5,48.1]},"properties":{}}"#,
        )
        .unwrap();
        f
    }

    #[tokio::test]
    async fn put_without_an_id_posts_and_reads_the_new_id_from_location() {
        let f = feature_file();
        for json in [false, true] {
            let (geo, seen) = geo_with(vec![with_headers(
                "201 Created",
                &format!(
                    "Location: https://geo.x/collections/plots~a/items/{ITEM}\r\nETag: \"e1\"\r\n"
                ),
                "",
            )])
            .await;
            items(
                &geo,
                ItemsCommands::Put {
                    collection: "plots~a".into(),
                    id: None,
                    file: f.path().display().to_string(),
                    if_match: None,
                },
                json,
            )
            .await
            .unwrap();
            let seen = seen.await.unwrap();
            assert!(first_line(&seen[0]).starts_with("POST /collections/plots~a/items "));
            assert_eq!(body_of(&seen[0])["type"], "Feature");
        }
    }

    #[tokio::test]
    async fn a_create_with_no_location_is_an_error_not_a_guess() {
        let (geo, _) = geo_with(vec![response("201 Created", "")]).await;
        let err = geo
            .create("plots~a", &json!({ "type": "Feature" }))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not say its id"), "{err}");
    }

    #[tokio::test]
    async fn put_with_an_id_replaces_under_if_match() {
        let f = feature_file();
        for json in [false, true] {
            let (geo, seen) =
                geo_with(vec![with_headers("204 No Content", "ETag: \"e2\"\r\n", "")]).await;
            items(
                &geo,
                ItemsCommands::Put {
                    collection: "plots~a".into(),
                    id: Some(ITEM.into()),
                    file: f.path().display().to_string(),
                    if_match: Some("\"e1\"".into()),
                },
                json,
            )
            .await
            .unwrap();
            let req = &seen.await.unwrap()[0];
            assert!(first_line(req).starts_with(&format!("PUT /collections/plots~a/items/{ITEM} ")));
            assert!(req.to_ascii_lowercase().contains("if-match: \"e1\""));
        }
    }

    #[tokio::test]
    async fn if_match_on_a_create_is_refused_before_sending() {
        let f = feature_file();
        let (geo, seen) = geo_with(vec![]).await;
        let err = items(
            &geo,
            ItemsCommands::Put {
                collection: "plots~a".into(),
                id: None,
                file: f.path().display().to_string(),
                if_match: Some("\"e1\"".into()),
            },
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("--if-match guards a replace"), "{err}");
        assert!(seen.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn put_of_a_missing_file_says_which() {
        let (geo, _) = geo_with(vec![]).await;
        let err = items(
            &geo,
            ItemsCommands::Put {
                collection: "plots~a".into(),
                id: None,
                file: "/nonexistent/plot.geojson".into(),
                if_match: None,
            },
            false,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("/nonexistent/plot.geojson"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn delete_with_yes_sends_if_match_in_both_formats() {
        for json in [false, true] {
            let (geo, seen) = geo_with(vec![response("204 No Content", "")]).await;
            items(
                &geo,
                ItemsCommands::Delete {
                    collection: "plots~a".into(),
                    id: ITEM.into(),
                    if_match: Some("\"e1\"".into()),
                    yes: true,
                },
                json,
            )
            .await
            .unwrap();
            let req = &seen.await.unwrap()[0];
            assert!(
                first_line(req).starts_with(&format!("DELETE /collections/plots~a/items/{ITEM} "))
            );
            assert!(req.to_ascii_lowercase().contains("if-match: \"e1\""));
        }
    }

    #[tokio::test]
    async fn delete_without_yes_asks_and_sends_nothing() {
        // Test stdin is not a terminal, so the confirmation is required.
        let (geo, seen) = geo_with(vec![]).await;
        let err = items(
            &geo,
            ItemsCommands::Delete {
                collection: "plots~a".into(),
                id: ITEM.into(),
                if_match: None,
                yes: false,
            },
            false,
        )
        .await
        .unwrap_err();
        let f = crate::exit::classify(&err);
        assert_eq!(f.exit, crate::exit::Exit::ConfirmationRequired);
        assert!(f.hint.unwrap_or_default().contains("--yes"));
        assert!(seen.await.unwrap().is_empty());
    }

    // --- grants ---------------------------------------------------------

    #[tokio::test]
    async fn share_grant_in_both_formats() {
        for json in [false, true] {
            let (c, _, o_seen) = clients_with(
                vec![],
                vec![
                    response("200 OK", r#"{"grants":[]}"#),
                    response("201 Created", &grant_json(&["ReadData"])),
                ],
            )
            .await;
            share(
                &c,
                ShareCommands::Grant {
                    collection: household("plots"),
                    to: "p2".into(),
                    actions: vec![DataAction::ReadData, DataAction::ReadData],
                    install: Some(INSTALL.into()),
                },
                json,
            )
            .await
            .unwrap();
            let seen = o_seen.await.unwrap();
            assert_eq!(
                body_of(&seen[1])["actions"],
                json!(["ReadData"]),
                "deduplicated"
            );
            assert_eq!(body_of(&seen[1])["namespace"], format!("install:{INSTALL}"));
        }
    }

    #[tokio::test]
    async fn share_revoke_of_all_in_both_formats() {
        for json in [false, true] {
            let (c, _, o_seen) = clients_with(
                vec![],
                vec![
                    response("200 OK", &grants_json(&["ReadData"])),
                    response("204 No Content", ""),
                ],
            )
            .await;
            share(
                &c,
                ShareCommands::Revoke {
                    collection: household("plots"),
                    to: "p2".into(),
                    actions: vec![],
                    install: Some(INSTALL.into()),
                },
                json,
            )
            .await
            .unwrap();
            assert!(first_line(&o_seen.await.unwrap()[1])
                .starts_with(&format!("DELETE /v1/plugin-grants/{GRANT} ")));
        }
    }

    #[tokio::test]
    async fn share_revoke_of_one_action_reports_what_stays() {
        for json in [false, true] {
            let (c, _, o_seen) = clients_with(
                vec![],
                vec![
                    response("200 OK", &grants_json(&["ReadData", "WriteData"])),
                    response("204 No Content", ""),
                    response("201 Created", &grant_json(&["WriteData"])),
                ],
            )
            .await;
            share(
                &c,
                ShareCommands::Revoke {
                    collection: household("plots"),
                    to: "p2".into(),
                    actions: vec![DataAction::ReadData],
                    install: Some(INSTALL.into()),
                },
                json,
            )
            .await
            .unwrap();
            assert_eq!(
                body_of(&o_seen.await.unwrap()[2])["actions"],
                json!(["WriteData"])
            );
        }
    }

    #[tokio::test]
    async fn revoking_an_action_not_held_changes_nothing() {
        let (c, _, o_seen) = clients_with(
            vec![],
            vec![response("200 OK", &grants_json(&["ReadData"]))],
        )
        .await;
        let t = Target {
            id: household("plots"),
            install: INSTALL.into(),
            namespace: format!("install:{INSTALL}"),
            name: "plots".into(),
        };
        let left = revoke(&c.grants, &t, "p2", &[DataAction::WriteData])
            .await
            .unwrap();
        assert_eq!(left.unwrap().actions, ["ReadData"]);
        assert_eq!(o_seen.await.unwrap().len(), 1, "only the read");
    }

    #[tokio::test]
    async fn share_list_in_every_shape() {
        for (json, body) in [
            (false, grants_json(&["ReadData", "WriteData"])),
            (false, r#"{"grants":[]}"#.to_owned()),
            (true, grants_json(&["ReadData"])),
        ] {
            let (c, _, o_seen) = clients_with(vec![], vec![response("200 OK", &body)]).await;
            share(
                &c,
                ShareCommands::List {
                    collection: household("plots"),
                    install: Some(INSTALL.into()),
                },
                json,
            )
            .await
            .unwrap();
            assert!(first_line(&o_seen.await.unwrap()[0])
                .starts_with(&format!("GET /v1/plugin-grants?install={INSTALL} ")));
        }
    }

    #[test]
    fn grants_render_with_who_what_and_since() {
        let g: Grant = serde_json::from_str(&grant_json(&["ReadData"])).unwrap();
        let text = render_grants(&[g]);
        for want in ["p2", "ReadData", GRANT, "2026-11-11"] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert_eq!(
            describe_actions(&["ReadData".into(), "WriteData".into()]),
            "read and write"
        );
        assert_eq!(
            describe_actions(&["WriteData".into()]),
            "write (without reading)"
        );
        assert_eq!(describe_actions(&["Locate".into()]), "Locate");
    }

    #[tokio::test]
    async fn the_owner_finds_the_install_and_anyone_else_is_told_to_pass_it() {
        let (c, _, _) = clients_with(
            vec![],
            vec![response(
                "403 Forbidden",
                r#"{"type":"about:blank","status":403,"code":"owner_only"}"#,
            )],
        )
        .await;
        let err = target(&c, &household("plots"), None).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--install <id>"), "{text}");
    }

    #[tokio::test]
    async fn geo_without_a_principal_is_an_error() {
        let (c, _, _) = clients_with(vec![response("200 OK", "{}")], vec![]).await;
        let err = target(&c, "trips~aaaaaaaaaaaa", Some(INSTALL))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not say who you are"), "{err}");
    }

    // --- links ----------------------------------------------------------

    const MINTED: &str = r#"{"url":"https://geo.x/shared/biscuit:abc/","token":"biscuit:abc","rid":"r1","expiresAt":"2026-11-18T00:00:00Z","precisionM":0,"precision":"exact"}"#;

    #[tokio::test]
    async fn link_create_list_and_revoke_in_both_formats() {
        let listed = r#"{"links":[{"rid":"r1","precisionM":0,"precision":"exact","expiresAt":"2026-11-18T00:00:00Z","state":"active"}]}"#;
        for json in [false, true] {
            let (geo, seen) = geo_with(vec![
                response("201 Created", MINTED),
                response("200 OK", listed),
                response("200 OK", r#"{"links":[]}"#),
                response("204 No Content", ""),
            ])
            .await;
            links(
                &geo,
                LinkCommands::Create {
                    collection: "plots~a".into(),
                    precision: Some("exact".into()),
                    ttl: None,
                },
                json,
            )
            .await
            .unwrap();
            for _ in 0..2 {
                links(
                    &geo,
                    LinkCommands::List {
                        collection: "plots~a".into(),
                    },
                    json,
                )
                .await
                .unwrap();
            }
            links(
                &geo,
                LinkCommands::Revoke {
                    collection: "plots~a".into(),
                    rid: "r1".into(),
                },
                json,
            )
            .await
            .unwrap();
            let seen = seen.await.unwrap();
            assert_eq!(body_of(&seen[0]), json!({ "precisionM": 0 }));
            assert!(first_line(&seen[3]).starts_with("DELETE /collections/plots~a/share-links/r1 "));
        }
    }

    #[tokio::test]
    async fn a_mint_without_a_url_is_an_error() {
        let (geo, _) = geo_with(vec![response("201 Created", r#"{"rid":"r1"}"#)]).await;
        let err = links(
            &geo,
            LinkCommands::Create {
                collection: "plots~a".into(),
                precision: None,
                ttl: None,
            },
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("sent no url"), "{err}");
    }

    #[tokio::test]
    async fn links_off_is_said_in_words() {
        let (geo, _) = geo_with(vec![response(
            "403 Forbidden",
            r#"{"type":"about:blank","title":"Sharing is off","status":403,"code":"share_link_disabled"}"#,
        )])
        .await;
        let err = geo
            .link_create("plots~a", &MintBody::default())
            .await
            .unwrap_err();
        let f = crate::exit::classify(&err);
        assert_eq!(f.code, "share_link_disabled");
        assert!(f.message.contains("share links are off"), "{}", f.message);
    }

    // --- refusals -------------------------------------------------------

    #[tokio::test]
    async fn refusals_in_each_shape_geo_and_the_operator_answer() {
        let cases: &[(&str, &str, &str)] = &[
            // problem+json with a code we have no sentence for: its title.
            (
                "409 Conflict",
                r#"{"type":"about:blank","title":"Something odd","status":409,"code":"odd_thing"}"#,
                "Something odd (odd_thing)",
            ),
            // a code with neither sentence nor title.
            (
                "409 Conflict",
                r#"{"status":409,"code":"odd_thing"}"#,
                "read usage: odd_thing",
            ),
            // the operator's nested fallback.
            (
                "404 Not Found",
                r#"{"error":{"code":"route_not_found","message":"No such route."}}"#,
                "is geo installed?",
            ),
            // the operator's flat shape.
            (
                "409 Conflict",
                r#"{"error":"grant_exists"}"#,
                "already exists",
            ),
            // no code at all: the generic status sentence.
            ("502 Bad Gateway", "upstream died", "server error"),
            ("401 Unauthorized", "", "airdress auth login"),
        ];
        for (status, body, want) in cases {
            let (geo, _) = geo_with(vec![response(status, body)]).await;
            let err = geo.usage().await.unwrap_err().to_string();
            assert!(err.contains(want), "{status} {body}: {err}");
        }
    }

    #[tokio::test]
    async fn a_malformed_grant_id_is_refused_before_sending() {
        let (c, _, o_seen) = clients_with(vec![], vec![]).await;
        assert!(c.grants.revoke("../x").await.is_err());
        assert!(c.grants.revoke("").await.is_err());
        drop(c);
        assert!(o_seen.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_geo_is_a_transport_error_naming_it() {
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let geo = GeoClient::with_base_url(base.clone(), bearer()).unwrap();
        let err = format!("{:#}", geo.collections().await.unwrap_err());
        assert!(err.contains("127.0.0.1"), "{err}");
    }

    // --- local checks ---------------------------------------------------

    #[test]
    fn every_verb_is_checked_before_connecting() {
        let ok: Vec<GeoCommands> = vec![
            GeoCommands::Usage,
            GeoCommands::Collections { command: None },
            GeoCommands::Collections {
                command: Some(CollectionsCommands::Show {
                    collection: "plots".into(),
                }),
            },
            GeoCommands::Items {
                command: ItemsCommands::List {
                    collection: "plots".into(),
                    limit: None,
                    bbox: None,
                    datetime: None,
                    filter: None,
                    cursor: None,
                },
            },
            GeoCommands::Items {
                command: ItemsCommands::Put {
                    collection: "plots".into(),
                    id: Some(ITEM.into()),
                    file: "-".into(),
                    if_match: None,
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Grant {
                    collection: "plots".into(),
                    to: "p2".into(),
                    actions: vec![DataAction::WriteData],
                    install: Some(INSTALL.into()),
                },
            },
            GeoCommands::Share {
                command: ShareCommands::List {
                    collection: "plots".into(),
                    install: None,
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::Create {
                        collection: "plots".into(),
                        precision: Some("20km".into()),
                        ttl: Some("1w".into()),
                    },
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::List {
                        collection: "plots".into(),
                    },
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::Revoke {
                        collection: "plots".into(),
                        rid: "r1".into(),
                    },
                },
            },
        ];
        for c in &ok {
            assert!(check_locally(c).is_ok(), "{c:?}");
        }
        let bad: Vec<GeoCommands> = vec![
            GeoCommands::Collections {
                command: Some(CollectionsCommands::Show {
                    collection: "a/b".into(),
                }),
            },
            GeoCommands::Items {
                command: ItemsCommands::Get {
                    collection: "plots".into(),
                    id: "not-a-uuid".into(),
                },
            },
            GeoCommands::Items {
                command: ItemsCommands::Delete {
                    collection: "plots".into(),
                    id: "x".into(),
                    if_match: None,
                    yes: true,
                },
            },
            GeoCommands::Items {
                command: ItemsCommands::Put {
                    collection: "plots".into(),
                    id: Some("x".into()),
                    file: "-".into(),
                    if_match: None,
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Revoke {
                    collection: "plots".into(),
                    to: "a b".into(),
                    actions: vec![],
                    install: None,
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Grant {
                    collection: "plots".into(),
                    to: "p2".into(),
                    actions: vec![DataAction::ReadData],
                    install: Some("../x".into()),
                },
            },
            GeoCommands::Share {
                command: ShareCommands::List {
                    collection: "plots".into(),
                    install: Some("a/b".into()),
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::Create {
                        collection: "plots".into(),
                        precision: Some("fine".into()),
                        ttl: None,
                    },
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::Create {
                        collection: "plots".into(),
                        precision: None,
                        ttl: Some("soon".into()),
                    },
                },
            },
            GeoCommands::Share {
                command: ShareCommands::Link {
                    command: LinkCommands::Revoke {
                        collection: "plots".into(),
                        rid: "a/b".into(),
                    },
                },
            },
        ];
        for c in &bad {
            assert!(check_locally(c).is_err(), "{c:?}");
        }
        assert_eq!(DataAction::WriteData.as_str(), "WriteData");
    }
}
