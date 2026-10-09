//! `airdress diff -f <file>` — server-side dry-run apply. Delegates
//! to [`super::apply::run`] with `dry_run = true`.

use std::path::Path;

use anyhow::Result;

use super::apply::{self, ApplyArgs};

#[derive(Debug)]
pub struct DiffArgs<'a> {
    pub profile: Option<&'a str>,
    /// Where the CLI's files are (resolved once, in `main`).
    pub paths: &'a crate::paths::Paths,
    pub explicit_airdress: Option<&'a str>,
    pub json: bool,
    pub quiet: bool,
    pub file: &'a Path,
    pub operator_url: Option<&'a str>,
}

pub async fn run(args: DiffArgs<'_>) -> Result<()> {
    apply::run(ApplyArgs {
        paths: args.paths,
        profile: args.profile,
        explicit_airdress: args.explicit_airdress,
        json: args.json,
        quiet: args.quiet,
        file: args.file,
        dry_run: true,
        operator_url: args.operator_url,
        machine_key: None,
    })
    .await
}
