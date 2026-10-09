# Contributing

Thank you for looking. This is a working tool for a small product, so
the bar is practical: a change should be something somebody can read in
a year and understand why it is there.

## Before a pull request

```sh
just lint     # cargo fmt --check + cargo clippy -- -D warnings
just test     # cargo test --workspace
just check    # the pre-commit hooks, over everything
just hooks-install
```

CI runs the same things, plus `cargo deny check` and the egress test.

## House rules that are not obvious

- **Nothing writes to stdout in the MCP server.** stdout is the
  protocol. Human-facing lines go to stderr; `println!` in
  `src/mcp/` or `crates/airdress-mcp/` is a bug the protocol cannot
  recover from.
- **Secrets live in `Redacted<T>`.** If you need the bytes, call
  `.expose()` at the point of use — never into a format string, a log
  line or an error.
- **No telemetry.** No analytics, no crash reporting, no tracing
  exporter, in this crate or any dependency. `deny.toml` lists the bans
  and CI enforces them. If you have a good reason to want one, open an
  issue first; the answer will probably still be no.
- **A new test file must be named in CI** in the same change, or it is
  a file that never runs.
- **Document numbers belong in comments**, never in an identifier, a
  route, a config key, a test name or a file name. `scripts/check-doc-numbers.sh`
  enforces it.
- Commit messages: imperative subject, say what changed and why.
- **Commits are attributed to people, or to our bot.** No
  `Co-Authored-By` trailer naming Claude or Anthropic, no
  `@anthropic.com` address in a message, and no author or committer
  named Claude or at anthropic.com.
  `scripts/check-commit-attribution.py` refuses them at `commit-msg`
  (installed by `just hooks-install`, through `.githooks/commit-msg`)
  and CI runs it over every pushed commit. Its fixtures are in
  `scripts/check-commit-attribution-test.sh`.

## A new tool in the MCP catalogue

Add it to `crates/airdress-mcp-catalogue` first: the name, the schema
and the annotations. That crate is also what the operator reads to serve
the same tools remotely, so a tool defined in only one of the two halves
is how they drift. Then implement it in `src/mcp/tools.rs`, and drive it
in `crates/airdress-mcp/tests/server_session.rs` — that test is what
proves the tool carries no credential.
