# Contributing

Thank you for looking. This is a working tool for a small product, so the
bar is practical: a change should be something somebody can read in a year
and understand why it is there.

## Building

The CLI is a Rust workspace. `rust-toolchain.toml` pins the toolchain;
`cargo build` and `cargo test` do the usual. The `mls` feature builds the
agent-device commands and is off by default.

```sh
just build    # cargo build --release
just test     # cargo test --workspace
just lint     # cargo fmt --check + cargo clippy -- -D warnings
just check    # every pre-commit hook, over everything
just hooks-install
```

CI runs the same things, plus `cargo deny check` and the egress test.

## Writing for people who use it

The README and `docs/` are the product's public face. Write them the way
the rest is written: concrete, short, in the present tense, about what the
command does for the person running it. "Airdress" with a capital A is the
product; "your airdress" is the address a person owns. Document numbers
and internal names stay out, and a hook enforces the second.

A change in behaviour comes with the doc that describes it, in the same
pull request. Check a command example against `--help` before committing
it.

## House rules that are not obvious

- **Nothing writes to stdout in the MCP server.** stdout is the protocol.
  Human-facing lines go to stderr; a `println!` in `src/mcp/` or
  `crates/airdress-mcp/` is a bug the protocol cannot recover from.
- **Secrets live in `Redacted<T>`.** If you need the bytes, call
  `.expose()` at the point of use, never into a format string, a log line
  or an error.
- **No telemetry.** No analytics, no crash reporting, no tracing exporter,
  in this crate or any dependency. `deny.toml` lists the bans and CI
  enforces them. If you have a good reason to want one, open an issue
  first; the answer will probably still be no.
- **A new test file must be named in CI** in the same change, or it is a
  file that never runs.
- **Document numbers belong in comments**, never in an identifier, a
  route, a config key, a test name, a file name or a help string.
  `scripts/check-doc-numbers.sh` enforces it.
- **A discarded `Result` says why.** `.log_warn("…")` or
  `.log_debug("…")`, never `let _ =`.
- **Commits are attributed to people, or to our bot.** No
  `Co-Authored-By` trailer naming Claude or Anthropic, no
  `@anthropic.com` address in a message, and no author or committer
  named Claude or at anthropic.com.
  `scripts/check-commit-attribution.py` refuses them at `commit-msg`
  (installed by `just hooks-install`, through `.githooks/commit-msg`)
  and CI runs it over every pushed commit. Its fixtures are in
  `scripts/check-commit-attribution-test.sh`.

## Commit messages

Every commit is a [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/),
because the history is what decides the next version:

```text
<type>[(<scope>)][!]: <subject>

<body: what changed and why>

[BREAKING CHANGE: <what breaks, and what to do about it>]
```

- **type** is one of `feat`, `fix`, `docs`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- **scope** is free: the area the change is in, e.g. `feat(shell): ...`,
  `fix(mcp): ...`, `build(release): ...`.
- **subject** is imperative and short; the header is at most 100
  characters. Document numbers stay out of the subject; the body may cite
  them.
- **breaking**: `!` before the colon, or a `BREAKING CHANGE:` footer.

`scripts/check-conventional-commit.py` refuses anything else at
`commit-msg`, and CI runs it over every pushed commit (fixtures:
`scripts/check-conventional-commit-test.sh`). `fixup!` and `squash!`
commits pass the hook, and CI refuses them, so fold them in with
`git rebase --autosquash` before a pull request lands.

## Who commits

A commit made under the owner's own git identity (listed in
`scripts/owner-identities.txt`) is refused unless the person or the agent
committing chose, for that commit, who commits it:

```sh
# The owner commits it. The hook adds a `Committed-As: owner` trailer.
AIRDRESS_COMMIT_AS=owner git commit

# The bot commits it: airdress-bot re-creates the staged change through the
# Git Data API, signed by GitHub.
just bot-commit "fix(shell): say why the host refused"
```

Set the variable for one command, never in a shell profile: it is the
record of a decision about one commit. CI checks pushed commits the same
way: under the owner's identity only with the `Committed-As: owner`
trailer; the bot's commits always pass. Other identities need no choice,
and naming `owner` for one of them is refused.

## Releases

[release-plz](https://release-plz.dev/) reads the conventional commits on
`main` and keeps a release pull request open with the next version and its
`CHANGELOG.md` entry. In `0.x`, a `fix` or a `feat` bumps the patch and a
breaking change bumps the minor. Every crate carries the one product version
(`release-plz.toml`). Merging the release pull request tags `v<version>`,
and the release-plz workflow hands that tag to `release.yml`, which builds
every target twice, compares the builds byte for byte and publishes.
Nothing is published to crates.io.

`just release-preview` shows locally what the next release pull request
would carry.

## A new tool in the MCP catalogue

Add it to `crates/airdress-mcp-catalogue` first: the name, the schema and
the annotations. That crate is what the server side reads to offer the same
tools remotely, so a tool defined in only one of the two halves is how they
drift. Then implement it in `src/mcp/tools.rs`, and drive it in
`crates/airdress-mcp/tests/server_session.rs`; that test is what proves the
tool carries no credential.

## Pull requests

Branch, commit, push the branch and open a pull request against `main`.
The pre-push hook blocks a direct push to `main`.
