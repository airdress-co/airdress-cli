build:
    cargo build --release

test:
    cargo test --workspace

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

lint: fmt-check clippy

check:
    prek run --all-files

install:
    cargo install --path .

clean:
    cargo clean

hooks-install:
    prek install
    git config core.hooksPath .githooks

hooks-update:
    prek autoupdate

# Build and publish an existing tag by hand. Normally release-plz does this:
# merging its release pull request tags main and dispatches release.yml.
release tag:
    gh workflow run release.yml -f tag={{tag}}

# Preview the next release locally: the version and CHANGELOG.md entry the
# release pull request would carry. Edits the working tree; `git checkout .`
# undoes it.
release-preview:
    release-plz update

# Commit the staged change as airdress-bot, signed by GitHub, through the Git
# Data API (airdress-ops' scripts/bot-commit.sh). The local commit is a draft
# the bot re-creates, which is the choice `AIRDRESS_COMMIT_AS=bot` records.
bot-commit message:
    AIRDRESS_COMMIT_AS=bot "${AIRDRESS_OPS:-../airdress-ops}/scripts/bot-commit.sh" {{ quote(message) }}

# Serve the tool catalogue over stdio, as an editor would start it.
mcp-serve *args:
    cargo run --quiet -- mcp serve {{args}}

# Print the tool catalogue, including the tools this build does not yet offer.
mcp-catalogue:
    cargo run --quiet -- mcp catalogue

# Prove the MCP server reaches nothing but the hosts it was given.
# Falls back to sudo where unprivileged user namespaces are refused.
mcp-egress-test:
    ./scripts/egress-allowlist-test.sh

# Licences, advisories, the telemetry bans, and the source allowlist.
deny:
    cargo deny check licenses advisories bans sources

# Regenerate the third-party licence list from the lockfile.
third-party:
    ./scripts/third-party.sh

# Document numbers stay out of code.
doc-numbers:
    ./scripts/check-doc-numbers.sh
