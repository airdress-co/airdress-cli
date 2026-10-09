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

release tag:
    gh workflow run release.yml -f tag={{tag}}

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
