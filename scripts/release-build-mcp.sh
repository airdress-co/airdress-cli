#!/usr/bin/env bash
# Build `airdress-mcp` for one Linux target exactly as the editor plugin
# does (airdress-claude-code, .github/workflows/server-build.yml), so the
# digest a release prints is the one the plugin pins: static musl, inside a
# digest-pinned image whose C compiler builds aws-lc-sys, from a copy of the
# source at a fixed path, with SOURCE_DATE_EPOCH the commit's and no
# AIRDRESS_BUILD_* metadata.
#
#   scripts/release-build-mcp.sh <target> <image@sha256:…> <out-dir>
#
# The runner's registry and git checkouts are mounted (writable: cargo
# unpacks fetched crates on first use) and the build is offline, so the
# private git dependency is fetched once, on the runner (`cargo fetch
# --locked`), and nothing in the container reaches the network for crates.
# Writes <out-dir>/airdress-mcp and prints its SHA-256.
set -euo pipefail

target=$1
image=$2
out=$3
case "$image" in *@sha256:*) ;; *) echo "not a digest-pinned image: $image" >&2; exit 1 ;; esac
root=$(git rev-parse --show-toplevel)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
engine=$(command -v docker || command -v podman)
mkdir -p "$out"
out=$(cd "$out" && pwd)

"$engine" run --rm \
  -v "$root":/src:ro -v "$out":/out \
  -v "$cargo_home/registry":/root/.cargo/registry \
  -v "$cargo_home/git":/root/.cargo/git \
  -e CARGO_TARGET_DIR=/out/target -e CARGO_INCREMENTAL=0 \
  -e SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --pretty=%ct)" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$image" bash -lc "
    set -euo pipefail
    mkdir -p /work && cp -r /src/. /work/ && cd /work
    rustup toolchain install >/dev/null
    export RUSTFLAGS='--remap-path-prefix=/work=/airdress-cli --remap-path-prefix=/root/.cargo=/cargo --remap-path-prefix=/out/target=/target -C target-feature=+crt-static'
    CARGO_NET_OFFLINE=true cargo build --release --locked -p airdress-mcp --target $target
    cp /out/target/$target/release/airdress-mcp /out/airdress-mcp
    rm -rf /out/target
    chown -R \"\$HOST_UID:\$HOST_GID\" /out
  "
sha256sum "$out/airdress-mcp"
