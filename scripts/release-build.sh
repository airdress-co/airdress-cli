#!/usr/bin/env bash
# Build the `airdress` binary for one release target, reproducibly (rust
# guide R-WS-8). The one definition the release's build and its independent
# rebuild both run, so the two passes cannot drift apart by editing one.
#
#   scripts/release-build.sh [--agent] <target> [cross]
#
# `--agent` builds `airdress-agent` instead (the `mls` feature, that binary
# only); `airdress` itself is never built with MLS.
#
# Reads AIRDRESS_BUILD_VERSION / _COMMIT / _TARGET from the environment.
#
# A `*-linux-musl` target is built static, inside the digest-pinned image
# named by AIRDRESS_BUILD_IMAGE (the musl cross toolchain `airdress-mcp` is
# built with), so the Linux binaries need no shared library and run on any
# Linux of the target's architecture: v0.1.2, built against an
# ubuntu-24.04 runner's glibc 2.39 and libdbus, refused to start on
# Debian 12. The checkout is mounted at /airdress-cli, the cargo home's
# registry and git at /cargo, the target directory at /target, and the
# build runs offline: `cargo fetch --locked` on the runner first, where the
# private git dependency can be reached. The binary lands where a native
# build puts it, target/<target>/release/.
# The same tag, toolchain (rust-toolchain.toml) and lockfile give the same
# bytes on another machine: the embedded date is the tag commit's, not the
# clock's (SOURCE_DATE_EPOCH for anything that reads it, AIRDRESS_BUILD_DATE
# for `airdress version`), and no absolute build path survives, the
# checkout, the cargo home and the target directory being remapped to fixed
# names. /project is where a `cross` container mounts the checkout.
set -euo pipefail

what=(--bin airdress)
if [ "${1:-}" = "--agent" ]; then
  what=(--features mls --bin airdress-agent)
  shift
fi
target=$1
use_cross=${2:-}
root=$(git rev-parse --show-toplevel)
cd "$root"

SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
AIRDRESS_BUILD_DATE=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --pretty=%cd)
export SOURCE_DATE_EPOCH AIRDRESS_BUILD_DATE
export CARGO_INCREMENTAL=0

RUSTFLAGS=""
for m in "$root=/airdress-cli" "${CARGO_HOME:-$HOME/.cargo}=/cargo" \
         "${CARGO_TARGET_DIR:-$root/target}=/target" "/project=/airdress-cli"; do
  RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$m"
done
export RUSTFLAGS
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH RUSTFLAGS=$RUSTFLAGS"

case "$target" in
  *-linux-musl)
    image=${AIRDRESS_BUILD_IMAGE:?a musl target is built in AIRDRESS_BUILD_IMAGE (image@sha256:...)}
    case "$image" in *@sha256:*) ;; *) echo "not a digest-pinned image: $image" >&2; exit 1 ;; esac
    cargo_home=${CARGO_HOME:-$HOME/.cargo}
    target_dir=${CARGO_TARGET_DIR:-$root/target}
    mkdir -p "$target_dir"
    engine=$(command -v docker || command -v podman)
    owner=()
    [ "$(basename "$engine")" = docker ] && owner=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")
    # Inside, every path already has its fixed name, so the remaps name
    # them for anything that reports the image's own cargo home.
    "$engine" run --rm \
      -v "$root":/airdress-cli:ro -v "$target_dir":/target \
      -v "$cargo_home/registry":/cargo/registry -v "$cargo_home/git":/cargo/git \
      -w /airdress-cli \
      -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 -e CARGO_NET_OFFLINE=true -e CARGO_BUILD_JOBS \
      -e SOURCE_DATE_EPOCH -e AIRDRESS_BUILD_DATE \
      -e AIRDRESS_BUILD_VERSION -e AIRDRESS_BUILD_COMMIT -e AIRDRESS_BUILD_TARGET \
      "${owner[@]}" \
      "$image" bash -c '
        set -euo pipefail
        # The registry and git checkouts are the runner'"'"'s; the image keeps
        # its own cargo and rustup where they are.
        mkdir -p "${CARGO_HOME:-/root/.cargo}"
        ln -sfn /cargo/registry "${CARGO_HOME:-/root/.cargo}/registry"
        ln -sfn /cargo/git "${CARGO_HOME:-/root/.cargo}/git"
        rustup toolchain install >/dev/null
        export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-/root/.cargo}=/cargo -C target-feature=+crt-static"
        echo "in-container RUSTFLAGS=$RUSTFLAGS"
        rc=0
        cargo build --locked --release --target "$0" "${@}" || rc=$?
        # Under docker the files are root'"'"'s otherwise; rootless podman
        # already maps root to the caller.
        [ -z "${HOST_UID:-}" ] || chown -R "$HOST_UID:$HOST_GID" /target
        exit "$rc"
      ' "$target" "${what[@]}"
    exit 0
    ;;
esac

if [ "$use_cross" = "cross" ]; then
  cross build --locked --release --target "$target" "${what[@]}"
else
  cargo build --locked --release --target "$target" "${what[@]}"
fi
