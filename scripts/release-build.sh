#!/usr/bin/env bash
# Build the `airdress` binary for one release target, reproducibly (rust
# guide R-WS-8). The one definition the release's build and its independent
# rebuild both run, so the two passes cannot drift apart by editing one.
#
#   scripts/release-build.sh <target> [cross]
#
# Reads AIRDRESS_BUILD_VERSION / _COMMIT / _TARGET from the environment.
# The same tag, toolchain (rust-toolchain.toml) and lockfile give the same
# bytes on another machine: the embedded date is the tag commit's, not the
# clock's (SOURCE_DATE_EPOCH for anything that reads it, AIRDRESS_BUILD_DATE
# for `airdress version`), and no absolute build path survives, the
# checkout, the cargo home and the target directory being remapped to fixed
# names. /project is where a `cross` container mounts the checkout.
set -euo pipefail

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

if [ "$use_cross" = "cross" ]; then
  cross build --locked --release --target "$target"
else
  cargo build --locked --release --target "$target"
fi
