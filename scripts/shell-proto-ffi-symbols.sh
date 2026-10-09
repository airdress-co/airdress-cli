#!/usr/bin/env bash
# The C ABI's exported symbols, on the Android library itself.
#
# crates/airdress-shell-proto/ffi-symbols.txt lists every symbol the app may
# call; a unit test holds it to src/ffi.rs. This script holds it to what the
# linker actually exported: it builds the arm64 Android .so with cargo-ndk
# and compares `nm -D --defined-only` against the list, both ways. A symbol
# the linker dropped, or one exported by accident, fails here.
#
# Needs: cargo-ndk, an NDK (ANDROID_NDK_HOME or ANDROID_NDK_LATEST_HOME),
# the aarch64-linux-android target, and llvm-nm from the NDK.
# cspell:ignore ANDROID_NDK_LATEST_HOME prebuilt
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-}}"
if [[ -z "$ndk" ]]; then
    echo "shell-proto-ffi-symbols: set ANDROID_NDK_HOME" >&2
    exit 2
fi
export ANDROID_NDK_HOME="$ndk"

cargo ndk -t arm64-v8a build -p airdress-shell-proto --release --lib --locked

so=target/aarch64-linux-android/release/libairdress_shell_proto.so
nm_bin=$(find "$ndk/toolchains/llvm/prebuilt" -name llvm-nm -type f | head -1)

want=$(grep -vE '^\s*(#|$)' crates/airdress-shell-proto/ffi-symbols.txt | sort)
got=$("$nm_bin" -D --defined-only "$so" | awk '{print $3}' | grep '^airdress_shell_' | sort)

if ! diff -u <(echo "$want") <(echo "$got"); then
    echo "shell-proto-ffi-symbols: $so exports differ from ffi-symbols.txt" >&2
    exit 1
fi
echo "shell-proto-ffi-symbols: $(echo "$got" | wc -l) symbols match"
