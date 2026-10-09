#!/usr/bin/env bash
# Prove that the MCP server reaches nothing but the hosts it was given.
#
# The session test (`crates/airdress-mcp/tests/server_session.rs`) drives
# every tool against mock hub and operator servers on loopback and
# asserts that both mocks were asked. On its own that shows what the
# server *did* reach, not what it *could*. Run here, inside a network
# namespace with only loopback up, it shows both: any connection to a
# host other than the mocks has nowhere to go, so a tool that reached
# for one fails the test rather than succeeding quietly.
#
# No capabilities needed: `unshare -rn` maps the caller to root inside a
# new user and network namespace, which every modern Linux allows
# unprivileged. On a kernel that does not, the script says so and exits
# non-zero rather than passing without having proved anything — a
# skipped check that reports success is the failure mode this whole
# exercise exists to avoid.
#
# Usage: scripts/egress-allowlist-test.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! command -v unshare >/dev/null 2>&1; then
    echo "egress test: unshare is not installed; cannot isolate the network" >&2
    exit 1
fi

# Two ways in. Unprivileged user namespaces are the portable one and
# what CI uses; a workstation with AppArmor's
# `apparmor_restrict_unprivileged_userns` set (Ubuntu 24.04 and later,
# by default) refuses them, and there passwordless sudo is the way.
if unshare -rn true 2>/dev/null; then
    ISOLATE="unshare -rn --"
elif sudo -n unshare -n true 2>/dev/null; then
    ISOLATE="sudo -n unshare -n --"
else
    echo "egress test: cannot create a network namespace here." >&2
    echo "  Unprivileged user namespaces are refused — on Ubuntu 24.04+ that is" >&2
    echo "  /proc/sys/kernel/apparmor_restrict_unprivileged_userns — and sudo" >&2
    echo "  needs a password. Run it with sudo, or let CI run it." >&2
    exit 1
fi

# Build outside the namespace, and resolve the TEST BINARY's path.
#
# What goes into the namespace is the test executable and nothing else:
# no cargo, no rustc, no registry, no git. That matters because three
# consecutive CI failures here were all the same shape — cargo not on
# PATH, then the rustup shim with no readable state, then cargo wanting
# the private git dependency while `--offline` forbade it. None of them
# was about egress. A compiled binary needs none of that machinery, so
# the test measures what it is for.
echo "egress test: building the session test"

# Build to a FILE, then read it. Not a pipeline: the reader used to
# `break` on the first matching artifact, cargo then wrote into a closed
# pipe and exited 101, and `pipefail` made that the script's answer. It
# raced — locally cargo had finished before the reader stopped, on a
# runner it had not, so the check failed in CI with its stderr
# suppressed and nothing about egress in the message.
artifacts=$(mktemp)
trap 'rm -f "$artifacts"' EXIT
if ! cargo test --locked --no-run -p airdress-mcp --test server_session \
    --message-format=json >"$artifacts"; then
    echo "egress test: the test would not build; that is not an egress result" >&2
    exit 1
fi

BINARY=$(python3 -c '
import json, sys

found = ""
with open(sys.argv[1]) as stream:
    for line in stream:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        executable = message.get("executable")
        name = (message.get("target") or {}).get("name") or ""
        if executable and name == "server_session":
            found = executable
print(found)
' "$artifacts")
[ -n "$BINARY" ] && [ -x "$BINARY" ] || {
    echo "egress test: could not find the built test binary" >&2
    exit 1
}

echo "egress test: running $(basename "$BINARY") with only loopback reachable"
exec $ISOLATE sh -c '
    set -e
    ip link set lo up 2>/dev/null || ifconfig lo up
    # No default route, no DNS, no reachable address but 127.0.0.1. A
    # request to anything else cannot succeed, which is the whole point.
    exec "$1" --nocapture
' sh "$BINARY"
