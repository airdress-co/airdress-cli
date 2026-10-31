#!/usr/bin/env bash
# Fixtures for scripts/manifest-kind.sh: every file name a release uploads,
# and the kind and platform the manifest must give it.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
fail=0

expect() { # <file-name> <expected output, empty for unlisted>
  got=$("$here/manifest-kind.sh" "$1")
  if [ "$got" = "$2" ]; then
    echo "ok    $1 -> ${2:-<unlisted>}"
  else
    echo "FAIL  $1: got '${got:-<unlisted>}', expected '${2:-<unlisted>}'" >&2
    fail=1
  fi
}

expect airdress-linux-amd64                      "binary linux-amd64"
expect airdress-linux-arm64                      "binary linux-arm64"
expect airdress-darwin-amd64                     "binary darwin-amd64"
expect airdress-darwin-arm64                     "binary darwin-arm64"
expect airdress-windows-amd64.exe                "binary windows-amd64"
expect airdress-agent-linux-amd64                "agent linux-amd64"
expect airdress-agent-linux-arm64                "agent linux-arm64"
expect airdress_0.1.25_amd64.deb                 "deb linux-amd64"
expect airdress_0.1.25_arm64.deb                 "deb linux-arm64"
expect airdress-agent_0.1.25_amd64.deb           "agent-deb linux-amd64"
expect airdress-agent_0.1.25_arm64.deb           "agent-deb linux-arm64"
expect airdress-0.1.25-1.x86_64.rpm              "rpm linux-amd64"
expect airdress-0.1.25-1.aarch64.rpm             "rpm linux-arm64"
# The one a naive case misfiles as a bare agent binary.
expect airdress-agent-0.1.25-1.x86_64.rpm        "agent-rpm linux-amd64"
expect airdress-agent-0.1.25-1.aarch64.rpm       "agent-rpm linux-arm64"
# A pre-release keeps the tag's form in the file name.
expect airdress-0.2.0-rc.1-1.x86_64.rpm          "rpm linux-amd64"
expect airdress-agent_0.2.0-rc.1_arm64.deb       "agent-deb linux-arm64"
# Not listed.
expect airdress-0.1.25-1.x86_64.rpm.sha256       ""
expect airdress-linux-amd64.sha256               ""
expect airdress-freebsd-amd64                    ""

exit "$fail"
