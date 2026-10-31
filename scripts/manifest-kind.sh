#!/usr/bin/env bash
# Classify one release file for manifest.json: print "<kind> <platform>",
# or nothing (exit 0) for a file the manifest does not list.
#
#   scripts/manifest-kind.sh <file-name>
#
# The agent has kinds of its own (`agent`, `agent-deb`, `agent-rpm`), and
# the CLI's artifacts are listed before it (release.yml's jq): an installer
# that took the first entry for a platform installed airdress-agent as
# `airdress` (v0.1.1, v0.1.2). The package patterns come before
# `airdress-agent-*`, which would otherwise claim the agent's rpm
# (airdress-agent-0.1.25-1.x86_64.rpm) as a bare `agent` binary.
# Tested by scripts/manifest-kind-test.sh.
set -euo pipefail

name=$1

case "$name" in
  airdress-agent_*.deb)   kind="agent-deb" ;;
  airdress-agent-*.rpm)   kind="agent-rpm" ;;
  airdress-agent-*)       kind="agent" ;;
  *.deb)                  kind="deb" ;;
  *.rpm)                  kind="rpm" ;;
  *)                      kind="binary" ;;
esac

case "$name" in
  *.sha256)                                   exit 0 ;;
  *linux-amd64*|*_amd64.deb|*.x86_64.rpm)     plat="linux-amd64" ;;
  *linux-arm64*|*_arm64.deb|*.aarch64.rpm)    plat="linux-arm64" ;;
  *darwin-amd64*)                             plat="darwin-amd64" ;;
  *darwin-arm64*)                             plat="darwin-arm64" ;;
  *windows-amd64*)                            plat="windows-amd64" ;;
  *)                                          exit 0 ;;
esac

echo "$kind $plat"
