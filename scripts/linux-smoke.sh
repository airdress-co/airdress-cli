#!/usr/bin/env bash
# Run the released Linux binaries and .debs on the distributions we say they
# run on, each in a clean container of that distribution.
#
#   scripts/linux-smoke.sh <dist-dir> [expected-version]
#
# <dist-dir> holds what one release leg uploads for this machine's
# architecture: airdress-linux-<arch>, airdress-agent-linux-<arch>, and the
# two .debs. With an expected version (e.g. v0.1.3) the `--version` lines
# must name it.
#
# The stated baseline is what this checks: Debian 12, Ubuntu 22.04 and
# 24.04, Fedora 40, RHEL 9 and Alpine. Each binary must be
# static, so no shared library and no glibc version is required of the
# host: v0.1.2 needed glibc 2.39 and libdbus and refused to start on
# Debian 12. Writes a Markdown table to $GITHUB_STEP_SUMMARY when set.
set -euo pipefail

dist=$(cd "$1" && pwd)
expect=${2:-}
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unknown architecture $(uname -m)" >&2; exit 1 ;;
esac
engine=$(command -v docker || command -v podman)

cli="airdress-linux-$arch"
agent="airdress-agent-linux-$arch"
for f in "$cli" "$agent"; do
  [ -f "$dist/$f" ] || { echo "missing $dist/$f" >&2; exit 1; }
  chmod +x "$dist/$f"
  # Static means no program interpreter: nothing for the host to supply.
  if readelf -l "$dist/$f" | grep -q 'Requesting program interpreter'; then
    echo "::error::$f is dynamically linked:" >&2
    readelf -d "$dist/$f" | grep NEEDED >&2 || true
    exit 1
  fi
  echo "static  $f"
done

# RHEL 9 is Red Hat's own Universal Base Image, RHEL 9's user land.
images=(
  docker.io/library/debian:12
  docker.io/library/ubuntu:22.04
  docker.io/library/ubuntu:24.04
  docker.io/library/fedora:40
  registry.access.redhat.com/ubi9/ubi-minimal:latest
  docker.io/library/alpine:3.20
)

summary=${GITHUB_STEP_SUMMARY:-/dev/null}
{
  echo "### Linux smoke ($arch)"
  echo
  echo "| Image | airdress | airdress-agent | .deb |"
  echo "|---|---|---|---|"
} >>"$summary"

fail=0
for image in "${images[@]}"; do
  echo "== $image"
  out=$("$engine" run --rm --pull=missing -v "$dist":/dist:ro -e CLI="$cli" -e AGENT="$agent" \
    -e EXPECT="$expect" "$image" sh -c '
      set -eu
      check() { # <label> <version line>
        case "$2" in
          "$1 "*) ;;
          *) echo "unexpected version line from $1: $2" >&2; exit 1 ;;
        esac
        [ -z "$EXPECT" ] || [ "${2#"$1 "}" = "$EXPECT" ] || {
          echo "$1 says ${2#"$1 "}, expected $EXPECT" >&2; exit 1; }
      }
      v=$(/dist/$CLI --version); check airdress "$v"
      a=$(/dist/$AGENT --version); check airdress-agent "$a"
      # A tiny smoke past argument parsing, needing no network and no
      # account: help, and an empty profile list in an empty home.
      /dist/$CLI --help >/dev/null
      HOME=$(mktemp -d) /dist/$CLI profile list >/dev/null
      deb=-
      if command -v dpkg >/dev/null 2>&1; then
        dpkg -i /dist/airdress_*.deb /dist/airdress-agent_*.deb >/dev/null
        check airdress "$(airdress --version)"
        check airdress-agent "$(airdress-agent --version)"
        deb=ok
      fi
      echo "$v|$a|$deb"
    ' 2>&1) && rc=0 || rc=$?
  echo "$out"
  if [ "$rc" -eq 0 ]; then
    IFS='|' read -r v a deb <<<"$(tail -n1 <<<"$out")"
    echo "| \`$image\` | $v | $a | $deb |" >>"$summary"
  else
    echo "::error::$image: $(tail -n1 <<<"$out")"
    echo "| \`$image\` | FAILED | | |" >>"$summary"
    fail=1
  fi
done
exit "$fail"
