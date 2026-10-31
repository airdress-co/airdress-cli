#!/usr/bin/env bash
# Package one release binary as a .deb or an .rpm with nfpm, and write its
# checksum.
#
#   scripts/package-linux.sh <deb|rpm> <nfpm-config> <binary> <arch> <tag> <package-name>
#
# <arch> is the Debian/Go name (amd64, arm64) for both formats; nfpm maps
# it to x86_64/aarch64 for rpm. Writes into the current directory:
#
#   deb: <package-name>_<version>_<arch>.deb
#   rpm: <package-name>-<version>-1.<rpm-arch>.rpm
#
# plus a .sha256 beside it. <version> is the tag without its `v`, so a file
# name keeps the tag's form (airdress_0.2.0-rc.1_amd64.deb); inside the
# package nfpm writes a pre-release as `0.2.0~rc.1`, which sorts below
# 0.2.0 in both dpkg and rpm (measured with nfpm 2.41.3). The rpm is
# unsigned: the repository copy is signed where the repositories are
# published, not here.
#
# The binary is static, so the package declares no Depends: there is no
# shared library for the system to supply.
#
# nfpm does its own envsubst on a few metadata fields (version, arch) but not
# on contents[].src, so ${BINARY_PATH} is expanded here, with an explicit
# list of variables so no other `$something` in the YAML is eaten.
set -euo pipefail

if [ $# -ne 6 ]; then
    echo "usage: $0 <deb|rpm> <nfpm-config> <binary> <arch> <tag> <package-name>" >&2
    exit 2
fi

packager=$1
config=$2
BINARY_PATH=$3
PKG_ARCH=$4
tag=$5
name=$6
PKG_VERSION=${tag#v}
export BINARY_PATH PKG_ARCH PKG_VERSION

case "$packager" in
    deb) out="${name}_${PKG_VERSION}_${PKG_ARCH}.deb" ;;
    rpm)
        case "$PKG_ARCH" in
            amd64) rpm_arch=x86_64 ;;
            arm64) rpm_arch=aarch64 ;;
            *) echo "error: no rpm arch for $PKG_ARCH" >&2; exit 2 ;;
        esac
        out="${name}-${PKG_VERSION}-1.${rpm_arch}.rpm"
        ;;
    *) echo "error: packager must be deb or rpm, got $packager" >&2; exit 2 ;;
esac

expanded=$(mktemp --suffix=.yaml)
trap 'rm -f "$expanded"' EXIT
# shellcheck disable=SC2016 # the variable names are envsubst's, literally
envsubst '$PKG_ARCH $PKG_VERSION $BINARY_PATH' <"$config" >"$expanded"
nfpm pkg --packager "$packager" --config "$expanded" --target "$out"
sha256sum "$out" >"$out.sha256"
cat "$out.sha256"
