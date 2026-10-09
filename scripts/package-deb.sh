#!/usr/bin/env bash
# Package one release binary as a .deb with nfpm, and write its checksum.
#
#   scripts/package-deb.sh <nfpm-config> <binary> <deb-arch> <tag> <package-name>
#
# Writes <package-name>_<version>_<deb-arch>.deb and its .sha256 into the
# current directory. The binary is static, so the package declares no
# Depends: there is no shared library for the system to supply.
#
# nfpm does its own envsubst on a few metadata fields (version, arch) but not
# on contents[].src, so ${BINARY_PATH} is expanded here, with an explicit
# list of variables so no other `$something` in the YAML is eaten.
set -euo pipefail

config=$1
BINARY_PATH=$2
DEB_ARCH=$3
tag=$4
name=$5
DEB_VERSION=${tag#v}
export BINARY_PATH DEB_ARCH DEB_VERSION

expanded=$(mktemp --suffix=.yaml)
trap 'rm -f "$expanded"' EXIT
envsubst '$DEB_ARCH $DEB_VERSION $BINARY_PATH' <"$config" >"$expanded"
deb="${name}_${DEB_VERSION}_${DEB_ARCH}.deb"
nfpm pkg --packager deb --config "$expanded" --target "$deb"
sha256sum "$deb" >"$deb.sha256"
cat "$deb.sha256"
