#!/usr/bin/env bash
# Public-hygiene grep, over the whole history.
#
# This repository is public. Nothing in it may name our internal estate:
# the GCP project, a Secret Manager entry, a VM, a jump host, a private
# address, the QA airdress, or a test account. The grep runs over every
# object in the history, not the working tree, because a public
# repository publishes the history too.
#
# Two modes:
#
#   (default)   the tracked files as they are now. This is what the hook
#               and CI run, because it is what a change can fix.
#   --history   every blob in every reachable commit. This is the
#               pre-publication audit. A finding here cannot be fixed by
#               a commit, only by rewriting the history — which happens
#               only on the owner's word — so its findings are recorded
#               and decided, not quietly removed.
#
# Two things are deliberately NOT in the pattern list. The ZITADEL
# issuer hostname carries the project name and is nonetheless public by
# necessity: every user's CLI contacts it, and the hub serves it from
# `/api/cli/oauth-config`. And `a.airdr.es` is the public hosting zone
# where customers' airdresses live, not an internal name; the QA
# airdress on it has its own pattern below.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Each pattern is a thing that must not appear, with what it is.
PATTERNS=(
    'airdress-co-ops:the GCP project'
    'airdress-tfstate:the state bucket'
    'qa-device:the QA airdress'
    'ipv6-operator:a fleet host name'
    'synthetic-login:a test account'
    '100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+:a tailnet address'
    '10\.[0-9]+\.[0-9]+\.[0-9]+:a private address'
    '192\.168\.[0-9]+\.[0-9]+:a private address'
    '172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+:a private address'
    'ai-nas-0:an internal host'
    'billing-internal-bearer:a secret name'
    'operator-ingress-bearer:a secret name'
    'functions-signer-seed:a secret name'
)

fail=0
check() {
    local where="$1" pattern="$2" what="$3" hits
    if hits=$(eval "$where" | grep -nIE "$pattern" 2>/dev/null); then
        echo "public-hygiene: found $what:" >&2
        echo "$hits" | head -20 >&2
        fail=1
    fi
}

if [[ "${1:-}" != "--history" ]]; then
    for entry in "${PATTERNS[@]}"; do
        pattern="${entry%%:*}"
        what="${entry#*:}"
        # The script's own pattern list is the one file whose job is
        # to contain these strings.
        if hits=$(git grep -nIE "$pattern" -- . \
            ':(exclude)scripts/check-public.sh' 2>/dev/null); then
            echo "public-hygiene: found $what:" >&2
            echo "$hits" | head -20 >&2
            fail=1
        fi
    done
else
    # Every blob in the history, once.
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    git rev-list --all --objects \
        | awk '{print $1}' \
        | sort -u > "$tmp/objects"
    git cat-file --batch-check='%(objectname) %(objecttype)' < "$tmp/objects" \
        | awk '$2 == "blob" {print $1}' > "$tmp/blobs"
    git cat-file --batch < "$tmp/blobs" > "$tmp/all" 2>/dev/null || true
    for entry in "${PATTERNS[@]}"; do
        pattern="${entry%%:*}"
        what="${entry#*:}"
        if hits=$(grep -aoE ".{0,40}$pattern.{0,40}" "$tmp/all" | sort -u); then
            echo "public-hygiene: found $what in the history:" >&2
            echo "$hits" | head -20 >&2
            fail=1
        fi
    done
fi

if [[ $fail -ne 0 ]]; then
    echo >&2
    echo "Nothing in a public repository may name our internal estate." >&2
    echo "Remove it, and rewrite the history only on the owner's word." >&2
    exit 1
fi
echo "public-hygiene: clean"
