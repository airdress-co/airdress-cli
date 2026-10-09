#!/usr/bin/env bash
# Fixtures for scripts/check-commit-attribution.py: messages and identities
# that must pass and must fail, driven through both modes against a scratch
# repository, so the hook path (`git var`) and the CI path (`git rev-list`)
# are each exercised for real.
set -euo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-commit-attribution.py"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
git init -q repo
cd repo
git config commit.gpgsign false

fail=0
pass_count=0

expect() {
    local want="$1" label="$2"
    shift 2
    local got=0 err
    # A refusal is exit 1 WITH a finding line; a crash also exits 1, and must
    # not count as the check working.
    err=$("$@" 2>&1 >/dev/null) || got=$?
    if { [ "$want" = pass ] && [ "$got" -eq 0 ]; } ||
        { [ "$want" = fail ] && [ "$got" -eq 1 ] && ! grep -q Traceback <<<"$err" &&
            grep -q '^commit-attribution: ' <<<"$err"; }; then
        pass_count=$((pass_count + 1))
    else
        echo "FAILED: $label (wanted $want, exit $got)" >&2
        fail=1
    fi
}

# --- the commit-msg hook: a message file plus the identities git would record.

hook() {
    local name="$1" email="$2" message="$3"
    printf '%s\n' "$message" > msg
    GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" \
        GIT_COMMITTER_NAME="${COMMITTER_NAME:-Ada Person}" \
        GIT_COMMITTER_EMAIL="${COMMITTER_EMAIL:-ada@example.org}" \
        python3 "$CHECK" commit-msg msg
}

PERSON=("Ada Person" "ada@example.org")
BODY=$'cli: do a thing\n\nBecause it was needed.'

expect pass "plain commit" hook "${PERSON[@]}" "$BODY"
expect pass "a human co-author" hook "${PERSON[@]}" "$BODY"$'\n\nCo-Authored-By: Grace Person <grace@example.org>'
expect pass "prose may mention the product" hook "${PERSON[@]}" $'docs: say the plugin works with Claude Code\n\nThe MCP server runs under any editor.'
expect pass "a commented-out trailer is stripped by git" hook "${PERSON[@]}" "$BODY"$'\n# Co-Authored-By: Claude <noreply@anthropic.com>'
expect pass "the bot" hook "airdress-bot[bot]" "123+airdress-bot[bot]@users.noreply.github.com" "$BODY"

expect fail "Claude co-author" hook "${PERSON[@]}" "$BODY"$'\n\nCo-Authored-By: Claude <noreply@anthropic.com>'
expect fail "lowercase trailer key" hook "${PERSON[@]}" "$BODY"$'\n\nco-authored-by: Claude Opus <claude@example.org>'
expect fail "Anthropic co-author" hook "${PERSON[@]}" "$BODY"$'\n\nCo-authored-by: Anthropic Assistant <bot@example.org>'
expect fail "uppercase trailer and name" hook "${PERSON[@]}" "$BODY"$'\n\nCO-AUTHORED-BY: CLAUDE <x@example.org>'
expect fail "an anthropic.com address outside a trailer" hook "${PERSON[@]}" "$BODY"$'\n\nSigned-off-by: Someone <someone@Anthropic.com>'
expect fail "author named Claude" hook "Claude" "ada@example.org" "$BODY"
expect fail "author named claude-code" hook "claude-code" "ada@example.org" "$BODY"
expect fail "author at anthropic.com" hook "Ada Person" "noreply@anthropic.com" "$BODY"
expect fail "author at a subdomain" hook "Ada Person" "ada@mail.ANTHROPIC.com" "$BODY"
COMMITTER_NAME="Claude" expect fail "committer named Claude" hook "${PERSON[@]}" "$BODY"
COMMITTER_EMAIL="noreply@anthropic.com" expect fail "committer at anthropic.com" hook "${PERSON[@]}" "$BODY"

# --- the CI mode: real commits, checked by range.

commit() {
    local name="$1" email="$2" message="$3"
    GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" \
        GIT_COMMITTER_NAME="Ada Person" GIT_COMMITTER_EMAIL="ada@example.org" \
        git commit -q --allow-empty -m "$message"
}

commit "${PERSON[@]}" "$BODY"
BASE=$(git rev-parse HEAD)
commit "Grace Person" "grace@example.org" "$BODY"
expect pass "range of human commits" python3 "$CHECK" range "$BASE..HEAD"
expect pass "whole history of human commits" python3 "$CHECK" range HEAD

commit "${PERSON[@]}" "$BODY"$'\n\nCo-Authored-By: Claude <noreply@anthropic.com>'
expect fail "range with a Claude trailer" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

commit "Claude" "noreply@anthropic.com" "$BODY"
expect fail "range with a Claude author" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"
expect pass "range after the bad commit is gone" python3 "$CHECK" range "$BASE..HEAD"

usage=0
python3 "$CHECK" >/dev/null 2>&1 || usage=$?
if [ "$usage" -ne 2 ]; then
    echo "FAILED: no arguments must be a usage error (exit 2), got $usage" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "check-commit-attribution: $pass_count fixtures behave"
