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
# The fixtures set the committer choice themselves; one inherited from the
# caller's shell would change what they test.
unset AIRDRESS_COMMIT_AS

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

# --- the committer choice: the owner's identity needs AIRDRESS_COMMIT_AS.

OWNER=("Robert Jefe Lindstaedt" "robert.lindstaedt@gmail.com")
OWNER_UMLAUT=("Robert Jefe Lindstädt" "robert.lindstaedt@gmail.com")

# The message file after the hook ran, as git would record it.
recorded() { git stripspace --strip-comments < msg; }
trailer_count() { recorded | git interpret-trailers --parse | grep -c '^Committed-As: owner$' || true; }
expect_trailers() {
    local want="$1" label="$2" got
    got=$(trailer_count)
    if [ "$got" = "$want" ]; then
        pass_count=$((pass_count + 1))
    else
        echo "FAILED: $label (wanted $want Committed-As trailer(s), found $got)" >&2
        fail=1
    fi
}

expect fail "owner author, no choice" hook "${OWNER[@]}" "$BODY"
expect fail "owner author spelt with an umlaut, no choice" hook "${OWNER_UMLAUT[@]}" "$BODY"
expect fail "owner name at another address" hook "Robert Jefe Lindstaedt" "robert@example.org" "$BODY"
expect fail "owner address under another name" hook "Somebody" "Robert.Lindstaedt@GMAIL.com" "$BODY"
COMMITTER_NAME="Robert Jefe Lindstädt" COMMITTER_EMAIL="robert.lindstaedt@gmail.com" \
    expect fail "owner committer only, no choice" hook "${PERSON[@]}" "$BODY"
expect fail "the trailer alone is not a choice" hook "${OWNER[@]}" "$BODY"$'\n\nCommitted-As: owner'
AIRDRESS_COMMIT_AS=yes expect fail "an unknown choice" hook "${OWNER[@]}" "$BODY"
AIRDRESS_COMMIT_AS=yes expect fail "an unknown choice, other identity" hook "${PERSON[@]}" "$BODY"
AIRDRESS_COMMIT_AS=owner expect fail "owner chosen for somebody else's commit" hook "${PERSON[@]}" "$BODY"
AIRDRESS_COMMIT_AS=owner expect fail "owner chosen, but a Claude trailer" \
    hook "${OWNER[@]}" "$BODY"$'\n\nCo-Authored-By: Claude <noreply@anthropic.com>'
expect_trailers 0 "no trailer added to a refused message"

AIRDRESS_COMMIT_AS=owner expect pass "owner chosen" hook "${OWNER[@]}" "$BODY"
expect_trailers 1 "owner chosen adds the trailer"
AIRDRESS_COMMIT_AS=owner expect pass "owner chosen, trailer already there (amend)" \
    hook "${OWNER[@]}" "$BODY"$'\n\nCommitted-As: owner'
expect_trailers 1 "an amend keeps one trailer"
AIRDRESS_COMMIT_AS=owner expect pass "owner chosen, with git's comment block" \
    hook "${OWNER[@]}" "$BODY"$'\n\n# Please enter the commit message for your changes.\n# On branch main'
expect_trailers 1 "the trailer survives comment stripping"
AIRDRESS_COMMIT_AS=owner COMMITTER_NAME="Robert Jefe Lindstädt" COMMITTER_EMAIL="robert.lindstaedt@gmail.com" \
    expect pass "owner chosen, owner as author and committer" hook "${OWNER[@]}" "$BODY"
AIRDRESS_COMMIT_AS=bot expect pass "bot chosen: a draft the bot re-creates" hook "${OWNER[@]}" "$BODY"
expect_trailers 0 "bot chosen adds no trailer"
AIRDRESS_COMMIT_AS=bot expect pass "bot chosen, other identity" hook "${PERSON[@]}" "$BODY"
expect pass "another person needs no choice" hook "${PERSON[@]}" "$BODY"
expect_trailers 0 "another person gets no trailer"

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

owner_commit() {
    local message="$1"
    GIT_AUTHOR_NAME="${OWNER[0]}" GIT_AUTHOR_EMAIL="${OWNER[1]}" \
        GIT_COMMITTER_NAME="${COMMITTER_NAME:-${OWNER_UMLAUT[0]}}" \
        GIT_COMMITTER_EMAIL="${COMMITTER_EMAIL:-${OWNER_UMLAUT[1]}}" \
        git commit -q --allow-empty -m "$message"
}

owner_commit "$BODY"$'\n\nCommitted-As: owner'
expect pass "range: the owner, with the trailer" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

owner_commit "$BODY"
expect fail "range: the owner, without the trailer" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

owner_commit "$BODY"$'\n\nCommitted-As: bot'
expect fail "range: the owner, with another trailer value" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

owner_commit "$BODY"$'\n\nCommitted-As: owner\n\nA paragraph after it.'
expect fail "range: a trailer that is not in the trailer block" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

# A pull request rebase-merged on GitHub: GitHub commits, the owner authored.
COMMITTER_NAME=GitHub COMMITTER_EMAIL=noreply@github.com owner_commit "$BODY"$'\n\nCommitted-As: owner'
expect pass "range: rebased by GitHub, owner author with the trailer" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"
COMMITTER_NAME=GitHub COMMITTER_EMAIL=noreply@github.com owner_commit "$BODY"
expect fail "range: rebased by GitHub, owner author without it" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

GIT_COMMITTER_NAME=GitHub GIT_COMMITTER_EMAIL=noreply@github.com \
    GIT_AUTHOR_NAME="airdress-bot[bot]" GIT_AUTHOR_EMAIL="284437753+airdress-bot[bot]@users.noreply.github.com" \
    git commit -q --allow-empty -m "$BODY"
expect pass "range: the bot through the API" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

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
