#!/usr/bin/env bash
# Fixtures for scripts/check-conventional-commit.py: messages that must pass
# and must fail, through both modes against a scratch repository, so the hook
# path (a message file) and the CI path (`git rev-list`) each run for real.
set -euo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-conventional-commit.py"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
git init -q -b main repo
cd repo
git config commit.gpgsign false
git config user.name "Ada Person"
git config user.email "ada@example.org"

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
      grep -q '^conventional-commit: ' <<<"$err"; }; then
    pass_count=$((pass_count + 1))
  else
    echo "FAILED: $label (wanted $want, exit $got)" >&2
    [ -n "$err" ] && echo "$err" | sed 's/^/    /' >&2
    fail=1
  fi
}

hook() {
  printf '%s\n' "$1" >msg
  python3 "$CHECK" commit-msg msg
}

# --- the commit-msg hook.

for type in feat fix docs refactor perf test build ci chore revert; do
  expect pass "type $type" hook "$type: do the thing"
done
expect pass "a scope" hook "feat(shell): open a terminal by profile"
expect pass "a scope with a slash and a dash" hook "fix(mcp/bus-delivery): ack once"
expect pass "breaking, with !" hook "feat(cli)!: rename --json to --output json"
expect pass "breaking, ! without a scope" hook "refactor!: drop the v1 profile store"
expect pass "a body" hook $'fix: refuse a stale claim\n\nThe operator answers 409; say so.'
expect pass "a BREAKING CHANGE footer" hook $'feat: one profile store\n\nBody.\n\nBREAKING CHANGE: the old store is not read.'
expect pass "a BREAKING-CHANGE footer" hook $'feat: one profile store\n\nBREAKING-CHANGE: the old store is not read.'
expect pass "prose that mentions a breaking change" hook $'docs: explain\n\nA breaking change, here, is one a script notices.'
expect pass "git's comment block is not the message" hook $'fix: x\n\n# Please enter the commit message\n# On branch main'
expect pass "the scissors line ends the message" hook $'fix: x\n# ------------------------ >8 ------------------------\nnot: a header\ndiff --git a/x b/x'
expect pass "leading blank lines are stripped by git" hook $'\n\nfix: x'
expect pass "a fixup! commit, before autosquash" hook "fixup! feat(shell): open a terminal"
expect pass "a squash! commit, before autosquash" hook "squash! fix: x"
expect pass "a header of exactly 100 characters" hook "feat: $(printf 'a%.0s' $(seq 94))"

expect fail "no type" hook "open a terminal by profile"
expect fail "an unknown type" hook "feature: open a terminal"
expect fail "a capitalized type" hook "Feat: open a terminal"
expect fail "an old-style area prefix" hook "agent bus: rustfmt the Windows half"
expect fail "no space after the colon" hook "fix:refuse a stale claim"
expect fail "an empty subject" hook "fix: "
expect fail "a subject starting with a space" hook "fix:  two spaces"
expect fail "an empty scope" hook "fix(): x"
expect fail "! after the colon" hook "feat:! x"
expect fail "a header of 101 characters" hook "feat: $(printf 'a%.0s' $(seq 95))"
expect fail "no blank line before the body" hook $'fix: x\nbody right under it'
expect fail "a lowercase breaking change footer" hook $'feat: x\n\nbreaking change: the store moved'
expect fail "a BREAKING CHANGE footer with no description" hook $'feat: x\n\nBREAKING CHANGE:'
expect fail "an empty message" hook $'# only a comment'
expect fail "git's default revert message" hook 'Revert "feat: x"'

# A merge in progress records git's own message; it is not refused.
git commit -q --allow-empty -m "chore: root"
git rev-parse HEAD >.git/MERGE_HEAD
expect pass "a merge in progress" hook "Merge branch 'feature'"
rm .git/MERGE_HEAD
expect fail "the same message outside a merge" hook "Merge branch 'feature'"

# --- the CI mode: real commits, checked by range.

BASE=$(git rev-parse HEAD)
git commit -q --allow-empty -m "feat(cli): one"
git commit -q --allow-empty -m $'fix: two\n\nBREAKING CHANGE: three'
expect pass "range of conventional commits" python3 "$CHECK" range "$BASE..HEAD"
expect pass "whole history" python3 "$CHECK" range HEAD

git commit -q --allow-empty -m "shell host: build on macOS again"
expect fail "range with a non-conventional commit" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

git commit -q --allow-empty -m "fixup! feat(cli): one"
expect fail "range with a fixup! never squashed" python3 "$CHECK" range "$BASE..HEAD"
git reset -q --hard "$BASE"

git switch -q -c side
git commit -q --allow-empty -m "feat: on a side branch"
git switch -q main
git commit -q --allow-empty -m "fix: on main"
git merge -q --no-ff --no-verify -m "Merge branch 'side'" side
expect pass "range with a merge commit" python3 "$CHECK" range "$BASE..HEAD"
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
echo "check-conventional-commit: $pass_count fixtures behave"
