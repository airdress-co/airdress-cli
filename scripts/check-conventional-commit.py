#!/usr/bin/env python3
"""Refuse a commit message that is not a conventional commit.

release-plz reads the history to decide the next version and to write
CHANGELOG.md, so every commit on main says what kind of change it is:

    <type>[(<scope>)][!]: <subject>

    [body]

    [footers, e.g. BREAKING CHANGE: <what breaks and what to do>]

  * type is one of: feat fix docs refactor perf test build ci chore revert
  * scope is free text in parentheses, e.g. `feat(shell): ...`
  * `!` before the colon, or a `BREAKING CHANGE:` footer (also spelled
    `BREAKING-CHANGE:`), marks a breaking change. The footer is uppercase
    by the specification, so a lowercase one is refused rather than missed.
  * the header is at most 100 characters, and a body is separated from it
    by one blank line.

Exempt: merge commits (git's own message), and, at commit-msg only,
`fixup!`, `squash!` and `amend!` commits, which an autosquash rebase folds
away before they can reach main. CI refuses those, because by then they
did not get folded.

Modes:

  commit-msg FILE   the commit-msg hook; prek passes FILE.
  range REVS...     CI: every commit `git rev-list REVS...` names.

Exit status 1 and one line per finding when anything is refused.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

TYPES = ("feat", "fix", "docs", "refactor", "perf", "test", "build", "ci", "chore", "revert")
HEADER = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^()\r\n]*)\))?(?P<bang>!)?: (?P<subject>.*)$"
)
MAX_HEADER = 100
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE: \S")
BREAKING_MISSPELT = re.compile(r"^breaking[ -]change\s*:", re.IGNORECASE)
AUTOSQUASH = re.compile(r"^(fixup|squash|amend)! ")
SCISSORS = re.compile(r"^. -+ >8 -+$")


def strip_comments(message: str, comment_char: str | None) -> str:
    """The message as git will record it: comments and everything below the
    scissors line (`git commit -v`) removed."""
    lines = []
    for line in message.splitlines():
        if comment_char and SCISSORS.match(line) and line.startswith(comment_char):
            break
        if comment_char and line.startswith(comment_char):
            continue
        lines.append(line)
    # git strips leading blank lines and trailing whitespace too.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def check(message: str, *, merge: bool = False, allow_autosquash: bool = False) -> list[str]:
    """Findings in a recorded (comment-free) commit message."""
    if merge:
        return []
    lines = message.splitlines()
    if not lines:
        return ["the message is empty"]
    header = lines[0]
    if allow_autosquash and AUTOSQUASH.match(header):
        return []
    findings = []
    if AUTOSQUASH.match(header):
        findings.append(f"`{header.split()[0]}` commit was never squashed: {header}")
        return findings
    match = HEADER.match(header)
    if not match:
        findings.append(f"the header is not `<type>[(<scope>)][!]: <subject>`: {header}")
    else:
        if match.group("type") not in TYPES:
            findings.append(f"unknown type `{match.group('type')}`: {header}")
        if match.group("scope") is not None and not match.group("scope").strip():
            findings.append(f"an empty scope: {header}")
        subject = match.group("subject")
        if not subject.strip() or subject != subject.lstrip():
            findings.append(f"the subject is empty or starts with a space: {header}")
    if len(header) > MAX_HEADER:
        findings.append(f"the header is {len(header)} characters, the limit is {MAX_HEADER}")
    if len(lines) > 1 and lines[1].strip():
        findings.append("the body must be separated from the header by a blank line")
    for number, line in enumerate(lines[1:], start=2):
        if BREAKING_MISSPELT.match(line) and not BREAKING_FOOTER.match(line):
            findings.append(f"line {number}: write the footer as `BREAKING CHANGE: <description>`: {line}")
    return findings


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def comment_char() -> str:
    try:
        value = git("config", "--get", "core.commentChar").strip()
    except subprocess.CalledProcessError:
        return "#"
    return "#" if value in ("", "auto") else value


def commit_msg(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        message = strip_comments(handle.read(), comment_char())
    git_dir = git("rev-parse", "--git-dir").strip()
    merging = os.path.exists(os.path.join(git_dir, "MERGE_HEAD"))
    return check(message, merge=merging, allow_autosquash=True)


def commit_range(revs: list[str]) -> list[str]:
    findings = []
    for sha in git("rev-list", *revs).split():
        parents, message = git("show", "-s", "--format=%P%x00%B", sha).split("\x00", 1)
        found = check(message.strip("\n"), merge=len(parents.split()) > 1)
        findings += [f"{sha[:12]}: {finding}" for finding in found]
    return findings


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "commit-msg":
        findings = commit_msg(argv[1])
    elif len(argv) >= 2 and argv[0] == "range":
        findings = commit_range(argv[1:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for finding in findings:
        print(f"conventional-commit: {finding}", file=sys.stderr)
    if findings:
        print(
            "conventional-commit: write `<type>[(<scope>)][!]: <subject>`, type one of "
            + ", ".join(TYPES)
            + ". See CONTRIBUTING.md.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
