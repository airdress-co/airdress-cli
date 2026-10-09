#!/usr/bin/env python3
"""Refuse commits attributed to an AI assistant.

Every commit in this repository is authored by a person or by our own bot.
This check refuses a commit that credits Claude or Anthropic:

  * a `Co-Authored-By:` trailer that names Claude or Anthropic, or any
    `@anthropic.com` address anywhere in the message;
  * an author or committer whose name contains "claude", or whose email is
    at anthropic.com (including noreply@anthropic.com) or a subdomain of it.

Matching is case-insensitive. Mentioning the product in the prose of a
message is fine; only attribution is refused.

Modes:

  commit-msg FILE   the commit-msg hook: checks FILE plus the identities git
                    is about to record (`git var GIT_AUTHOR_IDENT` and
                    `GIT_COMMITTER_IDENT`). prek passes FILE.
  range REVS...     CI: every commit `git rev-list REVS...` names, e.g.
                    `range BASE..HEAD`, or `range HEAD` for a whole history.

Exit status 1 and one line per finding when anything is refused.
"""

from __future__ import annotations

import re
import subprocess
import sys

TRAILER = re.compile(r"^\s*co-authored-by\s*:(?P<value>.*)$", re.IGNORECASE)
NAMES_ASSISTANT = re.compile(r"claude|anthropic", re.IGNORECASE)
ANTHROPIC_ADDRESS = re.compile(r"@(?:[a-z0-9-]+\.)*anthropic\.com\b", re.IGNORECASE)
NAME_CLAUDE = re.compile(r"claude", re.IGNORECASE)
IDENT = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^>]*)>")


def check_message(message: str, comment_char: str | None = "#") -> list[str]:
    """Findings in a commit message. Lines git strips as comments are skipped."""
    findings = []
    for number, line in enumerate(message.splitlines(), start=1):
        if comment_char and line.startswith(comment_char):
            continue
        trailer = TRAILER.match(line)
        if trailer and NAMES_ASSISTANT.search(trailer.group("value")):
            findings.append(f"line {number}: Co-Authored-By names an AI assistant: {line.strip()}")
        elif ANTHROPIC_ADDRESS.search(line):
            findings.append(f"line {number}: an @anthropic.com address: {line.strip()}")
    return findings


def check_ident(role: str, ident: str) -> list[str]:
    """Findings in a `Name <email> ...` identity."""
    match = IDENT.match(ident.strip())
    if not match:
        return [f"{role}: cannot parse identity {ident.strip()!r}"]
    name, email = match.group("name"), match.group("email")
    findings = []
    if NAME_CLAUDE.search(name):
        findings.append(f"{role} name names an AI assistant: {name}")
    if ANTHROPIC_ADDRESS.search(email):
        findings.append(f"{role} email is an anthropic.com address: {email}")
    return findings


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def comment_char() -> str:
    try:
        value = git("config", "--get", "core.commentChar").strip()
    except subprocess.CalledProcessError:
        return "#"
    # "auto" picks a character git cannot tell us in advance; "#" is its first choice.
    return "#" if value in ("", "auto") else value


def commit_msg(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        findings = check_message(handle.read(), comment_char())
    findings += check_ident("author", git("var", "GIT_AUTHOR_IDENT"))
    findings += check_ident("committer", git("var", "GIT_COMMITTER_IDENT"))
    return findings


def commit_range(revs: list[str]) -> list[str]:
    findings = []
    for sha in git("rev-list", *revs).split():
        fields = git("show", "-s", "--format=%an <%ae>%x00%cn <%ce>%x00%B", sha).split("\x00", 2)
        author, committer, message = fields
        found = check_ident("author", author) + check_ident("committer", committer)
        # A recorded message has had its comments stripped already.
        found += check_message(message, comment_char=None)
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
        print(f"commit-attribution: {finding}", file=sys.stderr)
    if findings:
        print(
            "commit-attribution: commits here are attributed to people or to our bot, "
            "never to an AI assistant. Remove the trailer or fix the identity.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
