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

It also makes the choice of committer explicit. A commit whose author or
committer is the repository owner's own identity (`owner-identities.txt`
beside this script) is refused unless the caller chose, for that commit:

  AIRDRESS_COMMIT_AS=owner  the owner commits it. The hook adds the trailer
                            `Committed-As: owner`, which is what CI looks for.
  AIRDRESS_COMMIT_AS=bot    a local draft the bot re-creates through the Git
                            Data API (`just bot-commit`). Nothing is added, so
                            the draft itself can never pass CI.

Any other identity needs no choice; naming `owner` for a commit git would
record under some other identity is refused, because the trailer would lie.

Modes:

  commit-msg FILE   the commit-msg hook: checks FILE plus the identities git
                    is about to record (`git var GIT_AUTHOR_IDENT` and
                    `GIT_COMMITTER_IDENT`). prek passes FILE.
  range REVS...     CI: every commit `git rev-list REVS...` names, e.g.
                    `range BASE..HEAD`, or `range HEAD` for a whole history.

Exit status 1 and one line per finding when anything is refused.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

TRAILER = re.compile(r"^\s*co-authored-by\s*:(?P<value>.*)$", re.IGNORECASE)
NAMES_ASSISTANT = re.compile(r"claude|anthropic", re.IGNORECASE)
ANTHROPIC_ADDRESS = re.compile(r"@(?:[a-z0-9-]+\.)*anthropic\.com\b", re.IGNORECASE)
NAME_CLAUDE = re.compile(r"claude", re.IGNORECASE)
IDENT = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^>]*)>")

CHOICE_ENV = "AIRDRESS_COMMIT_AS"
CHOICE_TRAILER = "Committed-As"
OWNER_IDENTITIES = Path(__file__).resolve().with_name("owner-identities.txt")
CHOICE_HELP = f"""a commit under the owner's identity needs an explicit choice of committer:
  as the owner: {CHOICE_ENV}=owner git commit ...
                (adds a `{CHOICE_TRAILER}: owner` trailer, which CI requires)
  as the bot:   just bot-commit "<message>"
                (or the Git Data API with an airdress-bot installation token)
  a merge:      just bot-merge <repo> <pr>   (airdress-ops)
                (re-creates the pull request's commits as the bot and
                fast-forwards main; GitHub's merge button records whoever
                pressed it as the committer, which this check refuses)"""


def _fold(text: str) -> str:
    return unicodedata.normalize("NFC", text).strip().casefold()


def load_owner(path: Path = OWNER_IDENTITIES) -> tuple[set[str], set[str]]:
    """The owner's names and addresses, folded for comparison."""
    names, emails = set(), set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, value = line.partition(":")
        if kind == "name":
            names.add(_fold(value))
        elif kind == "email":
            emails.add(_fold(value))
        else:
            raise ValueError(f"{path}: cannot parse {raw!r}")
    return names, emails


def _who(ident: str) -> str:
    match = IDENT.match(ident.strip())
    return f"{match.group('name')} <{match.group('email')}>" if match else ident.strip()


def is_owner(ident: str, owner: tuple[set[str], set[str]]) -> bool:
    match = IDENT.match(ident.strip())
    if not match:
        return False
    names, emails = owner
    return _fold(match.group("name")) in names or _fold(match.group("email")) in emails


def check_choice(author: str, committer: str, choice: str | None) -> tuple[list[str], bool]:
    """Findings for the committer choice, and whether to add the owner trailer."""
    owner = load_owner()
    roles = [role for role, ident in (("author", author), ("committer", committer)) if is_owner(ident, owner)]
    choice = (choice or "").strip()
    if choice not in ("", "owner", "bot"):
        return [f"{CHOICE_ENV}={choice!r} is not a choice: use owner or bot"], False
    if roles:
        if choice == "owner":
            return [], True
        if choice == "bot":
            return [], False
        verb = "are" if len(roles) > 1 else "is"
        return [f"{' and '.join(roles)} {verb} the owner's identity, and no choice was made"], False
    if choice == "owner":
        return [
            f"{CHOICE_ENV}=owner, but git would record {_who(author)} / {_who(committer)}, "
            "neither of which is the owner's identity"
        ], False
    return [], False


def add_choice_trailer(path: str) -> None:
    git(
        "interpret-trailers", "--in-place", "--if-exists", "addIfDifferent",
        "--trailer", f"{CHOICE_TRAILER}: owner", path,
    )


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


def commit_msg(path: str) -> tuple[list[str], list[str]]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        findings = check_message(handle.read(), comment_char())
    author = git("var", "GIT_AUTHOR_IDENT")
    committer = git("var", "GIT_COMMITTER_IDENT")
    findings += check_ident("author", author)
    findings += check_ident("committer", committer)
    choice, add_trailer = check_choice(author, committer, os.environ.get(CHOICE_ENV))
    if add_trailer and not findings:
        add_choice_trailer(path)
    return findings, choice


def commit_range(revs: list[str]) -> tuple[list[str], list[str]]:
    findings, choices = [], []
    owner = load_owner()
    trailer_format = f"%(trailers:key={CHOICE_TRAILER},valueonly,separator=%x01)"
    for sha in git("rev-list", *revs).split():
        fields = git("show", "-s", f"--format=%an <%ae>%x00%cn <%ce>%x00{trailer_format}%x00%B", sha)
        author, committer, trailers, message = fields.split("\x00", 3)
        found = check_ident("author", author) + check_ident("committer", committer)
        # A recorded message has had its comments stripped already.
        found += check_message(message, comment_char=None)
        findings += [f"{sha[:12]}: {finding}" for finding in found]
        values = {_fold(value) for value in trailers.split("\x01") if value.strip()}
        if (is_owner(author, owner) or is_owner(committer, owner)) and "owner" not in values:
            choices.append(
                f"{sha[:12]}: recorded under the owner's identity without a "
                f"`{CHOICE_TRAILER}: owner` trailer"
            )
    return findings, choices


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "commit-msg":
        findings, choices = commit_msg(argv[1])
    elif len(argv) >= 2 and argv[0] == "range":
        findings, choices = commit_range(argv[1:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for finding in findings + choices:
        print(f"commit-attribution: {finding}", file=sys.stderr)
    if findings:
        print(
            "commit-attribution: commits here are attributed to people or to our bot, "
            "never to an AI assistant. Remove the trailer or fix the identity.",
            file=sys.stderr,
        )
    if choices:
        for line in CHOICE_HELP.splitlines():
            print(f"commit-attribution: {line}", file=sys.stderr)
    return 1 if findings or choices else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
