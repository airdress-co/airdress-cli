#!/usr/bin/env bash
# Document numbers stay out of code — see CLAUDE.md "Document numbers stay
# out of code". Spec, RDR and RCP numbers belong in comments and Markdown,
# never in identifiers, strings, keys or file names.
#
# Checks every tracked file (arguments are ignored: a violation elsewhere in
# the tree is as much a violation as one in the staged files):
#
#   1. Path: fails when a tracked path matches (?i)(spec|rdr|rcp)[_-]?[0-9]{3}
#      outside documentation (docs/, research/, runbooks/, .spec-workflow,
#      CHANGELOG*, *.md).
#   2. Content: fails when a non-comment line of a code file contains a
#      document number. A line is a comment when, after leading whitespace, it
#      starts with // /// # -- * or /*; a trailing `// …`, ` # …` or ` -- …`
#      segment is also a comment.
#
# The number is matched as a token: not preceded by a letter or digit, not
# followed by a digit (so `spec_054_foo` is caught although `_` is a word
# character).
#
# Exemptions:
#
#   - A trailing `allow-doc-number: <reason>` on the line. Reviewed, sparing.
#   - EXEMPT_PREFIXES below, each with its reason.
# cspell:ignore lstrip toplevel tfvars startswith endswith splitlines
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

git ls-files -z | python3 -c '
import re, sys

SUMMARY = (
    "Document numbers (SPEC/RDR/RCP-NNN) stay out of code: name the "
    "thing, and put the spec reference in a comment.")

PATH_RE = re.compile(r"(?i)(spec|rdr|rcp)[_-]?[0-9]{3}")
TOKEN_RE = re.compile(r"(?i)(?<![a-z0-9])(spec|rdr|rcp)[_-]?[0-9]{3}(?![0-9])")
DOC_PREFIXES = ("docs/", "research/", "runbooks/", ".spec-workflow")
# Content checks only. Applied migrations are immutable: sqlx checksums every
# applied file and refuses to start on a mismatch, so a number already in a
# migration (a column COMMENT string, say) stays where it is. New migrations
# are held to the rule by review.
EXEMPT_PREFIXES = ("crates/airdress-hub/migrations/",)
CODE_EXT = (".rs", ".go", ".dart", ".swift", ".kt", ".kts", ".py", ".sh",
            ".bash", ".toml", ".yaml", ".yml", ".json", ".tf", ".tfvars",
            ".hcl", ".ts", ".js", ".cjs", ".mjs", ".sql")
CODE_NAMES = ("justfile", "Justfile", "Dockerfile", "Makefile")
SKIP_PARTS = ("node_modules/",)
SKIP_NAMES = ("package-lock.json", "pnpm-lock.yaml", "Cargo.lock", "go.sum")
LINE_COMMENT = ("///", "//", "#", "--", "/*", "*")
TRAILING = re.compile(r"(^|\s)(//|#|--)(\s|$)")

def is_doc(path):
    base = path.rsplit("/", 1)[-1]
    return (path.startswith(DOC_PREFIXES) or "/.spec-workflow" in path
            or base.startswith("CHANGELOG") or path.endswith(".md"))

def code_part(line):
    if line.lstrip().startswith(LINE_COMMENT):
        return ""
    m = TRAILING.search(line)
    return line[: m.start()] if m else line

failures = []
for path in sys.stdin.buffer.read().decode().split("\0"):
    if not path or is_doc(path):
        continue
    if PATH_RE.search(path):
        failures.append(f"{path}: file name carries a document number")
    base = path.rsplit("/", 1)[-1]
    if (any(p in path for p in SKIP_PARTS) or base in SKIP_NAMES
            or path.startswith(EXEMPT_PREFIXES)):
        continue
    if not (path.endswith(CODE_EXT) or base in CODE_NAMES):
        continue
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        if "allow-doc-number:" in line:
            continue
        if TOKEN_RE.search(code_part(line)):
            failures.append(f"{path}:{n}: {line.strip()[:120]}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    print(f"\n{len(failures)} violation(s). {SUMMARY}", file=sys.stderr)
    sys.exit(1)
'
