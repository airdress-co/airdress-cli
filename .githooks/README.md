# airdress-cli hooks

Pre-push hook blocks direct pushes. Use `bot-commit.sh` or set
`AIRDRESS_PUSH_OVERRIDE=1` to bypass.

## `bot-commit.sh` — no local copy needed here

This repo has never vendored its own copy, and doesn't need one: the
script is repo-agnostic. Every git command inside it acts on `$PWD`'s
repository, not on the directory the script itself lives in. Run it
from this repo's root, pointing at wherever a copy of it actually is —
`airdress-ops` has the canonical one:

```sh
cd airdress-cli
git add <files>
/path/to/airdress-ops/scripts/bot-commit.sh "commit message"
```

It derives `BOT_APP_ID` / `BOT_SECRET_NAME` / `BOT_GCP_PROJECT` from
`airdress-ops`'s platform tofu state (relative to the script's own
location, not `$PWD`), then commits, pushes, and verifies against
whichever repo `$PWD`'s `origin` points at — `airdress-cli` in this
case. See the script's own header comment for the full flow and for
what it does with any uncommitted work you weren't trying to commit.

## `commit-msg` — no commit attributed to an AI assistant

Because `core.hooksPath` points here, git never runs the hooks `prek install`
writes under `.git/hooks`. `commit-msg` runs prek's commit-msg stage itself,
which is `scripts/check-commit-attribution.py`: it refuses a `Co-Authored-By`
trailer naming Claude or Anthropic, any `@anthropic.com` address, and an
author or committer named Claude or at anthropic.com. CI runs the same check
over every pushed commit.
