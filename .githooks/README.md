# Git hooks

`just hooks-install` points `core.hooksPath` here and installs the
pre-commit hooks from `.pre-commit-config.yaml`.

`pre-push` blocks a direct `git push`: changes reach `main` through a pull
request. Set `AIRDRESS_PUSH_OVERRIDE=1` to push a feature branch.

## `commit-msg` — no commit attributed to an AI assistant

Because `core.hooksPath` points here, git never runs the hooks `prek install`
writes under `.git/hooks`. `commit-msg` runs prek's commit-msg stage itself,
which is `scripts/check-commit-attribution.py`: it refuses a `Co-Authored-By`
trailer naming Claude or Anthropic, any `@anthropic.com` address, and an
author or committer named Claude or at anthropic.com. CI runs the same check
over every pushed commit.
