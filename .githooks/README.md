# Git hooks

`just hooks-install` points `core.hooksPath` here and installs the
pre-commit hooks from `.pre-commit-config.yaml`.

`pre-push` blocks a direct `git push`: changes reach `main` through a pull
request. Set `AIRDRESS_PUSH_OVERRIDE=1` to push a feature branch.

## `commit-msg`

Because `core.hooksPath` points here, git never runs the hooks `prek install`
writes under `.git/hooks`. `commit-msg` runs prek's commit-msg stage itself
(or, without prek, the two scripts directly):

- `scripts/check-commit-attribution.py` refuses a `Co-Authored-By` trailer
  naming Claude or Anthropic, any `@anthropic.com` address, and an author or
  committer named Claude or at anthropic.com. It also refuses a commit under
  the owner's identity (`scripts/owner-identities.txt`) unless
  `AIRDRESS_COMMIT_AS` says who commits it: `owner` adds a
  `Committed-As: owner` trailer, `bot` marks a draft that `just bot-commit`
  re-creates as airdress-bot.
- `scripts/check-conventional-commit.py` refuses a message that is not a
  conventional commit, because release-plz reads them.

CI runs both over every pushed commit.
