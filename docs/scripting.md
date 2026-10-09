# Scripting

The CLI is built to be driven: one flag for machine-readable output, exit
codes that mean one thing each, and no prompt that a script cannot answer.

## `--output json`

Every command takes `--output json` (or `-o json`). The result is JSON on
stdout; a failure is exactly one JSON object on stderr, with a stable
`code` to decide on ([exit codes](exit-codes.md#failure-output)). Under
`--output json` the status line is silent and the resolved airdress
travels inside the envelope.

```sh
airdress airdress list --output json | jq -r '.[].name'
airdress fn deploy ./hello --yes --output json
airdress current --output json          # for a prompt: active profile, airdress, source
```

## A token for something else

```sh
TOKEN=$(airdress auth token)                    # for the hub's API
OP_TOKEN=$(airdress auth token --airdress home) # the one only that airdress accepts
```

`auth token` prints a fresh bearer and nothing else, refreshing first when
the cached one is stale. The output is a credential: do not log it, and
treat anything that captured it as a reason to sign out and in again.
Scripts should read this command, not the profile file.

## Confirmations

Every command that changes something it cannot undo asks first, and every
one of them takes `-y` / `--yes`. Without a terminal, or under
`--output json`, it never asks: it exits `7` with `confirmation_required`
and a hint naming `--yes`.

## Environment

| Variable | Effect |
| --- | --- |
| `AIRDRESS_NAME` | The airdress to act on, below `--airdress` |
| `AIRDRESS_QUIET` | `1`, `true`, `yes` or `on`: no `→ acting on …` line |
| `AIRDRESS_TIMEOUT` | Per-request timeout in seconds (default 30; `--timeout` wins) |
| `AIRDRESS_LOG` / `RUST_LOG` | Diagnostic traces, instead of `-v` / `-vv` |
| `AIRDRESS_OPERATOR_URL` | Talk to this airdress directly, skipping the hub lookup |
| `AIRDRESS_MACHINE_KEY`, `AIRDRESS_MACHINE_ENROLLMENT` | Act as an approved machine ([functions from CI](functions.md#deploying-from-ci)) |
| `AIRDRESS_FUNCTION_SIGNING_KEY` | The source-signing seed, as hex |
| `AIRDRESS_PLUGIN_INDEX_KEYS` | Pinned registry keys for `plugins verify` |
| `AIRDRESS_BOOTSTRAP_TOKEN` | For `device bootstrap`, instead of a flag |
| `AIRDRESS_CA_FILE` | Trust a private CA in addition to the system roots |
| `AIRDRESS_INSECURE` | Skip certificate validation. Development only; warns loudly every time |

Boolean variables take `1`, `true`, `yes` or `on`, case-insensitive. A
typo does not quietly turn validation off.

## Timeouts

The connect timeout is 10 seconds; each request has 30 unless `--timeout`
or `AIRDRESS_TIMEOUT` says otherwise. A request that did not answer in
time exits `5`.
