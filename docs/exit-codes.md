# Exit codes and failure output

`airdress`'s exit status and its failure report are a stable contract:
scripts, CI (`airdress-co/deploy-functions`), the editor extension and the
MCP client read them. A code is never renumbered or reused for another
meaning; a new kind of failure gets a new number.

| Code | Name | Meaning | Typical causes |
|------|------|---------|----------------|
| `0` | ok | The command did what it was asked. | Includes `airdress update --check` when an update is available (see below). |
| `1` | internal | Unexpected: a bug, an answer this CLI could not read, a local file it could not read or write, a `5xx` from the server itself. | `500`, a malformed body, a disk error. |
| `2` | usage | The command line is wrong. clap's own code, kept. | Unknown subcommand or flag, a missing argument, a missing signing key (`signer_unavailable`). |
| `3` | refused | The operator or hub refused the request, or a person declined at a prompt. | `403`, `404`, `422`, `429`, a dry run's refusal, `capability_not_granted`, `confirmation_declined`. |
| `4` | auth | Authentication is needed or has expired. | No profile, no sign-in, a refresh the hub refused, `401`, `machine_authorization_expired`. |
| `5` | network | The other end could not be reached or did not answer in time. | Connection refused, DNS failure, timeout, `408`, `502`, `503`, `504`. |
| `6` | conflict | The request lost a race with another writer. | `409`, `412`, `source_base_stale`, `epoch_conflict`, `root_key_mismatch`. |
| `7` | confirmation required | The command needs a yes and could not ask for one: stdin is not a terminal, or `--output json` is set. Pass `-y` / `--yes`. | A destructive command run from a script. |

An operator's or hub's refusal is classified by its **code** first (a
`source_base_stale` is `6` whatever its status), then by its HTTP status.

## Failure output

**Text mode** (the default) writes, to stderr:

```text
Error: <what failed: its cause>
hint: <the one useful next step, when there is one>
```

**`--output json`** writes exactly one JSON object to stderr, on one line,
and nothing else for the failure — the same shape the CLI's refusal readers
use, plus the operator's own fields:

```json
{"code":"source_base_stale","message":"stale base: …","hint":"re-base the tree …","status":409}
```

| Field | Always | Meaning |
|-------|--------|---------|
| `code` | yes | A stable snake-case identifier: the operator's own code verbatim (`epoch_conflict`, `publication_blocked`), or one of this CLI's (`internal`, `usage`, `auth_required`, `not_signed_in`, `sign_in_expired`, `profile_not_found`, `unreachable`, `timeout`, `confirmation_required`, `http_<status>`). A script decides on `code` and the exit status, never on `message`. |
| `message` | yes | For a person. May change between releases. |
| `hint` | no | What to do about it. |
| `status` | no | The HTTP status the operator or hub answered, when one did. |
| anything else | no | Every other field of the operator's answer (`reason`, `locations`, `denials`, `basedOn`, `current`, …), carried through unchanged. |

A command that prints a structured result on stdout (a deploy's reports, a
refusal of `fn publish`) still does; the failure object on stderr is in
addition to it.

## `airdress update --check`

Exits `0` whether or not an update is available. `--check` is a question,
and answering it is success; the answer is in the output (`Update
available: a -> b`, or `"update_available": true` under `--output json`).
Before this contract it exited `1` when an update was available, which a
script could not tell apart from a check that failed to reach the index —
the failure it most needs to notice.

## Exceptions

- **`airdress shell`** ends with the **remote program's own exit status**,
  passed through unchanged (as `ssh` does), so `airdress shell -- make test`
  works in a script. A failure of the shell client itself (before the
  program ran, or the session was lost) uses the codes above, but a remote
  program may exit with any of `1`–`255`, including those numbers.
- **A panic** in a serving mode (`shell host`, `agent device serve`,
  `mcp serve`) exits `101`, Rust's own code for a panic.
- **Help and `--version`** exit `0`; asking for help is not a failure.

## Confirmation prompts

Every command that changes something it cannot undo asks first, through
one prompt, and every one of them takes `-y` / `--yes`:
`device revoke`, `fn deploy`, `fn signers add|remove`, `home disconnect`,
`plugins install|uninstall|deauthorize`, `shell close`,
`shell device forget`.

- With `-y` / `--yes` it does not ask.
- Under `--output json`, or when stdin is not a terminal, it **never**
  asks: it exits `7` with `confirmation_required`, a hint naming `--yes`,
  and `"flag": "--yes"` in the JSON object.
- Otherwise it asks `… [y/N]` on stderr. The default is **No**: only `y` or
  `yes` (any case) confirms; anything else, an empty line or end of input,
  is a decline, exit `3` with `confirmation_declined`.

Two questions are answered only by a person, so no flag answers them and
they exit `7` without a terminal: `shell host trust` (trusting a device by
its fingerprint) and a shell host's first-use key ("Does it match?"),
including the join question asked inside `airdress shell`.
