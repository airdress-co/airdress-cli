# airdress-cli — Claude Code context

## What this repo is

Airdress CLI — auth, profiles, credential management, and self-update.
Rust (Cargo), async with tokio, clap for arg parsing.

## Common tasks

```sh
just build           # cargo build --release
just test            # cargo test
just fmt             # cargo fmt
just clippy          # cargo clippy -- -D warnings
just lint            # fmt-check + clippy
just check           # pre-commit run --all-files
just hooks-install   # install pre-commit + .githooks
just release v0.X.Y  # trigger release workflow via GH
```

## The MCP server

`src/mcp/` is the server; `crates/airdress-mcp` is a thin binary over
it, and `crates/airdress-mcp-catalogue` holds the tool names, schemas
and annotations. The catalogue is a separate crate because the operator
reads it too, by pinned revision, to serve the same tools over HTTP — a
tool defined in only one of the two halves is how they drift.

Three rules, each of which a test enforces:

- **Nothing writes to stdout.** stdout is the protocol. Every
  human-facing line goes to stderr.
- **Secrets live in `Redacted<T>`** (`src/redact.rs`). `.expose()` at
  the point of use, never into a format string. It has no `Display`, so
  `bearer_auth(token)` does not compile until the token is exposed, and
  it reaches a file only through `#[serde(with = "crate::redact::persist")]`.
- **No telemetry, and no host but the user's hub and operators.**
  `deny.toml` bans the crates; `crates/airdress-mcp/tests/server_session.rs`
  drives every tool with every other host unreachable, and
  `scripts/egress-allowlist-test.sh` runs the same test in a network
  namespace where only loopback is up.

Across the whole repo, a discarded `Result` is written as
`.log_warn("…")` or `.log_debug("…")` (`src/log_err.rs`, and the same in
`airdress-shell-host`), never `let _ =`.

A new tool goes into the catalogue crate first, then
`src/mcp/tools.rs`, then the session test.

## Pushing code

Direct `git push` is blocked by the pre-push hook. Use either:

- `bot-commit.sh "<message>"` — pushes as `airdress-bot[bot]` with verified badge
- `AIRDRESS_PUSH_OVERRIDE=1 git push` — emergency bypass

The bot-commit script lives in `airdress-ops/scripts/bot-commit.sh` and
derives credentials from the platform tofu state automatically.

## Releasing

Releases are dispatch-only — no local tag push:

```sh
just release v0.1.0-alpha.7
# or: gh workflow run release.yml -f tag=v0.1.0-alpha.7
```

The workflow creates the tag, builds all 5 platforms, uploads to
`downloads.airdress.co/airdress-cli/`, and creates a GitHub release.

## Login flows

`auth login` uses authorization code + PKCE on a loopback port with
`prompt=select_account` (`src/auth/pkce_flow.rs`), because ZITADEL's
device grant cannot force an account picker: the device request carries
only `client_id` + `scope`, and its legacy `/device` login auto-uses a
browser's single active session. `--device` / `--no-browser` still run the
device flow, with a notice. Redirect is `http://localhost:<port>` with no
path — the IdP client registers `http://localhost`, and a native client may
vary the port only. Tokens from either flow are stored as `device_flow`,
with the raw `id_token` kept beside them: `auth logout` sends it as
`id_token_hint` to the IdP's end_session endpoint (ZITADEL ends that
session by id, no browser cookie), then revokes the tokens (RFC 7009).

### On the hub's authorization server (SPEC-133 D-36)

`auth login` first asks `GET /api/cli/oauth-config?v=2`. When the issuer it
names has the hub's own origin, the CLI reads the hub's RFC 8414 metadata
and signs in there (`discovery::resolve_login_server`): the same PKCE
loopback flow (redirect `http://localhost:<port>/callback`; the hub forwards
`prompt=select_account` to ZITADEL) or RFC 8628 device flow. A hub that
ignores `v=2` answers with ZITADEL's issuer, and the CLI signs in there
directly, with a printed notice.

The authorization and device authorization requests carry **no**
`resource`: for the CLI's first-party client that is what makes the grant
cover every airdress the person owns plus the hub API. Naming one narrows
the grant to it. The token requests then carry `resource=` — the hub API's
(`<issuer>/api`) at login, `https://<fqdn>/v1` per operator afterwards.

The profile becomes schema v3, `method: "hub"` (`AuthConfig::Hub`): one
refresh token (it rotates on every use; a reused one revokes the grant),
and `access_tokens` keyed by resource. `auth::tokens::access_token(profile,
Audience::Hub | Audience::Operator(fqdn))` is the only way to get a bearer;
a refresh runs under a cross-process `flock` on `<profile>.lock`
(`storage::ProfileLock`) and re-reads the profile first, so two processes
never present one refresh token twice. `HubClient::bearer()` is for the hub
only; operators get `HubClient::operator_bearer(fqdn)`.

A v2 (`device_flow`) profile keeps working — its one token serves every
audience — until the next `auth login` moves it, which prints what happens
and revokes the old tokens at ZITADEL (its browser session is left alone).

## Auth tokens

A device-flow access token lives ~30 minutes; the refresh token beside
it is the credential that matters. `ensure_fresh` (`src/auth/refresh.rs`)
renews it on the way into every hub/operator call, and the IdP
round-trip sits behind the `TokenRefresher` trait so the logic is
tested against a fake (`refresh::test_support`), never the network.

- `airdress auth status` is a **pure read** — no refresh, no write. It
  reports `access_token_expired` and `refreshable` (a non-empty refresh
  token is on file; the IdP is not asked) and only says `expired` when
  a browser login is really needed.
- `airdress auth token [--profile p] [--airdress X]` prints a fresh bearer
  (the hub API's, or with `--airdress` the one X's operator accepts) to stdout
  and nothing else — it refreshes and writes the profile back, because
  asking for a credential is the explicit side-effecting act. Scripts
  should read this, not `auth.access_token` out of the profile file.

## Self-update (SPEC-036)

`airdress update` downloads from the SPEC-024 distribution contract
(index.json + manifest.json), verifies SHA-256 during streaming download,
and atomically replaces the binary. `--check` exits 1 if an update is
available. `--target <version>` pins a specific version.

Build-time version comes from `AIRDRESS_BUILD_VERSION` env var (set by
the release workflow from the git tag). Falls back to `CARGO_PKG_VERSION`.

## Context selection (SPEC-043)

Most airdress-targeting subcommands resolve the "current airdress"
through a five-tier precedence (highest wins):

1. `--airdress` / `-A` (global flag) — `airdress -A alice a probe`
2. `AIRDRESS_NAME` env — `AIRDRESS_NAME=alice airdress a probe`
3. `.airdress` directory marker — read-only, off by default,
   opt in via `~/.airdress/preferences.toml`:

   ```toml
   [discovery]
   directory_marker = true
   ```

   Then `echo alice > ~/airdresses/alice/.airdress` and the marker
   is discovered from CWD or any ancestor up to `$HOME`.
4. `active_airdress` pinned for the active profile — set via
   `airdress airdress use <name>` (alias `airdress a use <name>`).
   Validates at set-time against the hub; recovers from a stale
   pin (404/403 on a later command) by clearing it automatically.
5. Error → run `airdress airdress list` and `airdress a use <name>`.

Status line on ambient resolution (env / marker / profile-default
tiers) prints `→ acting on <name> (source: <tier>)` to **stderr**.
Explicit `--airdress` invocations are silent. Suppress with `--quiet`
or `AIRDRESS_QUIET={1,true,yes,on}` (case-insensitive allowlist).
`--output json` always suppresses the line and threads the resolved
airdress into the response envelope instead.

Verb mapping:

| Action                          | Canonical                         | Alias                  |
|---------------------------------|-----------------------------------|------------------------|
| Switch active profile           | `airdress profile use <name>`     | `airdress use <name>`  |
| Switch active airdress          | `airdress airdress use <name>`    | `airdress a use <name>`|
| Show resolved context           | `airdress current`                | —                      |

For shell-prompt integration, `airdress current` is the primitive:

```sh
airdress current                # text: "prod / alice (source: profile-default)"
airdress current --output json  # JSON for starship/p10k consumers
```

## Device pairing (SPEC-044)

`airdress device pair` mints a 5-minute pairing code on the current
airdress's operator and renders a QR + `airdress-pair://` deeplink.
Phone scans → operator records the new device → CLI reports success.

```sh
airdress device pair                                  # QR + deeplink
airdress device pair --no-qr                          # deeplink only
airdress device pair --label "alice-phone"            # explicit device label
airdress device pair --output json                    # scripted consumer envelope
```

Talks **directly** to the operator at `https://<airdress-fqdn>/v1/endpoints/*`
using the CLI's existing hub OAuth bearer (a ZITADEL access token).
The operator's `OwnerPrincipal` extractor validates the bearer via
JWKS and asserts `claims.sub == owner_sub`. See
[airdress-specs/airdress-operator/SPEC-011](https://github.com/airdress-co/airdress-specs/tree/main/airdress-operator/specs/SPEC-011-device-provisioning)
for the enrollment protocol and
[airdress-specs/airdress-ops/SPEC-044](https://github.com/airdress-co/airdress-specs/tree/main/airdress-ops/specs/SPEC-044-cli-device-pairing)
for the CLI surface.

The operator must be configured with `auth.audience` AND
`auth.owner_sub` for owner-protected routes to mount; without either
the operator panics at boot (RFC 8725 §2.4 fail-closed).

### Revoking a device (SPEC-049 task 5.6)

`airdress device revoke <ENROLLMENT_ID>` revokes one enrollment with the
same owner bearer `pair` uses. It exists for a device that cannot act for
itself: the operator's `airdress-operator endpoint revoke --token` needs a
sibling device's session token, and a single-device airdress whose phone
is dead has none.

```sh
airdress device revoke <ID> --dry-run   # preview: id, airdress, label
airdress device revoke <ID>             # preview, then [y/N] on a terminal
airdress device revoke <ID> --yes       # scripts: non-TTY stdin requires it
```

Order of calls: `GET /v1/endpoints/enrollments/{id}` (404 = not active or
not visible, stop), `DELETE …?dry_run=true` (preview; same authorization
as the revoke, and the response must carry `X-Dry-Run: true`), then the
real `DELETE`. The operator accepts the owner's bearer for this from
airdress-operator PR #218 on; an older operator refuses it.

### TLS flags for active dev

The CLI ships three flags for hitting operators whose TLS chain
isn't fully wired yet (LE staging, self-signed certs, no DNS flip):

```sh
airdress --insecure device pair                          # skip cert validation (warning on stderr)
airdress --ca-file ~/dev-ca.pem device pair              # trust a private CA in addition to system roots
airdress device pair --operator-url http://127.0.0.1:8080  # override the resolved URL entirely
```

Env equivalents: `AIRDRESS_INSECURE={1,true,yes,on}`,
`AIRDRESS_CA_FILE=<path>`. The truthy allowlist matches
`AIRDRESS_QUIET` (SPEC-043) — typos do NOT silently disable
validation.

`--insecure` prints a loud, **non-suppressible** stderr warning on
every invocation. `--ca-file` is the preferred path when you have a
private CA — it adds to the system root store rather than replacing
validation outright. `--operator-url` is dev-only; it bypasses the
hub FQDN lookup so the CLI talks straight to whatever URL you point
it at.

## Declarative resources (SPEC-033)

k8s-style apply/get/describe/delete against the operator's
[declarative-resource framework](https://github.com/airdress-co/airdress-specs/tree/main/airdress-operator/specs/SPEC-033-declarative-resource-framework).
Manifests are YAML by default (JSON accepted); multi-doc YAML uses
`---` separators.

```sh
airdress apply -f pool.yaml                  # server-side apply
airdress apply -f pool.yaml --dry-run        # predict, don't write
airdress diff  -f pool.yaml                  # alias for apply --dry-run

airdress get                                  # list registered Kinds
airdress get InferencePoolMember              # list resources of one Kind
airdress get InferencePoolMember/my-nas     # read one (YAML on stdout)

airdress describe InferencePoolMember/my-nas  # spec + status + conditions
airdress delete   InferencePoolMember/my-nas  # hard-delete
airdress delete   -f pool.yaml                  # delete every doc in a file
```

All verbs honour the SPEC-043 airdress resolver (`--airdress`,
`AIRDRESS_NAME`, `.airdress` marker, profile pin) and the SPEC-044
TLS dev flags (`--insecure`, `--ca-file`, `--operator-url`). They
talk directly to the operator with the hub's ZITADEL bearer.

## The shell host

`airdress shell host` (crate `crates/airdress-shell-host`) runs, on the
person's own machine, the profiles in `~/.config/airdress/shells.toml` as
sessions inside its one process, end to end to their enrolled devices.
`airdress shell profile …` edits that file; nothing over the network can.
It never switches user (`scripts/shell-host-no-user-switch.sh`), keeps
nothing running after it stops except the opt-in user unit (`--install`),
and verifies every device itself rather than trusting the operator.

```sh
cargo test -p airdress-shell-host --features testkit \
  --lib --test host_e2e --test host_poll --test probe_files -- --include-ignored
cargo run -p airdress-shell-host --example emulator_measure -- /usr/bin/htop
```

The tests drive a real host through the test kit's mock operator over both
transports. Where it departs from the design is in the crate's
`DESIGN-NOTES.md`.

## Workspace

This repo is one clone in the airdress workspace. `airdress-ops` is the hub:
it holds the manifest of every repo (`mani.yaml`), the cross-repo task
runner, and the drift check that keeps them honest.

- A new repo must be added to **both** `infra/tofu/platform/github.tf`
  (creation, branch protection, CI vars) **and** `mani.yaml` in
  airdress-ops. A pre-commit hook there enforces that they agree.
- Cross-repo commands work from inside this repo:
  `mani run status --all`, `mani run test --tags rust`, `mani list projects`.
- After any repo is added, renamed, or archived, run
  `just workspace-drift-online` in airdress-ops.
- Full guide: `airdress-ops/docs/workspace.md`.
