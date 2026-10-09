# airdress-cli

Airdress CLI — auth, profiles, and credential management for the
[Airdress Terraform provider](https://github.com/airdress-co/terraform-provider-airdress).

## Install

```sh
curl -fsSL https://get.airdress.co/cli | sh
```

## Usage

```sh
# Log in: opens the identity provider's account picker in your browser
# (every login asks which account, so a second profile never inherits the
# browser's current sign-in). A missing profile is created on the default hub.
airdress auth login
airdress auth login --profile qa        # a second account, side by side
airdress auth login --device            # URL + code, for a browser elsewhere —
                                        # no picker there: use a private window

# Log out: ends the identity-provider session this login created (using the
# profile's own ID token), revokes its tokens, then forgets them.
airdress auth logout

# Check status — a pure read. A stale access token beside a refresh
# token still reads "authenticated (… will refresh on next use)";
# "expired" means a browser login is really needed.
airdress auth status
airdress auth status --output json   # adds access_token_expired + refreshable

# A fresh bearer for scripts. Refreshes (and writes the profile back)
# when the cached token is stale. The output is a credential.
TOKEN=$(airdress auth token)
# The token one airdress's operator accepts (a hub sign-in holds one per
# airdress; each is refused by every other operator).
OP_TOKEN=$(airdress auth token --airdress home)

# Create a staging profile
airdress profile create staging --endpoint https://staging.airdress.co

# Switch profiles  (alias: `airdress use staging`)
airdress profile use staging

# List profiles
airdress profile list

# Work with airdresses
airdress airdress list                  # list yours
airdress airdress use alice             # pin one as current   (alias: `airdress a use alice`)
airdress airdress probe                 # probe the current airdress
airdress -A bob airdress probe          # one-off override via global flag
airdress current                        # show the resolved context

# Pair a phone / chat client to the current airdress (SPEC-044)
airdress device pair                    # QR + deeplink, waits for the scan
airdress device pair --label "phone"    # name the new device
airdress device pair --output json      # scripted consumer envelope

# Revoke a dead or lost device by enrollment id, with your own sign-in
airdress device revoke <ID> --dry-run   # show id, airdress and label only
airdress device revoke <ID>             # confirm, then revoke (--yes in scripts)

# Declarative resources against the operator (SPEC-033, k8s-style)
airdress apply -f pool.yaml                  # server-side apply
airdress diff  -f pool.yaml                  # dry-run
airdress get                                  # list registered Kinds
airdress get InferencePoolMember              # list resources of one Kind
airdress get InferencePoolMember/my-nas     # read one (YAML)
airdress get things                           # a lowercase or plural Kind resolves; Things list
                                              # EVENTS, COMMANDS, CHANNEL, FIRMWARE, LAST SEEN
airdress describe InferencePoolMember/my-nas
airdress delete   InferencePoolMember/my-nas
```

### Selecting the current airdress (SPEC-043)

Most subcommands resolve the "current airdress" by walking a five-tier
precedence (highest wins):

1. `--airdress` / `-A` (global flag)
2. `AIRDRESS_NAME` env var
3. `.airdress` directory marker — opt-in, read-only
4. The profile's pinned airdress (`airdress a use <name>`)
5. Error pointing to `airdress airdress list`

Status line prints to stderr on ambient resolution; suppress with
`--quiet` or `AIRDRESS_QUIET=1`. `--output json` is always silent and
includes the resolved airdress in the response envelope.

### Code-first functions (SPEC-112)

`airdress functions` (alias `airdress fn`) is the headless authoring loop.
Every verb calls the operator's authoring routes — the same ones the editor
extension uses — and prints what the operator answers. The checks are the
operator's: layout, imports, grants, stale bases and signatures.

```sh
airdress fn templates                        # the catalogue
airdress fn new hello ./greeter              # the template's files, as plain source,
                                             # function.json id = --function-id, else the dir name
                                             # if dotted, else local.<dir>;
                                             # writes function.yaml beside it: spec.capabilities,
                                             # spec.config and spec.events, the manifest
                                             # `fn deploy` applies (and shows) to create it
airdress fn validate ./greeter --name greeter   # no key: checked, not verified
airdress fn publish  ./greeter --name greeter --signing-key seed.hex \
    --based-on sha256:<the version the tree was read from>
airdress fn versions greeter                 # what it served, what is stored
airdress fn source sha256:<v>                # manifest + file index
airdress fn source sha256:<v> src/main.ts    # one file, raw
airdress fn logs greeter --since 15m -f      # the durable log, polled by row id
```

- **The tree** of a function directory is `function.json` and every
  regular file under `src/`, nothing else: `function.yaml`, a README or a
  `tsconfig.json` beside them are left out. Symlinks are refused.
- **Signing** uses an Ed25519 seed (`airdress fn keygen --out <file>`)
  from `--signing-key <file>` or `AIRDRESS_FUNCTION_SIGNING_KEY`. The
  signature covers the canonical file-set digest the operator verifies.
  `--signer-machine <id>` names the signer as an approved machine's
  registered source-signing key instead of by the literal key. With no key
  the tree is sent unsigned, which only an operator allowing unsigned source
  accepts for a publish; `validate` without a key is checked but not
  verified. Every answer names the digest the operator computed
  (`sourceDigest`), and the CLI stops if it is not the digest it signed.
- **Refusals** print one per line as `path:line:column: Reason: message`,
  plus one line per capability the owner has not granted naming its `spec.capabilities`
  path. Any refusal exits non-zero.
- **Stale bases are never retried.** Once a function serves a version, a
  publish must name it with `--based-on`. If the function has moved, both
  versions are printed and the command exits non-zero.

#### The Functions SDK, `@airdress/functions` (SPEC-114)

A function imports the library as `@airdress/functions/<module>` and pins
an exact version in `function.json` (`"sdk": "1.0.0"`). The operator
bundles its own compiled-in copy at publish; everything the CLI writes for
it sits beside `function.json`, never under `src/`, so none of it is ever
published.

```sh
airdress fn new dwell-webhook ./stay   # also: pins the newest version when the template has none,
                                       # .airdress/sdk-<version>.d.ts + tsconfig.json (types),
                                       # the local copy, and test/main.test.ts
airdress fn sdk pull ./stay            # refresh types + local copy for the pin
airdress fn sdk pull ./stay --pin newest   # (re)pin first: `newest` or an exact version
airdress fn sdk vendor ./stay          # copy the modules into src/sdk/, make the imports
                                       # relative, drop the pin: the tree refers to nothing
node test/main.test.ts                 # or: bun test/main.test.ts,
                                       # deno run --node-modules-dir=manual --allow-read test/main.test.ts
```

- **Where the copy comes from.** `GET /v1/functions/sdk/{version}` on the
  operator — never npm, where the `@airdress` scope is reserved and holds
  nothing. It lands in `.airdress/node_modules/@airdress/functions/`.
- **How local runtimes find it.** Node, Bun and Deno resolve a bare
  specifier from a `node_modules` directory beside or above the importing
  file — not from a path a `package.json` field names (`imports` maps only
  `#` specifiers; workspaces need an install). So `pull` links
  `node_modules → .airdress/node_modules` at the function root (or, when a
  real `node_modules` is already there, `node_modules/@airdress/functions`
  → the copy), and writes a `package.json` with `"type": "module"` when
  there is none. Deno needs `--node-modules-dir=manual`. Measured with
  Node 24.14, Bun 1.4.2 and Deno 2.9.7: without the link all three refuse
  the import; with it the dwell template's test passes in each.
- **Types.** `.airdress/sdk-<version>.d.ts` declares every module and the
  `airdress` global; the `tsconfig.json` includes it (only one version's,
  since two would declare the same modules). The operator does not
  type-check; the editor and `tsc --noEmit` do.
- **Refusals and notes.** A library refusal (`SdkNotPinned`,
  `SdkVersionUnknown`, `SdkVersionWithdrawn`, `SdkModuleUnknown`,
  `SdkModuleTestOnly`, `SdkCapabilityNotRequested`) prints at the import as
  `path:line:column`, with the operator's `fix` (`fix: add to
  function.json: "capabilities": […]`) and the next step. The check's
  notes — a deprecated or alpha module, a concurrency `dwell` warns about,
  a `pass_headers` entry with no effect — print as information and never
  stop a deploy. The codes are listed in
  `src/functions/sdk-refusals.txt`, the same list the editor extension
  carries.

#### Deploy: a tree to serving in one command (SPEC-113)

```sh
airdress fn keygen --out ~/.airdress/function-signing.key   # once: 0600, prints pubkey + fingerprint
airdress fn deploy ./greeter --signing-key ~/.airdress/function-signing.key
airdress fn deploy ./greeter --plan          # check + promote dry run; writes nothing
airdress fn promote greeter sha256:<v> --based-on sha256:<running>   # roll to any stored version
airdress fn signers add greeter --machine <machine id>   # its own apply, shown first;
                                             # also rewrites the committed function.yaml
airdress fn signers remove greeter --key <hex>
```

`deploy` checks the tree (an unsigned dry run), compares the operator's
digest with its own, asks **once**, signs, publishes, and then:

- for a function that exists, **promotes** the new version — which writes
  `spec.source.version` and nothing else, so a deploy can never widen a
  grant, change the config or touch the signer set;
- for a new one, applies one manifest: the directory's `function.yaml`
  (its grant and config) or one drafted from `function.json`, with
  `spec.source.signers: [ { key: <this key> } ]`, shown in full before it
  is sent, and written back as `function.yaml`.

It then waits until the function reports the new version loaded (the
first function after an operator deploy compiles the engine, ≈ 15 s;
`--wait-timeout`). `--yes` prints the confirmation without asking. A stop
the client makes has one code from a closed list
(`src/functions/deploy-stops.txt`: `check_failed`, `signer_not_this_client`,
`operator_predates_promote`, …); a refusal from the operator is shown as
it came. Who may sign is the function's **signer set**; the client checks
membership first and `signer_not_this_client` lists the members.

#### Deploying from CI

A repository holds function directories, each with its `function.yaml`,
and optionally `airdress.functions.yaml` at its root (`airdress fn
layout-schema` prints its JSON Schema):

```yaml
layout: 1
operator: 019e2b8c-….a.airdr.es
functions:
  - path: functions/relay
  - path: functions/digest
    manifest: deploy/prod/digest.yaml
```

Without it, every directory holding a `js-source/v1` `function.json` and a
`function.yaml` is a function.

```sh
airdress fn deploy --ci --since "$BEFORE_SHA"   # or --all
```

CI mode never prompts, never creates a function and never applies. It
deploys only the functions whose `function.json` or `src/` changed (a
manifest-only change deploys nothing), reads `basedOn` and the signer set
from the manifest **at the branch head** (`git fetch` first; a newer
commit touching the same function makes this run yield as `superseded`),
and after the promote rewrites exactly one scalar — `spec.source.version`
— in the manifest, for the pipeline to commit. A stale base names who
deployed what runs now and is never retried. `--output json` prints one
object per function.

The runner authenticates as an enrolled **machine**, with no hub profile:
every request is signed with its machine key (RFC 9421, the operator's own
`airdress-httpsig` crate). Secrets are read from files or from environment
variables holding their contents, never from arguments:

| What | Where |
| --- | --- |
| machine key | `--machine-key <file>` or `AIRDRESS_MACHINE_KEY` (path or contents) |
| its enrollment record | `<key>.json` beside it, or `AIRDRESS_MACHINE_ENROLLMENT` (path or JSON) |
| operator | `--operator-url` or `AIRDRESS_OPERATOR_URL` (required with a machine key) |
| source-signing seed | `--signing-key <file>` or `AIRDRESS_FUNCTION_SIGNING_KEY` |

`airdress apply -f <file> --machine-key <file> --operator-url <url>` sends an
apply as the machine; the operator decides by its grants (for a CI machine,
none: `403 resource_forbidden`). The environment variable is not read there.

The machine signs source as itself (`{ machine: <id> }` in the signer set)
with the seed registered as its source key. One-time setup, by the owner:
enroll and approve the machine; `airdress-operator machines source-key add
<id> --key <pub>`; grant it `Publish,Promote,ReadStatus` on each function;
then `airdress fn signers add <name> --machine <id>` (it updates the
committed `function.yaml` too) and commit it. The CLI warns when the machine's approval lapses within 14 days,
and stops with `machine_authorization_expired` once it has.

### Approving machines

A machine that runs `airdress-operator machine enroll` waits for the owner.
Decide from a terminal with your hub sign-in:

```sh
airdress machines pending                     # user code, name, purpose, fingerprint, code, expiry
airdress machines approve WDJB-MJHT --fingerprint SHA256:…        # or --confirmation-code …
airdress machines approve WDJB-MJHT --confirmation-code … --link-home [name]   # also bind it as a Home
airdress machines deny WDJB-MJHT
airdress machines list
airdress machines revoke <machine id> --reason "retired" [--source-signing rotated|compromised]
```

There is no approval without comparing what the machine printed. `--link-home`
(name defaults to `home`) is sent only when the pending listing offers `Home`
for that enrollment; otherwise the CLI refuses before sending anything.

### Homes (SPEC-116)

A Home Assistant linked at approval is a `Home` resource. Read it, or cut it
off:

```sh
airdress home list                  # hub, ready, connected (ws/poll), operate/observe counts, notify, last seen
airdress home get home              # hub + versions, Linked/Connected/Ready, shared vs effective,
                                    # sensitive opt-ins, notify, limits, conversation
airdress home disconnect home [--reason …] [--yes]   # revoke the machine, then delete the Home
airdress get home                   # the same table through the generic verb
```

`disconnect` revokes first, so the hub is cut off even if the delete then
fails — and it says so, with the command that finishes the job. The Home's
conversation is kept, marked disconnected.

### Plugins (SPEC-119)

Install and remove plugins on your operator with your hub sign-in (the
operator's owner-only `/v1/plugins/installs` routes):

```sh
airdress plugins list                                   # id, plugin, version, runtime state, host
airdress plugins install forms@0.2.0 [--subdomain surveys] [--signer key:<hex>|machine:<name>] [--dry-run] [--yes]
airdress plugins install forms --local                  # a definition the operator loaded
airdress plugins install geo --offer-personal           # offer its personal scope to your people
airdress plugins uninstall <id> [--backup] [--dry-run] [--yes]
airdress plugins verify forms@0.2.0 --index-key ed25519:<hex> [--author-key ed25519:<hex>]
airdress plugins authorize geo                          # its personal scope, for yourself
airdress plugins deauthorize geo [--keep] [--yes]       # erase your data in it, or keep it dormant
```

A plugin has two scopes, like a Slack app's bot and user tokens: the
**airdress** scope, which you approve at install and where it acts as the
install, and the **personal** scope, which you only **offer**
(`--offer-personal`). Each person on the airdress then authorizes it for
themselves with `authorize`, and their data in it is theirs; the owner is
shown how many authorized, never who, and cannot read it. `deauthorize`
revokes your own authorization and, unless you `--keep` it, has the plugin
erase your data after you could export it.

Two kinds of signer (SPEC-119 R-8): a plugin's **author** signs each
release, and the **registry** signs only its index — versions, yanks, each
author's live and revoked keys, an expiry — and each release's build
provenance.

`install <name>[@<version>]` installs a release from the registry
(`https://plugins.airdress.co`; the latest when no version is given). The
operator checks the index against the registry key it pins and the release
against the install's **signer set** before anything is written. The CLI
first asks it for a dry run and shows where the plugin will serve, who
signed it, the signer set you pin by installing (the author keys the index
lists, unless you name `--signer`s; an upgrade is held to the set already
pinned), whether its build provenance is attested, and what it may do in
each scope; it asks once — a script must pass `--yes` — then installs
exactly the version shown. A refusal names its reason and where the install
stopped (`author_signer_mismatch at signature`, `author_key_compromised at
signature`, `index_rollback at resolve`, `provenance_missing at
provenance`, `version_yanked at resolve`, …). `--local` installs a
definition the operator has loaded instead.

`verify` checks a registry release without an operator, as an operator
would: the index signature against the registry keys you pin
(`--index-key`, or `AIRDRESS_PLUGIN_INDEX_KEYS`, comma-separated — the line
in `airdress-plugins/keys/index.pub`; `--trusted-key` is the old spelling)
and that it has not expired; the author's signature (against `--author-key`
pins, or the author keys the signed index lists); the provenance; and the
digest of the manifest and every artifact.

`uninstall` deletes the plugin's data: it reads the install first, shows what
goes, and asks; a script must pass `--yes`. `--backup` dumps the plugin's
database schema before it is dropped. An operator whose plugin runtime is off
answers that it does not serve plugin installs.

## Your airdress from an editor (MCP)

```sh
airdress mcp serve        # speak MCP over stdio, as an editor starts it
airdress mcp catalogue    # the tool list, as JSON
```

The same reads and writes this CLI does, offered as tools to an editor
or to a model inside one: the fleet, an airdress's status, the functions
dev loop (list, versions, logs, templates, validate, deploy, promote),
resources (list, read, apply), the recent inbound events, and any tools
the airdress's own functions publish, re-exported as `fn_<tool>`.

There is a second binary, `airdress-mcp`, which is the same server. It
exists so an editor plugin can ship one small artifact instead of the
whole CLI, and so that artifact can be built, signed and pinned on its
own.

Three properties worth knowing:

- **It holds no credential.** The profile store owns the tokens, this
  refreshes through it, and nothing it ever writes — a tool result, an
  error, a log line — carries a token, a refresh token, a device code or
  a signing key. A test drives every tool against mock servers that hand
  it real-shaped secrets and fails if one appears.
- **It contacts your hub and your operators, and nothing else.** No
  analytics, no crash reporting, no tracing exporter: the crates that
  could do it are banned in `deny.toml`, and the egress test runs the
  whole session with every other host unreachable.
- **`--read-only` really is.** It removes every tool that changes
  anything, and a model that asks for one by name is refused.

```sh
airdress mcp serve --read-only true --default-airdress my-airdress
```

An airdress can switch the editor path off; when it is off, every tool
answers one sentence saying so and where to manage the airdress. That
switch makes this client behave — it is not a fence around your own
data, which this CLI reaches either way.

## Exit codes

`0` ok, `1` internal, `2` usage, `3` refused, `4` authentication needed or
expired, `5` network, `6` conflict or stale base, `7` confirmation required
(pass `--yes`). Under `--output json` a failure is one JSON object on
stderr: `{"code", "message", "hint"?, "status"?}`. The full contract,
and its one exception (`airdress shell` passes the remote program's status
through): [docs/exit-codes.md](docs/exit-codes.md).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md), and
[SECURITY.md](./SECURITY.md) for how to report a vulnerability.

## License

Apache-2.0. See [LICENSE](./LICENSE), [NOTICE](./NOTICE) and
[THIRD-PARTY.md](./THIRD-PARTY.md).
