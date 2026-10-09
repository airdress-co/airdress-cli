# Functions

A function is TypeScript or JavaScript that runs behind your airdress: a
webhook relay, a counter, a bridge to something at home. You write it in a
directory, sign it, and deploy it; your airdress bundles and runs it. The
checks are the airdress's own, and the CLI prints what it answers.

`airdress functions` and `airdress fn` are the same command.

## A function directory

```text
hello/
  function.json      # id, runtime, capabilities, the SDK version it pins
  function.yaml      # the manifest a deploy applies: grants, config, events
  src/
    main.ts
```

The *tree* that is published is `function.json` and every regular file
under `src/`, and nothing else. `function.yaml`, a README or a
`tsconfig.json` beside them stay local. Symlinks are refused.

Start from a template:

```sh
airdress fn templates                 # what you can start from
airdress fn new hello ./hello         # writes the tree and a function.yaml
airdress fn new hello ./hello --function-id acme.hello
```

A function id has two dotted labels. Without `--function-id`, a dotted
directory name is used as is; any other name becomes `local.<name>`.

## Sign, then deploy

Source is signed with an Ed25519 key you hold. Make one once:

```sh
airdress fn keygen --out ~/.airdress/function-signing.key   # 0600; prints the public key and fingerprint
```

Pass it with `--signing-key <file>`, or put the hex seed in
`AIRDRESS_FUNCTION_SIGNING_KEY`. The seed itself is never printed.

```sh
airdress fn deploy ./hello --signing-key ~/.airdress/function-signing.key
airdress fn deploy ./hello --plan      # check, compare, dry-run; writes nothing
airdress fn deploy ./hello --yes       # scripts: confirm without asking
```

`deploy` checks the tree, compares the digest your airdress computed with
its own, asks once, signs and publishes. Then:

- for a function that already exists, it **promotes** the new version,
  which changes `spec.source.version` and nothing else, so a deploy can
  never widen a grant, change the config or touch who may sign;
- for a new function, it applies one manifest: the directory's
  `function.yaml`, or one drafted from `function.json`, with your key as the
  signer. The manifest is shown in full before it is sent and written back
  as `function.yaml`.

It then waits until the function reports the new version loaded. The first
function after an airdress update compiles the engine, which takes about
15 seconds; `--wait-timeout` adjusts the wait.

Who may sign is the function's **signer set**. The CLI checks membership
first; `signer_not_this_client` lists the members when yours is not one.

```sh
airdress fn signers add hello --machine <machine id>    # also updates the committed function.yaml
airdress fn signers remove hello --key <hex>
```

## Validate, publish, promote

The steps `deploy` combines are commands of their own:

```sh
airdress fn validate ./hello --name hello           # every check a publish runs; stores nothing
airdress fn publish  ./hello --name hello --signing-key seed.hex --based-on sha256:<running>
airdress fn promote  hello sha256:<v> --based-on sha256:<running>   # run any stored version
airdress fn promote  hello sha256:<v> --dry-run
```

Refusals print one per line as `path:line:column: Reason: message`, plus
one line per capability the owner has not granted, naming its
`spec.capabilities` path. Any refusal exits non-zero.

**A stale base is never retried.** Once a function serves a version, a
publish or promote must name it with `--based-on`. If the function moved
in between, both versions are printed and the command exits `6`. That is
how two writers, an editor and a pipeline, stay honest with each other.

## Read what runs

```sh
airdress fn versions hello                  # what it served, newest first, and what is stored
airdress fn source sha256:<v>               # a version's manifest and file index
airdress fn source sha256:<v> src/main.ts   # one file, raw
airdress fn logs hello --since 15m --follow # the durable log; --invocation <id> for one call
```

## The SDK, `@airdress/functions`

A function imports the library as `@airdress/functions/<module>` and pins
an exact version in `function.json` (`"sdk": "1.0.0"`). Your airdress
bundles its own compiled-in copy at publish. Everything the CLI writes for
the SDK sits beside `function.json`, never under `src/`, so none of it is
published.

```sh
airdress fn sdk pull ./hello                # types and a local copy for the pinned version
airdress fn sdk pull ./hello --pin newest   # (re)pin first: `newest` or an exact version
airdress fn sdk vendor ./hello              # copy the modules into src/sdk/, drop the pin
node test/main.test.ts                      # or bun, or deno run --node-modules-dir=manual --allow-read
```

The copy comes from your airdress, never from npm, and lands in
`.airdress/node_modules/@airdress/functions/`. `pull` links `node_modules`
to it at the function root so Node, Bun and Deno resolve the bare import,
and writes a `package.json` with `"type": "module"` when there is none.
`.airdress/sdk-<version>.d.ts` declares every module and the `airdress`
global; the generated `tsconfig.json` includes it. Your airdress does not
type-check; the editor and `tsc --noEmit` do.

An SDK refusal (`SdkNotPinned`, `SdkVersionUnknown`, `SdkModuleUnknown`,
`SdkCapabilityNotRequested`, …) prints at the import with a `fix:` line.
Notes, such as a deprecated module or a warning about concurrency, print
as information and never stop a deploy.

## Deploying from CI

A repository holds function directories, each with its `function.yaml`,
and optionally `airdress.functions.yaml` at its root:

```yaml
layout: 1
operator: <your airdress address>
functions:
  - path: functions/relay
  - path: functions/digest
    manifest: deploy/prod/digest.yaml
```

`airdress fn layout-schema` prints its JSON Schema. Without the file, every
directory holding a `js-source/v1` `function.json` and a `function.yaml` is
a function.

```sh
airdress fn deploy --ci --since "$BEFORE_SHA"   # or --all
```

CI mode never prompts, never creates a function and never applies. It
deploys the functions whose `function.json` or `src/` changed, reads
`basedOn` and the signer set from the manifest at the branch head, and after
the promote rewrites exactly one scalar, `spec.source.version`, in the
manifest for the pipeline to commit. A stale base names who deployed what
runs now, and is never retried. `--output json` prints one object per
function.

The runner authenticates as an approved **machine**, with no account
profile. Secrets come from files or from environment variables holding
their contents, never from arguments:

| What | Where |
| --- | --- |
| machine key | `--machine-key <file>` or `AIRDRESS_MACHINE_KEY` (path or contents) |
| its enrollment record | `<key>.json` beside it, or `AIRDRESS_MACHINE_ENROLLMENT` (path or JSON) |
| the airdress | `--operator-url` or `AIRDRESS_OPERATOR_URL` (required with a machine key) |
| source-signing seed | `--signing-key <file>` or `AIRDRESS_FUNCTION_SIGNING_KEY` |

One-time setup, by the owner: enroll and approve the machine
([machines](devices-and-machines.md#machines)), register its source-signing
key on the airdress, grant it `Publish`, `Promote` and `ReadStatus` on each
function, then `airdress fn signers add <name> --machine <id>` and commit
the updated `function.yaml`. The CLI warns when the machine's approval
lapses within 14 days and stops with `machine_authorization_expired` once
it has.

The public GitHub Action
[`airdress-co/deploy-functions`](https://github.com/airdress-co/deploy-functions)
wraps this mode.
