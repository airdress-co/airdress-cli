# Plugins

A plugin is a signed release that runs on your airdress: a form, a map, a
small app on its own subdomain. You install it with your sign-in; your
airdress checks every signature before anything is written.

```sh
airdress plugins list                                   # id, plugin, version, state, where it serves
airdress plugins install forms@0.2.0                    # a release from the registry
airdress plugins install forms                          # the latest
airdress plugins install forms --subdomain surveys      # serve it elsewhere
airdress plugins install forms --dry-run                # show, change nothing
airdress plugins install forms --local                  # a definition your airdress already loaded
airdress plugins uninstall <id> [--backup]              # destroys its data; asks first
```

`install` first asks your airdress for a dry run and shows you where the
plugin will serve, who signed it, which signers you pin by installing,
whether its build provenance is attested, and what it may do. It asks once,
then installs exactly the version shown. A script passes `--yes`. A refusal
names its reason and where the install stopped: `author_signer_mismatch at
signature`, `version_yanked at resolve`, `provenance_missing at
provenance`, and so on.

## Two signers

A plugin's **author** signs each release. The **registry**
(`https://plugins.airdress.co`) signs only its index: versions, yanks, each
author's live and revoked keys, an expiry, and each release's build
provenance. Installing pins the author keys the signed index lists, unless
you name your own with `--signer key:<hex>` or `--signer machine:<name>`;
an upgrade is held to the set already pinned.

Check a release yourself, without an airdress, as an airdress would:

```sh
airdress plugins verify forms@0.2.0 --index-key ed25519:<hex> [--author-key ed25519:<hex>]
```

`--index-key` can also come from `AIRDRESS_PLUGIN_INDEX_KEYS`,
comma-separated. `verify` checks the index signature and that it has not
expired, the author's signature, the provenance, and the digest of the
manifest and every artifact.

## Two scopes

A plugin has an **airdress** scope, which you approve at install and in
which it acts as the install, and a **personal** scope, which you only
*offer*:

```sh
airdress plugins install geo --offer-personal   # offer it to the people on your airdress
airdress plugins authorize geo                  # as one of those people: authorize it for yourself
airdress plugins deauthorize geo                # erase your data in it, after you could export it
airdress plugins deauthorize geo --keep         # keep it dormant instead
```

Each person's data in the personal scope is theirs. The owner is shown how
many people authorized, never who, and cannot read it.
