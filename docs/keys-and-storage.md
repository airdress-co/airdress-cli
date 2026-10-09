# Keys and storage

What the CLI keeps on your machine, where, and who can read it.

## Profiles and tokens

Profiles live under `~/.airdress/profiles/`, one file per profile, readable
by your user only. A profile holds the hub it belongs to, the account it
signed in as, its pinned airdress, and its tokens: one refresh token and
an access token per airdress. `airdress profile show` prints a profile with
the credentials redacted; `airdress auth token` is the one command that
prints a credential, because asking for it is the point.

Two processes never present the same refresh token twice: a refresh runs
under a lock on the profile file and re-reads it first.

Preferences, such as the `.airdress` directory marker opt-in, are in
`~/.airdress/preferences.toml`.

## Device keys

When the CLI acts as a device of your airdress, for shells or as an agent,
it holds keys of its own. They go to the operating system's secret store
where there is one: Keychain on macOS, Credential Manager on Windows, the
Secret Service on a Linux desktop. Where there is none, they go to files
under `~/.local/state/airdress/` readable by your user only.
`airdress shell device status` says which store this machine uses.

On Linux, the binary the one-line installer, the `.deb` and the editor
plugin give you is statically linked: it needs no system library, runs on
any distribution of its architecture, and reaches the Secret Service over
D-Bus like a binary you build yourself. Both use the same store, so a key
one of them saved is the key the other finds. A machine with no Secret
Service (a server, a container, an SSH session with no desktop) uses the
file store.

Nothing about custody depends on the store: the seed never leaves the
device, and your airdress never sees it.

## Shell hosts

A shell host keeps its machine key and shell key in
`~/.local/state/airdress/shell-host/`, so it can start under a user unit
without a keychain prompt. Its profiles are in
`~/.config/airdress/shells.toml`, and nothing over the network can change
them. Recordings stay on the host, sealed to the keys of your devices; the
host cannot read them.

## Function signing keys

`airdress fn keygen --out <file>` writes an Ed25519 seed to a new file with
mode `0600` and refuses to overwrite an existing one. The seed is never
printed; its public key and fingerprint are.

## Pinned host keys

The fingerprint of every shell host you have connected to is pinned in
`known-hosts.json` beside the shell client's keys. A host presenting another
key fails the handshake, and `airdress shell repin` is the only way to
accept a new one.
