# Shells from the CLI

`airdress shell` opens a terminal on one of your own machines, through your
airdress, end to end: the operator relays ciphertext and never holds a key.
The machine runs `airdress shell host`; this page is about the other end,
the CLI you type into.

```sh
airdress shell                      # pick a running session or a profile
airdress shell api                  # open profile "api" on your only host
airdress shell api --machine laptop # … on the host named "laptop"
airdress shell ls                   # hosts, profiles, running sessions
airdress shell attach <session>     # attach and take input (--view to watch)
airdress shell close <session>      # end a session (SIGHUP, then SIGKILL)
airdress shell recordings ls        # recordings sealed to your devices
airdress shell recordings play <id> # replay one here, at its own pace
```

`--auth-profile` picks the hub sign-in; the positional argument is always
a shell profile.

## The CLI is a device

Only a person on an enrolled device of their own reaches a shell. So the
first time you use `airdress shell` against an airdress, the CLI asks to
join it, and one of your phones approves (Devices → Asking to join):

- it asks as a **delegation-only human device of kind `cli`**, labelled
  "airdress CLI on \<machine\>";
- the phone approves with a **root-signed delegation** that names the CLI's
  identity key and says `cli`; the CLI never holds the root;
- the CLI then registers its shell key with **no presence key**
  (`presenceAlg: none`), signed by that identity key. The operator accepts
  `none` only from a delegation-only `cli` device, and your hosts accept it
  only when the delegation says `cli`, so nobody can turn a phone into such
  a device.

`airdress shell device join|status|forget` does this explicitly. The keys
live in the Secret Service where there is one, otherwise in 0600 files
under `~/.local/state/airdress/shell-client/<airdress>/`, and `device
status` says which.

Until a phone approves, the CLI holds no credential at all, and every shell
route refuses it.

## No step-up on Linux

An enrolled CLI on Linux opens, reattaches and resumes **without any
prompt**, like an SSH key without a passphrase (decision D-30). Phones are
different: every open and reattach there needs the fingerprint or PIN.

What stays is the terminal check: `airdress shell` and `airdress shell
attach` refuse to run unless both stdin and stdout are terminals.

### The accepted risk

This is threat T-10 of the shells requirements, in its own words:

> **A local process of the same user**, for example an AI agent running on
> the host or on the CLI's laptop. **Accepted risk (D-30), documented:** on
> a Linux machine with an enrolled CLI, a local agent running as that user
> can drive `airdress shell`, exactly as it could use an SSH key without a
> passphrase. It is slowed, not stopped, by the CLI's terminal check. On the
> host, the desk socket admits only a peer with a real TTY, checked by the
> host on the peer's own descriptors (D-29). An agent that owns a real
> terminal (a PTY it opened itself) passes that check too; that is the same
> accepted risk. Phones are not affected: their presence key needs the
> person.

If that is not acceptable on a machine, do not join the CLI there, or
`airdress shell device forget` it and revoke the device from a phone.

## The host's key

The first connection to a host prints its key's fingerprint:

```text
First connection to laptop.
  Host key  SHA256:…
Compare it with what `airdress shell host` printed on that machine ("This host's key").
Does it match? [y/N]
```

Answer only after comparing. The key is then pinned in
`known-hosts.json`, and every later connection uses the pinned key for the
handshake: a host presenting any other key fails it, whatever the operator
says. If the operator later reports another key, the CLI stops and shows
both fingerprints ("HOST KEY CHANGED"). There is no "continue": read the key
on the machine itself and pin it with `airdress shell repin <host>
<fingerprint>`, which refuses any fingerprint other than the one the host
now reports.

## Inside a session

The local terminal is in raw mode and passes bytes through, `Ctrl-C`
included (the program on the host gets it, as from a local keyboard).
Window size changes are forwarded. The escape key is `Ctrl-]`, then:

| Key | What |
|---|---|
| `d` | detach; the session keeps running |
| `q` | close the session, after a confirmation |
| `i` | take input back on this device |
| `?` | show these keys |
| `Ctrl-]` | send one `Ctrl-]` |

Attaching takes input; the device that had it becomes a viewer and is told
("Input moved to …"), and so are you if it moves away. `attach --view`
watches without taking it.

## Network changes

A lost connection comes back by itself, with nothing to answer:

1. the same leg again, while the operator still holds it;
2. else a new leg with the session's single-use resume ticket, and the host
   replays from the last byte this CLI received;
3. if the host refuses that ticket, once more with the ticket the previous
   resume redeemed (a cut in the middle of a resume);
4. else a full reattach, which on Linux also asks nothing.

Output is reassembled by offset: nothing is lost, and nothing is shown
twice.

## Recordings

A recorded session is sealed on the host to the shell keys of your devices,
and the host forgets each segment's key when the segment ends: it cannot
read its own recordings. `recordings ls` and `recordings play <id>` fetch
them over the end-to-end channel and open them with this device's key.
Because that channel belongs to a session, they go through a running
session on the host (`--session` picks which). On the host machine itself,
`recordings play --file <segment>` reads a segment file directly.

## For the editor: `--json-proto`

`airdress shell [profile] --json-proto` and `airdress shell attach <session>
--json-proto` speak JSON lines on stdin and stdout instead of a terminal, so
the editor can reuse this CLI's device and keys. It is exempt from the
terminal check, and refuses a host whose key is not pinned yet (pin it once
from a terminal).

In, one per line: the protocol's inner messages in their JSON form
(`{"type": "in", "data": "<base64>"}`, `{"type": "resize", "cols": 120,
"rows": 40}`, `{"type": "take_input"}`, `{"type": "recording_list"}`, …),
plus `{"type": "detach"}` and `{"type": "close"}`. `presence`, `rekey`,
`ack` and `credit` are the CLI's own and are refused.

Out, one per line: `connected`, `output` (`data`, base64, in order and
never repeated), `redraw` (`cols`, `rows`, `data`), `roles`, `exit`,
`host_stopping`, `error`, `reconnecting`, `recording_*`, `structured`, and
finally `ended`.
