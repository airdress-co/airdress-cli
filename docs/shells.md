# Shells

`airdress shell` opens a terminal on one of your own machines, through your
airdress, end to end encrypted: the relay carries ciphertext and never holds
a key. The machine runs `airdress shell host`; your laptop or phone opens
sessions on it by **profile**, never by typing a command into the network.

## On the machine: a host

```sh
airdress shell host --operator https://<your airdress address> --name studio
```

On first run the host enrolls with your airdress and waits for your
approval. Approve it from any terminal with your sign-in, after comparing
the fingerprint it printed:

```sh
airdress machines pending
airdress machines approve WDJB-MJHT --fingerprint SHA256:…
```

Then give it something to offer. Profiles live in
`~/.config/airdress/shells.toml` on the host, and only a command run on the
host itself can change them:

```sh
airdress shell profile add --id dev --label "Dev shell" --program bash --cwd ~/code
airdress shell profile add --id top --program htop --record true
airdress shell profile list       # and whether each can open
airdress shell profile check      # validate the file
```

Each profile can record its sessions (`--record`), notify your phone when a
program needs you or is done (`--notify`, `--notify-bell`), end idle
sessions (`--idle-timeout`, default 24h) and cap any session
(`--max-lifetime`, default 7d).

Keep the host running with your login session:

```sh
airdress shell host --install      # a systemd user unit; nothing system-wide
airdress shell host --uninstall
airdress shell host status        # what it is bound to, keys, profiles, devices
airdress shell host reauth        # renew its approval before it lapses
```

The host never switches user and keeps nothing running after it stops
except the unit you asked for.

## From your laptop: a session

```sh
airdress shell                    # pick a running session or a profile
airdress shell dev                # open profile "dev" on your only host
airdress shell dev --machine studio
airdress shell ls                 # hosts, profiles, running sessions
airdress shell attach <session>   # take input; --view to watch
airdress shell close <session>    # SIGHUP, then SIGKILL
```

`--auth-profile` picks the account profile; the positional argument is
always a shell profile.

### The CLI is a device

Only a person on an enrolled device of their own reaches a shell. The first
time you use `airdress shell` against an airdress, the CLI asks to join it,
and one of your phones approves (Devices → Asking to join). From then on it
is a device of yours, labelled "airdress CLI on <machine>".

```sh
airdress shell device join        # ask explicitly
airdress shell device status      # whether this CLI is a device, and where its keys are
airdress shell device forget      # forget it here; revoke it from a phone as well
```

Until a phone approves, the CLI holds no credential at all.

### No unlock on Linux, and what that means

A phone asks for its fingerprint or PIN on every open. An enrolled CLI on
Linux opens, reattaches and resumes **without a prompt**, like an SSH key
without a passphrase. So any process running as your user on that machine
can drive `airdress shell`; the terminal check slows that down and does not
stop it. If that is not acceptable on a machine, do not join the CLI there,
or `airdress shell device forget` it and revoke the device from a phone.

### The host's key

The first connection to a host prints its key's fingerprint and asks you to
compare it with what `airdress shell host` printed on that machine. Answer
only after comparing. The key is then pinned, and every later connection is
checked against it; a host presenting another key fails, whatever the relay
says. If the key really changed, read the new fingerprint on the machine
and pin it:

```sh
airdress shell repin studio SHA256:…
```

## Inside a session

The terminal is in raw mode and passes everything through, `Ctrl-C`
included. Window size changes are forwarded. The escape key is `Ctrl-]`,
then:

| Key | What |
| --- | --- |
| `d` | detach; the session keeps running |
| `q` | close the session, after a confirmation |
| `i` | take input back on this device |
| `?` | show these keys |
| `Ctrl-]` | send one `Ctrl-]` |

Attaching takes input; the device that had it becomes a viewer and is told.
`attach --view` watches without taking it.

A lost connection comes back by itself, resuming where it stopped: nothing
is lost and nothing is shown twice.

## Recordings

A recorded session is sealed on the host to the keys of your devices; the
host cannot read its own recordings.

```sh
airdress shell recordings ls              # through a running session on the host
airdress shell recordings play <id>       # replay here, at its own pace; --speed, --max-idle
airdress shell host recordings list       # on the host machine itself
airdress shell host recordings prune      # remove those past retention
```

## For editors: `--json-proto`

`airdress shell <profile> --json-proto` and
`airdress shell attach <session> --json-proto` speak JSON lines on stdin and
stdout instead of a terminal, so an editor can reuse this CLI's device and
keys. It refuses a host whose key is not pinned yet: pin it once from a
terminal.
