# Getting started

Install the CLI ([README](../README.md#install)), then sign in. Everything
else follows from which airdress a command acts on.

## Sign in

```sh
airdress auth login
```

Your browser opens on the account picker. Every login asks which account,
so a second profile never silently inherits the one the browser is already
signed in to. When it is done the CLI prints which account the profile got.

On a machine without a browser, use the device flow and finish the sign-in
elsewhere:

```sh
airdress auth login --device      # prints a URL and a code
airdress auth login --no-browser  # the same, and never tries to open one
```

The device-flow page cannot show an account picker: it signs in whichever
account that browser already uses. Open the link in a private window when
you want a different one.

Check and end a sign-in:

```sh
airdress auth status              # a read; it never refreshes or writes
airdress auth logout              # ends the session at the identity provider, then forgets the tokens
```

`auth status` says `authenticated` while a refresh token is on file, even if
the access token beside it has lapsed; it renews on next use. `expired`
means a browser login is really needed.

## Profiles

A profile is one account on one hub. The default hub is
`https://account.airdress.co`; the default profile is created on your first
login.

```sh
airdress auth login --profile work          # a second account, side by side
airdress profile create staging --endpoint https://staging.example.com
airdress profile use work                   # make it the active one
airdress use work                           # the same, shorter
airdress profile list
airdress profile show                       # the active profile, credentials redacted
```

Most commands take `--profile <name>` to act as another profile once.

## Which airdress a command acts on

Most commands act on a *current* airdress. It is resolved in this order,
highest first:

1. `--airdress <name>` / `-A <name>` on the command line.
2. `AIRDRESS_NAME` in the environment.
3. A `.airdress` file in the working directory or a parent, holding the
   name. Off by default; opt in once in `~/.airdress/preferences.toml`:

   ```toml
   [discovery]
   directory_marker = true
   ```

4. The airdress pinned on the active profile: `airdress airdress use <name>`
   (or `airdress a use <name>`). The pin is checked against the hub when set,
   and cleared by itself if the airdress later disappears.

With none of these, the command stops and points you at
`airdress airdress list`.

When the airdress came from the environment, a marker or the pin, the CLI
says so on stderr: `→ acting on home (source: profile-default)`. Silence it
with `--quiet` or `AIRDRESS_QUIET=1`. `--output json` is always silent and
carries the resolved airdress in its envelope instead.

```sh
airdress airdress list        # the airdresses you own
airdress a use home           # pin one
airdress airdress probe       # how the hub reaches it: direct or relayed
airdress -A office airdress probe   # one command on another
airdress current              # "work / home (source: profile-default)"
```

`airdress current --output json` is built for shell prompts.

## Where to next

- [Functions](functions.md): put code behind your airdress.
- [Shells](shells.md): a terminal on one of your machines.
- [Your airdress from an editor](editor.md): the same reach, over MCP.
- [Devices, machines and homes](devices-and-machines.md): what is attached
  to your airdress, and how it got there.
