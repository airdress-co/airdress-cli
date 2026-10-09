# Devices, machines and homes

Three kinds of thing attach to an airdress. **Devices** are yours: phones,
this CLI, an agent on your laptop. **Machines** are approved by you: a shell
host, a CI runner, a Home Assistant. A **Home** is a Home Assistant linked
as a resource. Every one of them is admitted by a person comparing
something, never by a token alone.

## Devices

Pair a phone or a chat client to the current airdress. The CLI mints a
pairing code, shows a QR and a link, and waits for the scan:

```sh
airdress device pair
airdress device pair --label "Ada's phone"
airdress device pair --no-qr             # link only
airdress device pair --output json       # for a script
```

Revoke a device that can no longer act for itself, a lost or wiped phone,
with your own sign-in:

```sh
airdress device revoke <ENROLLMENT_ID> --dry-run   # id, airdress, label; changes nothing
airdress device revoke <ENROLLMENT_ID>             # shows the same, asks, revokes
airdress device revoke <ENROLLMENT_ID> --yes       # scripts
```

The enrollment id is the one the editor extension's Enrollments view
shows.

`airdress device bootstrap` onboards the **first** device on an airdress
that has no owner bound yet, using its bootstrap token. Prefer
`AIRDRESS_BOOTSTRAP_TOKEN` over the flag: flags land in shell history. It
prints the resulting device session token once; store it.

## Machines

A machine (a shell host, a CI runner, a Home Assistant) asks to enroll and
prints a user code, a fingerprint and a confirmation code. You decide from
any terminal with your sign-in:

```sh
airdress machines pending                                    # what is waiting
airdress machines approve WDJB-MJHT --fingerprint SHA256:…   # or --confirmation-code …
airdress machines deny WDJB-MJHT
airdress machines list                                       # approved, revoked ones included
airdress machines revoke <machine id> --reason "retired"
```

There is no approval without comparing what the machine printed. A
revocation takes effect on the machine's next request. For a machine that
signs function source, `--source-signing rotated` keeps what it signed
running and `--source-signing compromised` quarantines it.

## Homes

A Home Assistant that enrolls as a machine can be linked as a `Home` at
approval:

```sh
airdress machines approve WDJB-MJHT --confirmation-code … --link-home        # named "home"
airdress machines approve WDJB-MJHT --confirmation-code … --link-home house
```

`--link-home` is sent only when the pending listing offers it for that
enrollment. Then:

```sh
airdress home list                  # connected, what functions may operate and observe, notify
airdress home get house             # versions, conditions, sensitive opt-ins, limits, conversation
airdress home disconnect house      # revoke the machine, then delete the Home
```

`disconnect` revokes first, so the home is cut off even if the delete then
fails, and says so with the command that finishes the job. The Home's
conversation is kept, marked disconnected.

## Agent chat

From the owner's side, decide which agent device holds a conversation:

```sh
airdress chat agents                               # the agent devices and their standing
airdress chat assign <conversation> "Agent on studio"
airdress chat assignments <conversation>           # who holds it, in which state
airdress chat unassign <conversation>              # delivery stops at once
```

Assigning does not hand the agent the conversation's keys: a phone of
yours that is in the conversation adds the device to it.

## This machine as an agent device

`airdress agent device join|status|leave|serve` enrolls the machine you are
on as an agent device, with a phone approving. It is present in builds made
with the `mls` feature, which the published releases do not yet include; a
released binary answers `unrecognized subcommand`.

## Renewing a certificate

`airdress tls renew` asks the current airdress to renew its TLS
certificate now. `--rotate` revokes the old certificate first, for the case
where the certificate authority would otherwise hand back the same one.
