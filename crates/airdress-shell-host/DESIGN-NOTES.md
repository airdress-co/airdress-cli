# airdress-shell-host: design notes

Where the host departs from, or fills a gap in, the shells design (SPEC-137
`design.md` §5.4, §6.3–§6.7, §7, §8, §9.2, §12.2, §13). Each note says what
the design says, what the host does, and why; each is a candidate amendment
to the spec. The operator side was read on branch `feat/shells` (operator
PR 342, commit `f0771783`) and re-read on operator main after PR 345
(`6a0c7bde`).

## H-1 The device-key statement is the operator's layout

`"airdress.shell.device-keys.v1" ‖ 0x00 ‖ device id (16) ‖ dhPublic (32) ‖
presenceAlg ‖ 0x00 ‖ presencePublic`, decided 2026-10-04. The protocol
crate's N-9 and its vectors were changed to match in the same PR
(`trust::device_keys_statement` is held equal to it by a test).

## H-2 Introductions are the operator's statement

Design §6.3 step 5 gives no byte layout; the host verifies the operator's:
`"airdress.shell.introduction.v1" ‖ 0x00 ‖ introducer (16) ‖ introduced
(16) ‖ identityPublic (32) ‖ deviceKind`, under the introducer's identity
key, which must already be trusted here. The kind for the presence rule
comes from the introduction (or the delegation), never from the operator's
`deviceKind` in an attestation.

## H-3 The first device is confirmed from the operator's list, or from a knock

Design §6.3: the host "lists the principal's devices on first start". It
does, from the machine-signed `GET /v1/shells/host/devices` (operator PR
345), which the operator scopes to the person the host's link names. Every
start, the listed devices that are not trusted or revoked here become
pending ones; an entry whose `identityFingerprint` does not name its
`identityPublic`, or a list for another principal, is dropped. While nothing
is trusted, the host prints each with its fingerprint and the command. The
person runs `airdress shell host trust <fingerprint>` at the machine's
terminal and answers `y`; `trust` asks the operator again when the
fingerprint is not pending yet. A device that knocks before it is
introduced is still refused `shell_device_not_introduced` and remembered as
pending, as before. Either way the kind is the operator's claim (`kind`, or
the attestation's `deviceKind`) until the person sets it with `--kind`, and
nothing from the list is trusted without the person.

## H-4 The shell key's signature

`host_info.sig` is the machine identity's Ed25519 signature over
`"airdress.shell.host-key.v1" ‖ 0x00 ‖ machine id (16) ‖ shell key (32)`,
base64url. The design names the signature but not its bytes; the operator
uses this layout and, since PR 345, checks it on receipt: an unsigned or
bad `host_info`, or a `shellKey` that is not the fingerprint of
`shellKeyPublic`, closes the channel 4009. The host therefore signs once at
start and does not start when it cannot, rather than sending `sig: null`.

## H-5 An exited session reports `exited` when it stops being readable

FR-S12 keeps an exited session readable for 10 minutes. The operator closes
every leg of a session as soon as it hears `exited`, so the host sends it at
the end of that window (with `reason: exit`); sessions ended by the host or
a person (`closed`, `idle`, `lifetime`, `host_stopped`) report at once.

## H-6 A profile's reason is its own field

Since operator PR 345, `state` is `ready` or `invalid`, and an invalid
profile carries `reason`, a short code in `[a-z][a-z0-9_]{0,63}`
(`program_missing`, `program_not_absolute`, `program_not_executable`,
`cwd_missing`, `print_mode_refused`, `bridge_not_supported`). A reason that
is not a code breaks the protocol, so one outside the grammar would go out
as `unspecified`; a test holds all six inside it. The earlier
`invalid:<reason>` is accepted by the operator for one release only.

## H-7 Two codes the design does not list

`shell_lifetime_warning` (an inner `error` 10 minutes before
`max_lifetime`; there is no inner message for it) and
`shell_structured_unavailable` (a `structured` message to a host without
adapters, which this host does not have yet).

## H-8 Recording chunks are 32 KiB, and listing is per host

Chunks are sealed at 32 KiB (the format allows 64) so a fetched chunk fits
one record under the operator's 64 KiB frame ceiling; a fetch returns 16
chunks and the device asks again. `recording_list` answers every recording
on the host: the host serves one person, and a device must hold a live
session to have a channel at all (the design does not say which session a
listing goes through).

## H-9 Snapshots fit one record

A snapshot is one inner message, and one record must stay under the
operator's frame ceiling, so the host sends the screen always and the
newest scrollback lines that fit (design §7.1 says up to
`scrollback_lines`).

## H-10 The probe watcher is `strace`, not `fanotify`

Design §9.2 names `fanotify`, which needs `CAP_SYS_ADMIN`. The test traces
the helper process with `strace -f` instead (no privilege for one's own
child), and attributes each access to the host's threads or to a child
that exec'd, so the stand-in harnesses may read their decoy credentials
while the host may not touch them.

## H-11 The binary links `setuid`; the crate does not

Design §14.1 asks for "no `setuid` / `setgid` / `initgroups` in the release
binary's symbols". Every binary that starts a process with the standard
library links `setuid`, `setgid` and `setgroups` behind
`CommandExt::uid/gid/groups`. The check is on the host crate's own objects
and source instead (`scripts/shell-host-no-user-switch.sh`).

## H-12 Sign-in probes judge by exit status

The sign-in commands of design §9.2 are not yet verified (task F.8); until
they are, `yes`/`no` is the command's exit status and `unknown` a command
that did not run or timed out.

## H-13 Identity keys stay in 0600 files

The machine key and the shell key live in `~/.local/state/airdress/
shell-host/` as SPEC-098 machines keep theirs, so a host under the user
unit starts without a keychain prompt. D-32's keychain rule is about bridge
secrets, which this host does not have yet.

## H-14 Operator mismatches found while building this

- **The session id (resolved).** The host binds the `sessionId` of the
  `open` frame into the prologue. Since operator PR 343 that is the id the
  device proposed, so both ends bind the same one; a frame carrying any
  other id fails the handshake, and a live session's id is not opened
  twice (`the_session_id_bound_is_the_one_the_device_proposed`).
- **The attestation's label (resolved).** Since operator PR 345 it carries
  `label`. The host cleans it again (control characters dropped, at most 80
  characters), keeps the newest one for a device, and uses it in `roles`
  and prompts; `<kind> <id prefix>` only when there is none.
- **A person's devices for a machine (resolved)** — H-3.
- **`host_info.sig` (resolved)** — checked by the operator (H-4).
- **The profile reason (resolved)** — its own field (H-6).
- **`approvedBy` and the poll's `principal`** are read as the operator
  sends them; the host requires `principal`, `operatorKey`, and treats a
  null `rootPublicKey` as "admit introduced devices only".

## Measured on the dev box, 2026-10-04

The release `airdress` binary as a host against the test kit's mock
operator over the WebSocket (`--example host_measure`), on x86_64 Linux:

| What | Measured | Bound |
|---|---|---|
| Idle, one channel, no session | RSS 13.7 MiB, CPU 0.000 % over 60 s | NFR-3: ≤ 30 MiB, ≤ 0.2 % over an hour |
| One idle session (`/bin/sh`, 120×40) | +0.7 MiB | NFR-3: ≤ 8 MiB plus its journal |
| `cat` of 50 MiB to a viewer that never acks | drained in 0.8 s, peak RSS 39 MiB | NFR-4: memory within the journal bound |
| A keystroke right after the flood | echoed in 3 ms | NFR-4: input not stalled > 200 ms |
| Ctrl-C to the channel closed (one idle session) | 14 ms | FR-S14: within 10 s |

Not measured: CPU over a full hour, input latency *during* the flood (only
after it), and anything over the relay or with a real operator.
