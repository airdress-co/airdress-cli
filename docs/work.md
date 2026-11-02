# Work items

`airdress work` hands out tasks and asks RFIs on your airdress. An RFI is a
question that holds up work until it has one official answer. Each item
has a number, its people and a history, and the app shows it as a card in
the conversation it came from.

An item is kept by your company's airdress. Its asker, its assignees, its
watchers and the owner can read it. It is not end to end between them:
your airdress can read it, which is what lets it keep lists, send
reminders and draft items for you.

Work items are off until your airdress turns them on. Until then every
command answers `not_enabled`.

## What waits on you

```sh
airdress work list                 # open items assigned to you, oldest first
airdress work list --view asked    # what you asked
airdress work list --view all      # everything you can read
airdress work show <id>            # one item, with its answer if it has one
```

## Hand out a task

```sh
airdress work task "Re-seal the bay 3 window" --to Ana --due 2026-11-06 --at "Holloway Rd"
```

`--to` and `--watch` take a person's name or id, and both repeat. Only the
owner can look people up by name. Anyone else passes ids.

The people on a task move it along:

```sh
airdress work status <id> in-process
airdress work status <id> completed     # or failed
airdress work status <id> cancelled     # the asker or the owner
```

## Ask an RFI

```sh
airdress work rfi "Sill under or over the membrane?" \
  --question "Does the new sill go under or over the membrane?" \
  --ref "Drawing A-301" --propose "Under" --to Bo
```

The person it is addressed to gives the one official answer, and says
whether it may cost more or take longer:

```sh
airdress work answer <id> "Under, lapped 100 mm." --cost possible
```

An answer is not approval of extra cost or time. Only the person who asked
closes an RFI, or withdraws it before an answer comes:

```sh
airdress work status <id> closed
airdress work status <id> void
```

## What happened

```sh
airdress work history <id>
```

The history is append-only: who changed what, and when. Add
`--output json` to any of these commands for scripting.
